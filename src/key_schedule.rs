//! TLS 1.3 Key Schedule Implementation using HKDF (RFC 5869 and RFC 8446)
//!
//! This module implements the complete TLS 1.3 key schedule as specified in RFC 8446,
//! Sections 7.1 and 7.2. It uses HKDF (HMAC-based Key Derivation Function) with SHA-256
//! to derive all cryptographic keys and secrets used during the TLS handshake and
//! application data transfer.
//!
//! Key Schedule Flow:
//! ```text
//!             0
//!             |
//!             v
//!   PSK ->  HKDF-Extract = Early Secret
//!             |
//!             +-----> Derive-Secret(., "ext binder" | "res binder")
//!             |                     = binder_key
//!             |
//!             +-----> Derive-Secret(., "c e traffic", ClientHello)
//!             |                     = client_early_traffic_secret
//!             |
//!             +-----> Derive-Secret(., "e exp master", ClientHello)
//!             |                     = early_exporter_master_secret
//!             v
//!       Derive-Secret(., "derived", "")
//!             |
//!             v
//!   (EC)DHE -> HKDF-Extract = Handshake Secret
//!             |
//!             +-----> Derive-Secret(., "c hs traffic", ClientHello...ServerHello)
//!             |                     = client_handshake_traffic_secret
//!             |
//!             +-----> Derive-Secret(., "s hs traffic", ClientHello...ServerHello)
//!             |                     = server_handshake_traffic_secret
//!             v
//!       Derive-Secret(., "derived", "")
//!             |
//!             v
//!   0 -> HKDF-Extract = Master Secret
//!             |
//!             +-----> Derive-Secret(., "c ap traffic", ClientHello...server Finished)
//!             |                     = client_application_traffic_secret_0
//!             |
//!             +-----> Derive-Secret(., "s ap traffic", ClientHello...server Finished)
//!             |                     = server_application_traffic_secret_0
//!             |
//!             +-----> Derive-Secret(., "exp master", ClientHello...server Finished)
//!             |                     = exporter_master_secret
//!             |
//!             +-----> Derive-Secret(., "res master", ClientHello...client Finished)
//!                                   = resumption_master_secret
//! ```

use hkdf::Hkdf;
use sha2::{Digest, Sha256};

use crate::aead::TrafficKeys;

const HASH_LEN: usize = 32; // SHA-256 output size
const KEY_LEN: usize = 16; // AES-128 key size
const IV_LEN: usize = 12; // AES-GCM IV size

/// HKDF-Extract as defined in RFC 5869, Section 2.2
///
/// HKDF-Extract(salt, IKM) -> PRK
/// 
/// # Arguments
/// * `salt` - Optional salt value (a non-secret random value)
/// * `ikm` - Input keying material
///
/// # Returns
/// A fixed-length pseudorandom key (PRK) of HashLen octets (32 bytes for SHA-256)
pub fn hkdf_extract(salt: Option<&[u8]>, ikm: &[u8]) -> [u8; HASH_LEN] {
    let (prk, _) = Hkdf::<Sha256>::extract(salt, ikm);
    let mut output = [0u8; HASH_LEN];
    output.copy_from_slice(&prk);
    output
}

/// HKDF-Expand as defined in RFC 5869, Section 2.3
///
/// HKDF-Expand(PRK, info, L) -> OKM
///
/// # Arguments
/// * `prk` - A pseudorandom key of at least HashLen octets
/// * `info` - Optional context and application specific information
/// * `length` - Length of output keying material in octets (<= 255*HashLen)
///
/// # Returns
/// Output keying material (OKM) of the specified length
///
/// # Panics
/// Panics if length exceeds 255 * HashLen (8160 bytes for SHA-256)
pub fn hkdf_expand(prk: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let hkdf = Hkdf::<Sha256>::from_prk(prk).expect("Invalid PRK length");
    let mut okm = vec![0u8; length];
    hkdf.expand(info, &mut okm)
        .expect("Invalid length for HKDF-Expand");
    okm
}

/// HKDF-Expand-Label as defined in RFC 8446, Section 7.1
///
/// ```text
/// HKDF-Expand-Label(Secret, Label, Context, Length) =
///      HKDF-Expand(Secret, HkdfLabel, Length)
///
/// Where HkdfLabel is specified as:
///
/// struct {
///     uint16 length = Length;
///     opaque label<7..255> = "tls13 " + Label;
///     opaque context<0..255> = Context;
/// } HkdfLabel;
/// ```
///
/// # Arguments
/// * `secret` - The input secret
/// * `label` - The label string (without "tls13 " prefix)
/// * `context` - Context data (usually a hash)
/// * `length` - Desired output length
fn hkdf_expand_label(secret: &[u8], label: &str, context: &[u8], length: usize) -> Vec<u8> {
    // Construct HkdfLabel
    let mut hkdf_label = Vec::new();
    
    // Length (2 bytes)
    hkdf_label.extend_from_slice(&(length as u16).to_be_bytes());
    
    // Label with "tls13 " prefix
    let full_label = format!("tls13 {}", label);
    hkdf_label.push(full_label.len() as u8);
    hkdf_label.extend_from_slice(full_label.as_bytes());
    
    // Context
    hkdf_label.push(context.len() as u8);
    hkdf_label.extend_from_slice(context);
    
    hkdf_expand(secret, &hkdf_label, length)
}

/// Derive-Secret as defined in RFC 8446, Section 7.1
///
/// ```text
/// Derive-Secret(Secret, Label, Messages) =
///      HKDF-Expand-Label(Secret, Label,
///                        Transcript-Hash(Messages), Hash.length)
/// ```
///
/// # Arguments
/// * `secret` - The input secret
/// * `label` - The label string
/// * `messages` - The transcript hash (or empty for intermediate derivation)
fn derive_secret(secret: &[u8], label: &str, messages: &[u8]) -> [u8; HASH_LEN] {
    let expanded = hkdf_expand_label(secret, label, messages, HASH_LEN);
    let mut output = [0u8; HASH_LEN];
    output.copy_from_slice(&expanded);
    output
}

/// TLS 1.3 Key Schedule Manager
///
/// Manages the progression through the TLS 1.3 key schedule stages:
/// - Early Secret (PSK-based, or all-zeros if no PSK)
/// - Handshake Secret (derived from ECDHE shared secret)
/// - Master Secret (final stage)
///
/// And derives all traffic secrets needed for encryption/decryption.
pub struct KeySchedule {
    /// Current secret in the key schedule
    current_secret: [u8; HASH_LEN],
    /// Current stage of the key schedule
    stage: KeyScheduleStage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyScheduleStage {
    /// Initial stage - Early Secret computed
    Early,
    /// After ECDHE - Handshake Secret computed
    Handshake,
    /// Final stage - Master Secret computed
    Master,
}

impl KeySchedule {
    /// Create a new KeySchedule starting at the Early Secret stage
    ///
    /// For TLS 1.3 without PSK (most common case), this initializes with:
    /// ```text
    /// Early Secret = HKDF-Extract(0, 0)
    /// ```
    ///
    /// Where both salt and IKM are 32 zero bytes.
    pub fn new() -> Self {
        let salt = [0u8; HASH_LEN];
        let ikm = [0u8; HASH_LEN]; // No PSK, use zero-filled IKM

        let early_secret = hkdf_extract(Some(&salt), &ikm);

        Self {
            current_secret: early_secret,
            stage: KeyScheduleStage::Early,
        }
    }

    /// Create a new KeySchedule with a pre-shared key (PSK)
    ///
    /// ```text
    /// Early Secret = HKDF-Extract(0, PSK)
    /// ```
    pub fn with_psk(psk: &[u8]) -> Self {
        let salt = [0u8; HASH_LEN];
        let early_secret = hkdf_extract(Some(&salt), psk);

        Self {
            current_secret: early_secret,
            stage: KeyScheduleStage::Early,
        }
    }

    /// Get the current stage of the key schedule
    pub fn stage(&self) -> KeyScheduleStage {
        self.stage
    }

    /// Get the current secret for testing purposes only
    ///
    /// # ⚠️ WARNING: Testing Only
    ///
    /// This method exposes the internal cryptographic secret and should
    /// **ONLY** be used in tests. Do not call this method in production code.
    ///
    /// Exposing cryptographic secrets increases the risk of:
    /// - Accidental logging of sensitive data
    /// - Memory dumps containing secret material
    /// - Timing attacks through debug interfaces
    ///
    /// # Safety
    ///
    /// While this method is marked `pub` to allow integration tests to access it,
    /// it should never be used in production code paths.
    #[doc(hidden)]
    pub fn current_secret_for_testing(&self) -> [u8; HASH_LEN] {
        self.current_secret
    }

    /// Advance from Early Secret to Handshake Secret
    ///
    /// ```text
    /// Handshake Secret = HKDF-Extract(
    ///     Derive-Secret(Early Secret, "derived", ""),
    ///     ECDHE shared secret
    /// )
    /// ```
    ///
    /// # Arguments
    /// * `shared_secret` - The ECDHE shared secret from X25519 key exchange
    ///
    /// # Panics
    /// Panics if not currently in Early stage
    pub fn advance_to_handshake_secret(&mut self, shared_secret: &[u8]) {
        assert_eq!(
            self.stage,
            KeyScheduleStage::Early,
            "Can only advance to Handshake Secret from Early Secret"
        );

        // Derive intermediate secret: Derive-Secret(Early Secret, "derived", "")
        let empty_hash = Sha256::digest(&[]);
        let derived_secret = derive_secret(&self.current_secret, "derived", &empty_hash);

        // Extract with the shared secret
        let handshake_secret = hkdf_extract(Some(&derived_secret), shared_secret);

        self.current_secret = handshake_secret;
        self.stage = KeyScheduleStage::Handshake;
    }

    /// Advance from Handshake Secret to Master Secret
    ///
    /// ```text
    /// Master Secret = HKDF-Extract(
    ///     Derive-Secret(Handshake Secret, "derived", ""),
    ///     0
    /// )
    /// ```
    ///
    /// # Panics
    /// Panics if not currently in Handshake stage
    pub fn advance_to_master_secret(&mut self) {
        assert_eq!(
            self.stage,
            KeyScheduleStage::Handshake,
            "Can only advance to Master Secret from Handshake Secret"
        );

        // Derive intermediate secret: Derive-Secret(Handshake Secret, "derived", "")
        let empty_hash = Sha256::digest(&[]);
        let derived_secret = derive_secret(&self.current_secret, "derived", &empty_hash);

        // Extract with zero-filled IKM
        let zero_ikm = [0u8; HASH_LEN];
        let master_secret = hkdf_extract(Some(&derived_secret), &zero_ikm);

        self.current_secret = master_secret;
        self.stage = KeyScheduleStage::Master;
    }

    /// Derive client handshake traffic secret
    ///
    /// ```text
    /// client_handshake_traffic_secret =
    ///     Derive-Secret(Handshake Secret,
    ///                   "c hs traffic",
    ///                   ClientHello...ServerHello)
    /// ```
    ///
    /// # Arguments
    /// * `transcript_hash` - Hash of ClientHello...ServerHello messages
    ///
    /// # Panics
    /// Panics if not currently in Handshake stage
    pub fn derive_client_handshake_traffic_secret(
        &self,
        transcript_hash: &[u8],
    ) -> [u8; HASH_LEN] {
        assert_eq!(
            self.stage,
            KeyScheduleStage::Handshake,
            "Can only derive handshake traffic secrets in Handshake stage"
        );
        derive_secret(&self.current_secret, "c hs traffic", transcript_hash)
    }

    /// Derive server handshake traffic secret
    ///
    /// ```text
    /// server_handshake_traffic_secret =
    ///     Derive-Secret(Handshake Secret,
    ///                   "s hs traffic",
    ///                   ClientHello...ServerHello)
    /// ```
    ///
    /// # Arguments
    /// * `transcript_hash` - Hash of ClientHello...ServerHello messages
    ///
    /// # Panics
    /// Panics if not currently in Handshake stage
    pub fn derive_server_handshake_traffic_secret(
        &self,
        transcript_hash: &[u8],
    ) -> [u8; HASH_LEN] {
        assert_eq!(
            self.stage,
            KeyScheduleStage::Handshake,
            "Can only derive handshake traffic secrets in Handshake stage"
        );
        derive_secret(&self.current_secret, "s hs traffic", transcript_hash)
    }

    /// Derive client application traffic secret (generation 0)
    ///
    /// ```text
    /// client_application_traffic_secret_0 =
    ///     Derive-Secret(Master Secret,
    ///                   "c ap traffic",
    ///                   ClientHello...server Finished)
    /// ```
    ///
    /// # Arguments
    /// * `transcript_hash` - Hash of ClientHello...server Finished messages
    ///
    /// # Panics
    /// Panics if not currently in Master stage
    pub fn derive_client_application_traffic_secret(
        &self,
        transcript_hash: &[u8],
    ) -> [u8; HASH_LEN] {
        assert_eq!(
            self.stage,
            KeyScheduleStage::Master,
            "Can only derive application traffic secrets in Master stage"
        );
        derive_secret(&self.current_secret, "c ap traffic", transcript_hash)
    }

    /// Derive server application traffic secret (generation 0)
    ///
    /// ```text
    /// server_application_traffic_secret_0 =
    ///     Derive-Secret(Master Secret,
    ///                   "s ap traffic",
    ///                   ClientHello...server Finished)
    /// ```
    ///
    /// # Arguments
    /// * `transcript_hash` - Hash of ClientHello...server Finished messages
    ///
    /// # Panics
    /// Panics if not currently in Master stage
    pub fn derive_server_application_traffic_secret(
        &self,
        transcript_hash: &[u8],
    ) -> [u8; HASH_LEN] {
        assert_eq!(
            self.stage,
            KeyScheduleStage::Master,
            "Can only derive application traffic secrets in Master stage"
        );
        derive_secret(&self.current_secret, "s ap traffic", transcript_hash)
    }

    /// Derive exporter master secret
    ///
    /// ```text
    /// exporter_master_secret =
    ///     Derive-Secret(Master Secret,
    ///                   "exp master",
    ///                   ClientHello...server Finished)
    /// ```
    ///
    /// # Arguments
    /// * `transcript_hash` - Hash of ClientHello...server Finished messages
    ///
    /// # Panics
    /// Panics if not currently in Master stage
    pub fn derive_exporter_master_secret(&self, transcript_hash: &[u8]) -> [u8; HASH_LEN] {
        assert_eq!(
            self.stage,
            KeyScheduleStage::Master,
            "Can only derive exporter master secret in Master stage"
        );
        derive_secret(&self.current_secret, "exp master", transcript_hash)
    }

    /// Derive resumption master secret
    ///
    /// ```text
    /// resumption_master_secret =
    ///     Derive-Secret(Master Secret,
    ///                   "res master",
    ///                   ClientHello...client Finished)
    /// ```
    ///
    /// # Arguments
    /// * `transcript_hash` - Hash of ClientHello...client Finished messages
    ///
    /// # Panics
    /// Panics if not currently in Master stage
    pub fn derive_resumption_master_secret(&self, transcript_hash: &[u8]) -> [u8; HASH_LEN] {
        assert_eq!(
            self.stage,
            KeyScheduleStage::Master,
            "Can only derive resumption master secret in Master stage"
        );
        derive_secret(&self.current_secret, "res master", transcript_hash)
    }
}

impl Default for KeySchedule {
    fn default() -> Self {
        Self::new()
    }
}

/// Derive traffic keys (key and IV) from a traffic secret
///
/// As specified in RFC 8446 Section 7.3:
/// ```text
/// [sender]_write_key = HKDF-Expand-Label(Secret, "key", "", key_length)
/// [sender]_write_iv  = HKDF-Expand-Label(Secret, "iv", "", iv_length)
/// ```
///
/// For AES-128-GCM:
/// - key_length = 16 bytes (128 bits)
/// - iv_length = 12 bytes (96 bits)
///
/// # Arguments
/// * `traffic_secret` - The handshake or application traffic secret
///
/// # Returns
/// `TrafficKeys` containing the derived key and IV
///
/// # Example
/// ```ignore
/// let mut key_schedule = KeySchedule::new();
/// key_schedule.advance_to_handshake_secret(&shared_secret);
/// let transcript_hash = compute_transcript_hash(&messages);
/// let server_secret = key_schedule.derive_server_handshake_traffic_secret(&transcript_hash);
/// let server_keys = derive_traffic_keys(&server_secret);
/// ```
pub fn derive_traffic_keys(traffic_secret: &[u8]) -> TrafficKeys {
    // Derive write key: HKDF-Expand-Label(Secret, "key", "", 16)
    let key_bytes = hkdf_expand_label(traffic_secret, "key", &[], KEY_LEN);
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&key_bytes);

    // Derive write IV: HKDF-Expand-Label(Secret, "iv", "", 12)
    let iv_bytes = hkdf_expand_label(traffic_secret, "iv", &[], IV_LEN);
    let mut iv = [0u8; IV_LEN];
    iv.copy_from_slice(&iv_bytes);

    TrafficKeys::new(key, iv)
}
