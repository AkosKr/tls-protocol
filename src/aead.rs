//! AES-128-GCM Authenticated Encryption with Associated Data (AEAD) for TLS 1.3
//!
//! This module implements authenticated encryption and decryption for TLS 1.3 records
//! using AES-128-GCM as specified in RFC 8446 Section 5.2 and RFC 5116.
//!
//! # AEAD Properties
//! - **Confidentiality**: AES-128 in Galois/Counter Mode (GCM)
//! - **Authentication**: 128-bit authentication tag (prevents tampering)
//! - **Key Size**: 16 bytes (128 bits)
//! - **IV Size**: 12 bytes (96 bits)
//! - **Nonce**: Per-record, constructed by XORing sequence number with IV
//!
//! # TLS 1.3 Record Encryption (RFC 8446 Section 5.2)
//!
//! ```text
//! struct {
//!     opaque content[TLSPlaintext.length];
//!     ContentType type;
//!     uint8 zeros[length_of_padding];
//! } TLSInnerPlaintext;
//!
//! struct {
//!     ContentType opaque_type = application_data; /* 23 */
//!     ProtocolVersion legacy_record_version = 0x0303; /* TLS v1.2 */
//!     uint16 length;
//!     opaque encrypted_record[TLSCiphertext.length];
//! } TLSCiphertext;
//! ```
//!
//! The encrypted_record field is the AEAD-encrypted form of TLSInnerPlaintext.
//!
//! # Nonce Construction (RFC 8446 Section 5.3)
//!
//! ```text
//! The per-record nonce for the AEAD construction is formed as follows:
//!
//! 1. The 64-bit record sequence number is encoded in network byte order
//!    and padded to the left with zeros to iv_length.
//!
//! 2. The padded sequence number is XORed with either the static
//!    client_write_iv or server_write_iv (depending on the role).
//!
//! The resulting quantity (of length iv_length) is used as the per-record nonce.
//! ```
//!
//! # Additional Authenticated Data (AAD)
//!
//! The AAD for AEAD is the TLS record header:
//! ```text
//! additional_data = TLSCiphertext.opaque_type ||
//!                   TLSCiphertext.legacy_record_version ||
//!                   TLSCiphertext.length
//! ```
//!
//! # Security Considerations
//!
//! ## Nonce Uniqueness and Sequence Numbers
//! - Sequence numbers must never repeat for a given key
//! - Maximum of 2^64-1 records can be encrypted per traffic secret
//! - After sequence number exhaustion, traffic keys must be updated
//!
//! ## Authentication and Error Handling
//! - Failed authentication MUST result in connection termination
//! - No distinction should be made between different types of auth failures
//!
//! ## Constant-Time Guarantees and Timing Side-Channels
//! This implementation uses a **defense-in-depth** approach to timing side-channels:
//!
//! 1. **Cryptographic Layer** (constant-time, provided by `aes-gcm` crate):
//!    - AES-GCM encryption and decryption operations
//!    - Authentication tag verification using constant-time comparison
//!    - These operations do not leak information about plaintext or key material
//!
//! 2. **Protocol Layer** (this module, may leak some timing):
//!    - Length validation and bounds checking (happens before crypto)
//!    - Record format validation
//!    - These checks may introduce timing variations for obviously malformed records
//!
//! **Rationale**: Length checks fail-fast for performance and reject records that would
//! fail authentication anyway. The critical security property—indistinguishability between
//! decryption and authentication failures—is preserved by the constant-time crypto layer.
//! An attacker cannot use timing to distinguish between "bad padding" and "bad MAC" because
//! AES-GCM has no padding, and tag verification is constant-time.
//!
//! ## Key Management
//! - Keys and IVs are zeroized on drop (via `ZeroizeOnDrop` trait)
//! - Traffic keys should be rotated regularly (TLS 1.3 key update mechanism)
//! - Never reuse keys across different connections
//!
//! ## Implementation Dependencies
//! - **`aes-gcm` crate**: Provides the core AES-GCM implementation with constant-time
//!   guarantees for encryption, decryption, and authentication tag operations
//! - **`zeroize` crate**: Ensures sensitive key material is securely erased from memory

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes128Gcm, Nonce,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::TlsError;

/// AES-128-GCM key size in bytes (128 bits)
pub const KEY_SIZE: usize = 16;

/// AES-128-GCM IV size in bytes (96 bits)
pub const IV_SIZE: usize = 12;

/// AES-128-GCM authentication tag size in bytes (128 bits)
pub const TAG_SIZE: usize = 16;

/// Maximum TLS 1.3 plaintext record size (2^14 bytes = 16KB)
pub const MAX_PLAINTEXT_SIZE: usize = 16384;

/// Maximum TLS 1.3 ciphertext record size (plaintext + tag + content type)
/// = 2^14 + 256 bytes
pub const MAX_CIPHERTEXT_SIZE: usize = MAX_PLAINTEXT_SIZE + 256;

/// Traffic keys derived from a traffic secret
///
/// Contains the key and IV needed for AEAD encryption/decryption.
/// These are derived from the handshake or application traffic secrets
/// using HKDF-Expand-Label (see RFC 8446 Section 7.3).
///
/// # Security
/// - Fields are private to prevent accidental exposure or misuse
/// - Implements `ZeroizeOnDrop` to securely erase key material when dropped
/// - No accessor methods provided - keys should only be used via `AeadCipher`
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct TrafficKeys {
    /// AES-128 encryption key (16 bytes)
    key: [u8; KEY_SIZE],
    /// Initialization vector / write IV (12 bytes)
    iv: [u8; IV_SIZE],
}

impl TrafficKeys {
    /// Create new traffic keys from raw key and IV bytes
    ///
    /// # Arguments
    /// * `key` - 16-byte AES-128 key
    /// * `iv` - 12-byte initialization vector
    pub fn new(key: [u8; KEY_SIZE], iv: [u8; IV_SIZE]) -> Self {
        Self { key, iv }
    }
}

impl std::fmt::Debug for TrafficKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrafficKeys")
            .field("key", &"<redacted>")
            .field("iv", &"<redacted>")
            .finish()
    }
}

/// AES-128-GCM AEAD cipher for TLS 1.3 record encryption
///
/// Manages encryption and decryption of TLS 1.3 records using AES-128-GCM.
/// Handles per-record nonce construction and maintains sequence numbers.
///
/// # Example
/// ```ignore
/// let traffic_keys = TrafficKeys::new(key, iv);
/// let mut cipher = AeadCipher::new(traffic_keys);
///
/// // Encrypt a record
/// let plaintext = b"Hello, TLS 1.3!";
/// let aad = &[0x17, 0x03, 0x03, 0x00, 0x10]; // Record header
/// let ciphertext = cipher.encrypt(plaintext, aad)?;
///
/// // Decrypt a record
/// let decrypted = cipher.decrypt(&ciphertext, aad)?;
/// assert_eq!(plaintext, &decrypted[..]);
/// ```
pub struct AeadCipher {
    /// AES-128-GCM cipher instance
    cipher: Aes128Gcm,
    /// Write IV (XORed with sequence number to create nonce)
    iv: [u8; IV_SIZE],
    /// Sequence number for nonce generation (incremented per record)
    sequence_number: u64,
}

impl AeadCipher {
    /// Create a new AEAD cipher from traffic keys
    ///
    /// Initializes the cipher with sequence number 0.
    ///
    /// # Arguments
    /// * `keys` - Traffic keys containing the AES key and IV
    pub fn new(keys: TrafficKeys) -> Self {
        let cipher = Aes128Gcm::new_from_slice(&keys.key)
            .expect("Invalid key length for AES-128-GCM");

        Self {
            cipher,
            iv: keys.iv,
            sequence_number: 0,
        }
    }

    /// Construct a per-record nonce from the sequence number
    ///
    /// Per RFC 8446 Section 5.3:
    /// 1. Encode the 64-bit sequence number in network byte order (big-endian)
    /// 2. Pad to the left with zeros to IV length (12 bytes)
    /// 3. XOR with the write IV
    ///
    /// # Arguments
    /// * `seq_num` - The 64-bit record sequence number
    ///
    /// # Returns
    /// A 12-byte nonce for this specific record
    fn construct_nonce(&self, seq_num: u64) -> [u8; IV_SIZE] {
        let mut nonce = [0u8; IV_SIZE];

        // Encode sequence number as 64-bit big-endian, padded to 12 bytes
        // First 4 bytes are zeros (padding), last 8 bytes are the sequence number
        let seq_bytes = seq_num.to_be_bytes();
        nonce[IV_SIZE - 8..].copy_from_slice(&seq_bytes);

        // XOR with the write IV
        for (nonce_byte, iv_byte) in nonce.iter_mut().zip(self.iv.iter()) {
            *nonce_byte ^= iv_byte;
        }

        nonce
    }

    /// Encrypt a TLS record using AES-128-GCM
    ///
    /// # Arguments
    /// * `plaintext` - The plaintext data to encrypt
    /// * `aad` - Additional Authenticated Data (typically the TLS record header)
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - Ciphertext (plaintext encrypted + 16-byte authentication tag)
    /// * `Err(TlsError::EncryptionFailed)` - If encryption fails
    ///
    /// # Side Effects
    /// Increments the internal sequence number after successful encryption.
    ///
    /// # Security Notes
    /// - The sequence number must never repeat for a given key
    /// - Maximum of 2^64-1 records can be encrypted
    /// - After 2^64-1 records, the traffic secret must be rotated
    pub fn encrypt(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, TlsError> {
        // Validate plaintext size
        if plaintext.len() > MAX_PLAINTEXT_SIZE {
            return Err(TlsError::RecordTooLarge);
        }

        // Construct nonce for this record
        let nonce = self.construct_nonce(self.sequence_number);
        let nonce_ref = Nonce::from_slice(&nonce);

        // Prepare payload with AAD
        let payload = Payload {
            msg: plaintext,
            aad,
        };

        // Encrypt with AEAD
        let ciphertext = self
            .cipher
            .encrypt(nonce_ref, payload)
            .map_err(|_| TlsError::EncryptionFailed)?;

        // Increment sequence number for next record
        self.sequence_number = self
            .sequence_number
            .checked_add(1)
            .ok_or(TlsError::SequenceNumberOverflow)?;

        Ok(ciphertext)
    }

    /// Decrypt a TLS record using AES-128-GCM
    ///
    /// # Arguments
    /// * `ciphertext` - The encrypted data (includes 16-byte authentication tag)
    /// * `aad` - Additional Authenticated Data (must match what was used in encryption)
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - Decrypted plaintext
    /// * `Err(TlsError)` - If validation, decryption, or authentication fails
    ///
    /// # Side Effects
    /// Increments the internal sequence number after successful decryption.
    ///
    /// # Security Notes
    /// - Authentication tag verification MUST succeed before returning plaintext
    /// - Failed authentication indicates tampering and MUST terminate the connection
    /// - **Constant-time guarantees**: This implementation relies on the `aes-gcm` crate
    ///   for constant-time cryptographic operations (AES-GCM encryption/decryption and
    ///   authentication tag verification). However, this layer performs length validation
    ///   checks that may introduce timing side-channels for invalid inputs (e.g., records
    ///   that are too short or too long). These checks occur before cryptographic processing
    ///   and are considered acceptable as they reject malformed records that wouldn't pass
    ///   authentication anyway. Once a record reaches the cryptographic layer, the underlying
    ///   `aes-gcm` crate provides constant-time guarantees for decryption and authentication.
    ///   
    ///   **Defense strategy**: Distinguish between:
    ///   1. Format validation (may leak timing): length checks, basic sanity checks
    ///   2. Cryptographic operations (constant-time): decryption and tag verification
    ///   
    ///   This is a defense-in-depth approach where catastrophic failures (authentication
    ///   failures) are protected by constant-time crypto, while benign format errors can
    ///   fail fast for better performance.
    pub fn decrypt(&mut self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, TlsError> {
        // Early validation: reject obviously invalid records before crypto operations
        // Note: These checks may leak timing information, but only for malformed records
        // that would fail authentication anyway. This is an acceptable trade-off.
        if ciphertext.len() < TAG_SIZE {
            return Err(TlsError::InvalidLength(ciphertext.len() as u16));
        }

        if ciphertext.len() > MAX_CIPHERTEXT_SIZE {
            return Err(TlsError::RecordTooLarge);
        }

        // Construct nonce for this record
        let nonce = self.construct_nonce(self.sequence_number);
        let nonce_ref = Nonce::from_slice(&nonce);

        // Prepare payload with AAD
        let payload = Payload {
            msg: ciphertext,
            aad,
        };

        // Decrypt and verify AEAD tag
        // The aes-gcm crate provides constant-time guarantees for this operation.
        // Both decryption and authentication tag verification are performed in
        // constant time to prevent timing attacks that could distinguish between
        // decryption failures and authentication failures.
        let plaintext = self
            .cipher
            .decrypt(nonce_ref, payload)
            .map_err(|_| TlsError::DecryptionFailed)?;

        // Increment sequence number for next record
        // This happens after successful decryption, so no timing leak risk here
        // (the expensive crypto operation dominates timing measurements)
        self.sequence_number = self
            .sequence_number
            .checked_add(1)
            .ok_or(TlsError::SequenceNumberOverflow)?;

        Ok(plaintext)
    }

    /// Get the current sequence number
    ///
    /// Useful for debugging and testing. In production, sequence numbers should
    /// generally be treated as internal state: avoid exposing them across API
    /// boundaries or modifying them directly. They may be logged or monitored
    /// to detect anomalies (e.g., unexpected resets, gaps, or approaching the
    /// `u64` limit that would cause `TlsError::SequenceNumberOverflow`), but
    /// application logic should not depend on specific sequence number values.
    pub fn sequence_number(&self) -> u64 {
        self.sequence_number
    }

    /// Update the cipher with new traffic keys and reset sequence number
    ///
    /// This method provides a safe way to transition to new traffic keys
    /// (e.g., during key update). The sequence number is automatically reset
    /// to zero when new keys are installed, preventing nonce reuse with the old key.
    ///
    /// # Security
    /// This is the ONLY safe way to reset the sequence number. Resetting the
    /// sequence number while continuing to use the same key would violate
    /// AES-GCM security guarantees and lead to catastrophic nonce reuse.
    ///
    /// # Arguments
    /// * `keys` - New traffic keys to install
    ///
    /// # Example
    /// ```ignore
    /// // After key update in TLS 1.3
    /// let new_keys = derive_traffic_keys(&new_secret);
    /// cipher.update_keys(new_keys);
    /// // Sequence number is now 0 with the new key
    /// ```
    pub fn update_keys(&mut self, keys: TrafficKeys) {
        self.cipher = Aes128Gcm::new_from_slice(&keys.key)
            .expect("Invalid key length for AES-128-GCM");
        self.iv = keys.iv;
        self.sequence_number = 0;
    }
}

impl std::fmt::Debug for AeadCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AeadCipher")
            .field("iv", &"<redacted>")
            .field("sequence_number", &self.sequence_number)
            .finish()
    }
}

/// Encrypt a TLS 1.3 inner plaintext (content + content type + padding)
///
/// This is a convenience function that handles the TLS 1.3 record format:
/// - Appends the content type byte
/// - Optionally adds padding zeros
/// - Encrypts the combined data
///
/// # Arguments
/// * `cipher` - The AEAD cipher to use
/// * `content` - The plaintext content to encrypt
/// * `content_type` - The actual content type (will be encrypted)
/// * `aad` - Additional authenticated data (record header)
/// * `padding_len` - Number of zero bytes to append (for traffic analysis resistance)
///
/// # Returns
/// * `Ok(Vec<u8>)` - Encrypted TLSInnerPlaintext (content + type + padding + tag)
/// * `Err(TlsError)` - If encryption fails or record too large
pub fn encrypt_record(
    cipher: &mut AeadCipher,
    content: &[u8],
    content_type: u8,
    aad: &[u8],
    padding_len: usize,
) -> Result<Vec<u8>, TlsError> {
    // Build TLSInnerPlaintext: content || content_type || padding
    let mut inner_plaintext = Vec::with_capacity(content.len() + 1 + padding_len);
    inner_plaintext.extend_from_slice(content);
    inner_plaintext.push(content_type);
    inner_plaintext.extend(std::iter::repeat_n(0u8, padding_len));

    // Encrypt
    cipher.encrypt(&inner_plaintext, aad)
}

/// Decrypt a TLS 1.3 encrypted record and extract content type
///
/// This is a convenience function that:
/// - Decrypts the ciphertext
/// - Strips padding zeros from the end
/// - Extracts the content type byte
/// - Returns the plaintext content
///
/// # Arguments
/// * `cipher` - The AEAD cipher to use
/// * `ciphertext` - The encrypted record
/// * `aad` - Additional authenticated data (must match encryption)
///
/// # Returns
/// * `Ok((Vec<u8>, u8))` - Tuple of (plaintext content, content type)
/// * `Err(TlsError)` - If decryption fails or format is invalid
pub fn decrypt_record(
    cipher: &mut AeadCipher,
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, u8), TlsError> {
    // Decrypt to get TLSInnerPlaintext
    let inner_plaintext = cipher.decrypt(ciphertext, aad)?;

    if inner_plaintext.is_empty() {
        return Err(TlsError::InvalidRecord);
    }

    // Find the content type by scanning backwards for the first non-zero byte
    // Per RFC 8446 Section 5.2: TLSInnerPlaintext = content || ContentType || zeros[padding]
    // The ContentType byte is always non-zero, serving as a delimiter between content and padding
    let mut content_type_pos = inner_plaintext.len() - 1;
    while content_type_pos > 0 && inner_plaintext[content_type_pos] == 0 {
        content_type_pos -= 1;
    }

    // Extract content type
    let content_type = inner_plaintext[content_type_pos];

    // Validate that content type is non-zero (RFC 8446: ContentType 0 is invalid)
    // This ensures we found a valid delimiter and not just all zeros
    if content_type == 0 {
        return Err(TlsError::InvalidRecord);
    }

    // Extract content (everything before content type and padding)
    let content = inner_plaintext[..content_type_pos].to_vec();

    Ok((content, content_type))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test nonce construction as per RFC 8446 Section 5.3
    #[test]
    fn test_nonce_construction() {
        let iv = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let key = [0u8; KEY_SIZE];
        let keys = TrafficKeys::new(key, iv);
        let cipher = AeadCipher::new(keys);

        // Sequence number 0
        // Padded seq: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        // XOR with IV gives IV back
        let nonce_0 = cipher.construct_nonce(0);
        assert_eq!(nonce_0, iv);

        // Sequence number 1
        // Padded seq: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        // XOR with IV: [1^1, 2^0, 3^0, 4^0, 5^0, 6^0, 7^0, 8^0, 9^0, a^0, b^0, c^1]
        let nonce_1 = cipher.construct_nonce(1);
        let expected_1 = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0d,
        ];
        assert_eq!(nonce_1, expected_1);

        // Sequence number 256 (0x100)
        // Padded seq: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]
        // XOR with IV: [1^0, 2^0, 3^0, 4^0, 5^0, 6^0, 7^0, 8^0, 9^0, a^0, b^1, c^0]
        let nonce_256 = cipher.construct_nonce(256);
        let expected_256 = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0a, 0x0c,
        ];
        assert_eq!(nonce_256, expected_256);
    }

    /// Test that sequence numbers increment correctly
    #[test]
    fn test_sequence_number_increment() {
        let keys = TrafficKeys::new([0u8; KEY_SIZE], [0u8; IV_SIZE]);
        let mut cipher = AeadCipher::new(keys);

        assert_eq!(cipher.sequence_number(), 0);

        let plaintext = b"test";
        let aad = &[0x17, 0x03, 0x03, 0x00, 0x04];

        cipher.encrypt(plaintext, aad).unwrap();
        assert_eq!(cipher.sequence_number(), 1);

        cipher.encrypt(plaintext, aad).unwrap();
        assert_eq!(cipher.sequence_number(), 2);
    }

    /// Test basic encrypt/decrypt round-trip
    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; KEY_SIZE];
        let iv = [0x13u8; IV_SIZE];
        
        // Use separate cipher instances for encryption and decryption
        // to maintain proper sequence numbers
        let mut encrypt_cipher = AeadCipher::new(TrafficKeys::new(key, iv));
        let mut decrypt_cipher = AeadCipher::new(TrafficKeys::new(key, iv));

        let plaintext = b"Hello, TLS 1.3!";
        let aad = &[0x17, 0x03, 0x03, 0x00, 0x0f];

        let ciphertext = encrypt_cipher.encrypt(plaintext, aad).unwrap();
        assert_ne!(ciphertext.as_slice(), plaintext);
        assert_eq!(ciphertext.len(), plaintext.len() + TAG_SIZE);

        let decrypted = decrypt_cipher.decrypt(&ciphertext, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
