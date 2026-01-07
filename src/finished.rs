//! TLS 1.3 Finished Message Implementation (RFC 8446, Section 4.4.4)
//!
//! The Finished message is the final message in the authentication block.
//! It is essential for providing authentication of the handshake and computed keys.
//!
//! ## Message Structure
//!
//! ```text
//! struct {
//!     opaque verify_data[Hash.length];
//! } Finished;
//! ```
//!
//! For SHA-256, the `verify_data` is 32 bytes.
//!
//! ## Key Derivation
//!
//! The `finished_key` is derived using HKDF-Expand-Label:
//!
//! ```text
//! finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
//! ```
//!
//! Where BaseKey is:
//! - `client_handshake_traffic_secret` for client Finished
//! - `server_handshake_traffic_secret` for server Finished
//!
//! ## Verify Data Calculation
//!
//! ```text
//! verify_data = HMAC(finished_key, Transcript-Hash(Handshake Context))
//! ```
//!
//! The Transcript-Hash includes all handshake messages up to (but not including)
//! the Finished message being computed.
//!
//! ## Security Considerations
//!
//! - Constant-time comparison prevents timing attacks
//! - Separate keys for client and server prevent reflection attacks
//! - Keys are derived from handshake traffic secrets, ensuring authentication
//!
//! ## Usage
//!
//! ```rust,no_run
//! use tls_protocol::{Finished, TranscriptHash};
//!
//! # fn example(client_secret: &[u8; 32], transcript: &TranscriptHash) {
//! // Client side - Generate Finished message
//! let finished = Finished::generate_client_finished(
//!     client_secret,
//!     &transcript.current_hash()
//! );
//! let finished_bytes = finished.to_bytes();
//!
//! // Server side - Verify Finished message
//! # let server_secret = [0u8; 32];
//! let received_finished = Finished::from_bytes(&finished_bytes).unwrap();
//! received_finished.verify_server_finished(
//!     &server_secret,
//!     &transcript.current_hash()
//! ).unwrap();
//! # }
//! ```

use crate::error::TlsError;
use crate::key_schedule::hkdf_expand_label;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// SHA-256 output size in bytes (also the size of verify_data)
pub const VERIFY_DATA_LEN: usize = 32;

/// TLS 1.3 Handshake message type for Finished
pub const HANDSHAKE_TYPE_FINISHED: u8 = 20;

/// HMAC-SHA256 type alias
type HmacSha256 = Hmac<Sha256>;

/// TLS 1.3 Finished Message
///
/// Contains the `verify_data` which authenticates the handshake.
/// The length is always 32 bytes for SHA-256.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finished {
    /// The HMAC verification data (32 bytes for SHA-256)
    verify_data: [u8; VERIFY_DATA_LEN],
}

impl Finished {
    /// Create a new Finished message with the given verify_data
    ///
    /// # Arguments
    /// * `verify_data` - The HMAC output (32 bytes for SHA-256)
    pub fn new(verify_data: [u8; VERIFY_DATA_LEN]) -> Self {
        Self { verify_data }
    }

    /// Generate a client Finished message
    ///
    /// # Process
    /// 1. Derive `finished_key` from `client_handshake_traffic_secret`
    /// 2. Compute `verify_data = HMAC(finished_key, transcript_hash)`
    /// 3. Return Finished message containing verify_data
    ///
    /// # Arguments
    /// * `client_handshake_traffic_secret` - The client's handshake traffic secret
    /// * `transcript_hash` - Hash of all handshake messages up to (but not including) client Finished
    ///
    /// # Returns
    /// A `Finished` message ready to be sent to the server
    ///
    /// # Example
    /// ```rust,no_run
    /// use tls_protocol::Finished;
    ///
    /// # fn example(client_secret: &[u8; 32], transcript_hash: &[u8; 32]) {
    /// let finished = Finished::generate_client_finished(client_secret, transcript_hash);
    /// let finished_bytes = finished.to_bytes();
    /// // Send finished_bytes to server
    /// # }
    /// ```
    pub fn generate_client_finished(
        client_handshake_traffic_secret: &[u8],
        transcript_hash: &[u8],
    ) -> Self {
        let mut finished_key = derive_finished_key(client_handshake_traffic_secret);
        let verify_data = compute_verify_data(&finished_key, transcript_hash);
        finished_key.zeroize();
        Self::new(verify_data)
    }

    /// Generate a server Finished message
    ///
    /// # Process
    /// 1. Derive `finished_key` from `server_handshake_traffic_secret`
    /// 2. Compute `verify_data = HMAC(finished_key, transcript_hash)`
    /// 3. Return Finished message containing verify_data
    ///
    /// # Arguments
    /// * `server_handshake_traffic_secret` - The server's handshake traffic secret
    /// * `transcript_hash` - Hash of all handshake messages up to (but not including) server Finished
    ///
    /// # Returns
    /// A `Finished` message ready to be sent to the client
    pub fn generate_server_finished(
        server_handshake_traffic_secret: &[u8],
        transcript_hash: &[u8],
    ) -> Self {
        let mut finished_key = derive_finished_key(server_handshake_traffic_secret);
        let verify_data = compute_verify_data(&finished_key, transcript_hash);
        finished_key.zeroize();
        Self::new(verify_data)
    }

    /// Verify a server Finished message (client-side verification)
    ///
    /// # Process
    /// 1. Derive expected `finished_key` from `server_handshake_traffic_secret`
    /// 2. Compute expected `verify_data = HMAC(finished_key, transcript_hash)`
    /// 3. Compare with received verify_data using constant-time comparison
    ///
    /// # Arguments
    /// * `server_handshake_traffic_secret` - The server's handshake traffic secret
    /// * `transcript_hash` - Hash of all handshake messages up to (but not including) server Finished
    ///
    /// # Returns
    /// `Ok(())` if verification succeeds, `Err(TlsError::InvalidFinished)` otherwise
    ///
    /// # Security
    /// Uses constant-time comparison to prevent timing attacks
    ///
    /// # Example
    /// ```rust,no_run
    /// use tls_protocol::Finished;
    ///
    /// # fn example(received_bytes: &[u8], server_secret: &[u8; 32], transcript_hash: &[u8; 32]) -> Result<(), tls_protocol::TlsError> {
    /// let finished = Finished::from_bytes(received_bytes)?;
    /// finished.verify_server_finished(server_secret, transcript_hash)?;
    /// // Server is authenticated
    /// # Ok(())
    /// # }
    /// ```
    pub fn verify_server_finished(
        &self,
        server_handshake_traffic_secret: &[u8],
        transcript_hash: &[u8],
    ) -> Result<(), TlsError> {
        let mut finished_key = derive_finished_key(server_handshake_traffic_secret);
        let mut expected_verify_data = compute_verify_data(&finished_key, transcript_hash);

        // Constant-time comparison to prevent timing attacks
        let result = if self.verify_data.ct_eq(&expected_verify_data).into() {
            Ok(())
        } else {
            Err(TlsError::InvalidFinished)
        };

        finished_key.zeroize();
        expected_verify_data.zeroize();
        
        result
    }

    /// Verify a client Finished message (server-side verification)
    ///
    /// # Process
    /// 1. Derive expected `finished_key` from `client_handshake_traffic_secret`
    /// 2. Compute expected `verify_data = HMAC(finished_key, transcript_hash)`
    /// 3. Compare with received verify_data using constant-time comparison
    ///
    /// # Arguments
    /// * `client_handshake_traffic_secret` - The client's handshake traffic secret
    /// * `transcript_hash` - Hash of all handshake messages up to (but not including) client Finished
    ///
    /// # Returns
    /// `Ok(())` if verification succeeds, `Err(TlsError::InvalidFinished)` otherwise
    ///
    /// # Security
    /// Uses constant-time comparison to prevent timing attacks
    pub fn verify_client_finished(
        &self,
        client_handshake_traffic_secret: &[u8],
        transcript_hash: &[u8],
    ) -> Result<(), TlsError> {
        let mut finished_key = derive_finished_key(client_handshake_traffic_secret);
        let mut expected_verify_data = compute_verify_data(&finished_key, transcript_hash);

        // Constant-time comparison to prevent timing attacks
        let result =if self.verify_data.ct_eq(&expected_verify_data).into() {
            Ok(())
        } else {
            Err(TlsError::InvalidFinished)
        };

        finished_key.zeroize();
        expected_verify_data.zeroize();

        result
    }

    /// Get the verify_data
    ///
    /// # Returns
    /// A reference to the 32-byte verify_data
    pub fn verify_data(&self) -> &[u8; VERIFY_DATA_LEN] {
        &self.verify_data
    }

    /// Serialize the Finished message to bytes
    ///
    /// Format:
    /// ```text
    /// - Handshake message type (1 byte): 0x14 (Finished)
    /// - Length (3 bytes): 0x00 0x00 0x20 (32 bytes)
    /// - verify_data (32 bytes)
    /// ```
    ///
    /// Total: 36 bytes
    ///
    /// # Returns
    /// The serialized Finished message
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(36);

        // Handshake message type (1 byte)
        bytes.push(HANDSHAKE_TYPE_FINISHED);

        // Length (3 bytes) - 32 bytes for verify_data
        let length = VERIFY_DATA_LEN as u32;
        bytes.extend_from_slice(&[
            ((length >> 16) & 0xFF) as u8,
            ((length >> 8) & 0xFF) as u8,
            (length & 0xFF) as u8,
        ]);

        // verify_data (32 bytes)
        bytes.extend_from_slice(&self.verify_data);

        bytes
    }

    /// Deserialize a Finished message from bytes
    ///
    /// Expected format:
    /// ```text
    /// - Handshake message type (1 byte): 0x14 (Finished)
    /// - Length (3 bytes): 0x00 0x00 0x20 (32 bytes)
    /// - verify_data (32 bytes)
    /// ```
    ///
    /// # Arguments
    /// * `bytes` - The serialized Finished message (36 bytes expected)
    ///
    /// # Returns
    /// `Ok(Finished)` if parsing succeeds, `Err(TlsError)` otherwise
    ///
    /// # Errors
    /// - `TlsError::InvalidHandshakeMessage` - If the format is invalid
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TlsError> {
        if bytes.len() < 4 {
            return Err(TlsError::InvalidHandshakeMessage(
                "Finished message too short".to_string(),
            ));
        }

        // Check handshake message type
        if bytes[0] != HANDSHAKE_TYPE_FINISHED {
            return Err(TlsError::InvalidHandshakeMessage(format!(
                "Invalid handshake type for Finished: expected {}, got {}",
                HANDSHAKE_TYPE_FINISHED, bytes[0]
            )));
        }

        // Parse length (3 bytes)
        let length = ((bytes[1] as u32) << 16) | ((bytes[2] as u32) << 8) | (bytes[3] as u32);

        if length != VERIFY_DATA_LEN as u32 {
            return Err(TlsError::InvalidHandshakeMessage(format!(
                "Invalid Finished message length: expected {}, got {}",
                VERIFY_DATA_LEN, length
            )));
        }

        // Check total message length
        let expected_total_len = 4 + VERIFY_DATA_LEN;
        if bytes.len() != expected_total_len {
            return Err(TlsError::InvalidHandshakeMessage(format!(
                "Finished message has incorrect total length: expected {}, got {}",
                expected_total_len,
                bytes.len()
            )));
        }

        // Extract verify_data
        let mut verify_data = [0u8; VERIFY_DATA_LEN];
        verify_data.copy_from_slice(&bytes[4..4 + VERIFY_DATA_LEN]);

        Ok(Self::new(verify_data))
    }

    /// Parse a Finished message from just the payload (without handshake header)
    ///
    /// Expected format: 32 bytes of verify_data
    ///
    /// # Arguments
    /// * `payload` - The verify_data (32 bytes)
    ///
    /// # Returns
    /// `Ok(Finished)` if parsing succeeds, `Err(TlsError)` otherwise
    pub fn from_payload(payload: &[u8]) -> Result<Self, TlsError> {
        if payload.len() != VERIFY_DATA_LEN {
            return Err(TlsError::InvalidHandshakeMessage(format!(
                "Invalid Finished payload length: expected {}, got {}",
                VERIFY_DATA_LEN,
                payload.len()
            )));
        }

        let mut verify_data = [0u8; VERIFY_DATA_LEN];
        verify_data.copy_from_slice(payload);

        Ok(Self::new(verify_data))
    }
}

/// Derive the finished_key from a handshake traffic secret
///
/// ```text
/// finished_key = HKDF-Expand-Label(Secret, "finished", "", Hash.length)
/// ```
///
/// # Arguments
/// * `handshake_traffic_secret` - Client or server handshake traffic secret
///
/// # Returns
/// The derived finished_key (32 bytes for SHA-256)
///
/// # Implementation Note
/// This uses HKDF-Expand-Label with:
/// - Label: "finished"
/// - Context: empty (zero-length)
/// - Length: 32 (SHA-256 output size)
fn derive_finished_key(handshake_traffic_secret: &[u8]) -> [u8; VERIFY_DATA_LEN] {
    let mut expanded = hkdf_expand_label(handshake_traffic_secret, "finished", &[], VERIFY_DATA_LEN);
    let mut finished_key = [0u8; VERIFY_DATA_LEN];
    finished_key.copy_from_slice(&expanded);
    expanded.zeroize();
    finished_key
}

/// Compute verify_data using HMAC-SHA256
///
/// ```text
/// verify_data = HMAC(finished_key, transcript_hash)
/// ```
///
/// # Arguments
/// * `finished_key` - The derived finished_key (32 bytes)
/// * `transcript_hash` - The transcript hash up to this point (32 bytes)
///
/// # Returns
/// The computed verify_data (32 bytes)
fn compute_verify_data(finished_key: &[u8], transcript_hash: &[u8]) -> [u8; VERIFY_DATA_LEN] {
    let mut mac = HmacSha256::new_from_slice(finished_key)
        .expect("HMAC can take key of any size");
    mac.update(transcript_hash);

    let result = mac.finalize();
    let mut verify_data = [0u8; VERIFY_DATA_LEN];
    verify_data.copy_from_slice(&result.into_bytes());

    verify_data
}

impl Drop for Finished {
    /// Zero out sensitive data when dropped
    fn drop(&mut self) {
        self.verify_data.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_finished_serialization() {
        let verify_data = [0xAB; VERIFY_DATA_LEN];
        let finished = Finished::new(verify_data);

        let bytes = finished.to_bytes();

        // Check length (36 bytes total)
        assert_eq!(bytes.len(), 36);

        // Check handshake type
        assert_eq!(bytes[0], HANDSHAKE_TYPE_FINISHED);

        // Check length field (32 bytes)
        assert_eq!(bytes[1], 0x00);
        assert_eq!(bytes[2], 0x00);
        assert_eq!(bytes[3], 0x20);

        // Check verify_data
        assert_eq!(&bytes[4..], &verify_data);
    }

    #[test]
    fn test_finished_deserialization() {
        let verify_data = [0xCD; VERIFY_DATA_LEN];
        let mut bytes = vec![HANDSHAKE_TYPE_FINISHED, 0x00, 0x00, 0x20];
        bytes.extend_from_slice(&verify_data);

        let finished = Finished::from_bytes(&bytes).unwrap();
        assert_eq!(finished.verify_data(), &verify_data);
    }

    #[test]
    fn test_finished_roundtrip() {
        let verify_data = [0x42; VERIFY_DATA_LEN];
        let finished = Finished::new(verify_data);

        let bytes = finished.to_bytes();
        let parsed = Finished::from_bytes(&bytes).unwrap();

        assert_eq!(finished, parsed);
    }

    #[test]
    fn test_finished_from_payload() {
        let verify_data = [0x77; VERIFY_DATA_LEN];
        let finished = Finished::from_payload(&verify_data).unwrap();
        assert_eq!(finished.verify_data(), &verify_data);
    }

    #[test]
    fn test_finished_invalid_type() {
        let mut bytes = vec![0xFF, 0x00, 0x00, 0x20]; // Invalid type
        bytes.extend_from_slice(&[0u8; VERIFY_DATA_LEN]);

        let result = Finished::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_finished_invalid_length() {
        let mut bytes = vec![HANDSHAKE_TYPE_FINISHED, 0x00, 0x00, 0x10]; // Wrong length
        bytes.extend_from_slice(&[0u8; 16]);

        let result = Finished::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_finished_too_short() {
        let bytes = vec![HANDSHAKE_TYPE_FINISHED, 0x00]; // Too short

        let result = Finished::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_derive_finished_key() {
        // Test that derive_finished_key produces consistent output
        let secret = [0x33; 32];
        let key1 = derive_finished_key(&secret);
        let key2 = derive_finished_key(&secret);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_compute_verify_data() {
        // Test that compute_verify_data produces consistent output
        let finished_key = [0x44; 32];
        let transcript_hash = [0x55; 32];

        let verify1 = compute_verify_data(&finished_key, &transcript_hash);
        let verify2 = compute_verify_data(&finished_key, &transcript_hash);
        assert_eq!(verify1, verify2);
    }

    #[test]
    fn test_verify_data_different_inputs() {
        // Test that different inputs produce different verify_data
        let finished_key1 = [0x01; 32];
        let finished_key2 = [0x02; 32];
        let transcript_hash = [0x03; 32];

        let verify1 = compute_verify_data(&finished_key1, &transcript_hash);
        let verify2 = compute_verify_data(&finished_key2, &transcript_hash);
        assert_ne!(verify1, verify2);
    }

    #[test]
    fn test_finished_generation_and_verification() {
        // Test client Finished generation and server verification
        let client_secret = [0x11; 32];
        let transcript_hash = [0x22; 32];

        let client_finished = Finished::generate_client_finished(&client_secret, &transcript_hash);

        // Verification should succeed with correct secret
        assert!(client_finished.verify_client_finished(&client_secret, &transcript_hash).is_ok());

        // Verification should fail with wrong secret
        let wrong_secret = [0x99; 32];
        assert!(client_finished.verify_client_finished(&wrong_secret, &transcript_hash).is_err());

        // Verification should fail with wrong transcript
        let wrong_transcript = [0x88; 32];
        assert!(client_finished.verify_client_finished(&client_secret, &wrong_transcript).is_err());
    }

    #[test]
    fn test_server_finished_generation_and_verification() {
        // Test server Finished generation and client verification
        let server_secret = [0xAA; 32];
        let transcript_hash = [0xBB; 32];

        let server_finished = Finished::generate_server_finished(&server_secret, &transcript_hash);

        // Verification should succeed with correct secret
        assert!(server_finished.verify_server_finished(&server_secret, &transcript_hash).is_ok());

        // Verification should fail with wrong secret
        let wrong_secret = [0xCC; 32];
        assert!(server_finished.verify_server_finished(&wrong_secret, &transcript_hash).is_err());
    }
}
