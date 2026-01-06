//! TLS 1.3 Transcript Hash Manager (RFC 8446, Section 4.4.1)
//!
//! This module implements the transcript hash maintenance for TLS 1.3 handshake.
//! The transcript hash is a running SHA-256 hash of all handshake messages,
//! used for key derivation and authentication.
//!
//! ## Usage
//!
//! ```rust
//! use tls_protocol::TranscriptHash;
//! use tls_protocol::ClientHello;
//!
//! // Create a new transcript hash
//! let mut transcript = TranscriptHash::new();
//!
//! // Update with handshake messages
//! let client_hello = ClientHello::default_tls13([0u8; 32], vec![0xaa; 32]);
//! transcript.update(&client_hello.to_bytes());
//!
//! // Get current hash value (non-consuming)
//! let hash = transcript.current_hash();
//!
//! // Fork the state for different key derivations
//! let handshake_transcript = transcript.clone();
//! ```
//!
//! ## TLS 1.3 Usage Points
//!
//! The transcript hash is used at several points in TLS 1.3:
//! 1. **Handshake Secret Derivation** - After ServerHello
//! 2. **Finished Message** - HMAC over transcript
//! 3. **CertificateVerify** - Server signs transcript hash
//! 4. **Session Resumption** - PSK binder calculation

use sha2::{Digest, Sha256};

/// SHA-256 output size in bytes
pub const HASH_OUTPUT_SIZE: usize = 32;

/// Transcript Hash Manager for TLS 1.3 handshake messages
///
/// Maintains a running SHA-256 hash of all handshake messages.
/// The transcript hash is used for:
/// - Key derivation (input to HKDF)
/// - Finished message verification
/// - CertificateVerify signature
/// - Session resumption PSK binders
///
/// # Examples
///
/// ```rust
/// use tls_protocol::TranscriptHash;
///
/// let mut transcript = TranscriptHash::new();
/// transcript.update(b"ClientHello");
/// transcript.update(b"ServerHello");
/// let hash = transcript.current_hash();
/// ```
#[derive(Clone)]
pub struct TranscriptHash {
    hasher: Sha256,
}

impl TranscriptHash {
    /// Create a new empty transcript hash
    ///
    /// Initializes an empty SHA-256 hasher ready to accept handshake messages.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tls_protocol::TranscriptHash;
    ///
    /// let transcript = TranscriptHash::new();
    /// ```
    pub fn new() -> Self {
        Self {
            hasher: Sha256::new(),
        }
    }

    /// Update the transcript hash with additional message bytes
    ///
    /// Feeds handshake message data into the running hash. Messages should be
    /// added in the order they are sent/received during the handshake.
    ///
    /// # Arguments
    ///
    /// * `data` - The handshake message bytes to add to the transcript
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tls_protocol::TranscriptHash;
    ///
    /// let mut transcript = TranscriptHash::new();
    /// transcript.update(b"ClientHello message bytes");
    /// transcript.update(b"ServerHello message bytes");
    /// ```
    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    /// Get the current hash value without consuming the transcript
    ///
    /// Returns the SHA-256 hash of all messages added so far, while allowing
    /// continued updates to the transcript. This is useful for forking the
    /// hash state at different points in the handshake.
    ///
    /// # Returns
    ///
    /// A 32-byte SHA-256 hash value
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tls_protocol::TranscriptHash;
    ///
    /// let mut transcript = TranscriptHash::new();
    /// transcript.update(b"ClientHello");
    /// 
    /// // Get hash for handshake keys
    /// let handshake_hash = transcript.current_hash();
    /// 
    /// // Continue adding messages
    /// transcript.update(b"ServerHello");
    /// let final_hash = transcript.current_hash();
    /// ```
    pub fn current_hash(&self) -> [u8; HASH_OUTPUT_SIZE] {
        let hasher_clone = self.hasher.clone();
        let result = hasher_clone.finalize();
        let mut hash = [0u8; HASH_OUTPUT_SIZE];
        hash.copy_from_slice(&result);
        hash
    }

    /// Finalize and consume the transcript hash
    ///
    /// Returns the final SHA-256 hash value and consumes the transcript.
    /// Use this when you're done adding messages and won't need the transcript anymore.
    ///
    /// # Returns
    ///
    /// A 32-byte SHA-256 hash value
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tls_protocol::TranscriptHash;
    ///
    /// let mut transcript = TranscriptHash::new();
    /// transcript.update(b"ClientHello");
    /// transcript.update(b"ServerHello");
    /// transcript.update(b"Finished");
    /// 
    /// let final_hash = transcript.finalize();
    /// // transcript is now consumed and cannot be used
    /// ```
    pub fn finalize(self) -> [u8; HASH_OUTPUT_SIZE] {
        let result = self.hasher.finalize();
        let mut hash = [0u8; HASH_OUTPUT_SIZE];
        hash.copy_from_slice(&result);
        hash
    }

    /// Reset the transcript hash to empty state
    ///
    /// Clears all previously added messages and starts fresh.
    /// Useful for session resumption scenarios.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tls_protocol::TranscriptHash;
    ///
    /// let mut transcript = TranscriptHash::new();
    /// transcript.update(b"some data");
    /// 
    /// transcript.reset();
    /// // Now empty again, ready for new messages
    /// ```
    pub fn reset(&mut self) {
        self.hasher = Sha256::new();
    }

    /// Update transcript with a ClientHello message
    ///
    /// Convenience method that serializes a ClientHello and adds it to the transcript.
    ///
    /// # Arguments
    ///
    /// * `client_hello` - The ClientHello message to add
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tls_protocol::{TranscriptHash, ClientHello};
    ///
    /// let mut transcript = TranscriptHash::new();
    /// let client_hello = ClientHello::default_tls13([0u8; 32], vec![0xaa; 32]);
    /// transcript.update_client_hello(&client_hello);
    /// ```
    pub fn update_client_hello(&mut self, client_hello: &crate::ClientHello) {
        self.update(&client_hello.to_bytes());
    }

    /// Update transcript with a ServerHello message
    ///
    /// Convenience method that serializes a ServerHello and adds it to the transcript.
    ///
    /// # Arguments
    ///
    /// * `server_hello` - The ServerHello message to add
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tls_protocol::{TranscriptHash, ServerHello};
    /// use tls_protocol::extensions::{Extension, TLS_VERSION_1_3};
    ///
    /// let mut transcript = TranscriptHash::new();
    /// let server_hello = ServerHello::new(
    ///     [0u8; 32],
    ///     vec![],
    ///     0x1301,
    ///     vec![Extension::SupportedVersions(vec![TLS_VERSION_1_3])],
    /// );
    /// transcript.update_server_hello(&server_hello);
    /// ```
    pub fn update_server_hello(&mut self, server_hello: &crate::ServerHello) {
        self.update(&server_hello.to_bytes());
    }

    /// Get the hash of an empty transcript
    ///
    /// Returns the SHA-256 hash of an empty input, used in some TLS 1.3
    /// derivations (e.g., "derived" secret calculation).
    ///
    /// # Returns
    ///
    /// A 32-byte SHA-256 hash of empty input
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tls_protocol::TranscriptHash;
    ///
    /// let empty_hash = TranscriptHash::empty_hash();
    /// ```
    pub fn empty_hash() -> [u8; HASH_OUTPUT_SIZE] {
        let result = Sha256::digest(&[]);
        let mut hash = [0u8; HASH_OUTPUT_SIZE];
        hash.copy_from_slice(&result);
        hash
    }
}

impl Default for TranscriptHash {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for TranscriptHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TranscriptHash")
            .field("current_hash", &hex_string(&self.current_hash()))
            .finish()
    }
}

/// Helper function to convert bytes to hex string for debug output
fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_transcript() {
        let transcript = TranscriptHash::new();
        let hash = transcript.current_hash();
        
        // Empty hash should match SHA-256 of empty input
        let expected = Sha256::digest(&[]);
        assert_eq!(hash, expected.as_slice());
    }

    #[test]
    fn test_empty_hash() {
        let empty = TranscriptHash::empty_hash();
        let expected = Sha256::digest(&[]);
        assert_eq!(empty, expected.as_slice());
    }

    #[test]
    fn test_single_update() {
        let mut transcript = TranscriptHash::new();
        let data = b"Hello, TLS 1.3!";
        transcript.update(data);
        
        let hash = transcript.current_hash();
        let expected = Sha256::digest(data);
        assert_eq!(hash, expected.as_slice());
    }

    #[test]
    fn test_multiple_updates() {
        let mut transcript = TranscriptHash::new();
        transcript.update(b"ClientHello");
        transcript.update(b"ServerHello");
        
        let hash = transcript.current_hash();
        
        // Should match one-shot hash
        let mut hasher = Sha256::new();
        hasher.update(b"ClientHello");
        hasher.update(b"ServerHello");
        let expected = hasher.finalize();
        
        assert_eq!(hash, expected.as_slice());
    }

    #[test]
    fn test_current_hash_non_consuming() {
        let mut transcript = TranscriptHash::new();
        transcript.update(b"data1");
        
        let hash1 = transcript.current_hash();
        let hash2 = transcript.current_hash();
        
        // Should be identical
        assert_eq!(hash1, hash2);
        
        // Should still be able to update
        transcript.update(b"data2");
        let hash3 = transcript.current_hash();
        
        // Should be different now
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_finalize_consuming() {
        let mut transcript = TranscriptHash::new();
        transcript.update(b"final data");
        
        let final_hash = transcript.finalize();
        
        // Should match expected hash
        let expected = Sha256::digest(b"final data");
        assert_eq!(final_hash, expected.as_slice());
    }

    #[test]
    fn test_clone_forking() {
        let mut transcript = TranscriptHash::new();
        transcript.update(b"ClientHello");
        transcript.update(b"ServerHello");
        
        // Fork at this point
        let mut fork1 = transcript.clone();
        let mut fork2 = transcript.clone();
        
        // All should have same hash initially
        assert_eq!(transcript.current_hash(), fork1.current_hash());
        assert_eq!(transcript.current_hash(), fork2.current_hash());
        
        // Update each independently
        transcript.update(b"original");
        fork1.update(b"fork1");
        fork2.update(b"fork2");
        
        // Should all be different now
        let h1 = transcript.current_hash();
        let h2 = fork1.current_hash();
        let h3 = fork2.current_hash();
        
        assert_ne!(h1, h2);
        assert_ne!(h2, h3);
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_reset() {
        let mut transcript = TranscriptHash::new();
        let empty_hash = transcript.current_hash();
        
        transcript.update(b"some data");
        let with_data = transcript.current_hash();
        assert_ne!(empty_hash, with_data);
        
        transcript.reset();
        let after_reset = transcript.current_hash();
        assert_eq!(empty_hash, after_reset);
    }

    #[test]
    fn test_default_trait() {
        let t1 = TranscriptHash::new();
        let t2 = TranscriptHash::default();
        
        assert_eq!(t1.current_hash(), t2.current_hash());
    }
}
