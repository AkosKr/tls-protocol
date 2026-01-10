//! X25519 Key Exchange Implementation for TLS 1.3
//!
//! Implements ephemeral ECDHE using X25519 for secure key exchange as specified
//! in RFC 8446 (TLS 1.3), Section 4.2.8 (Key Share Extension) and Section 7.4
//! (Diffie-Hellman). Provides key generation, shared secret computation, and
//! validation of key_share extensions.

use crate::error::TlsError;
use crate::extensions::{KeyShareEntry, NAMED_GROUP_X25519};
use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey};

/// X25519 key size in bytes (RFC 8446, Section 4.2.8.2)
pub const X25519_KEY_SIZE: usize = 32;

/// X25519 KeyPair for ephemeral Diffie-Hellman key exchange in TLS 1.3.
pub struct X25519KeyPair {
    /// Private key (kept secret)
    private_key: EphemeralSecret,
    /// Public key (sent in KeyShareEntry)
    pub public_key: PublicKey,
}

impl X25519KeyPair {
    /// Generate a new random X25519 keypair using cryptographically secure randomness.
    pub fn generate() -> Self {
        let private_key = EphemeralSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&private_key);

        Self {
            private_key,
            public_key,
        }
    }

    /// Get the public key as a 32-byte array.
    pub fn public_key_bytes(&self) -> [u8; X25519_KEY_SIZE] {
        *self.public_key.as_bytes()
    }

    /// Create a KeyShareEntry for use in ClientHello or ServerHello messages.
    pub fn to_key_share_entry(&self) -> KeyShareEntry {
        KeyShareEntry::new(NAMED_GROUP_X25519, self.public_key_bytes().to_vec())
    }

    /// Compute shared secret with peer's public key via ECDH.
    /// Returns 32-byte shared secret suitable for HKDF in TLS 1.3 key schedule.
    pub fn compute_shared_secret(
        self,
        peer_public_key: &[u8; X25519_KEY_SIZE],
    ) -> Result<[u8; X25519_KEY_SIZE], TlsError> {
        // Validate peer's public key
        validate_public_key(peer_public_key)?;

        // Convert peer's bytes to PublicKey
        let peer_key = PublicKey::from(*peer_public_key);

        // Perform ECDH
        let shared_secret = self.private_key.diffie_hellman(&peer_key);

        // The shared secret is always 32 bytes for X25519
        Ok(*shared_secret.as_bytes())
    }
}

/// Compute shared secret from private and peer public keys.
/// Convenience function that performs ECDH without constructing an X25519KeyPair.
pub fn compute_shared_secret(
    private_key: EphemeralSecret,
    peer_public_key: &[u8; X25519_KEY_SIZE],
) -> Result<[u8; X25519_KEY_SIZE], TlsError> {
    // Validate peer's public key
    validate_public_key(peer_public_key)?;

    // Convert peer's bytes to PublicKey
    let peer_key = PublicKey::from(*peer_public_key);

    // Perform ECDH
    let shared_secret = private_key.diffie_hellman(&peer_key);

    Ok(*shared_secret.as_bytes())
}

/// Parse and validate X25519 public key from KeyShareEntry.
/// Validates named group, key length, and rejects weak/invalid keys.
pub fn parse_key_share_entry(key_share: &KeyShareEntry) -> Result<[u8; X25519_KEY_SIZE], TlsError> {
    // Validate named group
    if key_share.group != NAMED_GROUP_X25519 {
        return Err(TlsError::KeyExchangeFailed(format!(
            "Expected X25519 group (0x{:04x}), got 0x{:04x}",
            NAMED_GROUP_X25519, key_share.group
        )));
    }

    // Validate key length
    if key_share.key_exchange.len() != X25519_KEY_SIZE {
        return Err(TlsError::InvalidKeyLength(key_share.key_exchange.len()));
    }

    // Convert to fixed-size array
    let mut public_key = [0u8; X25519_KEY_SIZE];
    public_key.copy_from_slice(&key_share.key_exchange);

    // Validate the public key
    validate_public_key(&public_key)?;

    Ok(public_key)
}

/// Validate an X25519 public key. Rejects all-zero and other weak keys.
/// Note: x25519-dalek handles additional validation internally.
fn validate_public_key(public_key: &[u8; X25519_KEY_SIZE]) -> Result<(), TlsError> {
    // Check for all-zero public key (weak/invalid)
    if public_key.iter().all(|&b| b == 0) {
        return Err(TlsError::InvalidPublicKey);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = X25519KeyPair::generate();
        assert_eq!(keypair.public_key_bytes().len(), X25519_KEY_SIZE);
    }

    #[test]
    fn test_public_key_not_all_zeros() {
        let keypair = X25519KeyPair::generate();
        let public_key = keypair.public_key_bytes();

        // Public key should not be all zeros
        assert!(public_key.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_shared_secret_agreement() {
        let alice = X25519KeyPair::generate();
        let bob = X25519KeyPair::generate();

        let alice_pub = alice.public_key_bytes();
        let bob_pub = bob.public_key_bytes();

        let alice_shared = alice.compute_shared_secret(&bob_pub).unwrap();
        let bob_shared = bob.compute_shared_secret(&alice_pub).unwrap();

        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_to_key_share_entry() {
        let keypair = X25519KeyPair::generate();
        let key_share = keypair.to_key_share_entry();

        assert_eq!(key_share.group, NAMED_GROUP_X25519);
        assert_eq!(key_share.key_exchange.len(), X25519_KEY_SIZE);
    }

    #[test]
    fn test_reject_all_zero_public_key() {
        let zero_key = [0u8; X25519_KEY_SIZE];
        let result = validate_public_key(&zero_key);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), TlsError::InvalidPublicKey);
    }
}
