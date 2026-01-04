//! Comprehensive tests for X25519 key exchange implementation
//!
//! Tests cover:
//! - Key pair generation
//! - Shared secret computation
//! - Invalid key length rejection (Issue #12 requirement)
//! - Non-canonical value rejection (Issue #12 requirement)
//! - KeyShareEntry parsing and validation
//! - Integration with existing TLS structures

use tls_protocol::error::TlsError;
use tls_protocol::extensions::{KeyShareEntry, NAMED_GROUP_X25519, NAMED_GROUP_SECP256R1};
use tls_protocol::x25519_key_exchange::{
    compute_shared_secret, parse_key_share_entry, X25519KeyPair, X25519_KEY_SIZE,
};

// ============================================================================
// Basic Functionality Tests
// ============================================================================

#[test]
fn test_keypair_generation() {
    let keypair = X25519KeyPair::generate();
    let public_key = keypair.public_key_bytes();

    // Public key should be exactly 32 bytes
    assert_eq!(public_key.len(), X25519_KEY_SIZE);
}

#[test]
fn test_public_key_is_not_all_zeros() {
    let keypair = X25519KeyPair::generate();
    let public_key = keypair.public_key_bytes();

    // Public key should not be all zeros (extremely unlikely with proper random generation)
    assert!(public_key.iter().any(|&b| b != 0));
}

#[test]
fn test_different_keypairs_have_different_keys() {
    let keypair1 = X25519KeyPair::generate();
    let keypair2 = X25519KeyPair::generate();

    // Two different keypairs should have different public keys
    assert_ne!(keypair1.public_key_bytes(), keypair2.public_key_bytes());
}

// ============================================================================
// Shared Secret Computation Tests
// ============================================================================

#[test]
fn test_shared_secret_agreement() {
    // Alice and Bob generate their keypairs
    let alice = X25519KeyPair::generate();
    let bob = X25519KeyPair::generate();

    // Store public keys before moving
    let alice_pub = alice.public_key_bytes();
    let bob_pub = bob.public_key_bytes();

    // Alice computes shared secret using Bob's public key
    let alice_shared = alice
        .compute_shared_secret(&bob_pub)
        .expect("Alice's shared secret computation failed");

    // Bob computes shared secret using Alice's public key
    let bob_shared = bob
        .compute_shared_secret(&alice_pub)
        .expect("Bob's shared secret computation failed");

    // Both should arrive at the same shared secret
    assert_eq!(alice_shared, bob_shared);
}

#[test]
fn test_shared_secret_is_32_bytes() {
    let alice = X25519KeyPair::generate();
    let bob = X25519KeyPair::generate();

    let shared_secret = alice
        .compute_shared_secret(&bob.public_key_bytes())
        .expect("Shared secret computation failed");

    // Shared secret should be exactly 32 bytes for X25519
    assert_eq!(shared_secret.len(), X25519_KEY_SIZE);
}

#[test]
fn test_shared_secret_is_not_all_zeros() {
    let alice = X25519KeyPair::generate();
    let bob = X25519KeyPair::generate();

    let shared_secret = alice
        .compute_shared_secret(&bob.public_key_bytes())
        .expect("Shared secret computation failed");

    // Shared secret should not be all zeros (indicates proper ECDH)
    assert!(shared_secret.iter().any(|&b| b != 0));
}

#[test]
fn test_different_keypairs_produce_different_shared_secrets() {
    let alice1 = X25519KeyPair::generate();
    let alice2 = X25519KeyPair::generate();
    let bob1 = X25519KeyPair::generate();
    let bob2 = X25519KeyPair::generate();

    let bob1_pub = bob1.public_key_bytes();
    let bob2_pub = bob2.public_key_bytes();

    let shared1 = alice1
        .compute_shared_secret(&bob1_pub)
        .expect("First shared secret computation failed");

    let shared2 = alice2
        .compute_shared_secret(&bob2_pub)
        .expect("Second shared secret computation failed");

    // Different peer keys should produce different shared secrets
    assert_ne!(shared1, shared2);
}

#[test]
fn test_compute_shared_secret_standalone_function() {
    let alice = X25519KeyPair::generate();
    let bob = X25519KeyPair::generate();

    // Test the standalone compute_shared_secret function
    let shared = compute_shared_secret(alice.private_key, &bob.public_key_bytes())
        .expect("Standalone shared secret computation failed");

    assert_eq!(shared.len(), X25519_KEY_SIZE);
    assert!(shared.iter().any(|&b| b != 0));
}

// ============================================================================
// Invalid Key Length Tests (Issue #12 Requirement)
// ============================================================================

#[test]
fn test_reject_short_key_in_key_share_entry() {
    // Create KeyShareEntry with key that's too short (31 bytes instead of 32)
    let short_key = vec![0xaa; 31];
    let key_share = KeyShareEntry::new(NAMED_GROUP_X25519, short_key);

    let result = parse_key_share_entry(&key_share);

    // Should reject with InvalidKeyLength error
    assert!(result.is_err());
    match result.unwrap_err() {
        TlsError::InvalidKeyLength(len) => assert_eq!(len, 31),
        _ => panic!("Expected InvalidKeyLength error"),
    }
}

#[test]
fn test_reject_long_key_in_key_share_entry() {
    // Create KeyShareEntry with key that's too long (33 bytes instead of 32)
    let long_key = vec![0xaa; 33];
    let key_share = KeyShareEntry::new(NAMED_GROUP_X25519, long_key);

    let result = parse_key_share_entry(&key_share);

    // Should reject with InvalidKeyLength error
    assert!(result.is_err());
    match result.unwrap_err() {
        TlsError::InvalidKeyLength(len) => assert_eq!(len, 33),
        _ => panic!("Expected InvalidKeyLength error"),
    }
}

#[test]
fn test_reject_empty_key_in_key_share_entry() {
    // Create KeyShareEntry with empty key
    let empty_key = vec![];
    let key_share = KeyShareEntry::new(NAMED_GROUP_X25519, empty_key);

    let result = parse_key_share_entry(&key_share);

    // Should reject with InvalidKeyLength error
    assert!(result.is_err());
    match result.unwrap_err() {
        TlsError::InvalidKeyLength(len) => assert_eq!(len, 0),
        _ => panic!("Expected InvalidKeyLength error"),
    }
}

#[test]
fn test_reject_very_long_key() {
    // Create KeyShareEntry with excessively long key (1024 bytes)
    let very_long_key = vec![0xaa; 1024];
    let key_share = KeyShareEntry::new(NAMED_GROUP_X25519, very_long_key);

    let result = parse_key_share_entry(&key_share);

    // Should reject with InvalidKeyLength error
    assert!(result.is_err());
    match result.unwrap_err() {
        TlsError::InvalidKeyLength(len) => assert_eq!(len, 1024),
        _ => panic!("Expected InvalidKeyLength error"),
    }
}

// ============================================================================
// Non-canonical Value Tests (Issue #12 Requirement)
// ============================================================================

#[test]
fn test_reject_all_zero_public_key() {
    // All-zero public key is weak/invalid
    let zero_key = [0u8; X25519_KEY_SIZE];
    let keypair = X25519KeyPair::generate();

    let result = keypair.compute_shared_secret(&zero_key);

    // Should reject with InvalidPublicKey error
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), TlsError::InvalidPublicKey);
}

#[test]
fn test_reject_all_zero_key_in_key_share_entry() {
    // Create KeyShareEntry with all-zero key
    let zero_key = vec![0u8; X25519_KEY_SIZE];
    let key_share = KeyShareEntry::new(NAMED_GROUP_X25519, zero_key);

    let result = parse_key_share_entry(&key_share);

    // Should reject with InvalidPublicKey error
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), TlsError::InvalidPublicKey);
}

#[test]
fn test_reject_all_zero_key_with_standalone_function() {
    // Test that the standalone compute_shared_secret also rejects all-zero keys
    let zero_key = [0u8; X25519_KEY_SIZE];
    let keypair = X25519KeyPair::generate();

    let result = compute_shared_secret(keypair.private_key, &zero_key);

    // Should reject with InvalidPublicKey error
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), TlsError::InvalidPublicKey);
}

// ============================================================================
// KeyShareEntry Integration Tests
// ============================================================================

#[test]
fn test_to_key_share_entry() {
    let keypair = X25519KeyPair::generate();
    let key_share = keypair.to_key_share_entry();

    // Verify named group is X25519
    assert_eq!(key_share.group, NAMED_GROUP_X25519);

    // Verify key length is correct
    assert_eq!(key_share.key_exchange.len(), X25519_KEY_SIZE);

    // Verify key exchange data matches public key
    assert_eq!(key_share.key_exchange, keypair.public_key_bytes().to_vec());
}

#[test]
fn test_parse_valid_key_share_entry() {
    let keypair = X25519KeyPair::generate();
    let key_share = keypair.to_key_share_entry();

    // Parse the KeyShareEntry
    let parsed_key = parse_key_share_entry(&key_share)
        .expect("Failed to parse valid KeyShareEntry");

    // Verify parsed key matches original public key
    assert_eq!(parsed_key, keypair.public_key_bytes());
}

#[test]
fn test_reject_wrong_named_group() {
    // Create KeyShareEntry with wrong named group (secp256r1 instead of X25519)
    let keypair = X25519KeyPair::generate();
    let key_share = KeyShareEntry::new(NAMED_GROUP_SECP256R1, keypair.public_key_bytes().to_vec());

    let result = parse_key_share_entry(&key_share);

    // Should reject with KeyExchangeFailed error
    assert!(result.is_err());
    match result.unwrap_err() {
        TlsError::KeyExchangeFailed(msg) => {
            assert!(msg.contains("Expected X25519 group"));
            assert!(msg.contains(&format!("0x{:04x}", NAMED_GROUP_X25519)));
            assert!(msg.contains(&format!("0x{:04x}", NAMED_GROUP_SECP256R1)));
        }
        _ => panic!("Expected KeyExchangeFailed error"),
    }
}

#[test]
fn test_reject_unknown_named_group() {
    // Create KeyShareEntry with unknown named group
    let unknown_group = 0x9999;
    let keypair = X25519KeyPair::generate();
    let key_share = KeyShareEntry::new(unknown_group, keypair.public_key_bytes().to_vec());

    let result = parse_key_share_entry(&key_share);

    // Should reject with KeyExchangeFailed error
    assert!(result.is_err());
    match result.unwrap_err() {
        TlsError::KeyExchangeFailed(_) => {}
        _ => panic!("Expected KeyExchangeFailed error"),
    }
}

// ============================================================================
// Full Integration/Round-trip Tests
// ============================================================================

#[test]
fn test_full_key_exchange_flow() {
    // Simulate a full TLS 1.3 key exchange between client and server

    // Step 1: Client generates keypair
    let client_keypair = X25519KeyPair::generate();
    let client_key_share = client_keypair.to_key_share_entry();

    // Step 2: Server receives client's KeyShareEntry and generates its own keypair
    let client_public_key = parse_key_share_entry(&client_key_share)
        .expect("Server failed to parse client's KeyShareEntry");

    let server_keypair = X25519KeyPair::generate();
    let server_key_share = server_keypair.to_key_share_entry();

    // Step 3: Server computes shared secret
    let server_shared = server_keypair
        .compute_shared_secret(&client_public_key)
        .expect("Server failed to compute shared secret");

    // Step 4: Client receives server's KeyShareEntry
    let server_public_key = parse_key_share_entry(&server_key_share)
        .expect("Client failed to parse server's KeyShareEntry");

    // Step 5: Client computes shared secret
    let client_shared = client_keypair
        .compute_shared_secret(&server_public_key)
        .expect("Client failed to compute shared secret");

    // Step 6: Verify both parties computed the same shared secret
    assert_eq!(client_shared, server_shared);

    // Step 7: Verify shared secret is suitable for HKDF (32 bytes, not all zeros)
    assert_eq!(client_shared.len(), X25519_KEY_SIZE);
    assert!(client_shared.iter().any(|&b| b != 0));
}

#[test]
fn test_key_share_entry_roundtrip() {
    // Test that we can create a KeyShareEntry and parse it back
    let original_keypair = X25519KeyPair::generate();
    let original_public_key = original_keypair.public_key_bytes();

    // Create KeyShareEntry
    let key_share = original_keypair.to_key_share_entry();

    // Parse it back
    let parsed_public_key = parse_key_share_entry(&key_share)
        .expect("Failed to parse KeyShareEntry");

    // Verify we get the same public key back
    assert_eq!(parsed_public_key, original_public_key);
}

#[test]
fn test_serialization_with_extension_framework() {
    // Test that KeyShareEntry works with the existing extension serialization
    use tls_protocol::extensions::Extension;

    let keypair = X25519KeyPair::generate();
    let key_share = keypair.to_key_share_entry();

    // Create KeyShare extension
    let extension = Extension::KeyShare(vec![key_share.clone()]);

    // Serialize
    let serialized = extension.to_bytes();

    // Deserialize
    let (deserialized, _) = Extension::from_bytes(&serialized)
        .expect("Failed to deserialize KeyShare extension");

    // Verify it matches
    match deserialized {
        Extension::KeyShare(entries) => {
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].group, NAMED_GROUP_X25519);
            assert_eq!(entries[0].key_exchange, key_share.key_exchange);
        }
        _ => panic!("Expected KeyShare extension"),
    }
}

// ============================================================================
// Edge Cases and Security Tests
// ============================================================================

#[test]
fn test_multiple_key_exchanges_produce_different_secrets() {
    // Verify that the same keypair produces different shared secrets
    // with different peers (basic sanity check)
    let alice1 = X25519KeyPair::generate();
    let alice2 = X25519KeyPair::generate();
    let bob = X25519KeyPair::generate();
    let charlie = X25519KeyPair::generate();

    let bob_pub = bob.public_key_bytes();
    let charlie_pub = charlie.public_key_bytes();

    let shared_with_bob = alice1
        .compute_shared_secret(&bob_pub)
        .expect("Failed to compute shared secret with Bob");

    let shared_with_charlie = alice2
        .compute_shared_secret(&charlie_pub)
        .expect("Failed to compute shared secret with Charlie");

    // Different peers should result in different shared secrets
    assert_ne!(shared_with_bob, shared_with_charlie);
}

#[test]
fn test_shared_secret_suitable_for_hkdf() {
    // Verify that the shared secret has the properties needed for HKDF
    // (RFC 8446 Section 7.1 uses HKDF with the shared secret)
    let alice = X25519KeyPair::generate();
    let bob = X25519KeyPair::generate();

    let shared_secret = alice
        .compute_shared_secret(&bob.public_key_bytes())
        .expect("Failed to compute shared secret");

    // 1. Must be exactly 32 bytes (required by TLS 1.3 key schedule)
    assert_eq!(shared_secret.len(), 32);

    // 2. Should not be all zeros (extremely unlikely with valid ECDH)
    assert!(shared_secret.iter().any(|&b| b != 0));

    // 3. Should have reasonable entropy (not all same byte)
    let first_byte = shared_secret[0];
    assert!(shared_secret.iter().any(|&b| b != first_byte));
}

#[test]
fn test_keypair_generation_is_random() {
    // Generate multiple keypairs and verify they're different
    // (ensures proper randomness)
    let keypairs: Vec<_> = (0..10).map(|_| X25519KeyPair::generate()).collect();

    // All public keys should be different
    for i in 0..keypairs.len() {
        for j in (i + 1)..keypairs.len() {
            assert_ne!(
                keypairs[i].public_key_bytes(),
                keypairs[j].public_key_bytes(),
                "Keypairs {} and {} have the same public key!",
                i,
                j
            );
        }
    }
}
