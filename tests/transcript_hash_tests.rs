//! Tests for TLS 1.3 Transcript Hash Manager
//!
//! This test suite validates the transcript hash implementation as specified in:
//! - RFC 8446 Section 4.4.1 (Transcript Hash definition)
//! - RFC 6234 (SHA-256 specification)
//!
//! Includes:
//! - Basic hash operations (empty, single, multiple updates)
//! - Incremental vs one-shot hashing verification
//! - Hash forking/snapshot functionality
//! - State management (reset, clone)
//! - Integration with TLS messages (ClientHello, ServerHello)
//! - Real TLS 1.3 handshake scenarios

use sha2::{Digest, Sha256};
use tls_protocol::{TranscriptHash, ClientHello, ServerHello};
use tls_protocol::extensions::{Extension, KeyShareEntry, TLS_VERSION_1_3, NAMED_GROUP_X25519};

/// Helper function to convert hex strings to byte vectors
fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let hex = hex.replace(|c: char| c.is_whitespace(), "");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// Helper function to convert bytes to hex string
#[allow(dead_code)]
fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ============================================================================
// Basic Functionality Tests
// ============================================================================

#[test]
fn test_new_transcript_empty_hash() {
    let transcript = TranscriptHash::new();
    let hash = transcript.current_hash();
    
    // Empty transcript should produce SHA-256 of empty input
    let expected = Sha256::digest(&[]);
    assert_eq!(hash.len(), 32);
    assert_eq!(hash, expected.as_slice());
}

#[test]
fn test_empty_hash_static_method() {
    let empty = TranscriptHash::empty_hash();
    let expected = Sha256::digest(&[]);
    
    assert_eq!(empty.len(), 32);
    assert_eq!(empty, expected.as_slice());
}

#[test]
fn test_single_update() {
    let mut transcript = TranscriptHash::new();
    let data = b"Test message for TLS 1.3 transcript";
    
    transcript.update(data);
    let hash = transcript.current_hash();
    
    let expected = Sha256::digest(data);
    assert_eq!(hash, expected.as_slice());
}

#[test]
fn test_multiple_sequential_updates() {
    let mut transcript = TranscriptHash::new();
    
    transcript.update(b"ClientHello");
    transcript.update(b"ServerHello");
    transcript.update(b"EncryptedExtensions");
    
    let hash = transcript.current_hash();
    
    // Verify matches one-shot hash
    let expected = Sha256::digest(b"ClientHelloServerHelloEncryptedExtensions");
    assert_eq!(hash, expected.as_slice());
}

#[test]
fn test_empty_update() {
    let mut transcript = TranscriptHash::new();
    transcript.update(b"");
    
    let hash = transcript.current_hash();
    let expected = Sha256::digest(&[]);
    
    assert_eq!(hash, expected.as_slice());
}

#[test]
fn test_large_update() {
    let mut transcript = TranscriptHash::new();
    let large_data = vec![0x42u8; 10000];
    
    transcript.update(&large_data);
    let hash = transcript.current_hash();
    
    let expected = Sha256::digest(&large_data);
    assert_eq!(hash, expected.as_slice());
}

// ============================================================================
// Incremental vs One-Shot Hashing Tests
// ============================================================================

#[test]
fn test_incremental_vs_oneshot_simple() {
    // Incremental hashing
    let mut transcript = TranscriptHash::new();
    transcript.update(b"Hello, ");
    transcript.update(b"TLS 1.3!");
    let incremental_hash = transcript.current_hash();
    
    // One-shot hashing
    let oneshot_hash = Sha256::digest(b"Hello, TLS 1.3!");
    
    assert_eq!(incremental_hash, oneshot_hash.as_slice());
}

#[test]
fn test_incremental_vs_oneshot_multiple_messages() {
    // Incremental
    let mut transcript = TranscriptHash::new();
    let messages = [
        b"ClientHello" as &[u8],
        b"ServerHello",
        b"EncryptedExtensions",
        b"Certificate",
        b"CertificateVerify",
        b"Finished",
    ];
    
    for msg in &messages {
        transcript.update(msg);
    }
    let incremental_hash = transcript.current_hash();
    
    // One-shot
    let mut combined = Vec::new();
    for msg in &messages {
        combined.extend_from_slice(msg);
    }
    let oneshot_hash = Sha256::digest(&combined);
    
    assert_eq!(incremental_hash, oneshot_hash.as_slice());
}

#[test]
fn test_incremental_vs_oneshot_with_different_chunk_sizes() {
    let data = b"The quick brown fox jumps over the lazy dog";
    
    // Incremental - 1 byte at a time
    let mut transcript1 = TranscriptHash::new();
    for byte in data {
        transcript1.update(&[*byte]);
    }
    
    // Incremental - 4 bytes at a time
    let mut transcript2 = TranscriptHash::new();
    for chunk in data.chunks(4) {
        transcript2.update(chunk);
    }
    
    // One-shot
    let oneshot = Sha256::digest(data);
    
    assert_eq!(transcript1.current_hash(), oneshot.as_slice());
    assert_eq!(transcript2.current_hash(), oneshot.as_slice());
}

// ============================================================================
// Hash Forking/Snapshot Tests
// ============================================================================

#[test]
fn test_clone_creates_independent_copy() {
    let mut original = TranscriptHash::new();
    original.update(b"shared data");
    
    let mut forked = original.clone();
    
    // Both should have same hash initially
    assert_eq!(original.current_hash(), forked.current_hash());
    
    // Update original
    original.update(b"original only");
    
    // Update fork
    forked.update(b"fork only");
    
    // Should now be different
    assert_ne!(original.current_hash(), forked.current_hash());
}

#[test]
fn test_multiple_forks_from_same_point() {
    let mut base = TranscriptHash::new();
    base.update(b"ClientHello");
    base.update(b"ServerHello");
    
    let base_hash = base.current_hash();
    
    // Create multiple forks
    let mut fork1 = base.clone();
    let mut fork2 = base.clone();
    let mut fork3 = base.clone();
    
    // All forks should have same initial hash
    assert_eq!(fork1.current_hash(), base_hash);
    assert_eq!(fork2.current_hash(), base_hash);
    assert_eq!(fork3.current_hash(), base_hash);
    
    // Update each fork differently
    fork1.update(b"path1");
    fork2.update(b"path2");
    fork3.update(b"path3");
    
    let h1 = fork1.current_hash();
    let h2 = fork2.current_hash();
    let h3 = fork3.current_hash();
    
    // All should be different
    assert_ne!(h1, h2);
    assert_ne!(h2, h3);
    assert_ne!(h1, h3);
    
    // Base should still have original hash
    assert_eq!(base.current_hash(), base_hash);
}

#[test]
fn test_fork_for_handshake_vs_application_keys() {
    // Simulate TLS 1.3 key schedule forking
    let mut transcript = TranscriptHash::new();
    transcript.update(b"ClientHello");
    transcript.update(b"ServerHello");
    
    // Fork for handshake keys
    let handshake_transcript = transcript.clone();
    let handshake_hash = handshake_transcript.current_hash();
    
    // Continue with more messages
    transcript.update(b"EncryptedExtensions");
    transcript.update(b"Certificate");
    transcript.update(b"CertificateVerify");
    transcript.update(b"Finished");
    
    // Fork for application keys
    let application_hash = transcript.current_hash();
    
    // Handshake hash should be different from application hash
    assert_ne!(handshake_hash, application_hash);
}

// ============================================================================
// State Management Tests
// ============================================================================

#[test]
fn test_current_hash_is_non_consuming() {
    let mut transcript = TranscriptHash::new();
    transcript.update(b"data1");
    
    // Call current_hash multiple times
    let hash1 = transcript.current_hash();
    let hash2 = transcript.current_hash();
    let hash3 = transcript.current_hash();
    
    // All should be identical
    assert_eq!(hash1, hash2);
    assert_eq!(hash2, hash3);
    
    // Should still be able to update
    transcript.update(b"data2");
    let hash4 = transcript.current_hash();
    
    // New hash should be different
    assert_ne!(hash1, hash4);
}

#[test]
fn test_finalize_consuming() {
    let mut transcript = TranscriptHash::new();
    transcript.update(b"test data");
    
    let final_hash = transcript.finalize();
    
    // Should match expected
    let expected = Sha256::digest(b"test data");
    assert_eq!(final_hash, expected.as_slice());
    
    // transcript is now consumed and cannot be used
    // (This is enforced by Rust's ownership system)
}

#[test]
fn test_reset_clears_state() {
    let mut transcript = TranscriptHash::new();
    let empty_hash = transcript.current_hash();
    
    transcript.update(b"some data");
    transcript.update(b"more data");
    let populated_hash = transcript.current_hash();
    
    assert_ne!(empty_hash, populated_hash);
    
    transcript.reset();
    let after_reset = transcript.current_hash();
    
    assert_eq!(empty_hash, after_reset);
}

#[test]
fn test_reset_allows_reuse() {
    let mut transcript = TranscriptHash::new();
    
    // First session
    transcript.update(b"session1 data");
    let session1_hash = transcript.current_hash();
    
    // Reset for second session
    transcript.reset();
    transcript.update(b"session2 data");
    let session2_hash = transcript.current_hash();
    
    assert_ne!(session1_hash, session2_hash);
    
    // Verify session2 hash is correct
    let expected = Sha256::digest(b"session2 data");
    assert_eq!(session2_hash, expected.as_slice());
}

#[test]
fn test_default_trait() {
    let t1 = TranscriptHash::new();
    let t2 = TranscriptHash::default();
    
    assert_eq!(t1.current_hash(), t2.current_hash());
}

// ============================================================================
// TLS Message Integration Tests
// ============================================================================

#[test]
fn test_update_client_hello() {
    let mut transcript = TranscriptHash::new();
    
    let random = [0x42u8; 32];
    let public_key = vec![0xaa; 32];
    let client_hello = ClientHello::default_tls13(random, public_key);
    
    transcript.update_client_hello(&client_hello);
    
    // Verify hash is not empty
    let hash = transcript.current_hash();
    let empty_hash = TranscriptHash::empty_hash();
    assert_ne!(hash, empty_hash);
    
    // Verify it matches manual update
    let mut manual_transcript = TranscriptHash::new();
    manual_transcript.update(&client_hello.to_bytes());
    assert_eq!(hash, manual_transcript.current_hash());
}

#[test]
fn test_update_server_hello() {
    let mut transcript = TranscriptHash::new();
    
    let random = [0x88u8; 32];
    let extensions = vec![
        Extension::SupportedVersions(vec![TLS_VERSION_1_3]),
        Extension::KeyShare(vec![KeyShareEntry::new(NAMED_GROUP_X25519, vec![0xbb; 32])]),
    ];
    let server_hello = ServerHello::new(random, vec![], 0x1301, extensions);
    
    transcript.update_server_hello(&server_hello);
    
    // Verify hash is not empty
    let hash = transcript.current_hash();
    let empty_hash = TranscriptHash::empty_hash();
    assert_ne!(hash, empty_hash);
    
    // Verify it matches manual update
    let mut manual_transcript = TranscriptHash::new();
    manual_transcript.update(&server_hello.to_bytes());
    assert_eq!(hash, manual_transcript.current_hash());
}

#[test]
fn test_client_hello_and_server_hello_sequence() {
    let mut transcript = TranscriptHash::new();
    
    // ClientHello
    let client_random = [0x11u8; 32];
    let client_public_key = vec![0xaa; 32];
    let client_hello = ClientHello::default_tls13(client_random, client_public_key);
    transcript.update_client_hello(&client_hello);
    
    let after_client_hello = transcript.current_hash();
    
    // ServerHello
    let server_random = [0x22u8; 32];
    let server_extensions = vec![
        Extension::SupportedVersions(vec![TLS_VERSION_1_3]),
        Extension::KeyShare(vec![KeyShareEntry::new(NAMED_GROUP_X25519, vec![0xbb; 32])]),
    ];
    let server_hello = ServerHello::new(server_random, vec![], 0x1301, server_extensions);
    transcript.update_server_hello(&server_hello);
    
    let after_server_hello = transcript.current_hash();
    
    // Hashes should be different
    assert_ne!(after_client_hello, after_server_hello);
    
    // Verify manual computation matches
    let mut manual = TranscriptHash::new();
    manual.update(&client_hello.to_bytes());
    manual.update(&server_hello.to_bytes());
    assert_eq!(after_server_hello, manual.current_hash());
}

// ============================================================================
// Real TLS 1.3 Handshake Scenarios
// ============================================================================

#[test]
fn test_full_handshake_transcript_simulation() {
    let mut transcript = TranscriptHash::new();
    
    // Step 1: ClientHello
    let client_hello = ClientHello::default_tls13([0x01u8; 32], vec![0xaa; 32]);
    transcript.update_client_hello(&client_hello);
    
    // Step 2: ServerHello
    let server_hello = ServerHello::new(
        [0x02u8; 32],
        vec![],
        0x1301,
        vec![
            Extension::SupportedVersions(vec![TLS_VERSION_1_3]),
            Extension::KeyShare(vec![KeyShareEntry::new(NAMED_GROUP_X25519, vec![0xbb; 32])]),
        ],
    );
    transcript.update_server_hello(&server_hello);
    
    // Fork for handshake keys
    let handshake_transcript = transcript.clone();
    let handshake_hash = handshake_transcript.current_hash();
    
    // Step 3: Encrypted messages (simulated as raw bytes)
    transcript.update(b"EncryptedExtensions");
    transcript.update(b"Certificate");
    transcript.update(b"CertificateVerify");
    transcript.update(b"Finished");
    
    let final_hash = transcript.current_hash();
    
    // Verify hashes are different at different stages
    assert_ne!(handshake_hash, final_hash);
    
    // Verify hash lengths
    assert_eq!(handshake_hash.len(), 32);
    assert_eq!(final_hash.len(), 32);
}

#[test]
fn test_transcript_for_finished_message() {
    // Simulate transcript hash used for Finished message verification
    let mut transcript = TranscriptHash::new();
    
    transcript.update(b"ClientHello");
    transcript.update(b"ServerHello");
    transcript.update(b"EncryptedExtensions");
    transcript.update(b"Certificate");
    transcript.update(b"CertificateVerify");
    
    let hash_for_finished = transcript.current_hash();
    
    // Add server Finished
    transcript.update(b"ServerFinished");
    
    // Fork for client Finished
    let client_finished_hash = transcript.current_hash();
    
    assert_ne!(hash_for_finished, client_finished_hash);
    assert_eq!(hash_for_finished.len(), 32);
    assert_eq!(client_finished_hash.len(), 32);
}

#[test]
fn test_session_resumption_reset() {
    let mut transcript = TranscriptHash::new();
    
    // First handshake
    transcript.update(b"ClientHello1");
    transcript.update(b"ServerHello1");
    let first_hash = transcript.current_hash();
    
    // Reset for session resumption
    transcript.reset();
    
    // Second handshake
    transcript.update(b"ClientHello2");
    transcript.update(b"ServerHello2");
    let second_hash = transcript.current_hash();
    
    assert_ne!(first_hash, second_hash);
}

// ============================================================================
// Edge Cases and Property Tests
// ============================================================================

#[test]
fn test_different_inputs_produce_different_hashes() {
    let mut t1 = TranscriptHash::new();
    let mut t2 = TranscriptHash::new();
    
    t1.update(b"message A");
    t2.update(b"message B");
    
    assert_ne!(t1.current_hash(), t2.current_hash());
}

#[test]
fn test_order_matters() {
    let mut t1 = TranscriptHash::new();
    t1.update(b"A");
    t1.update(b"B");
    
    let mut t2 = TranscriptHash::new();
    t2.update(b"B");
    t2.update(b"A");
    
    assert_ne!(t1.current_hash(), t2.current_hash());
}

#[test]
fn test_hash_output_is_32_bytes() {
    let mut transcript = TranscriptHash::new();
    transcript.update(b"test");
    
    let hash = transcript.current_hash();
    assert_eq!(hash.len(), 32);
    
    let final_hash = transcript.finalize();
    assert_eq!(final_hash.len(), 32);
}

#[test]
fn test_known_sha256_test_vector() {
    // SHA-256 test vector: SHA-256("abc") = ba7816bf...
    let mut transcript = TranscriptHash::new();
    transcript.update(b"abc");
    
    let hash = transcript.current_hash();
    let expected = hex_to_bytes(
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    
    assert_eq!(hash.to_vec(), expected);
}

#[test]
fn test_debug_format() {
    let mut transcript = TranscriptHash::new();
    transcript.update(b"test");
    
    let debug_str = format!("{:?}", transcript);
    assert!(debug_str.contains("TranscriptHash"));
    assert!(debug_str.contains("current_hash"));
}
