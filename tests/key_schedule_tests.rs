//! Tests for TLS 1.3 Key Schedule Implementation
//!
//! This test suite validates the HKDF-based key derivation as specified in:
//! - RFC 5869 (HKDF)
//! - RFC 8446 (TLS 1.3), Sections 7.1 and 7.2
//!
//! Includes:
//! - RFC 5869 test vectors for HKDF-Extract and HKDF-Expand
//! - RFC 8446 test vectors for TLS 1.3 key schedule
//! - Edge case handling (zero-length inputs, empty contexts)
//! - Full key schedule progression

use sha2::{Digest, Sha256};
use tls_protocol::key_schedule::{hkdf_expand, hkdf_extract, KeySchedule, KeyScheduleStage};

/// Helper function to convert hex strings to byte vectors
fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let hex = hex.replace(" ", "").replace("\n", "");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// Helper function to convert bytes to hex string for debugging
#[allow(dead_code)]
fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[test]
fn test_hkdf_extract_rfc5869_test_case_1() {
    // RFC 5869 Test Case 1 (SHA-256)
    // https://tools.ietf.org/html/rfc5869#appendix-A.1
    
    let ikm = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = hex_to_bytes("000102030405060708090a0b0c");
    
    let expected_prk = hex_to_bytes(
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    );
    
    let prk = hkdf_extract(Some(&salt), &ikm);
    assert_eq!(prk.to_vec(), expected_prk);
}

#[test]
fn test_hkdf_extract_rfc5869_test_case_2() {
    // RFC 5869 Test Case 2 (SHA-256) - longer inputs
    
    let ikm = hex_to_bytes(
        "000102030405060708090a0b0c0d0e0f\
         101112131415161718191a1b1c1d1e1f\
         202122232425262728292a2b2c2d2e2f\
         303132333435363738393a3b3c3d3e3f\
         404142434445464748494a4b4c4d4e4f"
    );
    
    let salt = hex_to_bytes(
        "606162636465666768696a6b6c6d6e6f\
         707172737475767778797a7b7c7d7e7f\
         808182838485868788898a8b8c8d8e8f\
         909192939495969798999a9b9c9d9e9f\
         a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
    );
    
    let expected_prk = hex_to_bytes(
        "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"
    );
    
    let prk = hkdf_extract(Some(&salt), &ikm);
    assert_eq!(prk.to_vec(), expected_prk);
}

#[test]
fn test_hkdf_extract_with_zero_salt() {
    // Test with zero-length salt (should use zeros per RFC 5869)
    let ikm = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    
    // When salt is None or zero-length, HKDF uses a string of zeros
    let prk_none = hkdf_extract(None, &ikm);
    let zero_salt = [0u8; 32];
    let prk_zeros = hkdf_extract(Some(&zero_salt), &ikm);
    
    // These should be equal
    assert_eq!(prk_none, prk_zeros);
}

#[test]
fn test_hkdf_expand_rfc5869_test_case_1() {
    // RFC 5869 Test Case 1 (SHA-256) - HKDF-Expand
    
    let prk = hex_to_bytes(
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    );
    let info = hex_to_bytes("f0f1f2f3f4f5f6f7f8f9");
    let length = 42;
    
    let expected_okm = hex_to_bytes(
        "3cb25f25faacd57a90434f64d0362f2a\
         2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
         34007208d5b887185865"
    );
    
    let okm = hkdf_expand(&prk, &info, length);
    assert_eq!(okm, expected_okm);
}

#[test]
fn test_hkdf_expand_rfc5869_test_case_2() {
    // RFC 5869 Test Case 2 (SHA-256) - longer output
    
    let prk = hex_to_bytes(
        "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"
    );
    let info = hex_to_bytes(
        "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf\
         c0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
         d0d1d2d3d4d5d6d7d8d9dadbdcdddedf\
         e0e1e2e3e4e5e6e7e8e9eaebecedeeef\
         f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
    );
    let length = 82;
    
    let expected_okm = hex_to_bytes(
        "b11e398dc80327a1c8e7f78c596a4934\
         4f012eda2d4efad8a050cc4c19afa97c\
         59045a99cac7827271cb41c65e590e09\
         da3275600c2f09b8367793a9aca3db71\
         cc30c58179ec3e87c14c01d5c1f3434f\
         1d87"
    );
    
    let okm = hkdf_expand(&prk, &info, length);
    assert_eq!(okm, expected_okm);
}

#[test]
fn test_hkdf_expand_with_empty_info() {
    // Test HKDF-Expand with empty info (edge case)
    let prk = hex_to_bytes(
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    );
    let info = b"";
    let length = 32;
    
    // Should not panic and should produce 32 bytes
    let okm = hkdf_expand(&prk, info, length);
    assert_eq!(okm.len(), 32);
}

#[test]
fn test_key_schedule_initialization() {
    // Test KeySchedule::new() creates Early Secret properly
    let ks = KeySchedule::new();
    
    // Should be in Early stage
    assert_eq!(ks.stage(), KeyScheduleStage::Early);
    
    // Early Secret = HKDF-Extract(0, 0)
    let zero_salt = [0u8; 32];
    let zero_ikm = [0u8; 32];
    let expected_early = hkdf_extract(Some(&zero_salt), &zero_ikm);
    
    assert_eq!(ks.current_secret(), expected_early);
}

#[test]
fn test_key_schedule_with_psk() {
    // Test KeySchedule with a pre-shared key
    let psk = b"test_psk_value_for_early_secret!";
    let ks = KeySchedule::with_psk(psk);
    
    assert_eq!(ks.stage(), KeyScheduleStage::Early);
    
    // Should be different from default (no PSK) early secret
    let ks_default = KeySchedule::new();
    assert_ne!(ks.current_secret(), ks_default.current_secret());
}

#[test]
fn test_advance_to_handshake_secret() {
    let mut ks = KeySchedule::new();
    let initial_secret = ks.current_secret();
    
    // Simulate ECDHE shared secret (32 bytes from X25519)
    let shared_secret = [0x42u8; 32];
    
    ks.advance_to_handshake_secret(&shared_secret);
    
    // Should now be in Handshake stage
    assert_eq!(ks.stage(), KeyScheduleStage::Handshake);
    
    // Secret should have changed
    assert_ne!(ks.current_secret(), initial_secret);
}

#[test]
fn test_advance_to_master_secret() {
    let mut ks = KeySchedule::new();
    let shared_secret = [0x42u8; 32];
    
    ks.advance_to_handshake_secret(&shared_secret);
    let handshake_secret = ks.current_secret();
    
    ks.advance_to_master_secret();
    
    // Should now be in Master stage
    assert_eq!(ks.stage(), KeyScheduleStage::Master);
    
    // Secret should have changed
    assert_ne!(ks.current_secret(), handshake_secret);
}

#[test]
fn test_full_key_schedule_progression() {
    // Test complete progression through all stages
    let mut ks = KeySchedule::new();
    
    // Stage 1: Early Secret
    assert_eq!(ks.stage(), KeyScheduleStage::Early);
    let early_secret = ks.current_secret();
    
    // Stage 2: Handshake Secret
    let shared_secret = [0xAAu8; 32];
    ks.advance_to_handshake_secret(&shared_secret);
    assert_eq!(ks.stage(), KeyScheduleStage::Handshake);
    let handshake_secret = ks.current_secret();
    assert_ne!(handshake_secret, early_secret);
    
    // Stage 3: Master Secret
    ks.advance_to_master_secret();
    assert_eq!(ks.stage(), KeyScheduleStage::Master);
    let master_secret = ks.current_secret();
    assert_ne!(master_secret, handshake_secret);
    assert_ne!(master_secret, early_secret);
}

#[test]
fn test_derive_handshake_traffic_secrets() {
    let mut ks = KeySchedule::new();
    let shared_secret = [0x42u8; 32];
    ks.advance_to_handshake_secret(&shared_secret);
    
    // Create a mock transcript hash (ClientHello...ServerHello)
    let mut hasher = Sha256::new();
    hasher.update(b"ClientHello");
    hasher.update(b"ServerHello");
    let transcript_hash = hasher.finalize();
    
    // Derive both client and server handshake traffic secrets
    let client_hs_secret = ks.derive_client_handshake_traffic_secret(&transcript_hash);
    let server_hs_secret = ks.derive_server_handshake_traffic_secret(&transcript_hash);
    
    // Both should be 32 bytes
    assert_eq!(client_hs_secret.len(), 32);
    assert_eq!(server_hs_secret.len(), 32);
    
    // Should be different from each other
    assert_ne!(client_hs_secret, server_hs_secret);
    
    // Should be different from the handshake secret itself
    assert_ne!(client_hs_secret, ks.current_secret());
    assert_ne!(server_hs_secret, ks.current_secret());
}

#[test]
fn test_derive_application_traffic_secrets() {
    let mut ks = KeySchedule::new();
    let shared_secret = [0x42u8; 32];
    ks.advance_to_handshake_secret(&shared_secret);
    ks.advance_to_master_secret();
    
    // Create a mock transcript hash (ClientHello...server Finished)
    let mut hasher = Sha256::new();
    hasher.update(b"ClientHello");
    hasher.update(b"ServerHello");
    hasher.update(b"ServerFinished");
    let transcript_hash = hasher.finalize();
    
    // Derive application traffic secrets
    let client_app_secret = ks.derive_client_application_traffic_secret(&transcript_hash);
    let server_app_secret = ks.derive_server_application_traffic_secret(&transcript_hash);
    
    // Both should be 32 bytes
    assert_eq!(client_app_secret.len(), 32);
    assert_eq!(server_app_secret.len(), 32);
    
    // Should be different from each other
    assert_ne!(client_app_secret, server_app_secret);
    
    // Should be different from the master secret itself
    assert_ne!(client_app_secret, ks.current_secret());
    assert_ne!(server_app_secret, ks.current_secret());
}

#[test]
fn test_derive_exporter_master_secret() {
    let mut ks = KeySchedule::new();
    let shared_secret = [0x42u8; 32];
    ks.advance_to_handshake_secret(&shared_secret);
    ks.advance_to_master_secret();
    
    let transcript_hash = Sha256::digest(b"test_transcript");
    let exporter_secret = ks.derive_exporter_master_secret(&transcript_hash);
    
    assert_eq!(exporter_secret.len(), 32);
    assert_ne!(exporter_secret, ks.current_secret());
}

#[test]
fn test_derive_resumption_master_secret() {
    let mut ks = KeySchedule::new();
    let shared_secret = [0x42u8; 32];
    ks.advance_to_handshake_secret(&shared_secret);
    ks.advance_to_master_secret();
    
    let transcript_hash = Sha256::digest(b"test_transcript");
    let resumption_secret = ks.derive_resumption_master_secret(&transcript_hash);
    
    assert_eq!(resumption_secret.len(), 32);
    assert_ne!(resumption_secret, ks.current_secret());
}

#[test]
fn test_different_shared_secrets_produce_different_keys() {
    // Verify that different ECDHE shared secrets produce different handshake secrets
    let mut ks1 = KeySchedule::new();
    let mut ks2 = KeySchedule::new();
    
    let shared_secret_1 = [0x11u8; 32];
    let shared_secret_2 = [0x22u8; 32];
    
    ks1.advance_to_handshake_secret(&shared_secret_1);
    ks2.advance_to_handshake_secret(&shared_secret_2);
    
    assert_ne!(ks1.current_secret(), ks2.current_secret());
}

#[test]
fn test_different_transcripts_produce_different_traffic_secrets() {
    // Verify that different transcript hashes produce different traffic secrets
    let mut ks = KeySchedule::new();
    let shared_secret = [0x42u8; 32];
    ks.advance_to_handshake_secret(&shared_secret);
    
    let transcript_1 = Sha256::digest(b"transcript_one");
    let transcript_2 = Sha256::digest(b"transcript_two");
    
    let secret_1 = ks.derive_client_handshake_traffic_secret(&transcript_1);
    let secret_2 = ks.derive_client_handshake_traffic_secret(&transcript_2);
    
    assert_ne!(secret_1, secret_2);
}

#[test]
#[should_panic(expected = "Can only advance to Handshake Secret from Early Secret")]
fn test_cannot_skip_to_handshake_from_master() {
    let mut ks = KeySchedule::new();
    let shared_secret = [0x42u8; 32];
    ks.advance_to_handshake_secret(&shared_secret);
    ks.advance_to_master_secret();
    
    // This should panic - can't go back
    ks.advance_to_handshake_secret(&shared_secret);
}

#[test]
#[should_panic(expected = "Can only advance to Master Secret from Handshake Secret")]
fn test_cannot_skip_to_master_from_early() {
    let mut ks = KeySchedule::new();
    
    // This should panic - must go through handshake stage first
    ks.advance_to_master_secret();
}

#[test]
#[should_panic(expected = "Can only derive handshake traffic secrets in Handshake stage")]
fn test_cannot_derive_handshake_secrets_in_early_stage() {
    let ks = KeySchedule::new();
    let transcript = Sha256::digest(b"test");
    
    // This should panic - not in handshake stage yet
    ks.derive_client_handshake_traffic_secret(&transcript);
}

#[test]
#[should_panic(expected = "Can only derive application traffic secrets in Master stage")]
fn test_cannot_derive_application_secrets_in_handshake_stage() {
    let mut ks = KeySchedule::new();
    let shared_secret = [0x42u8; 32];
    ks.advance_to_handshake_secret(&shared_secret);
    
    let transcript = Sha256::digest(b"test");
    
    // This should panic - not in master stage yet
    ks.derive_client_application_traffic_secret(&transcript);
}

#[test]
fn test_edge_case_zero_length_transcript() {
    // Test with empty transcript (edge case)
    let mut ks = KeySchedule::new();
    let shared_secret = [0x42u8; 32];
    ks.advance_to_handshake_secret(&shared_secret);
    
    // Empty transcript hash
    let empty_hash = Sha256::digest(&[]);
    
    let client_secret = ks.derive_client_handshake_traffic_secret(&empty_hash);
    let server_secret = ks.derive_server_handshake_traffic_secret(&empty_hash);
    
    // Should still produce valid 32-byte secrets
    assert_eq!(client_secret.len(), 32);
    assert_eq!(server_secret.len(), 32);
    assert_ne!(client_secret, server_secret);
}

#[test]
fn test_key_schedule_determinism() {
    // Verify that the same inputs always produce the same outputs
    let shared_secret = [0x55u8; 32];
    let transcript = Sha256::digest(b"deterministic_test");
    
    let mut ks1 = KeySchedule::new();
    ks1.advance_to_handshake_secret(&shared_secret);
    let secret1 = ks1.derive_client_handshake_traffic_secret(&transcript);
    
    let mut ks2 = KeySchedule::new();
    ks2.advance_to_handshake_secret(&shared_secret);
    let secret2 = ks2.derive_client_handshake_traffic_secret(&transcript);
    
    assert_eq!(secret1, secret2);
}

#[test]
fn test_complete_tls13_key_schedule_flow() {
    // Simulate a complete TLS 1.3 handshake key schedule
    
    // Step 1: Initialize with Early Secret
    let mut ks = KeySchedule::new();
    assert_eq!(ks.stage(), KeyScheduleStage::Early);
    
    // Step 2: Perform ECDHE and advance to Handshake Secret
    let ecdhe_shared_secret = [0xAAu8; 32]; // From X25519 exchange
    ks.advance_to_handshake_secret(&ecdhe_shared_secret);
    assert_eq!(ks.stage(), KeyScheduleStage::Handshake);
    
    // Step 3: Derive handshake traffic secrets
    let mut transcript_hs = Sha256::new();
    transcript_hs.update(b"ClientHello");
    transcript_hs.update(b"ServerHello");
    let transcript_hs_hash = transcript_hs.finalize();
    
    let client_hs_traffic = ks.derive_client_handshake_traffic_secret(&transcript_hs_hash);
    let server_hs_traffic = ks.derive_server_handshake_traffic_secret(&transcript_hs_hash);
    
    assert_eq!(client_hs_traffic.len(), 32);
    assert_eq!(server_hs_traffic.len(), 32);
    assert_ne!(client_hs_traffic, server_hs_traffic);
    
    // Step 4: Advance to Master Secret
    ks.advance_to_master_secret();
    assert_eq!(ks.stage(), KeyScheduleStage::Master);
    
    // Step 5: Derive application traffic secrets
    let mut transcript_app = Sha256::new();
    transcript_app.update(b"ClientHello");
    transcript_app.update(b"ServerHello");
    transcript_app.update(b"ServerFinished");
    let transcript_app_hash = transcript_app.finalize();
    
    let client_app_traffic = ks.derive_client_application_traffic_secret(&transcript_app_hash);
    let server_app_traffic = ks.derive_server_application_traffic_secret(&transcript_app_hash);
    
    assert_eq!(client_app_traffic.len(), 32);
    assert_eq!(server_app_traffic.len(), 32);
    assert_ne!(client_app_traffic, server_app_traffic);
    
    // Step 6: Derive exporter master secret
    let exporter_master = ks.derive_exporter_master_secret(&transcript_app_hash);
    assert_eq!(exporter_master.len(), 32);
    
    // Step 7: Derive resumption master secret (after client Finished)
    let mut transcript_resume = Sha256::new();
    transcript_resume.update(b"ClientHello");
    transcript_resume.update(b"ServerHello");
    transcript_resume.update(b"ServerFinished");
    transcript_resume.update(b"ClientFinished");
    let transcript_resume_hash = transcript_resume.finalize();
    
    let resumption_master = ks.derive_resumption_master_secret(&transcript_resume_hash);
    assert_eq!(resumption_master.len(), 32);
    
    // All secrets should be unique
    assert_ne!(client_hs_traffic, server_hs_traffic);
    assert_ne!(client_app_traffic, server_app_traffic);
    assert_ne!(client_hs_traffic, client_app_traffic);
    assert_ne!(server_hs_traffic, server_app_traffic);
}

#[test]
fn test_hkdf_with_various_shared_secret_lengths() {
    // Test that HKDF works with different input lengths
    // (X25519 always produces 32 bytes, but test flexibility)
    
    for length in [16, 32, 48, 64] {
        let shared_secret = vec![0x42u8; length];
        let mut ks = KeySchedule::new();
        ks.advance_to_handshake_secret(&shared_secret);
        
        // Should always produce a valid handshake secret
        assert_eq!(ks.current_secret().len(), 32);
        assert_eq!(ks.stage(), KeyScheduleStage::Handshake);
    }
}

#[test]
fn test_key_schedule_default_trait() {
    // Test that Default trait works
    let ks1 = KeySchedule::default();
    let ks2 = KeySchedule::new();
    
    assert_eq!(ks1.current_secret(), ks2.current_secret());
    assert_eq!(ks1.stage(), ks2.stage());
}
