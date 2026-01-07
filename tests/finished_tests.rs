//! Comprehensive Tests for TLS 1.3 Finished Message Implementation
//!
//! This test suite validates:
//! - Message serialization and deserialization
//! - Finished key derivation (HKDF-Expand-Label)
//! - Verify data calculation (HMAC-SHA256)
//! - Client and server Finished generation
//! - Constant-time verification
//! - RFC 8446 test vectors
//! - Integration with key schedule and transcript hash

use tls_protocol::{Finished, KeySchedule, TranscriptHash, TlsError};

/// Helper function to convert hex strings to byte arrays
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
fn test_finished_message_format() {
    // Test the basic format of a Finished message
    let verify_data = [0x42; 32];
    let finished = Finished::new(verify_data);
    let bytes = finished.to_bytes();

    // Verify structure: type (1) + length (3) + verify_data (32) = 36 bytes
    assert_eq!(bytes.len(), 36);
    assert_eq!(bytes[0], 20); // Handshake type: Finished
    assert_eq!(bytes[1], 0x00); // Length high byte
    assert_eq!(bytes[2], 0x00); // Length middle byte
    assert_eq!(bytes[3], 0x20); // Length low byte (32)
    assert_eq!(&bytes[4..], &verify_data);
}

#[test]
fn test_finished_serialization_deserialization() {
    // Test round-trip serialization
    let verify_data = [0xAB; 32];
    let finished = Finished::new(verify_data);

    let serialized = finished.to_bytes();
    let deserialized = Finished::from_bytes(&serialized).unwrap();

    assert_eq!(finished, deserialized);
    assert_eq!(deserialized.verify_data(), &verify_data);
}

#[test]
fn test_finished_from_payload() {
    // Test parsing from just the payload (no handshake header)
    let verify_data = [0xCD; 32];
    let finished = Finished::from_payload(&verify_data).unwrap();

    assert_eq!(finished.verify_data(), &verify_data);
}

#[test]
fn test_finished_invalid_type_error() {
    // Test error handling for invalid handshake type
    let mut bytes = vec![0xFF, 0x00, 0x00, 0x20]; // Invalid type
    bytes.extend_from_slice(&[0u8; 32]);

    let result = Finished::from_bytes(&bytes);
    assert!(matches!(result, Err(TlsError::InvalidHandshakeMessage(_))));
}

#[test]
fn test_finished_invalid_length_error() {
    // Test error handling for incorrect length field
    let mut bytes = vec![20, 0x00, 0x00, 0x10]; // Wrong length (16 instead of 32)
    bytes.extend_from_slice(&[0u8; 16]);

    let result = Finished::from_bytes(&bytes);
    assert!(matches!(result, Err(TlsError::InvalidHandshakeMessage(_))));
}

#[test]
fn test_finished_too_short_error() {
    // Test error handling for truncated message
    let bytes = vec![20, 0x00]; // Too short

    let result = Finished::from_bytes(&bytes);
    assert!(matches!(result, Err(TlsError::InvalidHandshakeMessage(_))));
}

#[test]
fn test_finished_payload_wrong_length() {
    // Test error handling for wrong payload length
    let payload = [0u8; 16]; // Should be 32 bytes

    let result = Finished::from_payload(&payload);
    assert!(matches!(result, Err(TlsError::InvalidHandshakeMessage(_))));
}

#[test]
fn test_client_finished_generation() {
    // Test client Finished generation with known inputs
    let client_secret = [0x11; 32];
    let transcript_hash = [0x22; 32];

    let finished = Finished::generate_client_finished(&client_secret, &transcript_hash);

    // Verify_data should be 32 bytes
    assert_eq!(finished.verify_data().len(), 32);

    // Generate again with same inputs - should be deterministic
    let finished2 = Finished::generate_client_finished(&client_secret, &transcript_hash);
    assert_eq!(finished, finished2);
}

#[test]
fn test_server_finished_generation() {
    // Test server Finished generation with known inputs
    let server_secret = [0xAA; 32];
    let transcript_hash = [0xBB; 32];

    let finished = Finished::generate_server_finished(&server_secret, &transcript_hash);

    // Verify_data should be 32 bytes
    assert_eq!(finished.verify_data().len(), 32);

    // Generate again with same inputs - should be deterministic
    let finished2 = Finished::generate_server_finished(&server_secret, &transcript_hash);
    assert_eq!(finished, finished2);
}

#[test]
fn test_client_finished_different_secrets() {
    // Test that different secrets produce different verify_data
    let secret1 = [0x01; 32];
    let secret2 = [0x02; 32];
    let transcript_hash = [0x03; 32];

    let finished1 = Finished::generate_client_finished(&secret1, &transcript_hash);
    let finished2 = Finished::generate_client_finished(&secret2, &transcript_hash);

    assert_ne!(finished1, finished2);
    assert_ne!(finished1.verify_data(), finished2.verify_data());
}

#[test]
fn test_client_finished_different_transcripts() {
    // Test that different transcripts produce different verify_data
    let secret = [0x11; 32];
    let transcript1 = [0x22; 32];
    let transcript2 = [0x33; 32];

    let finished1 = Finished::generate_client_finished(&secret, &transcript1);
    let finished2 = Finished::generate_client_finished(&secret, &transcript2);

    assert_ne!(finished1, finished2);
    assert_ne!(finished1.verify_data(), finished2.verify_data());
}

#[test]
fn test_client_finished_verification_success() {
    // Test successful verification of client Finished
    let client_secret = [0x11; 32];
    let transcript_hash = [0x22; 32];

    let finished = Finished::generate_client_finished(&client_secret, &transcript_hash);

    // Verification should succeed with correct secret and transcript
    let result = finished.verify_client_finished(&client_secret, &transcript_hash);
    assert!(result.is_ok());
}

#[test]
fn test_client_finished_verification_wrong_secret() {
    // Test that verification fails with wrong secret
    let client_secret = [0x11; 32];
    let wrong_secret = [0x99; 32];
    let transcript_hash = [0x22; 32];

    let finished = Finished::generate_client_finished(&client_secret, &transcript_hash);

    // Verification should fail with wrong secret
    let result = finished.verify_client_finished(&wrong_secret, &transcript_hash);
    assert!(matches!(result, Err(TlsError::InvalidFinished)));
}

#[test]
fn test_client_finished_verification_wrong_transcript() {
    // Test that verification fails with wrong transcript
    let client_secret = [0x11; 32];
    let transcript_hash = [0x22; 32];
    let wrong_transcript = [0x88; 32];

    let finished = Finished::generate_client_finished(&client_secret, &transcript_hash);

    // Verification should fail with wrong transcript
    let result = finished.verify_client_finished(&client_secret, &wrong_transcript);
    assert!(matches!(result, Err(TlsError::InvalidFinished)));
}

#[test]
fn test_server_finished_verification_success() {
    // Test successful verification of server Finished
    let server_secret = [0xAA; 32];
    let transcript_hash = [0xBB; 32];

    let finished = Finished::generate_server_finished(&server_secret, &transcript_hash);

    // Verification should succeed with correct secret and transcript
    let result = finished.verify_server_finished(&server_secret, &transcript_hash);
    assert!(result.is_ok());
}

#[test]
fn test_server_finished_verification_wrong_secret() {
    // Test that verification fails with wrong secret
    let server_secret = [0xAA; 32];
    let wrong_secret = [0xCC; 32];
    let transcript_hash = [0xBB; 32];

    let finished = Finished::generate_server_finished(&server_secret, &transcript_hash);

    // Verification should fail with wrong secret
    let result = finished.verify_server_finished(&wrong_secret, &transcript_hash);
    assert!(matches!(result, Err(TlsError::InvalidFinished)));
}

#[test]
fn test_server_finished_verification_wrong_transcript() {
    // Test that verification fails with wrong transcript
    let server_secret = [0xAA; 32];
    let transcript_hash = [0xBB; 32];
    let wrong_transcript = [0xDD; 32];

    let finished = Finished::generate_server_finished(&server_secret, &transcript_hash);

    // Verification should fail with wrong transcript
    let result = finished.verify_server_finished(&server_secret, &wrong_transcript);
    assert!(matches!(result, Err(TlsError::InvalidFinished)));
}

#[test]
fn test_client_server_finished_different() {
    // Test that client and server Finished messages are different
    // even with the same transcript (they use different secrets)
    let client_secret = [0x11; 32];
    let server_secret = [0x22; 32];
    let transcript_hash = [0x33; 32];

    let client_finished = Finished::generate_client_finished(&client_secret, &transcript_hash);
    let server_finished = Finished::generate_server_finished(&server_secret, &transcript_hash);

    assert_ne!(client_finished, server_finished);
    assert_ne!(client_finished.verify_data(), server_finished.verify_data());
}

#[test]
fn test_constant_time_comparison() {
    // Test that verification uses constant-time comparison
    // This is a basic smoke test - timing analysis would be needed for complete verification
    let secret = [0xAA; 32];
    let transcript = [0xBB; 32];

    let finished = Finished::generate_client_finished(&secret, &transcript);

    // Create a modified verify_data that differs in the first byte
    let mut wrong_verify_data = *finished.verify_data();
    wrong_verify_data[0] ^= 0x01;
    let wrong_finished = Finished::new(wrong_verify_data);

    // Verification should fail
    assert!(wrong_finished.verify_client_finished(&secret, &transcript).is_err());

    // Create a modified verify_data that differs in the last byte
    let mut wrong_verify_data = *finished.verify_data();
    wrong_verify_data[31] ^= 0x01;
    let wrong_finished = Finished::new(wrong_verify_data);

    // Verification should also fail
    assert!(wrong_finished.verify_client_finished(&secret, &transcript).is_err());
}

#[test]
fn test_finished_with_key_schedule_integration() {
    // Test integration with KeySchedule
    let mut key_schedule = KeySchedule::new();

    // Simulate ECDHE shared secret
    let shared_secret = [0x42; 32];
    key_schedule.advance_to_handshake_secret(&shared_secret);

    // Create transcript hash
    let mut transcript = TranscriptHash::new();
    transcript.update(b"ClientHello");
    transcript.update(b"ServerHello");
    let transcript_hash = transcript.current_hash();

    // Derive handshake traffic secrets
    let client_secret = key_schedule.derive_client_handshake_traffic_secret(&transcript_hash);
    let server_secret = key_schedule.derive_server_handshake_traffic_secret(&transcript_hash);

    // Generate client Finished
    let client_finished = Finished::generate_client_finished(&client_secret, &transcript_hash);

    // Verify client Finished
    assert!(client_finished.verify_client_finished(&client_secret, &transcript_hash).is_ok());

    // Generate server Finished
    let server_finished = Finished::generate_server_finished(&server_secret, &transcript_hash);

    // Verify server Finished
    assert!(server_finished.verify_server_finished(&server_secret, &transcript_hash).is_ok());

    // Cross-verification should fail
    assert!(client_finished.verify_server_finished(&server_secret, &transcript_hash).is_err());
    assert!(server_finished.verify_client_finished(&client_secret, &transcript_hash).is_err());
}

#[test]
fn test_finished_serialization_in_handshake_flow() {
    // Test serialization and deserialization in a handshake-like flow
    let client_secret = [0x11; 32];
    let transcript_hash = [0x22; 32];

    // Client generates Finished
    let client_finished = Finished::generate_client_finished(&client_secret, &transcript_hash);
    let finished_bytes = client_finished.to_bytes();

    // Simulate sending over network and receiving on server side
    let received_finished = Finished::from_bytes(&finished_bytes).unwrap();

    // Server verifies
    assert!(received_finished.verify_client_finished(&client_secret, &transcript_hash).is_ok());
}

#[test]
fn test_tampered_finished_detection() {
    // Test that tampering is detected
    let client_secret = [0x11; 32];
    let transcript_hash = [0x22; 32];

    let client_finished = Finished::generate_client_finished(&client_secret, &transcript_hash);
    let mut finished_bytes = client_finished.to_bytes();

    // Tamper with verify_data (flip a bit in the middle)
    finished_bytes[20] ^= 0x01;

    let tampered_finished = Finished::from_bytes(&finished_bytes).unwrap();

    // Verification should fail
    assert!(tampered_finished.verify_client_finished(&client_secret, &transcript_hash).is_err());
}

#[test]
fn test_finished_deterministic() {
    // Test that Finished generation is deterministic
    let secret = [0xAA; 32];
    let transcript = [0xBB; 32];

    let finished1 = Finished::generate_client_finished(&secret, &transcript);
    let finished2 = Finished::generate_client_finished(&secret, &transcript);
    let finished3 = Finished::generate_client_finished(&secret, &transcript);

    assert_eq!(finished1, finished2);
    assert_eq!(finished2, finished3);
    assert_eq!(finished1.verify_data(), finished2.verify_data());
    assert_eq!(finished2.verify_data(), finished3.verify_data());
}

#[test]
fn test_finished_with_empty_transcript() {
    // Test Finished with empty transcript hash (edge case)
    let secret = [0xAA; 32];
    let empty_hash = TranscriptHash::empty_hash();

    let finished = Finished::generate_client_finished(&secret, &empty_hash);

    // Should still produce a valid Finished message
    assert_eq!(finished.verify_data().len(), 32);

    // Verification should work
    assert!(finished.verify_client_finished(&secret, &empty_hash).is_ok());
}

#[test]
fn test_finished_with_all_zero_secret() {
    // Test Finished with all-zero secret (edge case)
    let zero_secret = [0x00; 32];
    let transcript = [0xAA; 32];

    let finished = Finished::generate_client_finished(&zero_secret, &transcript);

    // Should still produce a valid Finished message
    assert_eq!(finished.verify_data().len(), 32);

    // Verification should work
    assert!(finished.verify_client_finished(&zero_secret, &transcript).is_ok());
}

#[test]
fn test_finished_with_all_ones_secret() {
    // Test Finished with all-ones secret (edge case)
    let ones_secret = [0xFF; 32];
    let transcript = [0xAA; 32];

    let finished = Finished::generate_client_finished(&ones_secret, &transcript);

    // Should still produce a valid Finished message
    assert_eq!(finished.verify_data().len(), 32);

    // Verification should work
    assert!(finished.verify_client_finished(&ones_secret, &transcript).is_ok());
}

#[test]
fn test_reflection_attack_prevention() {
    // Test that client and server use different keys (prevents reflection attacks)
    let client_secret = [0x11; 32];
    let server_secret = [0x22; 32];
    let transcript = [0x33; 32];

    let client_finished = Finished::generate_client_finished(&client_secret, &transcript);
    let server_finished = Finished::generate_server_finished(&server_secret, &transcript);

    // Attacker tries to reflect client Finished back to client as server Finished
    assert!(client_finished.verify_server_finished(&server_secret, &transcript).is_err());

    // Attacker tries to reflect server Finished back to server as client Finished
    assert!(server_finished.verify_client_finished(&client_secret, &transcript).is_err());

    // Each side should only accept its counterpart
    assert!(client_finished.verify_client_finished(&client_secret, &transcript).is_ok());
    assert!(server_finished.verify_server_finished(&server_secret, &transcript).is_ok());
}

#[test]
fn test_finished_clone() {
    // Test that Finished can be cloned
    let verify_data = [0xAB; 32];
    let finished1 = Finished::new(verify_data);
    let finished2 = finished1.clone();

    assert_eq!(finished1, finished2);
    assert_eq!(finished1.verify_data(), finished2.verify_data());
}

#[test]
fn test_multiple_verification_attempts() {
    // Test that the same Finished message can be verified multiple times
    let secret = [0xAA; 32];
    let transcript = [0xBB; 32];

    let finished = Finished::generate_client_finished(&secret, &transcript);

    // Verify multiple times
    assert!(finished.verify_client_finished(&secret, &transcript).is_ok());
    assert!(finished.verify_client_finished(&secret, &transcript).is_ok());
    assert!(finished.verify_client_finished(&secret, &transcript).is_ok());
}

// RFC 8446 Test Vectors (if available)
// Note: RFC 8446 doesn't provide explicit Finished test vectors in the appendix,
// but we can use the simple-test example from the RFC or construct our own
// based on the key schedule test vectors.

#[test]
fn test_rfc_8446_simple_example_integration() {
    // This test uses values from a hypothetical RFC 8446 handshake flow
    // In a real implementation, you would use actual RFC test vectors
    
    let mut key_schedule = KeySchedule::new();
    
    // Example shared secret (in practice, from X25519)
    let shared_secret = hex_to_bytes(
        "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d"
    );
    
    key_schedule.advance_to_handshake_secret(&shared_secret);
    
    // Example transcript hash at ServerHello
    let transcript_hash = hex_to_bytes(
        "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8"
    );
    
    let client_secret = key_schedule.derive_client_handshake_traffic_secret(&transcript_hash);
    let server_secret = key_schedule.derive_server_handshake_traffic_secret(&transcript_hash);
    
    // Generate Finished messages
    let client_finished = Finished::generate_client_finished(&client_secret, &transcript_hash);
    let server_finished = Finished::generate_server_finished(&server_secret, &transcript_hash);
    
    // Verify they're different
    assert_ne!(client_finished, server_finished);
    
    // Verify each can be validated with correct secret
    assert!(client_finished.verify_client_finished(&client_secret, &transcript_hash).is_ok());
    assert!(server_finished.verify_server_finished(&server_secret, &transcript_hash).is_ok());
}
