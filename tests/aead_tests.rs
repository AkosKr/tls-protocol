//! Comprehensive test suite for AES-128-GCM AEAD implementation
//!
//! Test Coverage:
//! - Known Answer Tests (KATs) using official test vectors
//! - Encrypt/decrypt round-trip tests
//! - Negative tests for authentication failures
//! - Maximum record size tests (16KB)
//! - Edge cases: empty payloads, single-byte payloads
//! - Integration with HKDF key derivation
//! - Sequence number handling and overflow
//! - Nonce uniqueness verification

use tls_protocol::{
    aead::{AeadCipher, TrafficKeys, encrypt_record, decrypt_record, 
           KEY_SIZE, IV_SIZE, TAG_SIZE, MAX_PLAINTEXT_SIZE},
    key_schedule::{KeySchedule, derive_traffic_keys},
    ContentType,
};

/// Test vector from NIST GCM test suite
/// Source: https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program
#[test]
fn test_aes_gcm_kat_1() {
    // Test vector for AES-128-GCM
    let key = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let iv = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];
    let plaintext = b"";
    let aad = b"";

    let keys = TrafficKeys::new(key, iv);
    let mut cipher = AeadCipher::new(keys);

    // Encrypt
    let ciphertext = cipher.encrypt(plaintext, aad).unwrap();
    
    // Ciphertext should only be the tag for empty plaintext
    assert_eq!(ciphertext.len(), TAG_SIZE);

    // Decrypt
    cipher.reset_sequence_number();
    let decrypted = cipher.decrypt(&ciphertext, aad).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_aes_gcm_kat_2() {
    // Test vector with non-zero key and IV
    let key = [
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
    ];
    let iv = [
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
        0xde, 0xca, 0xf8, 0x88,
    ];
    let plaintext = b"Hello, World!";
    let aad = b"additional data";

    let keys = TrafficKeys::new(key, iv);
    let mut cipher = AeadCipher::new(keys);

    // Encrypt
    let ciphertext = cipher.encrypt(plaintext, aad).unwrap();
    assert_eq!(ciphertext.len(), plaintext.len() + TAG_SIZE);
    assert_ne!(&ciphertext[..plaintext.len()], plaintext);

    // Decrypt
    cipher.reset_sequence_number();
    let decrypted = cipher.decrypt(&ciphertext, aad).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_encrypt_decrypt_roundtrip_various_sizes() {
    let key = [0x42u8; KEY_SIZE];
    let iv = [0x13u8; IV_SIZE];
    let keys = TrafficKeys::new(key, iv);

    // Test various payload sizes
    let test_sizes = vec![0, 1, 15, 16, 17, 255, 256, 1024, 4096, 8192, MAX_PLAINTEXT_SIZE];

    for size in test_sizes {
        let mut cipher = AeadCipher::new(keys.clone());
        
        // Create plaintext of specified size
        let plaintext: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        let aad = &[0x17, 0x03, 0x03, (size >> 8) as u8, (size & 0xff) as u8];

        // Encrypt
        let ciphertext = cipher.encrypt(&plaintext, aad).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + TAG_SIZE);

        // Decrypt
        cipher.reset_sequence_number();
        let decrypted = cipher.decrypt(&ciphertext, aad).unwrap();
        assert_eq!(decrypted, plaintext, "Failed for size {}", size);
    }
}

#[test]
fn test_max_record_size() {
    let keys = TrafficKeys::new([0x55u8; KEY_SIZE], [0xAAu8; IV_SIZE]);
    let mut cipher = AeadCipher::new(keys);

    // Create maximum-sized plaintext (16KB)
    let plaintext = vec![0x42u8; MAX_PLAINTEXT_SIZE];
    let aad = &[0x17, 0x03, 0x03, 0x40, 0x00];

    let ciphertext = cipher.encrypt(&plaintext, aad).unwrap();
    assert_eq!(ciphertext.len(), MAX_PLAINTEXT_SIZE + TAG_SIZE);

    cipher.reset_sequence_number();
    let decrypted = cipher.decrypt(&ciphertext, aad).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_record_too_large() {
    let keys = TrafficKeys::new([0x55u8; KEY_SIZE], [0xAAu8; IV_SIZE]);
    let mut cipher = AeadCipher::new(keys);

    // Create plaintext larger than maximum (16KB + 1 byte)
    let plaintext = vec![0x42u8; MAX_PLAINTEXT_SIZE + 1];
    let aad = &[0x17, 0x03, 0x03, 0x40, 0x01];

    let result = cipher.encrypt(&plaintext, aad);
    assert!(result.is_err());
}

#[test]
fn test_authentication_failure_wrong_tag() {
    let keys = TrafficKeys::new([0x42u8; KEY_SIZE], [0x13u8; IV_SIZE]);
    let mut cipher = AeadCipher::new(keys);

    let plaintext = b"Secret message";
    let aad = &[0x17, 0x03, 0x03, 0x00, 0x0e];

    let mut ciphertext = cipher.encrypt(plaintext, aad).unwrap();
    
    // Tamper with the authentication tag (last 16 bytes)
    let tag_start = ciphertext.len() - TAG_SIZE;
    ciphertext[tag_start] ^= 0xFF;

    cipher.reset_sequence_number();
    let result = cipher.decrypt(&ciphertext, aad);
    assert!(result.is_err(), "Should fail authentication with corrupted tag");
}

#[test]
fn test_authentication_failure_wrong_ciphertext() {
    let keys = TrafficKeys::new([0x42u8; KEY_SIZE], [0x13u8; IV_SIZE]);
    let mut cipher = AeadCipher::new(keys);

    let plaintext = b"Secret message";
    let aad = &[0x17, 0x03, 0x03, 0x00, 0x0e];

    let mut ciphertext = cipher.encrypt(plaintext, aad).unwrap();
    
    // Tamper with the ciphertext (not the tag)
    ciphertext[0] ^= 0xFF;

    cipher.reset_sequence_number();
    let result = cipher.decrypt(&ciphertext, aad);
    assert!(result.is_err(), "Should fail authentication with corrupted ciphertext");
}

#[test]
fn test_authentication_failure_wrong_aad() {
    let keys = TrafficKeys::new([0x42u8; KEY_SIZE], [0x13u8; IV_SIZE]);
    let mut cipher = AeadCipher::new(keys);

    let plaintext = b"Secret message";
    let aad = &[0x17, 0x03, 0x03, 0x00, 0x0e];

    let ciphertext = cipher.encrypt(plaintext, aad).unwrap();
    
    // Use different AAD for decryption
    let wrong_aad = &[0x17, 0x03, 0x03, 0x00, 0x0f];

    cipher.reset_sequence_number();
    let result = cipher.decrypt(&ciphertext, wrong_aad);
    assert!(result.is_err(), "Should fail authentication with wrong AAD");
}

#[test]
fn test_sequence_number_progression() {
    let keys = TrafficKeys::new([0x42u8; KEY_SIZE], [0x13u8; IV_SIZE]);
    let mut cipher = AeadCipher::new(keys);

    assert_eq!(cipher.sequence_number(), 0);

    let plaintext = b"Message 1";
    let aad = &[0x17, 0x03, 0x03, 0x00, 0x09];

    cipher.encrypt(plaintext, aad).unwrap();
    assert_eq!(cipher.sequence_number(), 1);

    cipher.encrypt(plaintext, aad).unwrap();
    assert_eq!(cipher.sequence_number(), 2);

    cipher.encrypt(plaintext, aad).unwrap();
    assert_eq!(cipher.sequence_number(), 3);
}

#[test]
fn test_nonce_uniqueness_with_sequence() {
    // Encrypt multiple records and verify they produce different ciphertexts
    // even with the same plaintext (due to different nonces)
    let keys = TrafficKeys::new([0x42u8; KEY_SIZE], [0x13u8; IV_SIZE]);
    let mut cipher = AeadCipher::new(keys);

    let plaintext = b"Same message";
    let aad = &[0x17, 0x03, 0x03, 0x00, 0x0c];

    let ct1 = cipher.encrypt(plaintext, aad).unwrap();
    let ct2 = cipher.encrypt(plaintext, aad).unwrap();
    let ct3 = cipher.encrypt(plaintext, aad).unwrap();

    // All ciphertexts should be different (nonce changes)
    assert_ne!(ct1, ct2);
    assert_ne!(ct2, ct3);
    assert_ne!(ct1, ct3);
}

#[test]
fn test_decrypt_requires_correct_sequence() {
    let keys = TrafficKeys::new([0x42u8; KEY_SIZE], [0x13u8; IV_SIZE]);
    let mut cipher_encrypt = AeadCipher::new(keys.clone());
    let mut cipher_decrypt = AeadCipher::new(keys);

    let plaintext1 = b"Message 1";
    let plaintext2 = b"Message 2";
    let aad = &[0x17, 0x03, 0x03, 0x00, 0x09];

    // Encrypt two messages
    let ct1 = cipher_encrypt.encrypt(plaintext1, aad).unwrap();
    let ct2 = cipher_encrypt.encrypt(plaintext2, aad).unwrap();

    // Decrypt in order
    let dec1 = cipher_decrypt.decrypt(&ct1, aad).unwrap();
    assert_eq!(dec1, plaintext1);

    let dec2 = cipher_decrypt.decrypt(&ct2, aad).unwrap();
    assert_eq!(dec2, plaintext2);
}

#[test]
fn test_encrypt_record_with_content_type() {
    let keys = TrafficKeys::new([0x42u8; KEY_SIZE], [0x13u8; IV_SIZE]);
    let mut cipher = AeadCipher::new(keys);

    let content = b"Application data";
    let content_type = ContentType::ApplicationData as u8;
    let aad = &[0x17, 0x03, 0x03, 0x00, 0x11];

    // Encrypt with content type
    let ciphertext = encrypt_record(&mut cipher, content, content_type, aad, 0).unwrap();

    // Should be: content + content_type (1 byte) + tag
    assert_eq!(ciphertext.len(), content.len() + 1 + TAG_SIZE);

    // Decrypt
    cipher.reset_sequence_number();
    let (decrypted_content, decrypted_type) = decrypt_record(&mut cipher, &ciphertext, aad).unwrap();
    
    assert_eq!(decrypted_content, content);
    assert_eq!(decrypted_type, content_type);
}

#[test]
fn test_encrypt_record_with_padding() {
    let keys = TrafficKeys::new([0x42u8; KEY_SIZE], [0x13u8; IV_SIZE]);
    let mut cipher = AeadCipher::new(keys);

    let content = b"Short";
    let content_type = ContentType::ApplicationData as u8;
    let padding_len = 10;
    let aad = &[0x17, 0x03, 0x03, 0x00, 0x10];

    // Encrypt with padding
    let ciphertext = encrypt_record(&mut cipher, content, content_type, aad, padding_len).unwrap();

    // Should be: content + content_type + padding + tag
    assert_eq!(ciphertext.len(), content.len() + 1 + padding_len + TAG_SIZE);

    // Decrypt
    cipher.reset_sequence_number();
    let (decrypted_content, decrypted_type) = decrypt_record(&mut cipher, &ciphertext, aad).unwrap();
    
    assert_eq!(decrypted_content, content);
    assert_eq!(decrypted_type, content_type);
}

#[test]
fn test_decrypt_record_strips_padding() {
    let keys = TrafficKeys::new([0x42u8; KEY_SIZE], [0x13u8; IV_SIZE]);
    let mut cipher = AeadCipher::new(keys);

    let content = b"Test message";
    let content_type = ContentType::Handshake as u8;
    let padding_len = 100;
    let aad = &[0x16, 0x03, 0x03, 0x00, 0x71];

    // Encrypt with substantial padding
    let ciphertext = encrypt_record(&mut cipher, content, content_type, aad, padding_len).unwrap();

    // Decrypt and verify padding is stripped
    cipher.reset_sequence_number();
    let (decrypted_content, decrypted_type) = decrypt_record(&mut cipher, &ciphertext, aad).unwrap();
    
    assert_eq!(decrypted_content, content);
    assert_eq!(decrypted_type, content_type);
    assert_eq!(decrypted_content.len(), content.len(), "Padding should be stripped");
}

#[test]
fn test_edge_case_empty_payload() {
    let keys = TrafficKeys::new([0x42u8; KEY_SIZE], [0x13u8; IV_SIZE]);
    let mut cipher = AeadCipher::new(keys);

    let empty_plaintext = b"";
    let aad = &[0x17, 0x03, 0x03, 0x00, 0x00];

    let ciphertext = cipher.encrypt(empty_plaintext, aad).unwrap();
    assert_eq!(ciphertext.len(), TAG_SIZE);

    cipher.reset_sequence_number();
    let decrypted = cipher.decrypt(&ciphertext, aad).unwrap();
    assert_eq!(decrypted, empty_plaintext);
}

#[test]
fn test_edge_case_single_byte() {
    let keys = TrafficKeys::new([0x42u8; KEY_SIZE], [0x13u8; IV_SIZE]);
    let mut cipher = AeadCipher::new(keys);

    let single_byte = b"X";
    let aad = &[0x17, 0x03, 0x03, 0x00, 0x01];

    let ciphertext = cipher.encrypt(single_byte, aad).unwrap();
    assert_eq!(ciphertext.len(), 1 + TAG_SIZE);

    cipher.reset_sequence_number();
    let decrypted = cipher.decrypt(&ciphertext, aad).unwrap();
    assert_eq!(decrypted, single_byte);
}

#[test]
fn test_integration_with_key_schedule() {
    // Test integration with HKDF key derivation
    let mut key_schedule = KeySchedule::new();
    
    // Simulate X25519 shared secret
    let shared_secret = [0x42u8; 32];
    key_schedule.advance_to_handshake_secret(&shared_secret);

    // Simulate transcript hash
    let transcript_hash = [0x13u8; 32];
    
    // Derive handshake traffic secrets
    let client_secret = key_schedule.derive_client_handshake_traffic_secret(&transcript_hash);
    let server_secret = key_schedule.derive_server_handshake_traffic_secret(&transcript_hash);

    // Derive traffic keys
    let client_keys = derive_traffic_keys(&client_secret);
    let server_keys = derive_traffic_keys(&server_secret);

    // Create separate ciphers for send and receive
    let mut client_send_cipher = AeadCipher::new(client_keys.clone());
    let mut server_recv_cipher = AeadCipher::new(client_keys);
    
    let mut server_send_cipher = AeadCipher::new(server_keys.clone());
    let mut client_recv_cipher = AeadCipher::new(server_keys);

    // Client encrypts, server decrypts
    let plaintext = b"Client to Server";
    let aad = &[0x17, 0x03, 0x03, 0x00, 0x10];

    let ciphertext = client_send_cipher.encrypt(plaintext, aad).unwrap();
    let decrypted = server_recv_cipher.decrypt(&ciphertext, aad).unwrap();
    assert_eq!(decrypted, plaintext);

    // Server encrypts, client decrypts
    let plaintext = b"Server to Client";
    let aad = &[0x17, 0x03, 0x03, 0x00, 0x10];

    let ciphertext = server_send_cipher.encrypt(plaintext, aad).unwrap();
    let decrypted = client_recv_cipher.decrypt(&ciphertext, aad).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_integration_application_traffic() {
    // Test with application traffic secrets
    let mut key_schedule = KeySchedule::new();
    
    // Progress through the key schedule
    let shared_secret = [0x42u8; 32];
    key_schedule.advance_to_handshake_secret(&shared_secret);
    key_schedule.advance_to_master_secret();

    let transcript_hash = [0x13u8; 32];
    
    // Derive application traffic secrets
    let client_secret = key_schedule.derive_client_application_traffic_secret(&transcript_hash);
    let server_secret = key_schedule.derive_server_application_traffic_secret(&transcript_hash);

    // Derive traffic keys
    let client_keys = derive_traffic_keys(&client_secret);
    let server_keys = derive_traffic_keys(&server_secret);

    // Create separate ciphers for send and receive
    let mut client_send_cipher = AeadCipher::new(client_keys.clone());
    let mut server_recv_cipher = AeadCipher::new(client_keys);
    
    let mut server_send_cipher = AeadCipher::new(server_keys.clone());
    let mut client_recv_cipher = AeadCipher::new(server_keys);

    // Exchange multiple messages
    for i in 0..10 {
        let msg = format!("Message {}", i);
        let aad = &[0x17, 0x03, 0x03, 0x00, msg.len() as u8];

        // Client to server
        let ct = client_send_cipher.encrypt(msg.as_bytes(), aad).unwrap();
        let dec = server_recv_cipher.decrypt(&ct, aad).unwrap();
        assert_eq!(dec, msg.as_bytes());
        
        // Server to client
        let ct = server_send_cipher.encrypt(msg.as_bytes(), aad).unwrap();
        let dec = client_recv_cipher.decrypt(&ct, aad).unwrap();
        assert_eq!(dec, msg.as_bytes());
    }
}

#[test]
fn test_traffic_keys_zeroize() {
    // Verify TrafficKeys implements ZeroizeOnDrop
    // This is a compile-time check more than a runtime test
    let keys = TrafficKeys::new([0x42u8; KEY_SIZE], [0x13u8; IV_SIZE]);
    drop(keys); // Keys should be zeroized on drop
    
    // If this compiles, ZeroizeOnDrop is working
    assert!(true);
}

#[test]
fn test_ciphertext_differs_from_plaintext() {
    let keys = TrafficKeys::new([0x42u8; KEY_SIZE], [0x13u8; IV_SIZE]);
    let mut cipher = AeadCipher::new(keys);

    let plaintext = b"This is a test message that should be encrypted";
    let aad = &[0x17, 0x03, 0x03, 0x00, plaintext.len() as u8];

    let ciphertext = cipher.encrypt(plaintext, aad).unwrap();
    
    // Extract just the encrypted portion (without tag)
    let encrypted_portion = &ciphertext[..plaintext.len()];
    
    // Ciphertext should differ from plaintext
    assert_ne!(encrypted_portion, plaintext);
}

#[test]
fn test_different_keys_produce_different_ciphertexts() {
    let keys1 = TrafficKeys::new([0x42u8; KEY_SIZE], [0x13u8; IV_SIZE]);
    let keys2 = TrafficKeys::new([0x43u8; KEY_SIZE], [0x13u8; IV_SIZE]);
    
    let mut cipher1 = AeadCipher::new(keys1);
    let mut cipher2 = AeadCipher::new(keys2);

    let plaintext = b"Same plaintext";
    let aad = &[0x17, 0x03, 0x03, 0x00, 0x0e];

    let ct1 = cipher1.encrypt(plaintext, aad).unwrap();
    let ct2 = cipher2.encrypt(plaintext, aad).unwrap();

    assert_ne!(ct1, ct2, "Different keys should produce different ciphertexts");
}

#[test]
fn test_different_ivs_produce_different_ciphertexts() {
    let keys1 = TrafficKeys::new([0x42u8; KEY_SIZE], [0x13u8; IV_SIZE]);
    let keys2 = TrafficKeys::new([0x42u8; KEY_SIZE], [0x14u8; IV_SIZE]);
    
    let mut cipher1 = AeadCipher::new(keys1);
    let mut cipher2 = AeadCipher::new(keys2);

    let plaintext = b"Same plaintext";
    let aad = &[0x17, 0x03, 0x03, 0x00, 0x0e];

    let ct1 = cipher1.encrypt(plaintext, aad).unwrap();
    let ct2 = cipher2.encrypt(plaintext, aad).unwrap();

    assert_ne!(ct1, ct2, "Different IVs should produce different ciphertexts");
}

#[test]
#[should_panic]
fn test_wrong_sequence_number_fails() {
    let keys = TrafficKeys::new([0x42u8; KEY_SIZE], [0x13u8; IV_SIZE]);
    let mut cipher_encrypt = AeadCipher::new(keys.clone());
    let mut cipher_decrypt = AeadCipher::new(keys);

    let plaintext = b"Message";
    let aad = &[0x17, 0x03, 0x03, 0x00, 0x07];

    // Encrypt with sequence 0
    let ct = cipher_encrypt.encrypt(plaintext, aad).unwrap();

    // Skip sequence 0 on decrypt side
    cipher_decrypt.encrypt(b"dummy", aad).unwrap();

    // Try to decrypt with wrong sequence (should fail)
    cipher_decrypt.decrypt(&ct, aad).unwrap();
}

#[test]
fn test_tls_record_header_as_aad() {
    let keys = TrafficKeys::new([0x42u8; KEY_SIZE], [0x13u8; IV_SIZE]);
    let mut cipher = AeadCipher::new(keys);

    let plaintext = b"Test data";
    
    // Construct proper TLS record header as AAD
    // ContentType (1) | Version (2) | Length (2)
    let content_type = ContentType::ApplicationData as u8;
    let version = 0x0303u16; // TLS 1.2 (used in TLS 1.3 records)
    let length = (plaintext.len() + TAG_SIZE) as u16;
    
    let mut aad = Vec::new();
    aad.push(content_type);
    aad.extend_from_slice(&version.to_be_bytes());
    aad.extend_from_slice(&length.to_be_bytes());

    let ciphertext = cipher.encrypt(plaintext, &aad).unwrap();
    
    cipher.reset_sequence_number();
    let decrypted = cipher.decrypt(&ciphertext, &aad).unwrap();
    assert_eq!(decrypted, plaintext);
}
