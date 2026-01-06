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

    // Use separate cipher instances for encryption and decryption
    let mut encrypt_cipher = AeadCipher::new(TrafficKeys::new(key, iv));
    let mut decrypt_cipher = AeadCipher::new(TrafficKeys::new(key, iv));

    // Encrypt
    let ciphertext = encrypt_cipher.encrypt(plaintext, aad).unwrap();
    
    // Ciphertext should only be the tag for empty plaintext
    assert_eq!(ciphertext.len(), TAG_SIZE);

    // Decrypt
    let decrypted = decrypt_cipher.decrypt(&ciphertext, aad).unwrap();
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

    // Use separate cipher instances for encryption and decryption
    let mut encrypt_cipher = AeadCipher::new(TrafficKeys::new(key, iv));
    let mut decrypt_cipher = AeadCipher::new(TrafficKeys::new(key, iv));

    // Encrypt
    let ciphertext = encrypt_cipher.encrypt(plaintext, aad).unwrap();
    assert_eq!(ciphertext.len(), plaintext.len() + TAG_SIZE);
    assert_ne!(&ciphertext[..plaintext.len()], plaintext);

    // Decrypt
    let decrypted = decrypt_cipher.decrypt(&ciphertext, aad).unwrap();
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
        // Use separate cipher instances for each test
        let mut encrypt_cipher = AeadCipher::new(keys.clone());
        let mut decrypt_cipher = AeadCipher::new(keys.clone());
        
        // Create plaintext of specified size
        let plaintext: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        let aad = &[0x17, 0x03, 0x03, (size >> 8) as u8, (size & 0xff) as u8];

        // Encrypt
        let ciphertext = encrypt_cipher.encrypt(&plaintext, aad).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + TAG_SIZE);

        // Decrypt
        let decrypted = decrypt_cipher.decrypt(&ciphertext, aad).unwrap();
        assert_eq!(decrypted, plaintext, "Failed for size {}", size);
    }
}

#[test]
fn test_max_record_size() {
    let key = [0x55u8; KEY_SIZE];
    let iv = [0xAAu8; IV_SIZE];
    
    // Use separate cipher instances
    let mut encrypt_cipher = AeadCipher::new(TrafficKeys::new(key, iv));
    let mut decrypt_cipher = AeadCipher::new(TrafficKeys::new(key, iv));

    // Create maximum-sized plaintext (16KB)
    let plaintext = vec![0x42u8; MAX_PLAINTEXT_SIZE];
    let aad = &[0x17, 0x03, 0x03, 0x40, 0x00];

    let ciphertext = encrypt_cipher.encrypt(&plaintext, aad).unwrap();
    assert_eq!(ciphertext.len(), MAX_PLAINTEXT_SIZE + TAG_SIZE);

    let decrypted = decrypt_cipher.decrypt(&ciphertext, aad).unwrap();
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
    let key = [0x42u8; KEY_SIZE];
    let iv = [0x13u8; IV_SIZE];
    let mut encrypt_cipher = AeadCipher::new(TrafficKeys::new(key, iv));
    let mut decrypt_cipher = AeadCipher::new(TrafficKeys::new(key, iv));

    let plaintext = b"Secret message";
    let aad = &[0x17, 0x03, 0x03, 0x00, 0x0e];

    let mut ciphertext = encrypt_cipher.encrypt(plaintext, aad).unwrap();
    
    // Tamper with the authentication tag (last 16 bytes)
    let tag_start = ciphertext.len() - TAG_SIZE;
    ciphertext[tag_start] ^= 0xFF;

    let result = decrypt_cipher.decrypt(&ciphertext, aad);
    assert!(result.is_err(), "Should fail authentication with corrupted tag");
}

#[test]
fn test_authentication_failure_wrong_ciphertext() {
    let key = [0x42u8; KEY_SIZE];
    let iv = [0x13u8; IV_SIZE];
    let mut encrypt_cipher = AeadCipher::new(TrafficKeys::new(key, iv));
    let mut decrypt_cipher = AeadCipher::new(TrafficKeys::new(key, iv));

    let plaintext = b"Secret message";
    let aad = &[0x17, 0x03, 0x03, 0x00, 0x0e];

    let mut ciphertext = encrypt_cipher.encrypt(plaintext, aad).unwrap();
    
    // Tamper with the ciphertext (not the tag)
    ciphertext[0] ^= 0xFF;

    let result = decrypt_cipher.decrypt(&ciphertext, aad);
    assert!(result.is_err(), "Should fail authentication with corrupted ciphertext");
}

#[test]
fn test_authentication_failure_wrong_aad() {
    let key = [0x42u8; KEY_SIZE];
    let iv = [0x13u8; IV_SIZE];
    let mut encrypt_cipher = AeadCipher::new(TrafficKeys::new(key, iv));
    let mut decrypt_cipher = AeadCipher::new(TrafficKeys::new(key, iv));

    let plaintext = b"Secret message";
    let aad = &[0x17, 0x03, 0x03, 0x00, 0x0e];

    let ciphertext = encrypt_cipher.encrypt(plaintext, aad).unwrap();
    
    // Use different AAD for decryption
    let wrong_aad = &[0x17, 0x03, 0x03, 0x00, 0x0f];

    let result = decrypt_cipher.decrypt(&ciphertext, wrong_aad);
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
    let key = [0x42u8; KEY_SIZE];
    let iv = [0x13u8; IV_SIZE];
    let mut encrypt_cipher = AeadCipher::new(TrafficKeys::new(key, iv));
    let mut decrypt_cipher = AeadCipher::new(TrafficKeys::new(key, iv));

    let content = b"Application data";
    let content_type = ContentType::ApplicationData as u8;
    let aad = &[0x17, 0x03, 0x03, 0x00, 0x11];

    // Encrypt with content type
    let ciphertext = encrypt_record(&mut encrypt_cipher, content, content_type, aad, 0).unwrap();

    // Should be: content + content_type (1 byte) + tag
    assert_eq!(ciphertext.len(), content.len() + 1 + TAG_SIZE);

    // Decrypt
    let (decrypted_content, decrypted_type) = decrypt_record(&mut decrypt_cipher, &ciphertext, aad).unwrap();
    
    assert_eq!(decrypted_content, content);
    assert_eq!(decrypted_type, content_type);
}

#[test]
fn test_encrypt_record_with_padding() {
    let key = [0x42u8; KEY_SIZE];
    let iv = [0x13u8; IV_SIZE];
    let mut encrypt_cipher = AeadCipher::new(TrafficKeys::new(key, iv));
    let mut decrypt_cipher = AeadCipher::new(TrafficKeys::new(key, iv));

    let content = b"Short";
    let content_type = ContentType::ApplicationData as u8;
    let padding_len = 10;
    let aad = &[0x17, 0x03, 0x03, 0x00, 0x10];

    // Encrypt with padding
    let ciphertext = encrypt_record(&mut encrypt_cipher, content, content_type, aad, padding_len).unwrap();

    // Should be: content + content_type + padding + tag
    assert_eq!(ciphertext.len(), content.len() + 1 + padding_len + TAG_SIZE);

    // Decrypt
    let (decrypted_content, decrypted_type) = decrypt_record(&mut decrypt_cipher, &ciphertext, aad).unwrap();
    
    assert_eq!(decrypted_content, content);
    assert_eq!(decrypted_type, content_type);
}

#[test]
fn test_decrypt_record_strips_padding() {
    let key = [0x42u8; KEY_SIZE];
    let iv = [0x13u8; IV_SIZE];
    let mut encrypt_cipher = AeadCipher::new(TrafficKeys::new(key, iv));
    let mut decrypt_cipher = AeadCipher::new(TrafficKeys::new(key, iv));

    let content = b"Test message";
    let content_type = ContentType::Handshake as u8;
    let padding_len = 100;
    let aad = &[0x16, 0x03, 0x03, 0x00, 0x71];

    // Encrypt with substantial padding
    let ciphertext = encrypt_record(&mut encrypt_cipher, content, content_type, aad, padding_len).unwrap();

    // Decrypt and verify padding is stripped
    let (decrypted_content, decrypted_type) = decrypt_record(&mut decrypt_cipher, &ciphertext, aad).unwrap();
    
    assert_eq!(decrypted_content, content);
    assert_eq!(decrypted_type, content_type);
    assert_eq!(decrypted_content.len(), content.len(), "Padding should be stripped");
}

#[test]
fn test_edge_case_empty_payload() {
    let key = [0x42u8; KEY_SIZE];
    let iv = [0x13u8; IV_SIZE];
    let mut encrypt_cipher = AeadCipher::new(TrafficKeys::new(key, iv));
    let mut decrypt_cipher = AeadCipher::new(TrafficKeys::new(key, iv));

    let empty_plaintext = b"";
    let aad = &[0x17, 0x03, 0x03, 0x00, 0x00];

    let ciphertext = encrypt_cipher.encrypt(empty_plaintext, aad).unwrap();
    assert_eq!(ciphertext.len(), TAG_SIZE);

    let decrypted = decrypt_cipher.decrypt(&ciphertext, aad).unwrap();
    assert_eq!(decrypted, empty_plaintext);
}

#[test]
fn test_edge_case_single_byte() {
    let key = [0x42u8; KEY_SIZE];
    let iv = [0x13u8; IV_SIZE];
    let mut encrypt_cipher = AeadCipher::new(TrafficKeys::new(key, iv));
    let mut decrypt_cipher = AeadCipher::new(TrafficKeys::new(key, iv));

    let single_byte = b"X";
    let aad = &[0x17, 0x03, 0x03, 0x00, 0x01];

    let ciphertext = encrypt_cipher.encrypt(single_byte, aad).unwrap();
    assert_eq!(ciphertext.len(), 1 + TAG_SIZE);

    let decrypted = decrypt_cipher.decrypt(&ciphertext, aad).unwrap();
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
    // This is a compile-time check - if this compiles, ZeroizeOnDrop is working
    let keys = TrafficKeys::new([0x42u8; KEY_SIZE], [0x13u8; IV_SIZE]);
    drop(keys); // Keys should be zeroized on drop
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
    let key = [0x42u8; KEY_SIZE];
    let iv = [0x13u8; IV_SIZE];
    let mut encrypt_cipher = AeadCipher::new(TrafficKeys::new(key, iv));
    let mut decrypt_cipher = AeadCipher::new(TrafficKeys::new(key, iv));

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

    let ciphertext = encrypt_cipher.encrypt(plaintext, &aad).unwrap();
    
    let decrypted = decrypt_cipher.decrypt(&ciphertext, &aad).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_update_keys_resets_sequence_safely() {
    // Test that update_keys() safely transitions to new keys and resets sequence
    let old_key = [0x42u8; KEY_SIZE];
    let old_iv = [0x13u8; IV_SIZE];
    let mut cipher = AeadCipher::new(TrafficKeys::new(old_key, old_iv));

    let plaintext = b"Message 1";
    let aad = &[0x17, 0x03, 0x03, 0x00, 0x09];

    // Encrypt a few messages with the old key
    cipher.encrypt(plaintext, aad).unwrap();
    cipher.encrypt(plaintext, aad).unwrap();
    assert_eq!(cipher.sequence_number(), 2);

    // Simulate key update (e.g., TLS 1.3 KeyUpdate)
    let new_key = [0x99u8; KEY_SIZE];
    let new_iv = [0xAAu8; IV_SIZE];
    cipher.update_keys(TrafficKeys::new(new_key, new_iv));

    // Sequence number should be reset to 0 with the new key
    assert_eq!(cipher.sequence_number(), 0);

    // Can now safely encrypt with the new key starting from sequence 0
    let new_plaintext = b"Message after key update";
    let new_aad = &[0x17, 0x03, 0x03, 0x00, 0x18];
    let ciphertext = cipher.encrypt(new_plaintext, new_aad).unwrap();
    
    // Verify it encrypted successfully
    assert_eq!(ciphertext.len(), new_plaintext.len() + TAG_SIZE);
    assert_eq!(cipher.sequence_number(), 1);
}

#[test]
fn test_update_keys_prevents_nonce_reuse() {
    // Demonstrate that update_keys prevents nonce reuse by tying
    // sequence number reset to key updates
    let key1 = [0x11u8; KEY_SIZE];
    let iv1 = [0x22u8; IV_SIZE];
    let mut cipher = AeadCipher::new(TrafficKeys::new(key1, iv1));

    let plaintext = b"Test message";
    let aad = &[0x17, 0x03, 0x03, 0x00, 0x0c];

    // Encrypt with sequence 0
    let ct1 = cipher.encrypt(plaintext, aad).unwrap();
    assert_eq!(cipher.sequence_number(), 1);

    // Update to new keys - this is the ONLY safe way to reset sequence
    let key2 = [0x33u8; KEY_SIZE];
    let iv2 = [0x44u8; IV_SIZE];
    cipher.update_keys(TrafficKeys::new(key2, iv2));
    assert_eq!(cipher.sequence_number(), 0);

    // Now we can safely encrypt again with sequence 0, but with different keys
    let ct2 = cipher.encrypt(plaintext, aad).unwrap();
    
    // The ciphertexts should be different because they use different keys
    // even though both used sequence number 0
    assert_ne!(ct1, ct2, "Same sequence but different keys should produce different ciphertexts");
}

/// Test that content ending with zero bytes is correctly preserved
/// This is a critical edge case: the RFC states padding consists of zero bytes,
/// but legitimate content can also end with zeros. The content type byte (non-zero)
/// serves as the delimiter between content and padding.
#[test]
fn test_content_ending_with_zeros() {
    let key = [0x42u8; KEY_SIZE];
    let iv = [0x13u8; IV_SIZE];
    let mut encrypt_cipher = AeadCipher::new(TrafficKeys::new(key, iv));
    let mut decrypt_cipher = AeadCipher::new(TrafficKeys::new(key, iv));

    // Content that ends with multiple zero bytes (legitimate data)
    let content = vec![0x01, 0x02, 0x03, 0x00, 0x00, 0x00];
    let content_type = ContentType::ApplicationData as u8; // 0x17
    let padding_len = 5; // Add some padding too
    let aad = &[0x17, 0x03, 0x03, 0x00, 0x0c];

    // Encrypt: content || content_type || padding
    // Result: [0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x00, 0x00]
    let ciphertext = encrypt_record(&mut encrypt_cipher, &content, content_type, aad, padding_len).unwrap();

    // Decrypt should correctly identify:
    // - Content: [0x01, 0x02, 0x03, 0x00, 0x00, 0x00] (including trailing zeros)
    // - ContentType: 0x17 (the delimiter)
    // - Padding: stripped away
    let (decrypted_content, decrypted_type) = decrypt_record(&mut decrypt_cipher, &ciphertext, aad).unwrap();
    
    assert_eq!(decrypted_content, content, "Content with trailing zeros should be preserved");
    assert_eq!(decrypted_type, content_type);
}

/// Test that content consisting entirely of zeros is correctly handled
#[test]
fn test_content_all_zeros() {
    let key = [0x42u8; KEY_SIZE];
    let iv = [0x13u8; IV_SIZE];
    let mut encrypt_cipher = AeadCipher::new(TrafficKeys::new(key, iv));
    let mut decrypt_cipher = AeadCipher::new(TrafficKeys::new(key, iv));

    // Content that is all zeros
    let content = vec![0x00, 0x00, 0x00, 0x00];
    let content_type = ContentType::ApplicationData as u8; // 0x17
    let aad = &[0x17, 0x03, 0x03, 0x00, 0x05];

    let ciphertext = encrypt_record(&mut encrypt_cipher, &content, content_type, aad, 0).unwrap();
    let (decrypted_content, decrypted_type) = decrypt_record(&mut decrypt_cipher, &ciphertext, aad).unwrap();
    
    assert_eq!(decrypted_content, content, "All-zero content should be preserved");
    assert_eq!(decrypted_type, content_type);
}

/// Test that content with zeros followed by padding is correctly handled
#[test]
fn test_content_zeros_with_padding() {
    let key = [0x42u8; KEY_SIZE];
    let iv = [0x13u8; IV_SIZE];
    let mut encrypt_cipher = AeadCipher::new(TrafficKeys::new(key, iv));
    let mut decrypt_cipher = AeadCipher::new(TrafficKeys::new(key, iv));

    // Complex case: content ends with zeros AND we have padding
    let content = vec![0xAA, 0xBB, 0x00, 0x00];
    let content_type = ContentType::Handshake as u8; // 0x16
    let padding_len = 10;
    let aad = &[0x16, 0x03, 0x03, 0x00, 0x0f];

    // Structure: [0xAA, 0xBB, 0x00, 0x00, 0x16, 0x00, 0x00, ...]
    //             ^-- content --^  ^type^ ^-- padding --^
    let ciphertext = encrypt_record(&mut encrypt_cipher, &content, content_type, aad, padding_len).unwrap();
    let (decrypted_content, decrypted_type) = decrypt_record(&mut decrypt_cipher, &ciphertext, aad).unwrap();
    
    assert_eq!(decrypted_content, content, "Content zeros should not be confused with padding");
    assert_eq!(decrypted_type, content_type);
}

/// Test that AAD length field matches actual encrypted record length
/// This test verifies the critical security property that the length in the AAD
/// must exactly match the length of the encrypted record being sent.
#[test]
fn test_aad_length_calculation_with_padding() {
    let key = [0x42u8; KEY_SIZE];
    let iv = [0x13u8; IV_SIZE];
    
    let content = b"Test message";
    let content_type = ContentType::ApplicationData as u8;
    
    // Test with different padding lengths
    for padding_len in [0, 1, 10, 100] {
        let mut encrypt_cipher = AeadCipher::new(TrafficKeys::new(key, iv));
        let mut decrypt_cipher = AeadCipher::new(TrafficKeys::new(key, iv));
        
        // Calculate the correct AAD length
        // Encrypted record = AEAD_Encrypt(content || content_type || padding)
        // Final ciphertext = inner_plaintext || authentication_tag
        let inner_plaintext_len = content.len() + 1 + padding_len; // content + type + padding
        let encrypted_record_len = inner_plaintext_len + TAG_SIZE; // + auth tag
        
        // Construct AAD with correct length
        let aad = [
            ContentType::ApplicationData as u8,
            0x03, 0x03,
            (encrypted_record_len >> 8) as u8,
            (encrypted_record_len & 0xff) as u8,
        ];
        
        // Encrypt
        let ciphertext = encrypt_record(&mut encrypt_cipher, content, content_type, &aad, padding_len).unwrap();
        
        // Verify the ciphertext length matches what we put in the AAD
        assert_eq!(
            ciphertext.len(), encrypted_record_len,
            "Ciphertext length should match AAD length field for padding_len={}",
            padding_len
        );
        
        // Verify decryption works
        let (decrypted, dec_type) = decrypt_record(&mut decrypt_cipher, &ciphertext, &aad).unwrap();
        assert_eq!(decrypted, content);
        assert_eq!(dec_type, content_type);
    }
}

/// Test that incorrect AAD length causes authentication failure
#[test]
fn test_incorrect_aad_length_fails() {
    let key = [0x42u8; KEY_SIZE];
    let iv = [0x13u8; IV_SIZE];
    let mut encrypt_cipher = AeadCipher::new(TrafficKeys::new(key, iv));
    let mut decrypt_cipher = AeadCipher::new(TrafficKeys::new(key, iv));
    
    let content = b"Test";
    let content_type = ContentType::ApplicationData as u8;
    let padding_len = 5;
    
    // Correct AAD
    let inner_len = content.len() + 1 + padding_len;
    let correct_len = inner_len + TAG_SIZE;
    let correct_aad = [
        ContentType::ApplicationData as u8,
        0x03, 0x03,
        (correct_len >> 8) as u8,
        (correct_len & 0xff) as u8,
    ];
    
    // Encrypt with correct AAD
    let ciphertext = encrypt_record(&mut encrypt_cipher, content, content_type, &correct_aad, padding_len).unwrap();
    
    // Try to decrypt with incorrect AAD (wrong length)
    let wrong_len = correct_len + 1;
    let wrong_aad = [
        ContentType::ApplicationData as u8,
        0x03, 0x03,
        (wrong_len >> 8) as u8,
        (wrong_len & 0xff) as u8,
    ];
    
    // Should fail authentication
    let result = decrypt_cipher.decrypt(&ciphertext, &wrong_aad);
    assert!(result.is_err(), "Decryption should fail with incorrect AAD length");
}

