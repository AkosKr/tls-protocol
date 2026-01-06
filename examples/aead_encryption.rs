//! Example demonstrating AES-128-GCM authenticated encryption in TLS 1.3
//!
//! This example shows the complete flow from key derivation to record encryption/decryption.

use sha2::{Digest, Sha256};
use tls_protocol::{
    aead::{AeadCipher, encrypt_record, decrypt_record},
    key_schedule::{KeySchedule, derive_traffic_keys},
    ContentType,
};

fn main() {
    println!("TLS 1.3 AES-128-GCM Encryption Example\n");
    println!("======================================\n");

    // Step 1: Initialize Key Schedule and advance to Handshake Secret
    let mut key_schedule = KeySchedule::new();
    let shared_secret = [0x42u8; 32]; // From X25519 key exchange
    key_schedule.advance_to_handshake_secret(&shared_secret);
    println!("✓ Key schedule initialized and advanced to Handshake Secret\n");

    // Step 2: Compute transcript hash and derive handshake traffic secrets
    let mut hasher = Sha256::new();
    hasher.update(b"ClientHello");
    hasher.update(b"ServerHello");
    let transcript_hash = hasher.finalize();
    
    let client_hs_secret = key_schedule.derive_client_handshake_traffic_secret(&transcript_hash);
    let server_hs_secret = key_schedule.derive_server_handshake_traffic_secret(&transcript_hash);
    println!("✓ Derived handshake traffic secrets");
    
    // Step 3: Derive traffic keys from secrets
    let client_keys = derive_traffic_keys(&client_hs_secret);
    let _server_keys = derive_traffic_keys(&server_hs_secret); // For completeness
    println!("✓ Derived traffic keys (16-byte AES key + 12-byte IV)\n");

    // Step 4: Create separate ciphers for each direction
    // Client sends with client_keys, server receives with client_keys
    // Server sends with server_keys, client receives with server_keys
    let mut client_send = AeadCipher::new(client_keys.clone());
    let mut server_recv = AeadCipher::new(client_keys);
    println!("✓ Created client send and server receive ciphers\n");

    // Step 5: Encrypt a handshake message (Client → Server)
    let plaintext = b"Encrypted Handshake Message";
    let content_type = ContentType::Handshake as u8;
    
    // Construct AAD (TLS record header)
    let inner_len = plaintext.len() + 1; // content + content_type
    let record_len = (inner_len + 16) as u16; // + authentication tag
    let aad = [
        ContentType::ApplicationData as u8, // TLS 1.3 opaque type
        0x03, 0x03, // TLS 1.2 legacy version
        (record_len >> 8) as u8,
        (record_len & 0xff) as u8,
    ];
    
    println!("Encrypting record:");
    println!("  Plaintext: {} bytes", plaintext.len());
    println!("  AAD (record header): {:?}", aad);
    
    let ciphertext = encrypt_record(&mut client_send, plaintext, content_type, &aad, 0).unwrap();
    println!("  Ciphertext: {} bytes", ciphertext.len());
    println!("  Client sequence number after encrypt: {}\n", client_send.sequence_number());

    // Step 6: Decrypt the message (Server side)
    println!("Decrypting record:");
    let (decrypted, decrypted_type) = decrypt_record(&mut server_recv, &ciphertext, &aad).unwrap();
    println!("  Decrypted: {} bytes", decrypted.len());
    println!("  Content type: 0x{:02x}", decrypted_type);
    println!("  Server sequence number after decrypt: {}", server_recv.sequence_number());
    
    assert_eq!(decrypted, plaintext);
    assert_eq!(decrypted_type, content_type);
    println!("  ✓ Authentication tag verified");
    println!("  ✓ Message integrity confirmed\n");

    // Step 7: Advance to Master Secret and application traffic
    key_schedule.advance_to_master_secret();
    
    let mut app_hasher = Sha256::new();
    app_hasher.update(&transcript_hash);
    app_hasher.update(b"Finished");
    let app_transcript = app_hasher.finalize();
    
    let client_app_secret = key_schedule.derive_client_application_traffic_secret(&app_transcript);
    let server_app_secret = key_schedule.derive_server_application_traffic_secret(&app_transcript);
    
    let client_app_keys = derive_traffic_keys(&client_app_secret);
    let _server_app_keys = derive_traffic_keys(&server_app_secret); // For completeness
    
    let mut client_app_send = AeadCipher::new(client_app_keys.clone());
    let mut server_app_recv = AeadCipher::new(client_app_keys);
    
    println!("✓ Advanced to Master Secret");
    println!("✓ Derived application traffic keys\n");

    // Step 8: Encrypt application data
    println!("Encrypting application data:");
    let app_data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let app_inner_len = app_data.len() + 1;
    let app_record_len = (app_inner_len + 16) as u16;
    let app_aad = [
        ContentType::ApplicationData as u8,
        0x03, 0x03,
        (app_record_len >> 8) as u8,
        (app_record_len & 0xff) as u8,
    ];
    
    let app_ct = encrypt_record(
        &mut client_app_send,
        app_data,
        ContentType::ApplicationData as u8,
        &app_aad,
        0,
    ).unwrap();
    
    println!("  Application data: {} bytes", app_data.len());
    println!("  Encrypted: {} bytes", app_ct.len());
    
    let (app_dec, _) = decrypt_record(&mut server_app_recv, &app_ct, &app_aad).unwrap();
    println!("  Decrypted: {}", String::from_utf8_lossy(&app_dec));
    assert_eq!(app_dec, app_data);
    println!("  ✓ Application data transmitted successfully\n");

    // Step 9: Multiple records
    println!("Exchanging multiple records:");
    for i in 1..=5 {
        let msg = format!("Message {}", i).into_bytes();
        let len = (msg.len() + 1 + 16) as u16;
        let aad = [
            ContentType::ApplicationData as u8,
            0x03, 0x03,
            (len >> 8) as u8,
            (len & 0xff) as u8,
        ];
        
        let ct = encrypt_record(
            &mut client_app_send,
            &msg,
            ContentType::ApplicationData as u8,
            &aad,
            0,
        ).unwrap();
        
        let (dec, _) = decrypt_record(&mut server_app_recv, &ct, &aad).unwrap();
        assert_eq!(dec, msg);
        println!("  ✓ Record {}: encrypted and decrypted successfully", i);
    }
    
    println!("\n  Final client sequence number: {}", client_app_send.sequence_number());
    println!("  Final server sequence number: {}\n", server_app_recv.sequence_number());

    // Summary
    println!("Summary");
    println!("=======");
    println!("✓ Complete TLS 1.3 key schedule flow");
    println!("✓ HKDF-based traffic key derivation");
    println!("✓ AES-128-GCM encryption and decryption");
    println!("✓ Per-record nonce construction (sequence number XOR IV)");
    println!("✓ Authentication tag generation and verification");
    println!("✓ Multiple record handling with incrementing sequence numbers");
    println!("\nAll operations completed successfully!");
}
