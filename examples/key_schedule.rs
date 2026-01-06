//! Example demonstrating the complete TLS 1.3 key schedule
//! 
//! This example shows how to:
//! 1. Perform X25519 ECDHE key exchange
//! 2. Progress through the key schedule stages
//! 3. Derive handshake and application traffic secrets
//!
//! This simulates what happens during a real TLS 1.3 handshake.

use sha2::{Digest, Sha256};
use tls_protocol::key_schedule::KeySchedule;
use tls_protocol::x25519_key_exchange::X25519KeyPair;

fn main() {
    println!("=== TLS 1.3 Key Schedule Example ===\n");

    // Step 1: Simulate ECDHE Key Exchange
    println!("Step 1: Performing X25519 ECDHE Key Exchange");
    println!("-------------------------------------------");
    
    let client_keypair = X25519KeyPair::generate();
    let server_keypair = X25519KeyPair::generate();
    
    let client_public = client_keypair.public_key_bytes();
    let server_public = server_keypair.public_key_bytes();
    
    println!("Client public key: {:?}", hex::encode(&client_public));
    println!("Server public key: {:?}", hex::encode(&server_public));
    
    // Both parties compute the shared secret
    let client_shared = client_keypair
        .compute_shared_secret(&server_public)
        .expect("Client key exchange failed");
    
    let server_shared = server_keypair
        .compute_shared_secret(&client_public)
        .expect("Server key exchange failed");
    
    assert_eq!(client_shared, server_shared);
    println!("Shared secret computed: {:?}", hex::encode(&client_shared));
    println!();

    // Step 2: Initialize Key Schedule (Early Secret)
    println!("Step 2: Initializing Key Schedule (Early Secret)");
    println!("------------------------------------------------");
    
    let mut key_schedule = KeySchedule::new();
    println!("Early Secret: {:?}", hex::encode(&key_schedule.current_secret()));
    println!();

    // Step 3: Advance to Handshake Secret
    println!("Step 3: Advancing to Handshake Secret");
    println!("-------------------------------------");
    
    key_schedule.advance_to_handshake_secret(&client_shared);
    println!("Handshake Secret: {:?}", hex::encode(&key_schedule.current_secret()));
    println!();

    // Step 4: Derive Handshake Traffic Secrets
    println!("Step 4: Deriving Handshake Traffic Secrets");
    println!("------------------------------------------");
    
    // Create mock transcript hash (ClientHello...ServerHello)
    let mut transcript_handshake = Sha256::new();
    transcript_handshake.update(b"ClientHello_message_bytes");
    transcript_handshake.update(b"ServerHello_message_bytes");
    let handshake_transcript = transcript_handshake.finalize();
    
    let client_hs_traffic = key_schedule
        .derive_client_handshake_traffic_secret(&handshake_transcript);
    let server_hs_traffic = key_schedule
        .derive_server_handshake_traffic_secret(&handshake_transcript);
    
    println!("Client Handshake Traffic Secret: {:?}", hex::encode(&client_hs_traffic));
    println!("Server Handshake Traffic Secret: {:?}", hex::encode(&server_hs_traffic));
    println!("\n✓ These secrets would be used to encrypt/decrypt handshake messages");
    println!();

    // Step 5: Advance to Master Secret
    println!("Step 5: Advancing to Master Secret");
    println!("----------------------------------");
    
    key_schedule.advance_to_master_secret();
    println!("Master Secret: {:?}", hex::encode(&key_schedule.current_secret()));
    println!();

    // Step 6: Derive Application Traffic Secrets
    println!("Step 6: Deriving Application Traffic Secrets");
    println!("--------------------------------------------");
    
    // Create mock transcript hash (ClientHello...server Finished)
    let mut transcript_app = Sha256::new();
    transcript_app.update(b"ClientHello_message_bytes");
    transcript_app.update(b"ServerHello_message_bytes");
    transcript_app.update(b"EncryptedExtensions_bytes");
    transcript_app.update(b"Certificate_bytes");
    transcript_app.update(b"CertificateVerify_bytes");
    transcript_app.update(b"ServerFinished_bytes");
    let app_transcript = transcript_app.finalize();
    
    let client_app_traffic = key_schedule
        .derive_client_application_traffic_secret(&app_transcript);
    let server_app_traffic = key_schedule
        .derive_server_application_traffic_secret(&app_transcript);
    
    println!("Client Application Traffic Secret: {:?}", hex::encode(&client_app_traffic));
    println!("Server Application Traffic Secret: {:?}", hex::encode(&server_app_traffic));
    println!("\n✓ These secrets would be used to encrypt/decrypt application data");
    println!();

    // Step 7: Derive Other Master Secrets
    println!("Step 7: Deriving Additional Master Secrets");
    println!("------------------------------------------");
    
    let exporter_master = key_schedule.derive_exporter_master_secret(&app_transcript);
    println!("Exporter Master Secret: {:?}", hex::encode(&exporter_master));
    println!("  (Used for TLS exporters - RFC 5705)");
    
    let resumption_master = key_schedule.derive_resumption_master_secret(&app_transcript);
    println!("Resumption Master Secret: {:?}", hex::encode(&resumption_master));
    println!("  (Used for session resumption tickets)");
    println!();

    // Summary
    println!("=== Key Schedule Complete ===");
    println!("\nKey Hierarchy:");
    println!("  Early Secret");
    println!("    ↓ (+ ECDHE shared secret)");
    println!("  Handshake Secret");
    println!("    ├→ Client Handshake Traffic Secret");
    println!("    └→ Server Handshake Traffic Secret");
    println!("    ↓ (+ zero)");
    println!("  Master Secret");
    println!("    ├→ Client Application Traffic Secret");
    println!("    ├→ Server Application Traffic Secret");
    println!("    ├→ Exporter Master Secret");
    println!("    └→ Resumption Master Secret");
    println!("\nAll secrets are 32 bytes (SHA-256 output size)");
    println!("Each secret is cryptographically independent and serves a specific purpose.");
}

// Helper module to provide hex encoding
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
