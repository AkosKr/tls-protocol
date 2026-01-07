//! Example: TLS 1.3 Finished Message Handshake Flow
//!
//! This example demonstrates the complete Finished message flow in a TLS 1.3 handshake:
//! 1. Key schedule initialization with ECDHE shared secret
//! 2. Transcript hash computation up to ServerHello
//! 3. Derivation of handshake traffic secrets
//! 4. Server Finished message generation and client verification
//! 5. Client Finished message generation and server verification
//!
//! Run with:
//! ```bash
//! cargo run --example finished_handshake
//! ```

use tls_protocol::{Finished, KeySchedule, TranscriptHash};

fn main() {
    println!("=== TLS 1.3 Finished Message Example ===\n");

    // Step 1: Initialize key schedule
    println!("Step 1: Initialize Key Schedule");
    let mut key_schedule = KeySchedule::new();
    println!("  ✓ Early secret initialized\n");

    // Step 2: Simulate ECDHE key exchange
    println!("Step 2: ECDHE Key Exchange");
    let shared_secret = [0x42u8; 32]; // In practice, from X25519
    key_schedule.advance_to_handshake_secret(&shared_secret);
    println!("  ✓ Handshake secret derived\n");

    // Step 3: Build transcript hash
    println!("Step 3: Build Transcript Hash");
    let mut transcript = TranscriptHash::new();
    
    // Simulate ClientHello
    let client_hello = b"ClientHello message data...";
    transcript.update(client_hello);
    println!("  ✓ Added ClientHello");
    
    // Simulate ServerHello
    let server_hello = b"ServerHello message data...";
    transcript.update(server_hello);
    println!("  ✓ Added ServerHello");
    
    let transcript_hash = transcript.current_hash();
    println!("  ✓ Transcript hash: {}...\n", hex(&transcript_hash[..8]));

    // Step 4: Derive handshake traffic secrets
    println!("Step 4: Derive Handshake Traffic Secrets");
    let client_secret = key_schedule.derive_client_handshake_traffic_secret(&transcript_hash);
    println!("  ✓ Client secret: {}...", hex(&client_secret[..8]));
    
    let server_secret = key_schedule.derive_server_handshake_traffic_secret(&transcript_hash);
    println!("  ✓ Server secret: {}...\n", hex(&server_secret[..8]));

    // Step 5: Add server handshake messages to transcript
    println!("Step 5: Add Server Handshake Messages");
    transcript.update(b"EncryptedExtensions...");
    transcript.update(b"Certificate...");
    transcript.update(b"CertificateVerify...");
    println!("  ✓ Updated transcript\n");

    // Step 6: Server generates Finished message
    println!("Step 6: Server Generates Finished Message");
    let transcript_before_server_finished = transcript.current_hash();
    let server_finished = Finished::generate_server_finished(
        &server_secret,
        &transcript_before_server_finished,
    );
    println!("  ✓ Server Finished generated");
    println!("  ✓ verify_data: {}...", hex(&server_finished.verify_data()[..8]));
    
    let server_finished_bytes = server_finished.to_bytes();
    println!("  ✓ Serialized: {} bytes\n", server_finished_bytes.len());

    // Step 7: Client receives and verifies Server Finished
    println!("Step 7: Client Verifies Server Finished");
    let received_server_finished = Finished::from_bytes(&server_finished_bytes)
        .expect("Failed to parse server Finished");
    
    match received_server_finished.verify_server_finished(&server_secret, &transcript_before_server_finished) {
        Ok(()) => println!("  ✓ Server Finished verification PASSED"),
        Err(e) => {
            println!("  ✗ Server Finished verification FAILED: {}", e);
            return;
        }
    }
    println!("  ✓ Server is authenticated\n");

    // Step 8: Add server Finished to transcript
    println!("Step 8: Update Transcript with Server Finished");
    transcript.update(&server_finished_bytes);
    println!("  ✓ Transcript updated\n");

    // Step 9: Client generates Finished message
    println!("Step 9: Client Generates Finished Message");
    let transcript_before_client_finished = transcript.current_hash();
    let client_finished = Finished::generate_client_finished(
        &client_secret,
        &transcript_before_client_finished,
    );
    println!("  ✓ Client Finished generated");
    println!("  ✓ verify_data: {}...", hex(&client_finished.verify_data()[..8]));
    
    let client_finished_bytes = client_finished.to_bytes();
    println!("  ✓ Serialized: {} bytes\n", client_finished_bytes.len());

    // Step 10: Server receives and verifies Client Finished
    println!("Step 10: Server Verifies Client Finished");
    let received_client_finished = Finished::from_bytes(&client_finished_bytes)
        .expect("Failed to parse client Finished");
    
    match received_client_finished.verify_client_finished(&client_secret, &transcript_before_client_finished) {
        Ok(()) => println!("  ✓ Client Finished verification PASSED"),
        Err(e) => {
            println!("  ✗ Client Finished verification FAILED: {}", e);
            return;
        }
    }
    println!("  ✓ Client is authenticated\n");

    // Step 11: Handshake complete
    println!("Step 11: Handshake Authentication Complete");
    transcript.update(&client_finished_bytes);
    println!("  ✓ Final transcript updated");
    println!("  ✓ Ready to transition to application keys\n");

    println!("=== SUCCESS ===");
    println!("Both parties authenticated each other successfully.");
    println!("Handshake can now proceed to application data exchange.");

    // Demonstrate tamper detection
    println!("\n=== Tamper Detection Demo ===");
    let mut tampered_bytes = server_finished_bytes.clone();
    tampered_bytes[10] ^= 0x01; // Flip one bit
    
    match Finished::from_bytes(&tampered_bytes) {
        Ok(tampered_finished) => {
            match tampered_finished.verify_server_finished(&server_secret, &transcript_before_server_finished) {
                Ok(()) => println!("✗ Tampered message accepted (BUG!)"),
                Err(_) => println!("✓ Tampered message rejected (as expected)"),
            }
        }
        Err(_) => println!("✓ Tampered message rejected during parsing"),
    }

    // Demonstrate reflection attack prevention
    println!("\n=== Reflection Attack Prevention Demo ===");
    match client_finished.verify_server_finished(&server_secret, &transcript_before_client_finished) {
        Ok(()) => println!("✗ Client Finished accepted as Server Finished (BUG!)"),
        Err(_) => println!("✓ Client Finished rejected as Server Finished (as expected)"),
    }
    
    match server_finished.verify_client_finished(&client_secret, &transcript_before_server_finished) {
        Ok(()) => println!("✗ Server Finished accepted as Client Finished (BUG!)"),
        Err(_) => println!("✓ Server Finished rejected as Client Finished (as expected)"),
    }
}

/// Helper function to format bytes as hex string
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
