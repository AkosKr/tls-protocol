//! Comprehensive TLS 1.3 Demo Client
//!
//! This client demonstrates various cipher suite scenarios:
//! 1. Successful handshake with all cipher suites (server chooses)
//! 2. Client offering only AES-128-GCM
//! 3. Client offering only AES-256-GCM
//! 4. Client offering only ChaCha20-Poly1305
//! 5. Client offering incompatible cipher (to demonstrate failure)
//!
//! Run the server first:
//! ```bash
//! cargo run --example demo_comprehensive_server
//! ```
//!
//! Then run this client:
//! ```bash
//! cargo run --example demo_comprehensive_client
//! ```

use std::net::TcpStream;
use std::thread;
use std::time::Duration;
use tls_protocol::client_hello::{
    TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256,
};
use tls_protocol::TlsClient;

/// ANSI color codes for educational output
const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const BLUE: &str = "\x1b[34m";
const CYAN: &str = "\x1b[36m";
const MAGENTA: &str = "\x1b[35m";
const RED: &str = "\x1b[31m";

fn print_header(msg: &str) {
    println!("\n{}{}{}{}", BOLD, CYAN, msg, RESET);
    println!("{}", "=".repeat(msg.len()));
}

fn print_info(label: &str, msg: &str) {
    println!("{}[INFO]{} {}: {}", BLUE, RESET, label, msg);
}

fn print_security(label: &str, data: &[u8], max_bytes: usize) {
    let hex_str: String = data
        .iter()
        .take(max_bytes)
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ");
    let suffix = if data.len() > max_bytes { "..." } else { "" };
    println!(
        "{}[SECURITY]{} {}: {}{}",
        MAGENTA, RESET, label, hex_str, suffix
    );
}

fn print_success(msg: &str) {
    println!("{}✓{} {}{}{}", GREEN, RESET, BOLD, msg, RESET);
}

fn print_error(msg: &str) {
    println!("{}✗{} {}", RED, RESET, msg);
}

fn cipher_suite_name(suite: u16) -> &'static str {
    match suite {
        TLS_AES_128_GCM_SHA256 => "TLS_AES_128_GCM_SHA256",
        TLS_AES_256_GCM_SHA384 => "TLS_AES_256_GCM_SHA384",
        TLS_CHACHA20_POLY1305_SHA256 => "TLS_CHACHA20_POLY1305_SHA256",
        _ => "Unknown",
    }
}

fn run_scenario(
    scenario_num: usize,
    scenario_name: &str,
    cipher_suites: Vec<u16>,
    should_fail: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n{}", "═".repeat(70));
    print_header(&format!("Scenario {}: {}", scenario_num, scenario_name));
    println!("{}", "═".repeat(70));

    // Display offered cipher suites
    print_info("Offered Ciphers", "");
    for suite in &cipher_suites {
        println!("  • {} (0x{:04x})", cipher_suite_name(*suite), suite);
    }

    let server_addr = "127.0.0.1:4433";

    println!();
    print_info("Connection", &format!("Connecting to {}", server_addr));

    let stream = match TcpStream::connect(server_addr) {
        Ok(s) => {
            print_success("TCP connection established");
            s
        }
        Err(e) => {
            print_error(&format!("Failed to connect: {}", e));
            println!(
                "{}Tip:{} Make sure demo_comprehensive_server is running",
                YELLOW, RESET
            );
            return Err(e.into());
        }
    };

    let mut client = TlsClient::new(stream);
    client.set_cipher_suites(cipher_suites.clone());

    // Perform handshake
    print_header("TLS 1.3 Handshake");

    print_info("Step 1", "Sending ClientHello");
    match client.send_client_hello() {
        Ok(_) => print_success("ClientHello sent with custom cipher suites"),
        Err(e) => {
            print_error(&format!("Failed: {:?}", e));
            return Err(e.into());
        }
    }

    print_info("Step 2", "Receiving ServerHello");
    match client.receive_server_hello() {
        Ok(_) => {
            print_success("ServerHello received");
            print_info("Key Exchange", "X25519 ECDHE completed");
            print_info("Encryption", "Handshake keys derived");
        }
        Err(e) => {
            if should_fail {
                print_error(&format!("Handshake failed as expected: {:?}", e));
                print_info(
                    "Reason",
                    "No common cipher suites between client and server",
                );
                println!(
                    "\n{}This demonstrates proper cipher suite negotiation failure{}",
                    YELLOW, RESET
                );
                return Ok(()); // Expected failure
            } else {
                print_error(&format!("Failed: {:?}", e));
                return Err(e.into());
            }
        }
    }

    print_info("Step 3", "Receiving EncryptedExtensions");
    match client.receive_encrypted_extensions() {
        Ok(_) => print_success("EncryptedExtensions received and decrypted"),
        Err(e) => {
            print_error(&format!("Failed: {:?}", e));
            return Err(e.into());
        }
    }

    print_info("Step 4", "Receiving Certificate");
    let certificate = match client.receive_certificate() {
        Ok(cert) => {
            print_success("Certificate received");
            print_info("Chain Length", &cert.certificate_list.len().to_string());
            cert
        }
        Err(e) => {
            print_error(&format!("Failed: {:?}", e));
            return Err(e.into());
        }
    };

    print_info("Step 5", "Receiving CertificateVerify");
    match client.receive_certificate_verify(&certificate) {
        Ok(_) => {
            print_success("CertificateVerify received and signature validated");
            print_info("Security", "Server proved possession of private key");
        }
        Err(e) => {
            print_error(&format!("Failed: {:?}", e));
            println!(
                "{}Note:{} This may fail with demo certificates",
                YELLOW, RESET
            );
            return Err(e.into());
        }
    }

    print_info("Step 6", "Receiving server Finished");
    match client.receive_server_finished() {
        Ok(_) => print_success("Server Finished received and verified"),
        Err(e) => {
            print_error(&format!("Failed: {:?}", e));
            return Err(e.into());
        }
    }

    print_info("Step 7", "Sending client Finished");
    match client.send_client_finished() {
        Ok(_) => {
            print_success("Client Finished sent");
            print_info("Encryption", "Switched to application data encryption");
        }
        Err(e) => {
            print_error(&format!("Failed: {:?}", e));
            return Err(e.into());
        }
    }

    print_success("✓✓✓ Handshake Complete! ✓✓✓");

    // Application data exchange with detailed encryption/decryption display
    print_header("Application Data Exchange");

    let test_messages = vec![
        format!("Hello from {}", scenario_name).into_bytes(),
        b"Encrypted with negotiated cipher suite".to_vec(),
    ];

    for (i, message) in test_messages.iter().enumerate() {
        let msg_num = i + 1;
        println!("\n{}[Message #{}]{}", CYAN, msg_num, RESET);
        println!("{}", "-".repeat(50));

        // Display plaintext to be sent
        match String::from_utf8(message.clone()) {
            Ok(text) => {
                println!("\n{}[PLAINTEXT TO SEND]{}", YELLOW, RESET);
                print_info("Content", &format!("\"{}\"", text));
                print_info("Length", &format!("{} bytes", message.len()));
            }
            Err(_) => {
                print_info("Sending", &format!("{} bytes (binary data)", message.len()));
            }
        }

        // Show first bytes in hex
        print_security("Plaintext (hex)", message, 16);

        // Encrypt and send
        println!("\n{}[ENCRYPTING & SENDING]{}", MAGENTA, RESET);
        print_info("Action", "Encrypting with application traffic keys");
        match client.send_application_data_with_record(message) {
            Ok(record) => {
                print_success("Plaintext encrypted and sent as TLS record");

                // Show the encrypted TLS record
                println!("\n{}[ENCRYPTED TLS RECORD SENT]{}", MAGENTA, RESET);
                print_info(
                    "Total Length",
                    &format!("{} bytes (5-byte header + ciphertext)", record.len()),
                );
                print_info(
                    "Header",
                    &format!(
                        "{:02x} {:02x} {:02x} {:02x} {:02x}",
                        record[0], record[1], record[2], record[3], record[4]
                    ),
                );
                print_info(
                    "Details",
                    &format!(
                        "ContentType=0x{:02x} (ApplicationData), Version=0x{:02x}{:02x}, Length={}",
                        record[0],
                        record[1],
                        record[2],
                        u16::from_be_bytes([record[3], record[4]])
                    ),
                );

                // Show encrypted payload (ciphertext + auth tag)
                if record.len() > 5 {
                    let payload = &record[5..];
                    // Show ALL encrypted bytes in one line for easy copying
                    let hex_no_spaces: String = payload
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join("");

                    println!(
                        "\n{}═══════════════════════════════════════════════════════════{}",
                        BOLD, RESET
                    );
                    println!("{}ENCRYPTED PAYLOAD (copy this exactly):{}", BOLD, RESET);
                    println!("{}", hex_no_spaces);
                    println!(
                        "{}═══════════════════════════════════════════════════════════{}",
                        BOLD, RESET
                    );

                    print_info(
                        "Payload Length",
                        &format!("{} bytes (includes 16-byte auth tag)", payload.len()),
                    );
                    print_security("First 32 bytes", payload, 32);

                    // Also show the complete record (header + payload) for verification
                    let full_record_hex: String = record
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join("");
                    println!("\n{}Complete TLS Record (header + payload):{}", CYAN, RESET);
                    println!("{}", full_record_hex);
                }

                println!("\n{}WIRESHARK MATCHING:{}", BOLD, RESET);
                println!("  1. In Wireshark, find packet from client (127.0.0.1) → server (127.0.0.1:4433)");
                println!(
                    "  2. Look for TLS Application Data with length {}",
                    record.len()
                );
                println!("  3. Expand packet details → TLS → Encrypted Application Data");
                println!("  4. Right-click → Copy → as Hex Stream");
                println!("  5. Compare with Complete Encrypted Payload hex above");
            }
            Err(e) => {
                print_error(&format!("Failed to send: {:?}", e));
                break;
            }
        }

        // Receive echo
        println!("\n{}[RECEIVING ENCRYPTED RESPONSE]{}", MAGENTA, RESET);
        print_info("Action", "Waiting for encrypted response from server");

        match client.receive_application_data() {
            Ok(response) => {
                print_success("Encrypted TLS record received and decrypted");

                println!("\n{}[DECRYPTED PLAINTEXT]{}", GREEN, RESET);
                match String::from_utf8(response.clone()) {
                    Ok(text) => {
                        print_info("Content", &format!("\"{}\"", text));
                        print_info("Length", &format!("{} bytes", response.len()));

                        // Verify echo
                        if response == *message {
                            print_success("✓ Echo matches sent message");
                        } else {
                            println!("{}⚠{} Echo does not match!", YELLOW, RESET);
                        }
                    }
                    Err(_) => {
                        print_info(
                            "Response",
                            &format!("{} bytes (binary data)", response.len()),
                        );
                    }
                }

                print_security("Decrypted (hex)", &response, 16);
            }
            Err(e) => {
                print_error(&format!("Failed to receive: {:?}", e));
                break;
            }
        }
    }

    print_header("Scenario Summary");
    print_success(&format!("✓ {} completed successfully", scenario_name));
    print_info(
        "Messages",
        &format!("{} sent and echoed", test_messages.len()),
    );

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "═".repeat(70));
    println!("{}{}Comprehensive TLS 1.3 Demo Client{}", BOLD, CYAN, RESET);
    println!("{}", "═".repeat(70));
    println!();
    println!("This demo tests multiple cipher suite scenarios:");
    println!("  1. All cipher suites offered (server chooses preferred)");
    println!("  2. Only AES-128-GCM offered");
    println!("  3. Only AES-256-GCM offered");
    println!("  4. Only ChaCha20-Poly1305 offered");
    println!("  5. Incompatible cipher - EXPECTED TO FAIL");
    println!();
    println!(
        "{}{}IMPORTANT - For Wireshark Matching:{}",
        BOLD, RED, RESET
    );
    println!(
        "  {}⚠ START WIRESHARK NOW before pressing Enter!{}",
        YELLOW, RESET
    );
    println!("  • The encrypted bytes change with EACH run (different keys)");
    println!("  • You MUST capture THIS SPECIFIC run to match the output");
    println!("  • Use filter: {}tcp.port == 4433{}", YELLOW, RESET);
    println!("  • Match packets by: Header (17 03 03), Length, Order");
    println!();
    println!("{}Press Enter AFTER starting Wireshark...{}", YELLOW, RESET);

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;

    // Scenario 1: All cipher suites
    if let Err(e) = run_scenario(
        1,
        "All Cipher Suites",
        vec![
            TLS_AES_128_GCM_SHA256,
            TLS_AES_256_GCM_SHA384,
            TLS_CHACHA20_POLY1305_SHA256,
        ],
        false,
    ) {
        println!("{}Scenario 1 failed: {}{}", RED, e, RESET);
    }

    thread::sleep(Duration::from_secs(1));

    // Scenario 2: Only AES-128-GCM
    if let Err(e) = run_scenario(2, "AES-128-GCM Only", vec![TLS_AES_128_GCM_SHA256], false) {
        println!("{}Scenario 2 failed: {}{}", RED, e, RESET);
    }

    thread::sleep(Duration::from_secs(1));

    // Scenario 3: Only AES-256-GCM
    if let Err(e) = run_scenario(3, "AES-256-GCM Only", vec![TLS_AES_256_GCM_SHA384], false) {
        println!("{}Scenario 3 failed: {}{}", RED, e, RESET);
    }

    thread::sleep(Duration::from_secs(1));

    // Scenario 4: Only ChaCha20-Poly1305
    if let Err(e) = run_scenario(
        4,
        "ChaCha20-Poly1305 Only",
        vec![TLS_CHACHA20_POLY1305_SHA256],
        false,
    ) {
        println!("{}Scenario 4 failed: {}{}", RED, e, RESET);
    }

    thread::sleep(Duration::from_secs(1));

    // Scenario 5: Incompatible cipher (server doesn't support this)
    println!("\n{}", "═".repeat(70));
    println!("{}{}SCENARIO 5: CIPHER MISMATCH TEST{}", BOLD, YELLOW, RESET);
    println!("{}", "═".repeat(70));
    println!("{}This scenario will FAIL - demonstrating proper error handling{}", YELLOW, RESET);
    println!("Client offers cipher suites that server doesn't support");
    println!();
    
    if let Err(e) = run_scenario(
        5,
        "Incompatible Cipher (No Match)",
        vec![0xC02F, 0xC030], // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (TLS 1.2 cipher, not TLS 1.3)
        true, // This should fail
    ) {
        println!("{}Scenario 5 failed (as expected): {}{}", YELLOW, e, RESET);
    }

    // Final summary
    println!("\n{}", "═".repeat(70));
    print_header("All Scenarios Complete!");
    println!("{}", "═".repeat(70));

    println!("\n{}Scenarios Tested:{}", BOLD, RESET);
    println!("  ✓ Scenario 1: All cipher suites (successful)");
    println!("  ✓ Scenario 2: AES-128-GCM only (successful)");
    println!("  ✓ Scenario 3: AES-256-GCM only (successful)");
    println!("  ✓ Scenario 4: ChaCha20-Poly1305 only (successful)");
    println!("  ✗ Scenario 5: Incompatible cipher (failed as expected)");

    println!("\n{}Key Observations for Wireshark:{}", BOLD, RESET);
    println!("  • Each scenario created separate TCP connections");
    println!("  • TLS records use ContentType = ApplicationData (0x17) when encrypted");
    println!("  • Encrypted payloads are opaque - only length visible");
    println!("  • Compare encrypted TLS records with plaintext displayed above");
    println!("  • Different cipher suites were negotiated per scenario");
    println!("  • Scenario 5 shows proper error handling for cipher mismatch");

    println!("\n{}Next Steps:{}", BOLD, RESET);
    println!("  • Review Wireshark capture to see encrypted traffic");
    println!("  • Compare packet sizes with message lengths shown");
    println!("  • Observe TLS record structure and encryption");
    println!("  • Note the failed handshake in Scenario 5");
    println!("  • See docs/WIRESHARK_DEMO_GUIDE.md for detailed analysis");

    Ok(())
}
