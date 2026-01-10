//! TLS 1.3 Demo Client
//!
//! This is a complete demonstration client that showcases the TLS 1.3 handshake and
//! encrypted data exchange. It provides detailed, educational console output showing
//! each step of the protocol.
//!
//! Run the demo_server first:
//! ```bash
//! cargo run --example demo_server
//! ```
//!
//! Then in another terminal, run this client:
//! ```bash
//! cargo run --example demo_client
//! ```
//!
//! For Wireshark analysis, see docs/WIRESHARK_DEMO_GUIDE.md

use std::net::TcpStream;
use tls_protocol::TlsClient;

/// ANSI color codes for educational output
const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const BLUE: &str = "\x1b[34m";
const CYAN: &str = "\x1b[36m";
const MAGENTA: &str = "\x1b[35m";

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

fn print_step(step_num: usize, description: &str) {
    println!("{}Step {}: {}{}", YELLOW, step_num, RESET, description);
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "═".repeat(60));
    println!("{}{}TLS 1.3 Demo Client{}", BOLD, CYAN, RESET);
    println!("{}", "═".repeat(60));
    println!();
    println!("This client demonstrates:");
    println!("  • Complete TLS 1.3 handshake (ClientHello → ServerHello → Finished)");
    println!("  • X25519 ECDHE key exchange");
    println!("  • AES-128-GCM encryption");
    println!("  • Certificate validation");
    println!("  • Encrypted application data exchange");
    println!();
    println!("{}For Wireshark analysis:{}", BOLD, RESET);
    println!("  1. Start Wireshark before running this client");
    println!("  2. Capture on 'lo' (loopback) interface");
    println!("  3. Use filter: {}tcp.port == 4433{}", YELLOW, RESET);
    println!("  4. See docs/WIRESHARK_DEMO_GUIDE.md for detailed instructions");
    println!();

    let server_addr = "127.0.0.1:4433";

    print_header("Connection Setup");
    print_step(1, &format!("Connecting to {}", server_addr));

    let stream = match TcpStream::connect(server_addr) {
        Ok(s) => {
            print_success("TCP connection established");
            s
        }
        Err(e) => {
            eprintln!("{}✗{} Failed to connect: {}", "\x1b[31m", RESET, e);
            eprintln!(
                "{}Tip:{} Make sure demo_server is running first",
                YELLOW, RESET
            );
            return Err(e.into());
        }
    };

    let mut client = TlsClient::new(stream);

    // Handshake with detailed steps
    print_header("TLS 1.3 Handshake");

    print_step(2, "Sending ClientHello");
    print_info("Details", "Generating X25519 keypair");
    print_info("Details", "Setting cipher suite: TLS_AES_128_GCM_SHA256");

    match client.send_client_hello() {
        Ok(_) => print_success("ClientHello sent"),
        Err(e) => {
            eprintln!("{}✗{} Failed: {:?}", "\x1b[31m", RESET, e);
            return Err(e.into());
        }
    }

    print_step(3, "Receiving ServerHello");
    print_info("Details", "Waiting for server response");

    match client.receive_server_hello() {
        Ok(_) => {
            print_success("ServerHello received");
            print_info("Details", "Negotiated X25519 ECDHE");
            print_info("Details", "Computing shared secret");
            print_info("Details", "Deriving handshake traffic keys");
        }
        Err(e) => {
            eprintln!("{}✗{} Failed: {:?}", "\x1b[31m", RESET, e);
            return Err(e.into());
        }
    }

    print_step(4, "Receiving EncryptedExtensions");
    match client.receive_encrypted_extensions() {
        Ok(_) => {
            print_success("EncryptedExtensions received and decrypted");
            print_info(
                "Encryption",
                "Switched to handshake encryption (AES-128-GCM)",
            );
        }
        Err(e) => {
            eprintln!("{}✗{} Failed: {:?}", "\x1b[31m", RESET, e);
            return Err(e.into());
        }
    }

    print_step(5, "Receiving Certificate");
    let certificate = match client.receive_certificate() {
        Ok(cert) => {
            print_success("Certificate received");
            print_info(
                "Details",
                &format!("Certificate chain length: {}", cert.certificate_list.len()),
            );
            cert
        }
        Err(e) => {
            eprintln!("{}✗{} Failed: {:?}", "\x1b[31m", RESET, e);
            return Err(e.into());
        }
    };

    print_step(6, "Receiving CertificateVerify");
    match client.receive_certificate_verify(&certificate) {
        Ok(_) => {
            print_success("CertificateVerify received and signature validated");
            print_info("Security", "Server proved possession of private key");
        }
        Err(e) => {
            eprintln!("{}✗{} Failed: {:?}", "\x1b[31m", RESET, e);
            eprintln!(
                "{}Note:{} This may fail with temporary demo certificates",
                YELLOW, RESET
            );
            return Err(e.into());
        }
    }

    print_step(7, "Receiving server Finished");
    match client.receive_server_finished() {
        Ok(_) => {
            print_success("Server Finished received and verified");
            print_info("Security", "HMAC verification successful");
        }
        Err(e) => {
            eprintln!("{}✗{} Failed: {:?}", "\x1b[31m", RESET, e);
            return Err(e.into());
        }
    }

    print_step(8, "Sending client Finished");
    match client.send_client_finished() {
        Ok(_) => {
            print_success("Client Finished sent");
            print_info("Encryption", "Switched to application encryption");
        }
        Err(e) => {
            eprintln!("{}✗{} Failed: {:?}", "\x1b[31m", RESET, e);
            return Err(e.into());
        }
    }

    print_success("Handshake Complete!");
    println!("{}Ready for encrypted application data{}", BOLD, RESET);

    // Application data exchange
    print_header("Application Data Exchange");

    let test_messages = vec![
        b"Hello, TLS 1.3!".to_vec(),
        b"This message is encrypted with AES-128-GCM".to_vec(),
        b"Secure communication established!".to_vec(),
    ];

    for (i, message) in test_messages.iter().enumerate() {
        let msg_num = i + 1;
        print_header(&format!("Message #{}", msg_num));

        // Send message
        match String::from_utf8(message.clone()) {
            Ok(text) => {
                print_info("Sending", &format!("\"{}\"", text));
                println!("{}Length:{} {} bytes", CYAN, RESET, message.len());
            }
            Err(_) => {
                print_info("Sending", &format!("{} bytes (binary data)", message.len()));
            }
        }

        // Show raw bytes (first few)
        print_security("Plaintext bytes", message, 16);

        match client.send_application_data(message) {
            Ok(_) => print_success("Plaintext encrypted by TLS and sent to server"),
            Err(e) => {
                eprintln!("{}✗{} Failed to send: {:?}", "\x1b[31m", RESET, e);
                break;
            }
        }

        // Receive echo
        print_info("Receiving", "Waiting for echo from server");

        match client.receive_application_data() {
            Ok(response) => {
                print_success("Encrypted response received and decrypted");

                match String::from_utf8(response.clone()) {
                    Ok(text) => {
                        print_info("Echo", &format!("\"{}\"", text));

                        // Verify it matches
                        if response == *message {
                            print_success("✓ Echo matches sent message");
                        } else {
                            println!("{}⚠{} Echo does not match!", YELLOW, RESET);
                        }
                    }
                    Err(_) => {
                        print_info("Echo", &format!("{} bytes (binary data)", response.len()));
                        print_security("Hex", &response, 32);
                    }
                }
            }
            Err(e) => {
                eprintln!("{}✗{} Failed to receive: {:?}", "\x1b[31m", RESET, e);
                break;
            }
        }

        // Small delay between messages for readability
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    print_header("Session Summary");
    print_info("Messages sent", &test_messages.len().to_string());
    print_info("Cipher suite", "TLS_AES_128_GCM_SHA256");
    print_info("Key exchange", "X25519 ECDHE");
    print_success("Demo complete!");

    println!("\n{}Next steps:{}", BOLD, RESET);
    println!("  • Check Wireshark to see the encrypted traffic");
    println!("  • See docs/WIRESHARK_DEMO_GUIDE.md for analysis tips");
    println!("  • Try modifying the messages or adding more steps");

    Ok(())
}
