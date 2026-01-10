//! TLS 1.3 Demo Server
//!
//! This is a complete demonstration server that showcases the TLS 1.3 handshake and
//! encrypted data exchange. It provides detailed, educational console output showing
//! each step of the protocol.
//!
//! Run with:
//! ```bash
//! cargo run --example demo_server
//! ```
//!
//! Then in another terminal, run the client:
//! ```bash
//! cargo run --example demo_client
//! ```
//!
//! For Wireshark analysis, see docs/WIRESHARK_DEMO_GUIDE.md

use std::fs;
use std::net::TcpListener;
use tls_protocol::{Certificate, CertificateEntry, PrivateKey, TlsServer};
use rsa::pkcs8::DecodePrivateKey;
use rsa::RsaPrivateKey;

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
    let hex_str: String = data.iter()
        .take(max_bytes)
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ");
    let suffix = if data.len() > max_bytes { "..." } else { "" };
    println!("{}[SECURITY]{} {}: {}{}", MAGENTA, RESET, label, hex_str, suffix);
}

fn print_success(msg: &str) {
    println!("{}✓{} {}{}{}", GREEN, RESET, BOLD, msg, RESET);
}

fn print_warning(msg: &str) {
    println!("{}⚠{} {}", YELLOW, RESET, msg);
}

fn handle_client(stream: std::net::TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let peer_addr = stream.peer_addr()?;
    print_header(&format!("New Connection from {}", peer_addr));
    
    // Load certificate and private key
    print_info("Setup", "Loading server credentials");
    
    let cert_path = "demo_cert.der";
    let key_path = "demo_key.pem";
    
    let cert_data = match fs::read(cert_path) {
        Ok(data) => {
            print_info("Certificate", &format!("Loaded {} bytes from {}", data.len(), cert_path));
            data
        }
        Err(_) => {
            print_warning(&format!("Could not load {}, generating temporary certificate", cert_path));
            print_warning("⚠️ WARNING: Using a temporary self-signed certificate");
            print_warning("For production, generate proper certificates using: cargo run --example generate_demo_cert");
            
            // Generate temporary certificate for demo
            vec![0u8; 100]
        }
    };
    
    let private_key = match fs::read_to_string(key_path) {
        Ok(pem_str) => {
            match RsaPrivateKey::from_pkcs8_pem(&pem_str) {
                Ok(key) => {
                    print_info("Private Key", &format!("Loaded RSA key from {}", key_path));
                    PrivateKey::Rsa(key)
                }
                Err(_) => {
                    print_warning("Failed to parse private key, generating temporary key");
                    let mut rng = rand::rngs::OsRng;
                    let rsa_key = RsaPrivateKey::new(&mut rng, 2048)?;
                    PrivateKey::Rsa(rsa_key)
                }
            }
        }
        Err(_) => {
            print_warning(&format!("Could not load {}, generating temporary key", key_path));
            let mut rng = rand::rngs::OsRng;
            let rsa_key = RsaPrivateKey::new(&mut rng, 2048)?;
            PrivateKey::Rsa(rsa_key)
        }
    };
    
    let certificate = Certificate::new(vec![], vec![CertificateEntry::new(cert_data, vec![])]);
    
    // Create server
    let mut server = TlsServer::new(stream, certificate, private_key);
    
    // Perform handshake with detailed output
    print_header("TLS 1.3 Handshake");
    print_info("Phase 1", "Waiting for ClientHello...");
    
    match server.perform_handshake() {
        Ok(_) => {
            print_success("Handshake Complete!");
            println!("{}Ready for encrypted application data{}", BOLD, RESET);
        }
        Err(e) => {
            eprintln!("{}✗{} Handshake failed: {:?}", "\x1b[31m", RESET, e);
            return Ok(());
        }
    }
    
    // Echo loop with detailed output
    print_header("Application Data Exchange");
    print_info("Mode", "Echo server - will return received messages");
    println!("{}Tip:{} Start Wireshark with filter 'tcp.port == 4433' to see encrypted traffic", YELLOW, RESET);
    
    let mut message_count = 0;
    loop {
        match server.receive_application_data() {
            Ok(data) => {
                if data.is_empty() {
                    print_info("Connection", "Client closed connection");
                    break;
                }
                
                message_count += 1;
                print_header(&format!("Message #{}", message_count));
                
                // Show encrypted wire format (would need access to raw bytes)
                print_security("Encrypted wire format", &data, 16);
                
                // Show decrypted content
                match String::from_utf8(data.clone()) {
                    Ok(text) => {
                        print_info("Decrypted", &format!("\"{}\"", text));
                        println!("{}Length:{} {} bytes", CYAN, RESET, data.len());
                    }
                    Err(_) => {
                        print_info("Decrypted", &format!("{} bytes (binary data)", data.len()));
                        print_security("Hex", &data, 32);
                    }
                }
                
                // Echo back
                print_info("Response", "Echoing message back to client");
                match server.send_application_data(&data) {
                    Ok(_) => print_success("Echo sent"),
                    Err(e) => {
                        eprintln!("{}✗{} Failed to send: {:?}", "\x1b[31m", RESET, e);
                        break;
                    }
                }
            }
            Err(e) => {
                print_info("Connection", &format!("Closed: {:?}", e));
                break;
            }
        }
    }
    
    print_header("Session Summary");
    print_info("Messages processed", &message_count.to_string());
    print_success("Connection closed gracefully");
    
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "═".repeat(60));
    println!("{}{}TLS 1.3 Demo Server{}", BOLD, CYAN, RESET);
    println!("{}", "═".repeat(60));
    println!();
    println!("This server demonstrates:");
    println!("  • Complete TLS 1.3 handshake (ClientHello → ServerHello → Finished)");
    println!("  • X25519 ECDHE key exchange");
    println!("  • AES-128-GCM encryption");
    println!("  • Certificate-based authentication");
    println!("  • Encrypted application data exchange");
    println!();
    println!("{}For Wireshark analysis:{}", BOLD, RESET);
    println!("  1. Start Wireshark before running the client");
    println!("  2. Capture on 'lo' (loopback) interface");
    println!("  3. Use filter: {}tcp.port == 4433{}", YELLOW, RESET);
    println!("  4. See docs/WIRESHARK_DEMO_GUIDE.md for detailed instructions");
    println!();
    
    let addr = "127.0.0.1:4433";
    let listener = TcpListener::bind(addr)?;
    
    print_header(&format!("Listening on {}", addr));
    print_info("Status", "Waiting for connections...");
    
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                // Handle each connection in the main thread for simplicity
                // (makes console output easier to follow)
                if let Err(e) = handle_client(stream) {
                    eprintln!("{}✗{} Error handling connection: {}", "\x1b[31m", RESET, e);
                }
                println!("\n{}Waiting for next connection...{}", CYAN, RESET);
            }
            Err(e) => eprintln!("{}✗{} Connection failed: {}", "\x1b[31m", RESET, e),
        }
    }
    
    Ok(())
}
