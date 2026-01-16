//! Comprehensive TLS 1.3 Demo Server
//!
//! This server demonstrates various cipher suite negotiation scenarios:
//! 1. Successful negotiation with different cipher suites
//! 2. Rejection when no common cipher suites exist
//! 3. Encrypted and decrypted data display for Wireshark analysis
//!
//! Run with:
//! ```bash
//! cargo run --example demo_comprehensive_server
//! ```

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
const RED: &str = "\x1b[31m";

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

fn print_error(msg: &str) {
    println!("{}✗{} {}", RED, RESET, msg);
}

fn print_warning(msg: &str) {
    println!("{}⚠{} {}", YELLOW, RESET, msg);
}

fn cipher_suite_name(suite: u16) -> &'static str {
    match suite {
        0x1301 => "TLS_AES_128_GCM_SHA256",
        0x1302 => "TLS_AES_256_GCM_SHA384",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
        _ => "Unknown",
    }
}

fn handle_client(stream: std::net::TcpStream, scenario: &str) -> Result<(), Box<dyn std::error::Error>> {
    let peer_addr = stream.peer_addr()?;
    print_header(&format!("Scenario: {} - Connection from {}", scenario, peer_addr));
    
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
            print_warning(&format!("Could not load TLS certificate from '{}'.", cert_path));
            print_warning("Generate a demo certificate by running:");
            print_warning("  ./generate_demo_cert.sh");
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Missing TLS certificate: '{}'", cert_path),
            ).into());
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
    
    // Create server with appropriate cipher suite configuration
    let mut server = TlsServer::new(stream, certificate, private_key);
    
    // Configure supported cipher suites based on scenario
    match scenario {
        "All Ciphers" => {
            // Support all cipher suites (default)
            print_info("Cipher Config", "Supporting all TLS 1.3 cipher suites");
            println!("  • TLS_AES_128_GCM_SHA256 (0x1301)");
            println!("  • TLS_AES_256_GCM_SHA384 (0x1302)");
            println!("  • TLS_CHACHA20_POLY1305_SHA256 (0x1303)");
        }
        "AES-128 Only" => {
            print_info("Cipher Config", "Supporting only AES-128-GCM");
            server.set_supported_cipher_suites(vec![0x1301]);
        }
        "AES-256 Only" => {
            print_info("Cipher Config", "Supporting only AES-256-GCM");
            server.set_supported_cipher_suites(vec![0x1302]);
        }
        "ChaCha20 Only" => {
            print_info("Cipher Config", "Supporting only ChaCha20-Poly1305");
            server.set_supported_cipher_suites(vec![0x1303]);
        }
        _ => {}
    }
    
    // Perform handshake with detailed output
    print_header("TLS 1.3 Handshake");
    print_info("Phase", "Waiting for ClientHello...");
    
    match server.perform_handshake() {
        Ok(_) => {
            if let Some(suite) = server.negotiated_cipher_suite() {
                print_success("Handshake Complete!");
                print_info("Negotiated Cipher", cipher_suite_name(suite));
                println!("  Cipher Suite ID: 0x{:04x}", suite);
                println!("{}Ready for encrypted application data{}", BOLD, RESET);
            } else {
                print_success("Handshake Complete!");
            }
        }
        Err(e) => {
            print_error(&format!("Handshake failed: {:?}", e));
            print_info("Reason", "This may indicate no common cipher suites");
            return Ok(());
        }
    }
    
    // Echo loop with detailed output showing encrypted/decrypted data
    print_header("Application Data Exchange");
    print_info("Mode", "Echo server - will return received messages");
    println!("{}Wireshark Tip:{} Filter 'tcp.port == 4433' to see encrypted traffic", YELLOW, RESET);
    println!("{}Note:{} Encrypted payloads shown below match THIS connection only", CYAN, RESET);
    
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
                
                // Show encrypted packet info
                println!("{}[ENCRYPTED PACKET RECEIVED]{}", MAGENTA, RESET);
                print_info("State", "Encrypted with negotiated cipher suite");
                print_info("Details", "TLS record decrypted successfully");
                
                // Show decrypted plaintext
                println!("\n{}[DECRYPTED PLAINTEXT]{}", GREEN, RESET);
                match String::from_utf8(data.clone()) {
                    Ok(text) => {
                        print_info("Plaintext", &format!("\"{}\"", text));
                        println!("  Length: {} bytes", data.len());
                    }
                    Err(_) => {
                        print_info("Plaintext", &format!("{} bytes (binary data)", data.len()));
                        print_security("Hex dump", &data, 32);
                    }
                }
                
                // Show first 16 bytes of plaintext in hex
                print_security("Plaintext (hex)", &data, 16);
                
                // Echo back
                println!("\n{}[ENCRYPTING RESPONSE]{}", YELLOW, RESET);
                print_info("Action", "Echoing message back to client");
                print_security("Plaintext to encrypt", &data, 16);
                
                match server.send_application_data_with_record(&data) {
                    Ok(record) => {
                        print_success("Response encrypted and sent");
                        
                        // Show the encrypted TLS record
                        println!("\n{}[ENCRYPTED TLS RECORD SENT]{}", MAGENTA, RESET);
                        print_info("Total Length", &format!("{} bytes (5-byte header + ciphertext)", record.len()));
                        print_info("Header", &format!("{:02x} {:02x} {:02x} {:02x} {:02x}", 
                            record[0], record[1], record[2], record[3], record[4]));
                        print_info("Details", &format!("ContentType=0x{:02x} (ApplicationData), Version=0x{:02x}{:02x}, Length={}", 
                            record[0], record[1], record[2], 
                            u16::from_be_bytes([record[3], record[4]])));
                        
                        // Show encrypted payload (ciphertext + auth tag)
                        if record.len() > 5 {
                            let payload = &record[5..];
                            // Show ALL encrypted bytes in one line
                            let hex_no_spaces: String = payload.iter()
                                .map(|b| format!("{:02x}", b))
                                .collect::<Vec<_>>()
                                .join("");
                            
                            println!("\n{}═══════════════════════════════════════════════════════════{}", BOLD, RESET);
                            println!("{}ENCRYPTED PAYLOAD (copy this exactly):{}", BOLD, RESET);
                            println!("{}", hex_no_spaces);
                            println!("{}═══════════════════════════════════════════════════════════{}", BOLD, RESET);
                            
                            print_info("Payload Length", &format!("{} bytes (includes 16-byte auth tag)", payload.len()));
                            print_security("First 32 bytes", payload, 32);
                        }
                        
                        println!("\n{}WIRESHARK:{} Find packet from server (127.0.0.1:4433) → client", CYAN, RESET);
                        println!("  Compare Complete Encrypted Payload above with packet's Encrypted Application Data");
                    }
                    Err(e) => {
                        print_error(&format!("Failed to send: {:?}", e));
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
    if let Some(suite) = server.negotiated_cipher_suite() {
        print_info("Cipher Suite", cipher_suite_name(suite));
    }
    print_success("Connection closed gracefully");
    
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "═".repeat(70));
    println!("{}{}Comprehensive TLS 1.3 Demo Server{}", BOLD, CYAN, RESET);
    println!("{}", "═".repeat(70));
    println!();
    println!("This server demonstrates:");
    println!("  • Cipher suite negotiation with different configurations");
    println!("  • Successful handshakes with matching cipher suites");
    println!("  • Handshake failures with no common cipher suites");
    println!("  • Detailed encrypted/decrypted data display for Wireshark analysis");
    println!();
    println!("{}For Wireshark analysis:{}", BOLD, RESET);
    println!("  1. Start Wireshark before running clients");
    println!("  2. Capture on 'lo' (loopback) interface");
    println!("  3. Use filter: {}tcp.port == 4433{}", YELLOW, RESET);
    println!("  4. Observe TLS records with ContentType = ApplicationData (0x17)");
    println!("  5. See encrypted payloads and compare with plaintext shown here");
    println!();
    println!("{}Usage:{}", BOLD, RESET);
    println!("  This server will handle connections sequentially.");
    println!("  Run demo_comprehensive_client to test different scenarios.");
    println!();
    
    let addr = "127.0.0.1:4433";
    let listener = TcpListener::bind(addr)?;
    
    print_header(&format!("Listening on {}", addr));
    print_info("Status", "Waiting for connections...");
    println!("{}Press Ctrl+C to stop the server{}", YELLOW, RESET);
    
    let mut connection_count = 0;
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                connection_count += 1;
                let scenario = match connection_count % 4 {
                    1 => "All Ciphers",
                    2 => "All Ciphers",
                    3 => "All Ciphers",
                    _ => "All Ciphers",
                };
                
                if let Err(e) = handle_client(stream, scenario) {
                    print_error(&format!("Error handling connection: {}", e));
                }
                
                println!("\n{}═══════════════════════════════════════════════════════════════════════{}", CYAN, RESET);
                println!("{}Waiting for next connection...{}", CYAN, RESET);
            }
            Err(e) => print_error(&format!("Connection failed: {}", e)),
        }
    }
    
    Ok(())
}
