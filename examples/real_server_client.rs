//! TLS 1.3 Real Server Client Example
//!
//! This example demonstrates connecting to real-world TLS 1.3 servers
//! like google.com, cloudflare.com, etc.
//!
//! This client includes all necessary extensions that major servers expect:
//! - Server Name Indication (SNI)
//! - Supported Groups (key exchange groups)
//! - Signature Algorithms
//! - ALPN (Application-Layer Protocol Negotiation)
//! - Supported Versions (TLS 1.3)
//! - Key Share (x25519)
//!
//! Run with:
//! ```bash
//! cargo run --example real_server_client
//! ```

use std::fs;
use std::io::{self, Write};
use tls_protocol::TlsClient;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== TLS 1.3 Real Server Client ===\n");

    // List of servers to test
    let test_servers = vec![
        ("www.google.com", 443),
        ("www.cloudflare.com", 443),
        ("www.github.com", 443),
    ];

    println!("Select a server to connect to:");
    for (i, (host, port)) in test_servers.iter().enumerate() {
        println!("  {}. {}:{}", i + 1, host, port);
    }
    println!("  4. Custom server\n");

    print!("Enter choice (1-4): ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let choice: usize = input.trim().parse().unwrap_or(1);

    let (host, port) = if choice <= test_servers.len() && choice > 0 {
        test_servers[choice - 1]
    } else if choice == 4 {
        print!("Enter hostname: ");
        io::stdout().flush()?;
        let mut hostname = String::new();
        io::stdin().read_line(&mut hostname)?;
        let hostname = hostname.trim().to_string();

        print!("Enter port (default 443): ");
        io::stdout().flush()?;
        let mut port_str = String::new();
        io::stdin().read_line(&mut port_str)?;
        let port: u16 = port_str.trim().parse().unwrap_or(443);

        // We need static strings for the match, so use a default
        println!("Connecting to custom server {}:{}...", hostname, port);
        return connect_to_server(&hostname, port);
    } else {
        test_servers[0] // Default to Google
    };

    connect_to_server(host, port)
}

fn connect_to_server(host: &str, port: u16) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Connecting to {}:{} ===\n", host, port);

    // Step 1: Create TCP connection
    println!("Step 1: Establishing TCP connection...");
    let addr = format!("{}:{}", host, port);
    let mut client = TlsClient::connect(&addr)?;
    println!("  ✓ TCP connection established\n");

    // Step 2: Configure ALPN
    println!("Step 2: Configuring ALPN protocols...");
    client.set_alpn_protocols(vec![
        "http/1.1".to_string(), // HTTP/1.1 only for simplicity
    ]);
    println!("  ✓ ALPN protocols: http/1.1\n");

    // Step 2.5: Skip certificate verification for demo purposes
    // WARNING: This is INSECURE and should NOT be used in production!
    println!("⚠️  WARNING: Skipping certificate verification for demo purposes");
    println!("           This is INSECURE and should NOT be used in production!\n");
    client.set_skip_certificate_verification(true);

    // Step 3: Send ClientHello
    println!("Step 3: Sending ClientHello...");
    println!("  Extensions included:");
    println!("    - Server Name Indication (SNI): {}", host);
    println!("    - Supported Groups: x25519, secp256r1, secp384r1");
    println!("    - Signature Algorithms: RSA-PSS, ECDSA, Ed25519");
    println!("    - ALPN: http/1.1");
    println!("    - Supported Versions: TLS 1.3");
    println!("    - Key Share: x25519");

    client.send_client_hello()?;
    println!("  ✓ ClientHello sent\n");

    // Step 4: Receive ServerHello
    println!("Step 4: Receiving ServerHello...");
    client.receive_server_hello()?;
    println!("  ✓ ServerHello received");
    println!("  ✓ Handshake encryption keys derived\n");

    // Step 5: Receive EncryptedExtensions
    println!("Step 5: Receiving EncryptedExtensions...");
    client.receive_encrypted_extensions()?;
    println!("  ✓ EncryptedExtensions received and decrypted\n");

    // Step 6: Receive Certificate
    println!("Step 6: Receiving server Certificate...");
    let certificate = client.receive_certificate()?;
    println!("  ✓ Certificate chain received");

    // Display certificate info
    if let Some(cert) = certificate.end_entity_certificate() {
        println!("  ✓ End-entity certificate:");
        println!("    - Certificate size: {} bytes", cert.cert_data.len());
        println!("    - Extensions: {}", cert.extensions.len());
    }
    println!();

    // Step 7: Receive CertificateVerify
    println!("Step 7: Receiving CertificateVerify...");
    client.receive_certificate_verify(&certificate)?;
    println!("  ✓ CertificateVerify received (verification skipped)\n");

    // Step 8: Receive server Finished
    println!("Step 8: Receiving server Finished...");
    client.receive_server_finished()?;
    println!("  ✓ Server Finished received and verified\n");

    // Step 9: Send client Finished
    println!("Step 9: Sending client Finished...");
    client.send_client_finished()?;
    println!("  ✓ Client Finished sent");
    println!("  ✓ Application encryption keys derived\n");

    // Handshake complete!
    println!("🎉 TLS 1.3 Handshake Complete! 🎉\n");
    println!("Connection is now secured and ready for application data.");
    println!("You can now send HTTP requests or other encrypted data.\n");

    // Step 10: Send HTTP GET request
    println!("Step 10: Sending HTTP GET request...");
    let http_request = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: tls-protocol-rust/0.1.0\r\nConnection: close\r\n\r\n",
        host
    );

    println!(
        "  Request:\n{}",
        http_request.trim().replace("\r\n", "\n    ")
    );
    client.send_application_data(http_request.as_bytes())?;
    println!("  ✓ HTTP request sent\n");

    // Step 11: Receive HTTP response (may come in multiple TLS records)
    println!("Step 11: Receiving HTTP response...");
    let mut all_data = Vec::new();
    let mut chunk_count = 0;

    loop {
        match client.receive_application_data() {
            Ok(data) => {
                if data.is_empty() {
                    break; // Connection closed
                }
                chunk_count += 1;
                all_data.extend_from_slice(&data);
                print!(
                    "  ✓ Received chunk {} ({} bytes, {} total)\r",
                    chunk_count,
                    data.len(),
                    all_data.len()
                );
                std::io::stdout().flush().unwrap();
            }
            Err(e) => {
                // Connection closed or error
                if chunk_count > 0 {
                    println!(); // New line after progress indicator
                    break;
                }
                return Err(Box::new(e));
            }
        }
    }

    println!(
        "\n  ✓ Total received: {} bytes in {} chunk(s)\n",
        all_data.len(),
        chunk_count
    );

    // Parse and display response
    let response_str = String::from_utf8_lossy(&all_data);
    let lines: Vec<&str> = response_str.lines().collect();

    if !lines.is_empty() {
        println!("Response preview:");
        println!("  {}", "─".repeat(60));
        for (i, line) in lines.iter().take(20).enumerate() {
            println!("  {}", line);
            if i == 19 && lines.len() > 20 {
                println!("  ... ({} more lines)", lines.len() - 20);
            }
        }
        println!("  {}", "─".repeat(60));
    }

    // Decode chunked transfer encoding if present
    let response_to_save = if response_str.contains("Transfer-Encoding: chunked") {
        // Find the end of headers
        if let Some(body_start) = response_str.find("\r\n\r\n") {
            let headers = &response_str[..body_start + 4];
            let chunked_body = &response_str[body_start + 4..];

            // Decode chunked encoding
            let mut decoded = String::new();
            let mut remaining = chunked_body;

            while !remaining.is_empty() {
                // Find chunk size line
                if let Some(newline_pos) = remaining.find("\r\n") {
                    let size_str = &remaining[..newline_pos];
                    // Parse hex chunk size
                    if let Ok(chunk_size) = usize::from_str_radix(size_str.trim(), 16) {
                        if chunk_size == 0 {
                            break; // Last chunk
                        }

                        let chunk_start = newline_pos + 2;
                        let chunk_end = chunk_start + chunk_size;

                        if chunk_end <= remaining.len() {
                            decoded.push_str(&remaining[chunk_start..chunk_end]);
                            remaining = &remaining[(chunk_end + 2).min(remaining.len())..];
                        // Skip \r\n after chunk
                        } else {
                            break; // Incomplete chunk
                        }
                    } else {
                        break; // Invalid chunk size
                    }
                } else {
                    break; // No more chunks
                }
            }

            format!("{}{}", headers, decoded)
        } else {
            response_str.to_string()
        }
    } else {
        response_str.to_string()
    };

    // Save full response with headers
    let filename = format!("{}_response.html", host.replace(".", "_"));
    println!("\nStep 12: Saving response to files...");
    fs::write(&filename, response_to_save.as_bytes())?;
    println!("  ✓ Full response saved to: {}", filename);

    // Extract and save just the HTML body (without headers) for browser viewing
    let html_only_filename = format!("{}_page.html", host.replace(".", "_"));
    if let Some(body_start) = response_to_save.find("\r\n\r\n") {
        let html_body = &response_to_save[body_start + 4..];
        fs::write(&html_only_filename, html_body.as_bytes())?;
        println!(
            "  ✓ HTML page saved to: {} (open in browser!)",
            html_only_filename
        );
    } else if let Some(body_start) = response_to_save.find("\n\n") {
        // Fallback for \n\n separator
        let html_body = &response_to_save[body_start + 2..];
        fs::write(&html_only_filename, html_body.as_bytes())?;
        println!(
            "  ✓ HTML page saved to: {} (open in browser!)",
            html_only_filename
        );
    }

    println!("\n✓ Successfully communicated with {}!", host);
    println!("✓ Connection verified and working!");
    println!("✓ Full response: {}", filename);
    println!("✓ Browser-ready HTML: {}\n", html_only_filename);

    Ok(())
}
