//! TLS 1.3 Client Example
//!
//! This example demonstrates how to use the TlsClient to establish a secure
//! TLS 1.3 connection, perform the handshake, and exchange application data.
//!
//! Note: This example is designed to connect to a real TLS 1.3 server.
//! For testing purposes, you can use a local test server or a public server
//! that supports TLS 1.3.
//!
//! Run with:
//! ```bash
//! cargo run --example tls_client
//! ```

fn main() {
    println!("=== TLS 1.3 Client Example ===\n");

    // Example 1: High-level API (automatic handshake)
    example_high_level_api();

    println!("\n{}\n", "=".repeat(50));

    // Example 2: Step-by-step handshake
    example_step_by_step();
}

/// Example using the high-level API with automatic handshake
fn example_high_level_api() {
    println!("Example 1: High-Level API");
    println!("-------------------------\n");

    // Note: This will fail without a real TLS 1.3 server running
    // For demonstration purposes, we show the intended usage

    println!("Step 1: Connect to server");
    println!("  let mut client = TlsClient::connect(\"example.com:443\")?;\n");

    println!("Step 2: Perform handshake (all steps automatic)");
    println!("  client.perform_handshake()?;");
    println!("  ✓ ClientHello sent");
    println!("  ✓ ServerHello received");
    println!("  ✓ EncryptedExtensions received");
    println!("  ✓ Certificate received");
    println!("  ✓ CertificateVerify received");
    println!("  ✓ Server Finished received and verified");
    println!("  ✓ Client Finished sent");
    println!("  ✓ Handshake complete!\n");

    println!("Step 3: Send application data");
    println!("  let request = b\"GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n\";");
    println!("  client.send_application_data(request)?;\n");

    println!("Step 4: Receive application data");
    println!("  let response = client.receive_application_data()?;");
    println!("  println!(\"Received: {{}} bytes\", response.len());\n");
}

/// Example using step-by-step handshake for more control
fn example_step_by_step() {
    println!("Example 2: Step-by-Step Handshake");
    println!("----------------------------------\n");

    println!("This example shows manual control over each handshake step:\n");

    println!("Step 1: Create client from TCP stream");
    println!("  use std::net::TcpStream;");
    println!("  let stream = TcpStream::connect(\"example.com:443\")?;");
    println!("  let mut client = TlsClient::new(stream);\n");

    println!("Step 2: Send ClientHello");
    println!("  client.send_client_hello()?;");
    println!("  ✓ Generated random bytes");
    println!("  ✓ Generated X25519 keypair");
    println!("  ✓ Created ClientHello with extensions");
    println!("  ✓ Sent to server\n");

    println!("Step 3: Receive ServerHello");
    println!("  client.receive_server_hello()?;");
    println!("  ✓ Parsed ServerHello");
    println!("  ✓ Validated extensions");
    println!("  ✓ Computed ECDHE shared secret");
    println!("  ✓ Derived handshake traffic keys");
    println!("  ✓ Switched to handshake encryption\n");

    println!("Step 4: Receive EncryptedExtensions");
    println!("  client.receive_encrypted_extensions()?;");
    println!("  ✓ Received encrypted message");
    println!("  ✓ Decrypted with handshake keys\n");

    println!("Step 5: Receive Certificate");
    println!("  let certificate = client.receive_certificate()?;");
    println!("  ✓ Received certificate chain");
    println!("  ✓ Validated certificate structure\n");

    println!("Step 6: Receive CertificateVerify");
    println!("  client.receive_certificate_verify(&certificate)?;");
    println!("  ✓ Received signature");
    println!("  ✓ Verified server possesses private key\n");

    println!("Step 7: Receive server Finished");
    println!("  client.receive_server_finished()?;");
    println!("  ✓ Received server Finished");
    println!("  ✓ Verified server's handshake authentication\n");

    println!("Step 8: Send client Finished");
    println!("  client.send_client_finished()?;");
    println!("  ✓ Generated client Finished");
    println!("  ✓ Sent to server");
    println!("  ✓ Derived application traffic keys");
    println!("  ✓ Switched to application encryption\n");

    println!("Step 9: Check handshake completion");
    println!("  assert!(client.is_ready());");
    println!("  ✓ Ready for application data!\n");

    println!("Step 10: Exchange application data");
    println!("  client.send_application_data(b\"Hello, TLS 1.3!\")?;");
    println!("  let response = client.receive_application_data()?;\n");
}

// Uncomment this for a real example with error handling
// You'll need a TLS 1.3 server running for this to work

/*
fn real_example() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Real TLS 1.3 Client Connection ===\n");

    // Connect to a TLS 1.3 server
    // For testing, you can use: openssl s_server -accept 4433 -tls1_3 -cert cert.pem -key key.pem
    println!("Connecting to localhost:4433...");
    let mut client = TlsClient::connect("localhost:4433")?;
    println!("✓ TCP connection established\n");

    // Perform handshake
    println!("Performing TLS 1.3 handshake...");
    client.perform_handshake()?;
    println!("✓ Handshake complete!\n");

    // Send application data
    println!("Sending application data...");
    let message = b"Hello from TLS 1.3 client!";
    client.send_application_data(message)?;
    println!("✓ Sent: {:?}\n", std::str::from_utf8(message)?);

    // Receive application data
    println!("Receiving application data...");
    let response = client.receive_application_data()?;
    println!("✓ Received: {} bytes", response.len());
    println!("  Data: {:?}\n", std::str::from_utf8(&response)?);

    println!("=== Connection Complete ===");

    Ok(())
}
*/
