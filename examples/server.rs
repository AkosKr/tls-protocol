//! TLS 1.3 Server Example
//!
//! This example demonstrates how to set up a TLS 1.3 server using the `TlsServer` struct.
//!
//! ⚠️ WARNING: This example uses placeholder credentials and will NOT complete a successful
//! handshake with real clients. To run a working TLS server, you must:
//! 1. Generate or obtain a valid X.509 certificate in DER format
//! 2. Load the corresponding private key
//! 3. Ensure the certificate's public key matches the private key
//!
//! Consider using a certificate generation library like `rcgen` or tools like OpenSSL
//! to create proper certificates for testing.

use std::net::TcpListener;
use std::thread;

use tls_protocol::{Certificate, CertificateEntry, PrivateKey, TlsServer};
use rsa::RsaPrivateKey;

fn handle_client(stream: std::net::TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    println!("New connection from: {}", stream.peer_addr()?);

    // 1. Setup Server Credentials
    // ⚠️ WARNING: This example uses placeholder credentials for demonstration purposes only.
    // The dummy certificate does NOT match the generated private key and will fail
    // signature verification on any real TLS client.
    //
    // For production use:
    // - Load a valid X.509 DER certificate from disk (e.g., using std::fs::read)
    // - Load the corresponding private key (e.g., from PEM using rsa::RsaPrivateKey::from_pkcs8_pem)
    // - Or use a library like `rcgen` to generate self-signed certificates for testing
    
    // Generate a temporary RSA key for demonstration (2048 bits)
    let mut rng = rand::rngs::OsRng;
    let rsa_key = RsaPrivateKey::new(&mut rng, 2048)?;
    let private_key = PrivateKey::Rsa(rsa_key);

    // Dummy certificate (NOT VALID - for demonstration only)
    let cert_data = vec![0u8; 100]; 
    let certificate = Certificate::new(vec![], vec![CertificateEntry::new(cert_data, vec![])]);

    // 2. Create TlsServer
    let mut server = TlsServer::new(stream, certificate, private_key);

    // 3. Perform Handshake
    println!("Performing handshake...");
    match server.perform_handshake() {
        Ok(_) => println!("Handshake successful!"),
        Err(e) => {
            eprintln!("Handshake failed: {:?}", e);
            return Ok(());
        }
    }

    // 4. Echo loop
    loop {
        match server.receive_application_data() {
            Ok(data) => {
                if data.is_empty() {
                    break;
                }
                println!("Received: {}", String::from_utf8_lossy(&data));
                server.send_application_data(&data)?;
            }
            Err(_) => break,
        }
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "127.0.0.1:4433";
    let listener = TcpListener::bind(addr)?;

    println!("TLS Server listening on {}", addr);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(move || {
                    if let Err(e) = handle_client(stream) {
                        eprintln!("Error handling connection: {}", e);
                    }
                });
            }
            Err(e) => eprintln!("Connection failed: {}", e),
        }
    }

    Ok(())
}
