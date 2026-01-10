//! TLS 1.3 Server Example
//!
//! This example demonstrates how to set up a TLS 1.3 server using the `TlsServer` struct.
//!
//! Note: To run a working TLS handshake, you need a valid X.509 certificate and
//! corresponding private key. This example uses placeholders.

use std::net::TcpListener;
use std::thread;

use tls_protocol::{Certificate, CertificateEntry, PrivateKey, TlsServer};
use rsa::RsaPrivateKey;

fn handle_client(stream: std::net::TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    println!("New connection from: {}", stream.peer_addr()?);

    // 1. Setup Server Credentials
    // In a real application, load these from disk (e.g. PEM files)
    
    // Generate a temporary RSA key for demonstration (2048 bits)
    let mut rng = rand::rngs::OsRng;
    let rsa_key = RsaPrivateKey::new(&mut rng, 2048)?;
    let private_key = PrivateKey::Rsa(rsa_key);

    // Create a dummy certificate placeholder
    // NOTE: This will fail signature verification on the client because the public key
    // in this dummy cert doesn't match the private key we just generated.
    // In a real implementation, you must construct a valid X.509 certificate containing `rsa_key.to_public_key()`.
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
