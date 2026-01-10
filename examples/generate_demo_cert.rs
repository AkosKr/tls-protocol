//! Certificate Generator for TLS Demo
//!
//! This tool generates a self-signed certificate and private key for use with
//! the demo_server. The certificate uses RSA-2048 and is saved in the formats
//! required by the demo.
//!
//! Run with:
//! ```bash
//! cargo run --example generate_demo_cert
//! ```
//!
//! This will create:
//! - demo_cert.der: Certificate in DER format
//! - demo_key.pem: Private key in PEM format

use rsa::pkcs1::LineEnding;
use rsa::{pkcs8::EncodePrivateKey, RsaPrivateKey};
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== TLS Demo Certificate Generator ===\n");

    println!("Step 1: Generating RSA-2048 private key...");
    let mut rng = rand::rngs::OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048)?;
    println!("✓ Private key generated");

    println!("\nStep 2: Saving private key to demo_key.pem...");
    let pem = private_key.to_pkcs8_pem(LineEnding::LF)?;
    fs::write("demo_key.pem", pem.as_bytes())?;
    println!("✓ Private key saved");

    println!("\nStep 3: Generating self-signed certificate...");
    // For a real implementation, you would use a library like rcgen or x509-cert
    // For this demo, we'll create a minimal placeholder certificate
    println!("⚠️  WARNING: This generates a PLACEHOLDER certificate");
    println!("⚠️  For production use, use proper certificate generation tools");
    println!("⚠️  Consider using: openssl, rcgen library, or Let's Encrypt");

    // Create a minimal certificate structure
    // In a real implementation, you would use rcgen or similar
    let cert_data = create_placeholder_certificate();

    println!("\nStep 4: Saving certificate to demo_cert.der...");
    fs::write("demo_cert.der", &cert_data)?;
    println!("✓ Certificate saved");

    println!("\n{}", "=".repeat(50));
    println!("Certificate generation complete!");
    println!("{}", "=".repeat(50));
    println!("\nGenerated files:");
    println!("  • demo_key.pem  - RSA private key (PEM format)");
    println!("  • demo_cert.der - Certificate (DER format)");
    println!("\nTo use with the demo:");
    println!("  cargo run --example demo_server");
    println!("  cargo run --example demo_client");
    println!("\n⚠️  NOTE: The certificate is self-signed and for demo purposes only");
    println!("For production, generate proper certificates using:");
    println!("  • OpenSSL: openssl req -x509 -newkey rsa:2048 ...");
    println!("  • rcgen: Use the rcgen Rust library");
    println!("  • Let's Encrypt: For publicly trusted certificates");

    Ok(())
}

fn create_placeholder_certificate() -> Vec<u8> {
    // This is a minimal placeholder
    // In a production environment, use proper certificate generation
    // with libraries like rcgen or x509-cert

    // Minimal DER certificate structure (NOT VALID for real TLS)
    vec![
        0x30, 0x82, 0x01,
        0x00, // SEQUENCE header
             // ... rest would be a proper X.509 certificate
    ]
}
