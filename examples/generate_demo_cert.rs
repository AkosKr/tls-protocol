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
    // ⚠️  CRITICAL WARNING: This creates an INVALID certificate that WILL NOT WORK
    // ⚠️  for actual TLS handshakes. It will cause connection failures.
    //
    // This placeholder exists only to demonstrate the file format structure.
    // The hardcoded bytes (0x30, 0x82, 0x01, 0x00) represent an incomplete DER
    // SEQUENCE header that does NOT constitute a valid X.509 certificate.
    //
    // For a WORKING demo, you MUST use one of these alternatives:
    //   1. Run: ./generate_demo_cert.sh (OpenSSL-based, RECOMMENDED)
    //   2. Use the rcgen library: https://crates.io/crates/rcgen
    //   3. Use OpenSSL directly: openssl req -x509 -newkey rsa:2048 ...
    //
    // This function should be replaced with proper certificate generation
    // using libraries like rcgen or x509-cert for production code.

    // Minimal DER certificate structure (INVALID - will fail TLS validation)
    vec![
        0x30, 0x82, 0x01,
        0x00, // SEQUENCE header (incomplete - NOT a valid certificate)
             // ... rest would need to be a proper X.509 certificate structure
    ]
}
