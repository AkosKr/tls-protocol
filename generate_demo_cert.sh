#!/bin/bash
# Generate demo certificate and key for TLS 1.3 demo
# This script creates a self-signed RSA certificate for localhost testing

echo "=== TLS Demo Certificate Generator ==="
echo ""
echo "This script generates a self-signed certificate for demo purposes."
echo "The certificate is valid for 365 days and uses RSA-2048."
echo ""

# Check if openssl is available
if ! command -v openssl &> /dev/null; then
    echo "ERROR: openssl is not installed"
    echo "Please install OpenSSL and try again"
    exit 1
fi

echo "Step 1: Generating RSA-2048 private key..."
openssl genpkey -algorithm RSA -out demo_key.pem -pkeyopt rsa_keygen_bits:2048
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to generate private key"
    exit 1
fi
echo "✓ Private key saved to demo_key.pem"

echo ""
echo "Step 2: Generating self-signed certificate..."
openssl req -new -x509 -key demo_key.pem -out demo_cert.pem -days 365 \
    -subj "/C=US/ST=Demo/L=Demo/O=TLS-Protocol-Demo/CN=localhost"
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to generate certificate"
    exit 1
fi
echo "✓ Certificate saved to demo_cert.pem"

echo ""
echo "Step 3: Converting certificate to DER format..."
openssl x509 -in demo_cert.pem -out demo_cert.der -outform DER
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to convert certificate to DER"
    exit 1
fi
echo "✓ Certificate saved to demo_cert.der"

echo ""
echo "=================================================="
echo "Certificate generation complete!"
echo "=================================================="
echo ""
echo "Generated files:"
echo "  • demo_key.pem  - RSA private key (PEM format)"
echo "  • demo_cert.pem - Certificate (PEM format)"
echo "  • demo_cert.der - Certificate (DER format)"
echo ""
echo "Certificate details:"
openssl x509 -in demo_cert.pem -noout -text | grep -A 2 "Subject:"
openssl x509 -in demo_cert.pem -noout -text | grep -A 2 "Validity"
echo ""
echo "To use with the demo:"
echo "  cargo run --example demo_server"
echo "  cargo run --example demo_client"
echo ""
echo "⚠️  NOTE: This certificate is self-signed and for demo purposes only"
