#!/bin/bash
# Start the comprehensive TLS demo server
# Run this in one terminal

set -e

echo "========================================="
echo "Comprehensive TLS Demo Server"
echo "========================================="
echo ""

# Check if certificate exists
if [ ! -f "demo_cert.der" ]; then
    echo "⚠ Certificate not found. Generating demo certificate..."
    ./generate_demo_cert.sh
    echo ""
fi

# Build the server
echo "Building server..."
cargo build --example demo_comprehensive_server
echo "✓ Build complete"
echo ""

# Run the server
echo "Starting server on 127.0.0.1:4433..."
echo "Press Ctrl+C to stop"
echo ""
cargo run --example demo_comprehensive_server
