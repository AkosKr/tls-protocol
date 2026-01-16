#!/bin/bash
# Start the comprehensive TLS demo client
# Run this in another terminal (after starting the server)

set -e

echo "========================================="
echo "Comprehensive TLS Demo Client"
echo "========================================="
echo ""

# Build the client
echo "Building client..."
cargo build --example demo_comprehensive_client
echo "✓ Build complete"
echo ""

# Run the client
echo "Starting client scenarios..."
echo ""
cargo run --example demo_comprehensive_client
