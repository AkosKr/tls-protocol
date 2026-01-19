#!/bin/bash
# Script to run the comprehensive TLS demo
#
# This script will:
# 1. Start the demo server in the background
# 2. Wait for it to be ready
# 3. Run the demo client
# 4. Clean up the server process

set -e

echo "========================================="
echo "Comprehensive TLS 1.3 Demo"
echo "========================================="
echo ""

# Check if certificate exists
if [ ! -f "demo_cert.der" ]; then
    echo "⚠ Certificate not found. Generating demo certificate..."
    ./generate_demo_cert.sh
    echo ""
fi

# Build the examples
echo "Building examples..."
cargo build --example demo_comprehensive_server --example demo_comprehensive_client
echo "✓ Build complete"
echo ""

# Start the server in the background
echo "Starting demo server..."
cargo run --example demo_comprehensive_server &
SERVER_PID=$!

# Give the server time to start
sleep 2

# Check if server is still running
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "✗ Server failed to start"
    exit 1
fi

echo "✓ Server started (PID: $SERVER_PID)"
echo ""

# Run the client
echo "Starting demo client..."
echo ""
cargo run --example demo_comprehensive_client

# Kill the server
echo ""
echo "Stopping server..."
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

echo ""
echo "========================================="
echo "Demo complete!"
echo "========================================="
