# Comprehensive TLS 1.3 Cipher Suite Demo

This demo showcases various cipher suite negotiation scenarios in TLS 1.3, including successful handshakes, cipher mismatches, and detailed encrypted/decrypted data display for Wireshark analysis.

## Overview

The comprehensive demo consists of:
- **demo_comprehensive_server.rs**: TLS server that supports cipher suite negotiation
- **demo_comprehensive_client.rs**: TLS client that tests different cipher suite configurations

## Demonstrated Scenarios

### Scenario 1: All Cipher Suites
- Client offers all TLS 1.3 cipher suites
- Server chooses based on preference
- Demonstrates standard negotiation

### Scenario 2: AES-128-GCM Only
- Client offers only `TLS_AES_128_GCM_SHA256` (0x1301)
- Tests specific cipher selection

### Scenario 3: AES-256-GCM Only
- Client offers only `TLS_AES_256_GCM_SHA384` (0x1302)
- Tests alternate cipher selection

### Scenario 4: ChaCha20-Poly1305 Only
- Client offers only `TLS_CHACHA20_POLY1305_SHA256` (0x1303)
- Tests alternative cipher algorithm

### Scenario 5: Incompatible Cipher (Error Case)
- Client offers ciphers the server doesn't support (0xC02F, 0xC030)
- Tests error handling when no common cipher suite exists
- Demonstrates proper handshake failure

## Features

### Encrypted/Decrypted Data Display
Each message exchange shows:
1. **Plaintext before encryption** - The actual data to be sent
2. **Hex dump** - Raw bytes of the plaintext
3. **Encrypted TLS record** - Complete header + encrypted payload with hex dump
4. **Encryption status** - Indication when data is encrypted
5. **Decrypted plaintext** - Data after TLS record decryption
6. **Verification** - Confirms echo matches original message

**NEW**: The demos now display the actual encrypted bytes sent over the network, making it easy to match with Wireshark packet captures. See [ENCRYPTED_DATA_DISPLAY_GUIDE.md](../ENCRYPTED_DATA_DISPLAY_GUIDE.md) for details.

### Wireshark Integration
The demos are designed to work with Wireshark:
- All traffic goes through localhost port 4433
- Console output shows plaintext for comparison
- TLS records can be observed in Wireshark
- Encrypted payloads vs plaintext comparison

## Running the Demo

### Method 1: Separate Terminal Sessions (Recommended)
This method allows you to see server and client logs in separate windows.

#### Terminal 1 - Start the server:
```bash
./run_demo_server.sh
```

#### Terminal 2 - Run the client:
```bash
./run_demo_client.sh
```

### Method 2: Automated Script (Deprecated)
```bash
./run_comprehensive_demo.sh
```

This script runs both server and client together, but logs are interleaved.

### Method 3: Manual Execution

#### Terminal 1 - Start the server:
```bash
cargo run --example demo_comprehensive_server
```

#### Terminal 2 - Run the client:
```bash
cargo run --example demo_comprehensive_client
```

## Wireshark Setup

1. **Start Wireshark** before running the demos
2. **Capture on loopback interface** (`lo`)
3. **Apply filter**: `tcp.port == 4433`
4. **Observe**:
   - TCP handshake
   - TLS ClientHello with cipher suites
   - TLS ServerHello with selected cipher
   - Encrypted Handshake messages
   - Application Data records (ContentType 0x17)

### What to Look For in Wireshark

#### ClientHello Packet
- Cipher Suites list (varies by scenario)
- Key Share extension (X25519 public key)
- Supported Versions extension (TLS 1.3)

#### ServerHello Packet
- Selected cipher suite (single value)
- Server's Key Share (X25519 response)

#### Encrypted Records
- ContentType: ApplicationData (0x17)
- Opaque encrypted payload
- Length matches plaintext + overhead (16-byte auth tag)

## Code Modifications

The implementation has been enhanced to support:

### Client (`src/client.rs`)
- `set_cipher_suites()` - Configure custom cipher suite list
- `custom_cipher_suites` field - Store client preferences
- Modified `send_client_hello()` - Use custom or default ciphers

### Server (`src/server.rs`)
- `set_supported_cipher_suites()` - Configure server preferences
- `negotiated_cipher_suite()` - Get the selected cipher
- Cipher negotiation in `send_server_hello()` - Find common cipher
- Proper error handling for no overlap

## Example Output

```
═══════════════════════════════════════════════════════════════════
Scenario 1: All Cipher Suites
═══════════════════════════════════════════════════════════════════

[INFO] Offered Ciphers:
  • TLS_AES_128_GCM_SHA256 (0x1301)
  • TLS_AES_256_GCM_SHA384 (0x1302)
  • TLS_CHACHA20_POLY1305_SHA256 (0x1303)

✓ TCP connection established

TLS 1.3 Handshake
=================
✓ ClientHello sent with custom cipher suites
✓ ServerHello received
[INFO] Key Exchange: X25519 ECDHE completed

[PLAINTEXT TO SEND]
[INFO] Content: "Hello from All Cipher Suites"
[SECURITY] Plaintext (hex): 48 65 6c 6c 6f 20 66 72 6f 6d 20 41 6c 6c 20 43...

[ENCRYPTING & SENDING]
✓ Plaintext encrypted and sent as TLS record

[ENCRYPTED TLS RECORD SENT]
[INFO] Total Length: 46 bytes (5-byte header + ciphertext)
[INFO] Header: 17 03 03 00 29
[INFO] Details: ContentType=0x17 (ApplicationData), Version=0x0303, Length=41
[SECURITY] Encrypted Payload: a3 f2 8d 4e b1 c9 7a 2f 8e 5d 3c 1b 9f 4a 6e 2d...
[INFO] Payload Length: 41 bytes (includes 16-byte auth tag)

[RECEIVING ENCRYPTED RESPONSE]
✓ Encrypted TLS record received and decrypted

[DECRYPTED PLAINTEXT]
[INFO] Content: "Hello from All Cipher Suites"
✓ Echo matches sent message
```

## Cipher Suite Reference

| Suite ID | Name | Hash | AEAD |
|----------|------|------|------|
| 0x1301 | TLS_AES_128_GCM_SHA256 | SHA-256 | AES-128-GCM |
| 0x1302 | TLS_AES_256_GCM_SHA384 | SHA-384 | AES-256-GCM |
| 0x1303 | TLS_CHACHA20_POLY1305_SHA256 | SHA-256 | ChaCha20-Poly1305 |

All three cipher suites are TLS 1.3 mandatory-to-implement.

## Understanding the Output

### Color Coding
- **🔵 BLUE**: Informational messages
- **🟢 GREEN**: Success indicators and decrypted data
- **🟡 YELLOW**: Warnings and encryption actions
- **🟣 MAGENTA**: Security-related info (hex dumps, encryption)
- **🔴 RED**: Errors and failures
- **🔷 CYAN**: Headers and structure

### Data Flow
1. Plaintext message is shown
2. Hex dump displays raw bytes
3. Encryption status confirmed
4. TLS record sent over network
5. Encrypted TLS record received
6. Decryption applied
7. Plaintext recovered and verified

## Troubleshooting

### Certificate Issues
If you see certificate errors:
```bash
./generate_demo_cert.sh
```

### Connection Refused
Ensure the server is running before starting the client.

### Handshake Failures
Some scenarios intentionally fail to demonstrate cipher mismatch handling. Check the scenario description to see if failure is expected.

## Next Steps

1. **Review Wireshark captures** to see encrypted traffic
2. **Compare packet contents** with console output
3. **Modify cipher lists** to test other combinations
4. **Add custom scenarios** by editing the demo files

## See Also

- [WIRESHARK_DEMO_GUIDE.md](../docs/WIRESHARK_DEMO_GUIDE.md) - Detailed Wireshark analysis guide
- [README.md](../README.md) - Main project documentation
- [AEAD_IMPLEMENTATION.md](../docs/AEAD_IMPLEMENTATION.md) - Encryption details
