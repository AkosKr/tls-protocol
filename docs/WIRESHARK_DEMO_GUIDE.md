# Wireshark Demo Guide: Analyzing TLS 1.3 Traffic

This guide shows you how to capture and analyze TLS 1.3 traffic using Wireshark to verify that your handshake and data exchange are working correctly.

## Table of Contents
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Detailed Instructions](#detailed-instructions)
- [What to Expect](#what-to-expect)
- [Analyzing the Handshake](#analyzing-the-handshake)
- [Analyzing Application Data](#analyzing-application-data)
- [Common Issues](#common-issues)
- [Advanced Analysis](#advanced-analysis)

## Prerequisites

1. **Wireshark installed**: Download from [wireshark.org](https://www.wireshark.org/)
2. **Demo binaries built**: Run `cargo build --examples`
3. **Certificates generated**: Run `./generate_demo_cert.sh`

## Quick Start

### 1. Start Wireshark

```bash
# On Linux
sudo wireshark

# On macOS
# Open Wireshark from Applications

# On Windows
# Run Wireshark as Administrator
```

### 2. Configure Capture

1. Select the **loopback interface** (`lo` on Linux, `Loopback` on Windows/macOS)
2. Apply the display filter: `tcp.port == 4433`
3. Click **Start Capturing**

### 3. Run the Demo

In terminal 1:
```bash
cargo run --example demo_server
```

In terminal 2:
```bash
cargo run --example demo_client
```

### 4. Stop Capture

Once the client completes, click the red **Stop** button in Wireshark.

## Detailed Instructions

### Setting Up Wireshark Filters

Wireshark filters help focus on relevant traffic:

**Basic filter** (shows all traffic on port 4433):
```
tcp.port == 4433
```

**More specific filters**:
```
# Only TLS handshake messages
tls.handshake

# Only application data
tls.record.content_type == 23

# Specific connection
ip.addr == 127.0.0.1 && tcp.port == 4433
```

### Wireshark Display Columns

Add these columns for better visibility:
1. Go to **Edit → Preferences → Columns**
2. Add a new column:
   - Title: "TLS Info"
   - Type: "Custom"
   - Field: `tls.handshake.type`

## What to Expect

### Connection Timeline

Here's what you should see in Wireshark (in order):

```
1. TCP: SYN            [Client → Server]
2. TCP: SYN, ACK       [Server → Client]
3. TCP: ACK            [Client → Server]
   ↓ TCP Connection Established ↓

4. TLS: Client Hello   [Client → Server]
5. TLS: Server Hello   [Server → Client]
6. TLS: Change Cipher Spec (legacy, ignored)
7. TLS: Application Data (encrypted handshake messages)
   - EncryptedExtensions
   - Certificate
   - CertificateVerify
   - Finished
8. TLS: Application Data (encrypted handshake messages)
   - Client Finished
   ↓ Handshake Complete ↓

9. TLS: Application Data [Client → Server] (encrypted messages)
10. TLS: Application Data [Server → Client] (encrypted echoes)
11. TLS: Application Data [Client → Server] (more messages)
...
```

### Visual Indicators

✅ **Successful Handshake**:
- Client Hello and Server Hello are visible as plaintext
- Multiple "Application Data" packets after Server Hello
- No TCP retransmissions or errors
- Client sends multiple messages after handshake

❌ **Failed Handshake**:
- TCP connection resets (RST packets)
- TLS Alert messages
- No Application Data packets

## Analyzing the Handshake

### 1. Client Hello (Plaintext)

Click on the "Client Hello" packet and expand the TLS section:

**Key fields to examine**:
- **Version**: Should be TLS 1.2 (0x0303) for compatibility
- **Random**: 32 random bytes
- **Cipher Suites**: Look for `TLS_AES_128_GCM_SHA256 (0x1301)`
- **Extensions**:
  - `supported_versions`: Should include TLS 1.3 (0x0304)
  - `key_share`: X25519 public key (32 bytes)
  - `supported_groups`: secp256r1, x25519

**What it looks like**:
```
Transport Layer Security
    TLSv1.2 Record Layer: Handshake Protocol: Client Hello
        Content Type: Handshake (22)
        Version: TLS 1.2 (0x0303)
        Length: 512
        Handshake Protocol: Client Hello
            Handshake Type: Client Hello (1)
            Length: 508
            Version: TLS 1.2 (0x0303)
            Random: 1a2b3c4d... (32 bytes)
            Cipher Suites Length: 2
            Cipher Suites (1 suite)
                Cipher Suite: TLS_AES_128_GCM_SHA256 (0x1301)
            Extensions Length: 463
            Extension: supported_versions
                Type: supported_versions (43)
                Supported Version: TLS 1.3 (0x0304)
            Extension: key_share
                Type: key_share (51)
                Key Share extension
                    Named Group: x25519 (0x001d)
                    Key Exchange Length: 32
                    Key Exchange: [32 bytes of public key]
```

### 2. Server Hello (Plaintext)

**Key fields to examine**:
- **Version**: TLS 1.2 (0x0303)
- **Random**: 32 random bytes (different from client)
- **Cipher Suite**: `TLS_AES_128_GCM_SHA256 (0x1301)`
- **Extensions**:
  - `supported_versions`: TLS 1.3 (0x0304)
  - `key_share`: Server's X25519 public key

### 3. Encrypted Handshake Messages

After Server Hello, all messages are encrypted in "Application Data" records:

```
Transport Layer Security
    TLSv1.3 Record Layer: Application Data Protocol
        Content Type: Application Data (23)
        Version: TLS 1.2 (0x0303)
        Length: 1402
        Encrypted Application Data: [encrypted bytes]
```

**What's inside** (you can't see this in Wireshark without keys):
- EncryptedExtensions
- Certificate
- CertificateVerify
- Server Finished
- Client Finished

### 4. Verifying Encryption

To confirm encryption is active:

1. Right-click on an "Application Data" packet after Server Hello
2. Select **Follow → TCP Stream**
3. You should see:
   - Beginning: Readable Client Hello and Server Hello
   - Rest: Unreadable encrypted data (looks like random bytes)

**Example**:
```
Plaintext Client Hello:
16 03 01 02 00 01 00 01 fc 03 03 [readable fields]

Encrypted Application Data:
17 03 03 05 a2 [then random-looking encrypted bytes]
```

## Analyzing Application Data

### Message Structure

Each application data record has this structure:

```
TLS Record Header (5 bytes):
  Content Type: 0x17 (Application Data)
  Version: 0x03 0x03 (TLS 1.2 for compatibility)
  Length: 2 bytes (payload length including auth tag)

Encrypted Payload:
  [encrypted application data]
  [16-byte AEAD authentication tag]
```

### Identifying Messages

Use the packet size to distinguish messages:

- **Small packets (~40 bytes)**: Likely short messages like "Hello, TLS 1.3!"
- **Larger packets (>500 bytes)**: Certificate messages in handshake
- **Pairs of similar-sized packets**: Request and response (echo)

### Timing Analysis

Check the time delta between packets:

1. Add a "Time" column: Right-click column header → Column Preferences
2. Look at time between client send and server response
3. Typical echo latency on localhost: < 1ms

## Common Issues

### Issue: No Packets Captured

**Solutions**:
- Ensure you're capturing on the **loopback interface** (`lo`, not `eth0` or `wlan0`)
- Check the filter syntax: `tcp.port == 4433` (no quotes)
- Verify the demo is running on port 4433

### Issue: Handshake Fails

**Check for**:
- **TCP RST packets**: Connection reset, server not ready
- **TLS Alert messages**: Cryptographic or protocol errors
- **Retransmissions**: Network issues (unlikely on localhost)

**Common causes**:
- Certificate/key mismatch: Run `./generate_demo_cert.sh` again
- Port already in use: Kill other processes using port 4433
- Old certificate: Regenerate demo certificates

### Issue: Can't See TLS Details

**Solutions**:
1. Update Wireshark to the latest version (3.6+)
2. Go to **Edit → Preferences → Protocols → TLS**
3. Ensure "Reassemble TLS records" is enabled
4. Right-click packet → Decode As → TLS

### Issue: "Application Data" Shows No Details

This is **expected**! TLS 1.3 encrypts almost everything after Server Hello.

To decrypt (advanced):
1. Enable TLS key logging in your application (requires code changes)
2. Set `SSLKEYLOGFILE` environment variable
3. Configure Wireshark to use the key log file
4. **Note**: This is only for debugging, never in production!

## Advanced Analysis

### Statistics

View connection statistics:

1. **Statistics → Conversations**
   - Select TCP tab
   - Find the 127.0.0.1:port ↔ 127.0.0.1:4433 conversation
   - See total bytes transferred

2. **Statistics → Protocol Hierarchy**
   - See breakdown of TLS vs TCP vs IP traffic

3. **Statistics → I/O Graph**
   - Visualize traffic over time
   - Filter: `tcp.port == 4433`

### Exporting Data

Save captured traffic:

1. **File → Export Specified Packets**
2. Select display filter: `tcp.port == 4433`
3. Save as `.pcapng` file
4. Share for analysis or debugging

### TLS Stream Analysis

Detailed stream view:

1. Right-click any TLS packet
2. **Follow → TLS Stream**
3. See complete conversation (plaintext parts only)
4. Use arrow buttons to navigate between streams

## Understanding TLS 1.3 Differences

### TLS 1.3 vs 1.2 in Wireshark

**TLS 1.3 characteristics**:
- ✅ Uses legacy version (0x0303) in record headers
- ✅ Real version in `supported_versions` extension
- ✅ Most handshake encrypted in "Application Data" records
- ✅ 1-RTT handshake (faster than TLS 1.2)
- ✅ No ChangeCipherSpec (or it's ignored)

**TLS 1.2 characteristics**:
- Version 0x0303 means TLS 1.2
- Handshake messages visible (Certificate, ServerKeyExchange, etc.)
- ChangeCipherSpec used for encryption transition
- 2-RTT handshake

### Cipher Suite

Our demo uses:
- **Cipher**: `TLS_AES_128_GCM_SHA256 (0x1301)`
  - AES-128: Symmetric encryption
  - GCM: Galois/Counter Mode (AEAD)
  - SHA256: Hash function for key derivation

This is one of the mandatory cipher suites in TLS 1.3.

## Conclusion

You should now be able to:
- ✅ Capture TLS 1.3 traffic on localhost
- ✅ Identify handshake phases (Client Hello → Server Hello → Application Data)
- ✅ Verify encryption is active (opaque Application Data records)
- ✅ Analyze timing and message flow
- ✅ Troubleshoot common connection issues

For more details on the TLS 1.3 protocol, see [RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446).

## Screenshots Guide

When taking screenshots for your report or documentation:

1. **Overview**: Full Wireshark window showing complete handshake
2. **Client Hello**: Expanded view of Client Hello fields
3. **Server Hello**: Expanded view of Server Hello with key_share
4. **Application Data**: Show encrypted records with hex dump
5. **TCP Stream**: Follow stream showing plaintext beginning, encrypted rest
6. **Statistics**: Show Protocol Hierarchy or I/O Graph

## Troubleshooting Commands

```bash
# Check if port is in use
sudo lsof -i :4433

# Kill process using port
sudo kill -9 <PID>

# Test TCP connection
telnet 127.0.0.1 4433

# Check certificate
openssl x509 -in demo_cert.pem -text -noout

# Verify private key
openssl rsa -in demo_key.pem -check

# Test certificate/key match
openssl x509 -in demo_cert.pem -pubkey -noout | openssl md5
openssl rsa -in demo_key.pem -pubout | openssl md5
# ^ These should match
```

---

**Happy analyzing!** 🔍🔒
