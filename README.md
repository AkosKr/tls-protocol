# tls-protocol

A Rust implementation of the TLS 1.3 protocol for educational and cryptographic purposes.

## Overview

This project implements core components of the TLS 1.3 protocol as specified in RFC 8446. It provides building blocks for establishing secure TLS connections, including record layer handling, handshake messages, and stream management.

## Features Implemented

### Issue #1: Define TLS Record Types and Core Serialization ✅
**Goal**: Create the foundational types for the TLS "Envelope" and outbound serialization.

**Implementation**:
- `ContentType` enum with variants:
  - `Handshake` (22)
  - `Alert` (21)
  - `ApplicationData` (23)
  - `ChangeCipherSpec` (20)
  - `Invalid` (0)
- `RecordHeader` struct containing:
  - `content_type`: ContentType
  - `version`: u16 (legacy_version, typically 0x0303)
  - `length`: u16
- Type conversions: `From<u8>` and `Into<u8>` for ContentType via `TryFrom`
- `to_bytes()` method for RecordHeader serialization to 5-byte format

**Files**: [src/lib.rs](src/lib.rs)

### Issue #2: Implement Record Header Validation and Parsing Logic ✅
**Goal**: Create the logic for safely interpreting raw bytes as TLS headers.

**Implementation**:
- `TlsError` enum with variants:
  - `InvalidVersion`
  - `InvalidContentType`
  - `IncompleteData`
  - `RecordTooLarge`
  - `IoError`
- `parse_header(bytes: &[u8]) -> Result<RecordHeader, TlsError>` function
- Strict validation:
  - Ensures legacy_version is exactly 0x0303 (TLS 1.2 for compatibility)
  - Validates ContentType byte is within valid range
  - Checks for sufficient data length

**Files**: [src/error.rs](src/error.rs), [src/parser.rs](src/parser.rs), [tests/parser_tests.rs](tests/parser_tests.rs)

### Issue #3: Implement Record Decoding (The Parser) ✅
**Goal**: Read bytes from a stream and reconstruct a Header.

**Implementation**:
- `decode_header(src: &[u8]) -> Result<RecordHeader, TlsError>` function
- Handles "short reads" (buffers with < 5 bytes)
- Validates legacy_version is always 0x0303
- Returns appropriate errors for incomplete or invalid data

**Files**: [src/decoder.rs](src/decoder.rs), [tests/decoder_tests.rs](tests/decoder_tests.rs)

### Issue #4: Basic TCP Skeleton (Client/Server) ✅
**Goal**: Establish a raw TCP connection with TLS record handling.

**Implementation**:
- `TlsStream` struct wrapping `std::net::TcpStream`
- `write_record()` method that:
  - Takes a `ContentType` and `Vec<u8>` payload
  - Wraps payload in a proper TLS record header
  - Sends complete record over the TCP stream
- Example client and server demonstrating basic TCP communication
- Compatible with `nc -l -p 4433` for testing

**Files**: [src/tls_stream.rs](src/tls_stream.rs), [examples/client.rs](examples/client.rs), [examples/server.rs](examples/server.rs), [tests/tls_stream_tests.rs](tests/tls_stream_tests.rs)

### Issue #5: ClientHello Struct & Serialization ✅
**Goal**: Construct the first message of the TLS 1.3 handshake.

**Implementation**:
- `ClientHello` struct with fields:
  - `random`: [u8; 32] - 32 bytes of cryptographic random data
  - `legacy_session_id`: Vec<u8> - Legacy session ID for compatibility
  - `cipher_suites`: Vec<u16> - Supported cipher suites
  - `extensions`: Vec<Extension> - TLS extensions
  
- `Extension` enum supporting:
  - `SupportedVersions` - Mandatory for TLS 1.3 (extension type 43)
  - `KeyShare` - Mandatory for TLS 1.3 (extension type 51)
  - `Unknown` - For extensibility
  
- `KeyShareEntry` struct for key exchange with:
  - `group`: u16 - Named group (e.g., x25519, secp256r1)
  - `key_exchange`: Vec<u8> - Public key data
  
- TLS 1.3 cipher suite constants:
  - `TLS_AES_128_GCM_SHA256` (0x1301)
  - `TLS_AES_256_GCM_SHA384` (0x1302)
  - `TLS_CHACHA20_POLY1305_SHA256` (0x1303)
  
- Named group constants:
  - `NAMED_GROUP_X25519` (0x001d)
  - `NAMED_GROUP_SECP256R1` (0x0017)
  
- Serialization methods:
  - `ClientHello::to_bytes()` - Full handshake message serialization
  - `Extension::to_bytes()` - Extension serialization
  - `ClientHello::default_tls13()` - Helper for creating TLS 1.3 ClientHello with mandatory extensions
  
- Wire format (RFC 8446 compliant):
  - Handshake type (1 byte): 0x01
  - Length (3 bytes)
  - Legacy version (2 bytes): 0x0303
  - Random (32 bytes)
  - Legacy session ID (variable)
  - Cipher suites (variable)
  - Legacy compression methods (2 bytes)
  - Extensions (variable)

**Files**: [src/client_hello.rs](src/client_hello.rs), [tests/client_hello_tests.rs](tests/client_hello_tests.rs)

## Project Structure

```
tls-protocol/
├── src/
│   ├── lib.rs              # Core types and exports
│   ├── error.rs            # Error types
│   ├── parser.rs           # Header parsing logic
│   ├── decoder.rs          # Header decoding
│   ├── tls_stream.rs       # TCP stream wrapper
│   └── client_hello.rs     # ClientHello message implementation
├── tests/
│   ├── parser_tests.rs     # Parser validation tests
│   ├── decoder_tests.rs    # Decoder tests
│   ├── tls_stream_tests.rs # Stream tests
│   └── client_hello_tests.rs # ClientHello tests
├── examples/
│   ├── client.rs           # Example TLS client
│   └── server.rs           # Example TLS server
└── Cargo.toml

```

## Usage

### Basic Example: Creating a ClientHello

```rust
use tls_protocol::client_hello::{ClientHello, Extension, KeyShareEntry};
use tls_protocol::client_hello::{TLS_VERSION_1_3, NAMED_GROUP_X25519};

// Generate random bytes (32 bytes required)
let random = [0u8; 32]; // In production, use cryptographically secure random

// Generate or provide x25519 public key (32 bytes)
let public_key = vec![0xaa; 32];

// Create a default TLS 1.3 ClientHello
let client_hello = ClientHello::default_tls13(random, public_key);

// Serialize to bytes for sending over the wire
let bytes = client_hello.to_bytes();
```

### Working with TLS Records

```rust
use tls_protocol::{ContentType, RecordHeader};

// Create a record header
let header = RecordHeader::new(ContentType::Handshake, 0x0303, 512);

// Serialize to bytes
let bytes = header.to_bytes();
assert_eq!(bytes, [22, 3, 3, 2, 0]);
```

### Parsing TLS Records

```rust
use tls_protocol::{parse_header, decode_header};

// Parse a header from bytes
let data = [22, 3, 3, 0, 5];
let header = parse_header(&data).unwrap();
assert_eq!(header.length, 5);

// Decode with validation
let decoded = decode_header(&data).unwrap();
```

## Testing

Run all tests:
```bash
cargo test
```

Run specific test suites:
```bash
cargo test --test parser_tests
cargo test --test decoder_tests
cargo test --test tls_stream_tests
cargo test --test client_hello_tests
```

Run examples:
```bash
# Terminal 1 - Start server
cargo run --example server

# Terminal 2 - Run client
cargo run --example client
```

## Dependencies

- `rand = "0.8"` - For cryptographically secure random number generation

## References

- [RFC 8446 - The Transport Layer Security (TLS) Protocol Version 1.3](https://datatracker.ietf.org/doc/html/rfc8446)
- [RFC 5246 - The Transport Layer Security (TLS) Protocol Version 1.2](https://datatracker.ietf.org/doc/html/rfc5246)

## License

Educational use only.

## Contributors

- AkosKr
- BiroNorbi