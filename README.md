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
  - `extensions`: Vec<Extension> - TLS extensions from the extensions framework
  
- **TLS Extensions Framework** (`extensions.rs`):
  - `Extension` enum supporting:
    - `ServerName` - Server Name Indication (SNI, extension type 0)
    - `SignatureAlgorithms` - Supported signature algorithms (extension type 13)
    - `SupportedVersions` - Mandatory for TLS 1.3 (extension type 43)
    - `KeyShare` - Mandatory for TLS 1.3 (extension type 51)
    - `Unknown` - For extensibility
  
  - `KeyShareEntry` struct for key exchange with:
    - `group`: u16 - Named group (e.g., x25519, secp256r1)
    - `key_exchange`: Vec<u8> - Public key data
  
  - Extension validation helpers:
    - `validate_tls13_extensions()` - Ensures mandatory extensions are present
    - `check_duplicate_extensions()` - Detects duplicate extensions
    - `Extension::parse_extensions()` - Parse multiple extensions from bytes
    - `Extension::serialize_extensions()` - Serialize multiple extensions
  
  - Extension serialization and deserialization:
    - `Extension::to_bytes()` - Serialize single extension
    - `Extension::from_bytes()` - Deserialize single extension from bytes
  
- TLS 1.3 cipher suite constants:
  - `TLS_AES_128_GCM_SHA256` (0x1301)
  - `TLS_AES_256_GCM_SHA384` (0x1302)
  - `TLS_CHACHA20_POLY1305_SHA256` (0x1303)
  
- Named group constants (in `extensions.rs`):
  - `NAMED_GROUP_X25519` (0x001d)
  - `NAMED_GROUP_SECP256R1` (0x0017)
  - `NAMED_GROUP_SECP384R1` (0x0018)
  - `NAMED_GROUP_SECP521R1` (0x0019)
  
- Signature scheme constants (in `extensions.rs`):
  - RSA PKCS1: SHA256, SHA384, SHA512
  - ECDSA: secp256r1, secp384r1, secp521r1
  - RSA-PSS: SHA256, SHA384, SHA512
  - EdDSA: Ed25519, Ed448
  
- Serialization methods:
  - `ClientHello::to_bytes()` - Full handshake message serialization
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

**Files**: [src/client_hello.rs](src/client_hello.rs), [src/extensions.rs](src/extensions.rs), [tests/client_hello_tests.rs](tests/client_hello_tests.rs)

### Issue #9: TLS Framework Extension ✅
**Goal**: Create a comprehensive TLS extensions framework supporting serialization, deserialization, and validation.

**Implementation**:
- Complete `Extension` enum with full TLS 1.3 extension support
- Bidirectional serialization (to/from bytes)
- Extension validation for TLS 1.3 compliance
- Server Name Indication (SNI) support
- Signature algorithms extension
- Comprehensive error handling for malformed extensions

**Files**: [src/extensions.rs](src/extensions.rs), [src/error.rs](src/error.rs)

### Issue #11: ServerHello Message Parser ✅
**Goal**: Build a strict parser for the ServerHello message as defined in RFC 8446 (section 4.1.3).

**Implementation**:
- `ServerHello` struct with fields:
  - `random`: [u8; 32] - 32 bytes of cryptographic random data
  - `legacy_session_id_echo`: Vec<u8> - Echo of the legacy session ID from ClientHello
  - `cipher_suite`: u16 - The single selected cipher suite
  - `extensions`: Vec<Extension> - TLS extensions (reuses existing framework)

- `DowngradeProtection` enum for downgrade detection:
  - `Tls12Downgrade` - TLS 1.2 downgrade detected
  - `Tls11Downgrade` - TLS 1.1 or earlier downgrade detected

- Downgrade protection constants (RFC 8446, Appendix D.4):
  - `TLS_1_2_DOWNGRADE_SENTINEL` - Special value in random field for TLS 1.2 downgrade
  - `TLS_1_1_DOWNGRADE_SENTINEL` - Special value in random field for TLS 1.1 downgrade

- Parser functionality:
  - `ServerHello::from_bytes(data: &[u8]) -> Result<ServerHello, TlsError>` - Parse from wire format
  - Validates handshake type (0x02 for ServerHello)
  - Validates legacy_version (expects 0x0303 for TLS 1.2 compatibility)
  - Extracts and validates random field (32 bytes)
  - Parses legacy_session_id_echo (max 32 bytes)
  - Validates selected cipher suite (only TLS 1.3 suites)
  - Validates compression method (must be 0x00)
  - Integrates with extension framework for extensibility

- Validation features:
  - `ServerHello::validate()` - Comprehensive validation
  - Checks for mandatory extensions (supported_versions)
  - Verifies supported_versions contains TLS 1.3
  - Detects duplicate extensions
  - Validates cipher suite is TLS 1.3 compatible

- Downgrade protection:
  - `ServerHello::check_downgrade_protection() -> Option<DowngradeProtection>` - Detects downgrade attempts
  - Checks last 8 bytes of random field for sentinel values
  - Implements RFC 8446 Appendix D.4 security measures

- Serialization:
  - `ServerHello::to_bytes()` - Serialize to wire format
  - Full RFC 8446 compliant format

- Error handling:
  - `InvalidHandshakeType` - Non-ServerHello message
  - `InvalidVersion` - Incorrect legacy_version
  - `InvalidCipherSuite` - Unsupported cipher suite
  - `InvalidCompressionMethod` - Invalid compression method value
  - `InvalidRandom` - Reserved for future use (malformed random field handling)
  - `DowngradeDetected` - Reserved for future use (downgrade as error instead of returned value)
  - Clear error types for all validation and parsing failures
  - Note: Downgrade protection currently returns `Option<DowngradeProtection>` rather than an error

**Testing**:
- Valid ServerHello parsing and serialization
- Malformed message handling (incomplete data, invalid fields)
- Downgrade protection detection (TLS 1.2 and TLS 1.1)
- Missing mandatory extensions
- Invalid cipher suites
- Duplicate extension detection
- Session ID echo validation
- Roundtrip serialization tests
- Real-world-like ServerHello scenarios

**Files**: [src/server_hello.rs](src/server_hello.rs), [tests/server_hello_tests.rs](tests/server_hello_tests.rs), [src/error.rs](src/error.rs)

### Issue #12: X25519 Key Exchange Implementation ✅
**Goal**: Implement ephemeral ECDHE using X25519 for secure key exchange in TLS 1.3.

**Implementation**:
- **X25519 Key Pair Generation**:
  - `X25519KeyPair` struct containing private and public keys
  - `generate()` - Generates ephemeral X25519 keypairs using cryptographically secure randomness
  - Keys are exactly 32 bytes (per RFC 8446, Section 4.2.8.2)
  - Each connection uses a fresh keypair for forward secrecy

- **Key Exchange Operations**:
  - `compute_shared_secret()` - Performs ECDH scalar multiplication
  - Returns 32-byte shared secret suitable for HKDF in TLS 1.3 key schedule
  - Supports both method and standalone function interfaces
  - Constant-time implementation via x25519-dalek for side-channel resistance

- **Server Key Share Parsing & Validation**:
  - `parse_key_share_entry()` - Extracts and validates X25519 public keys from KeyShareEntry
  - Validates named group matches X25519 (0x001d)
  - Ensures key exchange data is exactly 32 bytes
  - Rejects weak or invalid public keys

- **Key Validation** (RFC 8446 compliance):
  - Strict 32-byte key length enforcement
  - Rejects all-zero public keys (weak/invalid keys)
  - Rejects non-canonical values and malformed keys
  - Comprehensive error handling for all validation failures

- **Integration with TLS Extensions**:
  - `to_key_share_entry()` - Creates KeyShareEntry from X25519KeyPair
  - Seamless integration with existing Extension framework
  - Compatible with ClientHello and ServerHello messages
  - Works with extension serialization/deserialization

- **Error Handling**:
  - `InvalidKeyLength` - Wrong key size (not 32 bytes)
  - `InvalidPublicKey` - Weak, malformed, or non-canonical keys
  - `KeyExchangeFailed` - Group mismatch or other exchange errors

- **Security Features**:
  - Ephemeral keys provide forward secrecy
  - Constant-time operations prevent timing attacks
  - Proper validation prevents weak key attacks
  - Shared secrets ready for HKDF (RFC 8446, Section 7.1)

**Testing** (Issue #12 requirements):
- Key pair generation and randomness verification
- Shared secret agreement between parties
- Invalid key length rejection (shorter, longer, empty, very long)
- Non-canonical value rejection (all-zero, weak keys)
- KeyShareEntry parsing and validation
- Wrong named group rejection
- Full TLS 1.3 handshake flow simulation
- HKDF suitability verification
- Serialization round-trip with extension framework

**Files**: [src/x25519_key_exchange.rs](src/x25519_key_exchange.rs), [tests/x25519_key_exchange_tests.rs](tests/x25519_key_exchange_tests.rs), [src/error.rs](src/error.rs)

## Project Structure

```
tls-protocol/
├── src/
│   ├── lib.rs              # Core types and exports
│   ├── error.rs            # Error types with extension error variants
│   ├── parser.rs           # Header parsing logic
│   ├── decoder.rs          # Header decoding
│   ├── tls_stream.rs       # TCP stream wrapper
│   ├── extensions.rs       # TLS extensions framework
│   ├── client_hello.rs     # ClientHello message implementation
│   ├── server_hello.rs     # ServerHello message parser
│   └── x25519_key_exchange.rs # X25519 key exchange implementation
├── tests/
│   ├── parser_tests.rs     # Parser validation tests
│   ├── decoder_tests.rs    # Decoder tests
│   ├── tls_stream_tests.rs # Stream tests
│   ├── client_hello_tests.rs # ClientHello tests
│   ├── server_hello_tests.rs # ServerHello parser tests
│   └── x25519_key_exchange_tests.rs # X25519 key exchange tests
├── examples/
│   ├── client.rs           # Example TLS client
│   └── server.rs           # Example TLS server
└── Cargo.toml

```

## Usage

### Basic Example: Creating a ClientHello

```rust
use tls_protocol::ClientHello;
use tls_protocol::extensions::{Extension, KeyShareEntry, TLS_VERSION_1_3, NAMED_GROUP_X25519};

// Generate random bytes (32 bytes required)
let random = [0u8; 32]; // In production, use cryptographically secure random

// Generate or provide x25519 public key (32 bytes)
let public_key = vec![0xaa; 32];

// Create a default TLS 1.3 ClientHello with mandatory extensions
let client_hello = ClientHello::default_tls13(random, public_key);

// Serialize to bytes for sending over the wire
let bytes = client_hello.to_bytes();
```

### Working with Extensions

```rust
use tls_protocol::extensions::{Extension, KeyShareEntry, NAMED_GROUP_X25519, TLS_VERSION_1_3};
use tls_protocol::extensions::{validate_tls13_extensions, check_duplicate_extensions};

// Create extensions
let extensions = vec![
    Extension::ServerName("example.com".to_string()),
    Extension::SupportedVersions(vec![TLS_VERSION_1_3]),
    Extension::KeyShare(vec![KeyShareEntry::new(NAMED_GROUP_X25519, vec![0xaa; 32])]),
];

// Validate TLS 1.3 mandatory extensions
validate_tls13_extensions(&extensions).expect("Missing mandatory extensions");

// Check for duplicates
check_duplicate_extensions(&extensions).expect("Duplicate extension found");

// Serialize extensions
let bytes = Extension::serialize_extensions(&extensions);

// Parse extensions from bytes
let parsed = Extension::parse_extensions(&bytes).expect("Failed to parse extensions");
```

### X25519 Key Exchange

```rust
use tls_protocol::x25519_key_exchange::X25519KeyPair;
use tls_protocol::extensions::{Extension, NAMED_GROUP_X25519};

// Generate ephemeral X25519 keypair for client
let client_keypair = X25519KeyPair::generate();

// Create KeyShareEntry for ClientHello
let client_key_share = client_keypair.to_key_share_entry();
let key_share_extension = Extension::KeyShare(vec![client_key_share]);

// ... send ClientHello with key_share_extension ...

// After receiving ServerHello with server's KeyShareEntry
use tls_protocol::x25519_key_exchange::parse_key_share_entry;

// Extract server's public key from KeyShareEntry
// let server_key_share = ...; // from ServerHello extensions
// let server_public_key = parse_key_share_entry(&server_key_share)
//     .expect("Invalid server key share");

// Compute shared secret (for key schedule)
// let shared_secret = client_keypair
//     .compute_shared_secret(&server_public_key)
//     .expect("Key exchange failed");

// The shared_secret is 32 bytes and ready for HKDF in TLS 1.3 key schedule
```

### Complete Key Exchange Example

```rust
use tls_protocol::x25519_key_exchange::{X25519KeyPair, parse_key_share_entry};
use tls_protocol::extensions::NAMED_GROUP_X25519;

// Client side: Generate keypair and create ClientHello
let client_keypair = X25519KeyPair::generate();
let client_key_share = client_keypair.to_key_share_entry();
// ... include client_key_share in ClientHello ...

// Server side: Receive ClientHello and generate server keypair
let client_public_key = parse_key_share_entry(&client_key_share)
    .expect("Invalid client key share");

let server_keypair = X25519KeyPair::generate();
let server_key_share = server_keypair.to_key_share_entry();

// Server computes shared secret
let server_shared = server_keypair
    .compute_shared_secret(&client_public_key)
    .expect("Server key exchange failed");

// ... send ServerHello with server_key_share ...

// Client side: Receive ServerHello and compute shared secret
let server_public_key = parse_key_share_entry(&server_key_share)
    .expect("Invalid server key share");

let client_shared = client_keypair
    .compute_shared_secret(&server_public_key)
    .expect("Client key exchange failed");

// Both parties now have the same shared secret
assert_eq!(client_shared, server_shared);
// Use shared_secret for HKDF in key schedule (RFC 8446, Section 7.1)
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

### Parsing ServerHello Messages

```rust
use tls_protocol::ServerHello;
use tls_protocol::server_hello::DowngradeProtection;

// Parse a ServerHello from received bytes
let server_hello_bytes = received_data; // From network
let server_hello = ServerHello::from_bytes(&server_hello_bytes)
    .expect("Failed to parse ServerHello");

// Check the selected cipher suite
println!("Selected cipher suite: 0x{:04x}", server_hello.cipher_suite);

// Check for downgrade protection
match server_hello.check_downgrade_protection() {
    Some(DowngradeProtection::Tls12Downgrade) => {
        println!("Warning: TLS 1.2 downgrade detected!");
    }
    Some(DowngradeProtection::Tls11Downgrade) => {
        println!("Warning: TLS 1.1 or earlier downgrade detected!");
    }
    None => {
        println!("No downgrade detected - secure TLS 1.3 connection");
    }
}

// Access extensions
for extension in &server_hello.extensions {
    println!("Extension: {:?}", extension);
}

// Create a ServerHello (for testing/server implementation)
use tls_protocol::extensions::{Extension, KeyShareEntry, TLS_VERSION_1_3, NAMED_GROUP_X25519};
use tls_protocol::server_hello::TLS_AES_128_GCM_SHA256;

let random = [0xaa; 32];
let session_id_echo = vec![];
let extensions = vec![
    Extension::SupportedVersions(vec![TLS_VERSION_1_3]),
    Extension::KeyShare(vec![KeyShareEntry::new(NAMED_GROUP_X25519, vec![0xbb; 32])]),
];

let server_hello = ServerHello::new(
    random,
    session_id_echo,
    TLS_AES_128_GCM_SHA256,
    extensions,
);

let bytes = server_hello.to_bytes();
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
- `x25519-dalek = "2.0"` - Constant-time X25519 elliptic curve Diffie-Hellman implementation

## References

- [RFC 8446 - The Transport Layer Security (TLS) Protocol Version 1.3](https://datatracker.ietf.org/doc/html/rfc8446)
- [RFC 5246 - The Transport Layer Security (TLS) Protocol Version 1.2](https://datatracker.ietf.org/doc/html/rfc5246)

## License

Educational use only.

## Contributors

- AkosKr
- BiroNorbi