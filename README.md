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

### Issue #15: Transcript Hash Manager (SHA-256) ✅
**Goal**: Implement logic to maintain the running hash of all handshake messages (transcript hash), using SHA-256, as specified in RFC 8446 Section 4.4.1.

**Implementation**:
- **TranscriptHash Struct - SHA-256 Transcript Manager**:
  - Maintains running SHA-256 hash of all handshake messages
  - Used for key derivation, Finished messages, CertificateVerify, and session resumption
  - Thread-safe cloning for forking hash state at different handshake stages

- **Core Methods**:
  - `new()` - Initialize empty transcript hash
  - `update(&mut self, data: &[u8])` - Feed handshake message bytes incrementally
  - `current_hash(&self) -> [u8; 32]` - Get current hash value (non-consuming)
  - `finalize(self) -> [u8; 32]` - Get final hash value (consuming)
  - `clone(&self) -> Self` - Fork/snapshot current hash state for parallel derivations
  - `reset(&mut self)` - Clear and restart for session resumption scenarios

- **Convenience Methods**:
  - `update_client_hello(&mut self, &ClientHello)` - Add serialized ClientHello
  - `update_server_hello(&mut self, &ServerHello)` - Add serialized ServerHello
  - `empty_hash() -> [u8; 32]` - Static method for SHA-256 of empty input

- **Hash State Management**:
  - Non-consuming `current_hash()` allows continued updates after reading
  - `clone()` creates independent fork for different key derivation points
  - Multiple forks can branch from same transcript state
  - Reset functionality for session resumption and connection reuse

- **TLS 1.3 Integration Points**:
  - **Key Schedule** - Provides transcript hash input to HKDF for deriving traffic secrets
  - **Finished Message** - HMAC over transcript hash for handshake authentication
  - **CertificateVerify** - Server signs transcript hash to prove certificate possession
  - **Session Resumption** - PSK binder calculation uses transcript hash

**Usage in TLS 1.3 Handshake**:
```rust
use tls_protocol::{TranscriptHash, ClientHello, ServerHello, KeySchedule};

// Initialize transcript
let mut transcript = TranscriptHash::new();

// Update with ClientHello
let client_hello = ClientHello::default_tls13([0u8; 32], vec![0xaa; 32]);
transcript.update_client_hello(&client_hello);

// Update with ServerHello
let server_hello = ServerHello::new(/* ... */);
transcript.update_server_hello(&server_hello);

// Fork for handshake traffic secrets
let handshake_transcript = transcript.clone();
let handshake_hash = handshake_transcript.current_hash();

// Use with KeySchedule for handshake key derivation
let mut key_schedule = KeySchedule::new();
key_schedule.advance_to_handshake_secret(&shared_secret);
let client_hs_traffic = key_schedule
    .derive_client_handshake_traffic_secret(&handshake_hash);

// Continue with more messages for application traffic secrets
transcript.update(b"EncryptedExtensions");
transcript.update(b"Certificate");
transcript.update(b"CertificateVerify");
transcript.update(b"Finished");

let application_hash = transcript.current_hash();
key_schedule.advance_to_master_secret();
let client_app_traffic = key_schedule
    .derive_client_application_traffic_secret(&application_hash);
```

**Key Design Features**:
- **Incremental Hashing** - Updates processed immediately without internal buffering
- **Fork-Friendly** - Clone creates independent copy for branching derivations
- **Type-Safe** - 32-byte arrays for SHA-256 outputs, preventing size errors
- **Zero-Copy** - Non-consuming reads allow continued updates
- **Session Reuse** - Reset method enables connection/session resumption

**Testing** (Issue #15 requirements):
- Empty hash calculation and static empty_hash() method
- Single and multiple message updates
- Incremental vs one-shot hashing equivalence (must match)
- Hash forking/cloning for independent progressions
- Multiple forks from same state remain independent
- State management (current_hash non-consuming, finalize consuming, reset)
- Integration with ClientHello and ServerHello messages
- Full TLS 1.3 handshake sequence simulation
- Real-world message serialization tests
- RFC 8446 compliance verification
- Known SHA-256 test vectors

**Files**: [src/transcript_hash.rs](src/transcript_hash.rs), [tests/transcript_hash_tests.rs](tests/transcript_hash_tests.rs)

### Issue #16: Certificate Message Parser ✅
**Goal**: Develop a parser for the TLS Certificate handshake message (RFC 8446 Section 4.4.2) to extract and validate DER-encoded X.509 certificate chains with per-certificate extensions.

**Implementation**:
- **Certificate Message Structure**:
  - `CertificateEntry` struct containing:
    - `cert_data`: Vec<u8> - DER-encoded X.509 certificate (1 to 2^24-1 bytes)
    - `extensions`: Vec<Extension> - Per-certificate extensions
  - `Certificate` struct containing:
    - `certificate_request_context`: Vec<u8> - Context for client authentication (0 to 255 bytes, empty for server auth)
    - `certificate_list`: Vec<CertificateEntry> - Chain of certificates

- **Certificate Parsing** (`Certificate::from_bytes`):
  - Validates handshake type (0x0b for Certificate message)
  - Parses certificate_request_context with 1-byte length prefix
  - Extracts certificate_list with 3-byte length prefix
  - For each certificate entry:
    - Parses 3-byte certificate data length field
    - Extracts DER-encoded X.509 certificate data
    - Parses 2-byte extensions length field
    - Extracts per-certificate extensions
  - Integrates with existing Extension framework from Issue #9

- **Certificate Serialization** (`Certificate::to_bytes`):
  - Produces RFC 8446 compliant wire format:
    - Handshake type (1 byte): 0x0b
    - Message length (3 bytes)
    - Context length (1 byte) + context data
    - Certificate list length (3 bytes)
    - For each entry: cert_data length (3 bytes) + DER bytes + extensions

- **Validation Features**:
  - `Certificate::validate()` - Comprehensive validation
  - Ensures at least one certificate is present (for server authentication)
  - Validates certificate_request_context doesn't exceed 255 bytes
  - Enforces maximum chain length of 10 certificates
  - Validates each certificate entry (non-empty, size limits)
  - Early rejection of malformed messages

- **Utility Methods**:
  - `is_server_authentication()` - Checks if context is empty (server auth vs client auth)
  - `end_entity_certificate()` - Returns the first certificate (leaf/end-entity certificate)
  - `CertificateEntry::validate()` - Validates individual certificate entry

- **Security Considerations**:
  - `MAX_CERTIFICATE_CHAIN_LENGTH` constant set to 10 certificates
  - Strict length validation to prevent buffer overflows
  - No unbounded memory allocation
  - 3-byte length fields validated against available data
  - Early rejection prevents resource exhaustion

- **Error Handling**:
  - `EmptyCertificateList` - No certificates present (required for server auth)
  - `CertificateChainTooLong` - Exceeds maximum 10 certificates
  - `InvalidCertificateData` - Malformed DER, length mismatch, or structural errors
  - `InvalidHandshakeType` - Non-Certificate message (not 0x0b)
  - `IncompleteData` - Insufficient bytes for parsing

**Testing** (Issue #16 requirements):
- Valid certificate parsing with 1, 2, and 3+ certificate chains
- Empty certificate list rejection
- Invalid length fields (too short, mismatched, overflow)
- Certificate request context validation (empty for server auth)
- Maximum chain length enforcement (10 certificates)
- Zero-length certificate data rejection
- Roundtrip serialization (serialize → parse → compare)
- Real-world DER certificate structure patterns
- Handshake type validation (must be 0x0b)
- Extensions integration with certificate entries
- End-entity certificate extraction
- Length field calculations in wire format

**Files**: [src/certificate.rs](src/certificate.rs), [tests/certificate_tests.rs](tests/certificate_tests.rs), [src/error.rs](src/error.rs)

### Issue #13: HKDF-based Key Derivation Pipeline ✅
**Goal**: Implement complete TLS 1.3 key schedule using HKDF (RFC 5869) with SHA-256, following RFC 8446 Sections 7.1 and 7.2.

**Implementation**:
- **HKDF Core Functions (RFC 5869)**:
  - `hkdf_extract(salt, ikm)` - Extract phase producing pseudorandom key (PRK)
  - `hkdf_expand(prk, info, length)` - Expand phase generating output keying material (OKM)
  - `hkdf_expand_label()` - TLS 1.3-specific wrapper with "tls13 " prefix
  - `derive_secret()` - Combines HKDF-Expand-Label with transcript hash

- **KeySchedule Struct - Complete TLS 1.3 Key Schedule**:
  - Manages progression through three stages: Early → Handshake → Master
  - `new()` - Initialize with Early Secret (no PSK case)
  - `with_psk(psk)` - Initialize with pre-shared key
  - `advance_to_handshake_secret(shared_secret)` - Progress using ECDHE output
  - `advance_to_master_secret()` - Final stage transition
  
- **Traffic Secret Derivation**:
  - `derive_client_handshake_traffic_secret(transcript)` - Client handshake encryption keys
  - `derive_server_handshake_traffic_secret(transcript)` - Server handshake encryption keys
  - `derive_client_application_traffic_secret(transcript)` - Client application data keys
  - `derive_server_application_traffic_secret(transcript)` - Server application data keys
  - `derive_exporter_master_secret(transcript)` - For key exporters
  - `derive_resumption_master_secret(transcript)` - For session resumption

- **Key Schedule Flow**:
  ```text
  PSK/0 → Early Secret
           ↓
  (EC)DHE → Handshake Secret → {client_hs_traffic, server_hs_traffic}
           ↓
  0 → Master Secret → {client_ap_traffic, server_ap_traffic, 
                      exporter_master, resumption_master}
  ```

- **Input Requirements**:
  - Shared secret from X25519 ECDHE (32 bytes)
  - Transcript hashes at various stages (SHA-256, 32 bytes)
  - Optional PSK for 0-RTT scenarios

- **Output Secrets**:
  - All secrets are 32 bytes (SHA-256 hash length)
  - Handshake traffic secrets protect handshake messages
  - Application traffic secrets protect application data
  - Master secrets support session resumption and key export

**Testing** (Issue #13 requirements):
- RFC 5869 test vectors for HKDF-Extract and HKDF-Expand (Test Cases 1 & 2)
- Edge cases: zero-length salt, empty info, various input lengths
- Complete key schedule progression (Early → Handshake → Master)
- Different shared secrets produce different keys
- Different transcripts produce different traffic secrets
- Stage enforcement (cannot skip stages or go backwards)
- Deterministic output verification
- Integration with X25519 key exchange output

**Files**: [src/key_schedule.rs](src/key_schedule.rs), [tests/key_schedule_tests.rs](tests/key_schedule_tests.rs)

## Project Structure

```
tls-protocol/
├── src/
│   ├── lib.rs              # Core types and exports
│   ├── error.rs            # Error types with extension and certificate error variants
│   ├── parser.rs           # Header parsing logic
│   ├── decoder.rs          # Header decoding
│   ├── tls_stream.rs       # TCP stream wrapper
│   ├── extensions.rs       # TLS extensions framework
│   ├── client_hello.rs     # ClientHello message implementation
│   ├── server_hello.rs     # ServerHello message parser
│   ├── certificate.rs      # Certificate message parser
│   ├── x25519_key_exchange.rs # X25519 key exchange implementation
│   ├── transcript_hash.rs  # Transcript hash manager (SHA-256)
│   ├── key_schedule.rs     # HKDF-based key derivation pipeline
│   └── aead.rs             # AEAD encryption/decryption
├── tests/
│   ├── parser_tests.rs     # Parser validation tests
│   ├── decoder_tests.rs    # Decoder tests
│   ├── tls_stream_tests.rs # Stream tests
│   ├── client_hello_tests.rs # ClientHello tests
│   ├── server_hello_tests.rs # ServerHello parser tests
│   ├── certificate_tests.rs # Certificate parser tests
│   ├── extension_tests.rs  # Extension framework tests
│   ├── x25519_key_exchange_tests.rs # X25519 key exchange tests
│   ├── transcript_hash_tests.rs # Transcript hash tests
│   ├── key_schedule_tests.rs # HKDF and key schedule tests
│   └── aead_tests.rs       # AEAD encryption tests
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

### Transcript Hash Management

```rust
use tls_protocol::{TranscriptHash, ClientHello, ServerHello};
use tls_protocol::extensions::{Extension, KeyShareEntry, TLS_VERSION_1_3, NAMED_GROUP_X25519};

// Create a new transcript hash
let mut transcript = TranscriptHash::new();

// Update with ClientHello
let client_hello = ClientHello::default_tls13([0u8; 32], vec![0xaa; 32]);
transcript.update_client_hello(&client_hello);

// Update with ServerHello
let server_hello = ServerHello::new(
    [0x88u8; 32],
    vec![],
    0x1301,
    vec![
        Extension::SupportedVersions(vec![TLS_VERSION_1_3]),
        Extension::KeyShare(vec![KeyShareEntry::new(NAMED_GROUP_X25519, vec![0xbb; 32])]),
    ],
);
transcript.update_server_hello(&server_hello);

// Get current hash value (non-consuming)
let hash_after_server_hello = transcript.current_hash();

// Fork the transcript for different key derivations
let handshake_transcript = transcript.clone();
let handshake_hash = handshake_transcript.current_hash();

// Continue with more messages
transcript.update(b"EncryptedExtensions");
transcript.update(b"Certificate");
transcript.update(b"Finished");

// Get final hash
let final_hash = transcript.current_hash();
```

### TLS 1.3 Key Schedule with HKDF

```rust
use tls_protocol::{KeySchedule, TranscriptHash, ClientHello, ServerHello};

// Step 1: Initialize key schedule (Early Secret stage)
let mut key_schedule = KeySchedule::new();

// Step 2: Build transcript hash with handshake messages
let mut transcript = TranscriptHash::new();
let client_hello = ClientHello::default_tls13([0u8; 32], vec![0xaa; 32]);
transcript.update_client_hello(&client_hello);

let server_hello = ServerHello::new(/* ... */);
transcript.update_server_hello(&server_hello);

// Step 3: After ECDHE, advance to Handshake Secret
// shared_secret comes from X25519KeyPair::compute_shared_secret()
let shared_secret = [0xAAu8; 32]; // 32-byte output from X25519
key_schedule.advance_to_handshake_secret(&shared_secret);

// Step 4: Derive handshake traffic secrets for encryption
// Transcript hash includes ClientHello...ServerHello
let transcript_hash = transcript.current_hash();

let client_hs_traffic = key_schedule
    .derive_client_handshake_traffic_secret(&transcript_hash);
let server_hs_traffic = key_schedule
    .derive_server_handshake_traffic_secret(&transcript_hash);

// Use these secrets to derive handshake encryption keys...

// Step 5: After handshake completes, advance to Master Secret
key_schedule.advance_to_master_secret();

// Step 6: Continue updating transcript with more messages
transcript.update(b"EncryptedExtensions");
transcript.update(b"Certificate");
transcript.update(b"CertificateVerify");
transcript.update(b"Finished");

// Step 7: Derive application traffic secrets for protected data
let app_transcript_hash = transcript.current_hash();

let client_app_traffic = key_schedule
    .derive_client_application_traffic_secret(&app_transcript_hash);
let server_app_traffic = key_schedule
    .derive_server_application_traffic_secret(&app_transcript_hash);

// Optional: Derive other master secrets
let exporter_master = key_schedule
    .derive_exporter_master_secret(&app_transcript_hash);
let resumption_master = key_schedule
    .derive_resumption_master_secret(&app_transcript_hash);
```

### Complete TLS 1.3 Handshake Flow

```rust
use tls_protocol::{ClientHello, ServerHello, KeySchedule, X25519KeyPair};
use tls_protocol::extensions::{Extension, KeyShareEntry, TLS_VERSION_1_3, NAMED_GROUP_X25519};
use sha2::{Digest, Sha256};

// Client Side
// -----------

// 1. Generate X25519 keypair
let client_keypair = X25519KeyPair::generate();

// 2. Create ClientHello with key share
let random = rand::random();
let client_hello = ClientHello::default_tls13(
    random,
    client_keypair.public_key_bytes().to_vec()
);

// Send ClientHello and start transcript hash
let mut transcript = Sha256::new();
transcript.update(&client_hello.to_bytes());

// Server Side
// -----------

// 3. Receive ClientHello, generate server keypair
let server_keypair = X25519KeyPair::generate();

// 4. Extract client's public key from ClientHello extensions
// (parse from received client_hello)
let client_public_key = [0xBBu8; 32]; // extracted from ClientHello

// 5. Compute ECDHE shared secret
let shared_secret = server_keypair
    .compute_shared_secret(&client_public_key)
    .expect("Key exchange failed");

// 6. Create ServerHello with server key share
let server_random = rand::random();
let server_hello = ServerHello::new(
    server_random,
    vec![],
    0x1301, // TLS_AES_128_GCM_SHA256
    vec![
        Extension::SupportedVersions(vec![TLS_VERSION_1_3]),
        Extension::KeyShare(vec![server_keypair.to_key_share_entry()]),
    ]
);

// Send ServerHello and update transcript
transcript.update(&server_hello.to_bytes());

// Clone the transcript before finalizing so we can keep updating the original.
let handshake_transcript = transcript.clone().finalize();

// 7. Initialize key schedule and derive handshake keys
let mut key_schedule = KeySchedule::new();
key_schedule.advance_to_handshake_secret(&shared_secret);

let server_hs_traffic = key_schedule
    .derive_server_handshake_traffic_secret(&handshake_transcript);
let client_hs_traffic = key_schedule
    .derive_client_handshake_traffic_secret(&handshake_transcript);

// Use handshake traffic secrets for encrypting remaining handshake...

// 8. After handshake finishes, derive application keys
transcript.update(b"EncryptedExtensions");
transcript.update(b"Certificate");
transcript.update(b"CertificateVerify");
transcript.update(b"ServerFinished");
let app_transcript = transcript.finalize();

key_schedule.advance_to_master_secret();
let server_app_traffic = key_schedule
    .derive_server_application_traffic_secret(&app_transcript);
let client_app_traffic = key_schedule
    .derive_client_application_traffic_secret(&app_transcript);

// Now ready to encrypt/decrypt application data!
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

### Parsing Certificate Messages

```rust
use tls_protocol::certificate::{Certificate, CertificateEntry};
use tls_protocol::extensions::Extension;

// Parse a Certificate message from received bytes
let certificate_bytes = received_data; // From network
let certificate = Certificate::from_bytes(&certificate_bytes)
    .expect("Failed to parse Certificate");

// Check if it's server authentication (empty context)
if certificate.is_server_authentication() {
    println!("Server authentication certificate chain");
}

// Get the end-entity (leaf) certificate
if let Some(end_entity) = certificate.end_entity_certificate() {
    println!("Server certificate: {} bytes", end_entity.cert_data.len());
    
    // Access the DER-encoded X.509 certificate data
    let der_cert = &end_entity.cert_data;
    
    // Process certificate extensions (if any)
    for ext in &end_entity.extensions {
        println!("Certificate extension: {:?}", ext);
    }
}

// Iterate through the certificate chain
println!("Certificate chain length: {}", certificate.certificate_list.len());
for (i, entry) in certificate.certificate_list.iter().enumerate() {
    println!("Certificate {}: {} bytes", i, entry.cert_data.len());
}

// Create a Certificate message (for testing/server implementation)
// Example: Server sending its certificate chain
let server_cert_der = vec![0x30, 0x82, 0x03, 0x50]; // DER-encoded certificate
// ... (full DER certificate data)

let intermediate_cert_der = vec![0x30, 0x82, 0x02, 0x00]; // DER-encoded intermediate
// ... (full DER certificate data)

let cert_entry1 = CertificateEntry::new(server_cert_der, vec![]);
let cert_entry2 = CertificateEntry::new(intermediate_cert_der, vec![]);

let certificate = Certificate::new(
    vec![], // Empty context for server authentication
    vec![cert_entry1, cert_entry2],
);

// Validate the certificate message
certificate.validate().expect("Invalid certificate");

// Serialize to bytes for sending
let bytes = certificate.to_bytes();

// The bytes can now be wrapped in a TLS record and sent over the network
```

### Complete TLS 1.3 Handshake with Certificate

```rust
use tls_protocol::{ClientHello, ServerHello, Certificate, CertificateEntry};
use tls_protocol::{TranscriptHash, KeySchedule};

// ... After ClientHello and ServerHello exchange ...

// Server sends Certificate message
let mut transcript = TranscriptHash::new();
transcript.update_client_hello(&client_hello);
transcript.update_server_hello(&server_hello);

// Parse encrypted extensions (would be encrypted in real TLS)
transcript.update(b"EncryptedExtensions");

// Parse Certificate message
let certificate_bytes = receive_handshake_message(); // From network
let certificate = Certificate::from_bytes(&certificate_bytes)
    .expect("Failed to parse Certificate");

// Update transcript with Certificate message
transcript.update(&certificate_bytes);

// Verify it's server authentication
assert!(certificate.is_server_authentication());

// Extract end-entity certificate for verification
let end_entity = certificate.end_entity_certificate()
    .expect("No certificates in chain");

// Verify the certificate chain
// (X.509 verification would happen here using end_entity.cert_data)

// Continue with CertificateVerify and Finished messages...
transcript.update(b"CertificateVerify");
transcript.update(b"Finished");

let handshake_hash = transcript.current_hash();
// Use handshake_hash for key derivation...
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
cargo test --test server_hello_tests
cargo test --test certificate_tests
cargo test --test extension_tests
cargo test --test x25519_key_exchange_tests
cargo test --test transcript_hash_tests
cargo test --test key_schedule_tests
cargo test --test aead_tests
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
- [RFC 5280 - Internet X.509 Public Key Infrastructure Certificate and CRL Profile](https://datatracker.ietf.org/doc/html/rfc5280)
- [RFC 5869 - HMAC-based Extract-and-Expand Key Derivation Function (HKDF)](https://datatracker.ietf.org/doc/html/rfc5869)

## License

Educational use only.

## Contributors

- AkosKr
- BiroNorbi