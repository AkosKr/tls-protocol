# AES-128-GCM Authenticated Encryption for TLS 1.3

This document describes the AES-128-GCM AEAD (Authenticated Encryption with Associated Data) implementation for TLS 1.3.

## Overview

This implementation provides authenticated encryption and decryption for TLS 1.3 records using AES-128-GCM as specified in:
- **RFC 8446** (TLS 1.3): Section 5.2 (Record Payload Protection), Section 5.3 (Per-Record Nonce)
- **RFC 5116** (AEAD Interface)
- **RFC 5869** (HKDF for key derivation)

## Features

### Encryption Path
- ✅ Derives AES-128 key (16 bytes) and IV (12 bytes) from HKDF output
- ✅ Encrypts outgoing records using AEAD
- ✅ Authenticates plaintext and additional data (TLS record header)
- ✅ Generates 128-bit authentication tags
- ✅ Per-record nonce construction via XOR with sequence number

### Decryption Path
- ✅ Decrypts incoming encrypted records
- ✅ Verifies AEAD authentication tags
- ✅ Rejects records with invalid tags (prevents tampering)
- ✅ Secure handling of decryption failures

### Security Features
- ✅ Constant-time operations where possible (via `aes-gcm` crate)
- ✅ Proper error handling without timing leaks
- ✅ Secure key and nonce management
- ✅ Automatic zeroization of sensitive data (via `zeroize` crate)
- ✅ Sequence number overflow protection

## Architecture

### Module Structure

```
src/aead.rs          - AES-128-GCM AEAD implementation
src/key_schedule.rs  - HKDF-based key derivation (extended with derive_traffic_keys)
src/error.rs         - Error types (extended with AEAD errors)
tests/aead_tests.rs  - Comprehensive test suite
examples/aead_encryption.rs - Usage example
```

### Core Types

#### `TrafficKeys`
```rust
pub struct TrafficKeys {
    pub key: [u8; 16],  // AES-128 key
    pub iv: [u8; 12],   // Initialization vector
}
```

- Derived from handshake or application traffic secrets
- Implements `ZeroizeOnDrop` for secure memory clearing
- Created via `derive_traffic_keys(&traffic_secret)`

#### `AeadCipher`
```rust
pub struct AeadCipher {
    cipher: Aes128Gcm,
    iv: [u8; 12],
    sequence_number: u64,
}
```

- Manages encryption/decryption of TLS records
- Maintains per-connection sequence number
- Constructs unique nonces for each record

## Key Derivation

Traffic keys are derived from traffic secrets using HKDF-Expand-Label:

```text
write_key = HKDF-Expand-Label(Secret, "key", "", 16)
write_iv  = HKDF-Expand-Label(Secret, "iv", "", 12)
```

### Usage Example

```rust
use tls_protocol::{KeySchedule, derive_traffic_keys, AeadCipher};

// 1. Derive traffic secret from key schedule
let mut key_schedule = KeySchedule::new();
key_schedule.advance_to_handshake_secret(&shared_secret);
let client_secret = key_schedule.derive_client_handshake_traffic_secret(&transcript_hash);

// 2. Derive traffic keys
let client_keys = derive_traffic_keys(&client_secret);

// 3. Create cipher
let mut cipher = AeadCipher::new(client_keys);
```

## Nonce Construction (RFC 8446 Section 5.3)

Each record uses a unique nonce constructed as follows:

1. **Encode** the 64-bit sequence number in network byte order (big-endian)
2. **Pad** to the left with zeros to IV length (12 bytes)
3. **XOR** with the write IV

```rust
// Pseudo-code
let mut nonce = [0u8; 12];
nonce[4..12].copy_from_slice(&sequence_number.to_be_bytes());
for i in 0..12 {
    nonce[i] ^= iv[i];
}
```

**Critical**: Sequence numbers MUST never repeat for a given key. Maximum of 2^64-1 records per traffic secret.

## Record Encryption

### TLS 1.3 Record Format

```text
TLSInnerPlaintext = content || content_type || zeros[padding]
TLSCiphertext = AEAD-Encrypt(TLSInnerPlaintext)

Record Header (AAD):
  opaque_type (0x17) || legacy_version (0x0303) || length
```

### Encryption API

```rust
use tls_protocol::{encrypt_record, ContentType};

let plaintext = b"Application data";
let content_type = ContentType::ApplicationData as u8;
let aad = &[0x17, 0x03, 0x03, 0x00, 0x11]; // Record header

let ciphertext = encrypt_record(
    &mut cipher,
    plaintext,
    content_type,
    aad,
    0, // padding length
)?;

// ciphertext = encrypted(plaintext || content_type || padding) || auth_tag
```

### Decryption API

```rust
use tls_protocol::decrypt_record;

let (plaintext, content_type) = decrypt_record(
    &mut cipher,
    &ciphertext,
    aad,
)?;

// Automatically verifies authentication tag and strips padding
```

## Additional Authenticated Data (AAD)

The TLS record header serves as AAD:

```rust
let aad = [
    content_type,           // 0x17 (ApplicationData) for TLS 1.3
    version_major,          // 0x03
    version_minor,          // 0x03 (legacy TLS 1.2 version)
    (length >> 8) as u8,    // Length high byte
    (length & 0xff) as u8,  // Length low byte
];
```

The AAD is authenticated but not encrypted, ensuring the record header cannot be tampered with.

## Testing

### Test Coverage

The implementation includes comprehensive tests:

#### Known Answer Tests (KATs)
- ✅ NIST GCM test vectors
- ✅ Zero and non-zero keys/IVs
- ✅ Various plaintext sizes

#### Round-Trip Tests
- ✅ Empty payloads
- ✅ Single-byte payloads
- ✅ Various sizes (0, 1, 15, 16, 17, 255, 256, 1024, 4096, 8192, 16384 bytes)
- ✅ Maximum record size (16KB)

#### Negative Tests
- ✅ Wrong authentication tag (corruption detection)
- ✅ Wrong ciphertext (tampering detection)
- ✅ Wrong AAD (prevents header manipulation)
- ✅ Record too large (>16KB)

#### Edge Cases
- ✅ Empty payloads
- ✅ Single-byte payloads
- ✅ Padding stripping
- ✅ Content type extraction

#### Integration Tests
- ✅ Integration with HKDF key schedule
- ✅ Handshake traffic secrets
- ✅ Application traffic secrets
- ✅ Multiple record exchanges

#### Security Tests
- ✅ Sequence number progression
- ✅ Nonce uniqueness
- ✅ Different keys produce different ciphertexts
- ✅ Different IVs produce different ciphertexts
- ✅ `TrafficKeys` zeroization on drop

### Running Tests

```bash
# Run all tests
cargo test

# Run only AEAD tests
cargo test --test aead_tests

# Run specific test
cargo test test_encrypt_decrypt_roundtrip

# Run with output
cargo test -- --nocapture
```

## Examples

See `examples/aead_encryption.rs` for a complete working example:

```bash
cargo run --example aead_encryption
```

This demonstrates:
1. Key schedule initialization and progression
2. Handshake secret derivation
3. Traffic key derivation
4. Handshake message encryption/decryption
5. Master secret derivation
6. Application data encryption/decryption
7. Multiple record handling

## Security Considerations

### Implemented
- ✅ **Nonce Uniqueness**: Sequence numbers ensure unique nonce per record
- ✅ **Key Separation**: Client and server use different keys
- ✅ **Authentication**: 128-bit tags prevent tampering
- ✅ **Memory Safety**: Sensitive data zeroized on drop
- ✅ **Overflow Protection**: Sequence number overflow detection

### Limitations
- ⚠️ **Sequence Number Limit**: Max 2^64-1 records per key (RFC requires key update before overflow)
- ⚠️ **Timing Side Channels**: While the `aes-gcm` crate aims for constant-time operations, complete protection requires careful system-level considerations
- ⚠️ **Error Information**: Decryption failures return generic errors to avoid leaking information

### Best Practices

1. **Never reuse keys**: Each traffic secret should have its own cipher instance
2. **Separate send/receive**: Use different cipher instances for sending and receiving
3. **Check sequence numbers**: Monitor for overflow and trigger key update
4. **Validate AAD**: Always use the correct TLS record header as AAD
5. **Handle errors securely**: Don't leak timing information through error handling paths

## Integration Points

### With Key Schedule (Issue #13)
```rust
use tls_protocol::{KeySchedule, derive_traffic_keys};

let mut ks = KeySchedule::new();
ks.advance_to_handshake_secret(&shared_secret);
let secret = ks.derive_client_handshake_traffic_secret(&transcript);
let keys = derive_traffic_keys(&secret);
```

### With Record Layer (Issues #1, #2, #3)
```rust
use tls_protocol::{encrypt_record, decrypt_record, RecordHeader, ContentType};

// Construct AAD from record header
let header = RecordHeader::new(ContentType::ApplicationData, 0x0303, length);
let aad = header.to_bytes();

// Encrypt/decrypt
let ct = encrypt_record(&mut cipher, plaintext, content_type, &aad, 0)?;
let (pt, ct_type) = decrypt_record(&mut cipher, &ct, &aad)?;
```

## Performance Considerations

- **AES-NI**: The `aes-gcm` crate uses hardware acceleration when available
- **Allocation**: Encryption/decryption allocate new `Vec<u8>` for output
- **Nonce Computation**: XOR operation is fast (O(IV_SIZE))
- **Tag Verification**: Constant-time comparison in `aes-gcm` crate

## Dependencies

```toml
aes-gcm = "0.10.3"    # AES-128-GCM implementation
zeroize = "1.7"       # Secure memory zeroization
hkdf = "0.12.4"       # Key derivation
sha2 = "0.10.9"       # SHA-256 for transcript hashes
```

## References

- [RFC 8446 - TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446.html)
  - Section 5.2: Record Payload Protection
  - Section 5.3: Per-Record Nonce
  - Section 7.3: Traffic Key Calculation
- [RFC 5116 - AEAD Interface](https://www.rfc-editor.org/rfc/rfc5116.html)
- [RFC 5869 - HKDF](https://www.rfc-editor.org/rfc/rfc5869.html)
- [NIST SP 800-38D - GCM](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)

## Future Work

- [ ] Support for other AEAD ciphers (AES-256-GCM, ChaCha20-Poly1305)
- [ ] Key update mechanism (RFC 8446 Section 4.6.3)
- [ ] 0-RTT early data encryption
- [ ] Performance optimizations (buffer pooling, in-place operations)
- [ ] FIPS compliance verification
