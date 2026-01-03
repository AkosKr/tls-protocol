use tls_protocol::client_hello::*;

#[test]
fn test_create_client_hello_with_default_tls13() {
    let random = [0x42; 32];
    let public_key = vec![0xaa; 32];
    
    let hello = ClientHello::default_tls13(random, public_key.clone());
    
    // Verify structure
    assert_eq!(hello.random, random);
    assert_eq!(hello.legacy_session_id.len(), 0);
    assert_eq!(hello.cipher_suites.len(), 3);
    assert!(hello.cipher_suites.contains(&TLS_AES_128_GCM_SHA256));
    assert!(hello.cipher_suites.contains(&TLS_AES_256_GCM_SHA384));
    assert!(hello.cipher_suites.contains(&TLS_CHACHA20_POLY1305_SHA256));
    
    // Verify extensions
    assert_eq!(hello.extensions.len(), 2);
    
    // Check for supported versions extension
    let has_supported_versions = hello.extensions.iter().any(|ext| {
        matches!(ext, Extension::SupportedVersions(_))
    });
    assert!(has_supported_versions);
    
    // Check for key share extension
    let has_key_share = hello.extensions.iter().any(|ext| {
        matches!(ext, Extension::KeyShare(_))
    });
    assert!(has_key_share);
}

#[test]
fn test_client_hello_serialization_format() {
    let random = [0x11; 32];
    let public_key = vec![0xbb; 32];
    
    let hello = ClientHello::default_tls13(random, public_key);
    let bytes = hello.to_bytes();
    
    // Verify handshake message format
    assert_eq!(bytes[0], 0x01, "Handshake type should be ClientHello (0x01)");
    
    // Extract length (3 bytes)
    let length = ((bytes[1] as usize) << 16) | ((bytes[2] as usize) << 8) | (bytes[3] as usize);
    assert_eq!(length, bytes.len() - 4, "Length should match actual data length");
    
    // Verify legacy version (TLS 1.2 for compatibility)
    assert_eq!(bytes[4], 0x03, "Legacy version major should be 0x03");
    assert_eq!(bytes[5], 0x03, "Legacy version minor should be 0x03");
    
    // Verify random
    assert_eq!(&bytes[6..38], &random[..], "Random bytes should match");
    
    // Verify legacy session ID length
    assert_eq!(bytes[38], 0x00, "Legacy session ID should be empty");
}

#[test]
fn test_client_hello_with_session_id() {
    let random = [0x22; 32];
    let session_id = vec![0x01, 0x02, 0x03, 0x04];
    let cipher_suites = vec![TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384];
    let public_key = vec![0xcc; 32];
    
    let extensions = vec![
        Extension::SupportedVersions(vec![TLS_VERSION_1_3]),
        Extension::KeyShare(vec![KeyShareEntry {
            group: NAMED_GROUP_X25519,
            key_exchange: public_key,
        }]),
    ];
    
    let hello = ClientHello::new(random, session_id.clone(), cipher_suites, extensions);
    let bytes = hello.to_bytes();
    
    // Session ID length should be at byte 38
    assert_eq!(bytes[38], 0x04, "Session ID length should be 4");
    
    // Session ID should follow
    assert_eq!(&bytes[39..43], &session_id[..], "Session ID should match");
}

#[test]
fn test_supported_versions_extension_serialization() {
    let ext = Extension::SupportedVersions(vec![TLS_VERSION_1_3]);
    let bytes = ext.to_bytes();
    
    // Extension type: 43 (0x002b)
    assert_eq!(bytes[0], 0x00);
    assert_eq!(bytes[1], 0x2b);
    
    // Extension data length: 3 (1 byte for length + 2 bytes for version)
    assert_eq!(bytes[2], 0x00);
    assert_eq!(bytes[3], 0x03);
    
    // Supported versions length: 2 bytes
    assert_eq!(bytes[4], 0x02);
    
    // TLS 1.3 version: 0x0304
    assert_eq!(bytes[5], 0x03);
    assert_eq!(bytes[6], 0x04);
    
    assert_eq!(bytes.len(), 7);
}

#[test]
fn test_supported_versions_extension_multiple_versions() {
    let ext = Extension::SupportedVersions(vec![TLS_VERSION_1_3, TLS_VERSION_1_2]);
    let bytes = ext.to_bytes();
    
    // Extension type: 43
    assert_eq!(&bytes[0..2], &[0x00, 0x2b]);
    
    // Extension data length: 5 (1 byte for length + 4 bytes for two versions)
    assert_eq!(&bytes[2..4], &[0x00, 0x05]);
    
    // Supported versions length: 4 bytes (2 versions)
    assert_eq!(bytes[4], 0x04);
    
    // Versions
    assert_eq!(&bytes[5..7], &[0x03, 0x04]); // TLS 1.3
    assert_eq!(&bytes[7..9], &[0x03, 0x03]); // TLS 1.2
}

#[test]
fn test_key_share_extension_serialization() {
    let public_key = vec![0xdd; 32];
    let ext = Extension::KeyShare(vec![KeyShareEntry {
        group: NAMED_GROUP_X25519,
        key_exchange: public_key.clone(),
    }]);
    let bytes = ext.to_bytes();
    
    // Extension type: 51 (0x0033)
    assert_eq!(bytes[0], 0x00);
    assert_eq!(bytes[1], 0x33);
    
    // Extension data length: 38 (2 + 2 + 2 + 32)
    assert_eq!(bytes[2], 0x00);
    assert_eq!(bytes[3], 0x26);
    
    // Client key share length: 36 (2 + 2 + 32)
    assert_eq!(bytes[4], 0x00);
    assert_eq!(bytes[5], 0x24);
    
    // Named group: x25519 (0x001d)
    assert_eq!(bytes[6], 0x00);
    assert_eq!(bytes[7], 0x1d);
    
    // Key exchange length: 32
    assert_eq!(bytes[8], 0x00);
    assert_eq!(bytes[9], 0x20);
    
    // Key exchange data
    assert_eq!(&bytes[10..42], &public_key[..]);
    
    assert_eq!(bytes.len(), 42);
}

#[test]
fn test_key_share_extension_multiple_groups() {
    let key1 = vec![0xaa; 32];
    let key2 = vec![0xbb; 32];
    
    let ext = Extension::KeyShare(vec![
        KeyShareEntry {
            group: NAMED_GROUP_X25519,
            key_exchange: key1.clone(),
        },
        KeyShareEntry {
            group: NAMED_GROUP_SECP256R1,
            key_exchange: key2.clone(),
        },
    ]);
    let bytes = ext.to_bytes();
    
    // Extension type: 51
    assert_eq!(&bytes[0..2], &[0x00, 0x33]);
    
    // Extension data length: 74 (2 + 36 + 36)
    assert_eq!(&bytes[2..4], &[0x00, 0x4a]);
    
    // Client key share length: 72 (36 + 36)
    assert_eq!(&bytes[4..6], &[0x00, 0x48]);
    
    // First entry - x25519
    assert_eq!(&bytes[6..8], &[0x00, 0x1d]);
    assert_eq!(&bytes[8..10], &[0x00, 0x20]);
    assert_eq!(&bytes[10..42], &key1[..]);
    
    // Second entry - secp256r1
    assert_eq!(&bytes[42..44], &[0x00, 0x17]);
    assert_eq!(&bytes[44..46], &[0x00, 0x20]);
    assert_eq!(&bytes[46..78], &key2[..]);
}

#[test]
fn test_unknown_extension() {
    let data = vec![0x01, 0x02, 0x03, 0x04];
    let ext = Extension::Unknown {
        extension_type: 0x1234,
        data: data.clone(),
    };
    let bytes = ext.to_bytes();
    
    // Extension type: 0x1234
    assert_eq!(bytes[0], 0x12);
    assert_eq!(bytes[1], 0x34);
    
    // Extension data length: 4
    assert_eq!(bytes[2], 0x00);
    assert_eq!(bytes[3], 0x04);
    
    // Extension data
    assert_eq!(&bytes[4..8], &data[..]);
}

#[test]
fn test_client_hello_cipher_suites_serialization() {
    let random = [0x33; 32];
    let cipher_suites = vec![
        TLS_AES_128_GCM_SHA256,
        TLS_AES_256_GCM_SHA384,
        TLS_CHACHA20_POLY1305_SHA256,
    ];
    let public_key = vec![0xee; 32];
    
    let extensions = vec![
        Extension::SupportedVersions(vec![TLS_VERSION_1_3]),
        Extension::KeyShare(vec![KeyShareEntry {
            group: NAMED_GROUP_X25519,
            key_exchange: public_key,
        }]),
    ];
    
    let hello = ClientHello::new(random, vec![], cipher_suites.clone(), extensions);
    let bytes = hello.to_bytes();
    
    // Find cipher suites in the serialized data
    // After handshake type (1) + length (3) + legacy version (2) + random (32) + session ID length (1)
    let offset = 39;
    
    // Cipher suites length (2 bytes): 6 (3 suites * 2 bytes)
    assert_eq!(bytes[offset], 0x00);
    assert_eq!(bytes[offset + 1], 0x06);
    
    // Cipher suites
    assert_eq!(&bytes[offset + 2..offset + 4], &[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
    assert_eq!(&bytes[offset + 4..offset + 6], &[0x13, 0x02]); // TLS_AES_256_GCM_SHA384
    assert_eq!(&bytes[offset + 6..offset + 8], &[0x13, 0x03]); // TLS_CHACHA20_POLY1305_SHA256
}

#[test]
fn test_client_hello_compression_methods() {
    let random = [0x44; 32];
    let public_key = vec![0xff; 32];
    
    let hello = ClientHello::default_tls13(random, public_key);
    let bytes = hello.to_bytes();
    
    // Find compression methods after cipher suites
    // After handshake type (1) + length (3) + legacy version (2) + random (32) + 
    // session ID length (1) + session ID (0) + cipher suites length (2) + cipher suites (6)
    let offset = 47;
    
    // Compression methods length: 1
    assert_eq!(bytes[offset], 0x01);
    
    // Compression method: null (0x00)
    assert_eq!(bytes[offset + 1], 0x00);
}

#[test]
fn test_generate_random() {
    let random1 = ClientHello::generate_random();
    let random2 = ClientHello::generate_random();
    
    // Both should be 32 bytes
    assert_eq!(random1.len(), 32);
    assert_eq!(random2.len(), 32);
    
    // Should be deterministic (same output each time for testing)
    assert_eq!(random1, random2);
}

#[test]
fn test_client_hello_extensions_serialization() {
    let random = [0x55; 32];
    let public_key = vec![0x11; 32];
    
    let hello = ClientHello::default_tls13(random, public_key);
    let bytes = hello.to_bytes();
    
    // Extensions should be at the end, after compression methods
    // Let's find the extensions length field
    let offset = 49; // After compression methods
    
    // Extensions length (2 bytes)
    let ext_length = ((bytes[offset] as usize) << 8) | (bytes[offset + 1] as usize);
    
    // Verify extensions are present
    assert!(ext_length > 0, "Extensions should be present");
    
    // Total message length should match
    assert_eq!(bytes.len(), 4 + 2 + 32 + 1 + 0 + 2 + 6 + 1 + 1 + 2 + ext_length);
}

#[test]
fn test_key_share_entry_equality() {
    let key1 = vec![0x01; 32];
    let key2 = vec![0x01; 32];
    
    let entry1 = KeyShareEntry {
        group: NAMED_GROUP_X25519,
        key_exchange: key1,
    };
    
    let entry2 = KeyShareEntry {
        group: NAMED_GROUP_X25519,
        key_exchange: key2,
    };
    
    assert_eq!(entry1, entry2);
}

#[test]
fn test_extension_equality() {
    let ext1 = Extension::SupportedVersions(vec![TLS_VERSION_1_3]);
    let ext2 = Extension::SupportedVersions(vec![TLS_VERSION_1_3]);
    
    assert_eq!(ext1, ext2);
}

#[test]
fn test_client_hello_equality() {
    let random = [0x66; 32];
    let public_key = vec![0x22; 32];
    
    let hello1 = ClientHello::default_tls13(random, public_key.clone());
    let hello2 = ClientHello::default_tls13(random, public_key);
    
    assert_eq!(hello1, hello2);
}

#[test]
fn test_empty_cipher_suites() {
    let random = [0x77; 32];
    let extensions = vec![Extension::SupportedVersions(vec![TLS_VERSION_1_3])];
    
    let hello = ClientHello::new(random, vec![], vec![], extensions);
    let bytes = hello.to_bytes();
    
    // Should still be valid with 0 cipher suites
    assert_eq!(bytes[0], 0x01); // ClientHello type
    
    // Cipher suites length should be 0
    let offset = 39;
    assert_eq!(bytes[offset], 0x00);
    assert_eq!(bytes[offset + 1], 0x00);
}

#[test]
fn test_large_client_hello() {
    let random = [0x88; 32];
    let session_id = vec![0xaa; 32]; // Max session ID size
    let cipher_suites = vec![
        TLS_AES_128_GCM_SHA256,
        TLS_AES_256_GCM_SHA384,
        TLS_CHACHA20_POLY1305_SHA256,
    ];
    
    let public_key = vec![0x33; 32];
    let extensions = vec![
        Extension::SupportedVersions(vec![TLS_VERSION_1_3, TLS_VERSION_1_2]),
        Extension::KeyShare(vec![
            KeyShareEntry {
                group: NAMED_GROUP_X25519,
                key_exchange: public_key.clone(),
            },
            KeyShareEntry {
                group: NAMED_GROUP_SECP256R1,
                key_exchange: public_key,
            },
        ]),
        Extension::Unknown {
            extension_type: 0x0000,
            data: vec![0x00; 100],
        },
    ];
    
    let hello = ClientHello::new(random, session_id, cipher_suites, extensions);
    let bytes = hello.to_bytes();
    
    // Should successfully serialize large message
    assert!(bytes.len() > 200);
    assert_eq!(bytes[0], 0x01); // ClientHello type
}
