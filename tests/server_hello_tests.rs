use tls_protocol::error::TlsError;
use tls_protocol::server_hello::{
    ServerHello, DowngradeProtection, TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384,
    TLS_CHACHA20_POLY1305_SHA256, TLS_1_2_DOWNGRADE_SENTINEL, TLS_1_1_DOWNGRADE_SENTINEL,
};
use tls_protocol::extensions::{Extension, KeyShareEntry, TLS_VERSION_1_3, NAMED_GROUP_X25519};

#[test]
fn test_valid_server_hello_parsing() {
    // Create a valid ServerHello
    let random = [0xaa; 32];
    let session_id = vec![];
    let cipher_suite = TLS_AES_128_GCM_SHA256;
    let extensions = vec![
        Extension::SupportedVersions(vec![TLS_VERSION_1_3]),
        Extension::KeyShare(vec![KeyShareEntry::new(NAMED_GROUP_X25519, vec![0xbb; 32])]),
    ];
    
    let server_hello = ServerHello::new(random, session_id.clone(), cipher_suite, extensions);
    let bytes = server_hello.to_bytes();
    
    // Parse it back
    let parsed = ServerHello::from_bytes(&bytes).unwrap();
    
    assert_eq!(parsed.random, random);
    assert_eq!(parsed.legacy_session_id_echo, session_id);
    assert_eq!(parsed.cipher_suite, cipher_suite);
    assert_eq!(parsed.extensions.len(), 2);
}

#[test]
fn test_server_hello_with_session_id() {
    let random = [0x11; 32];
    let session_id = vec![0x22; 16];
    let cipher_suite = TLS_AES_256_GCM_SHA384;
    let extensions = vec![
        Extension::SupportedVersions(vec![TLS_VERSION_1_3]),
    ];
    
    let server_hello = ServerHello::new(random, session_id.clone(), cipher_suite, extensions);
    let bytes = server_hello.to_bytes();
    
    let parsed = ServerHello::from_bytes(&bytes).unwrap();
    
    assert_eq!(parsed.legacy_session_id_echo, session_id);
    assert_eq!(parsed.cipher_suite, cipher_suite);
}

#[test]
fn test_invalid_handshake_type() {
    // Create a ClientHello (0x01) instead of ServerHello (0x02)
    let mut data = vec![
        0x01, // ClientHello instead of ServerHello
        0x00, 0x00, 0x28, // Length (40 bytes: 2+32+1+2+1+2)
        0x03, 0x03, // Legacy version
    ];
    data.extend_from_slice(&[0xaa; 32]); // Random (32 bytes)
    data.push(0x00); // Session ID length
    data.extend_from_slice(&[0x13, 0x01]); // Cipher suite
    data.push(0x00); // Compression method
    data.extend_from_slice(&[0x00, 0x00]); // Extensions length
    
    let result = ServerHello::from_bytes(&data);
    
    match result {
        Err(TlsError::InvalidHandshakeType(0x01)) => {},
        other => panic!("Expected InvalidHandshakeType(0x01), got {:?}", other),
    }
}

#[test]
fn test_incomplete_data() {
    // Too short data
    let data = vec![0x02, 0x00, 0x00, 0x28];
    
    let result = ServerHello::from_bytes(&data);
    
    assert!(matches!(result, Err(TlsError::IncompleteData)));
}

#[test]
fn test_invalid_legacy_version() {
    let mut data = vec![
        0x02, // ServerHello
        0x00, 0x00, 0x28, // Length (40 bytes = 2+32+1+2+1+2)
        0x03, 0x04, // Invalid version (TLS 1.3 instead of 0x0303)
    ];
    data.extend_from_slice(&[0xaa; 32]); // Random
    data.push(0x00); // Session ID length
    data.extend_from_slice(&[0x13, 0x01]); // Cipher suite
    data.push(0x00); // Compression method
    data.extend_from_slice(&[0x00, 0x00]); // Extensions length
    
    let result = ServerHello::from_bytes(&data);
    
    match result {
        Err(TlsError::InvalidVersion(0x0304)) => {},
        other => panic!("Expected InvalidVersion(0x0304), got {:?}", other),
    }
}

#[test]
fn test_invalid_cipher_suite() {
    let random = [0xaa; 32];
    let session_id: Vec<u8> = vec![];
    let invalid_cipher: u16 = 0x0000; // Invalid cipher suite
    
    let mut data = vec![
        0x02, // ServerHello
        0x00, 0x00, 0x28, // Length (40 bytes = 2+32+1+2+1+2)
        0x03, 0x03, // Legacy version
    ];
    data.extend_from_slice(&random);
    data.push(session_id.len() as u8);
    data.extend_from_slice(&invalid_cipher.to_be_bytes());
    data.push(0x00); // Compression method
    data.extend_from_slice(&[0x00, 0x00]); // Extensions length (0)
    
    let result = ServerHello::from_bytes(&data);
    
    match result {
        Err(TlsError::InvalidCipherSuite(0x0000)) => {},
        other => panic!("Expected InvalidCipherSuite(0x0000), got {:?}", other),
    }
}

#[test]
fn test_valid_tls13_cipher_suites() {
    let random = [0xaa; 32];
    let session_id = vec![];
    
    let cipher_suites = vec![
        TLS_AES_128_GCM_SHA256,
        TLS_AES_256_GCM_SHA384,
        TLS_CHACHA20_POLY1305_SHA256,
    ];
    
    for cipher_suite in cipher_suites {
        let extensions = vec![
            Extension::SupportedVersions(vec![TLS_VERSION_1_3]),
        ];
        
        let server_hello = ServerHello::new(
            random,
            session_id.clone(),
            cipher_suite,
            extensions,
        );
        
        let bytes = server_hello.to_bytes();
        let parsed = ServerHello::from_bytes(&bytes).unwrap();
        
        assert_eq!(parsed.cipher_suite, cipher_suite);
    }
}

#[test]
fn test_missing_supported_versions_extension() {
    let random = [0xaa; 32];
    let session_id = vec![];
    let cipher_suite = TLS_AES_128_GCM_SHA256;
    
    // Missing supported_versions extension
    let extensions = vec![
        Extension::KeyShare(vec![KeyShareEntry::new(NAMED_GROUP_X25519, vec![0xbb; 32])]),
    ];
    
    let server_hello = ServerHello::new(random, session_id, cipher_suite, extensions);
    let bytes = server_hello.to_bytes();
    
    let result = ServerHello::from_bytes(&bytes);
    
    assert!(matches!(
        result,
        Err(TlsError::MissingMandatoryExtension("supported_versions"))
    ));
}

#[test]
fn test_downgrade_protection_tls12_detected() {
    let mut random = [0xaa; 32];
    random[24..32].copy_from_slice(&TLS_1_2_DOWNGRADE_SENTINEL);
    
    let server_hello = ServerHello::new(
        random,
        vec![],
        TLS_AES_128_GCM_SHA256,
        vec![Extension::SupportedVersions(vec![TLS_VERSION_1_3])],
    );
    
    let protection = server_hello.check_downgrade_protection();
    
    assert_eq!(protection, Some(DowngradeProtection::Tls12Downgrade));
}

#[test]
fn test_downgrade_protection_tls11_detected() {
    let mut random = [0xaa; 32];
    random[24..32].copy_from_slice(&TLS_1_1_DOWNGRADE_SENTINEL);
    
    let server_hello = ServerHello::new(
        random,
        vec![],
        TLS_AES_128_GCM_SHA256,
        vec![Extension::SupportedVersions(vec![TLS_VERSION_1_3])],
    );
    
    let protection = server_hello.check_downgrade_protection();
    
    assert_eq!(protection, Some(DowngradeProtection::Tls11Downgrade));
}

#[test]
fn test_no_downgrade_protection() {
    let random = [0xaa; 32];
    
    let server_hello = ServerHello::new(
        random,
        vec![],
        TLS_AES_128_GCM_SHA256,
        vec![Extension::SupportedVersions(vec![TLS_VERSION_1_3])],
    );
    
    let protection = server_hello.check_downgrade_protection();
    
    assert_eq!(protection, None);
}

#[test]
fn test_roundtrip_serialization() {
    // Create a comprehensive ServerHello
    let random = [0x42; 32];
    let session_id = vec![0x11, 0x22, 0x33, 0x44];
    let cipher_suite = TLS_CHACHA20_POLY1305_SHA256;
    let extensions = vec![
        Extension::SupportedVersions(vec![TLS_VERSION_1_3]),
        Extension::KeyShare(vec![
            KeyShareEntry::new(NAMED_GROUP_X25519, vec![0xcc; 32]),
        ]),
        Extension::ServerName("example.com".to_string()),
    ];
    
    let original = ServerHello::new(
        random,
        session_id.clone(),
        cipher_suite,
        extensions.clone(),
    );
    
    // Serialize and deserialize
    let bytes = original.to_bytes();
    let parsed = ServerHello::from_bytes(&bytes).unwrap();
    
    // Verify all fields match
    assert_eq!(parsed.random, random);
    assert_eq!(parsed.legacy_session_id_echo, session_id);
    assert_eq!(parsed.cipher_suite, cipher_suite);
    assert_eq!(parsed.extensions.len(), 3);
}

#[test]
fn test_invalid_compression_method() {
    let random = [0xaa; 32];
    
    // Build ServerHello body (without handshake header)
    let mut body = vec![
        0x03, 0x03, // Legacy version
    ];
    body.extend_from_slice(&random);
    body.push(0x00); // Session ID length
    body.extend_from_slice(&TLS_AES_128_GCM_SHA256.to_be_bytes());
    body.push(0x01); // Invalid compression method (should be 0x00)
    
    // Add supported_versions extension
    let ext = Extension::SupportedVersions(vec![TLS_VERSION_1_3]);
    let ext_bytes = ext.to_bytes();
    let ext_len = (ext_bytes.len() as u16).to_be_bytes();
    body.extend_from_slice(&ext_len); // Extensions length
    body.extend_from_slice(&ext_bytes);
    
    // Now prepend handshake header
    let body_len = (body.len() as u32).to_be_bytes();
    let mut data = vec![0x02]; // ServerHello type
    data.extend_from_slice(&body_len[1..4]); // 3-byte length
    data.extend_from_slice(&body);
    
    let result = ServerHello::from_bytes(&data);
    
    match result {
        Err(TlsError::InvalidCompressionMethod(0x01)) => {}, // Expected
        other => panic!("Expected InvalidCompressionMethod(0x01), got {:?}", other),
    }
}

#[test]
fn test_session_id_too_long() {
    let random = [0xaa; 32];
    
    let mut data = vec![
        0x02, // ServerHello
        0x00, 0x00, 0x49, // Length (73 bytes = 2+32+1+33+2+1+2)
        0x03, 0x03, // Legacy version
    ];
    data.extend_from_slice(&random);
    data.push(33); // Session ID length > 32 (invalid)
    data.extend_from_slice(&[0x00; 33]); // Actual session ID data
    data.extend_from_slice(&[0x13, 0x01]); // Cipher suite
    data.push(0x00); // Compression method
    data.extend_from_slice(&[0x00, 0x00]); // Extensions length
    
    let result = ServerHello::from_bytes(&data);
    
    match result {
        Err(TlsError::InvalidLength(33)) => {},
        other => panic!("Expected InvalidLength(33), got {:?}", other),
    }
}

#[test]
fn test_duplicate_extensions() {
    let random = [0xaa; 32];
    let session_id = vec![];
    let cipher_suite = TLS_AES_128_GCM_SHA256;
    
    // Create extensions with duplicates
    let extensions = vec![
        Extension::SupportedVersions(vec![TLS_VERSION_1_3]),
        Extension::SupportedVersions(vec![TLS_VERSION_1_3]), // Duplicate
    ];
    
    let server_hello = ServerHello::new(random, session_id, cipher_suite, extensions);
    let bytes = server_hello.to_bytes();
    
    let result = ServerHello::from_bytes(&bytes);
    
    assert!(matches!(result, Err(TlsError::DuplicateExtension(_))));
}

#[test]
fn test_empty_extensions() {
    let random = [0xaa; 32];
    let session_id = vec![];
    let cipher_suite = TLS_AES_128_GCM_SHA256;
    let extensions = vec![];
    
    let server_hello = ServerHello::new(random, session_id, cipher_suite, extensions);
    let bytes = server_hello.to_bytes();
    
    // Should fail because supported_versions is mandatory
    let result = ServerHello::from_bytes(&bytes);
    
    assert!(matches!(
        result,
        Err(TlsError::MissingMandatoryExtension("supported_versions"))
    ));
}

#[test]
fn test_parse_real_world_like_server_hello() {
    // Simulate a realistic ServerHello message
    let mut random = [0u8; 32];
    for (i, byte) in random.iter_mut().enumerate() {
        *byte = (i * 7) as u8; // Semi-random pattern
    }
    
    let session_id = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let cipher_suite = TLS_AES_256_GCM_SHA384;
    
    let public_key = vec![
        0x9f, 0xd7, 0xad, 0x6d, 0xcf, 0xf4, 0x29, 0x8d,
        0xd3, 0xf9, 0x6d, 0x5b, 0x1b, 0x2a, 0xf9, 0x10,
        0xa0, 0x53, 0x5b, 0x14, 0x88, 0xd7, 0xf8, 0xfa,
        0xbb, 0x34, 0x9a, 0x98, 0x28, 0x80, 0xb6, 0x15,
    ];
    
    let extensions = vec![
        Extension::SupportedVersions(vec![TLS_VERSION_1_3]),
        Extension::KeyShare(vec![KeyShareEntry::new(NAMED_GROUP_X25519, public_key)]),
    ];
    
    let server_hello = ServerHello::new(random, session_id.clone(), cipher_suite, extensions);
    let bytes = server_hello.to_bytes();
    
    // Parse and verify
    let parsed = ServerHello::from_bytes(&bytes).unwrap();
    
    assert_eq!(parsed.random, random);
    assert_eq!(parsed.legacy_session_id_echo, session_id);
    assert_eq!(parsed.cipher_suite, cipher_suite);
    assert_eq!(parsed.extensions.len(), 2);
    assert!(parsed.check_downgrade_protection().is_none());
}
