use tls_protocol::extensions::*;

#[test]
fn test_server_name_extension() {
    let ext = Extension::ServerName("example.com".to_string());
    let bytes = ext.to_bytes();

    // Extension type (0)
    assert_eq!(&bytes[0..2], &[0x00, 0x00]);

    // Deserialize back
    let (parsed, consumed) = Extension::from_bytes(&bytes).unwrap();
    assert_eq!(consumed, bytes.len());
    assert_eq!(parsed, ext);
}

#[test]
fn test_signature_algorithms_extension() {
    let algorithms = vec![
        SIG_RSA_PSS_RSAE_SHA256,
        SIG_ECDSA_SECP256R1_SHA256,
        SIG_ED25519,
    ];
    let ext = Extension::SignatureAlgorithms(algorithms.clone());
    let bytes = ext.to_bytes();

    // Extension type (13)
    assert_eq!(&bytes[0..2], &[0x00, 0x0d]);

    // Deserialize back
    let (parsed, consumed) = Extension::from_bytes(&bytes).unwrap();
    assert_eq!(consumed, bytes.len());
    assert_eq!(parsed, ext);
}

#[test]
fn test_supported_versions_extension() {
    let ext = Extension::SupportedVersions(vec![TLS_VERSION_1_3, TLS_VERSION_1_2]);
    let bytes = ext.to_bytes();

    // Extension type (43)
    assert_eq!(&bytes[0..2], &[0x00, 0x2b]);
    // Extension length (5)
    assert_eq!(&bytes[2..4], &[0x00, 0x05]);
    // Versions length (4)
    assert_eq!(bytes[4], 0x04);

    // Deserialize back
    let (parsed, consumed) = Extension::from_bytes(&bytes).unwrap();
    assert_eq!(consumed, bytes.len());
    assert_eq!(parsed, ext);
}

#[test]
fn test_key_share_extension() {
    let key = vec![0xaa; 32];
    let entry = KeyShareEntry::new(NAMED_GROUP_X25519, key.clone());
    let ext = Extension::KeyShare(vec![entry.clone()]);
    let bytes = ext.to_bytes();

    // Extension type (51)
    assert_eq!(&bytes[0..2], &[0x00, 0x33]);

    // Deserialize back
    let (parsed, consumed) = Extension::from_bytes(&bytes).unwrap();
    assert_eq!(consumed, bytes.len());
    assert_eq!(parsed, ext);
}

#[test]
fn test_unknown_extension() {
    let ext = Extension::Unknown {
        extension_type: 0xFFFF,
        data: vec![0x01, 0x02, 0x03],
    };
    let bytes = ext.to_bytes();

    // Extension type
    assert_eq!(&bytes[0..2], &[0xFF, 0xFF]);
    // Extension length
    assert_eq!(&bytes[2..4], &[0x00, 0x03]);
    // Data
    assert_eq!(&bytes[4..], &[0x01, 0x02, 0x03]);

    // Deserialize back
    let (parsed, consumed) = Extension::from_bytes(&bytes).unwrap();
    assert_eq!(consumed, bytes.len());
    assert_eq!(parsed, ext);
}

#[test]
fn test_parse_multiple_extensions() {
    let extensions = vec![
        Extension::SupportedVersions(vec![TLS_VERSION_1_3]),
        Extension::KeyShare(vec![KeyShareEntry::new(NAMED_GROUP_X25519, vec![0xaa; 32])]),
    ];

    let bytes = Extension::serialize_extensions(&extensions);
    let parsed = Extension::parse_extensions(&bytes).unwrap();

    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed, extensions);
}

#[test]
fn test_validate_tls13_extensions_success() {
    let extensions = vec![
        Extension::SupportedVersions(vec![TLS_VERSION_1_3]),
        Extension::KeyShare(vec![KeyShareEntry::new(NAMED_GROUP_X25519, vec![0xaa; 32])]),
    ];

    assert!(validate_tls13_extensions(&extensions).is_ok());
}

#[test]
fn test_validate_tls13_extensions_missing_supported_versions() {
    let extensions = vec![Extension::KeyShare(vec![KeyShareEntry::new(
        NAMED_GROUP_X25519,
        vec![0xaa; 32],
    )])];

    assert!(validate_tls13_extensions(&extensions).is_err());
}

#[test]
fn test_validate_tls13_extensions_missing_key_share() {
    let extensions = vec![Extension::SupportedVersions(vec![TLS_VERSION_1_3])];

    assert!(validate_tls13_extensions(&extensions).is_err());
}

#[test]
fn test_check_duplicate_extensions() {
    let extensions = vec![
        Extension::SupportedVersions(vec![TLS_VERSION_1_3]),
        Extension::SupportedVersions(vec![TLS_VERSION_1_2]),
    ];

    assert!(check_duplicate_extensions(&extensions).is_err());
}

#[test]
fn test_key_share_entry_serialization() {
    let entry = KeyShareEntry::new(NAMED_GROUP_X25519, vec![0xbb; 32]);
    let bytes = entry.to_bytes();

    assert_eq!(&bytes[0..2], &[0x00, 0x1d]); // Group
    assert_eq!(&bytes[2..4], &[0x00, 0x20]); // Length (32)
    assert_eq!(&bytes[4..], &vec![0xbb; 32][..]); // Key data

    let (parsed, consumed) = KeyShareEntry::from_bytes(&bytes).unwrap();
    assert_eq!(consumed, bytes.len());
    assert_eq!(parsed, entry);
}

#[test]
fn test_key_share_entry_from_bytes_too_short() {
    // Test data with less than 4 bytes
    let data = vec![0x00, 0x1d];
    let result = KeyShareEntry::from_bytes(&data);
    assert!(result.is_err());
    
    // Test data with incomplete key_exchange
    let data = vec![0x00, 0x1d, 0x00, 0x20]; // Says 32 bytes but has 0
    let result = KeyShareEntry::from_bytes(&data);
    assert!(result.is_err());
}

#[test]
fn test_server_name_extension_malformed_list_length() {
    // Extension with invalid list length
    let mut bytes = vec![0x00, 0x00]; // Extension type
    bytes.extend_from_slice(&[0x00, 0x05]); // Extension length
    bytes.extend_from_slice(&[0x00, 0xFF]); // Invalid list length (larger than available data)
    
    let result = Extension::from_bytes(&bytes);
    assert!(result.is_err());
}

#[test]
fn test_server_name_extension_empty_hostname() {
    // Extension with empty hostname
    let mut bytes = vec![0x00, 0x00]; // Extension type
    bytes.extend_from_slice(&[0x00, 0x05]); // Extension length
    bytes.extend_from_slice(&[0x00, 0x03]); // List length
    bytes.push(0x00); // Name type: host_name
    bytes.extend_from_slice(&[0x00, 0x00]); // Hostname length: 0
    
    let result = Extension::from_bytes(&bytes);
    assert!(result.is_err());
}

#[test]
fn test_server_name_extension_too_long() {
    // Extension with hostname longer than 255 characters
    let long_hostname = "a".repeat(256);
    let mut bytes = vec![0x00, 0x00]; // Extension type
    let ext_len = 2 + 1 + 2 + 256;
    bytes.extend_from_slice(&(ext_len as u16).to_be_bytes()); // Extension length
    bytes.extend_from_slice(&((1 + 2 + 256) as u16).to_be_bytes()); // List length
    bytes.push(0x00); // Name type: host_name
    bytes.extend_from_slice(&[0x01, 0x00]); // Hostname length: 256
    bytes.extend_from_slice(long_hostname.as_bytes());
    
    let result = Extension::from_bytes(&bytes);
    assert!(result.is_err());
}

#[test]
fn test_signature_algorithms_extension_odd_length() {
    // Extension with odd-length data (invalid since each algorithm is 2 bytes)
    let mut bytes = vec![0x00, 0x0d]; // Extension type
    bytes.extend_from_slice(&[0x00, 0x04]); // Extension length
    bytes.extend_from_slice(&[0x00, 0x03]); // Algorithms length: 3 (odd, should be even)
    bytes.extend_from_slice(&[0x04, 0x01, 0x05]); // Invalid data
    
    let result = Extension::from_bytes(&bytes);
    assert!(result.is_err());
}

#[test]
fn test_supported_versions_extension_invalid_without_tls13() {
    // SupportedVersions extension without TLS 1.3
    let extensions = vec![
        Extension::SupportedVersions(vec![TLS_VERSION_1_2]), // Only TLS 1.2
        Extension::KeyShare(vec![KeyShareEntry::new(NAMED_GROUP_X25519, vec![0xaa; 32])]),
    ];
    
    let result = validate_tls13_extensions(&extensions);
    assert!(result.is_err());
}

#[test]
fn test_key_share_extension_empty_entries() {
    // KeyShare extension with empty entries list
    let extensions = vec![
        Extension::SupportedVersions(vec![TLS_VERSION_1_3]),
        Extension::KeyShare(vec![]), // Empty entries
    ];
    
    let result = validate_tls13_extensions(&extensions);
    assert!(result.is_err());
}

#[test]
fn test_key_share_extension_malformed_entries_length() {
    // Extension with invalid entries length
    let mut bytes = vec![0x00, 0x33]; // Extension type (51)
    bytes.extend_from_slice(&[0x00, 0x05]); // Extension length
    bytes.extend_from_slice(&[0x00, 0xFF]); // Invalid entries length (larger than available)
    
    let result = Extension::from_bytes(&bytes);
    assert!(result.is_err());
}

#[test]
fn test_parse_extensions_length_mismatch() {
    // Create valid extensions
    let extensions = vec![
        Extension::SupportedVersions(vec![TLS_VERSION_1_3]),
    ];
    
    let mut bytes = Extension::serialize_extensions(&extensions);
    // Add extra byte at the end (will cause length mismatch)
    bytes.push(0xFF);
    
    // This should succeed because parse_extensions only checks the declared length
    // But let's create a case where the declared length is incorrect
    let mut bad_bytes = vec![0x00, 0xFF]; // Declare length of 255
    bad_bytes.extend_from_slice(&[0x00, 0x2b]); // Extension type
    bad_bytes.extend_from_slice(&[0x00, 0x03]); // Extension length
    bad_bytes.extend_from_slice(&[0x02, 0x03, 0x04]); // Data
    
    let result = Extension::parse_extensions(&bad_bytes);
    assert!(result.is_err()); // Should fail due to incomplete data
}
