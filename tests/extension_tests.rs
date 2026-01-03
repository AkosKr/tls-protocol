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
