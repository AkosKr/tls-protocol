use tls_protocol::certificate::{Certificate, CertificateEntry, MAX_CERTIFICATE_CHAIN_LENGTH};
use tls_protocol::error::TlsError;
use tls_protocol::extensions::Extension;

#[test]
fn test_valid_certificate_with_single_cert() {
    // Create a simple DER-encoded certificate (mock data)
    let mut cert_data = vec![
        0x30, 0x82, 0x03, 0x50, // SEQUENCE, length 848
        0x30, 0x82, 0x02, 0x38, // ... more DER data
    ];
    cert_data.extend(vec![0xaa; 100]); // Extend with more data

    let entry = CertificateEntry::new(cert_data.clone(), vec![]);
    let certificate = Certificate::new(vec![], vec![entry]);

    // Serialize and parse
    let bytes = certificate.to_bytes();
    let parsed = Certificate::from_bytes(&bytes).unwrap();

    assert_eq!(parsed.certificate_request_context, vec![]);
    assert_eq!(parsed.certificate_list.len(), 1);
    assert_eq!(parsed.certificate_list[0].cert_data, cert_data);
    assert_eq!(parsed.certificate_list[0].extensions.len(), 0);
    assert!(parsed.is_server_authentication());
}

#[test]
fn test_valid_certificate_with_multiple_certs() {
    // Create a certificate chain with 3 certificates
    let mut cert1 = vec![0x30, 0x82, 0x01, 0x00]; // End-entity cert
    cert1.extend(vec![0xaa; 50]);

    let mut cert2 = vec![0x30, 0x82, 0x01, 0x10]; // Intermediate cert
    cert2.extend(vec![0xbb; 60]);

    let mut cert3 = vec![0x30, 0x82, 0x01, 0x20]; // Root cert
    cert3.extend(vec![0xcc; 70]);

    let entry1 = CertificateEntry::new(cert1.clone(), vec![]);
    let entry2 = CertificateEntry::new(cert2.clone(), vec![]);
    let entry3 = CertificateEntry::new(cert3.clone(), vec![]);

    let certificate = Certificate::new(vec![], vec![entry1, entry2, entry3]);

    // Serialize and parse
    let bytes = certificate.to_bytes();
    let parsed = Certificate::from_bytes(&bytes).unwrap();

    assert_eq!(parsed.certificate_list.len(), 3);
    assert_eq!(parsed.certificate_list[0].cert_data, cert1);
    assert_eq!(parsed.certificate_list[1].cert_data, cert2);
    assert_eq!(parsed.certificate_list[2].cert_data, cert3);
}

#[test]
fn test_certificate_with_extensions() {
    let cert_data = vec![0x30; 100];
    let extensions = vec![
        Extension::Unknown {
            extension_type: 1,
            data: vec![0x01, 0x02, 0x03],
        },
        Extension::Unknown {
            extension_type: 2,
            data: vec![0x04, 0x05],
        },
    ];

    let entry = CertificateEntry::new(cert_data.clone(), extensions.clone());
    let certificate = Certificate::new(vec![], vec![entry]);

    // Serialize and parse
    let bytes = certificate.to_bytes();
    let parsed = Certificate::from_bytes(&bytes).unwrap();

    assert_eq!(parsed.certificate_list[0].extensions.len(), 2);
}

#[test]
fn test_certificate_with_request_context() {
    let context = vec![0x01, 0x02, 0x03, 0x04];
    let cert_data = vec![0x30; 100];
    let entry = CertificateEntry::new(cert_data, vec![]);
    let certificate = Certificate::new(context.clone(), vec![entry]);

    // Serialize and parse
    let bytes = certificate.to_bytes();
    let parsed = Certificate::from_bytes(&bytes).unwrap();

    assert_eq!(parsed.certificate_request_context, context);
    assert!(!parsed.is_server_authentication());
}

#[test]
fn test_empty_certificate_list() {
    let certificate = Certificate::new(vec![], vec![]);

    // Should fail validation
    assert!(matches!(
        certificate.validate(),
        Err(TlsError::EmptyCertificateList)
    ));
}

#[test]
fn test_parse_empty_certificate_list() {
    // Create a certificate message with empty list
    let data = vec![
        0x0b, // Certificate handshake type
        0x00, 0x00, 0x04, // Length (4 bytes)
        0x00, // Context length
        0x00, 0x00, 0x00, // Certificate list length (0)
    ];

    let result = Certificate::from_bytes(&data);

    assert!(matches!(result, Err(TlsError::EmptyCertificateList)));
}

#[test]
fn test_invalid_handshake_type() {
    let data = vec![
        0x0c, // Wrong handshake type (not 0x0b)
        0x00, 0x00, 0x10, // Length
        0x00, // Context length
        0x00, 0x00, 0x08, // Certificate list length
        0x00, 0x00, 0x05, // Cert data length
        0x30, 0x30, 0x30, 0x30, 0x30, // Cert data
        0x00, 0x00, // Extensions length
    ];

    let result = Certificate::from_bytes(&data);

    match result {
        Err(TlsError::InvalidHandshakeType(0x0c)) => {}
        other => panic!("Expected InvalidHandshakeType(0x0c), got {:?}", other),
    }
}

#[test]
fn test_incomplete_data() {
    // Too short data
    let data = vec![0x0b, 0x00, 0x00];

    let result = Certificate::from_bytes(&data);

    assert!(matches!(result, Err(TlsError::IncompleteData)));
}

#[test]
fn test_incomplete_certificate_data() {
    let data = vec![
        0x0b, // Certificate handshake type
        0x00, 0x00, 0x10, // Length (16 bytes)
        0x00, // Context length
        0x00, 0x00, 0x0c, // Certificate list length (12 bytes)
        0x00, 0x00, 0xff, // Cert data length (255 bytes - but not enough data)
    ];

    let result = Certificate::from_bytes(&data);

    // The message header claims 16 bytes but we don't have that much data
    assert!(matches!(result, Err(TlsError::IncompleteData)));
}

#[test]
fn test_zero_length_certificate_data() {
    let data = vec![
        0x0b, // Certificate handshake type
        0x00, 0x00, 0x07, // Length
        0x00, // Context length
        0x00, 0x00, 0x03, // Certificate list length
        0x00, 0x00, 0x00, // Cert data length (0 - invalid)
    ];

    let result = Certificate::from_bytes(&data);

    assert!(matches!(result, Err(TlsError::InvalidCertificateData(_))));
}

#[test]
fn test_certificate_chain_too_long() {
    // Create a chain with more than MAX_CERTIFICATE_CHAIN_LENGTH certificates
    let mut entries = Vec::new();
    for i in 0..=MAX_CERTIFICATE_CHAIN_LENGTH {
        let mut cert_data = vec![0x30, i as u8];
        cert_data.extend(vec![0; 48]);
        entries.push(CertificateEntry::new(cert_data, vec![]));
    }

    let certificate = Certificate::new(vec![], entries);

    // Should fail validation
    let result = certificate.validate();

    assert!(matches!(result, Err(TlsError::CertificateChainTooLong(_))));
}

#[test]
fn test_parse_certificate_chain_too_long() {
    // Build a certificate message with 11 certificates (exceeds limit of 10)
    let mut data = vec![
        0x0b, // Certificate handshake type
    ];

    // We'll calculate the length later
    let length_offset = data.len();
    data.extend_from_slice(&[0x00, 0x00, 0x00]); // Placeholder for length

    data.push(0x00); // Context length

    // Calculate certificate list
    let mut cert_list = Vec::new();
    for _ in 0..11 {
        cert_list.extend_from_slice(&[0x00, 0x00, 0x05]); // Cert data length (5 bytes)
        cert_list.extend_from_slice(&[0x30, 0x30, 0x30, 0x30, 0x30]); // Cert data
        cert_list.extend_from_slice(&[0x00, 0x00]); // Extensions length (0)
    }

    // Add certificate list length
    let cert_list_len = cert_list.len();
    data.push((cert_list_len >> 16) as u8);
    data.push((cert_list_len >> 8) as u8);
    data.push(cert_list_len as u8);
    data.extend_from_slice(&cert_list);

    // Fix the total length
    let total_len = data.len() - 4; // Exclude handshake type and length field
    data[length_offset] = (total_len >> 16) as u8;
    data[length_offset + 1] = (total_len >> 8) as u8;
    data[length_offset + 2] = total_len as u8;

    let result = Certificate::from_bytes(&data);

    assert!(matches!(result, Err(TlsError::CertificateChainTooLong(11))));
}

#[test]
fn test_context_too_large() {
    let context = vec![0u8; 256]; // Exceeds 255 byte limit
    let entry = CertificateEntry::new(vec![0x30; 100], vec![]);
    let certificate = Certificate::new(context, vec![entry]);

    let result = certificate.validate();

    assert!(matches!(result, Err(TlsError::InvalidCertificateData(_))));
}

#[test]
fn test_roundtrip_serialization() {
    let mut cert1 = vec![0x30, 0x82, 0x03, 0x50];
    cert1.extend(vec![0xaa; 100]);

    let mut cert2 = vec![0x30, 0x82, 0x02, 0x00];
    cert2.extend(vec![0xbb; 80]);

    let entry1 = CertificateEntry::new(
        cert1,
        vec![Extension::Unknown {
            extension_type: 5,
            data: vec![0x01, 0x02],
        }],
    );
    let entry2 = CertificateEntry::new(cert2, vec![]);

    let context = vec![0x11, 0x22, 0x33];
    let original = Certificate::new(context.clone(), vec![entry1, entry2]);

    // Serialize
    let bytes = original.to_bytes();

    // Parse back
    let parsed = Certificate::from_bytes(&bytes).unwrap();

    // Compare
    assert_eq!(
        parsed.certificate_request_context,
        original.certificate_request_context
    );
    assert_eq!(
        parsed.certificate_list.len(),
        original.certificate_list.len()
    );

    for (parsed_entry, original_entry) in parsed
        .certificate_list
        .iter()
        .zip(original.certificate_list.iter())
    {
        assert_eq!(parsed_entry.cert_data, original_entry.cert_data);
        assert_eq!(
            parsed_entry.extensions.len(),
            original_entry.extensions.len()
        );
    }
}

#[test]
fn test_end_entity_certificate() {
    let cert1 = vec![0xaa; 100];
    let cert2 = vec![0xbb; 100];

    let entry1 = CertificateEntry::new(cert1.clone(), vec![]);
    let entry2 = CertificateEntry::new(cert2, vec![]);

    let certificate = Certificate::new(vec![], vec![entry1, entry2]);

    let end_entity = certificate.end_entity_certificate().unwrap();
    assert_eq!(end_entity.cert_data, cert1);
}

#[test]
fn test_real_world_der_certificate_start() {
    // A more realistic DER-encoded certificate beginning
    // This is a simplified X.509 v3 certificate structure
    let mut cert_data = vec![
        0x30, 0x82, 0x03, 0x50, // SEQUENCE (certificate)
        0x30, 0x82, 0x02, 0x38, // SEQUENCE (tbsCertificate)
        0xa0, 0x03, // [0] EXPLICIT (version)
        0x02, 0x01, 0x02, // INTEGER 2 (v3)
        0x02, 0x08, // INTEGER (serial number)
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    ];
    // Add more data to make it realistic size
    cert_data.extend(vec![0x30; 200]);

    let entry = CertificateEntry::new(cert_data.clone(), vec![]);
    let certificate = Certificate::new(vec![], vec![entry]);

    // Should validate and serialize/parse correctly
    assert!(certificate.validate().is_ok());

    let bytes = certificate.to_bytes();
    let parsed = Certificate::from_bytes(&bytes).unwrap();

    assert_eq!(parsed.certificate_list[0].cert_data, cert_data);
}

#[test]
fn test_handshake_type_in_serialization() {
    let cert_data = vec![0x30; 100];
    let entry = CertificateEntry::new(cert_data, vec![]);
    let certificate = Certificate::new(vec![], vec![entry]);

    let bytes = certificate.to_bytes();

    // First byte should be 0x0b (Certificate handshake type)
    assert_eq!(bytes[0], 0x0b);
}

#[test]
fn test_length_fields_in_serialization() {
    let cert_data = vec![0x30; 100];
    let entry = CertificateEntry::new(cert_data, vec![]);
    let certificate = Certificate::new(vec![], vec![entry]);

    let bytes = certificate.to_bytes();

    // Parse the length field (3 bytes after handshake type)
    let message_len =
        ((bytes[1] as usize) << 16) | ((bytes[2] as usize) << 8) | (bytes[3] as usize);

    // Total bytes should be handshake type (1) + length (3) + message_len
    assert_eq!(bytes.len(), 4 + message_len);
}

#[test]
fn test_maximum_valid_chain_length() {
    // Create exactly MAX_CERTIFICATE_CHAIN_LENGTH certificates
    let mut entries = Vec::new();
    for i in 0..MAX_CERTIFICATE_CHAIN_LENGTH {
        let mut cert_data = vec![0x30, i as u8];
        cert_data.extend(vec![0; 48]);
        entries.push(CertificateEntry::new(cert_data, vec![]));
    }

    let certificate = Certificate::new(vec![], entries);

    // Should pass validation
    assert!(certificate.validate().is_ok());

    // Should serialize and parse correctly
    let bytes = certificate.to_bytes();
    let parsed = Certificate::from_bytes(&bytes).unwrap();

    assert_eq!(parsed.certificate_list.len(), MAX_CERTIFICATE_CHAIN_LENGTH);
}
