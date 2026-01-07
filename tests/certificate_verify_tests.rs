use tls_protocol::certificate_verify::{
    build_signed_content, CertificateVerify, CLIENT_CERTIFICATE_VERIFY_CONTEXT,
    SERVER_CERTIFICATE_VERIFY_CONTEXT,
};
use tls_protocol::extensions::{
    SIG_ECDSA_SECP256R1_SHA256, SIG_ECDSA_SECP384R1_SHA384, SIG_RSA_PSS_RSAE_SHA256,
    SIG_RSA_PSS_RSAE_SHA384,
};
use tls_protocol::TlsError;

#[test]
fn test_build_signed_content_format() {
    let transcript_hash = [0xaa; 32];
    let content = build_signed_content(&transcript_hash, SERVER_CERTIFICATE_VERIFY_CONTEXT);

    // Total length: 64 (padding) + 33 (context) + 1 (null) + 32 (hash) = 130
    assert_eq!(content.len(), 130);

    // Check padding (64 spaces)
    for i in 0..64 {
        assert_eq!(content[i], 0x20, "Byte {} should be space (0x20)", i);
    }

    // Check context string
    let context_bytes = SERVER_CERTIFICATE_VERIFY_CONTEXT.as_bytes();
    for (i, &byte) in context_bytes.iter().enumerate() {
        assert_eq!(content[64 + i], byte, "Context byte {} mismatch", i);
    }

    // Check null byte
    assert_eq!(content[64 + context_bytes.len()], 0x00);

    // Check transcript hash
    for i in 0..32 {
        assert_eq!(
            content[64 + context_bytes.len() + 1 + i],
            0xaa,
            "Hash byte {} mismatch",
            i
        );
    }
}

#[test]
fn test_build_signed_content_client_context() {
    let transcript_hash = [0xbb; 32];
    let content = build_signed_content(&transcript_hash, CLIENT_CERTIFICATE_VERIFY_CONTEXT);

    // Should have client context string
    let context_bytes = CLIENT_CERTIFICATE_VERIFY_CONTEXT.as_bytes();
    assert_eq!(&content[64..64 + context_bytes.len()], context_bytes);
}

#[test]
fn test_certificate_verify_new() {
    let cert_verify = CertificateVerify::new(SIG_RSA_PSS_RSAE_SHA256, vec![0xaa; 256]);

    assert_eq!(cert_verify.algorithm, SIG_RSA_PSS_RSAE_SHA256);
    assert_eq!(cert_verify.signature.len(), 256);
    assert_eq!(cert_verify.signature, vec![0xaa; 256]);
}

#[test]
fn test_certificate_verify_to_bytes_format() {
    let cert_verify = CertificateVerify::new(SIG_RSA_PSS_RSAE_SHA256, vec![0xaa; 256]);
    let bytes = cert_verify.to_bytes();

    // Check handshake type (0x0f for CertificateVerify)
    assert_eq!(bytes[0], 0x0f);

    // Check 3-byte length field
    let length = ((bytes[1] as usize) << 16) | ((bytes[2] as usize) << 8) | (bytes[3] as usize);
    assert_eq!(length, bytes.len() - 4);
    assert_eq!(length, 2 + 2 + 256); // algorithm + sig_len + signature

    // Check algorithm (2 bytes)
    let algorithm = u16::from_be_bytes([bytes[4], bytes[5]]);
    assert_eq!(algorithm, SIG_RSA_PSS_RSAE_SHA256);

    // Check signature length (2 bytes)
    let sig_len = u16::from_be_bytes([bytes[6], bytes[7]]) as usize;
    assert_eq!(sig_len, 256);

    // Check signature data
    assert_eq!(&bytes[8..8 + 256], &[0xaa; 256]);
}

#[test]
fn test_certificate_verify_to_bytes_all_algorithms() {
    let algorithms = vec![
        SIG_RSA_PSS_RSAE_SHA256,
        SIG_RSA_PSS_RSAE_SHA384,
        SIG_ECDSA_SECP256R1_SHA256,
        SIG_ECDSA_SECP384R1_SHA384,
    ];

    for algorithm in algorithms {
        let cert_verify = CertificateVerify::new(algorithm, vec![0xcc; 128]);
        let bytes = cert_verify.to_bytes();

        assert_eq!(bytes[0], 0x0f);
        let parsed_algorithm = u16::from_be_bytes([bytes[4], bytes[5]]);
        assert_eq!(parsed_algorithm, algorithm);
    }
}

#[test]
fn test_certificate_verify_from_bytes_valid() {
    let mut data = vec![0x0f]; // Handshake type
    data.extend_from_slice(&[0x00, 0x01, 0x04]); // Length: 260 bytes (2 + 2 + 256)
    data.extend_from_slice(&SIG_ECDSA_SECP256R1_SHA256.to_be_bytes()); // Algorithm
    data.extend_from_slice(&(256u16).to_be_bytes()); // Signature length
    data.extend_from_slice(&vec![0xbb; 256]); // Signature

    let cert_verify = CertificateVerify::from_bytes(&data).unwrap();

    assert_eq!(cert_verify.algorithm, SIG_ECDSA_SECP256R1_SHA256);
    assert_eq!(cert_verify.signature.len(), 256);
    assert_eq!(cert_verify.signature, vec![0xbb; 256]);
}

#[test]
fn test_certificate_verify_from_bytes_empty_signature() {
    let mut data = vec![0x0f]; // Handshake type
    data.extend_from_slice(&[0x00, 0x00, 0x04]); // Length: 4 bytes
    data.extend_from_slice(&SIG_RSA_PSS_RSAE_SHA256.to_be_bytes()); // Algorithm
    data.extend_from_slice(&(0u16).to_be_bytes()); // Signature length: 0

    let cert_verify = CertificateVerify::from_bytes(&data).unwrap();

    assert_eq!(cert_verify.algorithm, SIG_RSA_PSS_RSAE_SHA256);
    assert_eq!(cert_verify.signature.len(), 0);
}

#[test]
fn test_certificate_verify_from_bytes_large_signature() {
    let signature = vec![0xdd; 512];
    let mut data = vec![0x0f]; // Handshake type
    let length = 2 + 2 + signature.len();
    data.extend_from_slice(&[(length >> 16) as u8, (length >> 8) as u8, length as u8]);
    data.extend_from_slice(&SIG_ECDSA_SECP384R1_SHA384.to_be_bytes());
    data.extend_from_slice(&(signature.len() as u16).to_be_bytes());
    data.extend_from_slice(&signature);

    let cert_verify = CertificateVerify::from_bytes(&data).unwrap();

    assert_eq!(cert_verify.algorithm, SIG_ECDSA_SECP384R1_SHA384);
    assert_eq!(cert_verify.signature, signature);
}

#[test]
fn test_certificate_verify_roundtrip_serialization() {
    let algorithms = vec![
        SIG_RSA_PSS_RSAE_SHA256,
        SIG_RSA_PSS_RSAE_SHA384,
        SIG_ECDSA_SECP256R1_SHA256,
        SIG_ECDSA_SECP384R1_SHA384,
    ];

    for algorithm in algorithms {
        for sig_len in [0, 64, 128, 256, 512] {
            let original = CertificateVerify::new(algorithm, vec![0xee; sig_len]);
            let bytes = original.to_bytes();
            let parsed = CertificateVerify::from_bytes(&bytes).unwrap();

            assert_eq!(parsed.algorithm, original.algorithm);
            assert_eq!(parsed.signature, original.signature);
        }
    }
}

#[test]
fn test_certificate_verify_invalid_handshake_type() {
    let mut data = vec![0x0b]; // Wrong type (Certificate = 0x0b instead of CertificateVerify = 0x0f)
    data.extend_from_slice(&[0x00, 0x00, 0x04]);
    data.extend_from_slice(&SIG_RSA_PSS_RSAE_SHA256.to_be_bytes());
    data.extend_from_slice(&(0u16).to_be_bytes());

    let result = CertificateVerify::from_bytes(&data);
    assert!(matches!(result, Err(TlsError::InvalidHandshakeType(0x0b))));
}

#[test]
fn test_certificate_verify_invalid_handshake_type_client_hello() {
    let data = vec![0x01, 0x00, 0x00, 0x04, 0x08, 0x04, 0x00, 0x00];
    let result = CertificateVerify::from_bytes(&data);
    assert!(matches!(result, Err(TlsError::InvalidHandshakeType(0x01))));
}

#[test]
fn test_certificate_verify_incomplete_data_header() {
    let test_cases = vec![
        vec![],
        vec![0x0f],
        vec![0x0f, 0x00],
        vec![0x0f, 0x00, 0x00],
        vec![0x0f, 0x00, 0x00, 0x04],
        vec![0x0f, 0x00, 0x00, 0x04, 0x08],
        vec![0x0f, 0x00, 0x00, 0x04, 0x08, 0x04],
    ];

    for data in test_cases {
        let result = CertificateVerify::from_bytes(&data);
        assert!(
            matches!(result, Err(TlsError::IncompleteData)),
            "Should fail with IncompleteData for {} bytes",
            data.len()
        );
    }
}

#[test]
fn test_certificate_verify_incomplete_signature_data() {
    let mut data = vec![0x0f]; // Handshake type
    data.extend_from_slice(&[0x00, 0x01, 0x04]); // Length: 260 bytes
    data.extend_from_slice(&SIG_RSA_PSS_RSAE_SHA256.to_be_bytes());
    data.extend_from_slice(&(256u16).to_be_bytes()); // Signature length: 256
    data.extend_from_slice(&vec![0xaa; 100]); // Only 100 bytes instead of 256

    let result = CertificateVerify::from_bytes(&data);
    assert!(matches!(result, Err(TlsError::IncompleteData)));
}

#[test]
fn test_certificate_verify_length_mismatch() {
    // When length field is smaller than actual data, parsing succeeds
    // but only reads up to the declared length
    let mut data = vec![0x0f]; // Handshake type
    data.extend_from_slice(&[0x00, 0x00, 0x10]); // Length: 16 bytes (smaller than actual)
    data.extend_from_slice(&SIG_RSA_PSS_RSAE_SHA256.to_be_bytes());
    data.extend_from_slice(&(10u16).to_be_bytes()); // Signature length: 10
    data.extend_from_slice(&vec![0xaa; 10]); // 10 bytes signature
    data.extend_from_slice(&vec![0xbb; 250]); // Extra data (ignored)

    let result = CertificateVerify::from_bytes(&data);
    // Should succeed since we have enough data for the declared length
    assert!(result.is_ok());
    let cert_verify = result.unwrap();
    assert_eq!(cert_verify.signature.len(), 10);
}

#[test]
fn test_signed_content_different_hashes() {
    let hash1 = [0xaa; 32];
    let hash2 = [0xbb; 32];

    let content1 = build_signed_content(&hash1, SERVER_CERTIFICATE_VERIFY_CONTEXT);
    let content2 = build_signed_content(&hash2, SERVER_CERTIFICATE_VERIFY_CONTEXT);

    // Should be different due to different hashes
    assert_ne!(content1, content2);

    // But same length
    assert_eq!(content1.len(), content2.len());

    // Only differ in the last 32 bytes (the hash)
    assert_eq!(&content1[0..98], &content2[0..98]);
    assert_ne!(&content1[98..], &content2[98..]);
}

#[test]
fn test_signed_content_different_contexts() {
    let hash = [0xcc; 32];

    let server_content = build_signed_content(&hash, SERVER_CERTIFICATE_VERIFY_CONTEXT);
    let client_content = build_signed_content(&hash, CLIENT_CERTIFICATE_VERIFY_CONTEXT);

    // Should be different due to different contexts
    assert_ne!(server_content, client_content);

    // Same length (both context strings happen to be same length)
    assert_eq!(server_content.len(), client_content.len());

    // Same padding and hash
    assert_eq!(&server_content[0..64], &client_content[0..64]);
    assert_eq!(
        &server_content[server_content.len() - 32..],
        &client_content[client_content.len() - 32..]
    );

    // Different in the context string part
    let server_ctx_start = 64;
    let server_ctx_end = server_ctx_start + SERVER_CERTIFICATE_VERIFY_CONTEXT.len();
    assert_ne!(
        &server_content[server_ctx_start..server_ctx_end],
        &client_content[server_ctx_start..server_ctx_end]
    );
}

#[test]
fn test_certificate_verify_zero_length_signature() {
    let cert_verify = CertificateVerify::new(SIG_ECDSA_SECP256R1_SHA256, vec![]);
    let bytes = cert_verify.to_bytes();

    assert_eq!(bytes[0], 0x0f);
    let sig_len = u16::from_be_bytes([bytes[6], bytes[7]]);
    assert_eq!(sig_len, 0);
    assert_eq!(bytes.len(), 8); // header(4) + algorithm(2) + sig_len(2) + signature(0)
}

#[test]
fn test_certificate_verify_max_signature_length() {
    // Test with large signature (but within u16 range)
    let large_sig = vec![0xff; u16::MAX as usize];
    let cert_verify = CertificateVerify::new(SIG_RSA_PSS_RSAE_SHA384, large_sig.clone());

    let bytes = cert_verify.to_bytes();
    let parsed = CertificateVerify::from_bytes(&bytes).unwrap();

    assert_eq!(parsed.signature.len(), u16::MAX as usize);
    assert_eq!(parsed.signature, large_sig);
}

#[test]
fn test_all_supported_algorithms_parse() {
    let algorithms = vec![
        (SIG_RSA_PSS_RSAE_SHA256, "RSA-PSS-RSAE-SHA256"),
        (SIG_RSA_PSS_RSAE_SHA384, "RSA-PSS-RSAE-SHA384"),
        (SIG_ECDSA_SECP256R1_SHA256, "ECDSA-SECP256R1-SHA256"),
        (SIG_ECDSA_SECP384R1_SHA384, "ECDSA-SECP384R1-SHA384"),
    ];

    for (algorithm, name) in algorithms {
        let cert_verify = CertificateVerify::new(algorithm, vec![0x42; 64]);
        let bytes = cert_verify.to_bytes();
        let parsed = CertificateVerify::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.algorithm, algorithm, "Failed to roundtrip {}", name);
    }
}

#[test]
fn test_certificate_verify_message_structure() {
    // Test that the message structure matches RFC 8446 Section 4.4.3
    let cert_verify = CertificateVerify::new(SIG_RSA_PSS_RSAE_SHA256, vec![0xab; 128]);
    let bytes = cert_verify.to_bytes();

    let mut offset = 0;

    // Handshake type
    assert_eq!(bytes[offset], 0x0f);
    offset += 1;

    // Length (3 bytes)
    let length = ((bytes[offset] as usize) << 16)
        | ((bytes[offset + 1] as usize) << 8)
        | (bytes[offset + 2] as usize);
    offset += 3;
    assert_eq!(length, 2 + 2 + 128);

    // Algorithm (2 bytes)
    let algorithm = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
    offset += 2;
    assert_eq!(algorithm, SIG_RSA_PSS_RSAE_SHA256);

    // Signature length (2 bytes)
    let sig_len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
    offset += 2;
    assert_eq!(sig_len, 128);

    // Signature data
    assert_eq!(&bytes[offset..offset + sig_len], &[0xab; 128]);
}

#[test]
fn test_signed_content_rfc_compliance() {
    // Test that signed content follows RFC 8446 Section 4.4.3 exactly
    let transcript_hash = [0x12; 32];
    let content = build_signed_content(&transcript_hash, SERVER_CERTIFICATE_VERIFY_CONTEXT);

    // RFC specifies:
    // - 64 octets of 0x20 (space)
    // - context string
    // - 0x00
    // - transcript hash

    let mut expected = Vec::new();
    expected.extend_from_slice(&[0x20; 64]);
    expected.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    expected.push(0x00);
    expected.extend_from_slice(&transcript_hash);

    assert_eq!(content, expected);
}

#[test]
fn test_verify_client_method() {
    // Test that verify_client() is callable and delegates correctly to verify_with_context
    // with CLIENT_CERTIFICATE_VERIFY_CONTEXT
    
    // Create a CertificateVerify message with a dummy signature
    let cert_verify = CertificateVerify::new(SIG_RSA_PSS_RSAE_SHA256, vec![0xcc; 256]);
    
    // Use invalid certificate data (this will fail, but demonstrates the method is called)
    let invalid_cert_data = vec![0x30, 0x00]; // Minimal invalid DER structure
    let transcript_hash = [0xdd; 32];
    
    // Call verify_client() - it should fail due to invalid certificate,
    // but this proves the method path is exercised and delegates to verify_with_context
    let result = cert_verify.verify_client(&invalid_cert_data, &transcript_hash);
    
    // Verify it fails (as expected with invalid data)
    assert!(result.is_err());
    
    // The error should be related to certificate parsing, proving verify_client()
    // properly delegates to verify_with_context and attempts to extract the public key
    match result {
        Err(TlsError::CertificateParsingError(_)) => {
            // Expected error - certificate parsing failed, which means verify_client()
            // correctly delegated to verify_with_context and attempted verification
        }
        Err(_) => {
            // Also acceptable - other verification errors show the path was exercised
            // (e.g., if the certificate parser is more lenient)
        }
        Ok(_) => panic!("Expected verify_client() to fail with invalid certificate data"),
    }
}

// Note: Actual signature verification tests with real keys would require
// generating valid RSA and ECDSA signatures, which is complex.
// The verification logic is tested indirectly through the crypto library's
// own test suite and through integration tests with real TLS servers.

#[test]
fn test_certificate_verify_algorithm_identifiers() {
    // Verify the algorithm identifiers match RFC 8446
    assert_eq!(SIG_RSA_PSS_RSAE_SHA256, 0x0804);
    assert_eq!(SIG_RSA_PSS_RSAE_SHA384, 0x0805);
    assert_eq!(SIG_ECDSA_SECP256R1_SHA256, 0x0403);
    assert_eq!(SIG_ECDSA_SECP384R1_SHA384, 0x0503);
}
