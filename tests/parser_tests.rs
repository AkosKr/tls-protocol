use tls_protocol::{parse_header, ContentType, RecordHeader, TlsError};

#[test]
fn test_parse_valid_header() {
    // Valid handshake record: type=22, version=0x0303, length=100
    let bytes = vec![22, 0x03, 0x03, 0x00, 0x64];
    let result: Result<RecordHeader, TlsError> = parse_header(&bytes);

    assert!(result.is_ok());
    let header = result.unwrap();
    assert_eq!(header.content_type, ContentType::Handshake);
    assert_eq!(header.version, 0x0303);
    assert_eq!(header.length, 100);
}

#[test]
fn test_parse_application_data() {
    // Valid application data record: type=23, version=0x0303, length=1024
    let bytes = vec![23, 0x03, 0x03, 0x04, 0x00];
    let result: Result<RecordHeader, TlsError> = parse_header(&bytes);

    assert!(result.is_ok());
    let header = result.unwrap();
    assert_eq!(header.content_type, ContentType::ApplicationData);
    assert_eq!(header.length, 1024);
}

#[test]
fn test_parse_alert() {
    // Valid alert record: type=21, version=0x0303, length=2
    let bytes = vec![21, 0x03, 0x03, 0x00, 0x02];
    let result: Result<RecordHeader, TlsError> = parse_header(&bytes);

    assert!(result.is_ok());
    let header = result.unwrap();
    assert_eq!(header.content_type, ContentType::Alert);
    assert_eq!(header.length, 2);
}

#[test]
fn test_parse_incomplete_data() {
    // Only 4 bytes - not enough for a complete header
    let bytes = vec![22, 0x03, 0x03, 0x00];
    let result: Result<RecordHeader, TlsError> = parse_header(&bytes);

    assert_eq!(result, Err(TlsError::IncompleteData));
}

#[test]
fn test_parse_empty_data() {
    let bytes = vec![];
    let result: Result<RecordHeader, TlsError> = parse_header(&bytes);

    assert_eq!(result, Err(TlsError::IncompleteData));
}

#[test]
fn test_parse_invalid_version() {
    // Invalid version: 0x0304 (should be 0x0303)
    let bytes = vec![22, 0x03, 0x04, 0x00, 0x64];
    let result: Result<RecordHeader, TlsError> = parse_header(&bytes);

    assert_eq!(result, Err(TlsError::InvalidVersion(0x0304)));
}

#[test]
fn test_parse_invalid_version_too_old() {
    // Invalid version: 0x0301 (TLS 1.0)
    let bytes = vec![22, 0x03, 0x01, 0x00, 0x64];
    let result: Result<RecordHeader, TlsError> = parse_header(&bytes);

    assert_eq!(result, Err(TlsError::InvalidVersion(0x0301)));
}

#[test]
fn test_parse_invalid_content_type() {
    // Invalid content type: 99 (not in valid range)
    let bytes = vec![99, 0x03, 0x03, 0x00, 0x64];
    let result: Result<RecordHeader, TlsError> = parse_header(&bytes);

    assert_eq!(result, Err(TlsError::InvalidContentType(99)));
}

#[test]
fn test_parse_invalid_length_too_large() {
    // Length exceeds maximum: 16385 bytes (0x4001)
    let bytes = vec![22, 0x03, 0x03, 0x40, 0x01];
    let result: Result<RecordHeader, TlsError> = parse_header(&bytes);

    assert_eq!(result, Err(TlsError::InvalidLength(16385)));
}

#[test]
fn test_parse_max_valid_length() {
    // Maximum valid length: 16384 bytes (0x4000)
    let bytes = vec![22, 0x03, 0x03, 0x40, 0x00];
    let result: Result<RecordHeader, TlsError> = parse_header(&bytes);

    assert!(result.is_ok());
    let header = result.unwrap();
    assert_eq!(header.length, 16384);
}

#[test]
fn test_parse_zero_length() {
    // Zero length is technically valid
    let bytes = vec![22, 0x03, 0x03, 0x00, 0x00];
    let result: Result<RecordHeader, TlsError> = parse_header(&bytes);

    assert!(result.is_ok());
    let header = result.unwrap();
    assert_eq!(header.length, 0);
}

#[test]
fn test_parse_rejects_unknown_version() {
    // Reject unknown/unsupported TLS version 0x0305
    let bytes = vec![22, 0x03, 0x05, 0x00, 0x64];
    let result: Result<RecordHeader, TlsError> = parse_header(&bytes);

    assert_eq!(result, Err(TlsError::InvalidVersion(0x0305)));
}

#[test]
fn test_parse_rejects_tls11() {
    // Reject TLS 1.1 (0x0302) - deprecated and insecure
    let bytes = vec![22, 0x03, 0x02, 0x00, 0x64];
    let result: Result<RecordHeader, TlsError> = parse_header(&bytes);

    assert_eq!(result, Err(TlsError::InvalidVersion(0x0302)));
}

#[test]
fn test_parse_accepts_tls12_tls13() {
    // Accept 0x0303 (used by both TLS 1.2 and TLS 1.3)
    let bytes = vec![22, 0x03, 0x03, 0x00, 0x64];
    let result: Result<RecordHeader, TlsError> = parse_header(&bytes);

    assert!(result.is_ok());
    let header = result.unwrap();
    assert_eq!(header.version, 0x0303);
}
