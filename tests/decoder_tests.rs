use tls_protocol::{decode_header, TlsError};
use std::convert::TryFrom;

// Mock types for testing (same as parser_tests.rs)
// These will be replaced with actual types when Issue #1 is merged
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TestContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

impl TryFrom<u8> for TestContentType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            20 => Ok(TestContentType::ChangeCipherSpec),
            21 => Ok(TestContentType::Alert),
            22 => Ok(TestContentType::Handshake),
            23 => Ok(TestContentType::ApplicationData),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct TestRecordHeader {
    content_type: TestContentType,
    version: u16,
    length: u16,
}

impl From<(TestContentType, u16, u16)> for TestRecordHeader {
    fn from((content_type, version, length): (TestContentType, u16, u16)) -> Self {
        Self {
            content_type,
            version,
            length,
        }
    }
}

// Tests for decode_header function

#[test]
fn test_decode_valid_handshake_header() {
    // Valid TLS 1.3 handshake record header
    // Content type: 22 (Handshake)
    // Version: 0x0303 (TLS 1.2/1.3)
    // Length: 5 bytes
    let buffer = vec![0x16, 0x03, 0x03, 0x00, 0x05];

    let result: Result<TestRecordHeader, TlsError> = decode_header(&buffer);
    assert!(result.is_ok());
    
    let header = result.unwrap();
    assert_eq!(header.content_type, TestContentType::Handshake);
    assert_eq!(header.version, 0x0303);
    assert_eq!(header.length, 5);
}

#[test]
fn test_decode_short_read_empty_buffer() {
    // Empty buffer - should return IncompleteData
    // This tests the key feature of decode_header: handling short reads
    let buffer: Vec<u8> = vec![];
    
    let result: Result<TestRecordHeader, TlsError> = decode_header(&buffer);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), TlsError::IncompleteData);
}

#[test]
fn test_decode_short_read_one_byte() {
    // Only 1 byte - not enough for a header
    let buffer = vec![0x16];
    
    let result: Result<TestRecordHeader, TlsError> = decode_header(&buffer);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), TlsError::IncompleteData);
}

#[test]
fn test_decode_short_read_two_bytes() {
    // Only 2 bytes - not enough for a header
    let buffer = vec![0x16, 0x03];
    
    let result: Result<TestRecordHeader, TlsError> = decode_header(&buffer);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), TlsError::IncompleteData);
}

#[test]
fn test_decode_short_read_three_bytes() {
    // Only 3 bytes - not enough for a header
    let buffer = vec![0x16, 0x03, 0x03];
    
    let result: Result<TestRecordHeader, TlsError> = decode_header(&buffer);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), TlsError::IncompleteData);
}

#[test]
fn test_decode_short_read_four_bytes() {
    // Only 4 bytes - still not enough (need 5)
    let buffer = vec![0x16, 0x03, 0x03, 0x00];
    
    let result: Result<TestRecordHeader, TlsError> = decode_header(&buffer);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), TlsError::IncompleteData);
}

#[test]
fn test_decode_valid_application_data_header() {
    // Valid application data record
    // Content type: 23 (ApplicationData)
    // Version: 0x0303
    // Length: 1024 bytes
    let buffer = vec![0x17, 0x03, 0x03, 0x04, 0x00];
    
    let result: Result<TestRecordHeader, TlsError> = decode_header(&buffer);
    assert!(result.is_ok());
    
    let header = result.unwrap();
    assert_eq!(header.content_type, TestContentType::ApplicationData);
    assert_eq!(header.version, 0x0303);
    assert_eq!(header.length, 1024);
}

#[test]
fn test_decode_buffer_with_extra_bytes() {
    // Buffer with more than 5 bytes (should still decode successfully)
    // The extra bytes would be the record payload in a real scenario
    let buffer = vec![0x16, 0x03, 0x03, 0x00, 0x05, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
    
    let result: Result<TestRecordHeader, TlsError> = decode_header(&buffer);
    assert!(result.is_ok());
    
    let header = result.unwrap();
    assert_eq!(header.content_type, TestContentType::Handshake);
    assert_eq!(header.length, 5);
}

#[test]
fn test_decode_alert_header() {
    // Valid alert record
    // Content type: 21 (Alert)
    // Version: 0x0303
    // Length: 2 bytes (typical alert size)
    let buffer = vec![0x15, 0x03, 0x03, 0x00, 0x02];
    
    let result: Result<TestRecordHeader, TlsError> = decode_header(&buffer);
    assert!(result.is_ok());
    
    let header = result.unwrap();
    assert_eq!(header.content_type, TestContentType::Alert);
    assert_eq!(header.version, 0x0303);
    assert_eq!(header.length, 2);
}

#[test]
fn test_decode_change_cipher_spec() {
    // ChangeCipherSpec record (content type 20)
    let buffer = vec![0x14, 0x03, 0x03, 0x00, 0x01];
    
    let result: Result<TestRecordHeader, TlsError> = decode_header(&buffer);
    assert!(result.is_ok());
    
    let header = result.unwrap();
    assert_eq!(header.content_type, TestContentType::ChangeCipherSpec);
    assert_eq!(header.length, 1);
}

#[test]
fn test_decode_invalid_content_type() {
    // Invalid content type (50) - not in valid range
    let buffer = vec![0x32, 0x03, 0x03, 0x00, 0x05];
    
    let result: Result<TestRecordHeader, TlsError> = decode_header(&buffer);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), TlsError::InvalidContentType(0x32));
}

#[test]
fn test_decode_invalid_version_tls10() {
    // TLS 1.0 (0x0301) - should be rejected
    let buffer = vec![0x16, 0x03, 0x01, 0x00, 0x05];
    
    let result: Result<TestRecordHeader, TlsError> = decode_header(&buffer);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), TlsError::InvalidVersion(0x0301));
}

#[test]
fn test_decode_invalid_version_tls11() {
    // TLS 1.1 (0x0302) - should be rejected
    let buffer = vec![0x16, 0x03, 0x02, 0x00, 0x05];
    
    let result: Result<TestRecordHeader, TlsError> = decode_header(&buffer);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), TlsError::InvalidVersion(0x0302));
}

#[test]
fn test_decode_invalid_version_unknown() {
    // Unknown version (0x0304) - should be rejected
    let buffer = vec![0x16, 0x03, 0x04, 0x00, 0x05];
    
    let result: Result<TestRecordHeader, TlsError> = decode_header(&buffer);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), TlsError::InvalidVersion(0x0304));
}

#[test]
fn test_decode_invalid_length_too_large() {
    // Length > 16384 (RFC maximum)
    // 0x4001 = 16385 bytes
    let buffer = vec![0x16, 0x03, 0x03, 0x40, 0x01];
    
    let result: Result<TestRecordHeader, TlsError> = decode_header(&buffer);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), TlsError::InvalidLength(16385));
}

#[test]
fn test_decode_valid_max_length() {
    // Maximum valid length: 16384 bytes (0x4000)
    let buffer = vec![0x16, 0x03, 0x03, 0x40, 0x00];
    
    let result: Result<TestRecordHeader, TlsError> = decode_header(&buffer);
    assert!(result.is_ok());
    
    let header = result.unwrap();
    assert_eq!(header.length, 16384);
}

#[test]
fn test_decode_zero_length() {
    // Zero-length record (edge case, but valid per spec)
    let buffer = vec![0x16, 0x03, 0x03, 0x00, 0x00];
    
    let result: Result<TestRecordHeader, TlsError> = decode_header(&buffer);
    assert!(result.is_ok());
    
    let header = result.unwrap();
    assert_eq!(header.length, 0);
}
