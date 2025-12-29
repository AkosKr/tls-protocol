use std::convert::TryFrom;
use tls_protocol::{parse_header, TlsError};

// Mock types for testing (mimicking the structure from branch 1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TestContentType {
<<<<<<< HEAD
    ChangeCipherSpec = 20,
=======
    ChangeChiperSpec = 20,
>>>>>>> b1e6f03 (Feature: implement TLS record header validation and parsing (issue #2))
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

impl TryFrom<u8> for TestContentType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
<<<<<<< HEAD
            20 => Ok(TestContentType::ChangeCipherSpec),
=======
            20 => Ok(TestContentType::ChangeChiperSpec),
>>>>>>> b1e6f03 (Feature: implement TLS record header validation and parsing (issue #2))
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

#[test]
fn test_parse_valid_header() {
    // Valid handshake record: type=22, version=0x0303, length=100
    let bytes = vec![22, 0x03, 0x03, 0x00, 0x64];
    let result: Result<TestRecordHeader, TlsError> = parse_header(&bytes);

    assert!(result.is_ok());
    let header = result.unwrap();
    assert_eq!(header.content_type, TestContentType::Handshake);
    assert_eq!(header.version, 0x0303);
    assert_eq!(header.length, 100);
}

#[test]
fn test_parse_application_data() {
    // Valid application data record: type=23, version=0x0303, length=1024
    let bytes = vec![23, 0x03, 0x03, 0x04, 0x00];
    let result: Result<TestRecordHeader, TlsError> = parse_header(&bytes);

    assert!(result.is_ok());
    let header = result.unwrap();
    assert_eq!(header.content_type, TestContentType::ApplicationData);
    assert_eq!(header.length, 1024);
}

#[test]
fn test_parse_alert() {
    // Valid alert record: type=21, version=0x0303, length=2
    let bytes = vec![21, 0x03, 0x03, 0x00, 0x02];
    let result: Result<TestRecordHeader, TlsError> = parse_header(&bytes);

    assert!(result.is_ok());
    let header = result.unwrap();
    assert_eq!(header.content_type, TestContentType::Alert);
    assert_eq!(header.length, 2);
}

#[test]
fn test_parse_incomplete_data() {
    // Only 4 bytes - not enough for a complete header
    let bytes = vec![22, 0x03, 0x03, 0x00];
    let result: Result<TestRecordHeader, TlsError> = parse_header(&bytes);

    assert_eq!(result, Err(TlsError::IncompleteData));
}

#[test]
fn test_parse_empty_data() {
    let bytes = vec![];
    let result: Result<TestRecordHeader, TlsError> = parse_header(&bytes);

    assert_eq!(result, Err(TlsError::IncompleteData));
}

#[test]
fn test_parse_invalid_version() {
    // Invalid version: 0x0304 (should be 0x0303)
    let bytes = vec![22, 0x03, 0x04, 0x00, 0x64];
    let result: Result<TestRecordHeader, TlsError> = parse_header(&bytes);

<<<<<<< HEAD
    assert_eq!(result, Err(TlsError::InvalidVersion(0x0304)));
=======
    assert_eq!(result, Err(TlsError::InvalidVersion));
>>>>>>> b1e6f03 (Feature: implement TLS record header validation and parsing (issue #2))
}

#[test]
fn test_parse_invalid_version_too_old() {
    // Invalid version: 0x0301 (TLS 1.0)
    let bytes = vec![22, 0x03, 0x01, 0x00, 0x64];
    let result: Result<TestRecordHeader, TlsError> = parse_header(&bytes);

<<<<<<< HEAD
    assert_eq!(result, Err(TlsError::InvalidVersion(0x0301)));
=======
    assert_eq!(result, Err(TlsError::InvalidVersion));
>>>>>>> b1e6f03 (Feature: implement TLS record header validation and parsing (issue #2))
}

#[test]
fn test_parse_invalid_content_type() {
    // Invalid content type: 99 (not in valid range)
    let bytes = vec![99, 0x03, 0x03, 0x00, 0x64];
    let result: Result<TestRecordHeader, TlsError> = parse_header(&bytes);

<<<<<<< HEAD
    assert_eq!(result, Err(TlsError::InvalidContentType(99)));
=======
    assert_eq!(result, Err(TlsError::InvalidContentType));
>>>>>>> b1e6f03 (Feature: implement TLS record header validation and parsing (issue #2))
}

#[test]
fn test_parse_invalid_length_too_large() {
    // Length exceeds maximum: 16385 bytes (0x4001)
    let bytes = vec![22, 0x03, 0x03, 0x40, 0x01];
    let result: Result<TestRecordHeader, TlsError> = parse_header(&bytes);

<<<<<<< HEAD
    assert_eq!(result, Err(TlsError::InvalidLength(16385)));
=======
    assert_eq!(result, Err(TlsError::InvalidLength));
>>>>>>> b1e6f03 (Feature: implement TLS record header validation and parsing (issue #2))
}

#[test]
fn test_parse_max_valid_length() {
    // Maximum valid length: 16384 bytes (0x4000)
    let bytes = vec![22, 0x03, 0x03, 0x40, 0x00];
    let result: Result<TestRecordHeader, TlsError> = parse_header(&bytes);

    assert!(result.is_ok());
    let header = result.unwrap();
    assert_eq!(header.length, 16384);
}

#[test]
fn test_parse_zero_length() {
    // Zero length is technically valid
    let bytes = vec![22, 0x03, 0x03, 0x00, 0x00];
    let result: Result<TestRecordHeader, TlsError> = parse_header(&bytes);

    assert!(result.is_ok());
    let header = result.unwrap();
    assert_eq!(header.length, 0);
}

#[test]
<<<<<<< HEAD
fn test_parse_rejects_unknown_version() {
    // Reject unknown/unsupported TLS version 0x0305
    let bytes = vec![22, 0x03, 0x05, 0x00, 0x64];
    let result: Result<TestRecordHeader, TlsError> = parse_header(&bytes);

    assert_eq!(result, Err(TlsError::InvalidVersion(0x0305)));
=======
fn test_parse_rejects_tls10() {
    // Reject TLS 1.0 (0x0301) - deprecated and insecure
    let bytes = vec![22, 0x03, 0x01, 0x00, 0x64];
    let result: Result<TestRecordHeader, TlsError> = parse_header(&bytes);

    assert_eq!(result, Err(TlsError::InvalidVersion));
>>>>>>> b1e6f03 (Feature: implement TLS record header validation and parsing (issue #2))
}

#[test]
fn test_parse_rejects_tls11() {
    // Reject TLS 1.1 (0x0302) - deprecated and insecure
    let bytes = vec![22, 0x03, 0x02, 0x00, 0x64];
    let result: Result<TestRecordHeader, TlsError> = parse_header(&bytes);

<<<<<<< HEAD
    assert_eq!(result, Err(TlsError::InvalidVersion(0x0302)));
=======
    assert_eq!(result, Err(TlsError::InvalidVersion));
>>>>>>> b1e6f03 (Feature: implement TLS record header validation and parsing (issue #2))
}

#[test]
fn test_parse_accepts_tls12_tls13() {
    // Accept 0x0303 (used by both TLS 1.2 and TLS 1.3)
    let bytes = vec![22, 0x03, 0x03, 0x00, 0x64];
    let result: Result<TestRecordHeader, TlsError> = parse_header(&bytes);

    assert!(result.is_ok());
    let header = result.unwrap();
    assert_eq!(header.version, 0x0303);
}
<<<<<<< HEAD
=======

#[test]
fn test_parse_rejects_tls13_indicator() {
    // Reject 0x0304 - TLS 1.3 records must use 0x0303, not 0x0304
    let bytes = vec![22, 0x03, 0x04, 0x00, 0x64];
    let result: Result<TestRecordHeader, TlsError> = parse_header(&bytes);

    assert_eq!(result, Err(TlsError::InvalidVersion));
}
>>>>>>> b1e6f03 (Feature: implement TLS record header validation and parsing (issue #2))
