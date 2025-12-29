use crate::error::TlsError;
use std::convert::TryFrom;

// Note: This module assumes ContentType and RecordHeader are defined elsewhere
// (from branch 1's implementation). The types are imported when both branches are merged.

/// Parse a TLS record header from raw bytes (TLS 1.2 and TLS 1.3 only)
///
/// # Arguments
/// * `bytes` - A slice of bytes containing at least 5 bytes for the header
///
/// # Returns
/// * `Ok(RecordHeader)` if parsing succeeds
/// * `Err(TlsError)` if validation fails
///
/// # Validation
/// - Ensures at least 5 bytes are available
/// - Validates version is exactly 0x0303 (used by both TLS 1.2 and TLS 1.3)
/// - Validates ContentType is within valid range
/// - Validates length is reasonable (0-16384 bytes, as per RFC 8446)
///
/// # Important Notes
/// - **TLS 1.2**: Uses 0x0303 as the protocol version
/// - **TLS 1.3**: Also uses 0x0303 in record headers (legacy_record_version per RFC 8446)
/// - The actual TLS 1.3 version negotiation happens in handshake messages, not here
/// - TLS 1.0 (0x0301) and TLS 1.1 (0x0302) are **rejected** (deprecated and insecure)
pub fn parse_header<ContentType, RecordHeader>(bytes: &[u8]) -> Result<RecordHeader, TlsError>
where
    ContentType: TryFrom<u8>,
    RecordHeader: From<(ContentType, u16, u16)>,
{
    // Check if we have enough bytes for a header (5 bytes minimum)
    if bytes.len() < 5 {
        return Err(TlsError::IncompleteData);
    }

    // Parse content type (1 byte)
    let content_type = ContentType::try_from(bytes[0]).map_err(|_| TlsError::InvalidContentType)?;

    // Parse version (2 bytes, big-endian)
    let version = u16::from_be_bytes([bytes[1], bytes[2]]);

    // Validate version - Only accept 0x0303 (TLS 1.2/1.3)
    // TLS 1.0 and 1.1 are deprecated and rejected for security
    if version != 0x0303 {
        return Err(TlsError::InvalidVersion);
    }

    // Parse length (2 bytes, big-endian)
    let length = u16::from_be_bytes([bytes[3], bytes[4]]);

    // Validate length - RFC 8446 specifies maximum of 2^14 (16384) bytes
    if length > 16384 {
        return Err(TlsError::InvalidLength);
    }
    Ok(RecordHeader::from((content_type, version, length)))
}
