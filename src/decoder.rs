use crate::error::TlsError;
use crate::parser::parse_header;
use std::convert::TryFrom;

/// Decode a TLS record header from a byte stream
///
/// This is a convenience wrapper around `parse_header` that provides a more
/// semantically appropriate name for stream reading use cases. Both functions
/// perform identical validation including buffer length checks.
///
/// # Arguments
/// * `src` - A slice of bytes from a stream/buffer
///
/// # Returns
/// * `Ok(RecordHeader)` if decoding and validation succeed
/// * `Err(TlsError::IncompleteData)` if buffer has fewer than 5 bytes
/// * `Err(TlsError)` for other validation errors (invalid version, content type, length)
///
/// # Example Usage
/// ```ignore
/// let buffer = vec![0x16, 0x03, 0x03, 0x00, 0x05];
/// match decode_header::<ContentType, RecordHeader>(&buffer) {
///     Ok(header) => println!("Successfully decoded header"),
///     Err(TlsError::IncompleteData) => println!("Need more bytes"),
///     Err(e) => println!("Validation error: {}", e),
/// }
/// ```
///
/// # Note
/// This function delegates directly to `parse_header` for all validation logic,
/// including buffer length checks and protocol validation.
pub fn decode_header<ContentType, RecordHeader>(
    src: &[u8],
) -> Result<RecordHeader, TlsError>
where
    ContentType: TryFrom<u8>,
    RecordHeader: From<(ContentType, u16, u16)>,
{
    // Delegate to parse_header for all parsing and validation logic.
    // parse_header handles buffer length checks, version validation,
    // content type validation, and length validation.
    parse_header::<ContentType, RecordHeader>(src)
}
