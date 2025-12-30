use crate::error::TlsError;
use crate::parser::parse_header;
use std::convert::TryFrom;

/// Decode a TLS record header from a byte stream
///
/// This function is designed to handle stream reading scenarios where the buffer
/// might not contain a complete header. It safely checks for sufficient bytes
/// before attempting to parse the header.
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
/// # Short Reads
/// This function explicitly handles "short reads" by returning `IncompleteData`
/// when the buffer contains fewer than 5 bytes (the minimum TLS record header size).
pub fn decode_header<ContentType, RecordHeader>(
    src: &[u8],
) -> Result<RecordHeader, TlsError>
where
    ContentType: TryFrom<u8>,
    RecordHeader: From<(ContentType, u16, u16)>,
{
    // Check if we have enough bytes for a complete header (5 bytes minimum)
    // This is the key difference from parse_header - we handle short reads
    if src.len() < 5 {
        return Err(TlsError::IncompleteData);
    }

    // Delegate to parse_header for actual parsing and validation
    // This maintains separation of concerns:
    // - decode_header: handles buffer length checking (stream reading concern)
    // - parse_header: handles validation logic (protocol correctness concern)
    parse_header::<ContentType, RecordHeader>(src)
}
