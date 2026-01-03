use std::convert::TryFrom;

/// Represents the content type of a TLS record as defined in RFC 8446 (TLS 1.3).
///
/// The content type indicates the higher-level protocol being encapsulated within
/// a TLS record layer message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    /// Invalid content type (value 0). Not used in valid TLS records.
    Invalid = 0,
    /// Change Cipher Spec protocol (value 20).
    /// Used for backward compatibility with TLS 1.2 and earlier.
    ChangeCipherSpec = 20,
    /// Alert protocol (value 21). Used to communicate error conditions or warnings.
    Alert = 21,
    /// Handshake protocol (value 22). Used during the TLS handshake phase.
    Handshake = 22,
    /// Application Data protocol (value 23). Used for encrypted application data.
    ApplicationData = 23,
}

impl From<ContentType> for u8 {
    /// Converts a `ContentType` to its corresponding byte value.
    ///
    /// # Examples
    ///
    /// ```
    /// # use tls_protocol::ContentType;
    /// assert_eq!(u8::from(ContentType::Handshake), 22);
    /// ```
    fn from(content_type: ContentType) -> Self {
        content_type as u8
    }
}

impl TryFrom<u8> for ContentType {
    type Error = ();

    /// Attempts to convert a byte value to a `ContentType`.
    ///
    /// # Returns
    ///
    /// - `Ok(ContentType)` if the byte corresponds to a valid content type (20, 21, 22, or 23)
    /// - `Err(())` if the byte is not a recognized content type
    ///
    /// # Examples
    ///
    /// ```
    /// # use tls_protocol::ContentType;
    /// # use std::convert::TryFrom;
    /// assert_eq!(ContentType::try_from(22), Ok(ContentType::Handshake));
    /// assert_eq!(ContentType::try_from(99), Err(()));
    /// ```
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(ContentType::Invalid),
            20 => Ok(ContentType::ChangeCipherSpec),
            21 => Ok(ContentType::Alert),
            22 => Ok(ContentType::Handshake),
            23 => Ok(ContentType::ApplicationData),
            _ => Err(()),
        }
    }
}

/// Represents a TLS record header as defined in RFC 8446 (TLS 1.3).
///
/// The record header is a 5-byte structure that precedes every TLS record.
/// It contains metadata about the record's content type, protocol version, and payload length.
///
/// # Structure
///
/// - Byte 0: Content type (1 byte)
/// - Bytes 1-2: Protocol version (2 bytes, big-endian)
/// - Bytes 3-4: Length of the record payload (2 bytes, big-endian)
///
/// # Protocol Versions
///
/// Common version values:
/// - `0x0303`: TLS 1.2
/// - `0x0304`: TLS 1.3
///
/// Note: In TLS 1.3, the legacy_record_version field should be set to `0x0303` for
/// compatibility, except for the initial ClientHello.
#[derive(Debug, Clone, Copy)]
pub struct RecordHeader {
    /// The type of content in this record (e.g., Handshake, ApplicationData)
    pub content_type: ContentType,
    /// The protocol version. For TLS 1.3, this is typically `0x0303` for compatibility.
    pub version: u16,
    /// The length of the record payload in bytes. Must not exceed 2^14 + 256 (16640 bytes).
    pub length: u16,
}

impl RecordHeader {
    /// Creates a new `RecordHeader` with the specified parameters.
    ///
    /// # Arguments
    ///
    /// * `content_type` - The type of content in this record
    /// * `version` - The TLS protocol version (e.g., `0x0303` for TLS 1.2/1.3 compatibility)
    /// * `length` - The length of the record payload in bytes
    ///
    /// # Returns
    ///
    /// - `Some(RecordHeader)` if the length is valid (0 to 16640 bytes)
    /// - `None` if the length exceeds the maximum allowed value (2^14 + 256 = 16640 bytes)
    ///
    /// # Examples
    ///
    /// ```
    /// # use tls_protocol::{RecordHeader, ContentType};
    /// let header = RecordHeader::new(ContentType::Handshake, 0x0303, 512);
    /// assert!(header.is_some());
    ///
    /// let invalid_header = RecordHeader::new(ContentType::Handshake, 0x0303, 20000);
    /// assert!(invalid_header.is_none());
    /// ```
    pub fn new(content_type: ContentType, version: u16, length: u16) -> Option<Self> {
        const MAX_LENGTH: u16 = (1 << 14) + 256; // 2^14 + 256 = 16640 (TLS maximum record size)

        if length > MAX_LENGTH {
            return None;
        }

        Some(Self {
            content_type,
            version,
            length,
        })
    }

    /// Serializes the record header to a 5-byte array.
    ///
    /// # Returns
    ///
    /// A 5-byte array containing:
    /// - Byte 0: Content type
    /// - Bytes 1-2: Protocol version (big-endian)
    /// - Bytes 3-4: Payload length (big-endian)
    ///
    /// # Examples
    ///
    /// ```
    /// # use tls_protocol::{RecordHeader, ContentType};
    /// let header = RecordHeader::new(ContentType::Handshake, 0x0303, 512).unwrap();
    /// let bytes = header.to_bytes();
    /// assert_eq!(bytes, [22, 3, 3, 2, 0]);
    /// ```
    pub fn to_bytes(&self) -> [u8; 5] {
        let mut bytes = [0u8; 5];
        bytes[0] = u8::from(self.content_type);
        bytes[1] = (self.version >> 8) as u8;
        bytes[2] = (self.version & 0xFF) as u8;
        bytes[3] = (self.length >> 8) as u8;
        bytes[4] = (self.length & 0xFF) as u8;
        bytes
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_header_to_bytes() {
        let high_header = RecordHeader::new(ContentType::Handshake, 0x0303, 512).unwrap();
        let high_edge_header = RecordHeader::new(ContentType::Handshake, 0x0303, 16640).unwrap();
        let low_header = RecordHeader::new(ContentType::Handshake, 0x0303, 128).unwrap();
        let low_edge_header = RecordHeader::new(ContentType::Handshake, 0x0303, 0).unwrap();

        let high_bytes = high_header.to_bytes();
        let high_edge_bytes = high_edge_header.to_bytes();
        let low_bytes = low_header.to_bytes();
        let low_edge_bytes = low_edge_header.to_bytes();

        assert_eq!(high_bytes, [22, 3, 3, 2, 0]);
        assert_eq!(high_edge_bytes, [22, 3, 3, 65, 0]);
        assert_eq!(low_bytes, [22, 3, 3, 0, 128]);
        assert_eq!(low_edge_bytes, [22, 3, 3, 0, 0]);
    }

    #[test]
    fn test_content_type_from_u8() {
        assert_eq!(ContentType::try_from(0), Ok(ContentType::Invalid));
        assert_eq!(ContentType::try_from(20), Ok(ContentType::ChangeCipherSpec));
        assert_eq!(ContentType::try_from(21), Ok(ContentType::Alert));
        assert_eq!(ContentType::try_from(22), Ok(ContentType::Handshake));
        assert_eq!(ContentType::try_from(23), Ok(ContentType::ApplicationData));
        assert_eq!(ContentType::try_from(99), Err(()));
    }

    #[test]
    fn test_u8_from_content_type() {
        assert_eq!(u8::from(ContentType::Invalid), 0);
        assert_eq!(u8::from(ContentType::ChangeCipherSpec), 20);
        assert_eq!(u8::from(ContentType::Alert), 21);
        assert_eq!(u8::from(ContentType::Handshake), 22);
        assert_eq!(u8::from(ContentType::ApplicationData), 23);
    }

}