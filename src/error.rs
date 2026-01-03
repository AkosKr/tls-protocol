use std::fmt;

/// TLS Error types for parsing and validation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsError {
    /// Invalid TLS version in the record header
    /// Carries the received raw version field.
    InvalidVersion(u16),
    /// Invalid content type value
    /// Carries the received content type byte.
    InvalidContentType(u8),
    /// Incomplete data - not enough bytes to parse
    IncompleteData,
    /// Invalid record length
    /// Carries the received record length.
    InvalidLength(u16),
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsError::InvalidVersion(version) => {
                write!(f, "Invalid TLS version: 0x{version:04x}")
            }
            TlsError::InvalidContentType(content_type) => {
                write!(f, "Invalid content type: {content_type}")
            }
            TlsError::IncompleteData => write!(f, "Incomplete data"),
            TlsError::InvalidLength(length) => {
                write!(f, "Invalid record length: {length}")
            }
        }
    }
}

impl std::error::Error for TlsError {}
