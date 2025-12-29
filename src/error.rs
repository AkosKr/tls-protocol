use std::fmt;

/// TLS Error types for parsing and validation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsError {
    /// Invalid TLS version in the record header
    InvalidVersion,
    /// Invalid content type value
    InvalidContentType,
    /// Incomplete data - not enough bytes to parse
    IncompleteData,
    /// Invalid record length
    InvalidLength,
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsError::InvalidVersion => write!(f, "Invalid TLS version"),
            TlsError::InvalidContentType => write!(f, "Invalid content type"),
            TlsError::IncompleteData => write!(f, "Incomplete data"),
            TlsError::InvalidLength => write!(f, "Invalid record length"),
        }
    }
}

impl std::error::Error for TlsError {}
