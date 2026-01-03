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
    /// Unknown or unsupported extension type
    /// Carries the extension type identifier.
    UnknownExtension(u16),
    /// Missing mandatory TLS extension
    /// Carries the name of the missing extension.
    MissingMandatoryExtension(&'static str),
    /// Invalid extension data format
    /// Carries a description of the error.
    InvalidExtensionData(String),
    /// Duplicate extension detected
    /// Carries the extension type identifier.
    DuplicateExtension(u16),
    /// Invalid handshake type
    /// Carries the received handshake type byte.
    InvalidHandshakeType(u8),
    /// Invalid or unsupported cipher suite
    /// Carries the cipher suite identifier.
    InvalidCipherSuite(u16),
    /// Invalid random field
    InvalidRandom,
    /// Downgrade protection violation detected
    DowngradeDetected,
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
            TlsError::UnknownExtension(ext_type) => {
                write!(f, "Unknown or unsupported extension: 0x{ext_type:04x}")
            }
            TlsError::MissingMandatoryExtension(ext_name) => {
                write!(f, "Missing mandatory TLS extension: {ext_name}")
            }
            TlsError::InvalidExtensionData(desc) => {
                write!(f, "Invalid extension data: {desc}")
            }
            TlsError::DuplicateExtension(ext_type) => {
                write!(f, "Duplicate extension detected: 0x{ext_type:04x}")
            }
            TlsError::InvalidHandshakeType(hs_type) => {
                write!(f, "Invalid handshake type: 0x{hs_type:02x}")
            }
            TlsError::InvalidCipherSuite(suite) => {
                write!(f, "Invalid or unsupported cipher suite: 0x{suite:04x}")
            }
            TlsError::InvalidRandom => {
                write!(f, "Invalid random field")
            }
            TlsError::DowngradeDetected => {
                write!(f, "Downgrade protection violation detected")
            }
        }
    }
}

impl std::error::Error for TlsError {}
