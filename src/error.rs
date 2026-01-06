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
    /// Invalid compression method
    /// Carries the received compression method byte.
    InvalidCompressionMethod(u8),
    // Note: The following error variants are reserved for future use
    // and are not currently thrown by the implementation.
    /// Invalid random field (reserved for future use)
    InvalidRandom,
    /// Downgrade protection violation detected (reserved for future use)
    DowngradeDetected,
    /// Invalid key length for X25519
    /// Carries the received key length.
    InvalidKeyLength(usize),
    /// Invalid public key (weak, malformed, or non-canonical)
    InvalidPublicKey,
    /// Key exchange failed
    /// Carries a description of the error.
    KeyExchangeFailed(String),
    /// Encryption operation failed
    EncryptionFailed,
    /// Decryption operation failed (may indicate tampering)
    DecryptionFailed,
    /// Sequence number overflow (2^64-1 records encrypted)
    SequenceNumberOverflow,
    /// Record size exceeds maximum allowed
    RecordTooLarge,
    /// Invalid record format
    InvalidRecord,
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
            TlsError::InvalidCompressionMethod(method) => {
                write!(f, "Invalid compression method: 0x{method:02x}, expected 0x00")
            }
            TlsError::InvalidRandom => {
                write!(f, "Invalid random field")
            }
            TlsError::DowngradeDetected => {
                write!(f, "Downgrade protection violation detected")
            }
            TlsError::InvalidKeyLength(length) => {
                write!(f, "Invalid key length: {length} bytes, expected 32 bytes for X25519")
            }
            TlsError::InvalidPublicKey => {
                write!(f, "Invalid public key: weak, malformed, or non-canonical value")
            }
            TlsError::KeyExchangeFailed(desc) => {
                write!(f, "Key exchange failed: {desc}")
            }
            TlsError::EncryptionFailed => {
                write!(f, "Encryption operation failed")
            }
            TlsError::DecryptionFailed => {
                write!(f, "Decryption operation failed (authentication tag verification failed)")
            }
            TlsError::SequenceNumberOverflow => {
                write!(f, "Sequence number overflow: maximum records encrypted with this key")
            }
            TlsError::RecordTooLarge => {
                write!(f, "Record size exceeds maximum allowed")
            }
            TlsError::InvalidRecord => {
                write!(f, "Invalid record format")
            }
        }
    }
}

impl std::error::Error for TlsError {}
