use crate::error::TlsError;

/// TLS Extension Type Identifiers (RFC 8446)
pub const EXT_SERVER_NAME: u16 = 0;
pub const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
pub const EXT_SUPPORTED_VERSIONS: u16 = 43;
pub const EXT_KEY_SHARE: u16 = 51;

/// TLS Version Constants
pub const TLS_VERSION_1_3: u16 = 0x0304;
pub const TLS_VERSION_1_2: u16 = 0x0303;

/// Named Group Identifiers for Key Exchange (RFC 8446)
pub const NAMED_GROUP_X25519: u16 = 0x001d;
pub const NAMED_GROUP_SECP256R1: u16 = 0x0017;
pub const NAMED_GROUP_SECP384R1: u16 = 0x0018;
pub const NAMED_GROUP_SECP521R1: u16 = 0x0019;

/// Signature Scheme Identifiers (RFC 8446)
pub const SIG_RSA_PKCS1_SHA256: u16 = 0x0401;
pub const SIG_RSA_PKCS1_SHA384: u16 = 0x0501;
pub const SIG_RSA_PKCS1_SHA512: u16 = 0x0601;
pub const SIG_ECDSA_SECP256R1_SHA256: u16 = 0x0403;
pub const SIG_ECDSA_SECP384R1_SHA384: u16 = 0x0503;
pub const SIG_ECDSA_SECP521R1_SHA512: u16 = 0x0603;
pub const SIG_RSA_PSS_RSAE_SHA256: u16 = 0x0804;
pub const SIG_RSA_PSS_RSAE_SHA384: u16 = 0x0805;
pub const SIG_RSA_PSS_RSAE_SHA512: u16 = 0x0806;
pub const SIG_ED25519: u16 = 0x0807;
pub const SIG_ED448: u16 = 0x0808;

/// Key Share Entry for TLS 1.3 Key Exchange
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyShareEntry {
    /// Named group (e.g., x25519, secp256r1)
    pub group: u16,
    /// Key exchange data (public key)
    pub key_exchange: Vec<u8>,
}

impl KeyShareEntry {
    /// Create a new KeyShareEntry
    pub fn new(group: u16, key_exchange: Vec<u8>) -> Self {
        Self {
            group,
            key_exchange,
        }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.group.to_be_bytes());
        let key_len = u16::try_from(self.key_exchange.len())
            .expect("KeyShareEntry key_exchange length exceeds u16::MAX");
        bytes.extend_from_slice(&key_len.to_be_bytes());
        bytes.extend_from_slice(&self.key_exchange);
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), TlsError> {
        if bytes.len() < 4 {
            return Err(TlsError::InvalidExtensionData(
                "KeyShareEntry too short".to_string(),
            ));
        }

        let group = u16::from_be_bytes([bytes[0], bytes[1]]);
        let key_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;

        if bytes.len() < 4 + key_len {
            return Err(TlsError::InvalidExtensionData(
                "KeyShareEntry key_exchange data incomplete".to_string(),
            ));
        }

        let key_exchange = bytes[4..4 + key_len].to_vec();
        let total_len = 4 + key_len;

        Ok((Self { group, key_exchange }, total_len))
    }
}

/// TLS Extension Types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Extension {
    /// Server Name Indication (SNI) - Extension Type 0
    ServerName(String),

    /// Signature Algorithms - Extension Type 13
    SignatureAlgorithms(Vec<u16>),

    /// Supported Versions - Extension Type 43 (mandatory for TLS 1.3)
    SupportedVersions(Vec<u16>),

    /// Key Share - Extension Type 51 (mandatory for TLS 1.3)
    KeyShare(Vec<KeyShareEntry>),

    /// Unknown/Unsupported Extension
    Unknown { extension_type: u16, data: Vec<u8> },
}

impl Extension {
    /// Get the extension type identifier
    pub fn extension_type(&self) -> u16 {
        match self {
            Extension::ServerName(_) => EXT_SERVER_NAME,
            Extension::SignatureAlgorithms(_) => EXT_SIGNATURE_ALGORITHMS,
            Extension::SupportedVersions(_) => EXT_SUPPORTED_VERSIONS,
            Extension::KeyShare(_) => EXT_KEY_SHARE,
            Extension::Unknown { extension_type, .. } => *extension_type,
        }
    }

    /// Serialize extension to bytes
    ///
    /// Format: [type: u16] [length: u16] [data: variable]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        match self {
            Extension::ServerName(hostname) => {
                // Extension type
                bytes.extend_from_slice(&EXT_SERVER_NAME.to_be_bytes());

                // Validate hostname length fits in the protocol
                let hostname_bytes = hostname.as_bytes();
                let hostname_len = hostname_bytes.len();
                
                // Calculate max length that fits: ext_len = 2 + (1 + 2 + hostname_len) <= u16::MAX
                // => hostname_len <= u16::MAX - 5
                let max_hostname_len = (u16::MAX as usize).saturating_sub(5);
                assert!(
                    hostname_len <= max_hostname_len,
                    "ServerName hostname length {} exceeds maximum {}",
                    hostname_len,
                    max_hostname_len
                );

                // Server Name List
                let mut list_data = Vec::new();
                // Name Type: host_name (0)
                list_data.push(0x00);
                // HostName length
                list_data.extend_from_slice(&(hostname_len as u16).to_be_bytes());
                // HostName
                list_data.extend_from_slice(hostname_bytes);

                // Extension length (includes list length field)
                let ext_len = 2 + list_data.len();
                bytes.extend_from_slice(&(ext_len as u16).to_be_bytes());

                // Server Name List Length
                bytes.extend_from_slice(&(list_data.len() as u16).to_be_bytes());
                // Server Name List
                bytes.extend_from_slice(&list_data);
            }

            Extension::SignatureAlgorithms(algorithms) => {
                // Extension type
                bytes.extend_from_slice(&EXT_SIGNATURE_ALGORITHMS.to_be_bytes());

                // Extension length (2 bytes for list length + algorithms)
                let data_len = 2 + algorithms.len() * 2;
                assert!(
                    data_len <= u16::MAX as usize,
                    "SignatureAlgorithms extension data length {} exceeds u16::MAX",
                    data_len
                );
                bytes.extend_from_slice(&(data_len as u16).to_be_bytes());

                // Algorithms length
                let algorithms_len_bytes = algorithms.len() * 2;
                assert!(
                    algorithms_len_bytes <= u16::MAX as usize,
                    "SignatureAlgorithms length {} exceeds u16::MAX",
                    algorithms_len_bytes
                );
                bytes.extend_from_slice(&(algorithms_len_bytes as u16).to_be_bytes());

                // Algorithms
                for &algo in algorithms {
                    bytes.extend_from_slice(&algo.to_be_bytes());
                }
            }

            Extension::SupportedVersions(versions) => {
                // Extension type
                bytes.extend_from_slice(&EXT_SUPPORTED_VERSIONS.to_be_bytes());

                // Extension length (1 byte for versions length + versions)
                let data_len = 1 + versions.len() * 2;
                assert!(
                    data_len <= u16::MAX as usize,
                    "SupportedVersions extension data length {} exceeds u16::MAX",
                    data_len
                );
                bytes.extend_from_slice(&(data_len as u16).to_be_bytes());

                // Versions length (in bytes)
                let versions_len_bytes = versions.len() * 2;
                assert!(
                    versions_len_bytes <= u8::MAX as usize,
                    "SupportedVersions versions length {} exceeds u8::MAX",
                    versions_len_bytes
                );
                bytes.push(versions_len_bytes as u8);

                // Versions
                for &version in versions {
                    bytes.extend_from_slice(&version.to_be_bytes());
                }
            }

            Extension::KeyShare(entries) => {
                // Extension type
                bytes.extend_from_slice(&EXT_KEY_SHARE.to_be_bytes());

                // Calculate entries data length
                let mut entries_data = Vec::new();
                for entry in entries {
                    entries_data.extend_from_slice(&entry.to_bytes());
                }

                // Extension length (2 bytes for entries length + entries)
                let ext_len = 2 + entries_data.len();
                assert!(
                    ext_len <= u16::MAX as usize,
                    "KeyShare extension length {} exceeds u16::MAX",
                    ext_len
                );
                bytes.extend_from_slice(&(ext_len as u16).to_be_bytes());

                // Client Key Share Length
                let entries_len = entries_data.len();
                assert!(
                    entries_len <= u16::MAX as usize,
                    "KeyShare entries length {} exceeds u16::MAX",
                    entries_len
                );
                bytes.extend_from_slice(&(entries_len as u16).to_be_bytes());

                // Entries
                bytes.extend_from_slice(&entries_data);
            }

            Extension::Unknown { extension_type, data } => {
                // Extension type
                bytes.extend_from_slice(&extension_type.to_be_bytes());

                // Extension length
                assert!(
                    data.len() <= u16::MAX as usize,
                    "Unknown extension data length {} exceeds u16::MAX",
                    data.len()
                );
                bytes.extend_from_slice(&(data.len() as u16).to_be_bytes());

                // Extension data
                bytes.extend_from_slice(data);
            }
        }

        bytes
    }

    /// Deserialize extension from bytes
    ///
    /// Returns (Extension, bytes_consumed)
    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), TlsError> {
        if bytes.len() < 4 {
            return Err(TlsError::IncompleteData);
        }

        let extension_type = u16::from_be_bytes([bytes[0], bytes[1]]);
        let extension_length = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;

        if bytes.len() < 4 + extension_length {
            return Err(TlsError::IncompleteData);
        }

        let extension_data = &bytes[4..4 + extension_length];
        let total_consumed = 4 + extension_length;

        let extension = match extension_type {
            EXT_SERVER_NAME => {
                if extension_data.len() < 2 {
                    return Err(TlsError::InvalidExtensionData(
                        "ServerName extension too short".to_string(),
                    ));
                }

                let list_length = u16::from_be_bytes([extension_data[0], extension_data[1]]) as usize;
                if extension_data.len() < 2 + list_length {
                    return Err(TlsError::InvalidExtensionData(
                        "ServerName list length mismatch".to_string(),
                    ));
                }

                let list_data = &extension_data[2..2 + list_length];
                if list_data.len() < 3 {
                    return Err(TlsError::InvalidExtensionData(
                        "ServerName list data too short".to_string(),
                    ));
                }

                let name_type = list_data[0];
                if name_type != 0x00 {
                    return Err(TlsError::InvalidExtensionData(
                        format!("Unknown ServerName type: {}", name_type),
                    ));
                }

                let name_length = u16::from_be_bytes([list_data[1], list_data[2]]) as usize;
                if list_data.len() < 3 + name_length {
                    return Err(TlsError::InvalidExtensionData(
                        "ServerName hostname length mismatch".to_string(),
                    ));
                }

                let hostname_bytes = &list_data[3..3 + name_length];
                let hostname = String::from_utf8(hostname_bytes.to_vec())
                    .map_err(|_| TlsError::InvalidExtensionData("Invalid UTF-8 in ServerName".to_string()))?;

                // Validate hostname length (RFC standards typically limit to 255 characters)
                if hostname.len() > 255 {
                    return Err(TlsError::InvalidExtensionData(
                        format!("ServerName hostname too long: {} characters (max 255)", hostname.len())
                    ));
                }

                // Validate hostname format: must not be empty and should contain valid DNS characters
                if hostname.is_empty() {
                    return Err(TlsError::InvalidExtensionData(
                        "ServerName hostname is empty".to_string()
                    ));
                }

                Extension::ServerName(hostname)
            }

            EXT_SIGNATURE_ALGORITHMS => {
                if extension_data.len() < 2 {
                    return Err(TlsError::InvalidExtensionData(
                        "SignatureAlgorithms extension too short".to_string(),
                    ));
                }

                let algos_length = u16::from_be_bytes([extension_data[0], extension_data[1]]) as usize;
                if algos_length % 2 != 0 {
                    return Err(TlsError::InvalidExtensionData(
                        "SignatureAlgorithms length must be even".to_string(),
                    ));
                }

                if extension_data.len() < 2 + algos_length {
                    return Err(TlsError::InvalidExtensionData(
                        "SignatureAlgorithms data incomplete".to_string(),
                    ));
                }

                let mut algorithms = Vec::new();
                for i in (0..algos_length).step_by(2) {
                    let algo = u16::from_be_bytes([extension_data[2 + i], extension_data[2 + i + 1]]);
                    algorithms.push(algo);
                }

                Extension::SignatureAlgorithms(algorithms)
            }

            EXT_SUPPORTED_VERSIONS => {
                if extension_data.is_empty() {
                    return Err(TlsError::InvalidExtensionData(
                        "SupportedVersions extension empty".to_string(),
                    ));
                }

                let versions_length = extension_data[0] as usize;
                if versions_length % 2 != 0 {
                    return Err(TlsError::InvalidExtensionData(
                        "SupportedVersions length must be even".to_string(),
                    ));
                }

                if extension_data.len() < 1 + versions_length {
                    return Err(TlsError::InvalidExtensionData(
                        "SupportedVersions data incomplete".to_string(),
                    ));
                }

                let mut versions = Vec::new();
                for i in (0..versions_length).step_by(2) {
                    let version = u16::from_be_bytes([extension_data[1 + i], extension_data[1 + i + 1]]);
                    versions.push(version);
                }

                Extension::SupportedVersions(versions)
            }

            EXT_KEY_SHARE => {
                if extension_data.len() < 2 {
                    return Err(TlsError::InvalidExtensionData(
                        "KeyShare extension too short".to_string(),
                    ));
                }

                let entries_length = u16::from_be_bytes([extension_data[0], extension_data[1]]) as usize;
                if extension_data.len() < 2 + entries_length {
                    return Err(TlsError::InvalidExtensionData(
                        "KeyShare entries data incomplete".to_string(),
                    ));
                }

                let mut entries = Vec::new();
                let mut offset = 2;
                let end = 2 + entries_length;

                while offset < end {
                    let (entry, consumed) = KeyShareEntry::from_bytes(&extension_data[offset..])?;
                    entries.push(entry);
                    offset += consumed;
                }

                if offset != end {
                    return Err(TlsError::InvalidExtensionData(
                        "KeyShare entries length mismatch".to_string(),
                    ));
                }

                Extension::KeyShare(entries)
            }

            _ => Extension::Unknown {
                extension_type,
                data: extension_data.to_vec(),
            },
        };

        Ok((extension, total_consumed))
    }

    /// Parse multiple extensions from bytes
    pub fn parse_extensions(bytes: &[u8]) -> Result<Vec<Extension>, TlsError> {
        if bytes.len() < 2 {
            return Err(TlsError::IncompleteData);
        }

        let extensions_length = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        if bytes.len() < 2 + extensions_length {
            return Err(TlsError::IncompleteData);
        }

        let mut extensions = Vec::new();
        let mut offset = 2;
        let end = 2 + extensions_length;

        while offset < end {
            let (ext, consumed) = Extension::from_bytes(&bytes[offset..])?;
            extensions.push(ext);
            offset += consumed;
        }

        if offset != end {
            return Err(TlsError::InvalidExtensionData(
                "Extensions length mismatch".to_string(),
            ));
        }

        Ok(extensions)
    }

    /// Serialize multiple extensions to bytes (with length prefix)
    pub fn serialize_extensions(extensions: &[Extension]) -> Vec<u8> {
        let mut data = Vec::new();

        for ext in extensions {
            data.extend_from_slice(&ext.to_bytes());
        }

        let data_len = data.len();
        assert!(
            data_len <= u16::MAX as usize,
            "Total extensions length {} exceeds u16::MAX",
            data_len
        );

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(data_len as u16).to_be_bytes());
        bytes.extend_from_slice(&data);

        bytes
    }
}

/// Validate that mandatory TLS 1.3 extensions are present
pub fn validate_tls13_extensions(extensions: &[Extension]) -> Result<(), TlsError> {
    let mut has_supported_versions = false;
    let mut has_key_share = false;

    for ext in extensions {
        match ext {
            Extension::SupportedVersions(versions) => {
                has_supported_versions = true;
                if !versions.contains(&TLS_VERSION_1_3) {
                    return Err(TlsError::MissingMandatoryExtension(
                        "TLS 1.3 not in supported_versions",
                    ));
                }
            }
            Extension::KeyShare(entries) => {
                has_key_share = true;
                if entries.is_empty() {
                    return Err(TlsError::InvalidExtensionData(
                        "KeyShare extension has no entries".to_string(),
                    ));
                }
            }
            _ => {}
        }
    }

    if !has_supported_versions {
        return Err(TlsError::MissingMandatoryExtension("supported_versions"));
    }

    if !has_key_share {
        return Err(TlsError::MissingMandatoryExtension("key_share"));
    }

    Ok(())
}

/// Check for duplicate extensions
pub fn check_duplicate_extensions(extensions: &[Extension]) -> Result<(), TlsError> {
    let mut seen = std::collections::HashSet::new();

    for ext in extensions {
        let ext_type = ext.extension_type();
        if !seen.insert(ext_type) {
            return Err(TlsError::DuplicateExtension(ext_type));
        }
    }

    Ok(())
}
