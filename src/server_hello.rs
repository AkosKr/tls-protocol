use crate::error::TlsError;
use crate::extensions::{Extension, TLS_VERSION_1_3};

/// TLS 1.3 cipher suites (re-exported from client_hello for consistency)
pub use crate::client_hello::{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256};

/// Downgrade protection sentinels (RFC 8446, Appendix D.4)
/// These are the last 8 bytes of the random field
pub const TLS_1_2_DOWNGRADE_SENTINEL: [u8; 8] = [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01];
pub const TLS_1_1_DOWNGRADE_SENTINEL: [u8; 8] = [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00];

/// Downgrade protection detection result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DowngradeProtection {
    /// TLS 1.2 downgrade detected
    Tls12Downgrade,
    /// TLS 1.1 or earlier downgrade detected
    Tls11Downgrade,
}

/// ServerHello message structure (RFC 8446, Section 4.1.3)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHello {
    /// Random bytes (32 bytes)
    /// May contain downgrade protection sentinels in the last 8 bytes
    pub random: [u8; 32],
    
    /// Legacy session ID echo (variable length, max 32 bytes)
    /// Should echo the session ID from ClientHello
    pub legacy_session_id_echo: Vec<u8>,
    
    /// Selected cipher suite (single value)
    pub cipher_suite: u16,
    
    /// TLS extensions
    pub extensions: Vec<Extension>,
}

impl ServerHello {
    /// Create a new ServerHello with the given parameters
    pub fn new(
        random: [u8; 32],
        legacy_session_id_echo: Vec<u8>,
        cipher_suite: u16,
        extensions: Vec<Extension>,
    ) -> Self {
        Self {
            random,
            legacy_session_id_echo,
            cipher_suite,
            extensions,
        }
    }
    
    /// Parse a ServerHello message from bytes
    /// 
    /// Expected format (RFC 8446):
    /// - Handshake type (1 byte): 0x02 (ServerHello)
    /// - Length (3 bytes): Total length of ServerHello data
    /// - Legacy version (2 bytes): 0x0303 (TLS 1.2 for compatibility)
    /// - Random (32 bytes)
    /// - Legacy session ID echo length (1 byte)
    /// - Legacy session ID echo (variable, max 32 bytes)
    /// - Cipher suite (2 bytes)
    /// - Legacy compression method (1 byte): 0x00
    /// - Extensions length (2 bytes)
    /// - Extensions (variable)
    pub fn from_bytes(data: &[u8]) -> Result<Self, TlsError> {
        let mut offset = 0;
        
        // Check minimum length (1 + 3 + 2 + 32 + 1 + 2 + 1 + 2 = 44 bytes minimum)
        if data.len() < 44 {
            return Err(TlsError::IncompleteData);
        }
        
        // Parse handshake type (expect 0x02 for ServerHello)
        let handshake_type = data[offset];
        offset += 1;
        
        if handshake_type != 0x02 {
            return Err(TlsError::InvalidHandshakeType(handshake_type));
        }
        
        // Parse 3-byte length field
        let length = ((data[offset] as usize) << 16)
            | ((data[offset + 1] as usize) << 8)
            | (data[offset + 2] as usize);
        offset += 3;
        
        // Verify we have enough data
        if data.len() < offset + length {
            return Err(TlsError::IncompleteData);
        }
        
        // Parse legacy_version (expect 0x0303 for TLS 1.2 compatibility)
        let legacy_version = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;
        
        if legacy_version != 0x0303 {
            return Err(TlsError::InvalidVersion(legacy_version));
        }
        
        // Parse random (32 bytes)
        if offset + 32 > data.len() {
            return Err(TlsError::IncompleteData);
        }
        
        let mut random = [0u8; 32];
        random.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;
        
        // Parse legacy_session_id_echo length
        if offset >= data.len() {
            return Err(TlsError::IncompleteData);
        }
        
        let session_id_len = data[offset] as usize;
        offset += 1;
        
        if session_id_len > 32 {
            return Err(TlsError::InvalidLength(session_id_len as u16));
        }
        
        // Parse legacy_session_id_echo
        if offset + session_id_len > data.len() {
            return Err(TlsError::IncompleteData);
        }
        
        let legacy_session_id_echo = data[offset..offset + session_id_len].to_vec();
        offset += session_id_len;
        
        // Parse cipher_suite (2 bytes)
        if offset + 2 > data.len() {
            return Err(TlsError::IncompleteData);
        }
        
        let cipher_suite = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;
        
        // Validate cipher suite (only TLS 1.3 suites are valid)
        if !Self::is_valid_tls13_cipher_suite(cipher_suite) {
            return Err(TlsError::InvalidCipherSuite(cipher_suite));
        }
        
        // Parse legacy_compression_method (expect 0x00)
        if offset >= data.len() {
            return Err(TlsError::IncompleteData);
        }
        
        let compression_method = data[offset];
        offset += 1;
        
        if compression_method != 0x00 {
            return Err(TlsError::InvalidCompressionMethod(compression_method));
        }
        
        // Parse extensions length (2 bytes)
        if offset + 2 > data.len() {
            return Err(TlsError::IncompleteData);
        }
        
        let extensions_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        
        // Parse extensions
        if offset + extensions_len > data.len() {
            return Err(TlsError::IncompleteData);
        }
        
        // Parse individual extensions (not using parse_extensions which expects its own length prefix)
        let mut extensions = Vec::new();
        let mut ext_offset = offset;
        let ext_end = offset + extensions_len;
        
        while ext_offset < ext_end {
            let (ext, consumed) = Extension::from_bytes(&data[ext_offset..])?;
            extensions.push(ext);
            ext_offset += consumed;
        }
        
        if ext_offset != ext_end {
            return Err(TlsError::InvalidExtensionData(
                "Extensions length mismatch".to_string()
            ));
        }
        
        let server_hello = Self {
            random,
            legacy_session_id_echo,
            cipher_suite,
            extensions,
        };
        
        // Validate the parsed ServerHello
        server_hello.validate()?;
        
        Ok(server_hello)
    }
    
    /// Serialize the ServerHello message to bytes
    /// 
    /// Format:
    /// - Handshake type (1 byte): 0x02 (ServerHello)
    /// - Length (3 bytes): Total length of ServerHello data
    /// - Legacy version (2 bytes): 0x0303 (TLS 1.2 for compatibility)
    /// - Random (32 bytes)
    /// - Legacy session ID echo length (1 byte)
    /// - Legacy session ID echo (variable)
    /// - Cipher suite (2 bytes)
    /// - Legacy compression method (1 byte): 0x00
    /// - Extensions length (2 bytes)
    /// - Extensions (variable)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        
        // Legacy version (2 bytes) - TLS 1.2 for compatibility
        data.extend_from_slice(&0x0303u16.to_be_bytes());
        
        // Random (32 bytes)
        data.extend_from_slice(&self.random);
        
        // Legacy session ID echo length (1 byte) + session ID
        assert!(
            self.legacy_session_id_echo.len() <= 32,
            "legacy_session_id_echo length must not exceed 32 bytes"
        );
        data.push(self.legacy_session_id_echo.len() as u8);
        data.extend_from_slice(&self.legacy_session_id_echo);
        
        // Cipher suite (2 bytes)
        data.extend_from_slice(&self.cipher_suite.to_be_bytes());
        
        // Legacy compression method (1 byte) - always 0x00
        data.push(0x00);
        
        // Serialize extensions manually (following ClientHello pattern)
        let mut extensions_data = Vec::new();
        for ext in &self.extensions {
            extensions_data.extend_from_slice(&ext.to_bytes());
        }
        
        // Extensions length (2 bytes) + extensions
        let extensions_len: u16 = extensions_data
            .len()
            .try_into()
            .expect("extensions data length exceeds u16 maximum (65535 bytes)");
        data.extend_from_slice(&extensions_len.to_be_bytes());
        data.extend_from_slice(&extensions_data);
        
        // Prepend handshake header
        let mut result = Vec::new();
        result.push(0x02); // ServerHello handshake type
        
        // 3-byte length
        let length = data.len() as u32;
        result.push((length >> 16) as u8);
        result.push((length >> 8) as u8);
        result.push(length as u8);
        
        result.extend_from_slice(&data);
        
        result
    }
    
    /// Check for downgrade protection in the random field
    /// 
    /// Per RFC 8446, Appendix D.4, TLS 1.3 servers that negotiate TLS 1.2 or below
    /// due to ClientHello.supported_versions not being present will set the last
    /// 8 bytes of ServerHello.random to a special value.
    pub fn check_downgrade_protection(&self) -> Option<DowngradeProtection> {
        let last_8_bytes = &self.random[24..32];
        
        if last_8_bytes == TLS_1_2_DOWNGRADE_SENTINEL {
            Some(DowngradeProtection::Tls12Downgrade)
        } else if last_8_bytes == TLS_1_1_DOWNGRADE_SENTINEL {
            Some(DowngradeProtection::Tls11Downgrade)
        } else {
            None
        }
    }
    
    /// Validate the ServerHello message
    /// 
    /// Checks:
    /// - Mandatory extensions are present (supported_versions for TLS 1.3)
    /// - Cipher suite is valid for TLS 1.3
    /// - No duplicate extensions
    fn validate(&self) -> Result<(), TlsError> {
        // Check for duplicate extensions
        crate::extensions::check_duplicate_extensions(&self.extensions)?;
        
        // Check for supported_versions extension (mandatory for TLS 1.3)
        let has_supported_versions = self.extensions.iter().any(|ext| {
            matches!(ext, Extension::SupportedVersions(_))
        });
        
        if !has_supported_versions {
            return Err(TlsError::MissingMandatoryExtension("supported_versions"));
        }
        
        // Verify that supported_versions contains exactly one version and it's TLS 1.3
        // Per RFC 8446 Section 4.2.1: ServerHello must contain exactly one version
        for ext in &self.extensions {
            if let Extension::SupportedVersions(versions) = ext {
                if versions.len() != 1 {
                    return Err(TlsError::InvalidExtensionData(
                        format!("supported_versions in ServerHello must contain exactly one version, found {}", versions.len())
                    ));
                }
                if versions[0] != TLS_VERSION_1_3 {
                    return Err(TlsError::InvalidExtensionData(
                        format!("supported_versions must contain TLS 1.3 (0x0304), found 0x{:04x}", versions[0])
                    ));
                }
            }
        }
        
        // Cipher suite is already validated in from_bytes
        
        Ok(())
    }
    
    /// Check if a cipher suite is valid for TLS 1.3
    fn is_valid_tls13_cipher_suite(suite: u16) -> bool {
        matches!(
            suite,
            TLS_AES_128_GCM_SHA256 | TLS_AES_256_GCM_SHA384 | TLS_CHACHA20_POLY1305_SHA256
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extensions::KeyShareEntry;
    use crate::extensions::NAMED_GROUP_X25519;
    
    #[test]
    fn test_server_hello_to_bytes() {
        let random = [0xaa; 32];
        let session_id = vec![];
        let cipher_suite = TLS_AES_128_GCM_SHA256;
        let extensions = vec![
            Extension::SupportedVersions(vec![TLS_VERSION_1_3]),
            Extension::KeyShare(vec![KeyShareEntry::new(NAMED_GROUP_X25519, vec![0xbb; 32])]),
        ];
        
        let server_hello = ServerHello::new(random, session_id, cipher_suite, extensions);
        let bytes = server_hello.to_bytes();
        
        // Verify handshake type
        assert_eq!(bytes[0], 0x02);
        
        // Verify we can parse it back
        let parsed = ServerHello::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.random, random);
        assert_eq!(parsed.cipher_suite, cipher_suite);
    }
    
    #[test]
    fn test_downgrade_protection_tls12() {
        let mut random = [0xaa; 32];
        random[24..32].copy_from_slice(&TLS_1_2_DOWNGRADE_SENTINEL);
        
        let server_hello = ServerHello::new(
            random,
            vec![],
            TLS_AES_128_GCM_SHA256,
            vec![Extension::SupportedVersions(vec![TLS_VERSION_1_3])],
        );
        
        assert_eq!(
            server_hello.check_downgrade_protection(),
            Some(DowngradeProtection::Tls12Downgrade)
        );
    }
    
    #[test]
    fn test_downgrade_protection_tls11() {
        let mut random = [0xaa; 32];
        random[24..32].copy_from_slice(&TLS_1_1_DOWNGRADE_SENTINEL);
        
        let server_hello = ServerHello::new(
            random,
            vec![],
            TLS_AES_128_GCM_SHA256,
            vec![Extension::SupportedVersions(vec![TLS_VERSION_1_3])],
        );
        
        assert_eq!(
            server_hello.check_downgrade_protection(),
            Some(DowngradeProtection::Tls11Downgrade)
        );
    }
    
    #[test]
    fn test_no_downgrade() {
        let random = [0xaa; 32];
        
        let server_hello = ServerHello::new(
            random,
            vec![],
            TLS_AES_128_GCM_SHA256,
            vec![Extension::SupportedVersions(vec![TLS_VERSION_1_3])],
        );
        
        assert_eq!(server_hello.check_downgrade_protection(), None);
    }
}
