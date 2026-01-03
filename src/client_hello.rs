/// TLS 1.3 cipher suites
pub const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
pub const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
pub const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

/// Extension type identifiers
pub const EXT_SUPPORTED_VERSIONS: u16 = 43;
pub const EXT_KEY_SHARE: u16 = 51;

/// TLS version constants
pub const TLS_VERSION_1_3: u16 = 0x0304;
pub const TLS_VERSION_1_2: u16 = 0x0303; // Legacy version for compatibility

/// Named group identifiers for key exchange
pub const NAMED_GROUP_X25519: u16 = 0x001d;
pub const NAMED_GROUP_SECP256R1: u16 = 0x0017;

/// Extension data for TLS extensions
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Extension {
    /// Supported versions extension (mandatory for TLS 1.3)
    /// Contains a list of supported TLS versions
    SupportedVersions(Vec<u16>),
    
    /// Key share extension (mandatory for TLS 1.3)
    /// Contains a list of key exchange entries (group, key_exchange data)
    KeyShare(Vec<KeyShareEntry>),
    
    /// Generic extension for future extensibility
    Unknown { extension_type: u16, data: Vec<u8> },
}

/// Key share entry for key exchange
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyShareEntry {
    /// Named group (e.g., x25519, secp256r1)
    pub group: u16,
    /// Key exchange data (public key)
    pub key_exchange: Vec<u8>,
}

impl Extension {
    /// Serialize extension to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        match self {
            Extension::SupportedVersions(versions) => {
                // Extension type (2 bytes)
                bytes.extend_from_slice(&EXT_SUPPORTED_VERSIONS.to_be_bytes());
                
                // Extension length (2 bytes)
                let data_len = 1 + versions.len() * 2; // 1 byte for length + versions
                bytes.extend_from_slice(&(data_len as u16).to_be_bytes());
                
                // Versions length (1 byte)
                bytes.push((versions.len() * 2) as u8);
                
                // Versions (2 bytes each)
                for version in versions {
                    bytes.extend_from_slice(&version.to_be_bytes());
                }
            }
            Extension::KeyShare(entries) => {
                // Extension type (2 bytes)
                bytes.extend_from_slice(&EXT_KEY_SHARE.to_be_bytes());
                
                // Calculate total data length
                let mut data_len = 2; // 2 bytes for entries length
                for entry in entries {
                    data_len += 2 + 2 + entry.key_exchange.len(); // group + length + data
                }
                
                // Extension length (2 bytes)
                bytes.extend_from_slice(&(data_len as u16).to_be_bytes());
                
                // Client key share length (2 bytes)
                bytes.extend_from_slice(&((data_len - 2) as u16).to_be_bytes());
                
                // Key share entries
                for entry in entries {
                    // Named group (2 bytes)
                    bytes.extend_from_slice(&entry.group.to_be_bytes());
                    
                    // Key exchange length (2 bytes)
                    bytes.extend_from_slice(&(entry.key_exchange.len() as u16).to_be_bytes());
                    
                    // Key exchange data
                    bytes.extend_from_slice(&entry.key_exchange);
                }
            }
            Extension::Unknown { extension_type, data } => {
                // Extension type (2 bytes)
                bytes.extend_from_slice(&extension_type.to_be_bytes());
                
                // Extension length (2 bytes)
                bytes.extend_from_slice(&(data.len() as u16).to_be_bytes());
                
                // Extension data
                bytes.extend_from_slice(data);
            }
        }
        
        bytes
    }
}

/// ClientHello message structure
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    /// Random bytes (32 bytes)
    pub random: [u8; 32],
    
    /// Legacy session ID (variable length, max 32 bytes)
    pub legacy_session_id: Vec<u8>,
    
    /// List of supported cipher suites
    pub cipher_suites: Vec<u16>,
    
    /// TLS extensions
    pub extensions: Vec<Extension>,
}

impl ClientHello {
    /// Create a new ClientHello with the given parameters
    pub fn new(
        random: [u8; 32],
        legacy_session_id: Vec<u8>,
        cipher_suites: Vec<u16>,
        extensions: Vec<Extension>,
    ) -> Self {
        Self {
            random,
            legacy_session_id,
            cipher_suites,
            extensions,
        }
    }
    
    /// Create a default ClientHello for TLS 1.3 with mandatory extensions
    /// 
    /// This includes:
    /// - Random 32 bytes (provided by caller or generated)
    /// - Empty legacy session ID
    /// - Default cipher suites (AES-128-GCM-SHA256, AES-256-GCM-SHA384)
    /// - Supported versions extension (TLS 1.3)
    /// - Key share extension (x25519 with provided or dummy public key)
    pub fn default_tls13(random: [u8; 32], x25519_public_key: Vec<u8>) -> Self {
        let cipher_suites = vec![
            TLS_AES_128_GCM_SHA256,
            TLS_AES_256_GCM_SHA384,
            TLS_CHACHA20_POLY1305_SHA256,
        ];
        
        let extensions = vec![
            Extension::SupportedVersions(vec![TLS_VERSION_1_3]),
            Extension::KeyShare(vec![KeyShareEntry {
                group: NAMED_GROUP_X25519,
                key_exchange: x25519_public_key,
            }]),
        ];
        
        Self::new(random, Vec::new(), cipher_suites, extensions)
    }
    
    /// Serialize the ClientHello message to bytes
    /// 
    /// Format:
    /// - Handshake type (1 byte): 0x01 (ClientHello)
    /// - Length (3 bytes): Total length of ClientHello data
    /// - Legacy version (2 bytes): 0x0303 (TLS 1.2 for compatibility)
    /// - Random (32 bytes)
    /// - Legacy session ID length (1 byte)
    /// - Legacy session ID (variable)
    /// - Cipher suites length (2 bytes)
    /// - Cipher suites (variable, 2 bytes each)
    /// - Legacy compression methods length (1 byte): 0x01
    /// - Legacy compression methods (1 byte): 0x00
    /// - Extensions length (2 bytes)
    /// - Extensions (variable)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        
        // Legacy version (2 bytes) - TLS 1.2 for compatibility
        data.extend_from_slice(&TLS_VERSION_1_2.to_be_bytes());
        
        // Random (32 bytes)
        data.extend_from_slice(&self.random);
        
        // Legacy session ID length (1 byte) + session ID
        data.push(self.legacy_session_id.len() as u8);
        data.extend_from_slice(&self.legacy_session_id);
        
        // Cipher suites length (2 bytes) + cipher suites
        let cipher_suites_len = (self.cipher_suites.len() * 2) as u16;
        data.extend_from_slice(&cipher_suites_len.to_be_bytes());
        for suite in &self.cipher_suites {
            data.extend_from_slice(&suite.to_be_bytes());
        }
        
        // Legacy compression methods (1 byte length + 1 byte method)
        data.push(0x01); // Length
        data.push(0x00); // No compression
        
        // Serialize extensions
        let mut extensions_data = Vec::new();
        for ext in &self.extensions {
            extensions_data.extend_from_slice(&ext.to_bytes());
        }
        
        // Extensions length (2 bytes) + extensions
        data.extend_from_slice(&(extensions_data.len() as u16).to_be_bytes());
        data.extend_from_slice(&extensions_data);
        
        // Now wrap in handshake message
        let mut message = Vec::new();
        
        // Handshake type (1 byte) - ClientHello = 0x01
        message.push(0x01);
        
        // Length (3 bytes)
        let length = data.len() as u32;
        message.push(((length >> 16) & 0xFF) as u8);
        message.push(((length >> 8) & 0xFF) as u8);
        message.push((length & 0xFF) as u8);
        
        // ClientHello data
        message.extend_from_slice(&data);
        
        message
    }
    
    /// Generate random bytes (helper method for testing)
    pub fn generate_random() -> [u8; 32] {
        // In a real implementation, use a cryptographically secure RNG
        // For now, we'll use a simple counter-based approach for testing
        let mut random = [0u8; 32];
        for (i, byte) in random.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(7).wrapping_add(13);
        }
        random
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extension_supported_versions() {
        let ext = Extension::SupportedVersions(vec![TLS_VERSION_1_3]);
        let bytes = ext.to_bytes();
        
        // Extension type (43)
        assert_eq!(bytes[0..2], [0x00, 0x2b]);
        // Extension length (3)
        assert_eq!(bytes[2..4], [0x00, 0x03]);
        // Versions length (2)
        assert_eq!(bytes[4], 0x02);
        // TLS 1.3 version
        assert_eq!(bytes[5..7], [0x03, 0x04]);
    }
    
    #[test]
    fn test_extension_key_share() {
        let key = vec![0x01, 0x02, 0x03, 0x04];
        let ext = Extension::KeyShare(vec![KeyShareEntry {
            group: NAMED_GROUP_X25519,
            key_exchange: key.clone(),
        }]);
        let bytes = ext.to_bytes();
        
        // Extension type (51)
        assert_eq!(bytes[0..2], [0x00, 0x33]);
        // Extension length (10 = 2 + 2 + 2 + 4)
        assert_eq!(bytes[2..4], [0x00, 0x0a]);
        // Key share length (8 = 2 + 2 + 4)
        assert_eq!(bytes[4..6], [0x00, 0x08]);
        // Named group (x25519 = 0x001d)
        assert_eq!(bytes[6..8], [0x00, 0x1d]);
        // Key exchange length (4)
        assert_eq!(bytes[8..10], [0x00, 0x04]);
        // Key exchange data
        assert_eq!(bytes[10..14], [0x01, 0x02, 0x03, 0x04]);
    }
    
    #[test]
    fn test_client_hello_structure() {
        let random = [0u8; 32];
        let public_key = vec![0xab; 32];
        
        let hello = ClientHello::default_tls13(random, public_key.clone());
        
        assert_eq!(hello.random, random);
        assert_eq!(hello.legacy_session_id.len(), 0);
        assert_eq!(hello.cipher_suites.len(), 3);
        assert_eq!(hello.extensions.len(), 2);
    }
    
    #[test]
    fn test_client_hello_serialization() {
        let random = [0u8; 32];
        let public_key = vec![0xab; 32];
        
        let hello = ClientHello::default_tls13(random, public_key);
        let bytes = hello.to_bytes();
        
        // Handshake type should be 0x01 (ClientHello)
        assert_eq!(bytes[0], 0x01);
        
        // Check that we have length (3 bytes) + data
        assert!(bytes.len() > 4);
        
        // Legacy version should be 0x0303
        assert_eq!(bytes[4..6], [0x03, 0x03]);
        
        // Random should be at offset 6
        assert_eq!(bytes[6..38], random);
    }
    
    #[test]
    fn test_client_hello_with_custom_values() {
        let random = ClientHello::generate_random();
        let session_id = vec![0x01, 0x02, 0x03];
        let cipher_suites = vec![TLS_AES_128_GCM_SHA256];
        let extensions = vec![Extension::SupportedVersions(vec![TLS_VERSION_1_3])];
        
        let hello = ClientHello::new(random, session_id.clone(), cipher_suites, extensions);
        let bytes = hello.to_bytes();
        
        // Verify handshake type
        assert_eq!(bytes[0], 0x01);
        
        // Verify session ID is included
        assert_eq!(bytes[38], 0x03); // Session ID length
        assert_eq!(&bytes[39..42], &session_id[..]);
    }
}
