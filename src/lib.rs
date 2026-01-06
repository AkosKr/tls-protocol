use std::convert::TryFrom;

// Re-export modules for convenient access
pub mod aead;
pub mod client_hello;
pub mod decoder;
pub mod error;
pub mod extensions;
pub mod key_schedule;
pub mod parser;
pub mod server_hello;
pub mod tls_stream;
pub mod x25519_key_exchange;
pub mod key_schedule;

// Re-export commonly used types
pub use aead::{AeadCipher, TrafficKeys, encrypt_record, decrypt_record};
pub use client_hello::ClientHello;
pub use decoder::decode_header;
pub use error::TlsError;
pub use extensions::{Extension, KeyShareEntry};
pub use key_schedule::{KeySchedule, derive_traffic_keys};
pub use parser::parse_header;
pub use server_hello::ServerHello;
pub use x25519_key_exchange::{X25519KeyPair, compute_shared_secret, parse_key_share_entry};
pub use key_schedule::KeySchedule;

/// Maximum allowed length for a TLS record payload in bytes.
/// 
/// According to RFC 8446, this is 2^14 + 256 = 16640 bytes.
pub const MAX_RECORD_LENGTH: u16 = (1 << 14) + 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    Invalid = 0,
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

impl From<ContentType> for u8 {
    fn from(content_type: ContentType) -> Self {
        content_type as u8
    }
}

impl TryFrom<u8> for ContentType {
    type Error = ();

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordHeader {
    pub content_type: ContentType,
    pub version: u16,
    pub length: u16,
}

impl RecordHeader {
    pub fn new(content_type: ContentType, version: u16, length: u16) -> Self {
        Self {
            content_type,
            version,
            length,
        }
    }

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

impl From<(ContentType, u16, u16)> for RecordHeader {
    fn from((content_type, version, length): (ContentType, u16, u16)) -> Self {
        Self {
            content_type,
            version,
            length,
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_header_to_bytes() {
        let header = RecordHeader::new(ContentType::Handshake, 0x0303, 512);
        let bytes = header.to_bytes();
        assert_eq!(bytes, [22, 3, 3, 2, 0]);
    }
}