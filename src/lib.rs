use std::convert::TryFrom;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    Invalid = 0,
    ChangeChiperSpec = 20,
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
            20 => Ok(ContentType::ChangeChiperSpec),
            21 => Ok(ContentType::Alert),
            22 => Ok(ContentType::Handshake),
            23 => Ok(ContentType::ApplicationData),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy)]
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