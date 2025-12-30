use std::io::Write;
use std::net::TcpStream;
use crate::{ContentType, RecordHeader};

pub struct TlsStream {
    stream: TcpStream,
}

impl TlsStream {
    pub fn new(stream: TcpStream) -> Self {
        TlsStream { stream }
    }

    pub fn connect(addr: &str) -> std::io::Result<Self> {
        let stream = TcpStream::connect(addr)?;
        Ok(TlsStream::new(stream))
    }

    /// Write a TLS record with the specified content type and payload
    /// Returns the total number of bytes written (header + payload)
    pub fn write_record(&mut self, content_type: ContentType, payload: &[u8]) -> std::io::Result<usize> {
        // TLS 1.2 version (0x0303)
        const TLS_1_2: u16 = 0x0303;
        
        // Create header with payload length
        let header = RecordHeader::new(content_type, TLS_1_2, payload.len() as u16);
        let header_bytes = header.to_bytes();
        
        // Write header
        self.stream.write_all(&header_bytes)?;
        
        // Write payload
        self.stream.write_all(payload)?;
        
        // Flush to ensure data is sent
        self.stream.flush()?;
        
        Ok(header_bytes.len() + payload.len())
    }
}