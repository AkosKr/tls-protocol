use tls_protocol::ContentType;
use std::net::{TcpListener, TcpStream};
use std::io::Read;
use std::convert::TryFrom;

fn handle_client(mut stream: TcpStream) -> std::io::Result<()> {
    let peer_addr = stream.peer_addr()?;
    println!("Client connected from: {}", peer_addr);
    
    let mut buffer = vec![0u8; 4096];
    
    loop {
        // Read at least the header (5 bytes)
        let n = stream.read(&mut buffer)?;
        if n == 0 {
            println!("Client disconnected");
            break;
        }
        
        if n < 5 {
            println!("Received incomplete record header ({} bytes)", n);
            continue;
        }
        
        // Parse the TLS record header
        let content_type = ContentType::try_from(buffer[0])
            .unwrap_or(ContentType::Invalid);
        let version = ((buffer[1] as u16) << 8) | (buffer[2] as u16);
        let length = ((buffer[3] as u16) << 8) | (buffer[4] as u16);
        
        println!("\n=== Received TLS Record ===");
        println!("Content Type: {:?}", content_type);
        println!("Version: 0x{:04x} (TLS {})", version, 
            if version == 0x0303 { "1.2" } 
            else if version == 0x0304 { "1.3" }
            else { "unknown" });
        println!("Payload Length: {} bytes", length);
        
        // Extract payload
        let payload_end = (5 + length as usize).min(n);
        let payload = &buffer[5..payload_end];
        
        println!("Payload (hex): {}", 
            payload.iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" "));
        
        // Try to display as string if it's printable
        if let Ok(s) = std::str::from_utf8(payload) {
            if s.chars().all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace()) {
                println!("Payload (text): \"{}\"", s);
            }
        }
        println!("===========================\n");
    }
    
    Ok(())
}

fn main() -> std::io::Result<()> {
    let addr = "127.0.0.1:4433";
    let listener = TcpListener::bind(addr)?;
    
    println!("TLS server listening on {}", addr);
    println!("Waiting for connections...\n");
    
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(e) = handle_client(stream) {
                    eprintln!("Error handling client: {}", e);
                }
            }
            Err(e) => {
                eprintln!("Connection failed: {}", e);
            }
        }
    }
    
    Ok(())
}
