use tls_protocol::{ContentType, tls_stream::TlsStream};

fn main() -> std::io::Result<()> {
    println!("Connecting to localhost:4433...");
    
    let mut tls_stream = TlsStream::connect("127.0.0.1:4433")?;
    println!("Connected!");
    
    // Send a test handshake record
    let payload = b"Hello, TLS!";
    let bytes_written = tls_stream.write_record(ContentType::Handshake, payload)?;
    
    println!("Sent {} bytes (5 byte header + {} byte payload)", bytes_written, payload.len());
    println!("Payload: {:?}", std::str::from_utf8(payload).unwrap());
    
    Ok(())
}
