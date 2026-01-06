use tls_protocol::{ContentType, tls_stream::TlsStream};
use std::net::TcpListener;
use std::io::Read;
use std::thread;
use std::time::Duration;

#[test]
fn test_write_record_handshake() {
    // Start a TCP server in a background thread
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind listener");
    let addr = listener.local_addr().expect("Failed to get local address");
    
    let server_handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("Failed to accept connection");
        stream.set_read_timeout(Some(Duration::from_secs(5))).expect("Failed to set timeout");
        let mut buffer = vec![0u8; 1024];
        let mut total_read = 0;
        let expected_bytes = 17; // 5 byte header + 12 byte payload
        
        // Read until we get all the data
        loop {
            match stream.read(&mut buffer[total_read..]) {
                Ok(0) => break,
                Ok(n) => total_read += n,
                Err(e) => panic!("Failed to read from stream: {}", e),
            }
            if total_read >= expected_bytes {
                break;
            }
        }
        buffer.truncate(total_read);
        buffer
    });
    
    // Give the server time to start
    thread::sleep(Duration::from_millis(10));
    
    // Connect and send a record
    let mut tls_stream = TlsStream::connect(&addr.to_string()).expect("Failed to connect");
    let payload = b"Test payload";
    let bytes_written = tls_stream.write_record(ContentType::Handshake, payload)
        .expect("Failed to write record");
    
    // Wait for server to finish reading
    let received = server_handle.join().expect("Server thread panicked");
    
    // Verify bytes written
    assert_eq!(bytes_written, 5 + payload.len());
    
    // Verify received data
    assert_eq!(received.len(), 5 + payload.len());
    
    // Verify header
    assert_eq!(received[0], 22); // ContentType::Handshake
    assert_eq!(received[1], 0x03); // TLS version major
    assert_eq!(received[2], 0x03); // TLS version minor (TLS 1.2)
    assert_eq!(received[3], 0x00); // Length high byte
    assert_eq!(received[4], 12); // Length low byte (payload.len())
    
    // Verify payload
    assert_eq!(&received[5..], payload);
}

#[test]
fn test_write_record_application_data() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind listener");
    let addr = listener.local_addr().expect("Failed to get local address");
    
    let server_handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("Failed to accept connection");
        stream.set_read_timeout(Some(Duration::from_secs(5))).expect("Failed to set timeout");
        let mut buffer = vec![0u8; 1024];
        let mut total_read = 0;
        let expected_bytes = 26; // 5 byte header + 21 byte payload
        
        // Read until we get all the data
        loop {
            match stream.read(&mut buffer[total_read..]) {
                Ok(0) => break,
                Ok(n) => total_read += n,
                Err(e) => panic!("Failed to read from stream: {}", e),
            }
            if total_read >= expected_bytes {
                break;
            }
        }
        buffer.truncate(total_read);
        buffer
    });
    
    thread::sleep(Duration::from_millis(10));
    
    let mut tls_stream = TlsStream::connect(&addr.to_string()).expect("Failed to connect");
    let payload = b"Application data test";
    let bytes_written = tls_stream.write_record(ContentType::ApplicationData, payload)
        .expect("Failed to write record");
    
    let received = server_handle.join().expect("Server thread panicked");
    
    assert_eq!(bytes_written, 5 + payload.len());
    assert_eq!(received[0], 23); // ContentType::ApplicationData
    assert_eq!(&received[5..], payload);
}

#[test]
fn test_write_record_alert() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind listener");
    let addr = listener.local_addr().expect("Failed to get local address");
    
    let server_handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("Failed to accept connection");
        stream.set_read_timeout(Some(Duration::from_secs(5))).expect("Failed to set timeout");
        let mut buffer = vec![0u8; 1024];
        let mut total_read = 0;
        let expected_bytes = 7; // 5 byte header + 2 byte payload
        
        // Read until we get all the data
        loop {
            match stream.read(&mut buffer[total_read..]) {
                Ok(0) => break,
                Ok(n) => total_read += n,
                Err(e) => panic!("Failed to read from stream: {}", e),
            }
            if total_read >= expected_bytes {
                break;
            }
        }
        buffer.truncate(total_read);
        buffer
    });
    
    thread::sleep(Duration::from_millis(10));
    
    let mut tls_stream = TlsStream::connect(&addr.to_string()).expect("Failed to connect");
    let payload = &[0x02, 0x28]; // Fatal alert, handshake_failure
    let bytes_written = tls_stream.write_record(ContentType::Alert, payload)
        .expect("Failed to write record");
    
    let received = server_handle.join().expect("Server thread panicked");
    
    assert_eq!(bytes_written, 5 + payload.len());
    assert_eq!(received[0], 21); // ContentType::Alert
    assert_eq!(received[4], 2); // Length
    assert_eq!(&received[5..], payload);
}

#[test]
fn test_write_record_empty_payload() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind listener");
    let addr = listener.local_addr().expect("Failed to get local address");
    
    let server_handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("Failed to accept connection");
        stream.set_read_timeout(Some(Duration::from_secs(5))).expect("Failed to set timeout");
        let mut buffer = vec![0u8; 1024];
        let mut total_read = 0;
        let expected_bytes = 5; // 5 byte header only
        
        // Read until we get all the data
        loop {
            match stream.read(&mut buffer[total_read..]) {
                Ok(0) => break,
                Ok(n) => total_read += n,
                Err(e) => panic!("Failed to read from stream: {}", e),
            }
            if total_read >= expected_bytes {
                break;
            }
        }
        buffer.truncate(total_read);
        buffer
    });
    
    thread::sleep(Duration::from_millis(10));
    
    let mut tls_stream = TlsStream::connect(&addr.to_string()).expect("Failed to connect");
    let payload = b"";
    let bytes_written = tls_stream.write_record(ContentType::Handshake, payload)
        .expect("Failed to write record");
    
    let received = server_handle.join().expect("Server thread panicked");
    
    assert_eq!(bytes_written, 5); // Only header
    assert_eq!(received.len(), 5);
    assert_eq!(received[3], 0x00); // Length high byte
    assert_eq!(received[4], 0x00); // Length low byte
}

#[test]
fn test_write_record_large_payload() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind listener");
    let addr = listener.local_addr().expect("Failed to get local address");
    
    let server_handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("Failed to accept connection");
        let mut buffer = vec![0u8; 4096];
        let mut total_read = 0;
        // Read until we get all the data
        loop {
            match stream.read(&mut buffer[total_read..]) {
                Ok(0) => break, // Connection closed
                Ok(n) => total_read += n,
                Err(e) => panic!("Failed to read from stream: {}", e),
            }
            if total_read >= 5 + 1024 {
                break;
            }
        }
        buffer.truncate(total_read);
        buffer
    });
    
    thread::sleep(Duration::from_millis(10));
    
    let mut tls_stream = TlsStream::connect(&addr.to_string()).expect("Failed to connect");
    let payload = vec![0x42u8; 1024]; // 1KB payload
    let bytes_written = tls_stream.write_record(ContentType::ApplicationData, &payload)
        .expect("Failed to write record");
    
    let received = server_handle.join().expect("Server thread panicked");
    
    assert_eq!(bytes_written, 5 + 1024);
    assert_eq!(received.len(), 5 + 1024);
    assert_eq!(received[0], 23); // ContentType::ApplicationData
    assert_eq!(received[3], 0x04); // Length high byte (1024 = 0x0400)
    assert_eq!(received[4], 0x00); // Length low byte
    assert_eq!(&received[5..], &payload[..]);
}

#[test]
fn test_write_multiple_records() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind listener");
    let addr = listener.local_addr().expect("Failed to get local address");
    
    let server_handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("Failed to accept connection");
        stream.set_read_timeout(Some(Duration::from_secs(5))).expect("Failed to set timeout");
        let mut buffer = vec![0u8; 1024];
        let mut total_read = 0;
        let expected_bytes = 21; // 10 bytes for first record + 11 bytes for second record
        
        // Read until we get all the data (multiple records may arrive separately)
        loop {
            match stream.read(&mut buffer[total_read..]) {
                Ok(0) => break, // Connection closed
                Ok(n) => total_read += n,
                Err(e) => panic!("Failed to read from stream: {}", e),
            }
            if total_read >= expected_bytes {
                break;
            }
        }
        buffer.truncate(total_read);
        buffer
    });
    
    thread::sleep(Duration::from_millis(10));
    
    let mut tls_stream = TlsStream::connect(&addr.to_string()).expect("Failed to connect");
    
    // Write first record
    let payload1 = b"First";
    let bytes1 = tls_stream.write_record(ContentType::Handshake, payload1)
        .expect("Failed to write first record");
    
    // Write second record
    let payload2 = b"Second";
    let bytes2 = tls_stream.write_record(ContentType::ApplicationData, payload2)
        .expect("Failed to write second record");
    
    let received = server_handle.join().expect("Server thread panicked");
    
    assert_eq!(bytes1, 5 + payload1.len());
    assert_eq!(bytes2, 5 + payload2.len());
    assert_eq!(received.len(), bytes1 + bytes2);
    
    // Verify first record header
    assert_eq!(received[0], 22); // Handshake
    assert_eq!(received[4], 5); // payload1 length
    assert_eq!(&received[5..10], payload1);
    
    // Verify second record header
    assert_eq!(received[10], 23); // ApplicationData
    assert_eq!(received[14], 6); // payload2 length
    assert_eq!(&received[15..21], payload2);
}

#[test]
fn test_connect_invalid_address() {
    // Try to connect to localhost on a port where nothing is listening
    // This should fail quickly with "connection refused" instead of timing out
    let result = TlsStream::connect("127.0.0.1:1");
    assert!(result.is_err(), "Should fail to connect to non-existent server");
}
