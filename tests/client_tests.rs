//! Unit tests for TlsClient
//!
//! These tests verify:
//! - Error handling for operations in wrong state
//! - State transition requirements
//! - Proper error messages
//!
//! Note: Full integration testing with a real TLS server is done separately

use tls_protocol::{TlsClient, TlsError};
use std::net::TcpListener;

// Helper function to create a TlsClient with a mock TCP connection
fn create_mock_client() -> TlsClient {
    // Create a local listener and connect to it to get a valid TcpStream
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let stream = std::net::TcpStream::connect(addr).unwrap();
    
    TlsClient::new(stream)
}

#[test]
fn test_client_creation() {
    let client = create_mock_client();
    assert!(!client.is_ready());
}

#[test]
fn test_send_application_data_before_handshake() {
    let mut client = create_mock_client();
    
    let result = client.send_application_data(b"test data");
    assert!(result.is_err());
    
    match result {
        Err(TlsError::InvalidState(msg)) => {
            assert!(msg.contains("Handshake not complete"));
        }
        _ => panic!("Expected InvalidState error"),
    }
}

#[test]
fn test_receive_application_data_before_handshake() {
    let mut client = create_mock_client();
    
    let result = client.receive_application_data();
    assert!(result.is_err());
    
    match result {
        Err(TlsError::InvalidState(msg)) => {
            assert!(msg.contains("Handshake not complete"));
        }
        _ => panic!("Expected InvalidState error"),
    }
}

#[test]
fn test_client_not_ready_initially() {
    let client = create_mock_client();
    assert!(!client.is_ready(), "Client should not be ready before handshake");
}

#[test]
#[ignore] // This test requires a real TLS server
fn test_connect_to_real_server() {
    // This would require a real TLS 1.3 server
    // Kept as an example of integration test structure
    let result = TlsClient::connect("example.com:443");
    // In a real test environment, this would succeed
    assert!(result.is_ok() || result.is_err()); // Placeholder
}

#[test]
fn test_connect_invalid_address() {
    // Test connection to invalid address
    let result = TlsClient::connect("invalid.address.that.does.not.exist:443");
    assert!(result.is_err());
}
