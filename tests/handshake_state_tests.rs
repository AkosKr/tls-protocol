//! Comprehensive tests for TLS 1.3 Handshake State Machine
//!
//! These tests verify:
//! - Valid state transitions
//! - Invalid transitions (out-of-order messages)
//! - Duplicate messages
//! - Encryption state tracking
//! - State query methods
//! - Failed state handling
//! - Reset functionality
//! - Full handshake flow integration
//! - Error messages
//! - Edge cases

use tls_protocol::{EncryptionState, HandshakeState, TlsError, TlsHandshake};

#[test]
fn test_initial_state() {
    let handshake = TlsHandshake::new();
    assert_eq!(*handshake.current_state(), HandshakeState::Start);
    assert_eq!(
        handshake.current_encryption_state(),
        EncryptionState::Plaintext
    );
    assert!(!handshake.is_handshake_complete());
    assert!(!handshake.is_failed());
}

#[test]
fn test_default_trait() {
    let handshake = TlsHandshake::default();
    assert_eq!(*handshake.current_state(), HandshakeState::Start);
    assert_eq!(
        handshake.current_encryption_state(),
        EncryptionState::Plaintext
    );
}

// ============================================================================
// Valid Transition Tests
// ============================================================================

#[test]
fn test_valid_transition_client_hello() {
    let mut handshake = TlsHandshake::new();
    let result = handshake.on_client_hello_sent();
    assert!(result.is_ok());
    assert_eq!(
        *handshake.current_state(),
        HandshakeState::ClientHelloSent
    );
    assert_eq!(
        handshake.current_encryption_state(),
        EncryptionState::Plaintext
    );
}

#[test]
fn test_valid_transition_server_hello() {
    let mut handshake = TlsHandshake::new();
    handshake.on_client_hello_sent().unwrap();

    let result = handshake.on_server_hello_received();
    assert!(result.is_ok());
    assert_eq!(
        *handshake.current_state(),
        HandshakeState::ServerHelloReceived
    );
    // Encryption should switch to handshake after ServerHello
    assert_eq!(
        handshake.current_encryption_state(),
        EncryptionState::HandshakeEncryption
    );
}

#[test]
fn test_valid_transition_encrypted_extensions() {
    let mut handshake = TlsHandshake::new();
    handshake.on_client_hello_sent().unwrap();
    handshake.on_server_hello_received().unwrap();

    let result = handshake.on_encrypted_extensions_received();
    assert!(result.is_ok());
    assert_eq!(
        *handshake.current_state(),
        HandshakeState::EncryptedExtensionsReceived
    );
    assert_eq!(
        handshake.current_encryption_state(),
        EncryptionState::HandshakeEncryption
    );
}

#[test]
fn test_valid_transition_certificate() {
    let mut handshake = TlsHandshake::new();
    handshake.on_client_hello_sent().unwrap();
    handshake.on_server_hello_received().unwrap();
    handshake.on_encrypted_extensions_received().unwrap();

    let result = handshake.on_certificate_received();
    assert!(result.is_ok());
    assert_eq!(
        *handshake.current_state(),
        HandshakeState::CertificateReceived
    );
    assert_eq!(
        handshake.current_encryption_state(),
        EncryptionState::HandshakeEncryption
    );
}

#[test]
fn test_valid_transition_certificate_verify() {
    let mut handshake = TlsHandshake::new();
    handshake.on_client_hello_sent().unwrap();
    handshake.on_server_hello_received().unwrap();
    handshake.on_encrypted_extensions_received().unwrap();
    handshake.on_certificate_received().unwrap();

    let result = handshake.on_certificate_verify_received();
    assert!(result.is_ok());
    assert_eq!(
        *handshake.current_state(),
        HandshakeState::CertificateVerifyReceived
    );
    assert_eq!(
        handshake.current_encryption_state(),
        EncryptionState::HandshakeEncryption
    );
}

#[test]
fn test_valid_transition_server_finished() {
    let mut handshake = TlsHandshake::new();
    handshake.on_client_hello_sent().unwrap();
    handshake.on_server_hello_received().unwrap();
    handshake.on_encrypted_extensions_received().unwrap();
    handshake.on_certificate_received().unwrap();
    handshake.on_certificate_verify_received().unwrap();

    let result = handshake.on_server_finished_received();
    assert!(result.is_ok());
    assert_eq!(
        *handshake.current_state(),
        HandshakeState::ServerFinishedReceived
    );
    // Still in handshake encryption
    assert_eq!(
        handshake.current_encryption_state(),
        EncryptionState::HandshakeEncryption
    );
}

#[test]
fn test_valid_transition_client_finished() {
    let mut handshake = TlsHandshake::new();
    handshake.on_client_hello_sent().unwrap();
    handshake.on_server_hello_received().unwrap();
    handshake.on_encrypted_extensions_received().unwrap();
    handshake.on_certificate_received().unwrap();
    handshake.on_certificate_verify_received().unwrap();
    handshake.on_server_finished_received().unwrap();

    let result = handshake.on_client_finished_sent();
    assert!(result.is_ok());
    assert_eq!(
        *handshake.current_state(),
        HandshakeState::ClientFinishedSent
    );
    // Encryption should switch to application
    assert_eq!(
        handshake.current_encryption_state(),
        EncryptionState::ApplicationEncryption
    );
    assert!(handshake.is_handshake_complete());
}

#[test]
fn test_valid_transition_application_data() {
    let mut handshake = TlsHandshake::new();
    handshake.on_client_hello_sent().unwrap();
    handshake.on_server_hello_received().unwrap();
    handshake.on_encrypted_extensions_received().unwrap();
    handshake.on_certificate_received().unwrap();
    handshake.on_certificate_verify_received().unwrap();
    handshake.on_server_finished_received().unwrap();
    handshake.on_client_finished_sent().unwrap();

    let result = handshake.on_application_data_sent();
    assert!(result.is_ok());
    assert_eq!(*handshake.current_state(), HandshakeState::Connected);
    assert_eq!(
        handshake.current_encryption_state(),
        EncryptionState::ApplicationEncryption
    );
    assert!(handshake.is_handshake_complete());
}

#[test]
fn test_full_valid_handshake_flow() {
    let mut handshake = TlsHandshake::new();

    // Complete handshake
    assert!(handshake.on_client_hello_sent().is_ok());
    assert!(handshake.on_server_hello_received().is_ok());
    assert!(handshake.on_encrypted_extensions_received().is_ok());
    assert!(handshake.on_certificate_received().is_ok());
    assert!(handshake.on_certificate_verify_received().is_ok());
    assert!(handshake.on_server_finished_received().is_ok());
    assert!(handshake.on_client_finished_sent().is_ok());
    assert!(handshake.on_application_data_sent().is_ok());

    // Verify final state
    assert_eq!(*handshake.current_state(), HandshakeState::Connected);
    assert!(handshake.is_handshake_complete());
    assert!(!handshake.is_failed());
}

// ============================================================================
// Invalid Transition Tests (Out-of-Order Messages)
// ============================================================================

#[test]
fn test_server_hello_before_client_hello() {
    let mut handshake = TlsHandshake::new();
    let result = handshake.on_server_hello_received();
    assert!(result.is_err());
    assert!(handshake.is_failed());

    if let Err(TlsError::UnexpectedMessage {
        expected,
        received,
        state,
    }) = result
    {
        assert_eq!(expected, "ClientHelloSent");
        assert_eq!(received, "ServerHello");
        assert_eq!(state, "Failed");
    } else {
        panic!("Expected UnexpectedMessage error");
    }
}

#[test]
fn test_encrypted_extensions_before_server_hello() {
    let mut handshake = TlsHandshake::new();
    handshake.on_client_hello_sent().unwrap();

    let result = handshake.on_encrypted_extensions_received();
    assert!(result.is_err());
    assert!(handshake.is_failed());
}

#[test]
fn test_certificate_before_encrypted_extensions() {
    let mut handshake = TlsHandshake::new();
    handshake.on_client_hello_sent().unwrap();
    handshake.on_server_hello_received().unwrap();

    let result = handshake.on_certificate_received();
    assert!(result.is_err());
    assert!(handshake.is_failed());
}

#[test]
fn test_certificate_verify_before_certificate() {
    let mut handshake = TlsHandshake::new();
    handshake.on_client_hello_sent().unwrap();
    handshake.on_server_hello_received().unwrap();
    handshake.on_encrypted_extensions_received().unwrap();

    let result = handshake.on_certificate_verify_received();
    assert!(result.is_err());
    assert!(handshake.is_failed());
}

#[test]
fn test_server_finished_before_certificate_verify() {
    let mut handshake = TlsHandshake::new();
    handshake.on_client_hello_sent().unwrap();
    handshake.on_server_hello_received().unwrap();
    handshake.on_encrypted_extensions_received().unwrap();
    handshake.on_certificate_received().unwrap();

    let result = handshake.on_server_finished_received();
    assert!(result.is_err());
    assert!(handshake.is_failed());
}

#[test]
fn test_client_finished_before_server_finished() {
    let mut handshake = TlsHandshake::new();
    handshake.on_client_hello_sent().unwrap();
    handshake.on_server_hello_received().unwrap();
    handshake.on_encrypted_extensions_received().unwrap();
    handshake.on_certificate_received().unwrap();
    handshake.on_certificate_verify_received().unwrap();

    let result = handshake.on_client_finished_sent();
    assert!(result.is_err());
    assert!(handshake.is_failed());
}

#[test]
fn test_skip_certificate_verify() {
    let mut handshake = TlsHandshake::new();
    handshake.on_client_hello_sent().unwrap();
    handshake.on_server_hello_received().unwrap();
    handshake.on_encrypted_extensions_received().unwrap();
    handshake.on_certificate_received().unwrap();
    // Skip CertificateVerify
    let result = handshake.on_server_finished_received();
    assert!(result.is_err());
    assert!(handshake.is_failed());
}

// ============================================================================
// Duplicate Message Tests
// ============================================================================

#[test]
fn test_duplicate_client_hello() {
    let mut handshake = TlsHandshake::new();
    handshake.on_client_hello_sent().unwrap();

    let result = handshake.on_client_hello_sent();
    assert!(result.is_err());
    assert!(handshake.is_failed());
}

#[test]
fn test_duplicate_server_hello() {
    let mut handshake = TlsHandshake::new();
    handshake.on_client_hello_sent().unwrap();
    handshake.on_server_hello_received().unwrap();

    let result = handshake.on_server_hello_received();
    assert!(result.is_err());
    assert!(handshake.is_failed());
}

#[test]
fn test_duplicate_encrypted_extensions() {
    let mut handshake = TlsHandshake::new();
    handshake.on_client_hello_sent().unwrap();
    handshake.on_server_hello_received().unwrap();
    handshake.on_encrypted_extensions_received().unwrap();

    let result = handshake.on_encrypted_extensions_received();
    assert!(result.is_err());
    assert!(handshake.is_failed());
}

#[test]
fn test_duplicate_certificate() {
    let mut handshake = TlsHandshake::new();
    handshake.on_client_hello_sent().unwrap();
    handshake.on_server_hello_received().unwrap();
    handshake.on_encrypted_extensions_received().unwrap();
    handshake.on_certificate_received().unwrap();

    let result = handshake.on_certificate_received();
    assert!(result.is_err());
    assert!(handshake.is_failed());
}

#[test]
fn test_duplicate_certificate_verify() {
    let mut handshake = TlsHandshake::new();
    handshake.on_client_hello_sent().unwrap();
    handshake.on_server_hello_received().unwrap();
    handshake.on_encrypted_extensions_received().unwrap();
    handshake.on_certificate_received().unwrap();
    handshake.on_certificate_verify_received().unwrap();

    let result = handshake.on_certificate_verify_received();
    assert!(result.is_err());
    assert!(handshake.is_failed());
}

#[test]
fn test_duplicate_server_finished() {
    let mut handshake = TlsHandshake::new();
    handshake.on_client_hello_sent().unwrap();
    handshake.on_server_hello_received().unwrap();
    handshake.on_encrypted_extensions_received().unwrap();
    handshake.on_certificate_received().unwrap();
    handshake.on_certificate_verify_received().unwrap();
    handshake.on_server_finished_received().unwrap();

    let result = handshake.on_server_finished_received();
    assert!(result.is_err());
    assert!(handshake.is_failed());
}

#[test]
fn test_duplicate_client_finished() {
    let mut handshake = TlsHandshake::new();
    handshake.on_client_hello_sent().unwrap();
    handshake.on_server_hello_received().unwrap();
    handshake.on_encrypted_extensions_received().unwrap();
    handshake.on_certificate_received().unwrap();
    handshake.on_certificate_verify_received().unwrap();
    handshake.on_server_finished_received().unwrap();
    handshake.on_client_finished_sent().unwrap();

    let result = handshake.on_client_finished_sent();
    assert!(result.is_err());
    assert!(handshake.is_failed());
}

// ============================================================================
// Encryption State Tests
// ============================================================================

#[test]
fn test_encryption_state_plaintext_phase() {
    let mut handshake = TlsHandshake::new();
    assert_eq!(
        handshake.current_encryption_state(),
        EncryptionState::Plaintext
    );

    handshake.on_client_hello_sent().unwrap();
    assert_eq!(
        handshake.current_encryption_state(),
        EncryptionState::Plaintext
    );
}

#[test]
fn test_encryption_state_handshake_phase() {
    let mut handshake = TlsHandshake::new();
    handshake.on_client_hello_sent().unwrap();
    handshake.on_server_hello_received().unwrap();

    assert_eq!(
        handshake.current_encryption_state(),
        EncryptionState::HandshakeEncryption
    );

    // Should remain in handshake encryption through all handshake messages
    handshake.on_encrypted_extensions_received().unwrap();
    assert_eq!(
        handshake.current_encryption_state(),
        EncryptionState::HandshakeEncryption
    );

    handshake.on_certificate_received().unwrap();
    assert_eq!(
        handshake.current_encryption_state(),
        EncryptionState::HandshakeEncryption
    );

    handshake.on_certificate_verify_received().unwrap();
    assert_eq!(
        handshake.current_encryption_state(),
        EncryptionState::HandshakeEncryption
    );

    handshake.on_server_finished_received().unwrap();
    assert_eq!(
        handshake.current_encryption_state(),
        EncryptionState::HandshakeEncryption
    );
}

#[test]
fn test_encryption_state_application_phase() {
    let mut handshake = TlsHandshake::new();
    handshake.on_client_hello_sent().unwrap();
    handshake.on_server_hello_received().unwrap();
    handshake.on_encrypted_extensions_received().unwrap();
    handshake.on_certificate_received().unwrap();
    handshake.on_certificate_verify_received().unwrap();
    handshake.on_server_finished_received().unwrap();
    handshake.on_client_finished_sent().unwrap();

    assert_eq!(
        handshake.current_encryption_state(),
        EncryptionState::ApplicationEncryption
    );

    handshake.on_application_data_sent().unwrap();
    assert_eq!(
        handshake.current_encryption_state(),
        EncryptionState::ApplicationEncryption
    );
}

// ============================================================================
// Application Data Before Handshake Complete Tests
// ============================================================================

#[test]
fn test_application_data_at_start() {
    let mut handshake = TlsHandshake::new();
    let result = handshake.on_application_data_sent();
    assert!(result.is_err());
    assert!(handshake.is_failed());

    if let Err(TlsError::HandshakeFailed(msg)) = result {
        assert!(msg.contains("handshake complete"));
    } else {
        panic!("Expected HandshakeFailed error");
    }
}

#[test]
fn test_application_data_after_client_hello() {
    let mut handshake = TlsHandshake::new();
    handshake.on_client_hello_sent().unwrap();

    let result = handshake.on_application_data_sent();
    assert!(result.is_err());
    assert!(handshake.is_failed());
}

#[test]
fn test_application_data_after_server_hello() {
    let mut handshake = TlsHandshake::new();
    handshake.on_client_hello_sent().unwrap();
    handshake.on_server_hello_received().unwrap();

    let result = handshake.on_application_data_sent();
    assert!(result.is_err());
    assert!(handshake.is_failed());
}

#[test]
fn test_application_data_before_client_finished() {
    let mut handshake = TlsHandshake::new();
    handshake.on_client_hello_sent().unwrap();
    handshake.on_server_hello_received().unwrap();
    handshake.on_encrypted_extensions_received().unwrap();
    handshake.on_certificate_received().unwrap();
    handshake.on_certificate_verify_received().unwrap();
    handshake.on_server_finished_received().unwrap();
    // Don't send client Finished yet

    let result = handshake.on_application_data_sent();
    assert!(result.is_err());
    assert!(handshake.is_failed());
}

#[test]
fn test_multiple_application_data_messages() {
    let mut handshake = TlsHandshake::new();
    handshake.on_client_hello_sent().unwrap();
    handshake.on_server_hello_received().unwrap();
    handshake.on_encrypted_extensions_received().unwrap();
    handshake.on_certificate_received().unwrap();
    handshake.on_certificate_verify_received().unwrap();
    handshake.on_server_finished_received().unwrap();
    handshake.on_client_finished_sent().unwrap();

    // First application data
    assert!(handshake.on_application_data_sent().is_ok());
    assert_eq!(*handshake.current_state(), HandshakeState::Connected);

    // Multiple application data messages should be allowed
    assert!(handshake.on_application_data_sent().is_ok());
    assert!(handshake.on_application_data_sent().is_ok());
    assert_eq!(*handshake.current_state(), HandshakeState::Connected);
}

// ============================================================================
// State Query Methods Tests
// ============================================================================

#[test]
fn test_is_handshake_complete_states() {
    let mut handshake = TlsHandshake::new();
    assert!(!handshake.is_handshake_complete());

    handshake.on_client_hello_sent().unwrap();
    assert!(!handshake.is_handshake_complete());

    handshake.on_server_hello_received().unwrap();
    assert!(!handshake.is_handshake_complete());

    handshake.on_encrypted_extensions_received().unwrap();
    assert!(!handshake.is_handshake_complete());

    handshake.on_certificate_received().unwrap();
    assert!(!handshake.is_handshake_complete());

    handshake.on_certificate_verify_received().unwrap();
    assert!(!handshake.is_handshake_complete());

    handshake.on_server_finished_received().unwrap();
    assert!(!handshake.is_handshake_complete());

    // Complete after client Finished
    handshake.on_client_finished_sent().unwrap();
    assert!(handshake.is_handshake_complete());

    handshake.on_application_data_sent().unwrap();
    assert!(handshake.is_handshake_complete());
}

#[test]
fn test_is_failed() {
    let mut handshake = TlsHandshake::new();
    assert!(!handshake.is_failed());

    // Cause a failure
    let _ = handshake.on_server_hello_received();
    assert!(handshake.is_failed());
}

#[test]
fn test_current_state_getter() {
    let mut handshake = TlsHandshake::new();
    assert_eq!(*handshake.current_state(), HandshakeState::Start);

    handshake.on_client_hello_sent().unwrap();
    assert_eq!(
        *handshake.current_state(),
        HandshakeState::ClientHelloSent
    );
}

#[test]
fn test_current_encryption_state_getter() {
    let mut handshake = TlsHandshake::new();
    assert_eq!(
        handshake.current_encryption_state(),
        EncryptionState::Plaintext
    );

    handshake.on_client_hello_sent().unwrap();
    handshake.on_server_hello_received().unwrap();
    assert_eq!(
        handshake.current_encryption_state(),
        EncryptionState::HandshakeEncryption
    );
}

// ============================================================================
// Reset Tests
// ============================================================================

#[test]
fn test_reset_from_start() {
    let mut handshake = TlsHandshake::new();
    handshake.reset();
    assert_eq!(*handshake.current_state(), HandshakeState::Start);
    assert_eq!(
        handshake.current_encryption_state(),
        EncryptionState::Plaintext
    );
}

#[test]
fn test_reset_from_mid_handshake() {
    let mut handshake = TlsHandshake::new();
    handshake.on_client_hello_sent().unwrap();
    handshake.on_server_hello_received().unwrap();
    handshake.on_encrypted_extensions_received().unwrap();

    handshake.reset();

    assert_eq!(*handshake.current_state(), HandshakeState::Start);
    assert_eq!(
        handshake.current_encryption_state(),
        EncryptionState::Plaintext
    );
    assert!(!handshake.is_handshake_complete());
    assert!(!handshake.is_failed());
}

#[test]
fn test_reset_from_completed() {
    let mut handshake = TlsHandshake::new();
    handshake.on_client_hello_sent().unwrap();
    handshake.on_server_hello_received().unwrap();
    handshake.on_encrypted_extensions_received().unwrap();
    handshake.on_certificate_received().unwrap();
    handshake.on_certificate_verify_received().unwrap();
    handshake.on_server_finished_received().unwrap();
    handshake.on_client_finished_sent().unwrap();
    handshake.on_application_data_sent().unwrap();

    handshake.reset();

    assert_eq!(*handshake.current_state(), HandshakeState::Start);
    assert_eq!(
        handshake.current_encryption_state(),
        EncryptionState::Plaintext
    );
    assert!(!handshake.is_handshake_complete());
}

#[test]
fn test_reset_from_failed() {
    let mut handshake = TlsHandshake::new();
    let _ = handshake.on_server_hello_received(); // Invalid transition
    assert!(handshake.is_failed());

    handshake.reset();

    assert_eq!(*handshake.current_state(), HandshakeState::Start);
    assert!(!handshake.is_failed());
}

#[test]
fn test_can_start_new_handshake_after_reset() {
    let mut handshake = TlsHandshake::new();
    handshake.on_client_hello_sent().unwrap();
    handshake.on_server_hello_received().unwrap();

    handshake.reset();

    // Should be able to start fresh handshake
    assert!(handshake.on_client_hello_sent().is_ok());
    assert!(handshake.on_server_hello_received().is_ok());
}

// ============================================================================
// Error Message Validation Tests
// ============================================================================

#[test]
fn test_unexpected_message_error_details() {
    let mut handshake = TlsHandshake::new();
    let result = handshake.on_server_hello_received();

    match result {
        Err(TlsError::UnexpectedMessage {
            expected,
            received,
            state,
        }) => {
            assert_eq!(expected, "ClientHelloSent");
            assert_eq!(received, "ServerHello");
            assert_eq!(state, "Failed");
        }
        _ => panic!("Expected UnexpectedMessage error"),
    }
}

#[test]
fn test_handshake_failed_error_message() {
    let mut handshake = TlsHandshake::new();
    let result = handshake.on_application_data_sent();

    match result {
        Err(TlsError::HandshakeFailed(msg)) => {
            assert!(msg.contains("Application data"));
            assert!(msg.contains("handshake complete"));
        }
        _ => panic!("Expected HandshakeFailed error"),
    }
}

// ============================================================================
// Clone and Debug Tests
// ============================================================================

#[test]
fn test_handshake_clone() {
    let mut handshake = TlsHandshake::new();
    handshake.on_client_hello_sent().unwrap();
    handshake.on_server_hello_received().unwrap();

    let cloned = handshake.clone();
    assert_eq!(
        *cloned.current_state(),
        HandshakeState::ServerHelloReceived
    );
    assert_eq!(
        cloned.current_encryption_state(),
        EncryptionState::HandshakeEncryption
    );
}

#[test]
fn test_handshake_debug() {
    let handshake = TlsHandshake::new();
    let debug_str = format!("{:?}", handshake);
    assert!(debug_str.contains("TlsHandshake"));
    assert!(debug_str.contains("Start"));
    assert!(debug_str.contains("Plaintext"));
}

#[test]
fn test_handshake_state_eq() {
    let state1 = HandshakeState::Start;
    let state2 = HandshakeState::Start;
    let state3 = HandshakeState::ClientHelloSent;

    assert_eq!(state1, state2);
    assert_ne!(state1, state3);
}

#[test]
fn test_encryption_state_eq() {
    let enc1 = EncryptionState::Plaintext;
    let enc2 = EncryptionState::Plaintext;
    let enc3 = EncryptionState::HandshakeEncryption;

    assert_eq!(enc1, enc2);
    assert_ne!(enc1, enc3);
}

// ============================================================================
// Edge Cases and Integration Tests
// ============================================================================

#[test]
fn test_state_after_failed_transition() {
    let mut handshake = TlsHandshake::new();
    let _ = handshake.on_encrypted_extensions_received(); // Invalid

    // State should be Failed
    match handshake.current_state() {
        HandshakeState::Failed(msg) => {
            assert!(msg.contains("EncryptedExtensions"));
        }
        _ => panic!("Expected Failed state"),
    }
}

#[test]
fn test_encryption_state_string_representation() {
    assert_eq!(EncryptionState::Plaintext.as_str(), "Plaintext");
    assert_eq!(
        EncryptionState::HandshakeEncryption.as_str(),
        "HandshakeEncryption"
    );
    assert_eq!(
        EncryptionState::ApplicationEncryption.as_str(),
        "ApplicationEncryption"
    );
}

#[test]
fn test_handshake_state_string_representation() {
    assert_eq!(HandshakeState::Start.as_str(), "Start");
    assert_eq!(
        HandshakeState::ClientHelloSent.as_str(),
        "ClientHelloSent"
    );
    assert_eq!(
        HandshakeState::ServerHelloReceived.as_str(),
        "ServerHelloReceived"
    );
    assert_eq!(
        HandshakeState::EncryptedExtensionsReceived.as_str(),
        "EncryptedExtensionsReceived"
    );
    assert_eq!(
        HandshakeState::CertificateReceived.as_str(),
        "CertificateReceived"
    );
    assert_eq!(
        HandshakeState::CertificateVerifyReceived.as_str(),
        "CertificateVerifyReceived"
    );
    assert_eq!(
        HandshakeState::ServerFinishedReceived.as_str(),
        "ServerFinishedReceived"
    );
    assert_eq!(
        HandshakeState::ClientFinishedSent.as_str(),
        "ClientFinishedSent"
    );
    assert_eq!(HandshakeState::Connected.as_str(), "Connected");
    assert_eq!(
        HandshakeState::Failed("test".to_string()).as_str(),
        "Failed"
    );
}
