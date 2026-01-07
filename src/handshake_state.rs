//! TLS 1.3 Handshake State Machine (RFC 8446, Section 2 & Appendix A)
//!
//! This module implements a state machine to track and enforce correct TLS 1.3
//! handshake message ordering, encryption state transitions, and protocol compliance.
//!
//! ## Handshake Flow (Client Perspective)
//!
//! 1. Start
//! 2. Send ClientHello → ClientHelloSent
//! 3. Receive ServerHello → ServerHelloReceived (switch to handshake encryption)
//! 4. Receive EncryptedExtensions → EncryptedExtensionsReceived
//! 5. Receive Certificate → CertificateReceived
//! 6. Receive CertificateVerify → CertificateVerifyReceived
//! 7. Receive Finished → ServerFinishedReceived
//! 8. Send Finished → ClientFinishedSent (switch to application encryption)
//! 9. Exchange ApplicationData → Connected
//!
//! ## Security Features
//!
//! - Enforces strict message ordering (prevents downgrade attacks)
//! - Validates encryption state transitions
//! - Blocks application data until handshake complete
//! - Fails closed on any protocol violation
//!
//! ## Usage
//!
//! ```rust
//! use tls_protocol::TlsHandshake;
//!
//! let mut handshake = TlsHandshake::new();
//!
//! // Send ClientHello
//! handshake.on_client_hello_sent().unwrap();
//!
//! // Receive ServerHello
//! handshake.on_server_hello_received().unwrap();
//! assert_eq!(handshake.current_encryption_state(),
//!            tls_protocol::EncryptionState::HandshakeEncryption);
//!
//! // Continue through handshake...
//! handshake.on_encrypted_extensions_received().unwrap();
//! handshake.on_certificate_received().unwrap();
//! handshake.on_certificate_verify_received().unwrap();
//! handshake.on_server_finished_received().unwrap();
//!
//! // Send client Finished
//! handshake.on_client_finished_sent().unwrap();
//! assert_eq!(handshake.current_encryption_state(),
//!            tls_protocol::EncryptionState::ApplicationEncryption);
//!
//! // Ready for application data
//! assert!(handshake.is_handshake_complete());
//! handshake.on_application_data_sent().unwrap();
//! ```

use crate::error::TlsError;

/// Handshake state representing the client's position in the TLS 1.3 handshake
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeState {
    /// Initial state - no messages sent or received
    Start,
    /// ClientHello has been sent
    ClientHelloSent,
    /// ServerHello has been received and validated
    ServerHelloReceived,
    /// EncryptedExtensions has been received
    EncryptedExtensionsReceived,
    /// Certificate message has been received
    CertificateReceived,
    /// CertificateVerify message has been received
    CertificateVerifyReceived,
    /// Server Finished message has been received and verified
    ServerFinishedReceived,
    /// Client Finished message has been sent
    ClientFinishedSent,
    /// Handshake complete, ready for application data
    Connected,
    /// Handshake failed with error description
    Failed(String),
}

impl HandshakeState {
    /// Get a string representation of the state for error messages
    pub fn as_str(&self) -> &str {
        match self {
            HandshakeState::Start => "Start",
            HandshakeState::ClientHelloSent => "ClientHelloSent",
            HandshakeState::ServerHelloReceived => "ServerHelloReceived",
            HandshakeState::EncryptedExtensionsReceived => "EncryptedExtensionsReceived",
            HandshakeState::CertificateReceived => "CertificateReceived",
            HandshakeState::CertificateVerifyReceived => "CertificateVerifyReceived",
            HandshakeState::ServerFinishedReceived => "ServerFinishedReceived",
            HandshakeState::ClientFinishedSent => "ClientFinishedSent",
            HandshakeState::Connected => "Connected",
            HandshakeState::Failed(_) => "Failed",
        }
    }
}

/// Encryption state tracking for TLS 1.3
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionState {
    /// No encryption - ClientHello and ServerHello are plaintext
    Plaintext,
    /// Handshake encryption active - uses handshake traffic keys
    HandshakeEncryption,
    /// Application encryption active - uses application traffic keys
    ApplicationEncryption,
}

impl EncryptionState {
    /// Get a string representation of the encryption state
    pub fn as_str(&self) -> &str {
        match self {
            EncryptionState::Plaintext => "Plaintext",
            EncryptionState::HandshakeEncryption => "HandshakeEncryption",
            EncryptionState::ApplicationEncryption => "ApplicationEncryption",
        }
    }
}

/// TLS 1.3 Handshake State Machine
///
/// Manages handshake state transitions and encryption state for a TLS 1.3 connection.
/// Enforces RFC 8446 message ordering and prevents protocol violations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsHandshake {
    /// Current handshake state
    state: HandshakeState,
    /// Current encryption state
    encryption_state: EncryptionState,
}

impl TlsHandshake {
    /// Create a new handshake state machine at the Start state
    pub fn new() -> Self {
        Self {
            state: HandshakeState::Start,
            encryption_state: EncryptionState::Plaintext,
        }
    }

    /// Get the current handshake state
    pub fn current_state(&self) -> &HandshakeState {
        &self.state
    }

    /// Get the current encryption state
    pub fn current_encryption_state(&self) -> EncryptionState {
        self.encryption_state
    }

    /// Check if the handshake is complete and ready for application data
    pub fn is_handshake_complete(&self) -> bool {
        matches!(
            self.state,
            HandshakeState::ClientFinishedSent | HandshakeState::Connected
        )
    }

    /// Check if the state machine has failed
    pub fn is_failed(&self) -> bool {
        matches!(self.state, HandshakeState::Failed(_))
    }

    /// Reset the state machine to the initial state
    pub fn reset(&mut self) {
        self.state = HandshakeState::Start;
        self.encryption_state = EncryptionState::Plaintext;
    }

    /// Transition to ClientHelloSent state
    ///
    /// Valid from: Start
    pub fn on_client_hello_sent(&mut self) -> Result<(), TlsError> {
        match self.state {
            HandshakeState::Start => {
                self.state = HandshakeState::ClientHelloSent;
                Ok(())
            }
            _ => {
                let error = format!(
                    "Cannot send ClientHello from state: {}",
                    self.state.as_str()
                );
                self.state = HandshakeState::Failed(error.clone());
                Err(TlsError::UnexpectedMessage {
                    expected: "Start".to_string(),
                    received: "ClientHello".to_string(),
                    state: self.state.as_str().to_string(),
                })
            }
        }
    }

    /// Transition to ServerHelloReceived state and enable handshake encryption
    ///
    /// Valid from: ClientHelloSent
    pub fn on_server_hello_received(&mut self) -> Result<(), TlsError> {
        match self.state {
            HandshakeState::ClientHelloSent => {
                self.state = HandshakeState::ServerHelloReceived;
                self.encryption_state = EncryptionState::HandshakeEncryption;
                Ok(())
            }
            _ => {
                let error = format!(
                    "Cannot receive ServerHello from state: {}",
                    self.state.as_str()
                );
                self.state = HandshakeState::Failed(error.clone());
                Err(TlsError::UnexpectedMessage {
                    expected: "ClientHelloSent".to_string(),
                    received: "ServerHello".to_string(),
                    state: self.state.as_str().to_string(),
                })
            }
        }
    }

    /// Transition to EncryptedExtensionsReceived state
    ///
    /// Valid from: ServerHelloReceived
    pub fn on_encrypted_extensions_received(&mut self) -> Result<(), TlsError> {
        match self.state {
            HandshakeState::ServerHelloReceived => {
                // Defensive check: Validate encryption state is correct for this message.
                // This should always pass under normal operation since `on_server_hello_received()`
                // sets HandshakeEncryption, but provides defense-in-depth against state corruption.
                if self.encryption_state != EncryptionState::HandshakeEncryption {
                    let error = format!(
                        "EncryptedExtensions must be in HandshakeEncryption, found: {}",
                        self.encryption_state.as_str()
                    );
                    self.state = HandshakeState::Failed(error.clone());
                    return Err(TlsError::MessageInWrongEncryptionState {
                        message: "EncryptedExtensions".to_string(),
                        expected_encryption: "HandshakeEncryption".to_string(),
                        actual_encryption: self.encryption_state.as_str().to_string(),
                    });
                }
                self.state = HandshakeState::EncryptedExtensionsReceived;
                Ok(())
            }
            _ => {
                let error = format!(
                    "Cannot receive EncryptedExtensions from state: {}",
                    self.state.as_str()
                );
                self.state = HandshakeState::Failed(error.clone());
                Err(TlsError::UnexpectedMessage {
                    expected: "ServerHelloReceived".to_string(),
                    received: "EncryptedExtensions".to_string(),
                    state: self.state.as_str().to_string(),
                })
            }
        }
    }

    /// Transition to CertificateReceived state
    ///
    /// Valid from: EncryptedExtensionsReceived
    pub fn on_certificate_received(&mut self) -> Result<(), TlsError> {
        match self.state {
            HandshakeState::EncryptedExtensionsReceived => {
                // Defensive check: Validate encryption state is correct for this message.
                // This should always pass under normal operation since `on_server_hello_received()`
                // sets HandshakeEncryption, but provides defense-in-depth against state corruption.
                if self.encryption_state != EncryptionState::HandshakeEncryption {
                    let error = format!(
                        "Certificate must be in HandshakeEncryption, found: {}",
                        self.encryption_state.as_str()
                    );
                    self.state = HandshakeState::Failed(error.clone());
                    return Err(TlsError::MessageInWrongEncryptionState {
                        message: "Certificate".to_string(),
                        expected_encryption: "HandshakeEncryption".to_string(),
                        actual_encryption: self.encryption_state.as_str().to_string(),
                    });
                }
                self.state = HandshakeState::CertificateReceived;
                Ok(())
            }
            _ => {
                let error = format!(
                    "Cannot receive Certificate from state: {}",
                    self.state.as_str()
                );
                self.state = HandshakeState::Failed(error.clone());
                Err(TlsError::UnexpectedMessage {
                    expected: "EncryptedExtensionsReceived".to_string(),
                    received: "Certificate".to_string(),
                    state: self.state.as_str().to_string(),
                })
            }
        }
    }

    /// Transition to CertificateVerifyReceived state
    ///
    /// Valid from: CertificateReceived
    pub fn on_certificate_verify_received(&mut self) -> Result<(), TlsError> {
        match self.state {
            HandshakeState::CertificateReceived => {
                // Defensive check: Validate encryption state is correct for this message.
                // This should always pass under normal operation since `on_server_hello_received()`
                // sets HandshakeEncryption, but provides defense-in-depth against state corruption.
                if self.encryption_state != EncryptionState::HandshakeEncryption {
                    let error = format!(
                        "CertificateVerify must be in HandshakeEncryption, found: {}",
                        self.encryption_state.as_str()
                    );
                    self.state = HandshakeState::Failed(error.clone());
                    return Err(TlsError::MessageInWrongEncryptionState {
                        message: "CertificateVerify".to_string(),
                        expected_encryption: "HandshakeEncryption".to_string(),
                        actual_encryption: self.encryption_state.as_str().to_string(),
                    });
                }
                self.state = HandshakeState::CertificateVerifyReceived;
                Ok(())
            }
            _ => {
                let error = format!(
                    "Cannot receive CertificateVerify from state: {}",
                    self.state.as_str()
                );
                self.state = HandshakeState::Failed(error.clone());
                Err(TlsError::UnexpectedMessage {
                    expected: "CertificateReceived".to_string(),
                    received: "CertificateVerify".to_string(),
                    state: self.state.as_str().to_string(),
                })
            }
        }
    }

    /// Transition to ServerFinishedReceived state
    ///
    /// Valid from: CertificateVerifyReceived
    pub fn on_server_finished_received(&mut self) -> Result<(), TlsError> {
        match self.state {
            HandshakeState::CertificateVerifyReceived => {
                // Defensive check: Validate encryption state is correct for this message.
                // This should always pass under normal operation since `on_server_hello_received()`
                // sets HandshakeEncryption, but provides defense-in-depth against state corruption.
                if self.encryption_state != EncryptionState::HandshakeEncryption {
                    let error = format!(
                        "Server Finished must be in HandshakeEncryption, found: {}",
                        self.encryption_state.as_str()
                    );
                    self.state = HandshakeState::Failed(error.clone());
                    return Err(TlsError::MessageInWrongEncryptionState {
                        message: "ServerFinished".to_string(),
                        expected_encryption: "HandshakeEncryption".to_string(),
                        actual_encryption: self.encryption_state.as_str().to_string(),
                    });
                }
                self.state = HandshakeState::ServerFinishedReceived;
                Ok(())
            }
            _ => {
                let error = format!(
                    "Cannot receive Server Finished from state: {}",
                    self.state.as_str()
                );
                self.state = HandshakeState::Failed(error.clone());
                Err(TlsError::UnexpectedMessage {
                    expected: "CertificateVerifyReceived".to_string(),
                    received: "ServerFinished".to_string(),
                    state: self.state.as_str().to_string(),
                })
            }
        }
    }

    /// Transition to ClientFinishedSent state and enable application encryption
    ///
    /// Valid from: ServerFinishedReceived
    pub fn on_client_finished_sent(&mut self) -> Result<(), TlsError> {
        match self.state {
            HandshakeState::ServerFinishedReceived => {
                self.state = HandshakeState::ClientFinishedSent;
                self.encryption_state = EncryptionState::ApplicationEncryption;
                Ok(())
            }
            _ => {
                let error = format!(
                    "Cannot send Client Finished from state: {}",
                    self.state.as_str()
                );
                self.state = HandshakeState::Failed(error.clone());
                Err(TlsError::UnexpectedMessage {
                    expected: "ServerFinishedReceived".to_string(),
                    received: "ClientFinished".to_string(),
                    state: self.state.as_str().to_string(),
                })
            }
        }
    }

    /// Transition to Connected state (ready for application data)
    ///
    /// Valid from: ClientFinishedSent
    pub fn on_application_data_sent(&mut self) -> Result<(), TlsError> {
        match self.state {
            HandshakeState::ClientFinishedSent | HandshakeState::Connected => {
                // Defensive check: Validate encryption state is correct for this message.
                // This should always pass under normal operation since `on_client_finished_sent()`
                // sets ApplicationEncryption, but provides defense-in-depth against state corruption.
                if self.encryption_state != EncryptionState::ApplicationEncryption {
                    let error = format!(
                        "ApplicationData must be in ApplicationEncryption, found: {}",
                        self.encryption_state.as_str()
                    );
                    self.state = HandshakeState::Failed(error.clone());
                    return Err(TlsError::MessageInWrongEncryptionState {
                        message: "ApplicationData".to_string(),
                        expected_encryption: "ApplicationEncryption".to_string(),
                        actual_encryption: self.encryption_state.as_str().to_string(),
                    });
                }
                self.state = HandshakeState::Connected;
                Ok(())
            }
            _ => {
                let error = format!(
                    "Cannot send ApplicationData from state: {}. Handshake not complete.",
                    self.state.as_str()
                );
                self.state = HandshakeState::Failed(error.clone());
                Err(TlsError::HandshakeFailed(
                    "Application data sent before handshake complete".to_string(),
                ))
            }
        }
    }
}

impl Default for TlsHandshake {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_handshake_starts_at_start_state() {
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
    fn test_valid_full_handshake_flow() {
        let mut handshake = TlsHandshake::new();

        // ClientHello sent
        assert!(handshake.on_client_hello_sent().is_ok());
        assert_eq!(*handshake.current_state(), HandshakeState::ClientHelloSent);
        assert_eq!(
            handshake.current_encryption_state(),
            EncryptionState::Plaintext
        );

        // ServerHello received - encryption switches to handshake
        assert!(handshake.on_server_hello_received().is_ok());
        assert_eq!(
            *handshake.current_state(),
            HandshakeState::ServerHelloReceived
        );
        assert_eq!(
            handshake.current_encryption_state(),
            EncryptionState::HandshakeEncryption
        );

        // EncryptedExtensions received
        assert!(handshake.on_encrypted_extensions_received().is_ok());
        assert_eq!(
            *handshake.current_state(),
            HandshakeState::EncryptedExtensionsReceived
        );

        // Certificate received
        assert!(handshake.on_certificate_received().is_ok());
        assert_eq!(
            *handshake.current_state(),
            HandshakeState::CertificateReceived
        );

        // CertificateVerify received
        assert!(handshake.on_certificate_verify_received().is_ok());
        assert_eq!(
            *handshake.current_state(),
            HandshakeState::CertificateVerifyReceived
        );

        // Server Finished received
        assert!(handshake.on_server_finished_received().is_ok());
        assert_eq!(
            *handshake.current_state(),
            HandshakeState::ServerFinishedReceived
        );

        // Client Finished sent - encryption switches to application
        assert!(handshake.on_client_finished_sent().is_ok());
        assert_eq!(
            *handshake.current_state(),
            HandshakeState::ClientFinishedSent
        );
        assert_eq!(
            handshake.current_encryption_state(),
            EncryptionState::ApplicationEncryption
        );
        assert!(handshake.is_handshake_complete());

        // ApplicationData sent
        assert!(handshake.on_application_data_sent().is_ok());
        assert_eq!(*handshake.current_state(), HandshakeState::Connected);
        assert!(handshake.is_handshake_complete());
    }

    #[test]
    fn test_client_hello_from_wrong_state() {
        let mut handshake = TlsHandshake::new();
        handshake.on_client_hello_sent().unwrap();

        // Try to send ClientHello again
        let result = handshake.on_client_hello_sent();
        assert!(result.is_err());
        assert!(handshake.is_failed());
    }

    #[test]
    fn test_out_of_order_messages() {
        let mut handshake = TlsHandshake::new();

        // Try to receive ServerHello before sending ClientHello
        let result = handshake.on_server_hello_received();
        assert!(result.is_err());
        assert!(handshake.is_failed());
    }

    #[test]
    fn test_reset() {
        let mut handshake = TlsHandshake::new();
        handshake.on_client_hello_sent().unwrap();
        handshake.on_server_hello_received().unwrap();

        handshake.reset();

        assert_eq!(*handshake.current_state(), HandshakeState::Start);
        assert_eq!(
            handshake.current_encryption_state(),
            EncryptionState::Plaintext
        );
        assert!(!handshake.is_handshake_complete());
    }

    #[test]
    fn test_application_data_before_handshake_complete() {
        let mut handshake = TlsHandshake::new();
        handshake.on_client_hello_sent().unwrap();

        let result = handshake.on_application_data_sent();
        assert!(result.is_err());
        assert!(handshake.is_failed());
    }
}
