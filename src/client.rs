//! TLS 1.3 Client Implementation
//!
//! This module provides a high-level TLS 1.3 client that orchestrates all the
//! protocol components into a working client implementation.
//!
//! # Example Usage
//!
//! ```rust,no_run
//! use tls_protocol::TlsClient;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Connect and perform handshake
//! let mut client = TlsClient::connect("example.com:443")?;
//! client.perform_handshake()?;
//!
//! // Send application data
//! client.send_application_data(b"GET / HTTP/1.1\r\n\r\n")?;
//!
//! // Receive application data
//! let response = client.receive_application_data()?;
//! # Ok(())
//! # }
//! ```

use std::io::{Read, Write};
use std::net::TcpStream;

use crate::aead::{decrypt_record, encrypt_record, AeadCipher};
use crate::certificate::Certificate;
use crate::certificate_verify::CertificateVerify;
use crate::client_hello::ClientHello;
use crate::error::TlsError;
use crate::extensions::Extension;
use crate::finished::Finished;
use crate::handshake_state::{EncryptionState, TlsHandshake};
use crate::key_schedule::{derive_traffic_keys, KeySchedule};
use crate::parser::parse_header;
use crate::server_hello::ServerHello;
use crate::transcript_hash::TranscriptHash;
use crate::x25519_key_exchange::{parse_key_share_entry, X25519KeyPair};
use crate::{ContentType, RecordHeader};

/// TLS 1.3 Client
///
/// Manages a complete TLS 1.3 client connection including handshake state,
/// key schedule, encryption, and application data transfer.
pub struct TlsClient {
    /// Underlying TCP stream
    stream: TcpStream,

    /// Handshake state machine
    handshake: TlsHandshake,

    /// Key schedule for deriving traffic secrets
    key_schedule: KeySchedule,

    /// Transcript hash for handshake messages
    transcript: TranscriptHash,

    /// Client's X25519 keypair for ECDHE
    client_keypair: Option<X25519KeyPair>,

    /// Client handshake traffic keys (used after ServerHello)
    client_handshake_keys: Option<AeadCipher>,

    /// Server handshake traffic keys (used after ServerHello)
    server_handshake_keys: Option<AeadCipher>,

    /// Client application traffic keys (used after Finished)
    client_application_keys: Option<AeadCipher>,

    /// Server application traffic keys (used after Finished)
    server_application_keys: Option<AeadCipher>,

    /// Server name for SNI extension (optional)
    server_name: Option<String>,

    /// Custom cipher suites to use in ClientHello (optional)
    /// If None, uses default cipher suites
    custom_cipher_suites: Option<Vec<u16>>,
}

impl TlsClient {
    /// Create a new TLS client from an existing TCP stream
    ///
    /// # Arguments
    /// * `stream` - An established TCP connection
    ///
    /// # Returns
    /// A new `TlsClient` instance ready to perform a handshake
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            handshake: TlsHandshake::new(),
            key_schedule: KeySchedule::new(),
            transcript: TranscriptHash::new(),
            client_keypair: None,
            client_handshake_keys: None,
            server_handshake_keys: None,
            client_application_keys: None,
            server_application_keys: None,
            server_name: None,
            custom_cipher_suites: None,
        }
    }

    /// Set custom cipher suites for the ClientHello
    ///
    /// # Arguments
    /// * `cipher_suites` - List of cipher suite identifiers to offer
    ///
    /// # Example
    /// ```rust,no_run
    /// use tls_protocol::TlsClient;
    /// use tls_protocol::client_hello::TLS_AES_128_GCM_SHA256;
    ///
    /// let mut client = TlsClient::connect("example.com:443")?;
    /// client.set_cipher_suites(vec![TLS_AES_128_GCM_SHA256]);
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn set_cipher_suites(&mut self, cipher_suites: Vec<u16>) {
        self.custom_cipher_suites = Some(cipher_suites);
    }

    /// Connect to a TLS server and create a new client
    ///
    /// # Arguments
    /// * `addr` - Server address in format "host:port"
    ///
    /// # Returns
    /// A new `TlsClient` instance with an established TCP connection
    ///
    /// # Example
    /// ```rust,no_run
    /// use tls_protocol::TlsClient;
    ///
    /// let client = TlsClient::connect("example.com:443")?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn connect(addr: &str) -> std::io::Result<Self> {
        let stream = TcpStream::connect(addr)?;

        // Extract hostname from address for SNI
        let server_name = if let Some(colon_pos) = addr.rfind(':') {
            Some(addr[..colon_pos].to_string())
        } else {
            Some(addr.to_string())
        };

        let mut client = Self::new(stream);
        client.server_name = server_name;
        Ok(client)
    }

    /// Get the current handshake state
    pub fn handshake_state(&self) -> &TlsHandshake {
        &self.handshake
    }

    /// Check if the handshake is complete and ready for application data
    pub fn is_ready(&self) -> bool {
        self.handshake.is_handshake_complete()
    }

    /// Helper method to decrypt a record using the given cipher
    fn decrypt_with_cipher(
        cipher: &mut AeadCipher,
        payload: &[u8],
        header_bytes: &[u8],
    ) -> Result<(ContentType, Vec<u8>), TlsError> {
        // decrypt_record returns (content, content_type)
        let (content, content_type_byte) = decrypt_record(cipher, payload, header_bytes)?;

        let real_content_type = ContentType::try_from(content_type_byte)
            .map_err(|_| TlsError::InvalidContentType(content_type_byte))?;

        Ok((real_content_type, content))
    }

    /// Read a TLS record from the stream
    ///
    /// Reads the record header, then the payload, and decrypts if necessary
    /// based on the current encryption state.
    fn read_record(&mut self) -> Result<(ContentType, Vec<u8>), TlsError> {
        // Read the 5-byte record header
        let mut header_bytes = [0u8; 5];
        self.stream
            .read_exact(&mut header_bytes)
            .map_err(|e| TlsError::InvalidState(format!("IO error: {}", e)))?;

        // Parse the header
        let header = parse_header::<ContentType, RecordHeader>(&header_bytes)?;

        // Read the payload
        let mut payload = vec![0u8; header.length as usize];
        self.stream
            .read_exact(&mut payload)
            .map_err(|e| TlsError::InvalidState(format!("IO error: {}", e)))?;

        // Decrypt if necessary based on encryption state
        let encryption_state = self.handshake.current_encryption_state();

        match encryption_state {
            EncryptionState::Plaintext => {
                // No decryption needed
                Ok((header.content_type, payload))
            }
            EncryptionState::HandshakeEncryption => {
                // Decrypt using handshake keys
                let cipher = self.server_handshake_keys.as_mut().ok_or_else(|| {
                    TlsError::InvalidState("No handshake keys available".to_string())
                })?;
                Self::decrypt_with_cipher(cipher, &payload, &header_bytes)
            }
            EncryptionState::ApplicationEncryption => {
                // Decrypt using application keys
                let cipher = self.server_application_keys.as_mut().ok_or_else(|| {
                    TlsError::InvalidState("No application keys available".to_string())
                })?;
                Self::decrypt_with_cipher(cipher, &payload, &header_bytes)
            }
        }
    }

    /// Helper method to encrypt and send a record using the given cipher
    fn encrypt_and_send_with_cipher(
        stream: &mut TcpStream,
        cipher: &mut AeadCipher,
        payload: &[u8],
        content_type: ContentType,
    ) -> Result<(), TlsError> {
        // Calculate the length of the ciphertext before encryption
        // ciphertext_len = inner_plaintext_len + TAG_SIZE
        // inner_plaintext_len = payload_len + 1 (content_type) + padding_len
        let padding_len = 0;
        let inner_plaintext_len = payload.len() + 1 + padding_len;
        let ciphertext_len = inner_plaintext_len + crate::aead::TAG_SIZE;

        // Construct the header with the ciphertext length
        let header = RecordHeader::new(ContentType::ApplicationData, 0x0303, ciphertext_len as u16);
        let header_bytes = header.to_bytes();

        // Encrypt using the full header (including length) as AAD
        let ciphertext = encrypt_record(
            cipher,
            payload,
            content_type as u8,
            &header_bytes,
            padding_len,
        )?;

        // Verify the ciphertext length matches our calculation
        debug_assert_eq!(ciphertext.len(), ciphertext_len);

        stream
            .write_all(&header_bytes)
            .map_err(|e| TlsError::InvalidState(format!("IO error: {}", e)))?;
        stream
            .write_all(&ciphertext)
            .map_err(|e| TlsError::InvalidState(format!("IO error: {}", e)))?;
        stream
            .flush()
            .map_err(|e| TlsError::InvalidState(format!("IO error: {}", e)))?;

        Ok(())
    }

    /// Write a TLS record to the stream
    ///
    /// Encrypts the payload if necessary based on the current encryption state.
    fn write_record(&mut self, content_type: ContentType, payload: &[u8]) -> Result<(), TlsError> {
        let encryption_state = self.handshake.current_encryption_state();

        match encryption_state {
            EncryptionState::Plaintext => {
                // Send plaintext record
                let header = RecordHeader::new(content_type, 0x0303, payload.len() as u16);
                let header_bytes = header.to_bytes();

                self.stream
                    .write_all(&header_bytes)
                    .map_err(|e| TlsError::InvalidState(format!("IO error: {}", e)))?;
                self.stream
                    .write_all(payload)
                    .map_err(|e| TlsError::InvalidState(format!("IO error: {}", e)))?;
                self.stream
                    .flush()
                    .map_err(|e| TlsError::InvalidState(format!("IO error: {}", e)))?;

                Ok(())
            }
            EncryptionState::HandshakeEncryption => {
                // Encrypt using handshake keys
                let cipher = self.client_handshake_keys.as_mut().ok_or_else(|| {
                    TlsError::InvalidState("No handshake keys available".to_string())
                })?;
                Self::encrypt_and_send_with_cipher(&mut self.stream, cipher, payload, content_type)
            }
            EncryptionState::ApplicationEncryption => {
                // Encrypt using application keys
                let cipher = self.client_application_keys.as_mut().ok_or_else(|| {
                    TlsError::InvalidState("No application keys available".to_string())
                })?;
                Self::encrypt_and_send_with_cipher(&mut self.stream, cipher, payload, content_type)
            }
        }
    }

    /// Send a handshake message
    fn send_handshake_message(&mut self, message: &[u8]) -> Result<(), TlsError> {
        self.write_record(ContentType::Handshake, message)
    }

    /// Receive a handshake message
    fn receive_handshake_message(&mut self) -> Result<Vec<u8>, TlsError> {
        let (content_type, payload) = self.read_record()?;

        if content_type != ContentType::Handshake {
            return Err(TlsError::UnexpectedMessage {
                expected: "Handshake".to_string(),
                received: format!("{:?}", content_type),
                state: self.handshake.current_state().as_str().to_string(),
            });
        }

        Ok(payload)
    }

    /// Send ClientHello and initiate the handshake
    ///
    /// Generates a random value, creates an X25519 keypair, constructs a ClientHello
    /// with mandatory extensions, and sends it to the server.
    pub fn send_client_hello(&mut self) -> Result<(), TlsError> {
        // Generate random bytes
        let random: [u8; 32] = rand::random();

        // Generate X25519 keypair
        let keypair = X25519KeyPair::generate();
        let public_key = keypair.public_key_bytes().to_vec();

        // Store keypair for later use
        self.client_keypair = Some(keypair);

        // Create ClientHello with custom or default cipher suites
        let mut client_hello = if let Some(ref cipher_suites) = self.custom_cipher_suites {
            // Use custom cipher suites
            let extensions = vec![
                Extension::SupportedVersions(vec![crate::extensions::TLS_VERSION_1_3]),
                Extension::KeyShare(vec![crate::extensions::KeyShareEntry {
                    group: crate::extensions::NAMED_GROUP_X25519,
                    key_exchange: public_key,
                }]),
            ];
            ClientHello::new(random, Vec::new(), cipher_suites.clone(), extensions)
        } else {
            // Use default cipher suites
            ClientHello::default_tls13(random, public_key)
        };

        // Add SNI extension if server name is available
        if let Some(ref server_name) = self.server_name {
            client_hello
                .extensions
                .insert(0, Extension::ServerName(server_name.clone()));
        }

        // Serialize ClientHello
        let client_hello_bytes = client_hello.to_bytes();

        // Send as plaintext
        self.send_handshake_message(&client_hello_bytes)?;

        // Update transcript
        self.transcript.update(&client_hello_bytes);

        // Update state machine
        self.handshake.on_client_hello_sent()?;

        Ok(())
    }

    /// Receive and process ServerHello
    ///
    /// Parses the ServerHello, validates it, computes the shared secret,
    /// derives handshake traffic keys, and switches to handshake encryption.
    pub fn receive_server_hello(&mut self) -> Result<(), TlsError> {
        // Receive ServerHello message
        let server_hello_bytes = self.receive_handshake_message()?;

        // Parse ServerHello
        let server_hello = ServerHello::from_bytes(&server_hello_bytes)?;

        // Check for downgrade protection
        if let Some(downgrade) = server_hello.check_downgrade_protection() {
            return Err(TlsError::InvalidState(format!(
                "Downgrade protection detected: {:?}",
                downgrade
            )));
        }

        // Update transcript with ServerHello
        self.transcript.update(&server_hello_bytes);

        // Extract server's key share
        let server_key_share = server_hello
            .extensions
            .iter()
            .find_map(|ext| {
                if let Extension::KeyShare(entries) = ext {
                    entries.first()
                } else {
                    None
                }
            })
            .ok_or_else(|| TlsError::MissingMandatoryExtension("KeyShare"))?;

        // Parse server's public key
        let server_public_key = parse_key_share_entry(server_key_share)?;

        // Compute shared secret (takes ownership of keypair)
        let client_keypair = self
            .client_keypair
            .take()
            .ok_or_else(|| TlsError::InvalidState("Client keypair not initialized".to_string()))?;

        let shared_secret = client_keypair.compute_shared_secret(&server_public_key)?;

        // Advance key schedule to handshake secret
        self.key_schedule
            .advance_to_handshake_secret(&shared_secret);

        // Get transcript hash up to ServerHello
        let transcript_hash = self.transcript.current_hash();

        // Derive handshake traffic secrets
        let client_handshake_secret = self
            .key_schedule
            .derive_client_handshake_traffic_secret(&transcript_hash);
        let server_handshake_secret = self
            .key_schedule
            .derive_server_handshake_traffic_secret(&transcript_hash);

        // Derive traffic keys from secrets
        let client_keys = derive_traffic_keys(&client_handshake_secret);
        let server_keys = derive_traffic_keys(&server_handshake_secret);

        // Create AEAD ciphers
        self.client_handshake_keys = Some(AeadCipher::new(client_keys));
        self.server_handshake_keys = Some(AeadCipher::new(server_keys));

        // Update state machine (switches to handshake encryption)
        self.handshake.on_server_hello_received()?;

        Ok(())
    }

    /// Receive and process EncryptedExtensions
    pub fn receive_encrypted_extensions(&mut self) -> Result<(), TlsError> {
        // Receive encrypted message
        let encrypted_extensions_bytes = self.receive_handshake_message()?;

        // Update transcript
        self.transcript.update(&encrypted_extensions_bytes);

        // Update state machine
        self.handshake.on_encrypted_extensions_received()?;

        Ok(())
    }

    /// Receive and process Certificate
    pub fn receive_certificate(&mut self) -> Result<Certificate, TlsError> {
        // Receive encrypted message
        let certificate_bytes = self.receive_handshake_message()?;

        // Parse Certificate
        let certificate = Certificate::from_bytes(&certificate_bytes)?;

        // Validate certificate
        certificate.validate()?;

        // Update transcript
        self.transcript.update(&certificate_bytes);

        // Update state machine
        self.handshake.on_certificate_received()?;

        Ok(certificate)
    }

    /// Receive and process CertificateVerify
    ///
    /// Verifies that the server possesses the private key corresponding to
    /// the certificate.
    pub fn receive_certificate_verify(
        &mut self,
        certificate: &Certificate,
    ) -> Result<(), TlsError> {
        // Receive encrypted message
        let cert_verify_bytes = self.receive_handshake_message()?;

        // Parse CertificateVerify
        let cert_verify = CertificateVerify::from_bytes(&cert_verify_bytes)?;

        // Get the end-entity certificate
        let end_entity = certificate.end_entity_certificate().ok_or_else(|| {
            TlsError::InvalidCertificateData("No certificates in chain".to_string())
        })?;

        // Verify the signature
        cert_verify.verify(&end_entity.cert_data, &self.transcript.current_hash())?;

        // Update transcript
        self.transcript.update(&cert_verify_bytes);

        // Update state machine
        self.handshake.on_certificate_verify_received()?;

        Ok(())
    }

    /// Receive and verify server Finished message
    pub fn receive_server_finished(&mut self) -> Result<(), TlsError> {
        // Get transcript hash before receiving Finished
        let transcript_hash = self.transcript.current_hash();

        // Receive encrypted message
        let finished_bytes = self.receive_handshake_message()?;

        // Parse Finished
        let finished = Finished::from_bytes(&finished_bytes)?;

        // Get server handshake traffic secret for verification
        let server_secret = self
            .key_schedule
            .derive_server_handshake_traffic_secret(&transcript_hash);

        // Verify server Finished
        finished.verify_server_finished(&server_secret, &transcript_hash)?;

        // Update transcript
        self.transcript.update(&finished_bytes);

        // Update state machine
        self.handshake.on_server_finished_received()?;

        Ok(())
    }

    /// Generate and send client Finished message
    ///
    /// Derives application traffic keys and switches to application encryption.
    pub fn send_client_finished(&mut self) -> Result<(), TlsError> {
        // Get transcript hash before sending Finished
        let transcript_hash = self.transcript.current_hash();

        // Get client handshake traffic secret
        let client_secret = self
            .key_schedule
            .derive_client_handshake_traffic_secret(&transcript_hash);

        // Generate client Finished
        let finished = Finished::generate_client_finished(&client_secret, &transcript_hash);

        // Serialize Finished
        let finished_bytes = finished.to_bytes();

        // Send encrypted message
        self.send_handshake_message(&finished_bytes)?;

        // Update transcript
        self.transcript.update(&finished_bytes);

        // Advance key schedule to master secret
        self.key_schedule.advance_to_master_secret();

        // Get updated transcript hash for application traffic secrets
        let app_transcript_hash = self.transcript.current_hash();

        // Derive application traffic secrets
        let client_app_secret = self
            .key_schedule
            .derive_client_application_traffic_secret(&app_transcript_hash);
        let server_app_secret = self
            .key_schedule
            .derive_server_application_traffic_secret(&app_transcript_hash);

        // Derive traffic keys
        let client_keys = derive_traffic_keys(&client_app_secret);
        let server_keys = derive_traffic_keys(&server_app_secret);

        // Create AEAD ciphers
        self.client_application_keys = Some(AeadCipher::new(client_keys));
        self.server_application_keys = Some(AeadCipher::new(server_keys));

        // Update state machine (switches to application encryption)
        self.handshake.on_client_finished_sent()?;

        Ok(())
    }

    /// Perform the complete TLS 1.3 handshake
    ///
    /// Executes all handshake steps in order:
    /// 1. Send ClientHello
    /// 2. Receive ServerHello
    /// 3. Receive EncryptedExtensions
    /// 4. Receive Certificate
    /// 5. Receive CertificateVerify
    /// 6. Receive server Finished
    /// 7. Send client Finished
    ///
    /// After successful completion, the connection is ready for application data.
    pub fn perform_handshake(&mut self) -> Result<(), TlsError> {
        // Step 1: Send ClientHello
        self.send_client_hello()?;

        // Step 2: Receive ServerHello
        self.receive_server_hello()?;

        // Step 3: Receive EncryptedExtensions
        self.receive_encrypted_extensions()?;

        // Step 4: Receive Certificate
        let certificate = self.receive_certificate()?;

        // Step 5: Receive CertificateVerify
        self.receive_certificate_verify(&certificate)?;

        // Step 6: Receive server Finished
        self.receive_server_finished()?;

        // Step 7: Send client Finished
        self.send_client_finished()?;

        Ok(())
    }

    /// Send application data
    ///
    /// Encrypts and sends application data. The handshake must be complete
    /// before calling this method.
    ///
    /// # Arguments
    /// * `data` - Application data to send
    ///
    /// # Returns
    /// * `Ok(())` on success
    /// * `Err(TlsError)` if handshake is not complete or transmission fails
    pub fn send_application_data(&mut self, data: &[u8]) -> Result<(), TlsError> {
        if !self.is_ready() {
            return Err(TlsError::InvalidState(
                "Handshake not complete, cannot send application data".to_string(),
            ));
        }

        self.write_record(ContentType::ApplicationData, data)?;

        // Update state machine
        self.handshake.on_application_data_sent()?;

        Ok(())
    }

    /// Send application data and return the encrypted TLS record
    ///
    /// Encrypts and sends application data, returning the complete encrypted TLS record
    /// (header + encrypted payload) that was sent. Useful for debugging and Wireshark analysis.
    ///
    /// # Arguments
    /// * `data` - Application data to send
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` containing the complete TLS record that was sent (5-byte header + ciphertext)
    /// * `Err(TlsError)` if handshake is not complete or transmission fails
    pub fn send_application_data_with_record(&mut self, data: &[u8]) -> Result<Vec<u8>, TlsError> {
        if !self.is_ready() {
            return Err(TlsError::InvalidState(
                "Handshake not complete, cannot send application data".to_string(),
            ));
        }

        // Get the cipher
        let cipher = self
            .client_application_keys
            .as_mut()
            .ok_or_else(|| TlsError::InvalidState("No application keys available".to_string()))?;

        // Calculate the ciphertext length
        let padding_len = 0;
        let inner_plaintext_len = data.len() + 1 + padding_len;
        let ciphertext_len = inner_plaintext_len + crate::aead::TAG_SIZE;

        // Construct the header
        let header = RecordHeader::new(ContentType::ApplicationData, 0x0303, ciphertext_len as u16);
        let header_bytes = header.to_bytes();

        // Encrypt
        let ciphertext = crate::aead::encrypt_record(
            cipher,
            data,
            ContentType::ApplicationData as u8,
            &header_bytes,
            padding_len,
        )?;

        // Combine header + ciphertext for the complete record
        let mut record = Vec::new();
        record.extend_from_slice(&header_bytes);
        record.extend_from_slice(&ciphertext);

        // Send the record
        self.stream
            .write_all(&record)
            .map_err(|e| TlsError::InvalidState(format!("IO error: {}", e)))?;
        self.stream
            .flush()
            .map_err(|e| TlsError::InvalidState(format!("IO error: {}", e)))?;

        // Update state machine
        self.handshake.on_application_data_sent()?;

        Ok(record)
    }

    /// Receive application data
    ///
    /// Receives and decrypts application data. The handshake must be complete
    /// before calling this method.
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` containing the decrypted application data
    /// * `Err(TlsError)` if handshake is not complete or reception fails
    pub fn receive_application_data(&mut self) -> Result<Vec<u8>, TlsError> {
        if !self.is_ready() {
            return Err(TlsError::InvalidState(
                "Handshake not complete, cannot receive application data".to_string(),
            ));
        }

        let (content_type, data) = self.read_record()?;

        if content_type != ContentType::ApplicationData {
            return Err(TlsError::UnexpectedMessage {
                expected: "ApplicationData".to_string(),
                received: format!("{:?}", content_type),
                state: self.handshake.current_state().as_str().to_string(),
            });
        }

        Ok(data)
    }
}
