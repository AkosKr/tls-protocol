//! TLS 1.3 Server Implementation
//!
//! This module provides a high-level TLS 1.3 server that orchestrates all the
//! protocol components into a working server implementation.

use std::io::{Read, Write};
use std::net::TcpStream;

use crate::aead::{decrypt_record, encrypt_record, AeadCipher};
use crate::certificate::Certificate;
use crate::certificate_verify::{CertificateVerify, PrivateKey, SERVER_CERTIFICATE_VERIFY_CONTEXT};
use crate::client_hello::ClientHello;
use crate::error::TlsError;
use crate::extensions::{Extension, KeyShareEntry};
use crate::finished::Finished;
use crate::handshake_state::{EncryptionState, TlsHandshake};
use crate::key_schedule::{derive_traffic_keys, KeySchedule};
use crate::parser::parse_header;
use crate::server_hello::ServerHello;
use crate::transcript_hash::TranscriptHash;
use crate::x25519_key_exchange::{parse_key_share_entry, X25519KeyPair};
use crate::{ContentType, RecordHeader};

/// TLS 1.3 Server
///
/// Manages a complete TLS 1.3 server connection.
pub struct TlsServer {
    /// Underlying TCP stream
    stream: TcpStream,

    /// Handshake state machine
    handshake: TlsHandshake,

    /// Key schedule for deriving traffic secrets
    key_schedule: KeySchedule,

    /// Transcript hash for handshake messages
    transcript: TranscriptHash,

    /// Server's X25519 public key (ephemeral)
    server_public_key: Option<Vec<u8>>,

    /// Received ClientHello message
    client_hello: Option<ClientHello>,

    /// Server's Identity Certificate
    certificate: Certificate,

    /// Server's Private Key for signing
    private_key: PrivateKey,

    /// Client handshake traffic keys (used after ServerHello)
    client_handshake_keys: Option<AeadCipher>,

    /// Server handshake traffic keys (used after ServerHello)
    server_handshake_keys: Option<AeadCipher>,

    /// Client application traffic keys (used after Finished)
    client_application_keys: Option<AeadCipher>,

    /// Server application traffic keys (used after Finished)
    server_application_keys: Option<AeadCipher>,
}

impl TlsServer {
    /// Create a new TLS server
    pub fn new(stream: TcpStream, certificate: Certificate, private_key: PrivateKey) -> Self {
        Self {
            stream,
            handshake: TlsHandshake::new(),
            key_schedule: KeySchedule::new(),
            transcript: TranscriptHash::new(),
            server_public_key: None,
            client_hello: None,
            certificate,
            private_key,
            client_handshake_keys: None,
            server_handshake_keys: None,
            client_application_keys: None,
            server_application_keys: None,
        }
    }

    /// Check if the handshake is complete
    pub fn is_ready(&self) -> bool {
        self.handshake.is_handshake_complete()
    }

    /// Helper method to decrypt a record using the given cipher
    fn decrypt_with_cipher(
        cipher: &mut AeadCipher,
        payload: &[u8],
        header_bytes: &[u8],
    ) -> Result<(ContentType, Vec<u8>), TlsError> {
        let (content, content_type_byte) = decrypt_record(cipher, payload, header_bytes)?;

        let real_content_type = ContentType::try_from(content_type_byte)
            .map_err(|_| TlsError::InvalidContentType(content_type_byte))?;

        Ok((real_content_type, content))
    }

    /// Read a TLS record from the stream
    fn read_record(&mut self) -> Result<(ContentType, Vec<u8>), TlsError> {
        let mut header_bytes = [0u8; 5];
        self.stream
            .read_exact(&mut header_bytes)
            .map_err(|e| TlsError::InvalidState(format!("IO error: {}", e)))?;

        let header = parse_header::<ContentType, RecordHeader>(&header_bytes)?;

        let mut payload = vec![0u8; header.length as usize];
        self.stream
            .read_exact(&mut payload)
            .map_err(|e| TlsError::InvalidState(format!("IO error: {}", e)))?;

        let encryption_state = self.handshake.current_encryption_state();

        match encryption_state {
            EncryptionState::Plaintext => Ok((header.content_type, payload)),
            EncryptionState::HandshakeEncryption => {
                let cipher = self.client_handshake_keys.as_mut().ok_or_else(|| {
                    TlsError::InvalidState("No handshake keys available".to_string())
                })?;
                Self::decrypt_with_cipher(cipher, &payload, &header_bytes)
            }
            EncryptionState::ApplicationEncryption => {
                let cipher = self.client_application_keys.as_mut().ok_or_else(|| {
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
    fn write_record(&mut self, content_type: ContentType, payload: &[u8]) -> Result<(), TlsError> {
        let encryption_state = self.handshake.current_encryption_state();

        match encryption_state {
            EncryptionState::Plaintext => {
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
                let cipher = self.server_handshake_keys.as_mut().ok_or_else(|| {
                    TlsError::InvalidState("No handshake keys available".to_string())
                })?;
                Self::encrypt_and_send_with_cipher(&mut self.stream, cipher, payload, content_type)
            }
            EncryptionState::ApplicationEncryption => {
                let cipher = self.server_application_keys.as_mut().ok_or_else(|| {
                    TlsError::InvalidState("No application keys available".to_string())
                })?;
                Self::encrypt_and_send_with_cipher(&mut self.stream, cipher, payload, content_type)
            }
        }
    }

    fn send_handshake_message(&mut self, message: &[u8]) -> Result<(), TlsError> {
        self.write_record(ContentType::Handshake, message)
    }

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

    /// Step 1: Receive ClientHello
    pub fn receive_client_hello(&mut self) -> Result<(), TlsError> {
        let client_hello_bytes = self.receive_handshake_message()?;
        let client_hello = ClientHello::from_bytes(&client_hello_bytes)?;

        // Find KeyShare extension and extract public key
        let client_key_share = client_hello
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

        let client_public_key = parse_key_share_entry(client_key_share)?;

        // Generate Server's X25519 keypair
        let server_keypair = X25519KeyPair::generate();
        let server_public_key_bytes = server_keypair.public_key_bytes().to_vec();

        // Compute Shared Secret immediately
        let shared_secret = server_keypair.compute_shared_secret(&client_public_key)?;

        // Store Public Key for ServerHello
        self.server_public_key = Some(server_public_key_bytes);

        // Store ClientHello for later use (e.g., echoing legacy_session_id)
        self.client_hello = Some(client_hello);

        self.transcript.update(&client_hello_bytes);
        self.key_schedule
            .advance_to_handshake_secret(&shared_secret);

        self.handshake.on_client_hello_received()?;

        // We prepare the KeyShare extension for ServerHello here or inside send_server_hello.
        // Let's store the ephemeral public key to be used in send_server_hello
        // Creating a temporary field or passing it?
        // Since `perform_handshake` is sequential, we can just assume `send_server_hello` generates a new one?
        // NO. We already computed the shared secret using the generated private key.
        // We MUST send the corresponding public key.
        // So we need to store `server_public_key_bytes` temporarily or re-generate?
        // We can't re-generate because we already advanced the key schedule with the shared secret derived from THAT private key.

        // Let's store the key share extension data in the struct? No, that's messy.
        // Better: receive_client_hello should probably return the `server_public_key_bytes` to be passed to `send_server_hello`?
        // Or store it in `self.server_keypair`? `X25519KeyPair` has `public_key`.
        // We can retrieve it from `self.server_keypair`.

        Ok(())
    }

    /// Step 2: Send ServerHello
    pub fn send_server_hello(&mut self) -> Result<(), TlsError> {
        let random: [u8; 32] = rand::random();
        let legacy_session_id_echo = self
            .client_hello
            .as_ref()
            .map(|ch| ch.legacy_session_id.clone())
            .unwrap_or_default();

        let cipher_suite = 0x1301; // TLS_AES_128_GCM_SHA256 (default)

        // Retrieve server public key
        let public_key = self
            .server_public_key
            .as_ref()
            .ok_or(TlsError::InvalidState("Keypair not generated".into()))?;

        let key_share_ext = Extension::KeyShare(vec![KeyShareEntry {
            group: 0x001D, // X25519
            key_exchange: public_key.clone(),
        }]);

        let extensions = vec![
            Extension::SupportedVersions(vec![0x0304]), // TLS 1.3
            key_share_ext,
        ];

        let server_hello =
            ServerHello::new(random, legacy_session_id_echo, cipher_suite, extensions);
        let server_hello_bytes = server_hello.to_bytes(); // NOTE: ServerHello to_bytes not implemented in context?
                                                          // Checking `server_hello.rs`: It has `from_bytes` but NOT `to_bytes` visible in the snippet I read?
                                                          // Wait, `ClientHello` has `to_bytes`. `ServerHello` probably should.
                                                          // I need to check `server_hello.rs` fully.

        self.send_handshake_message(&server_hello_bytes)?;
        self.transcript.update(&server_hello_bytes);

        // Derive keys
        let transcript_hash = self.transcript.current_hash();
        let client_handshake_secret = self
            .key_schedule
            .derive_client_handshake_traffic_secret(&transcript_hash);
        let server_handshake_secret = self
            .key_schedule
            .derive_server_handshake_traffic_secret(&transcript_hash);

        let client_keys = derive_traffic_keys(&client_handshake_secret);
        let server_keys = derive_traffic_keys(&server_handshake_secret);

        self.client_handshake_keys = Some(AeadCipher::new(client_keys));
        self.server_handshake_keys = Some(AeadCipher::new(server_keys));

        self.handshake.on_server_hello_sent()?;

        Ok(())
    }

    /// Step 3: Send EncryptedExtensions
    pub fn send_encrypted_extensions(&mut self) -> Result<(), TlsError> {
        // We need to serialize EncryptedExtensions.
        // It's a handshake message type 8.
        // Format: Type(1) + Len(3) + ExtLen(2) + Exts.
        // Since exts are empty: 08 00 00 02 00 00
        let message = vec![0x08, 0x00, 0x00, 0x02, 0x00, 0x00];

        self.send_handshake_message(&message)?;
        self.transcript.update(&message);
        self.handshake.on_encrypted_extensions_sent()?;
        Ok(())
    }

    /// Step 4: Send Certificate
    pub fn send_certificate(&mut self) -> Result<(), TlsError> {
        let cert_bytes = self.certificate.to_bytes();
        self.send_handshake_message(&cert_bytes)?;
        self.transcript.update(&cert_bytes);
        self.handshake.on_certificate_sent()?;
        Ok(())
    }

    /// Step 5: Send CertificateVerify
    pub fn send_certificate_verify(&mut self) -> Result<(), TlsError> {
        let transcript_hash = self.transcript.current_hash();
        let cert_verify = CertificateVerify::sign(
            &self.private_key,
            &transcript_hash,
            SERVER_CERTIFICATE_VERIFY_CONTEXT,
        )?;

        let verify_bytes = cert_verify.to_bytes();
        self.send_handshake_message(&verify_bytes)?;
        self.transcript.update(&verify_bytes);
        self.handshake.on_certificate_verify_sent()?;
        Ok(())
    }

    /// Step 6: Send Server Finished
    pub fn send_server_finished(&mut self) -> Result<(), TlsError> {
        let transcript_hash = self.transcript.current_hash();
        let server_secret = self
            .key_schedule
            .derive_server_handshake_traffic_secret(&transcript_hash);

        let finished = Finished::generate_server_finished(&server_secret, &transcript_hash);
        let finished_bytes = finished.to_bytes();

        self.send_handshake_message(&finished_bytes)?;
        self.transcript.update(&finished_bytes);
        self.handshake.on_server_finished_sent()?;
        Ok(())
    }

    /// Step 7: Receive Client Finished
    pub fn receive_client_finished(&mut self) -> Result<(), TlsError> {
        let transcript_hash = self.transcript.current_hash();
        let finished_bytes = self.receive_handshake_message()?;
        let finished = Finished::from_bytes(&finished_bytes)?;

        let client_secret = self
            .key_schedule
            .derive_client_handshake_traffic_secret(&transcript_hash);
        finished.verify_client_finished(&client_secret, &transcript_hash)?;

        self.transcript.update(&finished_bytes);

        // Advance to application keys
        self.key_schedule.advance_to_master_secret();
        let app_transcript_hash = self.transcript.current_hash();

        let client_app_secret = self
            .key_schedule
            .derive_client_application_traffic_secret(&app_transcript_hash);
        let server_app_secret = self
            .key_schedule
            .derive_server_application_traffic_secret(&app_transcript_hash);

        let client_keys = derive_traffic_keys(&client_app_secret);
        let server_keys = derive_traffic_keys(&server_app_secret);

        self.client_application_keys = Some(AeadCipher::new(client_keys));
        self.server_application_keys = Some(AeadCipher::new(server_keys));

        self.handshake.on_client_finished_received()?;
        Ok(())
    }

    /// Perform handshake
    pub fn perform_handshake(&mut self) -> Result<(), TlsError> {
        self.receive_client_hello()?;
        self.send_server_hello()?;
        self.send_encrypted_extensions()?;
        self.send_certificate()?;
        self.send_certificate_verify()?;
        self.send_server_finished()?;
        self.receive_client_finished()?;
        Ok(())
    }

    pub fn send_application_data(&mut self, data: &[u8]) -> Result<(), TlsError> {
        if !self.is_ready() {
            return Err(TlsError::InvalidState("Handshake not complete".into()));
        }
        self.write_record(ContentType::ApplicationData, data)?;
        self.handshake.on_application_data_sent()?;
        Ok(())
    }

    pub fn receive_application_data(&mut self) -> Result<Vec<u8>, TlsError> {
        if !self.is_ready() {
            return Err(TlsError::InvalidState("Handshake not complete".into()));
        }
        let (content_type, data) = self.read_record()?;
        if content_type != ContentType::ApplicationData {
            return Err(TlsError::UnexpectedMessage {
                expected: "ApplicationData".into(),
                received: format!("{:?}", content_type),
                state: self.handshake.current_state().as_str().into(),
            });
        }
        Ok(data)
    }
}
