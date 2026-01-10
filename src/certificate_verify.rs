//! CertificateVerify Message and Signature Verification (RFC 8446, Section 4.4.3)
//!
//! This module implements digital signature verification for the CertificateVerify handshake message.
//! It supports RSA-PSS and ECDSA signature algorithms as required by TLS 1.3.
//!
//! ## Supported Signature Algorithms
//!
//! - RSA-PSS-RSAE-SHA256 (0x0804) - Required for RSA certificates
//! - RSA-PSS-RSAE-SHA384 (0x0805) - Recommended for RSA certificates
//! - ECDSA-SECP256R1-SHA256 (0x0403) - Required for ECDSA certificates
//! - ECDSA-SECP384R1-SHA384 (0x0503) - Recommended for ECDSA certificates
//!
//! ## Usage
//!
//! ```rust,no_run
//! use tls_protocol::CertificateVerify;
//!
//! # fn example(received_bytes: &[u8], certificate: &tls_protocol::Certificate, transcript: &tls_protocol::TranscriptHash) -> Result<(), tls_protocol::TlsError> {
//! // Parse CertificateVerify message from network data
//! let cert_verify = CertificateVerify::from_bytes(&received_bytes)?;
//!
//! // Verify signature against certificate and transcript hash
//! cert_verify.verify(
//!     &certificate.end_entity_certificate().unwrap().cert_data,
//!     &transcript.current_hash()
//! )?;
//! # Ok(())
//! # }
//! ```

use crate::error::TlsError;
use crate::extensions::{
    SIG_ECDSA_SECP256R1_SHA256, SIG_ECDSA_SECP384R1_SHA384, SIG_RSA_PSS_RSAE_SHA256,
    SIG_RSA_PSS_RSAE_SHA384,
};

use p256::ecdsa::{
    signature::{Signer, Verifier},
    Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
};
use p384::ecdsa::{
    Signature as P384Signature, SigningKey as P384SigningKey, VerifyingKey as P384VerifyingKey,
};
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256, Sha384};
use x509_parser::der_parser::asn1_rs::Oid;
use x509_parser::der_parser::oid;
use x509_parser::oid_registry;
use x509_parser::prelude::*;

/// Context string for server CertificateVerify (RFC 8446, Section 4.4.3)
pub const SERVER_CERTIFICATE_VERIFY_CONTEXT: &str = "TLS 1.3, server CertificateVerify";

/// Context string for client CertificateVerify (RFC 8446, Section 4.4.3)
pub const CLIENT_CERTIFICATE_VERIFY_CONTEXT: &str = "TLS 1.3, client CertificateVerify";

/// OID for P-384 curve (secp384r1): 1.3.132.0.34
/// Note: This constant is not available in x509_parser::oid_registry as of version 0.16
const OID_EC_P384: Oid<'static> = oid!(1.3.132 .0 .34);

/// Number of space characters (0x20) prepended to signed content
const SIGNED_CONTENT_PADDING: usize = 64;

/// Public key types extracted from X.509 certificates
#[derive(Debug, Clone)]
pub enum PublicKey {
    /// RSA public key with modulus and exponent
    Rsa(RsaPublicKey),
    /// ECDSA public key on P-256 curve
    EcdsaP256(P256VerifyingKey),
    /// ECDSA public key on P-384 curve
    EcdsaP384(P384VerifyingKey),
}

/// Private key types for signing
#[derive(Debug, Clone)]
pub enum PrivateKey {
    /// RSA private key
    Rsa(RsaPrivateKey),
    /// ECDSA private key on P-256 curve
    EcdsaP256(P256SigningKey),
    /// ECDSA private key on P-384 curve
    EcdsaP384(P384SigningKey),
}

/// CertificateVerify handshake message (RFC 8446, Section 4.4.3)
///
/// This message is used to prove possession of the private key corresponding
/// to the certificate sent in the Certificate message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateVerify {
    /// Signature algorithm used (SignatureScheme)
    pub algorithm: u16,

    /// Digital signature bytes (0 to 2^16-1 bytes)
    pub signature: Vec<u8>,
}

impl CertificateVerify {
    /// Create a new CertificateVerify message
    pub fn new(algorithm: u16, signature: Vec<u8>) -> Self {
        Self {
            algorithm,
            signature,
        }
    }

    /// Sign the transcript hash with the given private key
    ///
    /// # Arguments
    /// * `private_key` - Key to sign with
    /// * `transcript_hash` - Current transcript hash
    /// * `context` - Context string (client or server)
    pub fn sign(
        private_key: &PrivateKey,
        transcript_hash: &[u8; 32],
        context: &str,
    ) -> Result<Self, TlsError> {
        let signed_content = build_signed_content(transcript_hash, context);
        let mut rng = rand::rngs::OsRng;

        match private_key {
            PrivateKey::Rsa(key) => {
                // Use RSA-PSS with SHA-256 (defaulting to 0x0804)
                // In a real implementation we should check key size and select appropriate algorithm
                let signing_key = rsa::pss::SigningKey::<Sha256>::new(key.clone());
                let signature = signing_key
                    .sign_with_rng(&mut rng, &signed_content)
                    .to_vec();
                Ok(Self::new(SIG_RSA_PSS_RSAE_SHA256, signature))
            }
            PrivateKey::EcdsaP256(key) => {
                let signature: P256Signature = key.sign(&signed_content);
                Ok(Self::new(
                    SIG_ECDSA_SECP256R1_SHA256,
                    signature.to_der().as_bytes().to_vec(),
                ))
            }
            PrivateKey::EcdsaP384(key) => {
                let signature: P384Signature = key.sign(&signed_content);
                Ok(Self::new(
                    SIG_ECDSA_SECP384R1_SHA384,
                    signature.to_der().as_bytes().to_vec(),
                ))
            }
        }
    }

    /// Parse a CertificateVerify message from bytes
    ///
    /// Expected format (RFC 8446, Section 4.4.3):
    /// - Handshake type (1 byte): 0x0f (CertificateVerify)
    /// - Length (3 bytes): Total length of CertificateVerify data
    /// - SignatureScheme (2 bytes): Algorithm identifier
    /// - Signature length (2 bytes)
    /// - Signature data (variable, 0 to 2^16-1 bytes)
    pub fn from_bytes(data: &[u8]) -> Result<Self, TlsError> {
        let mut offset = 0;

        // Check minimum length (1 + 3 + 2 + 2 = 8 bytes minimum)
        if data.len() < 8 {
            return Err(TlsError::IncompleteData);
        }

        // Parse handshake type (expect 0x0f for CertificateVerify)
        let handshake_type = data[offset];
        offset += 1;

        if handshake_type != 0x0f {
            return Err(TlsError::InvalidHandshakeType(handshake_type));
        }

        // Parse 3-byte length field
        let length = ((data[offset] as usize) << 16)
            | ((data[offset + 1] as usize) << 8)
            | (data[offset + 2] as usize);
        offset += 3;

        // Verify we have enough data
        if data.len() < offset + length {
            return Err(TlsError::IncompleteData);
        }

        // Parse SignatureScheme (2 bytes)
        if offset + 2 > data.len() {
            return Err(TlsError::IncompleteData);
        }
        let algorithm = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        // Parse signature length (2 bytes)
        if offset + 2 > data.len() {
            return Err(TlsError::IncompleteData);
        }
        let signature_length = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        // Parse signature data
        if offset + signature_length > data.len() {
            return Err(TlsError::IncompleteData);
        }
        let signature = data[offset..offset + signature_length].to_vec();

        Ok(Self {
            algorithm,
            signature,
        })
    }

    /// Serialize the CertificateVerify message to bytes
    ///
    /// Format:
    /// - Handshake type (1 byte): 0x0f (CertificateVerify)
    /// - Length (3 bytes): Total length of data
    /// - SignatureScheme (2 bytes)
    /// - Signature length (2 bytes)
    /// - Signature data (variable)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // SignatureScheme (2 bytes)
        data.extend_from_slice(&self.algorithm.to_be_bytes());

        // Signature length (2 bytes)
        let signature_length = self.signature.len();
        assert!(
            signature_length <= u16::MAX as usize,
            "Signature length must not exceed 65535 bytes"
        );
        data.extend_from_slice(&(signature_length as u16).to_be_bytes());

        // Signature data
        data.extend_from_slice(&self.signature);

        // Prepend handshake header
        let total_len = data.len();
        assert!(
            total_len < (1 << 24),
            "CertificateVerify message length must not exceed 2^24-1 bytes"
        );

        let mut result = Vec::new();
        result.push(0x0f); // CertificateVerify handshake type
        result.push((total_len >> 16) as u8);
        result.push((total_len >> 8) as u8);
        result.push(total_len as u8);
        result.extend_from_slice(&data);

        result
    }

    /// Verify the signature against the certificate and transcript hash
    ///
    /// This is the main verification function that:
    /// 1. Extracts the public key from the certificate
    /// 2. Constructs the signed content from the transcript hash
    /// 3. Dispatches to the appropriate verification algorithm
    /// 4. Validates that the key type matches the signature algorithm
    ///
    /// # Arguments
    ///
    /// * `cert_data` - DER-encoded X.509 certificate data
    /// * `transcript_hash` - SHA-256 hash of the handshake transcript
    ///
    /// # Returns
    ///
    /// * `Ok(())` if signature is valid
    /// * `Err(TlsError)` if signature is invalid or verification fails
    pub fn verify(&self, cert_data: &[u8], transcript_hash: &[u8; 32]) -> Result<(), TlsError> {
        // Preserve existing behavior: verify using the server CertificateVerify context.
        self.verify_with_context(
            cert_data,
            transcript_hash,
            SERVER_CERTIFICATE_VERIFY_CONTEXT,
        )
    }

    /// Verify a CertificateVerify message using the client context.
    ///
    /// This is used when validating a client's CertificateVerify message in mutual TLS
    /// handshakes, where the context string differs from the server case.
    pub fn verify_client(
        &self,
        cert_data: &[u8],
        transcript_hash: &[u8; 32],
    ) -> Result<(), TlsError> {
        self.verify_with_context(
            cert_data,
            transcript_hash,
            CLIENT_CERTIFICATE_VERIFY_CONTEXT,
        )
    }

    /// Internal helper to verify a CertificateVerify message with an explicit context.
    fn verify_with_context(
        &self,
        cert_data: &[u8],
        transcript_hash: &[u8; 32],
        context: &str,
    ) -> Result<(), TlsError> {
        // Extract public key from certificate
        let public_key = extract_public_key_from_der(cert_data)?;

        // Build signed content (RFC 8446, Section 4.4.3)
        let signed_content = build_signed_content(transcript_hash, context);

        // Verify signature based on algorithm
        match self.algorithm {
            SIG_RSA_PSS_RSAE_SHA256 => {
                let rsa_key = match public_key {
                    PublicKey::Rsa(key) => key,
                    _ => {
                        return Err(TlsError::SignatureAlgorithmMismatch(
                            "RSA-PSS signature requires RSA certificate".to_string(),
                        ))
                    }
                };
                verify_rsa_pss_rsae_sha256(&rsa_key, &signed_content, &self.signature)
            }
            SIG_RSA_PSS_RSAE_SHA384 => {
                let rsa_key = match public_key {
                    PublicKey::Rsa(key) => key,
                    _ => {
                        return Err(TlsError::SignatureAlgorithmMismatch(
                            "RSA-PSS signature requires RSA certificate".to_string(),
                        ))
                    }
                };
                verify_rsa_pss_rsae_sha384(&rsa_key, &signed_content, &self.signature)
            }
            SIG_ECDSA_SECP256R1_SHA256 => {
                let ec_key = match public_key {
                    PublicKey::EcdsaP256(key) => key,
                    _ => {
                        return Err(TlsError::SignatureAlgorithmMismatch(
                            "ECDSA-SECP256R1 signature requires P-256 certificate".to_string(),
                        ))
                    }
                };
                verify_ecdsa_secp256r1_sha256(&ec_key, &signed_content, &self.signature)
            }
            SIG_ECDSA_SECP384R1_SHA384 => {
                let ec_key = match public_key {
                    PublicKey::EcdsaP384(key) => key,
                    _ => {
                        return Err(TlsError::SignatureAlgorithmMismatch(
                            "ECDSA-SECP384R1 signature requires P-384 certificate".to_string(),
                        ))
                    }
                };
                verify_ecdsa_secp384r1_sha384(&ec_key, &signed_content, &self.signature)
            }
            _ => Err(TlsError::UnsupportedSignatureAlgorithm(self.algorithm)),
        }
    }
}

/// Build the signed content for CertificateVerify (RFC 8446, Section 4.4.3)
///
/// The signed content consists of:
/// - 64 space characters (0x20)
/// - Context string ("TLS 1.3, server CertificateVerify" or client variant)
/// - A single null byte (0x00)
/// - The transcript hash (32 bytes for SHA-256)
///
/// # Arguments
///
/// * `transcript_hash` - SHA-256 hash of the handshake transcript
/// * `context` - Context string (server or client)
///
/// # Returns
///
/// * Signed content ready for signature verification
pub fn build_signed_content(transcript_hash: &[u8; 32], context: &str) -> Vec<u8> {
    let mut content = Vec::new();

    // 64 space characters (0x20)
    content.extend_from_slice(&[0x20; SIGNED_CONTENT_PADDING]);

    // Context string
    content.extend_from_slice(context.as_bytes());

    // Single null byte (0x00)
    content.push(0x00);

    // Transcript hash
    content.extend_from_slice(transcript_hash);

    content
}

/// Extract public key from DER-encoded X.509 certificate
///
/// Parses the certificate and extracts the SubjectPublicKeyInfo,
/// returning the appropriate public key type (RSA, ECDSA P-256, or ECDSA P-384).
///
/// # Arguments
///
/// * `cert_data` - DER-encoded X.509 certificate
///
/// # Returns
///
/// * `Ok(PublicKey)` with the extracted public key
/// * `Err(TlsError)` if certificate parsing fails or key type is unsupported
pub fn extract_public_key_from_der(cert_data: &[u8]) -> Result<PublicKey, TlsError> {
    // Parse X.509 certificate
    let (_, cert) = X509Certificate::from_der(cert_data).map_err(|e| {
        TlsError::CertificateParsingError(format!("Failed to parse certificate: {}", e))
    })?;

    // Get SubjectPublicKeyInfo
    let spki = cert.public_key();
    let algorithm_oid = &spki.algorithm.algorithm;

    // Parse based on algorithm OID
    if algorithm_oid == &oid_registry::OID_PKCS1_RSAENCRYPTION {
        // RSA public key
        parse_rsa_public_key(&spki.subject_public_key.data)
    } else if algorithm_oid == &oid_registry::OID_KEY_TYPE_EC_PUBLIC_KEY {
        // ECDSA public key - check curve
        parse_ecdsa_public_key(spki)
    } else {
        Err(TlsError::CertificateParsingError(format!(
            "Unsupported public key algorithm: {:?}",
            algorithm_oid
        )))
    }
}

/// Parse RSA public key from raw bytes
fn parse_rsa_public_key(key_data: &[u8]) -> Result<PublicKey, TlsError> {
    use rsa::pkcs8::DecodePublicKey;

    // Try parsing as PKCS#1 RSAPublicKey
    match RsaPublicKey::from_public_key_der(key_data) {
        Ok(key) => Ok(PublicKey::Rsa(key)),
        Err(_) => {
            // Try parsing raw RSA key (this is what's typically in SPKI)
            use rsa::pkcs1::DecodeRsaPublicKey;
            RsaPublicKey::from_pkcs1_der(key_data)
                .map(PublicKey::Rsa)
                .map_err(|e| {
                    TlsError::CertificateParsingError(format!(
                        "Failed to parse RSA public key: {}",
                        e
                    ))
                })
        }
    }
}

/// Parse ECDSA public key and determine curve
fn parse_ecdsa_public_key(spki: &SubjectPublicKeyInfo) -> Result<PublicKey, TlsError> {
    // Get the curve OID from algorithm parameters
    let curve_oid = match &spki.algorithm.parameters {
        Some(params) => match params.as_oid() {
            Ok(oid) => oid,
            Err(e) => {
                return Err(TlsError::CertificateParsingError(format!(
                    "Failed to parse curve OID: {}",
                    e
                )))
            }
        },
        None => {
            return Err(TlsError::CertificateParsingError(
                "Missing curve parameters for ECDSA key".to_string(),
            ))
        }
    };

    let key_data = &spki.subject_public_key.data;

    // Check curve and parse accordingly
    if curve_oid == oid_registry::OID_EC_P256 {
        // P-256 curve
        P256VerifyingKey::from_sec1_bytes(key_data)
            .map(PublicKey::EcdsaP256)
            .map_err(|e| {
                TlsError::CertificateParsingError(format!(
                    "Failed to parse P-256 public key: {}",
                    e
                ))
            })
    } else if curve_oid == OID_EC_P384 {
        // P-384 curve (secp384r1)
        P384VerifyingKey::from_sec1_bytes(key_data)
            .map(PublicKey::EcdsaP384)
            .map_err(|e| {
                TlsError::CertificateParsingError(format!(
                    "Failed to parse P-384 public key: {}",
                    e
                ))
            })
    } else {
        Err(TlsError::CertificateParsingError(format!(
            "Unsupported elliptic curve: {:?}",
            curve_oid
        )))
    }
}

/// Verify RSA-PSS-RSAE-SHA256 signature
///
/// Uses SHA-256 as hash function with MGF1-SHA256 and 32-byte salt.
fn verify_rsa_pss_rsae_sha256(
    public_key: &RsaPublicKey,
    message: &[u8],
    signature: &[u8],
) -> Result<(), TlsError> {
    use rsa::pss::VerifyingKey;
    use rsa::signature::Verifier;
    use sha2::Sha256;

    // Create PSS verifying key with SHA-256
    let verifying_key = VerifyingKey::<Sha256>::new(public_key.clone());

    // Parse signature
    let sig = rsa::pss::Signature::try_from(signature)
        .map_err(|e| TlsError::InvalidSignature(format!("Invalid RSA signature format: {}", e)))?;

    // Verify signature
    verifying_key.verify(message, &sig).map_err(|e| {
        TlsError::InvalidSignature(format!("RSA-PSS-SHA256 verification failed: {}", e))
    })
}

/// Verify RSA-PSS-RSAE-SHA384 signature
///
/// Uses SHA-384 as hash function with MGF1-SHA384 and 48-byte salt.
fn verify_rsa_pss_rsae_sha384(
    public_key: &RsaPublicKey,
    message: &[u8],
    signature: &[u8],
) -> Result<(), TlsError> {
    use rsa::pss::VerifyingKey;
    use rsa::signature::Verifier;
    use sha2::Sha384;

    // Create PSS verifying key with SHA-384
    let verifying_key = VerifyingKey::<Sha384>::new(public_key.clone());

    // Parse signature
    let sig = rsa::pss::Signature::try_from(signature)
        .map_err(|e| TlsError::InvalidSignature(format!("Invalid RSA signature format: {}", e)))?;

    // Verify signature
    verifying_key.verify(message, &sig).map_err(|e| {
        TlsError::InvalidSignature(format!("RSA-PSS-SHA384 verification failed: {}", e))
    })
}

/// Verify ECDSA-SECP256R1-SHA256 signature
///
/// Signature is ASN.1 DER-encoded (r, s) pair on the P-256 curve.
fn verify_ecdsa_secp256r1_sha256(
    public_key: &P256VerifyingKey,
    message: &[u8],
    signature: &[u8],
) -> Result<(), TlsError> {
    // Hash the message with SHA-256
    let mut hasher = Sha256::new();
    hasher.update(message);
    let digest = hasher.finalize();

    // Parse DER signature
    let sig = P256Signature::from_der(signature).map_err(|e| {
        TlsError::InvalidSignature(format!("Invalid ECDSA signature format: {}", e))
    })?;

    // Verify signature
    public_key.verify(&digest, &sig).map_err(|e| {
        TlsError::InvalidSignature(format!("ECDSA-SECP256R1-SHA256 verification failed: {}", e))
    })
}

/// Verify ECDSA-SECP384R1-SHA384 signature
///
/// Signature is ASN.1 DER-encoded (r, s) pair on the P-384 curve.
fn verify_ecdsa_secp384r1_sha384(
    public_key: &P384VerifyingKey,
    message: &[u8],
    signature: &[u8],
) -> Result<(), TlsError> {
    // Hash the message with SHA-384
    let mut hasher = Sha384::new();
    hasher.update(message);
    let digest = hasher.finalize();

    // Parse DER signature
    let sig = P384Signature::from_der(signature).map_err(|e| {
        TlsError::InvalidSignature(format!("Invalid ECDSA signature format: {}", e))
    })?;

    // Verify signature
    public_key.verify(&digest, &sig).map_err(|e| {
        TlsError::InvalidSignature(format!("ECDSA-SECP384R1-SHA384 verification failed: {}", e))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_signed_content() {
        let transcript_hash = [0xaa; 32];
        let content = build_signed_content(&transcript_hash, SERVER_CERTIFICATE_VERIFY_CONTEXT);

        // Check structure
        assert_eq!(
            content.len(),
            64 + SERVER_CERTIFICATE_VERIFY_CONTEXT.len() + 1 + 32
        );

        // Check padding (64 spaces)
        assert_eq!(&content[0..64], &[0x20; 64]);

        // Check context string
        let context_start = 64;
        let context_end = context_start + SERVER_CERTIFICATE_VERIFY_CONTEXT.len();
        assert_eq!(
            &content[context_start..context_end],
            SERVER_CERTIFICATE_VERIFY_CONTEXT.as_bytes()
        );

        // Check null byte
        assert_eq!(content[context_end], 0x00);

        // Check transcript hash
        assert_eq!(&content[context_end + 1..], &transcript_hash[..]);
    }

    #[test]
    fn test_certificate_verify_serialization() {
        let cert_verify = CertificateVerify::new(SIG_RSA_PSS_RSAE_SHA256, vec![0xaa; 256]);

        let bytes = cert_verify.to_bytes();

        // Check handshake type
        assert_eq!(bytes[0], 0x0f);

        // Check length field (3 bytes)
        let length = ((bytes[1] as usize) << 16) | ((bytes[2] as usize) << 8) | (bytes[3] as usize);
        assert_eq!(length, bytes.len() - 4);

        // Check algorithm
        let algorithm = u16::from_be_bytes([bytes[4], bytes[5]]);
        assert_eq!(algorithm, SIG_RSA_PSS_RSAE_SHA256);

        // Check signature length
        let sig_len = u16::from_be_bytes([bytes[6], bytes[7]]) as usize;
        assert_eq!(sig_len, 256);

        // Check signature data
        assert_eq!(&bytes[8..8 + 256], &[0xaa; 256]);
    }

    #[test]
    fn test_certificate_verify_parsing() {
        let mut data = vec![0x0f]; // Handshake type
        data.extend_from_slice(&[0x00, 0x01, 0x04]); // Length: 260 bytes
        data.extend_from_slice(&SIG_ECDSA_SECP256R1_SHA256.to_be_bytes()); // Algorithm
        data.extend_from_slice(&(256u16).to_be_bytes()); // Signature length
        data.extend_from_slice(&vec![0xbb; 256]); // Signature

        let cert_verify = CertificateVerify::from_bytes(&data).unwrap();
        assert_eq!(cert_verify.algorithm, SIG_ECDSA_SECP256R1_SHA256);
        assert_eq!(cert_verify.signature.len(), 256);
        assert_eq!(cert_verify.signature, vec![0xbb; 256]);
    }

    #[test]
    fn test_certificate_verify_roundtrip() {
        let original = CertificateVerify::new(SIG_ECDSA_SECP384R1_SHA384, vec![0xcc; 128]);

        let bytes = original.to_bytes();
        let parsed = CertificateVerify::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.algorithm, original.algorithm);
        assert_eq!(parsed.signature, original.signature);
    }

    #[test]
    fn test_certificate_verify_invalid_handshake_type() {
        let mut data = vec![0x0b]; // Wrong type (Certificate instead of CertificateVerify)
        data.extend_from_slice(&[0x00, 0x00, 0x04]); // Length
        data.extend_from_slice(&[0x08, 0x04]); // Algorithm
        data.extend_from_slice(&[0x00, 0x00]); // Signature length

        let result = CertificateVerify::from_bytes(&data);
        assert!(matches!(result, Err(TlsError::InvalidHandshakeType(0x0b))));
    }

    #[test]
    fn test_certificate_verify_incomplete_data() {
        let data = vec![0x0f, 0x00, 0x00]; // Incomplete header
        let result = CertificateVerify::from_bytes(&data);
        assert!(matches!(result, Err(TlsError::IncompleteData)));
    }
}
