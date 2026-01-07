use crate::error::TlsError;
use crate::extensions::Extension;

/// Maximum number of certificates allowed in a certificate chain
/// This prevents excessive memory allocation and DoS attacks
pub const MAX_CERTIFICATE_CHAIN_LENGTH: usize = 10;

/// A single certificate entry in the certificate chain (RFC 8446, Section 4.4.2)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateEntry {
    /// DER-encoded X.509 certificate data (1 to 2^24-1 bytes)
    pub cert_data: Vec<u8>,

    /// Per-certificate extensions (0 to 2^16-1 bytes)
    pub extensions: Vec<Extension>,
}

impl CertificateEntry {
    /// Create a new certificate entry
    pub fn new(cert_data: Vec<u8>, extensions: Vec<Extension>) -> Self {
        Self {
            cert_data,
            extensions,
        }
    }

    /// Validate the certificate entry
    pub fn validate(&self) -> Result<(), TlsError> {
        // Check that certificate data is not empty
        if self.cert_data.is_empty() {
            return Err(TlsError::InvalidCertificateData(
                "Certificate data cannot be empty".to_string(),
            ));
        }

        // Check that certificate data doesn't exceed 2^24-1 bytes
        if self.cert_data.len() >= (1 << 24) {
            return Err(TlsError::InvalidCertificateData(format!(
                "Certificate data too large: {} bytes",
                self.cert_data.len()
            )));
        }

        Ok(())
    }
}

/// Certificate handshake message (RFC 8446, Section 4.4.2)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    /// Certificate request context (0 to 255 bytes)
    /// Should be empty for server authentication (non-empty for client auth in response to CertificateRequest)
    pub certificate_request_context: Vec<u8>,

    /// Certificate chain (list of certificate entries)
    pub certificate_list: Vec<CertificateEntry>,
}

impl Certificate {
    /// Create a new Certificate message
    pub fn new(
        certificate_request_context: Vec<u8>,
        certificate_list: Vec<CertificateEntry>,
    ) -> Self {
        Self {
            certificate_request_context,
            certificate_list,
        }
    }

    /// Parse a Certificate message from bytes
    ///
    /// Expected format (RFC 8446, Section 4.4.2):
    /// - Handshake type (1 byte): 0x0b (Certificate)
    /// - Length (3 bytes): Total length of Certificate data
    /// - Certificate request context length (1 byte)
    /// - Certificate request context (variable, 0 to 255 bytes)
    /// - Certificate list length (3 bytes)
    /// - Certificate entries (variable):
    ///   - Certificate data length (3 bytes)
    ///   - Certificate data (variable, 1 to 2^24-1 bytes, DER-encoded X.509)
    ///   - Extensions length (2 bytes)
    ///   - Extensions (variable, 0 to 2^16-1 bytes)
    pub fn from_bytes(data: &[u8]) -> Result<Self, TlsError> {
        let mut offset = 0;

        // Check minimum length (1 + 3 + 1 + 3 = 8 bytes minimum)
        if data.len() < 8 {
            return Err(TlsError::IncompleteData);
        }

        // Parse handshake type (expect 0x0b for Certificate)
        let handshake_type = data[offset];
        offset += 1;

        if handshake_type != 0x0b {
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

        // Parse certificate_request_context length (1 byte)
        if offset >= data.len() {
            return Err(TlsError::IncompleteData);
        }

        let context_len = data[offset] as usize;
        offset += 1;

        // Parse certificate_request_context
        if offset + context_len > data.len() {
            return Err(TlsError::IncompleteData);
        }

        let certificate_request_context = data[offset..offset + context_len].to_vec();
        offset += context_len;

        // Parse certificate_list length (3 bytes)
        if offset + 3 > data.len() {
            return Err(TlsError::IncompleteData);
        }

        let cert_list_len = ((data[offset] as usize) << 16)
            | ((data[offset + 1] as usize) << 8)
            | (data[offset + 2] as usize);
        offset += 3;

        // Parse certificate entries
        let _cert_list_start = offset;
        let cert_list_end = offset + cert_list_len;

        if cert_list_end > data.len() {
            return Err(TlsError::IncompleteData);
        }

        let mut certificate_list = Vec::new();

        while offset < cert_list_end {
            // Parse certificate data length (3 bytes)
            if offset + 3 > cert_list_end {
                return Err(TlsError::InvalidCertificateData(
                    "Incomplete certificate data length field".to_string(),
                ));
            }

            let cert_data_len = ((data[offset] as usize) << 16)
                | ((data[offset + 1] as usize) << 8)
                | (data[offset + 2] as usize);
            offset += 3;

            // Validate certificate data length
            if cert_data_len == 0 {
                return Err(TlsError::InvalidCertificateData(
                    "Certificate data length cannot be zero".to_string(),
                ));
            }

            // Parse certificate data
            if offset + cert_data_len > cert_list_end {
                return Err(TlsError::InvalidCertificateData(
                    "Incomplete certificate data".to_string(),
                ));
            }

            let cert_data = data[offset..offset + cert_data_len].to_vec();
            offset += cert_data_len;

            // Parse extensions length (2 bytes)
            if offset + 2 > cert_list_end {
                return Err(TlsError::InvalidCertificateData(
                    "Incomplete extensions length field".to_string(),
                ));
            }

            let extensions_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;

            // Parse extensions
            if offset + extensions_len > cert_list_end {
                return Err(TlsError::InvalidCertificateData(
                    "Incomplete extensions data".to_string(),
                ));
            }

            let mut extensions = Vec::new();
            let mut ext_offset = offset;
            let ext_end = offset + extensions_len;

            while ext_offset < ext_end {
                let (ext, consumed) = Extension::from_bytes(&data[ext_offset..])?;
                extensions.push(ext);
                ext_offset += consumed;
            }

            if ext_offset != ext_end {
                return Err(TlsError::InvalidExtensionData(
                    "Extensions length mismatch".to_string(),
                ));
            }

            offset += extensions_len;

            // Create and validate certificate entry
            let entry = CertificateEntry::new(cert_data, extensions);
            entry.validate()?;

            certificate_list.push(entry);

            // Check chain length limit
            if certificate_list.len() > MAX_CERTIFICATE_CHAIN_LENGTH {
                return Err(TlsError::CertificateChainTooLong(certificate_list.len()));
            }
        }

        if offset != cert_list_end {
            return Err(TlsError::InvalidCertificateData(
                "Certificate list length mismatch".to_string(),
            ));
        }

        let certificate = Self {
            certificate_request_context,
            certificate_list,
        };

        // Validate the parsed Certificate
        certificate.validate()?;

        Ok(certificate)
    }

    /// Serialize the Certificate message to bytes
    ///
    /// Format:
    /// - Handshake type (1 byte): 0x0b (Certificate)
    /// - Length (3 bytes): Total length of Certificate data
    /// - Certificate request context length (1 byte)
    /// - Certificate request context (variable)
    /// - Certificate list length (3 bytes)
    /// - Certificate entries (variable):
    ///   - Certificate data length (3 bytes)
    ///   - Certificate data (variable)
    ///   - Extensions length (2 bytes)
    ///   - Extensions (variable)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // Certificate request context length (1 byte) + context
        assert!(
            self.certificate_request_context.len() <= 255,
            "certificate_request_context length must not exceed 255 bytes"
        );
        data.push(self.certificate_request_context.len() as u8);
        data.extend_from_slice(&self.certificate_request_context);

        // Build certificate list data
        let mut cert_list_data = Vec::new();

        for entry in &self.certificate_list {
            // Certificate data length (3 bytes)
            let cert_data_len = entry.cert_data.len();
            assert!(
                cert_data_len < (1 << 24) && cert_data_len > 0,
                "certificate data length must be between 1 and 2^24-1 bytes"
            );

            cert_list_data.push((cert_data_len >> 16) as u8);
            cert_list_data.push((cert_data_len >> 8) as u8);
            cert_list_data.push(cert_data_len as u8);

            // Certificate data
            cert_list_data.extend_from_slice(&entry.cert_data);

            // Serialize extensions
            let mut extensions_data = Vec::new();
            for ext in &entry.extensions {
                extensions_data.extend_from_slice(&ext.to_bytes());
            }

            // Extensions length (2 bytes) + extensions
            let extensions_len: u16 = extensions_data
                .len()
                .try_into()
                .expect("extensions data length exceeds u16 maximum (65535 bytes)");
            cert_list_data.extend_from_slice(&extensions_len.to_be_bytes());
            cert_list_data.extend_from_slice(&extensions_data);
        }

        // Certificate list length (3 bytes) + certificate list
        let cert_list_len = cert_list_data.len();
        assert!(
            cert_list_len < (1 << 24),
            "certificate list length must not exceed 2^24-1 bytes"
        );

        data.push((cert_list_len >> 16) as u8);
        data.push((cert_list_len >> 8) as u8);
        data.push(cert_list_len as u8);
        data.extend_from_slice(&cert_list_data);

        // Prepend handshake header
        let total_len = data.len();
        assert!(
            total_len < (1 << 24),
            "Certificate message length must not exceed 2^24-1 bytes"
        );

        let mut result = Vec::new();
        result.push(0x0b); // Certificate handshake type
        result.push((total_len >> 16) as u8);
        result.push((total_len >> 8) as u8);
        result.push(total_len as u8);
        result.extend_from_slice(&data);

        result
    }

    /// Validate the Certificate message
    pub fn validate(&self) -> Result<(), TlsError> {
        // Check that certificate_request_context doesn't exceed 255 bytes
        if self.certificate_request_context.len() > 255 {
            return Err(TlsError::InvalidCertificateData(format!(
                "Certificate request context too large: {} bytes",
                self.certificate_request_context.len()
            )));
        }

        // For server authentication, at least one certificate must be present
        // (In client authentication scenarios, an empty list might be valid,
        // but for now we enforce non-empty for server auth which is the primary use case)
        if self.certificate_list.is_empty() {
            return Err(TlsError::EmptyCertificateList);
        }

        // Check chain length limit
        if self.certificate_list.len() > MAX_CERTIFICATE_CHAIN_LENGTH {
            return Err(TlsError::CertificateChainTooLong(
                self.certificate_list.len(),
            ));
        }

        // Validate each certificate entry
        for entry in &self.certificate_list {
            entry.validate()?;
        }

        Ok(())
    }

    /// Check if the certificate request context is empty
    /// (should be empty for server authentication)
    pub fn is_server_authentication(&self) -> bool {
        self.certificate_request_context.is_empty()
    }

    /// Get the end-entity (leaf) certificate
    /// Returns the first certificate in the chain (the server/client certificate)
    pub fn end_entity_certificate(&self) -> Option<&CertificateEntry> {
        self.certificate_list.first()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_entry_validation() {
        // Valid certificate entry
        let entry = CertificateEntry::new(vec![0x30; 100], vec![]);
        assert!(entry.validate().is_ok());

        // Empty certificate data
        let entry = CertificateEntry::new(vec![], vec![]);
        assert!(matches!(
            entry.validate(),
            Err(TlsError::InvalidCertificateData(_))
        ));
    }

    #[test]
    fn test_certificate_validation() {
        // Valid certificate with one entry
        let cert = Certificate::new(vec![], vec![CertificateEntry::new(vec![0x30; 100], vec![])]);
        assert!(cert.validate().is_ok());

        // Empty certificate list
        let cert = Certificate::new(vec![], vec![]);
        assert!(matches!(
            cert.validate(),
            Err(TlsError::EmptyCertificateList)
        ));

        // Context too large
        let cert = Certificate::new(
            vec![0u8; 256],
            vec![CertificateEntry::new(vec![0x30; 100], vec![])],
        );
        assert!(matches!(
            cert.validate(),
            Err(TlsError::InvalidCertificateData(_))
        ));
    }

    #[test]
    fn test_is_server_authentication() {
        let cert = Certificate::new(vec![], vec![CertificateEntry::new(vec![0x30; 100], vec![])]);
        assert!(cert.is_server_authentication());

        let cert = Certificate::new(
            vec![1, 2, 3],
            vec![CertificateEntry::new(vec![0x30; 100], vec![])],
        );
        assert!(!cert.is_server_authentication());
    }

    #[test]
    fn test_end_entity_certificate() {
        let cert1 = CertificateEntry::new(vec![0x30; 100], vec![]);
        let cert2 = CertificateEntry::new(vec![0x31; 100], vec![]);

        let cert = Certificate::new(vec![], vec![cert1.clone(), cert2]);

        let end_entity = cert.end_entity_certificate().unwrap();
        assert_eq!(end_entity.cert_data, cert1.cert_data);
    }
}
