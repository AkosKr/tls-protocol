// Re-export modules for convenient access
pub mod decoder;
pub mod error;
pub mod parser;

// Re-export commonly used types
pub use decoder::decode_header;
pub use error::TlsError;
pub use parser::parse_header;
