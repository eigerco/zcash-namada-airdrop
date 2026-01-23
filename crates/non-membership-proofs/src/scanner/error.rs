//! Scanner error types

use thiserror::Error;

/// Errors that can occur during chain scanning
#[derive(Debug, Error)]
pub enum ScannerError {
    /// An invalid viewing key was provided
    #[error("Invalid viewing key: {0}")]
    InvalidViewingKey(String),

    /// An error occurred during scanning using `zcash_client_backend`
    #[error("Scan error: {0}")]
    ScanError(zcash_client_backend::scanning::ScanError),

    /// An error occurred in the commitment tree management
    #[error("Tree error: {0}")]
    TreeError(String),

    /// Note not found at the specified position of the commitment tree
    #[error("Note not found at position {0}")]
    NoteNotFound(u64),

    /// Other general errors
    #[error("Other: {0}")]
    Other(&'static str),

    /// Int Conversion error
    #[error("Conversion error: {0}")]
    PositionConversionError(#[from] std::num::TryFromIntError),
}
