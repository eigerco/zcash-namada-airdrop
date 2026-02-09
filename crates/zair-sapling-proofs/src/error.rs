//! Error types for the claim circuit crate.

/// Errors that can occur during claim proof generation.
#[derive(Debug, thiserror::Error)]
pub enum ClaimProofError {
    /// Invalid rcm value
    #[error("Invalid rcm: not a valid scalar")]
    InvalidRcm,
    /// Invalid payment address
    #[error("Invalid payment address")]
    InvalidPaymentAddress,
    /// Invalid ak value
    #[error("Invalid ak: not a valid point")]
    InvalidAk,
    /// Invalid note commitment (cmu)
    #[error("Invalid note commitment: not a valid scalar")]
    InvalidCmu,
    /// Invalid merkle path
    #[error("Invalid merkle path: {0}")]
    InvalidMerklePath(String),
    /// Invalid non-membership merkle path
    #[error("Invalid non-membership merkle path: {0}")]
    InvalidNmMerklePath(String),
    /// Proof creation failed
    #[error("Proof creation failed: {0}")]
    ProofCreation(String),
    /// Proof decoding failed
    #[error("Proof decoding failed: {0}")]
    ProofDecoding(String),
    /// Integer conversion failed
    #[error("Integer conversion failed: {0}")]
    IntegerConversion(#[from] std::num::TryFromIntError),
}
