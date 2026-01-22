//! ZK Claim Circuit for Zcash-Namada Airdrop.
//!
//! This crate provides a ZK circuit that proves ownership of an unspent Sapling note
//! for the Zcash-to-Namada airdrop. The circuit is based on the Sapling Spend circuit
//! and will be extended with non-membership proofs.

pub mod builder;
pub mod circuit;
pub mod convenience;
pub mod error;
pub mod gadgets;
pub mod proving;
pub mod verifier;

pub use builder::{ParameterError, generate_parameters, load_parameters, save_parameters};
pub use convenience::{ClaimProofInputs, ClaimProofOutput, generate_claim_proof};
pub use error::ClaimProofError;
pub use proving::ClaimParameters;
pub use verifier::{VerificationError, verify_claim_proof_output};
