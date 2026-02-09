//! Sapling claim proving and verification.

pub mod error;
pub mod types;
#[cfg(feature = "verify")]
pub mod verifier;

#[cfg(feature = "prove")]
pub mod builder;
#[cfg(feature = "prove")]
pub mod convenience;
#[cfg(feature = "prove")]
pub mod proving;

#[cfg(feature = "prove")]
pub use builder::{ParameterError, generate_parameters, load_parameters, save_parameters};
#[cfg(feature = "prove")]
pub use convenience::generate_claim_proof;
pub use error::ClaimProofError;
#[cfg(feature = "prove")]
pub use proving::ClaimParameters;
pub use types::{ClaimProofInputs, ClaimProofOutput, GROTH_PROOF_SIZE, GrothProofBytes};
#[cfg(feature = "verify")]
pub use verifier::{VerificationError, verify_claim_proof_output};
