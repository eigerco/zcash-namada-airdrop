//! Application command implementations.
//!
//! This module contains the core logic for each CLI subcommand.

mod airdrop_claim;
mod airdrop_configuration;
mod claim_proofs;
#[cfg(feature = "prove")]
mod claim_proofs_prove;
mod claim_submission_sign;
mod claim_submission_verify;
mod note_metadata;
mod pool_processor;
mod signature_digest;
mod workflows;

pub use airdrop_claim::airdrop_claim;
pub use airdrop_configuration::build_airdrop_configuration;
pub use claim_proofs::verify_claim_sapling_proof;
#[cfg(feature = "prove")]
pub use claim_proofs_prove::{SaplingSetupScheme, generate_claim_params, generate_claim_proofs};
pub use claim_submission_sign::sign_claim_submission;
pub use claim_submission_verify::verify_claim_submission_signature;
#[cfg(feature = "prove")]
pub use workflows::claim_run;
pub use workflows::verify_run;
