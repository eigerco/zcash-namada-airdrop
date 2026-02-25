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
mod key;
mod note_metadata;
mod nullifier_uniqueness;
mod orchard_params;
#[cfg(feature = "prove")]
mod orchard_setup;
mod pool_processor;
mod sensitive_output;
mod signature_digest;
mod submission_auth;
mod submission_messages;
mod workflows;

pub use airdrop_claim::{GapTreeMode, airdrop_claim};
pub use airdrop_configuration::build_airdrop_configuration;
pub use claim_proofs::verify_claim_proofs;
#[cfg(feature = "prove")]
pub use claim_proofs_prove::{generate_claim_params, generate_claim_proofs};
pub use claim_submission_sign::sign_claim_submission;
pub use claim_submission_verify::verify_claim_submission_signature;
pub use key::{MnemonicSource, key_derive_seed, key_derive_ufvk};
pub use orchard_params::{
    OrchardParamsMode, generate_orchard_params_file, load_or_prepare_orchard_params,
};
#[cfg(feature = "prove")]
pub use orchard_setup::generate_orchard_params;
#[cfg(feature = "prove")]
pub use workflows::claim_run;
pub use workflows::verify_run;
