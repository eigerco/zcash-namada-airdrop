//! Application command implementations.
//!
//! This module contains the core logic for each CLI subcommand.

mod airdrop_claim;
mod airdrop_configuration;
mod claim_proofs;
mod note_metadata;
mod pool_processor;

pub use airdrop_claim::airdrop_claim;
pub use airdrop_configuration::build_airdrop_configuration;
pub use claim_proofs::verify_claim_sapling_proof;
#[cfg(feature = "prove")]
pub use claim_proofs::{generate_claim_params, generate_claim_proofs};

/// Generates and prints the JSON schema for the `AirdropConfiguration` struct.
///
/// # Errors
/// Returns an error if serialization to JSON fails.
#[allow(clippy::print_stdout, reason = "Prints schema to stdout")]
pub fn airdrop_configuration_schema() -> eyre::Result<()> {
    let schema = schemars::schema_for!(zair_core::schema::config::AirdropConfiguration);
    let schema_str = serde_json::to_string_pretty(&schema)?;
    println!("Airdrop Configuration JSON Schema:\n{schema_str}");
    Ok(())
}
