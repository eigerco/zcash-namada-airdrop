//! CLI command implementations for the airdrop crate.
//!
//! This module contains the core logic for each CLI subcommand.
//!
//! These commands interact with lightwalletd, process nullifiers for Sapling and Orchard pools,
//! and ensure data integrity for the airdrop process.

mod airdrop_claim;
mod airdrop_configuration;
mod note_metadata;
mod pool_processor;

pub use airdrop_claim::airdrop_claim;
pub use airdrop_configuration::{
    AirdropConfiguration, CommitmentTreeAnchors, HidingFactor, NonMembershipTreeAnchors,
    OrchardHidingFactor, SaplingHidingFactor, build_airdrop_configuration,
};

/// Generates and prints the JSON schema for the `AirdropConfiguration` struct.
///
/// # Errors
/// Returns an Error if serialization to JSON fails.
#[allow(clippy::print_stdout, reason = "Prints schema to stdout")]
pub fn airdrop_configuration_schema() -> eyre::Result<()> {
    let schema = schemars::schema_for!(AirdropConfiguration);
    let schema_str = serde_json::to_string_pretty(&schema)?;
    println!("Airdrop Configuration JSON Schema:\n{schema_str}");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn airdrop_configuration_schema_sanity_check() {
        let result = airdrop_configuration_schema();
        assert!(result.is_ok());
    }
}
