//! CLI command implementations for the airdrop crate.
//!
//! This module contains the core logic for each CLI subcommand.
//!
//! These commands interact with lightwalletd, process nullifiers for Sapling and Orchard pools,
//! and ensure data integrity for the airdrop process.

use crate::airdrop_configuration::AirdropConfiguration;

mod airdrop_claim;
mod airdrop_configuration;

pub use airdrop_claim::airdrop_claim;
pub use airdrop_configuration::build_airdrop_configuration;

#[allow(clippy::print_stdout, reason = "Prints schema to stdout")]
pub fn airdrop_configuration_schema() -> eyre::Result<()> {
    let schema = schemars::schema_for!(AirdropConfiguration);
    let schema_str = serde_json::to_string_pretty(&schema)?;
    println!("Airdrop Configuration JSON Schema:\n{schema_str}");

    Ok(())
}
