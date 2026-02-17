//! Config subcommands.

use std::path::PathBuf;

use zair_core::schema::config::ValueCommitmentScheme;
use zair_sdk::common::PoolSelection;

use super::{
    BuildConfigArgs, parse_orchard_target_id, parse_pool_selection, parse_sapling_target_id,
    parse_value_commitment_scheme,
};

/// Arguments for `config build`.
#[derive(Debug, clap::Args)]
pub struct ConfigBuildArgs {
    /// Build-config specific arguments.
    #[command(flatten)]
    pub config: BuildConfigArgs,
    /// Pool to include in the exported configuration.
    #[arg(long, env = "POOL", default_value = "both", value_parser = parse_pool_selection)]
    pub pool: PoolSelection,
    /// Sapling target id used for hiding nullifier derivation. Must be exactly 8 bytes.
    #[arg(
        long,
        env = "TARGET_SAPLING",
        default_value = "ZAIRTEST",
        value_parser = parse_sapling_target_id
    )]
    pub target_sapling: String,
    /// Sapling value commitment scheme.
    #[arg(
        long,
        env = "SCHEME_SAPLING",
        default_value = "native",
        value_parser = parse_value_commitment_scheme
    )]
    pub scheme_sapling: ValueCommitmentScheme,
    /// Orchard target id used for hiding nullifier derivation. Must be <= 32 bytes.
    #[arg(
        long,
        env = "TARGET_ORCHARD",
        default_value = "ZAIRTEST:O",
        value_parser = parse_orchard_target_id
    )]
    pub target_orchard: String,
    /// Orchard value commitment scheme.
    #[arg(
        long,
        env = "SCHEME_ORCHARD",
        default_value = "native",
        value_parser = parse_value_commitment_scheme
    )]
    pub scheme_orchard: ValueCommitmentScheme,
    /// Configuration output file.
    #[arg(long, env = "CONFIG_OUT", default_value = "config.json")]
    pub config_out: PathBuf,
    /// Sapling snapshot nullifiers output file.
    #[arg(
        long,
        env = "SNAPSHOT_OUT_SAPLING",
        default_value = "snapshot-sapling.bin"
    )]
    pub snapshot_out_sapling: PathBuf,
    /// Orchard snapshot nullifiers output file.
    #[arg(
        long,
        env = "SNAPSHOT_OUT_ORCHARD",
        default_value = "snapshot-orchard.bin"
    )]
    pub snapshot_out_orchard: PathBuf,
}

/// Config command group.
#[derive(Debug, clap::Subcommand)]
pub enum ConfigCommands {
    /// Build a snapshot of nullifiers from a source.
    Build {
        #[command(flatten)]
        args: ConfigBuildArgs,
    },
}
