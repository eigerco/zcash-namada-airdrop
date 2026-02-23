//! Config subcommands.

use std::path::PathBuf;

use zair_core::schema::config::ValueCommitmentScheme;
use zair_sdk::common::PoolSelection;

use super::constants::{
    DEFAULT_CONFIG_FILE, DEFAULT_GAP_TREE_ORCHARD_FILE, DEFAULT_GAP_TREE_SAPLING_FILE,
    DEFAULT_POOL, DEFAULT_SCHEME, DEFAULT_SNAPSHOT_ORCHARD_FILE, DEFAULT_SNAPSHOT_SAPLING_FILE,
    DEFAULT_TARGET_ORCHARD, DEFAULT_TARGET_SAPLING, ZAIR_CONFIG_OUT, ZAIR_GAP_TREE_OUT_ORCHARD,
    ZAIR_GAP_TREE_OUT_SAPLING, ZAIR_NO_GAP_TREE, ZAIR_POOL, ZAIR_SCHEME_ORCHARD,
    ZAIR_SCHEME_SAPLING, ZAIR_SNAPSHOT_OUT_ORCHARD, ZAIR_SNAPSHOT_OUT_SAPLING, ZAIR_TARGET_ORCHARD,
    ZAIR_TARGET_SAPLING,
};
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
    #[arg(
        long,
        env = ZAIR_POOL,
        default_value = DEFAULT_POOL,
        value_parser = parse_pool_selection
    )]
    pub pool: PoolSelection,
    /// Sapling target id used for hiding nullifier derivation. Must be exactly 8 bytes.
    #[arg(
        long,
        env = ZAIR_TARGET_SAPLING,
        default_value = DEFAULT_TARGET_SAPLING,
        value_parser = parse_sapling_target_id
    )]
    pub target_sapling: String,
    /// Sapling value commitment scheme.
    #[arg(
        long,
        env = ZAIR_SCHEME_SAPLING,
        default_value = DEFAULT_SCHEME,
        value_parser = parse_value_commitment_scheme
    )]
    pub scheme_sapling: ValueCommitmentScheme,
    /// Orchard target id used for hiding nullifier derivation. Must be <= 32 bytes.
    #[arg(
        long,
        env = ZAIR_TARGET_ORCHARD,
        default_value = DEFAULT_TARGET_ORCHARD,
        value_parser = parse_orchard_target_id
    )]
    pub target_orchard: String,
    /// Orchard value commitment scheme.
    #[arg(
        long,
        env = ZAIR_SCHEME_ORCHARD,
        default_value = DEFAULT_SCHEME,
        value_parser = parse_value_commitment_scheme
    )]
    pub scheme_orchard: ValueCommitmentScheme,
    /// Configuration output file.
    #[arg(long, env = ZAIR_CONFIG_OUT, default_value = DEFAULT_CONFIG_FILE)]
    pub config_out: PathBuf,
    /// Sapling snapshot nullifiers output file.
    #[arg(
        long,
        env = ZAIR_SNAPSHOT_OUT_SAPLING,
        default_value = DEFAULT_SNAPSHOT_SAPLING_FILE
    )]
    pub snapshot_out_sapling: PathBuf,
    /// Orchard snapshot nullifiers output file.
    #[arg(
        long,
        env = ZAIR_SNAPSHOT_OUT_ORCHARD,
        default_value = DEFAULT_SNAPSHOT_ORCHARD_FILE
    )]
    pub snapshot_out_orchard: PathBuf,
    /// Sapling gap-tree output file.
    #[arg(
        long,
        env = ZAIR_GAP_TREE_OUT_SAPLING,
        default_value = DEFAULT_GAP_TREE_SAPLING_FILE
    )]
    pub gap_tree_out_sapling: PathBuf,
    /// Orchard gap-tree output file.
    #[arg(
        long,
        env = ZAIR_GAP_TREE_OUT_ORCHARD,
        default_value = DEFAULT_GAP_TREE_ORCHARD_FILE
    )]
    pub gap_tree_out_orchard: PathBuf,
    /// Skip writing gap-tree artifacts.
    #[arg(long, env = ZAIR_NO_GAP_TREE, default_value_t = false)]
    pub no_gap_tree: bool,
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
