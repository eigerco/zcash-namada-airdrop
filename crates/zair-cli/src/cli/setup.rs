//! Setup subcommands.

use std::path::PathBuf;

use zair_core::schema::config::ValueCommitmentScheme;

use super::constants::{
    DEFAULT_ORCHARD_PARAMS_FILE, DEFAULT_SAPLING_PK_FILE, DEFAULT_SAPLING_VK_FILE, DEFAULT_SCHEME,
    ZAIR_SETUP_ORCHARD_PARAMS_OUT, ZAIR_SETUP_PK_OUT, ZAIR_SETUP_SCHEME, ZAIR_SETUP_VK_OUT,
};
use super::parse_value_commitment_scheme;

/// Setup command group.
#[derive(Debug, clap::Subcommand)]
pub enum SetupCommands {
    /// Generate Sapling claim proving and verifying keys.
    Sapling {
        /// Sapling circuit scheme to generate params for.
        #[arg(
            long,
            env = ZAIR_SETUP_SCHEME,
            default_value = DEFAULT_SCHEME,
            value_parser = parse_value_commitment_scheme
        )]
        scheme: ValueCommitmentScheme,

        /// Output file for proving key.
        #[arg(long, env = ZAIR_SETUP_PK_OUT, default_value = DEFAULT_SAPLING_PK_FILE)]
        pk_out: PathBuf,

        /// Output file for verifying key.
        #[arg(long, env = ZAIR_SETUP_VK_OUT, default_value = DEFAULT_SAPLING_VK_FILE)]
        vk_out: PathBuf,
    },
    /// Generate Orchard Halo2 params for proving and verification.
    Orchard {
        /// Orchard value commitment scheme to generate params for.
        #[arg(
            long,
            env = ZAIR_SETUP_SCHEME,
            default_value = DEFAULT_SCHEME,
            value_parser = parse_value_commitment_scheme
        )]
        scheme: ValueCommitmentScheme,

        /// Output file for Orchard Halo2 params.
        #[arg(
            long,
            env = ZAIR_SETUP_ORCHARD_PARAMS_OUT,
            default_value = DEFAULT_ORCHARD_PARAMS_FILE
        )]
        params_out: PathBuf,
    },
}
