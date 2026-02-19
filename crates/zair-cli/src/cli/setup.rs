//! Setup subcommands.

use std::path::PathBuf;

use zair_core::schema::config::ValueCommitmentScheme;

use super::parse_value_commitment_scheme;

/// Setup command group.
#[derive(Debug, clap::Subcommand)]
pub enum SetupCommands {
    /// Generate Sapling claim proving and verifying keys.
    Sapling {
        /// Sapling circuit scheme to generate params for.
        #[arg(
            long,
            env = "SETUP_SCHEME",
            default_value = "native",
            value_parser = parse_value_commitment_scheme
        )]
        scheme: ValueCommitmentScheme,

        /// Output file for proving key.
        #[arg(long, env = "SETUP_PK_OUT", default_value = "setup-sapling-pk.params")]
        pk_out: PathBuf,

        /// Output file for verifying key.
        #[arg(long, env = "SETUP_VK_OUT", default_value = "setup-sapling-vk.params")]
        vk_out: PathBuf,
    },
    /// Generate Orchard Halo2 params for proving and verification.
    Orchard {
        /// Orchard value commitment scheme to generate params for.
        #[arg(
            long,
            env = "SETUP_SCHEME",
            default_value = "native",
            value_parser = parse_value_commitment_scheme
        )]
        scheme: ValueCommitmentScheme,

        /// Output file for Orchard Halo2 params.
        #[arg(
            long,
            env = "SETUP_ORCHARD_PARAMS_OUT",
            default_value = "setup-orchard-params.bin"
        )]
        params_out: PathBuf,
    },
}
