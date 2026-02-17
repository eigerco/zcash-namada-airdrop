//! Setup subcommands.

use std::path::PathBuf;

use zair_sdk::commands::SaplingSetupScheme;

use super::parse_setup_scheme;

/// Setup command group.
#[derive(Debug, clap::Subcommand)]
pub enum SetupCommands {
    /// Generate claim circuit parameters (proving and verifying keys).
    Local {
        /// Sapling circuit scheme to generate params for.
        #[arg(
            long,
            env = "SETUP_SCHEME",
            default_value = "native",
            value_parser = parse_setup_scheme
        )]
        scheme: SaplingSetupScheme,

        /// Output file for proving key.
        #[arg(long, env = "SETUP_PK_OUT", default_value = "setup-sapling-pk.params")]
        pk_out: PathBuf,

        /// Output file for verifying key.
        #[arg(long, env = "SETUP_VK_OUT", default_value = "setup-sapling-vk.params")]
        vk_out: PathBuf,
    },
}
