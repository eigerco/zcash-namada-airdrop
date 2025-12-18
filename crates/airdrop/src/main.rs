//! Airdrop CLI Application

use clap::Parser as _;

use crate::cli::{Cli, Commands, CommonArgs};
use crate::commands::{airdrop_claim, build_airdrop_configuration};

mod airdrop_configuration;
mod chain_nullifiers;
mod cli;
mod commands;
mod proof;

/// Check if a slice is sorted and does not contains duplicates
#[allow(
    clippy::indexing_slicing,
    clippy::missing_asserts_for_indexing,
    reason = "Windows(2) guarantees 2 elements"
)]
pub(crate) fn is_sanitize<T: Ord + Clone>(v: &[T]) -> bool {
    v.is_sorted() && !v.windows(2).any(|w| w[0] == w[1])
}

fn init_tracing() {
    #[cfg(feature = "tokio-console")]
    {
        // tokio-console: layers the console subscriber with fmt
        use tracing_subscriber::prelude::*;
        tracing_subscriber::registry()
            .with(console_subscriber::spawn())
            .with(
                tracing_subscriber::fmt::layer().with_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
                ),
            )
            .init();
    }

    #[cfg(not(feature = "tokio-console"))]
    {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .with_timer(tracing_subscriber::fmt::time::uptime())
            .with_target(false)
            .init();
    }
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    // Initialize rustls crypto provider (required for TLS connections)
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // Load .env file (fails silently if not found)
    #[allow(
        clippy::let_underscore_must_use,
        clippy::let_underscore_untyped,
        reason = "Ignoring dotenv result intentionally"
    )]
    let _ = dotenvy::dotenv();

    init_tracing();

    let cli = Cli::parse();

    let res = match cli.command {
        Commands::BuildAirdropConfiguration {
            config,
            configuration_output_file,
            sapling_snapshot_nullifiers,
            orchard_snapshot_nullifiers,
        } => {
            build_airdrop_configuration(
                config,
                configuration_output_file,
                sapling_snapshot_nullifiers,
                orchard_snapshot_nullifiers,
            )
            .await
        }
        Commands::AirdropClaim {
            config,
            sapling_snapshot_nullifiers,
            orchard_snapshot_nullifiers,
            orchard_fvk,
            sapling_fvk,
            birthday_height,
            airdrop_claims_output_file,
        } => {
            airdrop_claim(
                config,
                sapling_snapshot_nullifiers,
                orchard_snapshot_nullifiers,
                &orchard_fvk,
                &sapling_fvk,
                birthday_height,
                airdrop_claims_output_file,
            )
            .await
        }
    };

    if let Err(e) = res {
        tracing::error!("Error: {:?}", e);
        std::process::exit(1);
    }

    Ok(())
}
