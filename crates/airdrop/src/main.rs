//! Airdrop CLI Application

use clap::Parser as _;
use non_membership_proofs::user_nullifiers::{OrchardViewingKeys, SaplingViewingKeys, ViewingKeys};
use zcash_keys::keys::UnifiedFullViewingKey;

use crate::cli::{Cli, Commands, CommonArgs};
use crate::commands::{airdrop_claim, airdrop_configuration_schema, build_airdrop_configuration};

mod airdrop_configuration;
mod chain_nullifiers;
mod cli;
mod commands;
mod proof;

pub(crate) const BUF_SIZE: usize = 1024 * 1024;

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

#[tokio::main(flavor = "multi_thread")]
async fn main() -> eyre::Result<()> {
    // Initialize rustls crypto provider (required for TLS connections)
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // Load .env file (fails silently if not found)
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
            unified_full_viewing_key,
            birthday_height,
            airdrop_claims_output_file,
            airdrop_configuration_file,
        } => {
            let ufvk = UnifiedFullViewingKey::decode(&config.network, &unified_full_viewing_key)
                .map_err(|e| eyre::eyre!("Failed to decode Unified Full Viewing Key: {:?}", e))?;

            let orchard_fvk = ufvk.orchard().ok_or_else(|| {
                eyre::eyre!("Unified Full Viewing Key does not contain an Orchard FVK")
            })?;

            let sapling_fvk = ufvk.sapling().ok_or_else(|| {
                eyre::eyre!("Unified Full Viewing Key does not contain a Sapling FVK")
            })?;

            let viewing_keys = ViewingKeys {
                sapling: Some(SaplingViewingKeys::from_dfvk(sapling_fvk)),
                orchard: Some(OrchardViewingKeys::from_fvk(orchard_fvk)),
            };

            airdrop_claim(
                config,
                sapling_snapshot_nullifiers,
                orchard_snapshot_nullifiers,
                viewing_keys,
                birthday_height,
                airdrop_claims_output_file,
                airdrop_configuration_file,
            )
            .await
        }
        Commands::AirdropConfigurationSchema => airdrop_configuration_schema(),
    };

    if let Err(e) = res {
        tracing::error!("Error: {:?}", e);
        std::process::exit(1);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use test_utils::nf;

    use super::*;

    #[test]
    fn test_is_sanitize_nullifiers() {
        let nf1 = nf!(0);
        let nf2 = nf!(1);
        let nf3 = nf!(2);

        assert!(is_sanitize(&[nf1, nf2, nf3]));

        // Nullifiers are unsorted
        assert!(!is_sanitize(&[nf2, nf1, nf3]));

        // Nullifiers contain duplicates
        assert!(!is_sanitize(&[nf1, nf1, nf2]));
    }
}
