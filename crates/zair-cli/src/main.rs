//! ZAIR CLI Application

mod cli;

use clap::Parser as _;
use cli::{Cli, Commands};
use zair_sdk::commands::{
    airdrop_claim, airdrop_configuration_schema, build_airdrop_configuration,
};

fn init_tracing() -> eyre::Result<()> {
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
            .try_init()
            .map_err(|e| eyre::eyre!("Failed to initialize tracing: {:?}", e))?;
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
            .try_init()
            .map_err(|e| eyre::eyre!("Failed to initialize tracing: {:?}", e))?;
    }

    Ok(())
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> eyre::Result<()> {
    // Initialize rustls crypto provider (required for TLS connections)
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|e| eyre::eyre!("Failed to install rustls crypto provider: {e:?}"))?;

    // Load .env file (fails silently if not found)
    let _ = dotenvy::dotenv();

    init_tracing()?;

    let cli = Cli::parse();

    let res = match cli.command {
        Commands::BuildConfig {
            config,
            pool,
            configuration_output_file,
            sapling_snapshot_nullifiers,
            orchard_snapshot_nullifiers,
            sapling_target_id,
            orchard_target_id,
        } => {
            build_airdrop_configuration(
                config.into(),
                pool,
                configuration_output_file,
                sapling_snapshot_nullifiers,
                orchard_snapshot_nullifiers,
                sapling_target_id,
                orchard_target_id,
            )
            .await
        }
        Commands::ClaimPrepare {
            lightwalletd_url,
            sapling_snapshot_nullifiers,
            orchard_snapshot_nullifiers,
            unified_full_viewing_key,
            birthday_height,
            airdrop_claims_output_file,
            airdrop_configuration_file,
        } => {
            airdrop_claim(
                lightwalletd_url,
                sapling_snapshot_nullifiers,
                orchard_snapshot_nullifiers,
                unified_full_viewing_key,
                birthday_height,
                airdrop_claims_output_file,
                airdrop_configuration_file,
            )
            .await
        }
        Commands::ConfigSchema => airdrop_configuration_schema(),
        #[cfg(feature = "prove")]
        Commands::Prove {
            claim_inputs_file,
            proofs_output_file,
            seed_file,
            network,
            proving_key_file,
        } => {
            zair_sdk::commands::generate_claim_proofs(
                claim_inputs_file,
                proofs_output_file,
                seed_file,
                network,
                proving_key_file,
            )
            .await
        }
        #[cfg(feature = "prove")]
        Commands::SetupLocal {
            proving_key_file,
            verifying_key_file,
        } => zair_sdk::commands::generate_claim_params(proving_key_file, verifying_key_file).await,
        Commands::Verify {
            proofs_file,
            verifying_key_file,
        } => zair_sdk::commands::verify_claim_sapling_proof(proofs_file, verifying_key_file).await,
    };

    if let Err(e) = res {
        tracing::error!("Error: {:?}", e);
        std::process::exit(1);
    }

    Ok(())
}
