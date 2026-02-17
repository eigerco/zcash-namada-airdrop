//! ZAIR CLI Application

mod cli;

use clap::Parser as _;
#[cfg(feature = "prove")]
use cli::SetupCommands;
use cli::{ClaimCommands, Cli, Commands, ConfigCommands, VerifyCommands};
use zair_sdk::commands::{airdrop_claim, build_airdrop_configuration};

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
#[allow(
    clippy::too_many_lines,
    reason = "Top-level CLI dispatch keeps all command wiring in one place"
)]
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
        #[cfg(feature = "prove")]
        Commands::Setup { command } => match command {
            SetupCommands::Local {
                scheme,
                pk_out,
                vk_out,
            } => zair_sdk::commands::generate_claim_params(pk_out, vk_out, scheme).await,
        },
        Commands::Config { command } => match command {
            ConfigCommands::Build { args } => {
                build_airdrop_configuration(
                    args.config.into(),
                    args.pool,
                    args.config_out,
                    args.snapshot_out_sapling,
                    args.snapshot_out_orchard,
                    args.target_sapling,
                    args.scheme_sapling,
                    args.target_orchard,
                    args.scheme_orchard,
                )
                .await
            }
        },
        Commands::Claim { command } => match command {
            #[cfg(feature = "prove")]
            ClaimCommands::Run { args } => {
                zair_sdk::commands::claim_run(
                    args.lightwalletd,
                    args.snapshot_sapling,
                    args.snapshot_orchard,
                    args.birthday,
                    args.claims_out,
                    args.proofs_out,
                    args.secrets_out,
                    args.submission_out,
                    args.seed,
                    args.account,
                    args.pk,
                    args.msg,
                    args.config,
                )
                .await
            }
            ClaimCommands::Prepare { args } => {
                airdrop_claim(
                    args.lightwalletd,
                    args.snapshot_sapling,
                    args.snapshot_orchard,
                    args.ufvk,
                    args.birthday,
                    args.claims_out,
                    args.config,
                )
                .await
            }
            #[cfg(feature = "prove")]
            ClaimCommands::Prove { args } => {
                zair_sdk::commands::generate_claim_proofs(
                    args.claims_in,
                    args.proofs_out,
                    args.seed,
                    args.account,
                    args.pk,
                    args.secrets_out,
                    args.config,
                )
                .await
            }
            ClaimCommands::Sign { args } => {
                zair_sdk::commands::sign_claim_submission(
                    args.proofs_in,
                    args.secrets_in,
                    args.seed,
                    args.account,
                    args.config,
                    args.msg,
                    args.submission_out,
                )
                .await
            }
        },
        Commands::Verify { command } => match command {
            VerifyCommands::Run { args } => {
                zair_sdk::commands::verify_run(args.vk, args.submission_in, args.msg, args.config)
                    .await
            }
            VerifyCommands::Proof { args } => {
                zair_sdk::commands::verify_claim_sapling_proof(args.proofs_in, args.vk, args.config)
                    .await
            }
            VerifyCommands::Signature { args } => {
                zair_sdk::commands::verify_claim_submission_signature(
                    args.submission_in,
                    args.msg,
                    args.config,
                )
                .await
            }
        },
    };

    if let Err(e) = res {
        tracing::error!("Error: {:?}", e);
        std::process::exit(1);
    }

    Ok(())
}
