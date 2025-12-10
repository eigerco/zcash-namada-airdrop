//! Airdrop CLI Application

use clap::Parser as _;
use eyre::ensure;
use futures::StreamExt;
use non_membership_proofs::source::light_walletd::LightWalletd;
use non_membership_proofs::user_nullifiers::{
    AnyFoundNote, OrchardViewingKeys, SaplingViewingKeys, UserNullifiers as _, ViewingKeys,
};
use non_membership_proofs::{
    Nullifier, Pool, build_leaf, build_merkle_tree, partition_by_pool, write_raw_nullifiers,
};
use rs_merkle::algorithms::Sha256;
use rs_merkle::{Hasher, MerkleTree};
use serde::Serialize;
use tokio::fs::File;
use tokio::io::{AsyncWrite, AsyncWriteExt as _, BufWriter};
use tracing::{debug, info};
use zcash_primitives::consensus::{MainNetwork, Network, TestNetwork};

use crate::chain_nullifiers::load_nullifiers_from_file;
use crate::cli::{Cli, Commands, CommonArgs};

mod airdrop_configuration;
mod chain_nullifiers;
mod cli;

#[derive(Debug, Serialize)]
struct NullifierProof {
    left_nullifier: Nullifier,
    right_nullifier: Nullifier,
    merkle_proof: Vec<u8>,
}

/// Search for a nullifier in the snapshot and generate a non-membership proof if not found
async fn check_nullifier_membership<H: Hasher, W: AsyncWrite + Unpin>(
    note: &AnyFoundNote,
    snapshot_nullifiers: &[Nullifier],
    merkle_tree: &MerkleTree<H>,
    keys: &ViewingKeys,
    writer: &mut W,
    buf: &mut Vec<u8>,
) -> eyre::Result<()> {
    // // Reverse bytes to match snapshot byte order
    // let mut nf_rev = *nullifier;
    // nf_rev.reverse();

    let nullifier = note.nullifier(keys).expect("Note should have a nullifier");

    match snapshot_nullifiers.binary_search(&nullifier) {
        Ok(_) => {
            debug!(
                "{:?} nullifier {:?} found in snapshot.",
                note.pool(),
                hex::encode(nullifier),
            );
        }
        Err(idx) => {
            let left = idx.saturating_sub(1);
            let right = idx.saturating_add(1);

            let leaf = build_leaf(&snapshot_nullifiers[left], &snapshot_nullifiers[right]);
            let leaf_hash = H::hash(&leaf);

            let merkle_proof = merkle_tree.proof(&[left]);

            assert!(
                merkle_proof.verify(merkle_tree.root().unwrap(), &[left], &[leaf_hash], 1),
                "Merkle proof verification failed for {:?} nullifier {}",
                note.pool(),
                hex::encode(nullifier)
            );

            info!(
                "Generated non-membership proof for {:?} nullifier {}",
                note.pool(),
                hex::encode(nullifier)
            );

            let nullifier_proof = NullifierProof {
                left_nullifier: snapshot_nullifiers[left],
                right_nullifier: snapshot_nullifiers[right],
                merkle_proof: merkle_proof.to_bytes(),
            };

            buf.clear();
            serde_json::to_writer(&mut *buf, &nullifier_proof)?;
            writer.write_all(buf).await?;
            writer.write_all(b"\n").await?;
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    // Initialize rustls crypto provider (required for TLS connections)
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // Load .env file (fails silently if not found)
    if let Err(e) = dotenvy::dotenv() {
        eprintln!("Note: .env file not loaded: {e}");
    } else {
        eprintln!("Loaded .env file");
    }

    // Debug: show current RUST_LOG setting
    if let Ok(rust_log) = std::env::var("RUST_LOG") {
        eprintln!("RUST_LOG is set to: {rust_log}");
    } else {
        eprintln!("RUST_LOG is not set, using default: info");
    }

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_timer(tracing_subscriber::fmt::time::uptime())
        .init();

    // Parse CLI arguments (includes env vars loaded from .env)
    let cli = Cli::parse();
    info!("Cli Configuration: {cli:?}");

    match &cli.command {
        Commands::BuildAirdropConfiguration {
            config,
            configuration_output_file,
            sapling_snapshot_nullifiers,
            orchard_snapshot_nullifiers,
        } => {
            let stream = chain_nullifiers::get_nullifiers(&config).await?;

            let (mut sapling_nullifiers, mut orchard_nullifiers) =
                partition_by_pool(stream).await?;

            info!(
                "Collected {} sapling nullifiers and {} orchard nullifiers",
                sapling_nullifiers.len(),
                orchard_nullifiers.len()
            );

            sapling_nullifiers.sort_unstable();
            orchard_nullifiers.sort_unstable();

            // store nullifiers
            // Store the nullifiers so we can later generate proofs for
            // the nullifiers we are interested in.
            write_raw_nullifiers(&sapling_nullifiers, sapling_snapshot_nullifiers).await?;
            info!("Written sapling nullifiers to disk");
            write_raw_nullifiers(&orchard_nullifiers, orchard_snapshot_nullifiers).await?;
            info!("Written orchard nullifiers to disk");

            let sapling_tree = build_merkle_tree::<Sha256>(&sapling_nullifiers)?;
            info!(
                "Built sapling merkle tree with root: {}",
                sapling_tree.root_hex().unwrap_or_default()
            );

            let orchard_tree = build_merkle_tree::<Sha256>(&orchard_nullifiers)?;
            info!(
                "Built orchard merkle tree with root: {}",
                orchard_tree.root_hex().unwrap_or_default()
            );

            airdrop_configuration::AirdropConfiguration::new(
                sapling_tree.root_hex().as_deref(),
                orchard_tree.root_hex().as_deref(),
            )
            .export_config(configuration_output_file)
            .await?;

            info!("Exported airdrop configuration to {configuration_output_file}",);

            Ok(())
        }
        Commands::AirdropClaim {
            config,
            sapling_snapshot_nullifiers,
            orchard_snapshot_nullifiers,
            orchard_fvk,
            sapling_fvk,
            birthday_height,
        } => {
            ensure!(
                birthday_height <= config.snapshot.end(),
                "Birthday height cannot be greater than the snapshot end height"
            );

            ensure!(
                config.source.lightwalletd_url.is_some(),
                "lightwalletd URL must be provided in the airdrop configuration"
            );

            // TODO: if the sapling or orchard snapshot nullifiers files do not exist,
            // it should be possible to build them from the chain again.

            let sapling_nullifiers = load_nullifiers_from_file(sapling_snapshot_nullifiers).await?;
            let orchard_nullifiers = load_nullifiers_from_file(orchard_snapshot_nullifiers).await?;

            info!(
                "Read {} sapling nullifiers and {} orchard nullifiers from disk",
                sapling_nullifiers.len(),
                orchard_nullifiers.len()
            );

            let sapling_tree = build_merkle_tree::<Sha256>(&sapling_nullifiers)?;
            info!(
                "Built sapling merkle tree with root: {}",
                sapling_tree.root_hex().unwrap_or_default()
            );
            let orchard_tree = build_merkle_tree::<Sha256>(&orchard_nullifiers)?;
            info!(
                "Built orchard merkle tree with root: {}",
                orchard_tree.root_hex().unwrap_or_default()
            );

            // Find user notes logic
            // safe to unwrap because of the ensure! above
            let lightwalletd =
                LightWalletd::connect(config.source.lightwalletd_url.as_ref().unwrap()).await?;

            // Create viewing keys for nullifier derivation
            let viewing_keys = ViewingKeys {
                sapling: Some(SaplingViewingKeys::from_dfvk(&sapling_fvk)),
                orchard: Some(OrchardViewingKeys::from_fvk(&orchard_fvk)),
            };

            let mut stream = match config.network {
                Network::TestNetwork => Box::pin(lightwalletd.user_nullifiers::<TestNetwork>(
                    &TestNetwork,
                    *config.snapshot.start(),
                    *config.snapshot.end(),
                    &orchard_fvk,
                    &sapling_fvk,
                )),
                Network::MainNetwork => Box::pin(lightwalletd.user_nullifiers::<MainNetwork>(
                    &MainNetwork,
                    *config.snapshot.start(),
                    *config.snapshot.end(),
                    &orchard_fvk,
                    &sapling_fvk,
                )),
            };

            let mut found_notes = vec![];

            info!("Scanning blocks for user notes...");

            while let Some(found_note) = stream.next().await {
                let found_note = found_note?;

                // Derive nullifier for this note
                let nullifier = match found_note.nullifier(&viewing_keys) {
                    Some(nf) => nf,
                    None => {
                        debug!(
                            "Skipping note at height {}: no viewing key available to derive nullifier",
                            found_note.height()
                        );
                        continue;
                    }
                };

                info!(
                    "Found {:?} note at height {}: nullifier = {}, scope = {:?}",
                    found_note.pool(),
                    found_note.height(),
                    hex::encode(nullifier),
                    found_note.scope()
                );

                found_notes.push(found_note);
            }

            info!("Scan complete. Found {} notes.", found_notes.len(),);

            // Summary by pool
            let sapling_count = found_notes
                .iter()
                .filter(|n| n.pool() == Pool::Sapling)
                .count();
            let orchard_count = found_notes
                .iter()
                .filter(|n| n.pool() == Pool::Orchard)
                .count();

            info!("Summary: {sapling_count} Sapling notes, {orchard_count} Orchard notes");

            let output_file = "output.bin";
            let file = File::create(output_file).await?;
            let mut writer = BufWriter::new(file);
            let mut buf = Vec::with_capacity(1024 * 1024);

            for note in &found_notes {
                let nullifier = match note.nullifier(&viewing_keys) {
                    Some(nf) => nf,
                    None => continue,
                };

                info!(
                    "Generating non-membership proof for {:?} nullifier: {}",
                    note.pool(),
                    hex::encode(nullifier)
                );

                match note.pool() {
                    Pool::Sapling => {
                        debug!("Using Sapling viewing key to derive nullifier");
                        check_nullifier_membership(
                            note,
                            &sapling_nullifiers,
                            &sapling_tree,
                            &viewing_keys,
                            &mut writer,
                            &mut buf,
                        )
                        .await?;
                    }
                    Pool::Orchard => {
                        debug!("Using Orchard viewing key to derive nullifier");
                        check_nullifier_membership(
                            note,
                            &orchard_nullifiers,
                            &orchard_tree,
                            &viewing_keys,
                            &mut writer,
                            &mut buf,
                        )
                        .await?;
                    }
                }
            }

            Ok(())
        }
    }
}
