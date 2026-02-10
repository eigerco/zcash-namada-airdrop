//! Command-line interface for the `zair` CLI application.

use std::path::PathBuf;

use clap::Parser;
use eyre::{Result, ensure, eyre};
use zair_sdk::common::{CommonConfig, PoolSelection};
use zcash_protocol::consensus::Network;

/// Command-line interface definition
#[derive(Debug, Parser)]
#[command(name = "zair")]
#[command(about = "Zcash airdrop tools")]
pub struct Cli {
    /// Cli subcommands
    #[command(subcommand)]
    pub command: Commands,
}

/// Cli subcommands
#[derive(Debug, clap::Subcommand)]
pub enum Commands {
    /// Build a snapshot of nullifiers from a source
    BuildConfig {
        /// Build-config specific arguments.
        #[command(flatten)]
        config: BuildConfigArgs,
        /// Pool to include in the exported configuration.
        #[arg(long, env = "POOL", default_value = "both", value_parser = parse_pool_selection)]
        pool: PoolSelection,
        /// Configuration output file
        #[arg(
            long,
            env = "CONFIGURATION_OUTPUT_FILE",
            default_value = "airdrop_configuration.json"
        )]
        configuration_output_file: PathBuf,
        /// Sapling snapshot nullifiers. This file stores the sapling nullifiers of the snapshot.
        #[arg(
            long,
            env = "SAPLING_SNAPSHOT_NULLIFIERS",
            default_value = "sapling-snapshot-nullifiers.bin"
        )]
        sapling_snapshot_nullifiers: PathBuf,
        /// Orchard snapshot nullifiers. This file stores the orchard nullifiers of the snapshot.
        #[arg(
            long,
            env = "ORCHARD_SNAPSHOT_NULLIFIERS",
            default_value = "orchard-snapshot-nullifiers.bin"
        )]
        orchard_snapshot_nullifiers: PathBuf,
        /// Sapling `target_id` used for airdrop nullifier derivation. Must be exactly 8 bytes.
        #[arg(
            long,
            env = "SAPLING_TARGET_ID",
            default_value = "ZAIRTEST",
            value_parser = parse_sapling_target_id
        )]
        sapling_target_id: String,
        /// Orchard `target_id` used for airdrop nullifier derivation. Must be <= 32 bytes.
        #[arg(
            long,
            env = "ORCHARD_TARGET_ID",
            default_value = "ZAIRTEST:Orchard",
            value_parser = parse_orchard_target_id
        )]
        orchard_target_id: String,
    },
    /// Prepare the airdrop claim.
    ///
    /// 1. Build the nullifiers non-membership proof Merkle trees from the snapshot nullifiers.
    /// 2. Scan the chain for notes belonging to the provided viewing keys.
    /// 3. Output the non-membership proofs.
    #[command(verbatim_doc_comment)]
    ClaimPrepare {
        /// Optional lightwalletd gRPC endpoint URL override.
        #[arg(long, env = "LIGHTWALLETD_URL")]
        lightwalletd_url: Option<String>,

        /// Sapling snapshot nullifiers. This file contains the sapling nullifiers of the snapshot.
        /// It's used to recreate the Merkle tree of the snapshot for sapling notes.
        #[arg(long, env = "SAPLING_SNAPSHOT_NULLIFIERS")]
        sapling_snapshot_nullifiers: Option<PathBuf>,
        /// Orchard snapshot nullifiers. This file contains the orchard nullifiers of the snapshot.
        /// It's used to recreate the Merkle tree of the snapshot for orchard notes.
        #[arg(long, env = "ORCHARD_SNAPSHOT_NULLIFIERS")]
        orchard_snapshot_nullifiers: Option<PathBuf>,

        /// Unified Full Viewing Key to scan for notes
        #[arg(long)]
        unified_full_viewing_key: String,

        /// Birthday height for the provided viewing keys
        #[arg(long, env = "BIRTHDAY_HEIGHT", default_value_t = 419_200)]
        birthday_height: u64,

        /// Export the valid airdrop claims to this JSON file
        #[arg(
            long,
            env = "AIRDROP_CLAIMS_FILE",
            default_value = "airdrop_claims.json"
        )]
        airdrop_claims_output_file: PathBuf,
        /// Airdrop configuration JSON file
        #[arg(
            long,
            env = "AIRDROP_CONFIGURATION_FILE",
            default_value = "airdrop_configuration.json"
        )]
        airdrop_configuration_file: PathBuf,
    },
    /// Prints the schema of the airdrop configuration JSON file
    ConfigSchema,
    /// Generate claim proofs using custom claim circuit
    #[cfg(feature = "prove")]
    Prove {
        /// Input file containing claim inputs (from `claim-prepare` command)
        #[arg(long, env = "AIRDROP_CLAIMS_FILE")]
        claim_inputs_file: PathBuf,

        /// Output file for generated claim proofs
        #[arg(
            long,
            env = "CLAIM_PROOFS_FILE",
            default_value = "airdrop_claim_proofs.json"
        )]
        proofs_output_file: PathBuf,

        /// Path to file containing 64-byte seed as hex for deriving spending keys
        #[arg(long, env = "SEED_FILE")]
        seed_file: PathBuf,

        /// Network to use (mainnet or testnet)
        #[arg(long, env = "NETWORK", default_value = "mainnet", value_parser = parse_network)]
        network: Network,

        /// Path to proving key file (will be generated if not exists)
        #[arg(
            long,
            env = "PROVING_KEY_FILE",
            default_value = "claim_proving_key.params"
        )]
        proving_key_file: PathBuf,
    },
    /// Generate claim circuit parameters (proving and verifying keys)
    #[cfg(feature = "prove")]
    SetupLocal {
        /// Output file for proving key
        #[arg(
            long,
            env = "PROVING_KEY_FILE",
            default_value = "claim_proving_key.params"
        )]
        proving_key_file: PathBuf,

        /// Output file for verifying key
        #[arg(
            long,
            env = "VERIFYING_KEY_FILE",
            default_value = "claim_verifying_key.params"
        )]
        verifying_key_file: PathBuf,
    },
    /// Verify claim proofs from a proofs file (output of `prove`)
    Verify {
        /// JSON file containing claim proofs (from `prove` command)
        #[arg(long, env = "CLAIM_PROOFS_FILE")]
        proofs_file: PathBuf,

        /// Path to the verifying key file
        #[arg(
            long,
            env = "VERIFYING_KEY_FILE",
            default_value = "claim_verifying_key.params"
        )]
        verifying_key_file: PathBuf,
    },
}

/// Common arguments for build-config.
#[derive(Debug, clap::Args)]
pub struct BuildConfigArgs {
    /// Network to use (mainnet or testnet)
    #[arg(long, env = "NETWORK", default_value = "mainnet", value_parser = parse_network)]
    pub network: Network,

    /// Snapshot block height (inclusive).
    #[arg(long, env = "SNAPSHOT_HEIGHT")]
    pub snapshot_height: u64,

    /// Optional lightwalletd gRPC endpoint URL override.
    #[arg(long, env = "LIGHTWALLETD_URL")]
    pub lightwalletd_url: Option<String>,
}

impl From<BuildConfigArgs> for CommonConfig {
    fn from(args: BuildConfigArgs) -> Self {
        Self {
            network: args.network,
            snapshot_height: args.snapshot_height,
            lightwalletd_url: args.lightwalletd_url,
        }
    }
}

fn parse_network(s: &str) -> Result<Network> {
    match s {
        "mainnet" => Ok(Network::MainNetwork),
        "testnet" => Ok(Network::TestNetwork),
        other => Err(eyre!(
            "Invalid network: {other}. Expected 'mainnet' or 'testnet'."
        )),
    }
}

fn parse_pool_selection(s: &str) -> Result<PoolSelection> {
    match s {
        "sapling" => Ok(PoolSelection::Sapling),
        "orchard" => Ok(PoolSelection::Orchard),
        "both" => Ok(PoolSelection::Both),
        other => Err(eyre!(
            "Invalid pool: {other}. Expected 'sapling', 'orchard', or 'both'."
        )),
    }
}

fn parse_sapling_target_id(s: &str) -> Result<String> {
    ensure!(s.len() == 8, "Sapling target_id must be exactly 8 bytes");
    Ok(s.to_string())
}

fn parse_orchard_target_id(s: &str) -> Result<String> {
    ensure!(s.len() <= 32, "Orchard target_id must be at most 32 bytes");
    Ok(s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_parse() {
        let network = parse_network("mainnet").expect("Failed to parse mainnet");
        assert_eq!(network, Network::MainNetwork);

        let network = parse_network("testnet").expect("Failed to parse testnet");
        assert_eq!(network, Network::TestNetwork);

        let network = parse_network("invalid_network");
        assert!(network.is_err());
    }

    #[test]
    fn pool_selection_parse() {
        assert!(matches!(
            parse_pool_selection("sapling").expect("sapling should parse"),
            PoolSelection::Sapling
        ));
        assert!(matches!(
            parse_pool_selection("orchard").expect("orchard should parse"),
            PoolSelection::Orchard
        ));
        assert!(matches!(
            parse_pool_selection("both").expect("both should parse"),
            PoolSelection::Both
        ));
        assert!(parse_pool_selection("nope").is_err());
    }

    #[test]
    fn target_id_validation() {
        assert!(parse_sapling_target_id("ZAIRTEST").is_ok());
        assert!(parse_sapling_target_id("short").is_err());

        assert!(parse_orchard_target_id("ZAIRTEST:Orchard").is_ok());
        assert!(parse_orchard_target_id(&"x".repeat(33)).is_err());
    }
}
