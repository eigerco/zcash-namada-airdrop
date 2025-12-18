//! Command-line interface for airdrop cli application

use std::ops::RangeInclusive;
use std::path::PathBuf;

use clap::Parser;
use eyre::{Context as _, Result, ensure, eyre};
use orchard::keys::FullViewingKey as OrchardFvk;
use sapling::zip32::DiversifiableFullViewingKey;
use zcash_protocol::consensus::Network;

#[derive(Debug, Parser)]
#[command(name = "airdrop")]
#[command(about = "Zcash airdrop tool for building snapshots and finding notes")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, clap::Subcommand)]
#[allow(
    clippy::large_enum_variant,
    reason = "CLI commands are only parsed once"
)]
pub enum Commands {
    /// Build a snapshot of nullifiers from a source
    BuildAirdropConfiguration {
        #[command(flatten)]
        config: CommonArgs,
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
    },
    /// Prepare the airdrop claim.
    ///
    /// 1. Build the nullifiers non-membership proof Merkle trees from the snapshot nullifiers.
    /// 2. Scan the chain for notes belonging to the provided viewing keys.
    /// 3. Output the non-membership proofs
    AirdropClaim {
        #[command(flatten)]
        config: CommonArgs,
        /// Sapling snapshot nullifiers. This file contains the sapling nullifiers of the snapshot.
        /// It's used to recreate the Merkle tree of the snapshot for sapling notes.
        #[arg(
            long,
            env = "SAPLING_SNAPSHOT_NULLIFIERS",
            default_value = "sapling-snapshot-nullifiers.bin"
        )]
        sapling_snapshot_nullifiers: Option<PathBuf>,
        /// Orchard snapshot nullifiers. This file contains the orchard nullifiers of the snapshot.
        /// It's used to recreate the Merkle tree of the snapshot for orchard notes.
        #[arg(
            long,
            env = "ORCHARD_SNAPSHOT_NULLIFIERS",
            default_value = "orchard-snapshot-nullifiers.bin"
        )]
        orchard_snapshot_nullifiers: Option<PathBuf>,

        /// Orchard Full Viewing Key (hex-encoded, 96 bytes)
        #[arg(short = 'o', long, env = "ORCHARD_FVK", value_parser = parse_orchard_fvk)]
        orchard_fvk: OrchardFvk,

        /// Sapling Diversifiable Full Viewing Key (hex-encoded, 128 bytes)
        #[arg(short = 's', long, env = "DIVERSIFIABLE_FULL_VIEWING_KEY", value_parser = parse_sapling_diversifiable_fvk)]
        sapling_fvk: DiversifiableFullViewingKey,

        /// Birthday height for the provided viewing keys
        #[arg(long, env = "BIRTHDAY_HEIGHT", default_value_t = 419_200)]
        birthday_height: u64,

        /// Export the valid airdrop claims to this JSON file
        #[arg(
            long,
            env = "AIRDROP_CLAIMS_OUTPUT_FILE",
            default_value = "airdrop_claims.json"
        )]
        airdrop_claims_output_file: PathBuf,
    },
}

#[derive(Debug, clap::Args)]
pub struct CommonArgs {
    /// Network to use (mainnet or testnet)
    #[arg(long, env = "NETWORK", default_value = "mainnet", value_parser = parse_network)]
    pub network: Network,

    /// Block range for the snapshot (e.g., 1000000..=1100000). Range is inclusive.
    #[arg(long, env = "SNAPSHOT", value_parser = parse_range)]
    pub snapshot: RangeInclusive<u64>,

    #[command(flatten)]
    pub source: SourceArgs,
}

#[derive(Debug, Clone, clap::Args)]
pub struct SourceArgs {
    /// Lightwalletd gRPC endpoint URL
    #[arg(long, env = "LIGHTWALLETD_URL")]
    pub lightwalletd_url: Option<String>,

    /// Input files in format
    #[command(flatten)]
    pub input_files: Option<FileSourceArgs>,
}

#[derive(Debug, Clone, clap::Args)]
pub struct FileSourceArgs {
    #[arg(long, env = "SAPLING_FILE")]
    pub sapling: Option<String>,
    #[arg(long, env = "ORCHARD_FILE")]
    pub orchard: Option<String>,
}

#[derive(Debug, Clone)]
pub enum Source {
    Lightwalletd {
        url: String,
    },
    File {
        orchard: Option<String>,
        sapling: Option<String>,
    },
}

impl TryFrom<SourceArgs> for Source {
    type Error = eyre::Report;

    fn try_from(args: SourceArgs) -> Result<Self, Self::Error> {
        match (args.lightwalletd_url, args.input_files) {
            (Some(url), None) => Ok(Self::Lightwalletd { url }),
            (None, Some(files)) => Ok(Self::File {
                orchard: files.orchard,
                sapling: files.sapling,
            }),
            (None, None) => Err(eyre!(
                "No source specified. Provide --lightwalletd-url OR --input-files sapling,orchard"
            )),
            (Some(_), Some(_)) => Err(eyre!(
                "Cannot specify both --lightwalletd-url and --input-files. Nullifiers must come from a single source."
            )),
        }
    }
}

fn parse_range(s: &str) -> Result<RangeInclusive<u64>> {
    let (start, end) = s
        .split_once("..=")
        .ok_or_else(|| eyre!("Invalid range format. Use START..=END"))?;

    let start = start.parse::<u64>()?;
    let end = end.parse::<u64>()?;

    ensure!(
        start <= end,
        "Range start must be less than or equal to end"
    );

    Ok(start..=end)
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

/// Parse hex-encoded Orchard Full Viewing Key
fn parse_orchard_fvk(hex: &str) -> Result<OrchardFvk> {
    let bytes = hex::decode(hex).wrap_err("Failed to decode Orchard FVK from hex string")?;

    let bytes: [u8; 96] = bytes.try_into().map_err(|v: Vec<u8>| {
        eyre!(
            "Invalid Orchard FVK length: expected 96 bytes, got {} bytes",
            v.len()
        )
    })?;

    OrchardFvk::from_bytes(&bytes)
        .ok_or_else(|| eyre!("Invalid Orchard FVK: failed to parse 96-byte representation"))
}

/// Parse hex-encoded Sapling Diversifiable Full Viewing Key
fn parse_sapling_diversifiable_fvk(hex: &str) -> Result<DiversifiableFullViewingKey> {
    let bytes =
        hex::decode(hex).wrap_err("Failed to decode Sapling Diversifiable FVK from hex string")?;

    let bytes: &[u8; 128] = bytes.as_slice().try_into().wrap_err(format!(
        "Slice conversion error, bytes len: {}",
        bytes.len()
    ))?;

    DiversifiableFullViewingKey::from_bytes(bytes)
        .ok_or_else(|| eyre!("Invalid Sapling FVK: failed to parse 128-byte representation"))
}
