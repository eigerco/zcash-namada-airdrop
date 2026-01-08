//! Command-line interface for airdrop cli application

use std::ops::RangeInclusive;
use std::path::PathBuf;

use clap::Parser;
use eyre::{Result, ensure, eyre};
use zcash_protocol::consensus::Network;

#[derive(Debug, Parser)]
#[command(name = "airdrop")]
#[command(about = "Zcash airdrop tool for building snapshots and finding notes")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, clap::Subcommand)]
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
    #[command(verbatim_doc_comment)]
    AirdropClaim {
        #[command(flatten)]
        config: CommonArgs,
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
            env = "AIRDROP_CLAIMS_OUTPUT_FILE",
            default_value = "airdrop_claims.json"
        )]
        airdrop_claims_output_file: PathBuf,
        /// Airdrop configuration JSON file
        #[arg(long, env = "AIRDROP_CONFIGURATION_FILE")]
        airdrop_configuration_file: Option<PathBuf>,
    },
    /// Prints the schema of the airdrop configuration JSON file
    AirdropConfigurationSchema,
}

/// Common arguments for both commands
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

/// Source of nullifiers for building the snapshot
#[derive(Debug, Clone, clap::Args)]
pub struct SourceArgs {
    /// Lightwalletd gRPC endpoint URL
    #[arg(long, env = "LIGHTWALLETD_URL")]
    pub lightwalletd_url: Option<String>,

    /// File-based nullifier input (only available with `file-source` feature)
    #[cfg(feature = "file-source")]
    #[command(flatten)]
    pub input_files: Option<FileSourceArgs>,
}

/// File-based nullifier source arguments (for development/testing).
/// Only available when compiled with `--features file-source`.
#[cfg(feature = "file-source")]
#[derive(Debug, Clone, clap::Args)]
pub struct FileSourceArgs {
    /// Sapling nullifiers input file
    #[arg(long, env = "SAPLING_INPUT_FILE")]
    pub sapling_input: Option<String>,
    /// Orchard nullifiers input file
    #[arg(long, env = "ORCHARD_INPUT_FILE")]
    pub orchard_input: Option<String>,
}

/// Source of nullifiers for building the snapshot
#[derive(Debug, Clone)]
pub enum Source {
    /// Lightwalletd gRPC source
    Lightwalletd { url: String },
    #[cfg(feature = "file-source")]
    /// File-based source (for development/testing)
    File {
        orchard: Option<String>,
        sapling: Option<String>,
    },
}

impl TryFrom<SourceArgs> for Source {
    type Error = eyre::Report;

    #[cfg(feature = "file-source")]
    fn try_from(args: SourceArgs) -> Result<Self, Self::Error> {
        match (args.lightwalletd_url, args.input_files) {
            (Some(url), None) => Ok(Self::Lightwalletd { url }),
            (None, Some(files)) => Ok(Self::File {
                orchard: files.orchard_input,
                sapling: files.sapling_input,
            }),
            (None, None) => Err(eyre!(
                "No source specified. Provide --lightwalletd-url OR input files (--sapling-input/--orchard-input with file-source feature)."
            )),
            (Some(_), Some(_)) => Err(eyre!(
                "Cannot specify both --lightwalletd-url and input files. Choose one source."
            )),
        }
    }

    #[cfg(not(feature = "file-source"))]
    fn try_from(args: SourceArgs) -> Result<Self, Self::Error> {
        args.lightwalletd_url
            .map(|url| Self::Lightwalletd { url })
            .ok_or_else(|| eyre!("No source specified. Provide --lightwalletd-url."))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_parse_range() {
        let range = parse_range("1000000..=1100000");
        let expected = 1_000_000_u64..=1_100_000_u64;
        assert!(matches!(range, Ok(r) if r == expected));
    }

    #[test]
    fn parse_range_invalid_cases() {
        let result = parse_range("100-200");
        assert!(matches!(result, Err(err) if err.to_string().contains("Invalid range format")));

        let result = parse_range("abc..=200");
        assert!(
            matches!(result, Err(err) if err.to_string().contains("invalid digit found in string"))
        );

        let result = parse_range("200..=100");
        assert!(
            matches!(result, Err(err) if err.to_string().contains("Range start must be less than or equal to end"))
        );
    }

    #[test]
    fn network_parse() {
        let network = parse_network("mainnet");
        assert!(matches!(network, Ok(Network::MainNetwork)));

        let network = parse_network("testnet");
        assert!(matches!(network, Ok(Network::TestNetwork)));
    }

    #[test]
    fn network_parse_invalid() {
        let result = parse_network("devnet");
        assert!(matches!(result, Err(err) if err.to_string().contains("Invalid network")));
    }

    #[test]
    fn source_from_lightwalletd() {
        let args = SourceArgs {
            lightwalletd_url: Some("http://localhost:9067".to_string()),
            #[cfg(feature = "file-source")]
            input_files: None,
        };

        let source = args.try_into();
        assert!(
            matches!(source, Ok(Source::Lightwalletd { url }) if url == "http://localhost:9067")
        );
    }

    #[test]
    fn source_no_source_specified() {
        let args = SourceArgs {
            lightwalletd_url: None,
            #[cfg(feature = "file-source")]
            input_files: None,
        };

        let result: Result<Source, _> = args.try_into();
        assert!(matches!(result, Err(err) if err.to_string().contains("No source specified")));
    }

    #[cfg(feature = "file-source")]
    #[test]
    fn source_from_files() {
        let args = SourceArgs {
            lightwalletd_url: None,
            input_files: Some(FileSourceArgs {
                sapling_input: Some("sapling.bin".to_string()),
                orchard_input: Some("orchard.bin".to_string()),
            }),
        };

        let source = args.try_into();
        assert!(matches!(source, Ok(Source::File { .. })));
    }

    #[cfg(feature = "file-source")]
    #[test]
    fn source_both_specified_error() {
        let args = SourceArgs {
            lightwalletd_url: Some("http://localhost:9067".to_string()),
            input_files: Some(FileSourceArgs {
                sapling_input: Some("sapling.bin".to_string()),
                orchard_input: None,
            }),
        };

        let result: Result<Source, _> = args.try_into();
        assert!(matches!(result, Err(err) if err.to_string().contains("Cannot specify both")));
    }
}
