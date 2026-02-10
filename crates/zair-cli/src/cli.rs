//! Command-line interface for the `zair` CLI application.

use std::ops::RangeInclusive;
use std::path::PathBuf;
use std::str::FromStr;

use clap::Parser;
use eyre::{Result, ensure, eyre};
use zair_core::schema::config::{HidingFactor, OrchardHidingFactor, SaplingHidingFactor};
use zair_sdk::common::CommonConfig;
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
        /// Common configuration arguments
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
        /// Hiding factor arguments for nullifier derivation
        #[command(flatten)]
        hiding_factor: HidingFactorArgs,
    },
    /// Prepare the airdrop claim.
    ///
    /// 1. Build the nullifiers non-membership proof Merkle trees from the snapshot nullifiers.
    /// 2. Scan the chain for notes belonging to the provided viewing keys.
    /// 3. Output the non-membership proofs.
    #[command(verbatim_doc_comment)]
    ClaimPrepare {
        /// Common configuration arguments
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

/// Common arguments for both commands
#[derive(Debug, clap::Args)]
pub struct CommonArgs {
    /// Network to use (mainnet or testnet)
    #[arg(long, env = "NETWORK", default_value = "mainnet", value_parser = parse_network)]
    pub network: Network,

    /// Block range for the snapshot (e.g., 1000000..=1100000). Range is inclusive.
    #[arg(long, env = "SNAPSHOT", value_parser = parse_range)]
    pub snapshot: RangeInclusive<u64>,

    /// Lightwalletd gRPC endpoint URL
    #[arg(long, env = "LIGHTWALLETD_URL")]
    pub lightwalletd_url: String,
}

impl From<CommonArgs> for CommonConfig {
    fn from(args: CommonArgs) -> Self {
        Self {
            network: args.network,
            snapshot: args.snapshot,
            lightwalletd_url: args.lightwalletd_url,
        }
    }
}

/// Arguments for hiding nullifier derivation
#[derive(Debug, Clone, clap::Args)]
pub struct HidingFactorArgs {
    /// Sapling personalization bytes for hiding nullifier
    #[arg(
        long,
        env = "SAPLING_PERSONALIZATION",
        default_value = "MASP_alt",
        value_parser = parse_sapling_personalization
    )]
    sapling_personalization: Bytes,

    /// Orchard domain separator for hiding nullifier
    #[arg(long, env = "ORCHARD_HIDING_DOMAIN", default_value = "MASP:Airdrop")]
    orchard_hiding_domain: String,

    /// Orchard tag bytes for hiding nullifier
    #[arg(long, env = "ORCHARD_HIDING_TAG", default_value = "K")]
    orchard_hiding_tag: Bytes,
}

impl TryFrom<HidingFactorArgs> for HidingFactor {
    type Error = eyre::ErrReport;

    fn try_from(args: HidingFactorArgs) -> Result<Self, Self::Error> {
        Ok(Self {
            sapling: SaplingHidingFactor {
                personalization: String::from_utf8(args.sapling_personalization.0)?,
            },
            orchard: OrchardHidingFactor {
                domain: args.orchard_hiding_domain.clone(),
                tag: String::from_utf8(args.orchard_hiding_tag.0)?,
            },
        })
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

/// Newtype wrapper for byte arrays parsed from CLI strings.
/// Clap interprets `Vec<u8>` as multiple u8 values, so we need this wrapper.
#[derive(Debug, Clone)]
struct Bytes(pub Vec<u8>);

impl FromStr for Bytes {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(Self(s.as_bytes().to_vec()))
    }
}

fn parse_sapling_personalization(s: &str) -> Result<Bytes> {
    let bytes = Bytes(s.as_bytes().to_vec());
    ensure!(
        bytes.0.len() <= 8,
        "Sapling personalization must be upto 8 bytes"
    );

    Ok(bytes)
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

        let result = parse_range("100..=abc");
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
        let network = parse_network("mainnet").expect("Failed to parse mainnet");
        assert_eq!(network, Network::MainNetwork);

        let network = parse_network("testnet").expect("Failed to parse testnet");
        assert_eq!(network, Network::TestNetwork);
    }

    #[test]
    fn network_parse_invalid() {
        let result = parse_network("devnet");
        assert!(matches!(result, Err(err) if err.to_string().contains("Invalid network")));
    }

    #[test]
    fn str_to_bytes() {
        let input = "MASP_alt";
        let bytes: Bytes = input.parse().unwrap();
        assert_eq!(bytes.0, b"MASP_alt".to_vec());
    }

    // HidingFactorArgs
    #[test]
    fn hiding_factor_args_to_hiding_factor() {
        let args = HidingFactorArgs {
            sapling_personalization: Bytes(b"MASP_alt".to_vec()),
            orchard_hiding_domain: "MASP:Airdrop".to_string(),
            orchard_hiding_tag: Bytes(b"K".to_vec()),
        };

        let hiding_factor: HidingFactor =
            args.try_into().expect("Failed to convert to HidingFactor");
        assert_eq!(
            hiding_factor.sapling.personalization,
            String::from_str("MASP_alt").expect("Failed to convert to string")
        );
        assert_eq!(hiding_factor.orchard.domain, "MASP:Airdrop".to_string());
        assert_eq!(
            hiding_factor.orchard.tag,
            String::from_str("K").expect("Failed to convert to string")
        );
    }

    #[test]
    fn validate_parse_sapling_personalization() {
        let res = parse_sapling_personalization("sapling")
            .expect("Failed to parse sapling personalization");
        assert_eq!(res.0, b"sapling".to_vec());

        let res = parse_sapling_personalization("sapling_sapling");
        assert!(res.is_err());
    }
}
