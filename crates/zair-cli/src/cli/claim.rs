//! Claim subcommands.

use std::path::PathBuf;

/// Arguments for the end-to-end claim pipeline.
#[cfg(feature = "prove")]
#[derive(Debug, clap::Args)]
pub struct ClaimRunArgs {
    /// Airdrop configuration file.
    #[arg(
        long,
        env = "CONFIG_FILE",
        value_name = "CONFIG_FILE",
        default_value = "config.json"
    )]
    pub config: PathBuf,
    /// Path to file containing 64-byte seed as hex.
    #[arg(long, env = "SEED_FILE", value_name = "SEED_FILE")]
    pub seed: PathBuf,
    /// Message payload file to bind into submission signatures.
    #[arg(
        long,
        env = "MESSAGE_FILE",
        value_name = "MESSAGE_FILE",
        default_value = "claim-message.bin"
    )]
    pub msg: PathBuf,
    /// Sapling snapshot nullifiers file.
    /// Defaults to `snapshot-sapling.bin` when Sapling is enabled in config.
    #[arg(long, env = "SNAPSHOT_SAPLING_FILE")]
    pub snapshot_sapling: Option<PathBuf>,
    /// Orchard snapshot nullifiers file.
    /// Defaults to `snapshot-orchard.bin` when Orchard is enabled in config.
    #[arg(long, env = "SNAPSHOT_ORCHARD_FILE")]
    pub snapshot_orchard: Option<PathBuf>,
    /// Path to proving key file.
    #[arg(
        long,
        env = "PROVING_KEY_FILE",
        value_name = "PROVING_KEY_FILE",
        default_value = "setup-sapling-pk.params"
    )]
    pub pk: PathBuf,
    /// ZIP-32 account index used to derive Sapling keys from the seed.
    #[arg(long, env = "ACCOUNT_ID", default_value_t = 0_u32)]
    pub account: u32,
    /// Scan start height for note discovery.
    #[arg(long, env = "BIRTHDAY")]
    pub birthday: u64,
    /// Optional lightwalletd gRPC endpoint URL override.
    #[arg(long, env = "LIGHTWALLETD_URL")]
    pub lightwalletd: Option<String>,
    /// Output file for prepared claims JSON.
    #[arg(long, env = "CLAIMS_OUT", default_value = "claim-prepared.json")]
    pub claims_out: PathBuf,
    /// Output file for generated proofs.
    #[arg(long, env = "PROOFS_OUT", default_value = "claim-proofs.json")]
    pub proofs_out: PathBuf,
    /// Output file for local-only claim secrets.
    #[arg(long, env = "SECRETS_OUT", default_value = "claim-proofs-secrets.json")]
    pub secrets_out: PathBuf,
    /// Output file for signed claim submission bundle.
    #[arg(long, env = "SUBMISSION_OUT", default_value = "claim-submission.json")]
    pub submission_out: PathBuf,
}

/// Arguments for claim preparation.
#[derive(Debug, clap::Args)]
pub struct ClaimPrepareArgs {
    /// Airdrop configuration file.
    #[arg(
        long,
        env = "CONFIG_FILE",
        value_name = "CONFIG_FILE",
        default_value = "config.json"
    )]
    pub config: PathBuf,
    /// Unified Full Viewing Key to scan for notes.
    #[arg(long, env = "UFVK")]
    pub ufvk: String,
    /// Sapling snapshot nullifiers file.
    /// Defaults to `snapshot-sapling.bin` when Sapling is enabled in config.
    #[arg(long, env = "SNAPSHOT_SAPLING_FILE")]
    pub snapshot_sapling: Option<PathBuf>,
    /// Orchard snapshot nullifiers file.
    /// Defaults to `snapshot-orchard.bin` when Orchard is enabled in config.
    #[arg(long, env = "SNAPSHOT_ORCHARD_FILE")]
    pub snapshot_orchard: Option<PathBuf>,
    /// Scan start height for note discovery.
    #[arg(long, env = "BIRTHDAY")]
    pub birthday: u64,
    /// Optional lightwalletd gRPC endpoint URL override.
    #[arg(long, env = "LIGHTWALLETD_URL")]
    pub lightwalletd: Option<String>,
    /// Output file for prepared claims JSON.
    #[arg(long, env = "CLAIMS_OUT", default_value = "claim-prepared.json")]
    pub claims_out: PathBuf,
}

/// Arguments for claim proof generation.
#[cfg(feature = "prove")]
#[derive(Debug, clap::Args)]
pub struct ClaimProveArgs {
    /// Airdrop configuration file.
    #[arg(
        long,
        env = "CONFIG_FILE",
        value_name = "CONFIG_FILE",
        default_value = "config.json"
    )]
    pub config: PathBuf,
    /// Input file containing claim inputs.
    #[arg(long, env = "CLAIMS_IN", default_value = "claim-prepared.json")]
    pub claims_in: PathBuf,
    /// Path to file containing 64-byte seed as hex for deriving spending keys.
    #[arg(long, env = "SEED_FILE", value_name = "SEED_FILE")]
    pub seed: PathBuf,
    /// Path to proving key file.
    #[arg(
        long,
        env = "PROVING_KEY_FILE",
        value_name = "PROVING_KEY_FILE",
        default_value = "setup-sapling-pk.params"
    )]
    pub pk: PathBuf,
    /// ZIP-32 account index used to derive Sapling keys from the seed.
    #[arg(long, env = "ACCOUNT_ID", default_value_t = 0_u32)]
    pub account: u32,
    /// Output file for generated claim proofs.
    #[arg(long, env = "PROOFS_OUT", default_value = "claim-proofs.json")]
    pub proofs_out: PathBuf,
    /// Output file for local-only claim secrets.
    #[arg(long, env = "SECRETS_OUT", default_value = "claim-proofs-secrets.json")]
    pub secrets_out: PathBuf,
}

/// Arguments for claim signing.
#[derive(Debug, clap::Args)]
pub struct ClaimSignArgs {
    /// Airdrop configuration file.
    #[arg(
        long,
        env = "CONFIG_FILE",
        value_name = "CONFIG_FILE",
        default_value = "config.json"
    )]
    pub config: PathBuf,
    /// Proofs file generated by `claim prove`.
    #[arg(long, env = "PROOFS_IN", default_value = "claim-proofs.json")]
    pub proofs_in: PathBuf,
    /// Local-only secrets file generated by `claim prove`.
    #[arg(long, env = "SECRETS_IN", default_value = "claim-proofs-secrets.json")]
    pub secrets_in: PathBuf,
    /// Path to file containing 64-byte seed as hex for deriving spending keys.
    #[arg(long, env = "SEED_FILE", value_name = "SEED_FILE")]
    pub seed: PathBuf,
    /// Message payload file to bind into submission signatures.
    #[arg(
        long,
        env = "MESSAGE_FILE",
        value_name = "MESSAGE_FILE",
        default_value = "claim-message.bin"
    )]
    pub msg: PathBuf,
    /// ZIP-32 account index used to derive Sapling keys from the seed.
    #[arg(long, env = "ACCOUNT_ID", default_value_t = 0_u32)]
    pub account: u32,
    /// Output file for signed submission bundle.
    #[arg(long, env = "SUBMISSION_OUT", default_value = "claim-submission.json")]
    pub submission_out: PathBuf,
}

/// Claim command group.
#[derive(Debug, clap::Subcommand)]
pub enum ClaimCommands {
    /// Recommended end-to-end claim pipeline:
    /// `prepare -> prove -> sign`.
    #[cfg(feature = "prove")]
    Run {
        #[command(flatten)]
        args: ClaimRunArgs,
    },
    /// Prepare the airdrop claim.
    #[command(verbatim_doc_comment)]
    Prepare {
        #[command(flatten)]
        args: ClaimPrepareArgs,
    },
    /// Generate claim proofs using custom claim circuit.
    #[cfg(feature = "prove")]
    Prove {
        #[command(flatten)]
        args: ClaimProveArgs,
    },
    /// Sign a Sapling proof bundle into a submission package.
    Sign {
        #[command(flatten)]
        args: ClaimSignArgs,
    },
}
