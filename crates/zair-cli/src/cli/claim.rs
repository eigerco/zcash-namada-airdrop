//! Claim subcommands.

use std::path::PathBuf;

use zair_sdk::commands::{GapTreeMode, OrchardParamsMode};

use super::{parse_gap_tree_mode, parse_orchard_params_mode};

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
    /// Shared message payload file fallback used for claim signatures.
    #[arg(long = "message", env = "MESSAGE_FILE", value_name = "MESSAGE_FILE")]
    pub message: Option<PathBuf>,
    /// Per-claim message assignments JSON.
    #[arg(long = "messages", env = "MESSAGES_FILE", value_name = "MESSAGES_FILE")]
    pub messages: Option<PathBuf>,
    /// Sapling snapshot nullifiers file.
    /// Defaults to `snapshot-sapling.bin` when Sapling is enabled in config.
    #[arg(long, env = "SNAPSHOT_SAPLING_FILE")]
    pub snapshot_sapling: Option<PathBuf>,
    /// Orchard snapshot nullifiers file.
    /// Defaults to `snapshot-orchard.bin` when Orchard is enabled in config.
    #[arg(long, env = "SNAPSHOT_ORCHARD_FILE")]
    pub snapshot_orchard: Option<PathBuf>,
    /// Sapling gap-tree file. Defaults to `gaptree-sapling.bin` when Sapling is enabled.
    #[arg(long, env = "GAP_TREE_SAPLING_FILE", visible_alias = "gaptree-sapling")]
    pub gap_tree_sapling: Option<PathBuf>,
    /// Orchard gap-tree file. Defaults to `gaptree-orchard.bin` when Orchard is enabled.
    #[arg(long, env = "GAP_TREE_ORCHARD_FILE", visible_alias = "gaptree-orchard")]
    pub gap_tree_orchard: Option<PathBuf>,
    /// Gap-tree mode: `none` (require files), `rebuild` (recompute and persist), `sparse`
    /// (in-memory only).
    #[arg(
        long,
        env = "GAP_TREE_MODE",
        default_value = "none",
        value_parser = parse_gap_tree_mode
    )]
    pub gap_tree_mode: GapTreeMode,
    /// Path to Sapling proving key file.
    #[arg(
        long = "sapling-pk",
        env = "SAPLING_PK_FILE",
        value_name = "SAPLING_PK_FILE",
        default_value = "setup-sapling-pk.params"
    )]
    pub sapling_pk: PathBuf,
    /// Path to the Orchard Halo2 params file.
    #[arg(
        long,
        env = "ORCHARD_PARAMS_FILE",
        value_name = "ORCHARD_PARAMS_FILE",
        default_value = "setup-orchard-params.bin"
    )]
    pub orchard_params: PathBuf,
    /// Orchard params handling mode: `require` (fail if missing) or `auto` (generate and persist).
    #[arg(
        long,
        env = "ORCHARD_PARAMS_MODE",
        default_value = "auto",
        value_parser = parse_orchard_params_mode
    )]
    pub orchard_params_mode: OrchardParamsMode,
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
    /// File containing the Unified Full Viewing Key (bech32).
    #[arg(long, env = "UFVK_FILE", default_value = "ufvk.txt")]
    pub ufvk: PathBuf,
    /// Sapling snapshot nullifiers file.
    /// Defaults to `snapshot-sapling.bin` when Sapling is enabled in config.
    #[arg(long, env = "SNAPSHOT_SAPLING_FILE")]
    pub snapshot_sapling: Option<PathBuf>,
    /// Orchard snapshot nullifiers file.
    /// Defaults to `snapshot-orchard.bin` when Orchard is enabled in config.
    #[arg(long, env = "SNAPSHOT_ORCHARD_FILE")]
    pub snapshot_orchard: Option<PathBuf>,
    /// Sapling gap-tree file. Defaults to `gaptree-sapling.bin` when Sapling is enabled.
    #[arg(long, env = "GAP_TREE_SAPLING_FILE", visible_alias = "gaptree-sapling")]
    pub gap_tree_sapling: Option<PathBuf>,
    /// Orchard gap-tree file. Defaults to `gaptree-orchard.bin` when Orchard is enabled.
    #[arg(long, env = "GAP_TREE_ORCHARD_FILE", visible_alias = "gaptree-orchard")]
    pub gap_tree_orchard: Option<PathBuf>,
    /// Gap-tree mode: `none` (require files), `rebuild` (recompute and persist), `sparse`
    /// (in-memory only).
    #[arg(
        long,
        env = "GAP_TREE_MODE",
        default_value = "none",
        value_parser = parse_gap_tree_mode
    )]
    pub gap_tree_mode: GapTreeMode,
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
    /// Path to Sapling proving key file.
    #[arg(
        long = "sapling-pk",
        env = "SAPLING_PK_FILE",
        value_name = "SAPLING_PK_FILE",
        default_value = "setup-sapling-pk.params"
    )]
    pub sapling_pk: PathBuf,
    /// Path to the Orchard Halo2 params file.
    #[arg(
        long,
        env = "ORCHARD_PARAMS_FILE",
        value_name = "ORCHARD_PARAMS_FILE",
        default_value = "setup-orchard-params.bin"
    )]
    pub orchard_params: PathBuf,
    /// Orchard params handling mode: `require` (fail if missing) or `auto` (generate and persist).
    #[arg(
        long,
        env = "ORCHARD_PARAMS_MODE",
        default_value = "auto",
        value_parser = parse_orchard_params_mode
    )]
    pub orchard_params_mode: OrchardParamsMode,
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
    /// Shared message payload file fallback used for claim signatures.
    #[arg(long = "message", env = "MESSAGE_FILE", value_name = "MESSAGE_FILE")]
    pub message: Option<PathBuf>,
    /// Per-claim message assignments JSON.
    #[arg(long = "messages", env = "MESSAGES_FILE", value_name = "MESSAGES_FILE")]
    pub messages: Option<PathBuf>,
    /// ZIP-32 account index used to derive spend-auth keys from the seed.
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
    #[command(group(
        clap::ArgGroup::new("message_input")
            .args(["message", "messages"])
            .required(true)
            .multiple(true)
    ))]
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
    /// Sign claim proofs into a submission package.
    #[command(group(
        clap::ArgGroup::new("message_input")
            .args(["message", "messages"])
            .required(true)
            .multiple(true)
    ))]
    Sign {
        #[command(flatten)]
        args: ClaimSignArgs,
    },
}
