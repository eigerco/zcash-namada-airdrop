//! Key derivation subcommands.

use std::path::PathBuf;

use clap::ArgGroup;
use zcash_protocol::consensus::Network;

use super::parse_network;

/// Arguments for `zair key derive-seed`.
#[derive(Debug, clap::Args)]
pub struct DeriveSeedArgs {
    /// Output file for the derived seed (hex).
    #[arg(long, env = "SEED_OUT", default_value = "seed.txt")]
    pub output: PathBuf,

    /// Read mnemonic from a file.
    #[arg(long, env = "MNEMONIC_FILE")]
    pub mnemonic_file: Option<PathBuf>,

    /// Read mnemonic from stdin.
    #[arg(long, env = "MNEMONIC_STDIN", default_value_t = false)]
    pub mnemonic_stdin: bool,

    /// Do not prompt for a BIP-39 passphrase (use empty passphrase).
    #[arg(long, env = "NO_PASSPHRASE", default_value_t = false)]
    pub no_passphrase: bool,
}

/// Arguments for `zair key derive-ufvk`.
#[derive(Debug, clap::Args)]
pub struct DeriveUfvkArgs {
    /// Network to derive keys for (mainnet or testnet).
    #[arg(long, env = "NETWORK", default_value = "mainnet", value_parser = parse_network)]
    pub network: Network,

    /// ZIP-32 account index used for key derivation.
    #[arg(long, env = "ACCOUNT_ID", default_value_t = 0_u32)]
    pub account: u32,

    /// Read seed from a file (hex). Defaults to `seed.txt` if omitted.
    #[arg(long, env = "SEED_FILE")]
    pub seed: Option<PathBuf>,

    /// Read mnemonic from a file (derives seed internally).
    #[arg(long, env = "MNEMONIC_FILE")]
    pub mnemonic_file: Option<PathBuf>,

    /// Read mnemonic from stdin (derives seed internally).
    #[arg(long, env = "MNEMONIC_STDIN", default_value_t = false)]
    pub mnemonic_stdin: bool,

    /// Do not prompt for a BIP-39 passphrase (use empty passphrase).
    #[arg(long, env = "NO_PASSPHRASE", default_value_t = false)]
    pub no_passphrase: bool,

    /// Output file for the derived UFVK.
    #[arg(long, env = "UFVK_OUT", default_value = "ufvk.txt")]
    pub output: PathBuf,
}

/// Key command group.
#[derive(Debug, clap::Subcommand)]
pub enum KeyCommands {
    /// Derive a 64-byte BIP-39 seed and write it as 128 hex chars to a file.
    #[command(group(
        ArgGroup::new("mnemonic_input")
            .args(["mnemonic_file", "mnemonic_stdin"])
            .multiple(false)
    ))]
    DeriveSeed {
        #[command(flatten)]
        args: DeriveSeedArgs,
    },

    /// Derive a UFVK from a seed file (default `seed.txt`) or mnemonic.
    #[command(group(
        ArgGroup::new("key_input")
            .args(["seed", "mnemonic_file", "mnemonic_stdin"])
            .multiple(false)
    ))]
    DeriveUfvk {
        #[command(flatten)]
        args: DeriveUfvkArgs,
    },
}
