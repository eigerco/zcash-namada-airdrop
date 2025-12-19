//! A utility to convert a Zcash mnemonic to Full Viewing Keys
//! Supports deriving keys for Sapling and Orchard pools.

use clap::Parser;
use eyre::{Context as _, Result, bail};
use mnemonic_to_fvks::mnemonic_to_keys;
use zcash_protocol::consensus::Network;

#[derive(Parser)]
#[command(name = "mnemonic-to-fvks")]
#[command(about = "A utility to convert a Zcash mnemonic to Full Viewing Keys", long_about = None)]
struct Cli {
    /// Specify the coin type for key derivation. Default is Mainnet. Available options: [mainnet,
    /// testnet]
    #[arg(long, env = "NETWORK", default_value = "mainnet", value_parser = parse_network)]
    network: Network,
}

fn parse_network(s: &str) -> Result<Network> {
    match s.to_lowercase().as_str() {
        "mainnet" => Ok(Network::MainNetwork),
        "testnet" => Ok(Network::TestNetwork),
        _ => bail!("Invalid network type: {s}. Use 'mainnet' or 'testnet'."),
    }
}

// TODO: check mlock to avoid sensitive data in swap

#[allow(clippy::print_stdout, reason = "CLI utility")]
fn main() -> Result<()> {
    // Load .env file (fails silently if not found)
    #[allow(
        clippy::let_underscore_must_use,
        clippy::let_underscore_untyped,
        reason = "Ignoring dotenv result intentionally"
    )]
    let _ = dotenvy::dotenv();
    let cli = Cli::parse();

    let keys = {
        let mnemonic =
            rpassword::prompt_password("Enter mnemonic: ").map(secrecy::SecretString::from)?;

        let pass_phrase =
            rpassword::prompt_password("Enter pass-phrase: ").map(secrecy::SecretString::from)?;

        let account_idx = {
            let input = rpassword::prompt_password("Enter account index: ")?;
            if input.trim().is_empty() {
                "0".to_owned()
            } else {
                input
            }
        };

        println!("Deriving all Zcash keys from mnemonic...\n");

        mnemonic_to_keys(
            &mnemonic,
            cli.network,
            &pass_phrase,
            account_idx.parse::<u32>()?,
        )
        .wrap_err_with(|| format!("Failed to derive Zcash keys for network {:?}", cli.network))
    };

    let keys = keys?;

    println!("\n{}", "=".repeat(50));
    println!("  ZCASH KEYS (Network: {:?})", cli.network);
    println!("\n{}", "=".repeat(50));

    // Human-readable Unified Full Viewing Key (Bech32 encoded)
    println!("\n📋 UNIFIED FULL VIEWING KEY (Human-readable)\n");
    println!("  {}\n", keys.ufvk.encode(&cli.network));

    println!("🧐 FULL VIEWING KEYS (Safe to share - view only)\n");
    println!("Orchard FVK:");
    println!(
        "  👀 {}\n",
        keys.ufvk
            .orchard()
            .map_or_else(String::new, |orchard_key| hex::encode(
                orchard_key.to_bytes()
            ))
    );
    println!("Sapling diversifiable FVK:");
    println!(
        "  👀 {}\n",
        keys.ufvk
            .sapling()
            .map_or_else(String::new, |sapling_key| hex::encode(
                sapling_key.to_bytes()
            ))
    );

    println!("\n{}", "=".repeat(50));

    Ok(())
}
