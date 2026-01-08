//! A utility to convert a Zcash mnemonic to Full Viewing Keys
//! Supports deriving keys for Sapling and Orchard pools.

use clap::Parser as _;
use eyre::{Context as _, Result};
use mnemonic_to_fvks::mnemonic_to_keys;

mod cli;
use cli::Cli;

// TODO: check mlock to avoid sensitive data in swap

#[allow(clippy::print_stdout, reason = "CLI utility")]
fn main() -> Result<()> {
    // Load .env file (fails silently if not found)
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
