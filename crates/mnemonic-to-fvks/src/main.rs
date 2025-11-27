//! A utility to convert a Zcash mnemonic to Full Viewing Keys and Spending Keys
//! Supports deriving keys for Sapling and Orchard pools.
use std::path::PathBuf;

use clap::Parser;
use eyre::{Result, WrapErr as _};
use mnemonic_to_fvks::{CoinType, Pool, mnemonic_to_keys, read_mnemonic_secure};
use zeroize::Zeroize as _;

#[derive(Parser)]
#[command(name = "mnemonic-to-fvks")]
#[command(about = "A utility to convert a Zcash mnemonic to Full Viewing Keys and Spending Keys", long_about = None)]
struct Cli {
    /// Select the pool(s) to derive FVKs for. Default is Both. Available options: [sapling,
    /// orchard, both]
    #[arg(short, long, value_enum, default_value_t = Pool::Both)]
    pool: Pool,

    /// Specify the coin type for key derivation. Default is Testnet. Available options: [mainnet,
    /// testnet, regtest]
    #[arg(short = 'c', long, value_enum, default_value_t = CoinType::Testnet)]
    coin_type: CoinType,

    /// Show spending keys (WARNING: these can spend funds!)
    #[arg(long, default_value_t = false)]
    show_spending_keys: bool,
}

#[allow(clippy::print_stdout, reason = "CLI utility")]
fn main() -> Result<()> {
    let _: Option<PathBuf> = dotenvy::dotenv().ok();
    let cli = Cli::parse();

    let mut mnemonic = read_mnemonic_secure()
        .wrap_err("Failed to read mnemonic from environment or user input")?;

    println!("Deriving all Zcash keys from mnemonic...\n");
    let keys = mnemonic_to_keys(&mnemonic, cli.coin_type).wrap_err_with(|| {
        format!(
            "Failed to derive Zcash keys for coin type {:?}",
            cli.coin_type
        )
    })?;
    mnemonic.zeroize();

    println!("\n{}", "=".repeat(50));
    println!("  ZCASH KEYS (Network: {:?})", cli.coin_type);
    println!("\n{}", "=".repeat(50));

    println!("📋 FULL VIEWING KEYS (Safe to share - view only)\n");
    println!("Orchard FVK:");
    println!("  {}\n", hex::encode(keys.orchard_fvk.to_bytes()));
    println!("Sapling FVK:");
    println!("  {}\n", hex::encode(keys.sapling_fvk.to_bytes()));

    println!("\n{}", "=".repeat(50));
    if cli.show_spending_keys {
        println!("⚠️  WARNING: SPENDING KEYS CAN SPEND FUNDS!");
        println!("\n{}", "=".repeat(50));

        println!("🔑 SPENDING KEYS (NEVER share these!)\n");
        println!("Orchard Spending Key:");
        println!("  {}\n", hex::encode(keys.orchard_spending_key.to_bytes()));
        println!("Sapling Spending Key:");
        println!("  {}\n", hex::encode(keys.sapling_spending_key.to_bytes()));
    } else {
        println!("ℹ️  Spending keys hidden. Use --show-spending-keys to display.");
    }
    println!("\n{}", "=".repeat(50));

    Ok(())
}
