//! A utility to convert a Zcash mnemonic to Full Viewing Keys and Spending Keys
//! Supports deriving keys for Sapling and Orchard pools.

use clap::Parser;
use eyre::{Context as _, Result, bail};
use mnemonic_to_fvks::{mnemonic_to_keys, read_mnemonic_secure};
use zcash_protocol::consensus::Network;
use zeroize::Zeroize as _;

#[derive(Parser)]
#[command(name = "mnemonic-to-fvks")]
#[command(about = "A utility to convert a Zcash mnemonic to Full Viewing Keys and Spending Keys", long_about = None)]
struct Cli {
    /// Specify the coin type for key derivation. Default is Testnet. Available options: [mainnet,
    /// testnet, regtest]
    #[arg(long, env = "NETWORK", default_value = "testnet", value_parser = parse_network)]
    network: Network,

    /// Show spending keys (WARNING: these can spend funds!)
    #[arg(long, default_value_t = false)]
    show_spending_keys: bool,
}

fn parse_network(s: &str) -> Result<Network> {
    match s.to_lowercase().as_str() {
        "mainnet" => Ok(Network::MainNetwork),
        "testnet" => Ok(Network::TestNetwork),
        _ => bail!("Invalid network type: {s}. Use 'mainnet', 'testnet', or 'regtest'."),
    }
}

#[allow(clippy::print_stdout, reason = "CLI utility")]
fn main() -> Result<()> {
    #[allow(
        clippy::let_underscore_untyped,
        reason = "Ignoring dotenv result intentionally"
    )]
    let _ = dotenvy::dotenv().ok();
    let cli = Cli::parse();

    let mut mnemonic = read_mnemonic_secure()
        .wrap_err("Failed to read mnemonic from environment or user input")?;

    println!("Deriving all Zcash keys from mnemonic...\n");
    let keys = mnemonic_to_keys(&mnemonic, cli.network)
        .wrap_err_with(|| format!("Failed to derive Zcash keys for network {:?}", cli.network))?;
    mnemonic.zeroize();

    println!("\n{}", "=".repeat(50));
    println!("  ZCASH KEYS (Network: {:?})", cli.network);
    println!("\n{}", "=".repeat(50));

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
    if cli.show_spending_keys {
        println!("⚠️  WARNING: SPENDING KEYS CAN SPEND FUNDS!");
        println!("\n{}", "=".repeat(50));

        println!("💳 SPENDING KEYS (NEVER share these!)\n");
        println!("Orchard Spending Key:");
        println!("  🔑 {}\n", hex::encode(keys.usk.orchard().to_bytes()));
        println!("Sapling Spending Key:");
        println!("  🔑 {}\n", hex::encode(keys.usk.sapling().to_bytes()));
    } else {
        println!("ℹ️  Spending keys are hidden. Use --show-spending-keys to display.");
    }
    println!("\n{}", "=".repeat(50));

    Ok(())
}
