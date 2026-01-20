use clap::Parser;
use eyre::{Result, bail};
use zcash_protocol::consensus::Network;

#[derive(Parser)]
#[command(name = "mnemonic-to-fvks")]
#[command(about = "A utility to convert a Zcash mnemonic to Full Viewing Keys", long_about = None)]
pub struct Cli {
    /// Specify the coin type for key derivation. Default is Mainnet. Available options: [mainnet,
    /// testnet]
    #[arg(long, env = "NETWORK", default_value = "mainnet", value_parser = parse_network)]
    pub network: Network,
}

pub fn parse_network(s: &str) -> Result<Network> {
    match s.to_lowercase().as_str() {
        "mainnet" => Ok(Network::MainNetwork),
        "testnet" => Ok(Network::TestNetwork),
        _ => bail!("Invalid network type: {s}. Use 'mainnet' or 'testnet'."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_parse_network() {
        for (input, expected) in [
            ("mainnet", Network::MainNetwork),
            ("testnet", Network::TestNetwork),
            ("MAINNET", Network::MainNetwork),
            ("TESTNET", Network::TestNetwork),
            ("MaInNeT", Network::MainNetwork),
            ("tEsTnEt", Network::TestNetwork),
        ] {
            assert!(matches!(parse_network(input), Ok(net) if net == expected));
        }
    }

    #[test]
    fn invalid_parse_network() {
        let res = parse_network("invalidnet");
        assert!(matches!(
            res, Err(e) if e.to_string() ==
            "Invalid network type: invalidnet. Use 'mainnet' or 'testnet'."
        ));
    }
}
