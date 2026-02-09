//! This test will build an airdrop configuration and compare the note-commitment roots. Then we
//! will compare the roots with the expected roots from chain.

#![allow(
    clippy::indexing_slicing,
    reason = "Test code should panic on invalid data"
)]

use assert_cmd::cargo::cargo_bin_cmd;
use serde_json::{Value, json};
use tempfile::tempdir;
use zair_core::base::ReverseBytes;
use zair_core::schema::config::AirdropConfiguration;

fn read_cookie() -> eyre::Result<String> {
    let cookie_path = dirs::cache_dir()
        .expect("No cache directory")
        .join("zebra/.cookie");

    Ok(std::fs::read_to_string(cookie_path)?.trim().to_string())
}

fn basic_auth_from_cookie(cookie: &str) -> String {
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(cookie);
    format!("Basic {encoded}")
}

fn get_tree_state(url: &str, cookie: &str, height: u64) -> eyre::Result<Value> {
    let mut response = ureq::post(url)
        .header("Authorization", &basic_auth_from_cookie(cookie))
        .send_json(json!({
            "jsonrpc": "1.0",
            "id": "rust",
            "method": "z_gettreestate",
            "params": [height.to_string()]
        }))?;

    let result: Value = response.body_mut().read_json()?;
    Ok(result["result"].clone())
}

#[test]
#[ignore = "Requires network access to fetch chain data, and access to local rpc node. The tests assume that the cookie for rpc is available at $XDG_CACHE_HOME/zebra/.cookie"]
fn test_build_airdrop_configuration() {
    const LIGHTWALLETD_URL: &str = "https://testnet.zec.rocks:443";
    const RPC_URL: &str = "http://127.0.0.1:18232";

    // Create temporary files paths
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let output_config_path = temp_dir.path().join("airdrop_config.json");
    let sapling_nullifiers_path = temp_dir.path().join("sapling-nullifiers.bin");
    let orchard_nullifiers_path = temp_dir.path().join("orchard-nullifiers.bin");

    // Execute the `zair build-config` subcommand
    let mut cmd = cargo_bin_cmd!("zair");

    let snapshot_start_height = 3_743_871_u64;
    let snapshot_end_height = 3_743_871_u64;

    cmd.args([
        "build-config",
        "--network",
        "testnet",
        "--lightwalletd-url",
        LIGHTWALLETD_URL,
        "--snapshot",
        format!("{snapshot_start_height}..={snapshot_end_height}").as_str(),
        "--configuration-output-file",
        output_config_path
            .to_str()
            .expect("Failed to convert path to str"),
        "--sapling-snapshot-nullifiers",
        sapling_nullifiers_path
            .to_str()
            .expect("Failed to convert path to str"),
        "--orchard-snapshot-nullifiers",
        orchard_nullifiers_path
            .to_str()
            .expect("Failed to convert path to str"),
    ])
    .assert()
    .success();

    // Sanity check: Ensure the output configuration file was created
    assert!(output_config_path.exists(), "Config file should exist");

    let configuration_contents =
        std::fs::read_to_string(&output_config_path).expect("Failed to read configuration file");
    let configuration: AirdropConfiguration =
        serde_json::from_str(&configuration_contents).expect("Failed to parse configuration JSON");

    // Fetch expected note commitment roots from the chain via RPC, to compare against
    // the generated configuration
    let cookie = read_cookie().expect("Failed to read cookie");
    let result = get_tree_state(RPC_URL, &cookie, snapshot_end_height + 1)
        .expect("Failed to get tree state from rpc");

    // Sanitice the rpc response and extract the expected anchors
    let expected_sapling_anchor: [u8; 32] = {
        let expected_sapling_anchor = result["sapling"]["commitments"]["finalRoot"]
            .as_str()
            .expect("Failed to get sapling root from rpc");
        hex::decode(expected_sapling_anchor.trim_start_matches("0x"))
            .expect("Failed to decode sapling anchor")
            .reverse_bytes()
            .expect("Sapling anchor is not 32 bytes")
    };

    let expected_orchard_anchor: [u8; 32] = {
        let expected_orchard_anchor = result["orchard"]["commitments"]["finalRoot"]
            .as_str()
            .expect("Failed to get orchard root from rpc");
        hex::decode(expected_orchard_anchor.trim_start_matches("0x"))
            .expect("Failed to decode orchard anchor")
            .try_into()
            .expect("Orchard anchor is not 32 bytes")
    };

    // Compare the generated configuration's note commitment roots against the expected roots
    assert_eq!(
        configuration.note_commitment_tree_anchors.sapling, expected_sapling_anchor,
        "Sapling note commitment root does not match expected value"
    );

    assert_eq!(
        configuration.note_commitment_tree_anchors.orchard, expected_orchard_anchor,
        "Orchard note commitment root does not match expected value"
    );

    assert_eq!(
        configuration.hiding_factor.sapling.personalization,
        "MASP_alt"
    );
    assert_eq!(configuration.hiding_factor.orchard.domain, "MASP:Airdrop");
    assert_eq!(configuration.hiding_factor.orchard.tag, "K");
}
