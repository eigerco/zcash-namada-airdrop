//! Shared constants for CLI.

// -------------------------
// Environment variables
// -------------------------

// Common
pub const ZAIR_CONFIG_FILE: &str = "ZAIR_CONFIG_FILE";
pub const ZAIR_SEED_FILE: &str = "ZAIR_SEED_FILE";
pub const ZAIR_MESSAGE_FILE: &str = "ZAIR_MESSAGE_FILE";
pub const ZAIR_MESSAGES_FILE: &str = "ZAIR_MESSAGES_FILE";
pub const ZAIR_ACCOUNT_ID: &str = "ZAIR_ACCOUNT_ID";
pub const ZAIR_NETWORK: &str = "ZAIR_NETWORK";
pub const ZAIR_LIGHTWALLETD_URL: &str = "ZAIR_LIGHTWALLETD_URL";
pub const ZAIR_BIRTHDAY: &str = "ZAIR_BIRTHDAY";
pub const ZAIR_SNAPSHOT_HEIGHT: &str = "ZAIR_SNAPSHOT_HEIGHT";

// Snapshot files
pub const ZAIR_SNAPSHOT_SAPLING_FILE: &str = "ZAIR_SNAPSHOT_SAPLING_FILE";
pub const ZAIR_SNAPSHOT_ORCHARD_FILE: &str = "ZAIR_SNAPSHOT_ORCHARD_FILE";

// Gap-tree
pub const ZAIR_GAP_TREE_SAPLING_FILE: &str = "ZAIR_GAP_TREE_SAPLING_FILE";
pub const ZAIR_GAP_TREE_ORCHARD_FILE: &str = "ZAIR_GAP_TREE_ORCHARD_FILE";
pub const ZAIR_GAP_TREE_MODE: &str = "ZAIR_GAP_TREE_MODE";

// Proving keys
pub const ZAIR_SAPLING_PK_FILE: &str = "ZAIR_SAPLING_PK_FILE";
pub const ZAIR_SAPLING_VK_FILE: &str = "ZAIR_SAPLING_VK_FILE";
pub const ZAIR_ORCHARD_PARAMS_FILE: &str = "ZAIR_ORCHARD_PARAMS_FILE";
pub const ZAIR_ORCHARD_PARAMS_MODE: &str = "ZAIR_ORCHARD_PARAMS_MODE";

// Setup
pub const ZAIR_SETUP_SCHEME: &str = "ZAIR_SETUP_SCHEME";
pub const ZAIR_SETUP_PK_OUT: &str = "ZAIR_SETUP_PK_OUT";
pub const ZAIR_SETUP_VK_OUT: &str = "ZAIR_SETUP_VK_OUT";
pub const ZAIR_SETUP_ORCHARD_PARAMS_OUT: &str = "ZAIR_SETUP_ORCHARD_PARAMS_OUT";

// Key
pub const ZAIR_SEED_OUT: &str = "ZAIR_SEED_OUT";
pub const ZAIR_MNEMONIC_FILE: &str = "ZAIR_MNEMONIC_FILE";
pub const ZAIR_MNEMONIC_STDIN: &str = "ZAIR_MNEMONIC_STDIN";
pub const ZAIR_NO_PASSPHRASE: &str = "ZAIR_NO_PASSPHRASE";
pub const ZAIR_UFVK_OUT: &str = "ZAIR_UFVK_OUT";

// Config
pub const ZAIR_POOL: &str = "ZAIR_POOL";
pub const ZAIR_TARGET_SAPLING: &str = "ZAIR_TARGET_SAPLING";
pub const ZAIR_SCHEME_SAPLING: &str = "ZAIR_SCHEME_SAPLING";
pub const ZAIR_TARGET_ORCHARD: &str = "ZAIR_TARGET_ORCHARD";
pub const ZAIR_SCHEME_ORCHARD: &str = "ZAIR_SCHEME_ORCHARD";
pub const ZAIR_CONFIG_OUT: &str = "ZAIR_CONFIG_OUT";
pub const ZAIR_SNAPSHOT_OUT_SAPLING: &str = "ZAIR_SNAPSHOT_OUT_SAPLING";
pub const ZAIR_SNAPSHOT_OUT_ORCHARD: &str = "ZAIR_SNAPSHOT_OUT_ORCHARD";
pub const ZAIR_GAP_TREE_OUT_SAPLING: &str = "ZAIR_GAP_TREE_OUT_SAPLING";
pub const ZAIR_GAP_TREE_OUT_ORCHARD: &str = "ZAIR_GAP_TREE_OUT_ORCHARD";
pub const ZAIR_NO_GAP_TREE: &str = "ZAIR_NO_GAP_TREE";

// Claim
pub const ZAIR_CLAIMS_OUT: &str = "ZAIR_CLAIMS_OUT";
pub const ZAIR_CLAIMS_IN: &str = "ZAIR_CLAIMS_IN";
pub const ZAIR_PROOFS_OUT: &str = "ZAIR_PROOFS_OUT";
pub const ZAIR_PROOFS_IN: &str = "ZAIR_PROOFS_IN";
pub const ZAIR_SECRETS_OUT: &str = "ZAIR_SECRETS_OUT";
pub const ZAIR_SECRETS_IN: &str = "ZAIR_SECRETS_IN";
pub const ZAIR_SUBMISSION_OUT: &str = "ZAIR_SUBMISSION_OUT";
pub const ZAIR_SUBMISSION_IN: &str = "ZAIR_SUBMISSION_IN";
pub const ZAIR_UFVK_FILE: &str = "ZAIR_UFVK_FILE";

// -------------------------
// Default values
// -------------------------

// File paths
pub const DEFAULT_CONFIG_FILE: &str = "config.json";
pub const DEFAULT_CLAIMS_FILE: &str = "claim-prepared.json";
pub const DEFAULT_PROOFS_FILE: &str = "claim-proofs.json";
pub const DEFAULT_SECRETS_FILE: &str = "claim-proofs-secrets.json";
pub const DEFAULT_SUBMISSION_FILE: &str = "claim-submission.json";
pub const DEFAULT_SAPLING_PK_FILE: &str = "setup-sapling-pk.params";
pub const DEFAULT_SAPLING_VK_FILE: &str = "setup-sapling-vk.params";
pub const DEFAULT_ORCHARD_PARAMS_FILE: &str = "setup-orchard-params.bin";
pub const DEFAULT_SNAPSHOT_SAPLING_FILE: &str = "snapshot-sapling.bin";
pub const DEFAULT_SNAPSHOT_ORCHARD_FILE: &str = "snapshot-orchard.bin";
pub const DEFAULT_GAP_TREE_SAPLING_FILE: &str = "gaptree-sapling.bin";
pub const DEFAULT_GAP_TREE_ORCHARD_FILE: &str = "gaptree-orchard.bin";
pub const DEFAULT_UFVK_FILE: &str = "ufvk.txt";
pub const DEFAULT_SEED_FILE: &str = "seed.txt";

// Parsed values
pub const DEFAULT_NETWORK: &str = "mainnet";
pub const DEFAULT_SCHEME: &str = "native";
pub const DEFAULT_GAP_TREE_MODE: &str = "none";
pub const DEFAULT_ORCHARD_PARAMS_MODE: &str = "auto";
pub const DEFAULT_POOL: &str = "both";
pub const DEFAULT_TARGET_SAPLING: &str = "ZAIRTEST";
pub const DEFAULT_TARGET_ORCHARD: &str = "ZAIRTEST:O";
