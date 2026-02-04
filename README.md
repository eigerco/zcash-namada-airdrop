# zcash-namada-airdrop

> **⚠️ Work in Progress**: This project is under active development and not yet complete.

A toolkit for generating non-membership proofs for Zcash shielded assets as part of the Namada airdrop. This allows Zcash users with unspent shielded notes (Sapling or Orchard) to prove they held funds at a specific snapshot height without revealing their nullifiers.

## What are Non-Membership Proofs?

A non-membership proof is a cryptographic proof that demonstrates a specific element (such as a nullifier) is not present in a given set, without revealing any additional information about the element itself. In the context of Zcash and this toolkit, non-membership proofs allow users to prove that their shielded note's nullifier does not appear in a snapshot of spent nullifiers. This enables users to show they held unspent funds at a particular block height, which is essential for privacy-preserving airdrops.

These proofs are constructed using Merkle trees built from the set of known nullifiers at the snapshot height. By providing a non-membership proof, a user can convince a verifier that their note was not spent (i.e., its nullifier is not in the tree).

## Setup Instructions

### Without nix

#### Prerequisites

- Rust 1.91+ (uses Rust 2024 edition)
- Protobuf compiler (`protoc`) - required for building the lightwalletd gRPC bindings

After cloning the repo:

```bash
git clone --branch v0.11.0 --single-branch https://github.com/zcash/orchard.git .patched-orchard
git -C .patched-orchard apply "../nix/airdrop-orchard-nullifier.patch"

git clone --branch v0.5.0 --single-branch https://github.com/zcash/sapling-crypto.git .patched-sapling-crypto
git -C .patched-sapling-crypto apply "../nix/airdrop-sapling-nullifier.patch"
```

> **Note**: The patches add support for deriving "hiding nullifiers" - a privacy-preserving nullifier derivation that allows proving non-membership without revealing the actual nullifier.

### With nix

This workspace uses Nix to enhance the development experience.

- **`nix develop`** - enter the development environment
- **`nix fmt`** - format the workspace
- **`nix flake check`** - run checks, like linters and formatters. At the moment `cargo clippy` is not running with the other linters.

The workspace also uses `pre-commit` checks. These can be removed if they prove problematic.

## Available Tools

### airdrop

- **Description**: CLI tool for building Zcash airdrop snapshots and generating claim proofs. It supports the following commands:
  - `build-airdrop-configuration`: Fetches nullifiers from a lightwalletd server and saves them as snapshot files. Also exports a configuration JSON with Merkle tree roots.
  - `airdrop-claim`: Scans the chain for notes belonging to provided viewing keys, builds Merkle trees from snapshot nullifiers, and generates claim inputs for unspent notes.
  - `generate-claim-proofs`: Generates Groth16 ZK proofs from claim inputs (runs in parallel).
  - `generate-claim-params`: Generates the Groth16 proving and verifying keys (organizers only).
  - `verify-claim-proof`: Verifies generated claim proofs against the verifying key.
  - Run with `--help` to check the usage.

### mnemonic-to-fvks

- **Description**: A utility to convert a Zcash mnemonic to Full Viewing Keys. Outputs the Unified Full Viewing Key in human-readable Bech32 format (e.g., `uview1...`), as well as the individual Orchard and Sapling keys in hex format. Run with `--help` to check the usage.

### non-membership-proofs

- **Description**: Core library for generating non-membership proofs for Zcash nullifiers. Provides functionality for:
  - Streaming nullifiers from lightwalletd or local files
  - Scanning the chain for user notes using Full Viewing Keys
  - Building Merkle trees from sorted nullifiers for non-membership proofs
  - Deriving standard and hiding nullifiers for Sapling and Orchard notes

### claim-circuit

- **Description**: Custom Groth16 ZK circuit for airdrop claims. Proves ownership of unspent Sapling notes without revealing the actual nullifier. The circuit verifies:
  - Note commitment inclusion in the Zcash commitment tree
  - The note was not spent at the snapshot height
  - Correct derivation of the hiding nullifier

## Usage

Assuming that the project is set up correctly.

### Building the Project

After completing the setup steps above, you can build the project. The project provides two binaries, `mnemonic-to-fvks` and the `airdrop`. To build them use:

```bash
cargo build --release
```

This will produce the optimized `mnemonic-to-fvks` and `airdrop` executables in the `target/release` directory.

### User Guide

For a complete walkthrough of the airdrop claim process, see the **[Usage Guide](docs/USAGE.md)**.
