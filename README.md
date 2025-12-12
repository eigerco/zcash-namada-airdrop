# zcash-namada-airdrop

A toolkit for generating non-membership proofs for Zcash shielded assets as part of the Namada airdrop. This allows Zcash users with unspent shielded notes (Sapling or Orchard) to prove they held funds at a specific snapshot height without revealing their nullifiers.

## Setup Instructions

### Without nix

#### Prerequisites

- Rust 1.91+ (uses Rust 2024 edition)
- Protobuf compiler (`protoc`) - required for building the lightwalletd gRPC bindings

After cloning the repo:

```bash
git submodule update --init --recursive

git clone --branch v0.11.0 --single-branch https://github.com/zcash/orchard.git .patched-orchard
git -C .patched-orchard apply "../nix/airdrop-orchard-nullifier.patch"

git clone --branch v0.5.0 --single-branch https://github.com/zcash/sapling-crypto.git .patched-sapling-crypto
git -C .patched-sapling-crypto apply "../nix/airdrop-sapling-nullifier.patch"
```

> **Note**: The patches add support for deriving "hiding nullifiers" - a privacy-preserving nullifier derivation that allows proving non-membership without revealing the actual nullifier.

### With nix

Submodule updates need to be run manually:

```bash
git submodule update --init --recursive
```

This workspace uses Nix to enhance the development experience.

- **`nix develop`** - enter the development environment
- **`nix fmt`** - format the workspace
- **`nix flake check`** - run checks, like linters and formatters. At the moment `cargo clippy` is not running with the other linters.

The workspace also uses `pre-commit` checks. These can be removed if they prove problematic.

## Available Tools

### airdrop

- **Description**: CLI tool for building Zcash airdrop snapshots and generating non-membership proofs. It supports two main commands:
  - `build-airdrop-configuration`: Fetches nullifiers from a lightwalletd server or local files and saves them as snapshot files. Also exports a configuration JSON with Merkle tree roots.
  - `airdrop-claim`: Scans the chain for notes belonging to provided viewing keys, builds Merkle trees from snapshot nullifiers, and generates non-membership proofs for unspent notes.
  - Run with `--help` to check the usage.

### mnemonic-to-fvks

- **Description**: A utility to convert a Zcash mnemonic to Full Viewing Keys. Supports Orchard and Sapling pools. Run with `--help` to check the usage.

### light-wallet-api

- **Description**: Rust bindings for the Zcash lightwalletd gRPC API. This crate compiles the protobuf definitions from the lightwalletd protocol and exposes them as Rust types for interacting with lightwalletd servers.

### non-membership-proofs

- **Description**: Core library for generating non-membership proofs for Zcash nullifiers. Provides functionality for:
  - Streaming nullifiers from lightwalletd or local files
  - Scanning the chain for user notes using Full Viewing Keys
  - Building Merkle trees from sorted nullifiers for non-membership proofs
  - Deriving standard and hiding nullifiers for Sapling and Orchard notes

## Zcash pools

A reminder of Zcash pools activation.

| Pool    | Network | Enabled at Block Height |
| ------- | ------- | ----------------------- |
| Sapling | Mainnet | 419,200                 |
| Sapling | Testnet | 280,000                 |
| Orchard | Mainnet | 1,687,104               |
| Orchard | Testnet | 1,842,420               |
