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

curl -sL https://static.crates.io/crates/halo2_gadgets/halo2_gadgets-0.3.1.crate | tar xz
mv halo2_gadgets-0.3.1 .patched-halo2-gadgets
patch -p1 -d .patched-halo2-gadgets < nix/airdrop-halo2-gadgets-sha256.patch
```

> **Note**: The patches expose private internals needed by the airdrop circuits - hiding nullifier derivation in sapling-crypto and orchard, circuit gadget visibility and note commitment helpers in orchard, and SHA-256 digest cell access in halo2_gadgets.

### With nix

This workspace uses Nix to enhance the development experience.

- **`nix develop`** - enter the development environment
- **`nix fmt`** - format the workspace
- **`nix flake check`** - run checks, like linters and formatters. At the moment `cargo clippy` is not running with the other linters.

The workspace also uses `pre-commit` checks. These can be removed if they prove problematic.

## Available Tools

### zair

- **Description**: CLI tool for building Zcash airdrop snapshots, generating claim inputs/proofs, and verifying submissions.
  - `zair key derive-seed` / `zair key derive-ufvk`: derive `seed.txt` or `ufvk.txt` from a wallet mnemonic.
  - `zair config build`: build `config.json`, snapshot and gap-tree files.
  - `zair claim prepare`: scan chain for your notes and write `claim-prepared.json` (UFVK is provided via a file).
  - `zair claim prove` / `zair claim sign` / `zair claim run`: generate proofs and signed submissions.
  - `zair verify proof` / `zair verify signature` / `zair verify run`: verify proofs and signatures.
  - `zair setup sapling` / `zair setup orchard`: generate proving/verification parameters (organizers/developers).
  - Run with `--help` to check the usage.

## Crates

- **zair-core**: Shared configuration and claim-input formats (JSON) used across the workspace.
- **zair-sdk**: Library/workflow crate used by `zair` (snapshot building, claim generation, proof helpers).
- **zair-nonmembership**: Nullifier and non-membership Merkle tree primitives used by the airdrop tools.
- **zair-scan**: lightwalletd integration + chain scanning used by the CLI (fetching nullifiers, scanning for notes, etc).
- **zair-sapling-proofs**: Sapling claim proving + verification API. Verification is available by default; proving is behind the `prove` feature (so verification-only consumers don't compile the circuit).
- **zair-sapling-circuit**: The Sapling claim circuit implementation (heavy; used only for keygen/proving).

## Usage

Assuming that the project is set up correctly.

### Building the Project

After completing the setup steps above, you can build the project. The project provides the `zair` binary:

```bash
cargo build --release
```

This will produce the optimized `zair` executable in the `target/release` directory.

### User Guide

For a complete walkthrough of the airdrop claim process, see the **[Usage Guide](docs/USAGE.md)**.
