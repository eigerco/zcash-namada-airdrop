# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-12-19

### Added

- `build-airdrop-configuration` command to fetch nullifiers and build Merkle trees
- `airdrop-claim` command to scan for user notes and generate non-membership proofs
- `airdrop-configuration-schema` command to print JSON schema for configuration
- Optional `--airdrop-configuration-file` argument for Merkle root verification
- Support for both Sapling and Orchard shielded pools
- Environment variable support for all CLI arguments
- Optional `file-source` feature for development/testing with local nullifier files
- Optional `tokio-console` feature for async runtime debugging
- JSON schema generation for airdrop configuration
