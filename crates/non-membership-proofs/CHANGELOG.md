# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-12-19

### Added

- `ChainNullifiers` trait for fetching nullifiers from various sources
- `UserNullifiers` trait for scanning user notes from the chain
- `LightWalletd` source implementation with gRPC and TLS support
- `FileSource` for loading nullifiers from binary files
- Merkle tree construction for nullifier sets
- Non-membership proof generation with range proofs
- Support for both Sapling and Orchard nullifier derivation
- Hiding nullifier support for privacy-preserving proofs
- `SaplingNote` wrapper with position and scope tracking for nullifier derivation
- `AnyFoundNote` enum for mixed Sapling/Orchard note streams
- Binary format utilities for reading/writing raw nullifiers
