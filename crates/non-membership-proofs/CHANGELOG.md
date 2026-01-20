# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `scanner` module with visitor pattern for block processing
  - `BlockScanner` for processing compact blocks
  - `AccountNotesVisitor` for collecting user notes with commitment tree witnesses
  - `ChainNullifiersVisitor` for collecting chain nullifiers
- `viewing_keys` module with `ViewingKeys` struct for unified key handling
- `nullifier` module for nullifier type definitions
- `light_walletd` module (promoted from `source::light_walletd`)
  - Added `scan_blocks_spawned` for channel-based scanning
  - Added `commitment_tree_anchors` for fetching tree roots
  - Added retry logic module

### Changed

- **BREAKING**: Renamed `merkle` module to `non_membership_tree`
- **BREAKING**: Moved `source::light_walletd` to top-level `light_walletd` module
- **BREAKING**: Removed `ChainNullifiers` and `UserNullifiers` traits in favor of visitor pattern
- Reorganized module structure for better separation of concerns

### Removed

- `source::file` module (use binary utilities directly)
- `user_nullifiers::decrypt_notes` module (replaced by scanner visitors)

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
