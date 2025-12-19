# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-12-19

### Added

- CLI tool to derive Full Viewing Keys from BIP-39 mnemonic seed phrases
- Support for both mainnet and testnet networks
- Unified Full Viewing Key (UFVK) output in human-readable Bech32 format
- Individual Orchard and Sapling FVK output in hex format
- Secure passphrase input using `rpassword`
- Account index selection for HD wallet derivation
- Secure memory handling for sensitive data using `secrecy` crate
