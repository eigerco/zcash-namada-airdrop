//! Airdrop library for Zcash-Namada airdrop toolkit.

pub mod cli;
pub mod commands;
pub mod proof_inputs;

pub(crate) const BUF_SIZE: usize = 1024 * 1024;
