//! Airdrop library for Zcash-Namada airdrop toolkit.

pub mod cli;
pub mod commands;
pub mod unspent_notes_proofs;

pub(crate) const BUF_SIZE: usize = 1024 * 1024;
