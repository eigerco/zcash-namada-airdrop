#![allow(clippy::print_stdout, reason = "Allow print for utility functions")]
//! Utilities for printing nullifiers

use crate::Nullifier;

/// Prints nullifiers as hex strings
pub fn print_nullifiers(nullifiers: &[Nullifier], limit: Option<usize>) {
    let count = limit.unwrap_or(nullifiers.len()).min(nullifiers.len());

    for (i, nf) in nullifiers.iter().take(count).enumerate() {
        println!("{:>8}: {}", i, hex::encode(nf));
    }

    if count < nullifiers.len() {
        println!("... and {} more", nullifiers.len().saturating_sub(count));
    }
}

/// Prints summary statistics
#[allow(
    clippy::float_arithmetic,
    clippy::cast_precision_loss,
    clippy::as_conversions,
    reason = "Size calculation is for display purposes only"
)]
pub fn print_summary(name: &str, nullifiers: &[Nullifier]) {
    println!("=== {name} ===");
    println!("  Count: {}", nullifiers.len());
    let size_bytes = nullifiers.len().saturating_mul(32);
    println!(
        "  Size:  {size_bytes} bytes ({:.2} MB)",
        size_bytes as f64 / 1_048_576.0_f64
    );

    if let (Some(first), Some(last)) = (nullifiers.first(), nullifiers.last()) {
        println!("  First: {}", hex::encode(first));
        println!("  Last:  {}", hex::encode(last));
    }
}
