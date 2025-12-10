//! Utilities for printing nullifiers

use crate::Nullifier;

/// Prints nullifiers as hex strings
pub fn print_nullifiers(nullifiers: &[Nullifier], limit: Option<usize>) {
    let count = limit.unwrap_or(nullifiers.len()).min(nullifiers.len());

    for (i, nf) in nullifiers.iter().take(count).enumerate() {
        println!("{:>8}: {}", i, hex::encode(nf));
    }

    if count < nullifiers.len() {
        println!("... and {} more", nullifiers.len() - count);
    }
}

/// Prints summary statistics
pub fn print_summary(name: &str, nullifiers: &[Nullifier]) {
    println!("=== {} ===", name);
    println!("  Count: {}", nullifiers.len());
    println!(
        "  Size:  {} bytes ({:.2} MB)",
        nullifiers.len() * 32,
        (nullifiers.len() * 32) as f64 / 1_048_576.0
    );

    if !nullifiers.is_empty() {
        println!("  First: {}", hex::encode(&nullifiers[0]));
        println!(
            "  Last:  {}",
            hex::encode(&nullifiers[nullifiers.len() - 1])
        );
    }
}
