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

const fn reverse_bytes<const N: usize>(input: [u8; N]) -> [u8; N] {
    let mut output = [0u8; N];
    let mut i = 0;
    while i < N {
        output[i] = input[N - 1 - i];
        i += 1;
    }
    output
}

/// Extension trait for reversing byte slices into fixed-size arrays
pub trait ReverseBytes<const N: usize> {
    /// Reverse bytes and convert to a fixed-size array
    /// Returns None if the slice length doesn't match N
    fn reverse_into_array(&self) -> Option<[u8; N]>;
}

impl<const N: usize> ReverseBytes<N> for [u8] {
    fn reverse_into_array(&self) -> Option<[u8; N]> {
        let arr: [u8; N] = self.try_into().ok()?;
        Some(reverse_bytes(arr))
    }
}

impl<const N: usize> ReverseBytes<N> for Vec<u8> {
    fn reverse_into_array(&self) -> Option<[u8; N]> {
        self.as_slice().reverse_into_array()
    }
}
