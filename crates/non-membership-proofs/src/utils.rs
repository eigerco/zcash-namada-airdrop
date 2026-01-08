//! Utility functions used across the non-membership proofs crate

use std::ops::Deref;

use crate::Nullifier;

#[allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "Loop is bounded by N, indexing is always in bounds"
)]
const fn reverse_bytes<const N: usize>(input: &[u8; N]) -> [u8; N] {
    let mut output = [0_u8; N];
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
    fn reverse_bytes(&self) -> Option<[u8; N]>;
}

impl<const N: usize> ReverseBytes<N> for [u8] {
    fn reverse_bytes(&self) -> Option<[u8; N]> {
        let arr: [u8; N] = self.try_into().ok()?;
        Some(reverse_bytes(&arr))
    }
}

impl<const N: usize> ReverseBytes<N> for Vec<u8> {
    fn reverse_bytes(&self) -> Option<[u8; N]> {
        self.as_slice().reverse_bytes()
    }
}

/// A collection of nullifiers that have been sanitised by sorting and deduplication.
///
/// Some functions have the precondition that the input nullifiers are sorted and contain no
/// duplicates. This type enforces that invariant
#[derive(Debug, PartialEq, Eq)]
pub struct SanitiseNullifiers {
    nullifiers: Vec<Nullifier>,
}

impl SanitiseNullifiers {
    /// Create a new `SanitiseNullifiers` by sorting and deduplicating the input nullifiers.
    #[must_use]
    pub fn new(mut nullifiers: Vec<Nullifier>) -> Self {
        if !nullifiers.is_sorted() {
            nullifiers.sort_unstable();
        }
        nullifiers.dedup();

        Self { nullifiers }
    }
}

impl Deref for SanitiseNullifiers {
    type Target = [Nullifier];

    fn deref(&self) -> &Self::Target {
        &self.nullifiers
    }
}

#[cfg(test)]
mod tests {
    use test_utils::nfs;

    use super::*;
    use crate::utils::SanitiseNullifiers;

    #[test]
    fn test_reverse_bytes() {
        let data = vec![1_u8, 2_u8, 3_u8, 4_u8, 5_u8];
        let reversed = data.reverse_bytes();
        assert_eq!(reversed, Some([5_u8, 4_u8, 3_u8, 2_u8, 1_u8]));

        let data = [1_u8, 2_u8, 3_u8, 4_u8, 5_u8];
        let reversed = data.reverse_bytes();
        assert_eq!(reversed, Some([5_u8, 4_u8, 3_u8, 2_u8, 1_u8]));

        let data = [1_u8, 2_u8, 3_u8];
        let reversed: Option<[u8; 5_usize]> = data.reverse_bytes();
        assert_eq!(reversed, None);
    }

    #[test]
    fn test_sanitise_nullifiers() {
        let nullifiers = nfs![3_u8, 2_u8, 1_u8, 2_u8, 3_u8, 1_u8];

        let sanitised = SanitiseNullifiers::new(nullifiers);

        let expected = nfs![1_u8, 2_u8, 3_u8];
        assert_eq!(*sanitised, expected);
    }
}
