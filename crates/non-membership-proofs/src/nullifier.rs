//! Nullifier type for Zcash shielded transactions.
//!
//! A nullifier is a 32-byte value that uniquely identifies a spent note
//! in Zcash's Sapling and Orchard shielded pools.

use std::ops::Deref;

use bytemuck::{Pod, Zeroable};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::utils::ReversedHex;

/// Size of a nullifier in bytes
pub const NULLIFIER_SIZE: usize = 32;

/// A representation of Nullifiers
///
/// Nullifiers in Zcash Orchard and Sapling pools are both 32 bytes long.
#[serde_as]
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[repr(transparent)]
pub struct Nullifier(#[serde_as(as = "ReversedHex")] [u8; NULLIFIER_SIZE]);

impl std::fmt::Display for Nullifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.0.iter().rev() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

// SAFETY: Nullifier is a #[repr(transparent)] wrapper around [u8; NULLIFIER_SIZE]
// which is itself Pod (plain old data with no padding, valid for any bit pattern).
#[allow(unsafe_code)]
unsafe impl Zeroable for Nullifier {}

// SAFETY: Nullifier is #[repr(transparent)] over [u8; 32], which is Pod.
// All bit patterns are valid, there's no padding, and it's Copy.
#[allow(unsafe_code)]
unsafe impl Pod for Nullifier {}

impl Nullifier {
    /// Minimum nullifier (all zeros)
    pub const MIN: Self = Self([0_u8; NULLIFIER_SIZE]);

    /// Maximum nullifier (all ones)
    pub const MAX: Self = Self([0xFF_u8; NULLIFIER_SIZE]);

    /// Create a new Nullifier from a byte array
    #[must_use]
    pub const fn new(bytes: [u8; NULLIFIER_SIZE]) -> Self {
        Self(bytes)
    }

    // /// Get the underlying byte array
    // #[must_use]
    // pub const fn as_bytes(&self) -> &[u8; NULLIFIER_SIZE] {
    //     &self.0
    // }
    //
    // /// Convert to the underlying byte array
    // #[must_use]
    // pub const fn to_bytes(self) -> [u8; NULLIFIER_SIZE] {
    //     self.0
    // }
}

impl From<&[u8; NULLIFIER_SIZE]> for Nullifier {
    fn from(bytes: &[u8; NULLIFIER_SIZE]) -> Self {
        Self(*bytes)
    }
}

impl From<[u8; NULLIFIER_SIZE]> for Nullifier {
    fn from(bytes: [u8; NULLIFIER_SIZE]) -> Self {
        Self(bytes)
    }
}

impl From<Nullifier> for [u8; NULLIFIER_SIZE] {
    fn from(nullifier: Nullifier) -> Self {
        nullifier.0
    }
}

impl AsRef<[u8; NULLIFIER_SIZE]> for Nullifier {
    fn as_ref(&self) -> &[u8; NULLIFIER_SIZE] {
        &self.0
    }
}

impl AsRef<[u8]> for Nullifier {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for Nullifier {
    type Target = [u8; NULLIFIER_SIZE];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<&[u8]> for Nullifier {
    type Error = std::array::TryFromSliceError;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        let arr: [u8; NULLIFIER_SIZE] = slice.try_into()?;
        Ok(Self(arr))
    }
}

impl TryFrom<Vec<u8>> for Nullifier {
    type Error = Vec<u8>;

    fn try_from(vec: Vec<u8>) -> Result<Self, Self::Error> {
        let arr: [u8; NULLIFIER_SIZE] = vec.try_into()?;
        Ok(Self(arr))
    }
}

/// A collection of nullifiers that have been sanitised by sorting and deduplication.
///
/// Some functions have the precondition that the input nullifiers are sorted and contain no
/// duplicates. This type enforces that invariant.
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
    use test_utils::{nf, nfs};

    use super::*;

    #[test]
    fn test_sanitise_nullifiers() {
        let nullifiers = vec![
            nf![3_u8],
            nf![2_u8],
            nf![1_u8],
            nf![2_u8],
            nf![3_u8],
            nf![1_u8],
        ];

        let sanitised = SanitiseNullifiers::new(nullifiers);

        let expected = nfs![1_u8, 2_u8, 3_u8];
        assert_eq!(*sanitised, expected);
    }

    #[test]
    fn display_outputs_reversed_hex() {
        let mut bytes = [0u8; NULLIFIER_SIZE];
        bytes[0] = 0xab;
        bytes[31] = 0xcd;
        let nullifier = Nullifier::new(bytes);
        assert_eq!(format!("{nullifier}"), format!("cd{}ab", "00".repeat(30)));
    }

    #[test]
    fn into_bytes_returns_inner_array() {
        let bytes = [42u8; NULLIFIER_SIZE];
        let nullifier = Nullifier::new(bytes);

        let converted: [u8; NULLIFIER_SIZE] = nullifier.into();

        assert_eq!(converted, bytes);
    }

    #[test]
    fn as_ref_returns_reference_to_inner_array() {
        let bytes = [123u8; NULLIFIER_SIZE];
        let nullifier = Nullifier::new(bytes);

        let reference: &[u8; NULLIFIER_SIZE] = nullifier.as_ref();

        assert_eq!(*reference, bytes);

        let slice_ref: &[u8] = nullifier.as_ref();
        assert_eq!(reference, slice_ref);
    }

    #[test]
    fn try_from_succeeds_with_valid_length() {
        let bytes = [7u8; NULLIFIER_SIZE];

        let nullifier =
            Nullifier::try_from(bytes.as_slice()).expect("Failed to convert from slice");
        assert_eq!(*nullifier, bytes);

        let nullifier = Nullifier::from(bytes);
        assert_eq!(&*nullifier, bytes.as_slice());
    }

    #[test]
    fn try_from_fails_with_invalid_length() {
        let too_short = vec![7u8; NULLIFIER_SIZE - 1];
        let too_long = vec![7u8; NULLIFIER_SIZE + 1];

        assert!(Nullifier::try_from(too_short.as_slice()).is_err());
        assert!(Nullifier::try_from(too_long.as_slice()).is_err());

        assert!(Nullifier::try_from(too_short).is_err());
        assert!(Nullifier::try_from(too_long).is_err());
    }
}
