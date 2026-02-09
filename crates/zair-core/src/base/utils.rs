//! Utility functions for core primitive types.

use serde_with::hex::Hex;

use super::nullifier::{NULLIFIER_SIZE, Nullifier};

/// A `serde_as` adapter that reverses byte order before hex encoding.
///
/// This is useful for displaying Zcash values (nullifiers, hashes, etc.)
pub struct ReversedHex;

impl<const N: usize> serde_with::SerializeAs<[u8; N]> for ReversedHex {
    fn serialize_as<S>(value: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let reversed = reverse_bytes(value);
        <Hex as serde_with::SerializeAs<[u8; N]>>::serialize_as(&reversed, serializer)
    }
}

impl<'de, const N: usize> serde_with::DeserializeAs<'de, [u8; N]> for ReversedHex {
    fn deserialize_as<D>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: [u8; N] =
            <Hex as serde_with::DeserializeAs<'de, [u8; N]>>::deserialize_as(deserializer)?;
        Ok(reverse_bytes(&bytes))
    }
}

impl serde_with::SerializeAs<Nullifier> for ReversedHex {
    fn serialize_as<S>(value: &Nullifier, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        <Self as serde_with::SerializeAs<[u8; NULLIFIER_SIZE]>>::serialize_as(value, serializer)
    }
}

impl<'de> serde_with::DeserializeAs<'de, Nullifier> for ReversedHex {
    fn deserialize_as<D>(deserializer: D) -> Result<Nullifier, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: [u8; NULLIFIER_SIZE] = <Self as serde_with::DeserializeAs<
            'de,
            [u8; NULLIFIER_SIZE],
        >>::deserialize_as(deserializer)?;
        Ok(Nullifier::new(bytes))
    }
}

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

impl ReverseBytes<{ NULLIFIER_SIZE }> for Nullifier {
    fn reverse_bytes(&self) -> Option<[u8; NULLIFIER_SIZE]> {
        Some(reverse_bytes(self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let nullifier_bytes: [u8; NULLIFIER_SIZE] = [
            0_u8, 1_u8, 2_u8, 3_u8, 4_u8, 5_u8, 6_u8, 7_u8, 8_u8, 9_u8, 10_u8, 11_u8, 12_u8, 13_u8,
            14_u8, 15_u8, 16_u8, 17_u8, 18_u8, 19_u8, 20_u8, 21_u8, 22_u8, 23_u8, 24_u8, 25_u8,
            26_u8, 27_u8, 28_u8, 29_u8, 30_u8, 31_u8,
        ];
        let nullifier = Nullifier::new(nullifier_bytes);
        assert_eq!(
            nullifier.reverse_bytes(),
            Some([
                31_u8, 30_u8, 29_u8, 28_u8, 27_u8, 26_u8, 25_u8, 24_u8, 23_u8, 22_u8, 21_u8, 20_u8,
                19_u8, 18_u8, 17_u8, 16_u8, 15_u8, 14_u8, 13_u8, 12_u8, 11_u8, 10_u8, 9_u8, 8_u8,
                7_u8, 6_u8, 5_u8, 4_u8, 3_u8, 2_u8, 1_u8, 0_u8
            ])
        );
    }
}
