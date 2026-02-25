//! Shared helpers for SHA-256 value commitments.

use sha2::{Digest as _, Sha256};

/// Fixed ASCII prefix used by the SHA-256 value commitment scheme.
pub const VALUE_COMMIT_SHA256_PREFIX: [u8; 4] = *b"Zair";

/// Build the SHA-256 value-commitment preimage.
///
/// The preimage is `b"Zair" || LE64(value) || rcv_sha256`.
#[must_use]
pub fn cv_sha256_preimage(value: u64, rcv_sha256: [u8; 32]) -> [u8; 44] {
    let mut preimage = [0_u8; 44];
    preimage[0..4].copy_from_slice(&VALUE_COMMIT_SHA256_PREFIX);
    preimage[4..12].copy_from_slice(&value.to_le_bytes());
    preimage[12..44].copy_from_slice(&rcv_sha256);
    preimage
}

/// Compute `cv_sha256 = SHA256(b"Zair" || LE64(value) || rcv_sha256)`.
#[must_use]
pub fn cv_sha256(value: u64, rcv_sha256: [u8; 32]) -> [u8; 32] {
    Sha256::digest(cv_sha256_preimage(value, rcv_sha256)).into()
}

#[cfg(test)]
mod tests {
    use super::{VALUE_COMMIT_SHA256_PREFIX, cv_sha256, cv_sha256_preimage};

    #[test]
    fn cv_sha256_preimage_layout() {
        let value = 0x0102_0304_0506_0708_u64;
        let rcv_sha256 = [9_u8; 32];
        let preimage = cv_sha256_preimage(value, rcv_sha256);

        assert_eq!(&preimage[0..4], &VALUE_COMMIT_SHA256_PREFIX);
        assert_eq!(&preimage[4..12], &value.to_le_bytes());
        assert_eq!(&preimage[12..44], &rcv_sha256);
    }

    #[test]
    fn cv_sha256_test_vector() {
        let mut rcv_sha256 = [0_u8; 32];
        for (idx, byte) in (0_u8..32).zip(rcv_sha256.iter_mut()) {
            *byte = idx;
        }

        let got = cv_sha256(1, rcv_sha256);
        let expected: [u8; 32] = [
            0x6b, 0x9b, 0x2a, 0x58, 0x66, 0x11, 0x31, 0x76, 0xdc, 0x8c, 0x7f, 0x50, 0x03, 0xd7,
            0xeb, 0xdf, 0xd3, 0xf9, 0xf3, 0x3c, 0x92, 0x16, 0x04, 0x57, 0xf8, 0x3f, 0xcd, 0x82,
            0xb8, 0x48, 0x6e, 0x71,
        ];

        assert_eq!(got, expected);
    }
}
