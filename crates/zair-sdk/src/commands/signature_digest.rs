//! Canonical hashing helpers for signed claim submissions.

use blake2b_simd::Params;
use eyre::ensure;
use zair_core::schema::submission::SubmissionPool;

use super::claim_proofs::ClaimProofsOutput;

/// Domain marker prepended to submission-signature digest preimages.
pub const SIGNATURE_PREIMAGE_TAG: &[u8; 8] = b"ZAIR_SIG";
/// Protocol version byte included in signature digest preimages.
pub const SIGNATURE_VERSION: u8 = 1;

/// Hash arbitrary bytes to 32 bytes with `BLAKE2b`.
#[must_use]
pub fn hash_bytes(data: &[u8]) -> [u8; 32] {
    let digest = Params::new().hash_length(32).hash(data);
    let mut out = [0_u8; 32];
    out.copy_from_slice(digest.as_bytes());
    out
}

/// Hash message bytes for submission signing.
#[must_use]
pub fn hash_message(message: &[u8]) -> [u8; 32] {
    hash_bytes(message)
}

/// Hash the unsigned proof bundle in canonical serialized order.
///
/// The field order is stable and matches the proofs JSON schema. Proofs are hashed
/// in their existing order; no sorting is applied.
pub fn hash_proof_bundle(proofs: &ClaimProofsOutput) -> eyre::Result<[u8; 32]> {
    let mut preimage = Vec::new();
    ensure!(
        u32::try_from(proofs.sapling_proofs.len()).is_ok(),
        "Sapling proof count exceeds u32::MAX"
    );
    let sapling_count = u32::try_from(proofs.sapling_proofs.len())?;
    preimage.extend_from_slice(&sapling_count.to_le_bytes());

    for proof in &proofs.sapling_proofs {
        preimage.extend_from_slice(&proof.zkproof);
        preimage.extend_from_slice(&proof.rk);

        match proof.cv {
            Some(cv) => {
                preimage.push(1);
                preimage.extend_from_slice(&cv);
            }
            None => preimage.push(0),
        }

        match proof.cv_sha256 {
            Some(cv_sha256) => {
                preimage.push(1);
                preimage.extend_from_slice(&cv_sha256);
            }
            None => preimage.push(0),
        }

        let nf: [u8; 32] = proof.airdrop_nullifier.into();
        preimage.extend_from_slice(&nf);
    }

    ensure!(
        u32::try_from(proofs.orchard_proofs.len()).is_ok(),
        "Orchard proof count exceeds u32::MAX"
    );
    let orchard_count = u32::try_from(proofs.orchard_proofs.len())?;
    preimage.extend_from_slice(&orchard_count.to_le_bytes());
    Ok(hash_bytes(&preimage))
}

/// Build the 32-byte message signed by Sapling spend authorization keys.
///
/// Preimage layout:
/// `ZAIR_SIG || version:u8 || pool:u8 || target_id_len:u8 || target_id || proof_hash ||
/// message_hash`
pub fn signature_digest(
    pool: SubmissionPool,
    target_id: &str,
    proof_hash: &[u8; 32],
    message_hash: &[u8; 32],
) -> eyre::Result<[u8; 32]> {
    ensure!(
        u8::try_from(target_id.len()).is_ok(),
        "target_id length exceeds 255 bytes"
    );
    let target_len = u8::try_from(target_id.len())?;

    let mut preimage = Vec::new();

    preimage.extend_from_slice(SIGNATURE_PREIMAGE_TAG);
    preimage.push(SIGNATURE_VERSION);
    preimage.push(pool.as_byte());
    preimage.push(target_len);
    preimage.extend_from_slice(target_id.as_bytes());
    preimage.extend_from_slice(proof_hash);
    preimage.extend_from_slice(message_hash);

    Ok(hash_bytes(&preimage))
}

#[cfg(test)]
mod tests {
    use zair_core::base::Nullifier;

    use super::*;
    use crate::commands::claim_proofs::{ClaimProofsOutput, SaplingClaimProofResult};

    #[test]
    fn proof_hash_is_deterministic_and_ordered() {
        let p0 = SaplingClaimProofResult {
            zkproof: [1_u8; 192],
            rk: [2_u8; 32],
            cv: Some([3_u8; 32]),
            cv_sha256: None,
            airdrop_nullifier: Nullifier::from([4_u8; 32]),
        };
        let p1 = SaplingClaimProofResult {
            zkproof: [9_u8; 192],
            rk: [8_u8; 32],
            cv: None,
            cv_sha256: Some([7_u8; 32]),
            airdrop_nullifier: Nullifier::from([6_u8; 32]),
        };

        let a = ClaimProofsOutput {
            sapling_proofs: vec![p0.clone(), p1.clone()],
            orchard_proofs: Vec::new(),
        };
        let b = ClaimProofsOutput {
            sapling_proofs: vec![p1, p0],
            orchard_proofs: Vec::new(),
        };

        let ah = hash_proof_bundle(&a).expect("hash should succeed");
        let ah2 = hash_proof_bundle(&a).expect("hash should succeed");
        let bh = hash_proof_bundle(&b).expect("hash should succeed");

        assert_eq!(ah, ah2);
        assert_ne!(ah, bh);
    }
}
