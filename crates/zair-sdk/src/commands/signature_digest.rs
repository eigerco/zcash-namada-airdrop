//! Canonical hashing helpers for signed claim submissions.

use blake2b_simd::Params;
use eyre::ensure;
use zair_core::base::{Nullifier, Pool};
use zair_core::schema::submission::{OrchardSignedClaim, SaplingSignedClaim};

use super::claim_proofs::{OrchardClaimProofResult, SaplingClaimProofResult};

/// Domain marker prepended to submission-signature digest preimages.
pub const SIGNATURE_PREIMAGE_TAG: &[u8; 8] = b"ZAIR_SIG";
/// Protocol version byte included in signature digest preimages.
pub const SIGNATURE_VERSION: u8 = 1;
/// Domain tag for Sapling proof-hash preimages.
pub const SAPLING_PROOF_TAG: &[u8; 21] = b"ZAIR_SAPLING_PROOF_V1";
/// Domain tag for Orchard proof-hash preimages.
pub const ORCHARD_PROOF_TAG: &[u8; 21] = b"ZAIR_ORCHARD_PROOF_V1";

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

fn hash_sapling_proof_fields(
    zkproof: &[u8; 192],
    rk: &[u8; 32],
    cv: Option<[u8; 32]>,
    cv_sha256: Option<[u8; 32]>,
    airdrop_nullifier: Nullifier,
) -> [u8; 32] {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(SAPLING_PROOF_TAG);
    preimage.extend_from_slice(zkproof);
    preimage.extend_from_slice(rk);
    match cv {
        Some(bytes) => {
            preimage.push(1);
            preimage.extend_from_slice(&bytes);
        }
        None => preimage.push(0),
    }
    match cv_sha256 {
        Some(bytes) => {
            preimage.push(1);
            preimage.extend_from_slice(&bytes);
        }
        None => preimage.push(0),
    }
    let nf: [u8; 32] = airdrop_nullifier.into();
    preimage.extend_from_slice(&nf);
    hash_bytes(&preimage)
}

fn hash_orchard_proof_fields(
    zkproof: &[u8],
    rk: &[u8; 32],
    cv: Option<[u8; 32]>,
    cv_sha256: Option<[u8; 32]>,
    airdrop_nullifier: Nullifier,
) -> eyre::Result<[u8; 32]> {
    ensure!(
        u32::try_from(zkproof.len()).is_ok(),
        "Orchard proof length exceeds u32::MAX"
    );
    let mut preimage = Vec::new();
    preimage.extend_from_slice(ORCHARD_PROOF_TAG);
    preimage.extend_from_slice(&u32::try_from(zkproof.len())?.to_le_bytes());
    preimage.extend_from_slice(zkproof);
    preimage.extend_from_slice(rk);
    match cv {
        Some(bytes) => {
            preimage.push(1);
            preimage.extend_from_slice(&bytes);
        }
        None => preimage.push(0),
    }
    match cv_sha256 {
        Some(bytes) => {
            preimage.push(1);
            preimage.extend_from_slice(&bytes);
        }
        None => preimage.push(0),
    }
    let nf: [u8; 32] = airdrop_nullifier.into();
    preimage.extend_from_slice(&nf);
    Ok(hash_bytes(&preimage))
}

/// Hash a single unsigned Sapling proof entry.
#[must_use]
pub fn hash_sapling_proof(proof: &SaplingClaimProofResult) -> [u8; 32] {
    hash_sapling_proof_fields(
        &proof.zkproof,
        &proof.rk,
        proof.cv,
        proof.cv_sha256,
        proof.airdrop_nullifier,
    )
}

/// Hash a single unsigned Orchard proof entry.
pub fn hash_orchard_proof(proof: &OrchardClaimProofResult) -> eyre::Result<[u8; 32]> {
    hash_orchard_proof_fields(
        &proof.zkproof,
        &proof.rk,
        proof.cv,
        proof.cv_sha256,
        proof.airdrop_nullifier,
    )
}

/// Hash the proof fields of a signed Sapling claim entry.
#[must_use]
pub fn hash_sapling_signed_claim_proof(claim: &SaplingSignedClaim) -> [u8; 32] {
    hash_sapling_proof_fields(
        &claim.zkproof,
        &claim.rk,
        claim.cv,
        claim.cv_sha256,
        claim.airdrop_nullifier,
    )
}

/// Hash the proof fields of a signed Orchard claim entry.
pub fn hash_orchard_signed_claim_proof(claim: &OrchardSignedClaim) -> eyre::Result<[u8; 32]> {
    hash_orchard_proof_fields(
        &claim.zkproof,
        &claim.rk,
        claim.cv,
        claim.cv_sha256,
        claim.airdrop_nullifier,
    )
}

/// Build the 32-byte message signed by spend authorization keys.
///
/// Preimage layout:
/// `ZAIR_SIG_V1 || version:u8 || pool:u8 || target_id_len:u8 || target_id || proof_hash ||
/// message_hash`
pub fn signature_digest(
    pool: Pool,
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
    use crate::commands::claim_proofs::{OrchardClaimProofResult, SaplingClaimProofResult};

    #[test]
    fn sapling_proof_hash_is_deterministic_and_sensitive_to_field_changes() {
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
        let h0 = hash_sapling_proof(&p0);
        let h0_again = hash_sapling_proof(&p0);
        let h1 = hash_sapling_proof(&p1);
        assert_eq!(h0, h0_again);
        assert_ne!(h0, h1);
    }

    #[test]
    fn orchard_proof_hash_is_deterministic_and_sensitive_to_length() {
        let p0 = OrchardClaimProofResult {
            zkproof: vec![1_u8; 5],
            rk: [2_u8; 32],
            cv: Some([3_u8; 32]),
            cv_sha256: None,
            airdrop_nullifier: Nullifier::from([4_u8; 32]),
        };
        let p1 = OrchardClaimProofResult {
            zkproof: vec![1_u8; 6],
            rk: [2_u8; 32],
            cv: Some([3_u8; 32]),
            cv_sha256: None,
            airdrop_nullifier: Nullifier::from([4_u8; 32]),
        };
        let h0 = hash_orchard_proof(&p0).expect("hash should succeed");
        let h0_again = hash_orchard_proof(&p0).expect("hash should succeed");
        let h1 = hash_orchard_proof(&p1).expect("hash should succeed");
        assert_eq!(h0, h0_again);
        assert_ne!(h0, h1);
    }
}
