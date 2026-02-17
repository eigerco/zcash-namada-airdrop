//! Submission/signature schema models.

use serde::{Deserialize, Serialize};
use serde_with::hex::Hex;
use serde_with::serde_as;

use crate::base::Nullifier;

/// Proof pool selector for signing/verification context.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SubmissionPool {
    /// Sapling claim proof/signature flow.
    Sapling,
    /// Orchard claim proof/signature flow.
    Orchard,
}

impl SubmissionPool {
    /// Encoded pool byte used in signature digest preimages.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Sapling => 0,
            Self::Orchard => 1,
        }
    }
}

/// A signed Sapling claim entry ready for target-chain submission.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaplingSignedClaim {
    /// The Groth16 proof bytes.
    #[serde_as(as = "Hex")]
    pub zkproof: [u8; 192],
    /// The re-randomized spend verification key.
    #[serde_as(as = "Hex")]
    pub rk: [u8; 32],
    /// Native value commitment bytes, if the active scheme is native.
    #[serde_as(as = "Option<Hex>")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cv: Option<[u8; 32]>,
    /// SHA-256 value commitment bytes, if the active scheme is sha256.
    #[serde_as(as = "Option<Hex>")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cv_sha256: Option<[u8; 32]>,
    /// Airdrop nullifier used for double-claim prevention.
    pub airdrop_nullifier: Nullifier,
    /// Spend authorization signature over the submission digest.
    #[serde_as(as = "Hex")]
    pub spend_auth_sig: [u8; 64],
}

/// Signed proof bundle and digest context for submission.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimSubmission {
    /// Pool this submission applies to.
    pub pool: SubmissionPool,
    /// Target domain identifier from airdrop configuration.
    pub target_id: String,
    /// Hash of the unsigned proof bundle.
    #[serde_as(as = "Hex")]
    pub proof_hash: [u8; 32],
    /// Hash of external message bytes.
    #[serde_as(as = "Hex")]
    pub message_hash: [u8; 32],
    /// Signed Sapling claims.
    pub sapling: Vec<SaplingSignedClaim>,
    /// Signed Orchard claims (not implemented yet).
    pub orchard: Vec<()>,
}
