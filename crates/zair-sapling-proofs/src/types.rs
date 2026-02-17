//! Types shared between proving and verifying.

/// Groth16 proof size in bytes (2 G1 points + 1 G2 point = 2*48 + 96 = 192).
pub const GROTH_PROOF_SIZE: usize = 192;

/// Groth16 proof bytes.
pub type GrothProofBytes = [u8; GROTH_PROOF_SIZE];

/// Which value commitment scheme is exposed by the claim proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueCommitmentScheme {
    /// Expose native Sapling value commitment.
    Native,
    /// Expose SHA-256 value commitment.
    Sha256,
}

#[cfg(feature = "prove")]
impl From<ValueCommitmentScheme> for zair_sapling_circuit::ValueCommitmentScheme {
    fn from(scheme: ValueCommitmentScheme) -> Self {
        match scheme {
            ValueCommitmentScheme::Native => Self::Native,
            ValueCommitmentScheme::Sha256 => Self::Sha256,
        }
    }
}

impl From<zair_core::schema::config::ValueCommitmentScheme> for ValueCommitmentScheme {
    fn from(scheme: zair_core::schema::config::ValueCommitmentScheme) -> Self {
        match scheme {
            zair_core::schema::config::ValueCommitmentScheme::Native => Self::Native,
            zair_core::schema::config::ValueCommitmentScheme::Sha256 => Self::Sha256,
        }
    }
}

/// Input data required to generate a claim proof (raw bytes format).
///
/// This struct provides a convenient way to pass proof inputs as raw bytes,
/// which is useful when reading from JSON files or network protocols.
#[derive(Debug, Clone)]
pub struct ClaimProofInputs {
    /// Diversifier (11 bytes)
    pub diversifier: [u8; 11],
    /// Diversified transmission key `pk_d` (32 bytes)
    pub pk_d: [u8; 32],
    /// Note value in zatoshis
    pub value: u64,
    /// Note commitment randomness rcm (32 bytes)
    pub rcm: [u8; 32],
    /// Authorization key ak (32 bytes)
    pub ak: [u8; 32],
    /// Position of the note in the commitment tree
    pub position: u64,
    /// Merkle proof path (32 siblings for depth-32 tree)
    pub merkle_path: Vec<[u8; 32]>,
    /// Expected note-commitment root (Sapling anchor) for this claim.
    pub anchor: [u8; 32],
    /// The hiding nullifier (computed externally via sapling's `nf_hiding`)
    pub hiding_nf: [u8; 32],
    /// Left nullifier bound of the non-membership gap
    pub nm_left_nf: [u8; 32],
    /// Right nullifier bound of the non-membership gap
    pub nm_right_nf: [u8; 32],
    /// Non-membership merkle path (siblings and position flags)
    pub nm_merkle_path: Vec<([u8; 32], bool)>,
    /// Non-membership tree root
    pub nm_anchor: [u8; 32],
    /// Which value commitment scheme to prove.
    pub value_commitment_scheme: ValueCommitmentScheme,
}

/// Output from generating a claim proof.
///
/// Note: The Zcash nullifier is NOT included to preserve privacy.
/// The circuit proves knowledge of the nullifier without exposing it.
/// The hiding nullifier IS included for airdrop double-claim prevention.
#[derive(Debug, Clone)]
pub struct ClaimProofOutput {
    /// The Groth16 proof (192 bytes)
    pub zkproof: GrothProofBytes,
    /// The re-randomized spend verification key (rk)
    pub rk: [u8; 32],
    /// The native value commitment (cv), if this proof uses the native scheme.
    pub cv: Option<[u8; 32]>,
    /// The SHA-256 value commitment (`cv_sha256`), if this proof uses the `sha256` scheme.
    pub cv_sha256: Option<[u8; 32]>,
    /// The hiding nullifier (airdrop-specific, 32 bytes)
    pub hiding_nf: [u8; 32],
}

/// Local-only randomness material produced while generating a claim proof.
#[derive(Debug, Clone)]
pub struct ClaimProofSecretMaterial {
    /// Spend authorization randomizer used for rk/signature binding.
    pub alpha: [u8; 32],
    /// Randomness for the native commitment.
    pub rcv: Option<[u8; 32]>,
    /// Randomness for the sha256 commitment.
    pub rcv_sha256: Option<[u8; 32]>,
}
