//! Types shared between proving and verifying.

/// Groth16 proof size in bytes (2 G1 points + 1 G2 point = 2*48 + 96 = 192).
pub const GROTH_PROOF_SIZE: usize = 192;

/// Groth16 proof bytes.
pub type GrothProofBytes = [u8; GROTH_PROOF_SIZE];

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
}

/// Output from generating a claim proof.
///
/// Note: The Zcash nullifier is NOT included to preserve privacy.
/// The circuit proves knowledge of the nullifier without exposing it.
/// The hiding nullifier IS included for airdrop double-claim prevention.
/// The `nm_anchor` IS included for non-membership verification.
#[derive(Debug, Clone)]
pub struct ClaimProofOutput {
    /// The Groth16 proof (192 bytes)
    pub zkproof: GrothProofBytes,
    /// The re-randomized spend verification key (rk)
    pub rk: [u8; 32],
    /// The value commitment (cv)
    pub cv: [u8; 32],
    /// The anchor (merkle tree root)
    pub anchor: [u8; 32],
    /// The hiding nullifier (airdrop-specific, 32 bytes)
    pub hiding_nf: [u8; 32],
    /// The non-membership tree root
    pub nm_anchor: [u8; 32],
}
