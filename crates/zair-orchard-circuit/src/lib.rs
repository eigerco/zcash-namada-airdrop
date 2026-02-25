//! Orchard airdrop circuit components used by ZAIR proving/verification.

extern crate alloc;

pub mod circuit;

/// Re-export Orchard constants used by copied circuit gadgets.
pub mod constants {
    pub use orchard::{
        NullifierK, OrchardCommitDomains, OrchardFixedBases, OrchardFixedBasesFull,
        OrchardHashDomains, ValueCommitV,
    };
    /// Orchard Sinsemilla personalization strings used by commit gadgets.
    pub mod fixed_bases {
        /// Personalization for note commitment hash.
        pub const NOTE_COMMITMENT_PERSONALIZATION: &str = "z.cash:Orchard-NoteCommit";
        /// Personalization for incoming viewing key commitment hash.
        pub const COMMIT_IVK_PERSONALIZATION: &str = "z.cash:Orchard-CommitIvk";
    }

    /// Number of bits used for Orchard base field decomposition.
    pub const L_ORCHARD_BASE: usize = 255;
    /// Number of bits in note value encoding.
    pub const L_VALUE: usize = 64;
    /// Scalar modulus adjustment constant `q = 2^255 - T_Q`.
    pub const T_Q: u128 = 45_560_315_531_506_369_815_346_746_415_080_538_113;
    /// Orchard note commitment tree depth.
    pub const MERKLE_DEPTH_ORCHARD: usize = orchard::NOTE_COMMITMENT_TREE_DEPTH;

    /// The Pallas base field modulus is `p = 2^254 + t_p`.
    pub const T_P: u128 = 45_560_315_531_419_706_090_280_762_371_685_220_353;
}

/// Re-export Orchard note types used by the circuit witness.
pub mod note {
    pub use orchard::note::{RandomSeed, Rho};
}

/// Re-export Orchard value types used by the circuit witness.
pub mod value {
    pub use orchard::value::{NoteValue, ValueCommitTrapdoor, ValueCommitment};
}

/// Re-export Orchard anchor wrapper.
pub mod tree {
    pub use orchard::Anchor;
}
