use std::ops::RangeInclusive;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::hex::Hex;
use serde_with::serde_as;

use crate::base::ReversedHex;

/// Configuration for an airdrop, including snapshot range and Merkle roots and the hiding factors
/// for each Zcash pool.
#[derive(Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub struct AirdropConfiguration {
    /// The inclusive range of block heights for the snapshot.
    pub snapshot_range: RangeInclusive<u64>,
    /// The non-membership tree roots for Sapling and Orchard nullifiers.
    pub non_membership_tree_anchors: NonMembershipTreeAnchors,
    /// The commitment tree anchors for Sapling and Orchard pools at snapshot height.
    pub note_commitment_tree_anchors: CommitmentTreeAnchors,
    /// Hiding factor for nullifiers.
    #[serde(default)]
    pub hiding_factor: HidingFactor,
}

/// Commitment tree anchors for Sapling and Orchard pools.
#[serde_as]
#[derive(Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq, Clone)]
pub struct CommitmentTreeAnchors {
    /// Sapling commitment tree anchor.
    #[serde_as(as = "ReversedHex")]
    #[schemars(with = "String")]
    pub sapling: [u8; 32],
    /// Orchard commitment tree anchor.
    #[serde_as(as = "Hex")]
    #[schemars(with = "String")]
    pub orchard: [u8; 32],
}

/// Non-membership tree roots for Sapling and Orchard nullifiers.
#[serde_as]
#[derive(Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq, Clone)]
pub struct NonMembershipTreeAnchors {
    /// Sapling non-membership tree root.
    #[serde_as(as = "Hex")]
    #[schemars(with = "String")]
    pub sapling: [u8; 32],
    /// Orchard non-membership tree root.
    #[serde_as(as = "Hex")]
    #[schemars(with = "String")]
    pub orchard: [u8; 32],
}

/// Hiding factor for hiding-nullifier derivation.
#[derive(Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq, Default)]
pub struct HidingFactor {
    /// Hiding factor for Sapling hiding-nullifiers.
    pub sapling: SaplingHidingFactor,
    /// Hiding factor for Orchard hiding-nullifiers.
    pub orchard: OrchardHidingFactor,
}

/// Sapling hiding factor.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, PartialEq, Eq, Default)]
pub struct SaplingHidingFactor {
    /// Personalization bytes, are used to derive the hiding sapling nullifier.
    pub personalization: String,
}

/// Orchard hiding factor.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, PartialEq, Eq, Default)]
pub struct OrchardHidingFactor {
    /// Domain separator for the hiding orchard nullifier.
    pub domain: String,
    /// Tag bytes, are used to derive the hiding orchard nullifier.
    pub tag: String,
}

impl AirdropConfiguration {
    /// Create a new airdrop configuration.
    #[must_use]
    pub const fn new(
        snapshot_range: RangeInclusive<u64>,
        non_membership_tree_anchors: NonMembershipTreeAnchors,
        note_commitment_tree_anchors: CommitmentTreeAnchors,
        hiding_factor: HidingFactor,
    ) -> Self {
        Self {
            snapshot_range,
            non_membership_tree_anchors,
            note_commitment_tree_anchors,
            hiding_factor,
        }
    }
}
