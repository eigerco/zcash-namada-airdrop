//! Non-membership Merkle tree utilities.

mod core;
mod gap_tree;
mod node;
mod pool;
mod sparse;

pub use core::{MerklePathError, TreePosition};

pub use gap_tree::{
    OrchardGapTree, SaplingGapTree, map_orchard_user_positions, map_sapling_user_positions,
};
pub use node::{NON_MEMBERSHIP_TREE_DEPTH, NonMembershipNode};
pub use sparse::{NonMembershipTree, OrchardNonMembershipTree};
