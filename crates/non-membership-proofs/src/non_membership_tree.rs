//! This module provides a Merkle tree using `BridgeTree`.
//!
//! # Architecture
//!
//! - **Leaves**: Created from nullifier pairs using Pedersen hash with level-based domain
//!   separation (level 62). Each leaf represents a "gap" between two adjacent nullifiers.
//!
//! - **Internal nodes**: Combined using Pedersen hash with level-based domain separation (levels
//!   0-31), matching the Zcash Sapling specification.
//!
//! - **Storage**: Uses `BridgeTree` for space efficiency - only stores data needed to generate
//!   witnesses for marked leaves.

mod node;
mod tree;

pub use node::NonMembershipNode;
pub use tree::{MerklePathError, NonMembershipTree, TreePosition};
