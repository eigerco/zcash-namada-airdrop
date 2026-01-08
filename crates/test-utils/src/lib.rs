//! Shared test utilities for the workspace.

use non_membership_proofs::Nullifier;

/// Helper macro to create a nullifier with a specific last byte.
#[macro_export]
macro_rules! nf {
    ($v:expr) => {{
        let mut arr = [0_u8; 32];
        arr[31] = $v;
        arr
    }};
}

/// Helper macro to create a sorted vector of nullifiers.
#[macro_export]
macro_rules! nfs {
    ($($v:expr),* $(,)?) => {{
        let mut v = vec![$( $crate::nf!($v) ),*];
        v.sort();
        v
    }};
}

/// The minimum nullifier (all bytes zero).
pub const MIN_NF: Nullifier = [0_u8; 32];

/// The maximum nullifier (all bytes 0xFF).
pub const MAX_NF: Nullifier = [0xFF_u8; 32];
