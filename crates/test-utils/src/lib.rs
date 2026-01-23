//! Shared test utilities for the workspace.

/// Helper macro to create a nullifier byte array with a specific last byte.
///
/// Returns `[u8; 32]` which can be converted to `Nullifier` via `.into()`.
#[macro_export]
macro_rules! nf {
    ($v:expr) => {{
        let mut arr = [0_u8; 32];
        arr[31] = $v;
        arr.into()
    }};
}

/// Helper macro to create a sorted vector of nullifier byte arrays.
///
/// Returns items that can be converted to `Nullifier` via `.into()`.
#[macro_export]
macro_rules! nfs {
    ($($v:expr),* $(,)?) => {{
        let mut v = vec![$( $crate::nf!($v) ),*];
        v.sort();
        v
    }};
}
