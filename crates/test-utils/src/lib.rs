//! Shared test utilities for the workspace.

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
