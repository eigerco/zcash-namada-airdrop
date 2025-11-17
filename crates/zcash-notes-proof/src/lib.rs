mod find_user_notes_minimal;

pub use find_user_notes_minimal::{
    FoundNote, collect_spent_nullifiers, derive_orchard_nullifier, derive_sapling_nullifier,
    find_user_notes, get_tree_state,
};

pub mod light_wallet_api {
    // Re-export the generated types
    tonic::include_proto!("cash.z.wallet.sdk.rpc");
}
