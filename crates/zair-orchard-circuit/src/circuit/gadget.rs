//! Thin re-exports of upstream Orchard circuit gadgets used by the airdrop circuit.

pub use orchard::circuit::gadget::add_chip::{AddChip, AddConfig};
pub use orchard::circuit::gadget::{
    AddInstruction, assign_free_advice, commit_ivk, derive_nullifier, note_commit,
    value_commit_orchard,
};
