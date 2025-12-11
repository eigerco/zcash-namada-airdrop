//! Note decryption module for Zcash CompactBlocks
//!
//! Decrypts Sapling and Orchard notes from lightwalletd CompactBlocks
//! using the provided viewing keys.

use light_wallet_api::{CompactBlock, CompactOrchardAction, CompactSaplingOutput, CompactTx};
use orchard::keys::{FullViewingKey as OrchardFvk, PreparedIncomingViewingKey as OrchardPivk};
use orchard::note::{Note as OrchardNote, Nullifier as OrchardNullifier};
use orchard::note_encryption::{CompactAction, OrchardDomain};
use sapling::NullifierDerivingKey;
use sapling::note_encryption::{
    CompactOutputDescription, PreparedIncomingViewingKey as SaplingPivk, SaplingDomain,
    Zip212Enforcement,
};
use sapling::zip32::DiversifiableFullViewingKey as SaplingDfvk;
use zcash_note_encryption::{EphemeralKeyBytes, batch};
use zcash_primitives::consensus::{BlockHeight, Parameters};
use zcash_primitives::transaction::components::sapling::zip212_enforcement;
use zip32::Scope;

/// A decrypted note from either the Sapling or Orchard pool
#[derive(Debug, Clone)]
pub(crate) enum DecryptedNote {
    Sapling(DecryptedSaplingNote),
    Orchard(DecryptedOrchardNote),
}

#[derive(Debug, Clone)]
pub(crate) struct DecryptedSaplingNote {
    pub tx_index: usize,
    pub output_index: usize,
    pub note: sapling::Note,
    pub scope: Scope,
}

#[derive(Debug, Clone)]
pub(crate) struct DecryptedOrchardNote {
    pub tx_index: usize,
    pub note: OrchardNote,
    pub scope: Scope,
}

// TODO: check the documentation comments below

/// Viewing keys for decryption and nullifier derivation
///
/// Provide both external (for receiving) and internal (for change) keys
pub struct SaplingViewingKeys {
    /// External viewing key for external scope (needed for note decryption)
    /// External scope is used for incoming payments.
    /// When we receive ZEC, the note is encrypted to the external ivk.
    pub external: SaplingPivk,
    /// Internal viewing key for internal scope (needed for note decryption)
    /// Internal scope is used for change outputs.
    /// When we send ZEC, any change is sent to an address derived from the internal ivk and the
    /// change output is encrypted to that ivk.
    pub internal: SaplingPivk,
    /// Nullifier deriving key for external scope (needed for nullifier derivation)
    pub nk_external: NullifierDerivingKey,
    /// Nullifier deriving key for internal scope (needed for nullifier derivation)
    pub nk_internal: NullifierDerivingKey,
    /// Reference to the DiversifiableFullViewingKey (needed for nullifier derivation)
    pub dfvk: SaplingDfvk,
}

/// Viewing keys for decryption and nullifier derivation for Orchard pool
pub struct OrchardViewingKeys {
    /// External viewing key for external scope (needed for note decryption)
    pub external: OrchardPivk,
    /// Internal viewing key for internal scope (needed for note decryption)
    pub internal: OrchardPivk,
    /// Full viewing key (needed for nullifier derivation)
    pub fvk: OrchardFvk,
}

/// Viewing keys for both Sapling and Orchard pools
pub struct ViewingKeys {
    /// Sapling viewing keys (if any)
    pub sapling: Option<SaplingViewingKeys>,
    /// Orchard viewing keys (if any)
    pub orchard: Option<OrchardViewingKeys>,
}

/// Decrypt all notes in a CompactBlock belonging to the given viewing keys
///
/// # Arguments
/// * `block` - The CompactBlock from lightwalletd
/// * `keys` - Viewing keys for Sapling and/or Orchard
/// * `zip212_enforcement` - ZIP-212 enforcement mode (On for blocks after Canopy)
///
/// # Returns
/// Vector of decrypted notes found in the block
pub(crate) fn decrypt_compact_block<P: Parameters>(
    params: &P,
    block: &CompactBlock,
    keys: &ViewingKeys,
) -> Vec<DecryptedNote> {
    let block_height = BlockHeight::from_u32(block.height as u32);
    let zip212 = zip212_enforcement(params, block_height);

    let mut notes = Vec::new();

    if let Some(ref sapling_keys) = keys.sapling {
        notes.extend(
            decrypt_sapling_notes(&block.vtx, sapling_keys, zip212)
                .into_iter()
                .map(DecryptedNote::Sapling),
        );
    }

    if let Some(ref orchard_keys) = keys.orchard {
        notes.extend(
            decrypt_orchard_notes(&block.vtx, orchard_keys)
                .into_iter()
                .map(DecryptedNote::Orchard),
        );
    }

    notes
}

// ============ Internal implementation ============

fn decrypt_sapling_notes(
    vtx: &[CompactTx],
    keys: &SaplingViewingKeys,
    zip212_enforcement: Zip212Enforcement,
) -> Vec<DecryptedSaplingNote> {
    let mut decrypted = Vec::new();
    // Keys and scopes
    let ivks = [keys.external.clone(), keys.internal.clone()];
    let scopes = [Scope::External, Scope::Internal];

    for (tx_index, tx) in vtx.iter().enumerate() {
        if tx.outputs.is_empty() {
            continue;
        }

        let outputs_with_domains: Vec<(SaplingDomain, CompactOutputDescription)> = tx
            .outputs
            .iter()
            .filter_map(|output| {
                let compact = proto_to_sapling_compact(output)?;
                let domain = SaplingDomain::new(zip212_enforcement);
                Some((domain, compact))
            })
            .collect();

        if outputs_with_domains.is_empty() {
            continue;
        }

        let results = batch::try_compact_note_decryption(&ivks, &outputs_with_domains);

        for (output_index, result) in results.into_iter().enumerate() {
            if let Some(((note, _), ivk_idx)) = result {
                decrypted.push(DecryptedSaplingNote {
                    tx_index,
                    output_index,
                    note,
                    scope: scopes[ivk_idx],
                });
            }
        }
    }

    decrypted
}

fn decrypt_orchard_notes(
    vtx: &[CompactTx],
    keys: &OrchardViewingKeys,
) -> Vec<DecryptedOrchardNote> {
    let mut decrypted = Vec::new();
    // Keys and scopes
    let ivks = [keys.external.clone(), keys.internal.clone()];
    let scopes = [Scope::External, Scope::Internal];

    for (tx_index, tx) in vtx.iter().enumerate() {
        if tx.actions.is_empty() {
            continue;
        }

        let actions_with_domains: Vec<(OrchardDomain, CompactAction)> = tx
            .actions
            .iter()
            .filter_map(|action| {
                let compact = proto_to_orchard_compact(action)?;
                let domain = OrchardDomain::for_compact_action(&compact);
                Some((domain, compact))
            })
            .collect();

        if actions_with_domains.is_empty() {
            continue;
        }

        let results = batch::try_compact_note_decryption(&ivks, &actions_with_domains);

        for result in results.into_iter() {
            if let Some(((note, _), ivk_idx)) = result {
                decrypted.push(DecryptedOrchardNote {
                    tx_index,
                    note,
                    scope: scopes[ivk_idx],
                });
            }
        }
    }

    decrypted
}

fn proto_to_sapling_compact(output: &CompactSaplingOutput) -> Option<CompactOutputDescription> {
    let cmu_bytes: [u8; 32] = output.cmu.as_slice().try_into().ok()?;
    let cmu = sapling::note::ExtractedNoteCommitment::from_bytes(&cmu_bytes).into_option()?;

    let epk_bytes: [u8; 32] = output.ephemeral_key.as_slice().try_into().ok()?;
    let ephemeral_key = EphemeralKeyBytes(epk_bytes);

    let enc_ciphertext: [u8; 52] = output.ciphertext.as_slice().try_into().ok()?;

    Some(CompactOutputDescription {
        cmu,
        ephemeral_key,
        enc_ciphertext,
    })
}

fn proto_to_orchard_compact(action: &CompactOrchardAction) -> Option<CompactAction> {
    let nf_bytes: [u8; 32] = action.nullifier.as_slice().try_into().ok()?;
    let nullifier = OrchardNullifier::from_bytes(&nf_bytes).into_option()?;

    let cmx_bytes: [u8; 32] = action.cmx.as_slice().try_into().ok()?;
    let cmx = orchard::note::ExtractedNoteCommitment::from_bytes(&cmx_bytes).into_option()?;

    let epk_bytes: [u8; 32] = action.ephemeral_key.as_slice().try_into().ok()?;
    let ephemeral_key = EphemeralKeyBytes(epk_bytes);

    let enc_ciphertext: [u8; 52] = action.ciphertext.as_slice().try_into().ok()?;

    Some(CompactAction::from_parts(
        nullifier,
        cmx,
        ephemeral_key,
        enc_ciphertext,
    ))
}

// ============ Helper constructors ============

impl SaplingViewingKeys {
    /// Create from a Sapling DiversifiableFullViewingKey
    pub fn from_dfvk(dfvk: &SaplingDfvk) -> Self {
        Self {
            external: SaplingPivk::new(&dfvk.to_ivk(Scope::External)),
            internal: SaplingPivk::new(&dfvk.to_ivk(Scope::Internal)),
            nk_external: dfvk.to_nk(Scope::External),
            nk_internal: dfvk.to_nk(Scope::Internal),
            dfvk: dfvk.clone(),
        }
    }

    /// Get the appropriate nullifier deriving key based on scope
    pub fn nk(&self, scope: Scope) -> &NullifierDerivingKey {
        match scope {
            Scope::External => &self.nk_external,
            Scope::Internal => &self.nk_internal,
        }
    }
}

impl OrchardViewingKeys {
    /// Create from an Orchard FullViewingKey
    pub fn from_fvk(fvk: &OrchardFvk) -> Self {
        use orchard::keys::Scope;
        Self {
            external: OrchardPivk::new(&fvk.to_ivk(Scope::External)),
            internal: OrchardPivk::new(&fvk.to_ivk(Scope::Internal)),
            fvk: fvk.clone(),
        }
    }
}
