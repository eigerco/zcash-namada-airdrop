/// Minimal version - Find user notes without database
///
/// This is a standalone module that scans Zcash blocks for user notes.
use eyre::{Result, WrapErr as _};
use orchard::keys::{
    FullViewingKey as OrchardFvk, PreparedIncomingViewingKey as OrchardPivk, Scope,
};
use orchard::note::{ExtractedNoteCommitment, Nullifier};
use orchard::note_encryption::{CompactAction, OrchardDomain};
use sapling_crypto::keys::FullViewingKey as SaplingFvk;
use sapling_crypto::note_encryption::{
    CompactOutputDescription, PreparedIncomingViewingKey as SaplingPivk, SaplingDomain,
};
use tonic::Request;
use tracing::{debug, error, info};
use zcash_note_encryption::{EphemeralKeyBytes, try_compact_note_decryption};
use zcash_primitives::consensus::Network;
use zcash_primitives::transaction::components::sapling::zip212_enforcement;

use crate::light_wallet_api::compact_tx_streamer_client::CompactTxStreamerClient;
use crate::light_wallet_api::{
    BlockId, BlockRange, CompactOrchardAction, CompactSaplingOutput, TreeState,
};

/// A note found for the user, with metadata
#[derive(Debug, Clone)]
pub enum FoundNote {
    Orchard {
        note: orchard::Note,
        height: u64,
        txid: Vec<u8>,
        scope: Scope,
    },
    Sapling {
        note: sapling_crypto::Note,
        height: u64,
        txid: Vec<u8>,
        position: u64, // Position in Sapling commitment tree (required for nullifier derivation)
    },
}

impl FoundNote {
    pub fn height(&self) -> u64 {
        match self {
            FoundNote::Orchard { height, .. } => *height,
            FoundNote::Sapling { height, .. } => *height,
        }
    }

    pub fn value(&self) -> u64 {
        match self {
            FoundNote::Orchard { note, .. } => note.value().inner(),
            FoundNote::Sapling { note, .. } => note.value().inner(),
        }
    }

    pub fn protocol(&self) -> &str {
        match self {
            FoundNote::Orchard { .. } => "Orchard",
            FoundNote::Sapling { .. } => "Sapling",
        }
    }

    pub fn position(&self) -> Option<u64> {
        match self {
            FoundNote::Orchard { .. } => None,
            FoundNote::Sapling { position, .. } => Some(*position),
        }
    }
}

/// Collect all spent nullifiers from the blockchain in the given block range
///
/// This scans all transactions and extracts revealed nullifiers (from spent notes).
/// Returns a HashSet for O(1) lookup when checking if a note is spent.
pub async fn collect_spent_nullifiers(
    client: &mut CompactTxStreamerClient<tonic::transport::Channel>,
    start_height: u64,
    end_height: u64,
    progress: Option<impl Fn(u64)>,
) -> Result<std::collections::HashSet<[u8; 32]>> {
    use std::collections::HashSet;

    debug!("Collecting spent nullifiers from blocks {start_height} to {end_height}...");

    // Request block range
    let mut blocks = client
        .get_block_range(Request::new(BlockRange {
            start: Some(BlockId {
                height: start_height,
                hash: vec![],
            }),
            end: Some(BlockId {
                height: end_height,
                hash: vec![],
            }),
            pool_types: vec![],
        }))
        .await
        .wrap_err_with(|| {
            format!(
                "Failed to fetch block range from lightwalletd (blocks {start_height} to {end_height})"
            )
        })?
        .into_inner();

    let mut spent_nullifiers = HashSet::new();
    let mut blocks_processed = 0;

    // Iterate through each block
    while let Some(block) = blocks
        .message()
        .await
        .wrap_err("Failed to receive next block from lightwalletd stream")?
    {
        let height = block.height;
        blocks_processed += 1;

        // Optional progress callback
        if let Some(ref progress_fn) = progress &&
            (height.is_multiple_of(1000) || height == end_height)
        {
            progress_fn(height);
        }

        // Process each transaction in the block
        for tx in block.vtx {
            // Extract Orchard nullifiers (from spent notes)
            for action in tx.actions {
                if action.nullifier.len() == 32 {
                    let nullifier: [u8; 32] = action.nullifier.as_slice().try_into().unwrap();
                    spent_nullifiers.insert(nullifier);
                }
            }

            // Extract Sapling nullifiers (from spent notes)
            for spend in tx.spends {
                if spend.nf.len() == 32 {
                    let nullifier: [u8; 32] = spend.nf.as_slice().try_into().unwrap();
                    spent_nullifiers.insert(nullifier);
                }
            }
        }
    }

    debug!("Nullifier collection complete!");
    debug!("Blocks processed: {blocks_processed}");
    debug!("Total spent nullifiers found: {}", spent_nullifiers.len());

    Ok(spent_nullifiers)
}

/// Get the tree state at a specific block height
///
/// Returns the tree state which includes commitment tree information for both Sapling and Orchard
pub async fn get_tree_state(
    client: &mut CompactTxStreamerClient<tonic::transport::Channel>,
    height: u64,
) -> Result<TreeState> {
    let tree_state = client
        .get_tree_state(Request::new(BlockId {
            height,
            hash: vec![],
        }))
        .await
        .wrap_err_with(|| format!("Failed to get tree state at height {height}"))?
        .into_inner();

    Ok(tree_state)
}

/// Parse the Sapling tree size from the hex-encoded tree state
///
/// The Sapling tree state is encoded as a hex string. The first few bytes encode
/// the tree size (number of leaves/notes in the commitment tree).
///
/// This uses the Frontier encoding format where the size is encoded as a compact_size at the start.
fn parse_sapling_tree_size(sapling_tree_hex: &str) -> Result<u64> {
    let bytes =
        hex::decode(sapling_tree_hex).wrap_err("Failed to decode Sapling tree state from hex")?;

    if bytes.is_empty() {
        return Ok(0);
    }

    // The tree state starts with a compact_size encoding of the number of leaves
    // Compact size format:
    // - If first byte < 0xfd: that's the size (1 byte)
    // - If first byte == 0xfd: next 2 bytes are the size (little-endian)
    // - If first byte == 0xfe: next 4 bytes are the size (little-endian)
    // - If first byte == 0xff: next 8 bytes are the size (little-endian)

    let first_byte = bytes[0];

    let size = if first_byte < 0xfd {
        first_byte as u64
    } else if first_byte == 0xfd {
        if bytes.len() < 3 {
            return Err(eyre::eyre!(
                "Invalid tree state: not enough bytes for fd compact size"
            ));
        }
        u16::from_le_bytes([bytes[1], bytes[2]]) as u64
    } else if first_byte == 0xfe {
        if bytes.len() < 5 {
            return Err(eyre::eyre!(
                "Invalid tree state: not enough bytes for fe compact size"
            ));
        }
        u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as u64
    } else {
        // first_byte == 0xff
        if bytes.len() < 9 {
            return Err(eyre::eyre!(
                "Invalid tree state: not enough bytes for ff compact size"
            ));
        }
        u64::from_le_bytes([
            bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8],
        ])
    };

    Ok(size)
}

/// Find all Orchard and Sapling notes belonging to a user in a block range
pub async fn find_user_notes(
    client: &mut CompactTxStreamerClient<tonic::transport::Channel>,
    start_height: u64,
    end_height: u64,
    orchard_fvk: &OrchardFvk,
    sapling_fvk: &SaplingFvk,
    network_type: &Network,
    progress: Option<impl Fn(u64)>,
) -> Result<Vec<FoundNote>> {
    debug!("Preparing viewing keys...");

    // Prepare Orchard viewing keys for both scopes (External and Internal)
    let orchard_ivk_external = orchard_fvk.to_ivk(Scope::External);
    let orchard_pivk_external = OrchardPivk::new(&orchard_ivk_external);

    let orchard_ivk_internal = orchard_fvk.to_ivk(Scope::Internal);
    let orchard_pivk_internal = OrchardPivk::new(&orchard_ivk_internal);

    // Prepare Sapling viewing key
    let sapling_ivk = sapling_fvk.vk.ivk();
    let sapling_pivk = SaplingPivk::new(&sapling_ivk);

    // Get tree state at the block before our scan to calculate correct absolute positions
    debug!(
        "Getting tree state at block {} to determine position offset...",
        start_height.saturating_sub(1)
    );
    let initial_sapling_position = if start_height > 0 {
        match get_tree_state(client, start_height - 1).await {
            Ok(tree_state) => match parse_sapling_tree_size(&tree_state.sapling_tree) {
                Ok(size) => {
                    info!(
                        "Sapling tree size at block {}: {} notes",
                        start_height - 1,
                        size
                    );
                    size
                }
                Err(e) => {
                    info!(
                        "Could not parse Sapling tree size ({}), starting position from 0. Nullifiers may be incorrect!",
                        e
                    );
                    0
                }
            },
            Err(e) => {
                info!(
                    "Could not get tree state ({}), starting position from 0. Nullifiers may be incorrect!",
                    e
                );
                0
            }
        }
    } else {
        0
    };

    debug!("Requesting blocks from {start_height} to {end_height}...",);

    // Request block range
    let mut blocks = client
        .get_block_range(Request::new(BlockRange {
            start: Some(BlockId {
                height: start_height,
                hash: vec![],
            }),
            end: Some(BlockId {
                height: end_height,
                hash: vec![],
            }),
            pool_types: vec![],
        }))
        .await
        .wrap_err_with(|| {
            format!(
                "Failed to fetch block range from lightwalletd (blocks {start_height} to {end_height})"
            )
        })?
        .into_inner();

    let mut found_notes = Vec::new();
    let mut blocks_processed = 0;
    let mut orchard_actions_processed = 0;

    // Separate position counters for each commitment tree
    // Sapling position MUST be absolute (from Sapling activation) for correct nullifier derivation
    let mut sapling_position = initial_sapling_position;

    debug!("Scanning blocks...");

    // Iterate through each block
    while let Some(block) = blocks
        .message()
        .await
        .wrap_err("Failed to receive next block from lightwalletd stream")?
    {
        let height = block.height;
        blocks_processed += 1;

        // Optional progress callback
        if let Some(ref progress_fn) = progress &&
            (height.is_multiple_of(1000) || height == end_height)
        {
            progress_fn(height);
        }

        // Process each transaction in the block
        for tx in block.vtx {
            let txid = tx.txid.clone();

            // Process each Orchard action in the transaction
            for action in tx.actions {
                orchard_actions_processed += 1;

                // Debug: print that we're processing an action
                if height.is_multiple_of(10000) && orchard_actions_processed % 100 == 0 {
                    debug!(
                        "  Processed {} Orchard actions so far at block {}",
                        orchard_actions_processed, height
                    );
                }

                // Helper to process decryption results
                let process_orchard = |pivk, scope: Scope| {
                    try_decrypt_orchard_output(pivk, &action)
                        .inspect_err(|e| error!("  Error decrypting with {scope:?} scope: {e}"))
                        .ok()
                        .flatten()
                        .map(|note| {
                            info!(
                                "  ✓ Found note ({scope:?}) at height {height} with value {}",
                                note.value().inner()
                            );
                            FoundNote::Orchard {
                                note,
                                height,
                                txid: txid.clone(),
                                scope,
                            }
                        })
                };

                // Try both External and Internal scopes
                found_notes.extend(
                    [
                        process_orchard(&orchard_pivk_external, Scope::External),
                        process_orchard(&orchard_pivk_internal, Scope::Internal),
                    ]
                    .into_iter()
                    .flatten(),
                );
            }

            // Process each Sapling output in the transaction
            for output in tx.outputs {
                // Try to decrypt Sapling output
                match try_decrypt_sapling_output(&sapling_pivk, &output, height, network_type) {
                    Ok(Some(note)) => {
                        info!(
                            "  ✓ Found Sapling note at height {height} with value {}",
                            note.value().inner()
                        );
                        found_notes.push(FoundNote::Sapling {
                            note,
                            height,
                            txid: txid.clone(),
                            position: sapling_position,
                        });
                    }
                    Ok(None) => {
                        // Note didn't decrypt - this is normal
                    }
                    Err(e) => {
                        error!("  Error decrypting Sapling output: {e}");
                    }
                }

                sapling_position += 1;
            }
        }
    }

    debug!("Scanning complete!");
    debug!("Blocks processed: {blocks_processed}",);
    debug!("Orchard actions processed: {orchard_actions_processed}");
    debug!("Total notes found: {}", found_notes.len());

    Ok(found_notes)
}

/// Try to decrypt an Orchard action with the given viewing key
fn try_decrypt_orchard_output(
    pivk: &OrchardPivk,
    action: &CompactOrchardAction,
) -> Result<Option<orchard::Note>> {
    // Extract action components - return None if any component is invalid
    let nf_option = Nullifier::from_bytes(&as_byte256(&action.nullifier));
    if nf_option.is_none().into() {
        // Invalid nullifier, skip this action
        return Ok(None);
    }
    let nf = nf_option.unwrap();

    let cmx_option = ExtractedNoteCommitment::from_bytes(&as_byte256(&action.cmx));
    if cmx_option.is_none().into() {
        // Invalid commitment, skip this action
        return Ok(None);
    }
    let cmx = cmx_option.unwrap();

    let ephemeral_key = EphemeralKeyBytes(as_byte256(&action.ephemeral_key));

    let ciphertext: [u8; 52] = match action.ciphertext.clone().try_into() {
        Ok(c) => c,
        Err(_) => {
            // Wrong ciphertext length, skip this action
            return Ok(None);
        }
    };

    // Create compact action - the domain is derived from it
    let compact_action = CompactAction::from_parts(nf, cmx, ephemeral_key, ciphertext);
    let domain = OrchardDomain::for_compact_action(&compact_action);

    // Attempt decryption
    let note =
        try_compact_note_decryption(&domain, pivk, &compact_action).map(|(note, _addr)| note);

    Ok(note)
}

/// Try to decrypt a Sapling output with the given viewing key
fn try_decrypt_sapling_output(
    pivk: &SaplingPivk,
    output: &CompactSaplingOutput,
    height: u64,
    network_type: &Network,
) -> Result<Option<sapling_crypto::Note>> {
    // Extract output components
    let cmu_bytes = match output.cmu.as_slice().try_into() {
        Ok(bytes) => bytes,
        Err(_) => return Ok(None),
    };
    let cmu = sapling_crypto::note::ExtractedNoteCommitment::from_bytes(&cmu_bytes);
    if cmu.is_none().into() {
        return Ok(None);
    }

    let ephemeral_key = EphemeralKeyBytes(match output.ephemeral_key.as_slice().try_into() {
        Ok(bytes) => bytes,
        Err(_) => return Ok(None),
    });

    let enc_ciphertext: [u8; 52] = match output.ciphertext.clone().try_into() {
        Ok(c) => c,
        Err(_) => return Ok(None),
    };

    // Create compact output
    let compact_output = CompactOutputDescription {
        cmu: cmu.unwrap(),
        ephemeral_key,
        enc_ciphertext,
    };

    // Determine ZIP 212 enforcement based on height
    let zip212_enforcement = zip212_enforcement(
        network_type,
        zcash_primitives::consensus::BlockHeight::from_u32(
            height
                .try_into()
                .wrap_err_with(|| format!("Block height {height} exceeds u32::MAX"))?,
        ),
    );

    let domain = SaplingDomain::new(zip212_enforcement);

    // Attempt decryption
    let note =
        try_compact_note_decryption(&domain, pivk, &compact_output).map(|(note, _addr)| note);

    Ok(note)
}

/// Helper to convert slice to 32-byte array
fn as_byte256(h: &[u8]) -> [u8; 32] {
    let mut hh = [0u8; 32];
    hh.copy_from_slice(h);
    hh
}

/// Derive the nullifier for an Orchard note
///
/// # Arguments
/// - `note`: The Orchard note
/// - `fvk`: The Orchard Full Viewing Key
///
/// # Returns
/// The 32-byte nullifier for this note
///
/// # How it works
/// The Orchard library's `note.nullifier(fvk)` method computes:
/// nf = DeriveNullifier(nk, rho, psi, cm)
/// where nk (nullifier key) is derived internally from the full viewing key.
///
/// Unlike Sapling, Orchard does not require the note's position in the commitment tree
/// because it uses the note's internal rho (nullifier) and psi (randomness) values
/// which are part of the note itself.
///
/// This is what gets revealed on-chain when the note is spent.
pub fn derive_orchard_nullifier(
    note: &orchard::Note,
    fvk: &orchard::keys::FullViewingKey,
) -> [u8; 32] {
    // The orchard library provides a direct method to compute the nullifier
    // All the complex cryptography (using rho, psi, and nullifier key) is handled internally
    let mut nullifier = note.nullifier(fvk).to_bytes();

    // Reverse bytes to match the byte order used in compact blocks
    // The nullifier computation returns bytes in one order, but compact blocks use the reverse
    nullifier.reverse();
    nullifier
}

/// Derive the nullifier for a Sapling note
///
/// # Arguments
/// - `note`: The Sapling note
/// - `fvk`: The Sapling Full Viewing Key
/// - `position`: The note's position in the Sapling commitment tree (REQUIRED for Sapling)
///
/// # Returns
/// The 32-byte nullifier for this note
///
/// # How it works
/// Unlike Orchard, Sapling requires the note's position in the commitment tree to compute the
/// nullifier. The computation is: nf = PRF_nf(nk, rho) where:
/// - nk is the nullifier key (derived from the FVK)
/// - rho is derived from the note commitment and the position
///
/// This is what gets revealed on-chain when the note is spent.
pub fn derive_sapling_nullifier(
    note: &sapling_crypto::Note,
    fvk: &SaplingFvk,
    position: u64,
) -> [u8; 32] {
    // Derive the nullifier key from the FVK
    let nk = fvk.vk.nk;

    // Compute the nullifier
    // For Sapling, the nullifier is PRF_nf(nk, rho) where rho is derived from the note
    // The position is used directly (u64) without conversion
    let mut nullifier = note.nf(&nk, position).0;

    // Reverse bytes to match the byte order used in compact blocks
    // The nullifier computation returns bytes in one order, but compact blocks use the reverse
    nullifier.reverse();
    nullifier
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nullifier_is_deterministic() {
        // This test verifies that deriving a nullifier multiple times
        // produces the same result (determinism is critical!)
        //
        // Note: We can't easily test this without setting up full keys and notes,
        // but the test structure is here for when we have test vectors
    }
}
