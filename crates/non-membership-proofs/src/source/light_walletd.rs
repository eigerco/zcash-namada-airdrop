//! Connection to lightwalletd grpc service

use std::ops::RangeInclusive;
use std::pin::Pin;

use async_stream::try_stream;
use futures_core::Stream;
use light_wallet_api::compact_tx_streamer_client::CompactTxStreamerClient;
use light_wallet_api::{BlockId, BlockRange};
use orchard::keys::FullViewingKey as OrchardFvk;
use sapling::zip32::DiversifiableFullViewingKey;
use tonic::transport::Channel;
use zcash_primitives::consensus::Parameters;

use crate::chain_nullifiers::{ChainNullifiers, PoolNullifier};
use crate::user_nullifiers::decrypt_notes::{DecryptedNote, decrypt_compact_block};
use crate::user_nullifiers::{
    AnyFoundNote, FoundNote, NoteMetadata, OrchardViewingKeys, SaplingNote, SaplingViewingKeys,
    UserNullifiers, ViewingKeys,
};
use crate::{Nullifier, Pool};

/// Errors that can occur when interacting with lightwalletd
#[derive(Debug, thiserror::Error)]
pub enum LightWalletdError {
    /// gRPC error from lightwalletd
    #[error("gRPC: {0}")]
    Grpc(#[from] tonic::Status),
    /// Transport error connecting to lightwalletd
    #[error("Transport: {0}")]
    Transport(#[from] tonic::transport::Error),
    /// Invalid nullifier length
    #[error("Invalid nullifier length: expected 32, got {0}")]
    InvalidLength(usize),
}

/// A lightwalletd client
pub struct LightWalletd {
    client: CompactTxStreamerClient<Channel>,
}

impl LightWalletd {
    /// Connect to a lightwalletd endpoint
    ///
    /// Prerequisite:
    /// rustls::crypto::ring::default_provider().install_default() needs to be called before this
    /// function is called.
    pub async fn connect(endpoint: &str) -> Result<Self, LightWalletdError> {
        let client = CompactTxStreamerClient::connect(endpoint.to_string()).await?;

        Ok(Self { client })
    }
}

/// Read nullifiers from a lightwalletd via gRPC.
///
/// # Cancellation
///
/// The stream can be cancelled by dropping it. The underlying gRPC connection
/// will be closed, though the server may continue processing briefly until it
/// detects the disconnect. No explicit cancellation signal is sent.
impl ChainNullifiers for LightWalletd {
    type Error = LightWalletdError;
    type Stream = Pin<Box<dyn Stream<Item = Result<PoolNullifier, Self::Error>> + Send>>;

    fn into_nullifiers_stream(&self, range: &RangeInclusive<u64>) -> Self::Stream {
        let request = BlockRange {
            start: Some(BlockId {
                height: *range.start(),
                hash: vec![],
            }),
            end: Some(BlockId {
                height: *range.end(),
                hash: vec![],
            }),
            pool_types: vec![],
        };

        let mut client = self.client.clone();

        Box::pin(try_stream! {
            let mut stream = client
                .get_block_range(request)
                .await?
                .into_inner();

            while let Some(block) = stream.message().await? {
                for tx in block.vtx {
                    // Sapling nullifiers
                    for spend in tx.spends {
                        let nullifier: Nullifier = spend.nf
                            .try_into()
                            .map_err(|v: Vec<u8>| LightWalletdError::InvalidLength(v.len()))?;

                        yield PoolNullifier {
                            pool: Pool::Sapling,
                            nullifier,
                        };
                    }

                    // Orchard nullifiers
                    for action in tx.actions {
                        let nullifier: Nullifier = action.nullifier
                            .try_into()
                            .map_err(|v: Vec<u8>| LightWalletdError::InvalidLength(v.len()))?;

                        yield PoolNullifier {
                            pool: Pool::Orchard,
                            nullifier,
                        };
                    }
                }
            }
        })
    }
}

impl UserNullifiers for LightWalletd {
    type Error = LightWalletdError;
    type Stream = Pin<Box<dyn Stream<Item = Result<AnyFoundNote, Self::Error>> + Send>>;

    fn user_nullifiers<P: Parameters + Clone + Send + 'static>(
        &self,
        network: &P,
        start_height: u64,
        end_height: u64,
        orchard_fvk: &OrchardFvk,
        sapling_fvk: &DiversifiableFullViewingKey,
    ) -> Self::Stream {
        let network = network.clone();
        let request = BlockRange {
            start: Some(BlockId {
                height: start_height,
                hash: vec![],
            }),
            end: Some(BlockId {
                height: end_height,
                hash: vec![],
            }),
            pool_types: vec![],
        };

        let mut client = self.client.clone();

        let sapling_viewing_keys = SaplingViewingKeys::from_dfvk(sapling_fvk);
        let orchard_viewing_keys = OrchardViewingKeys::from_fvk(orchard_fvk);

        let keys = ViewingKeys {
            sapling: Some(sapling_viewing_keys),
            orchard: Some(orchard_viewing_keys),
        };

        Box::pin(try_stream! {
            let mut stream = client
                .get_block_range(request)
                .await?
                .into_inner();

            while let Some(block) = stream.message().await? {
                // Get the Sapling commitment tree size at the END of this block
                // This is reported in chain_metadata
                // TODO: validate this
                let sapling_tree_size_end = block
                    .chain_metadata
                    .as_ref()
                    .map(|m| m.sapling_commitment_tree_size)
                    .unwrap_or(0);

                // TODO: check block in place from tokio
                // request multithread run time
                let notes = decrypt_compact_block(&network, &block, &keys);

                // Build a map of cumulative Sapling outputs per transaction
                // This helps us calculate the position of each output in the commitment tree
                let mut tx_sapling_start_positions: Vec<u32> = Vec::with_capacity(block.vtx.len());
                let mut cumulative = 0u32;
                for tx in &block.vtx {
                    tx_sapling_start_positions.push(cumulative);
                    cumulative += tx.outputs.len() as u32;
                }

                // The tree size at the start of the block is the end size minus all outputs in this block
                let sapling_tree_size_start = sapling_tree_size_end.saturating_sub(cumulative);

                for note in notes {
                    match note {
                        DecryptedNote::Orchard(orchard_note) => {
                            let txid = block.vtx.get(orchard_note.tx_index)
                                .map(|tx| tx.txid.clone())
                                .unwrap_or_else(|| block.hash.clone());

                            yield AnyFoundNote::Orchard(FoundNote::<orchard::Note> {
                                note: orchard_note.note,
                                metadata: NoteMetadata {
                                    height: block.height,
                                    txid,
                                    scope: orchard_note.scope,
                                },
                            });
                        }
                        DecryptedNote::Sapling(sapling_note) => {
                            // Calculate the note's position in the global Sapling commitment tree
                            // Position = tree_size_at_block_start + outputs_before_this_tx + output_index
                            let tx_start = tx_sapling_start_positions
                                .get(sapling_note.tx_index)
                                .copied()
                                .unwrap_or(0);
                            let position = sapling_tree_size_start as u64
                                + tx_start as u64
                                + sapling_note.output_index as u64;

                            let txid = block.vtx.get(sapling_note.tx_index)
                                .map(|tx| tx.txid.clone())
                                .unwrap_or_else(|| block.hash.clone());

                            yield AnyFoundNote::Sapling(FoundNote::<SaplingNote> {
                                note: SaplingNote {
                                    note: sapling_note.note,
                                    position,
                                },
                                metadata: NoteMetadata {
                                    height: block.height,
                                    txid,
                                    scope: sapling_note.scope,
                                },
                            });
                        }
                    }
                }
            }
        })
    }
}
