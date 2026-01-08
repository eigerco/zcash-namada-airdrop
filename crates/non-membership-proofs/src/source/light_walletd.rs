//! Connection to lightwalletd gRPC service

mod config;
mod error;
mod utils;

use std::ops::RangeInclusive;
use std::time::Duration;

use async_stream::try_stream;
pub use config::LightWalletdConfig;
use futures::{Stream, StreamExt as _};
use tonic::transport::{Channel, ClientTlsConfig, Uri};
use tracing::warn;
use zcash_client_backend::proto::compact_formats::CompactBlock;
use zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient;
use zcash_client_backend::proto::service::{BlockId, BlockRange};
use zcash_protocol::consensus::Parameters;

use crate::chain_nullifiers::{BoxedNullifierStream, ChainNullifiers, PoolNullifier};
use crate::source::light_walletd::config::ValidatedLightWalletdConfig;
use crate::source::light_walletd::error::LightWalletdError;
use crate::source::light_walletd::utils::get_txid_or_null;
use crate::source::light_walletd::utils::retry::retry_with_backoff;
use crate::source::light_walletd::utils::sapling_positions::{
    calculate_note_position, calculate_sapling_positions,
};
use crate::user_nullifiers::decrypt_notes::{DecryptedNote, decrypt_compact_block};
use crate::user_nullifiers::{
    AnyFoundNote, BoxedNoteStream, FoundNote, NoteMetadata, SaplingNote, UserNullifiers,
    ViewingKeys,
};
use crate::{Nullifier, Pool};

/// Default connection timeout in seconds
const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 10;
/// Default request timeout in seconds
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;
/// Maximum number of retry attempts for transient errors
const MAX_RETRIES: u32 = 3;
/// Initial retry delay in milliseconds
const INITIAL_RETRY_DELAY_MS: u64 = 1000;
/// Maximum retry delay in milliseconds
const MAX_RETRY_DELAY_MS: u64 = 10000;
/// Factor for exponential backoff
const BACKOFF_FACTOR: u32 = 2;
/// Timeout for receiving stream messages in seconds
const STREAM_MESSAGE_TIMEOUT_SECS: u64 = 60;

/// A lightwalletd client
pub struct LightWalletd {
    client: CompactTxStreamerClient<Channel>,
    config: ValidatedLightWalletdConfig,
}

impl LightWalletd {
    /// Connect to a lightwalletd endpoint
    ///
    /// # Prerequisite
    ///
    /// `rustls::crypto::ring::default_provider().install_default()` needs to be called
    /// before this function is called.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection to the endpoint fails.
    pub async fn connect(endpoint: Uri) -> Result<Self, LightWalletdError> {
        Self::connect_with_config(endpoint, LightWalletdConfig::default().validate()?).await
    }

    /// Connect to lightwallerd endpoint with custom configuration
    ///
    /// # Prerequisite
    ///
    /// `rustls::crypto::ring::default_provider().install_default()` needs to be called
    /// before this function is called.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection to the endpoint fails.
    pub async fn connect_with_config(
        endpoint: Uri,
        config: ValidatedLightWalletdConfig,
    ) -> Result<Self, LightWalletdError> {
        // Enable TLS for HTTPS endpoints
        let enable_tls = endpoint.scheme() == Some(&http::uri::Scheme::HTTPS);

        let mut channel = Channel::builder(endpoint)
            .connect_timeout(config.connect_timeout)
            .timeout(config.request_timeout);

        if enable_tls {
            channel = channel.tls_config(ClientTlsConfig::new().with_webpki_roots())?;
        } else {
            warn!(
                "Connecting to lightwalletd without TLS. This is not recommended for production use."
            );
        }

        let channel = channel.connect().await?;
        let client = CompactTxStreamerClient::new(channel);

        Ok(Self { client, config })
    }

    /// Creates a block range stream with retry logic.
    async fn get_block_range_stream(
        client: &CompactTxStreamerClient<Channel>,
        config: &ValidatedLightWalletdConfig,
        range: &RangeInclusive<u64>,
    ) -> Result<tonic::Streaming<CompactBlock>, LightWalletdError> {
        retry_with_backoff(config, || {
            let mut client = client.clone();
            let request = BlockRange {
                start: Some(BlockId {
                    height: *range.start(),
                    hash: vec![],
                }),
                end: Some(BlockId {
                    height: *range.end(),
                    hash: vec![],
                }),
            };
            async move {
                client
                    .get_block_range(request)
                    .await
                    .map(tonic::Response::into_inner)
            }
        })
        .await
    }
}

/// Receives the next block from a stream with timeout.
async fn receive_next_block<S>(
    stream: &mut S,
    timeout_duration: Duration,
) -> Result<Option<CompactBlock>, LightWalletdError>
where
    S: Stream<Item = Result<CompactBlock, tonic::Status>> + Unpin,
{
    match tokio::time::timeout(timeout_duration, stream.next()).await {
        Ok(Some(Ok(block))) => Ok(Some(block)),
        Ok(Some(Err(status))) => Err(LightWalletdError::from(status)),
        Ok(None) => Ok(None),
        Err(_elapsed) => {
            warn!(
                "Timeout receiving block from lightwalletd after {}ms",
                timeout_duration.as_millis()
            );
            Err(LightWalletdError::StreamTimeout {
                timeout_duration: timeout_duration.as_millis(),
            })
        }
    }
}

/// Extract nullifiers from a compact block.
///
/// Processes all transactions in the block and extracts both Sapling and Orchard nullifiers.
fn extract_nullifiers_from_block(
    block: &CompactBlock,
) -> Result<Vec<PoolNullifier>, LightWalletdError> {
    let mut nullifiers = Vec::new();

    for tx in &block.vtx {
        // Sapling nullifiers
        for spend in &tx.spends {
            let nullifier: Nullifier = spend.nf.clone().try_into().map_err(|v: Vec<u8>| {
                LightWalletdError::InvalidLength {
                    block_height: block.height,
                    length: v.len(),
                }
            })?;
            nullifiers.push(PoolNullifier {
                pool: Pool::Sapling,
                nullifier,
            });
        }

        // Orchard nullifiers
        for action in &tx.actions {
            let nullifier: Nullifier =
                action.nullifier.clone().try_into().map_err(|v: Vec<u8>| {
                    LightWalletdError::InvalidLength {
                        block_height: block.height,
                        length: v.len(),
                    }
                })?;
            nullifiers.push(PoolNullifier {
                pool: Pool::Orchard,
                nullifier,
            });
        }
    }

    Ok(nullifiers)
}

/// Read nullifiers from a lightwalletd via gRPC.
///
/// # Cancellation
///
/// The stream can be cancelled by dropping it. The underlying gRPC connection
/// will be closed, though the server may continue processing briefly until it
/// detects the disconnect. No explicit cancellation signal is sent.
///
/// # Error Recovery
///
/// Initial connection failures are retried with exponential backoff. However,
/// mid-stream errors (connection drops after streaming begins) are **not** retried.
/// Callers should track the last successfully processed block height and restart
/// the stream from that point if needed.
impl ChainNullifiers for LightWalletd {
    type Error = LightWalletdError;
    type Stream = BoxedNullifierStream<Self::Error>;

    fn nullifiers_stream(&self, range: &RangeInclusive<u64>) -> Self::Stream {
        let client = self.client.clone();
        let config = self.config.clone();
        let range = range.clone();

        Box::pin(try_stream! {
            let mut stream = Self::get_block_range_stream(
                &client,
                &config,
                &range
            ).await?;

            while let Some(block) = receive_next_block(&mut stream, config.stream_message_timeout).await? {
                for nullifier in extract_nullifiers_from_block(&block)? {
                    yield nullifier;
                }
            }
        })
    }
}

/// # Error Recovery
///
/// Initial connection failures are retried with exponential backoff. However,
/// mid-stream errors (connection drops after streaming begins) are **not** retried.
/// Callers should track the last successfully processed block height and restart
/// the stream from that point if needed.
impl UserNullifiers for LightWalletd {
    type Error = LightWalletdError;
    type Stream = BoxedNoteStream<Self::Error>;

    /// This function is using `block_in_place` and requires a multi-threaded Tokio runtime.
    fn user_nullifiers<P: Parameters + Clone + Send + 'static>(
        &self,
        network: &P,
        range: RangeInclusive<u64>,
        keys: ViewingKeys,
    ) -> Self::Stream {
        let network = network.clone();
        let config = self.config.clone();
        let client = self.client.clone();

        Box::pin(try_stream! {
            let mut stream = Self::get_block_range_stream(
                &client,
                &config,
                &range
            ).await?;

            while let Some(block) = receive_next_block(&mut stream, config.stream_message_timeout).await? {
                let notes = tokio::task::block_in_place(|| decrypt_compact_block(&network, &block, &keys))?;

                let output_counts: Vec<usize> = block.vtx.iter().map(|tx| tx.outputs.len()).collect();
                let sapling_tree_size_end = block
                    .chain_metadata
                    .as_ref()
                    .map(|m| m.sapling_commitment_tree_size);

                let sapling_info = calculate_sapling_positions(
                    block.height,
                    sapling_tree_size_end,
                    &output_counts,
                )?;

                for note in notes {
                    match note {
                        DecryptedNote::Sapling(sapling_note) => {
                              let position = calculate_note_position(
                                  &sapling_info,
                                  sapling_note.tx_index,
                                  sapling_note.output_index,
                              )?;

                              let txid = get_txid_or_null(&block.vtx, sapling_note.tx_index);

                              yield AnyFoundNote::Sapling(FoundNote::<SaplingNote> {
                                  note: SaplingNote {
                                      note: sapling_note.note,
                                      position,
                                      scope: sapling_note.scope,
                                  },
                                  metadata: NoteMetadata {
                                      height: block.height,
                                      txid,
                                      scope: sapling_note.scope,
                                  },
                              });
                        }
                        DecryptedNote::Orchard(orchard_note) => {
                            let txid = get_txid_or_null(&block.vtx, orchard_note.tx_index);

                            yield AnyFoundNote::Orchard(FoundNote::<orchard::Note> {
                                note: orchard_note.note,
                                metadata: NoteMetadata {
                                    height: block.height,
                                    txid,
                                    scope: orchard_note.scope,
                                },
                            });
                        }
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "Tests")]

    use std::pin::pin;

    use futures::stream;
    use tonic::Status;
    use zcash_client_backend::proto::compact_formats::{
        CompactBlock, CompactOrchardAction, CompactSaplingSpend, CompactTx,
    };

    use super::*;

    fn make_block(height: u64) -> CompactBlock {
        CompactBlock {
            height,
            ..Default::default()
        }
    }

    fn make_compact_block(
        height: u64,
        sapling_nullifiers: Vec<Nullifier>,
        orchard_nullifiers: Vec<Nullifier>,
    ) -> CompactBlock {
        let spends: Vec<CompactSaplingSpend> = sapling_nullifiers
            .into_iter()
            .map(|nf| CompactSaplingSpend { nf: nf.to_vec() })
            .collect();

        let actions: Vec<CompactOrchardAction> = orchard_nullifiers
            .into_iter()
            .map(|nf| CompactOrchardAction {
                nullifier: nf.to_vec(),
                ..Default::default()
            })
            .collect();

        CompactBlock {
            height,
            vtx: vec![CompactTx {
                spends,
                actions,
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    mod extract_nullifiers_tests {
        use super::*;

        #[test]
        fn empty_and_no_transactions() {
            let block = make_compact_block(100, vec![], vec![]);
            assert!(extract_nullifiers_from_block(&block).unwrap().is_empty());

            let block = CompactBlock {
                height: 100,
                vtx: vec![],
                ..Default::default()
            };
            assert!(extract_nullifiers_from_block(&block).unwrap().is_empty());
        }

        #[test]
        fn sapling_only() {
            let nf1 = [1_u8; 32];
            let nf2 = [2_u8; 32];
            let block = make_compact_block(100, vec![nf1, nf2], vec![]);

            let result = extract_nullifiers_from_block(&block).unwrap();
            assert_eq!(result.len(), 2);
            assert_eq!(result[0].pool, Pool::Sapling);
            assert_eq!(result[0].nullifier, nf1);
            assert_eq!(result[1].pool, Pool::Sapling);
            assert_eq!(result[1].nullifier, nf2);
        }

        #[test]
        fn orchard_only() {
            let nf1 = [3_u8; 32];
            let nf2 = [4_u8; 32];
            let block = make_compact_block(100, vec![], vec![nf1, nf2]);

            let result = extract_nullifiers_from_block(&block).unwrap();
            assert_eq!(result.len(), 2);
            assert_eq!(result[0].pool, Pool::Orchard);
            assert_eq!(result[0].nullifier, nf1);
            assert_eq!(result[1].pool, Pool::Orchard);
            assert_eq!(result[1].nullifier, nf2);
        }

        #[test]
        fn mixed_pools_preserves_order() {
            let sapling_nf = [1_u8; 32];
            let orchard_nf = [2_u8; 32];
            let block = make_compact_block(100, vec![sapling_nf], vec![orchard_nf]);

            let result = extract_nullifiers_from_block(&block).unwrap();
            assert_eq!(result.len(), 2);
            assert_eq!(result[0].pool, Pool::Sapling);
            assert_eq!(result[1].pool, Pool::Orchard);
        }

        #[test]
        fn multiple_transactions() {
            let block = CompactBlock {
                height: 100,
                vtx: vec![
                    CompactTx {
                        spends: vec![CompactSaplingSpend {
                            nf: [1_u8; 32].to_vec(),
                        }],
                        ..Default::default()
                    },
                    CompactTx {
                        actions: vec![CompactOrchardAction {
                            nullifier: [2_u8; 32].to_vec(),
                            ..Default::default()
                        }],
                        ..Default::default()
                    },
                ],
                ..Default::default()
            };

            let result = extract_nullifiers_from_block(&block).unwrap();
            assert_eq!(result.len(), 2);
            assert_eq!(result[0].pool, Pool::Sapling);
            assert_eq!(result[1].pool, Pool::Orchard);
        }

        #[test]
        fn invalid_nullifier_lengths() {
            // Too short
            let block = CompactBlock {
                height: 42,
                vtx: vec![CompactTx {
                    spends: vec![CompactSaplingSpend { nf: vec![0_u8; 31] }],
                    ..Default::default()
                }],
                ..Default::default()
            };
            assert!(matches!(
                extract_nullifiers_from_block(&block),
                Err(LightWalletdError::InvalidLength {
                    block_height: 42,
                    length: 31
                })
            ));

            // Invalid orchard
            let block = CompactBlock {
                height: 200,
                vtx: vec![CompactTx {
                    actions: vec![CompactOrchardAction {
                        nullifier: vec![0_u8; 16],
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            };
            assert!(matches!(
                extract_nullifiers_from_block(&block),
                Err(LightWalletdError::InvalidLength {
                    block_height: 200,
                    length: 16
                })
            ));
        }

        #[test]
        #[allow(clippy::needless_range_loop)]
        fn many_nullifiers_order_preserved() {
            let block = CompactBlock {
                height: 100,
                vtx: vec![CompactTx {
                    spends: (0..10)
                        .map(|i| CompactSaplingSpend {
                            nf: [i; 32].to_vec(),
                        })
                        .collect(),
                    actions: (10..20)
                        .map(|i| CompactOrchardAction {
                            nullifier: [i; 32].to_vec(),
                            ..Default::default()
                        })
                        .collect(),
                    ..Default::default()
                }],
                ..Default::default()
            };

            let result = extract_nullifiers_from_block(&block).unwrap();
            assert_eq!(result.len(), 20);

            for i in 0..10 {
                assert_eq!(result[i].pool, Pool::Sapling);
                assert_eq!(result[i].nullifier[0], u8::try_from(i).unwrap());
            }
            for i in 10..20 {
                assert_eq!(result[i].pool, Pool::Orchard);
                assert_eq!(result[i].nullifier[0], u8::try_from(i).unwrap());
            }
        }
    }

    mod receive_next_block_tests {
        use super::*;

        #[tokio::test]
        async fn success_and_end_of_stream() {
            let mut s = stream::iter(vec![Ok(make_block(100)), Ok(make_block(101))]);
            let timeout = Duration::from_secs(1);

            let b1 = receive_next_block(&mut s, timeout).await.unwrap().unwrap();
            assert_eq!(b1.height, 100);

            let b2 = receive_next_block(&mut s, timeout).await.unwrap().unwrap();
            assert_eq!(b2.height, 101);

            let end = receive_next_block(&mut s, timeout).await.unwrap();
            assert!(end.is_none());
        }

        #[tokio::test]
        async fn grpc_error() {
            let mut s = stream::iter(vec![Err(Status::unavailable("down"))]);
            let result = receive_next_block(&mut s, Duration::from_secs(1)).await;
            assert!(matches!(result, Err(LightWalletdError::Grpc(_))));
        }

        #[tokio::test]
        async fn timeout() {
            let mut s = pin!(stream::pending::<Result<CompactBlock, Status>>());
            let result = receive_next_block(&mut s, Duration::from_millis(10)).await;
            assert!(matches!(
                result,
                Err(LightWalletdError::StreamTimeout {
                    timeout_duration: 10
                })
            ));
        }

        #[tokio::test]
        async fn error_stops_processing() {
            let items = vec![
                Ok(make_block(100)),
                Err(Status::internal("")),
                Ok(make_block(102)),
            ];
            let mut s = stream::iter(items);
            let timeout = Duration::from_secs(1);

            assert!(receive_next_block(&mut s, timeout).await.is_ok());
            assert!(matches!(
                receive_next_block(&mut s, timeout).await,
                Err(LightWalletdError::Grpc(_))
            ));
        }
    }
}
