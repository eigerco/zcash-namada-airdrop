//! Connection to lightwalletd gRPC service

use std::ops::RangeInclusive;
use std::pin::Pin;
use std::time::Duration;

use async_stream::try_stream;
use futures_core::Stream;
use orchard::keys::FullViewingKey as OrchardFvk;
use sapling::zip32::DiversifiableFullViewingKey;
use tonic::transport::{Channel, ClientTlsConfig, Uri};
use tracing::{debug, warn};
use zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient;
use zcash_client_backend::proto::service::{BlockId, BlockRange};
use zcash_protocol::TxId;
use zcash_protocol::consensus::Parameters;

use crate::chain_nullifiers::{ChainNullifiers, PoolNullifier};
use crate::user_nullifiers::decrypt_notes::{DecryptError, DecryptedNote, decrypt_compact_block};
use crate::user_nullifiers::{
    AnyFoundNote, FoundNote, NoteMetadata, OrchardViewingKeys, SaplingNote, SaplingViewingKeys,
    UserNullifiers, ViewingKeys,
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
/// Multiplier for exponential backoff
const BACKOFF_MULTIPLIER: u64 = 2;
/// Timeout for receiving stream messages in seconds
const STREAM_MESSAGE_TIMEOUT_SECS: u64 = 60;

/// Errors that can occur when interacting with lightwalletd
#[derive(Debug, thiserror::Error)]
#[allow(clippy::module_name_repetitions, reason = "Needed for clarity.")]
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
    /// Decryption error
    #[error("Decryption error: {0}")]
    Decrypt(#[from] DecryptError),
    /// Integer conversion error
    #[error("Integer conversion error: {0}")]
    IntConversion(#[from] std::num::TryFromIntError),
    /// Overflow error
    #[error("Overflow error")]
    OverflowError,
    /// Index error
    #[error("Index error: index {index} out of bounds for length {length}")]
    IndexError {
        /// The invalid index
        index: usize,
        /// The length of the collection
        length: usize,
    },
    /// Stream message timeout
    #[error("Stream message timeout after {0} seconds")]
    StreamTimeout(u64),
}

/// A lightwalletd client
pub struct LightWalletd {
    client: CompactTxStreamerClient<Channel>,
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
        // Enable TLS for HTTPS endpoints
        let enable_tls = endpoint.scheme() == Some(&http::uri::Scheme::HTTPS);

        let mut channel = Channel::builder(endpoint)
            .connect_timeout(Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS))
            .timeout(Duration::from_secs(DEFAULT_REQUEST_TIMEOUT_SECS));

        if enable_tls {
            channel = channel.tls_config(ClientTlsConfig::new().with_webpki_roots())?;
        } else {
            warn!(
                "Connecting to lightwalletd without TLS. This is not recommended for production use."
            );
        }

        let channel = channel.connect().await?;
        let client = CompactTxStreamerClient::new(channel);

        Ok(Self { client })
    }
}

/// Determines if a gRPC error is transient and should be retried.
///
/// Retryable errors include:
/// - `Unavailable`: Service temporarily unavailable
/// - `ResourceExhausted`: Rate limiting or quota exceeded
/// - `Aborted`: Operation aborted, typically due to concurrency issues
/// - `DeadlineExceeded`: Request timeout (may succeed on retry)
/// - `Unknown`: Unknown errors that might be transient
fn is_retryable_grpc_error(status: &tonic::Status) -> bool {
    use tonic::Code;
    matches!(
        status.code(),
        Code::Unavailable |
            Code::ResourceExhausted |
            Code::Aborted |
            Code::DeadlineExceeded |
            Code::Unknown
    )
}

/// Determines if a `LightWalletdError` is transient and should be retried.
#[allow(
    clippy::wildcard_enum_match_arm,
    reason = "We are interested in specific variants only."
)]
fn is_retryable_error(error: &LightWalletdError) -> bool {
    match error {
        LightWalletdError::Grpc(status) => is_retryable_grpc_error(status),
        LightWalletdError::Transport(_) => true, // Connection errors are often transient
        _ => false,
    }
}

/// Calculates the delay for exponential backoff.
fn calculate_backoff_delay(attempt: u32) -> Duration {
    let delay_ms =
        INITIAL_RETRY_DELAY_MS.saturating_mul(BACKOFF_MULTIPLIER.saturating_pow(attempt));
    Duration::from_millis(delay_ms.min(MAX_RETRY_DELAY_MS))
}

/// Retries an async operation with exponential backoff.
///
/// On transient errors (as determined by [`is_retryable_error`]), the operation
/// is retried up to [`MAX_RETRIES`] times. Delays between attempts follow
/// exponential backoff starting at [`INITIAL_RETRY_DELAY_MS`], multiplied by
/// [`BACKOFF_MULTIPLIER`] each attempt, capped at [`MAX_RETRY_DELAY_MS`].
///
/// # Type Parameters
///
/// * `F` - A closure that produces the future to retry. Called once per attempt.
/// * `Fut` - The future type returned by `F`.
/// * `T` - The success type.
/// * `E` - The error type, must be convertible to [`LightWalletdError`].
#[allow(
    clippy::arithmetic_side_effects,
    reason = "`attempt` can not overflow because it should always be less than `MAX_RETRIES`, which is far from the limits."
)]
async fn retry_with_backoff<F, Fut, T, E>(mut operation: F) -> Result<T, LightWalletdError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: Into<LightWalletdError>,
{
    let mut attempt = 0;

    loop {
        match operation().await {
            Ok(result) => return Ok(result),
            Err(e) => {
                let error = e.into();
                if attempt < MAX_RETRIES && is_retryable_error(&error) {
                    let delay = calculate_backoff_delay(attempt);
                    tokio::time::sleep(delay).await;
                    attempt += 1;
                } else {
                    return Err(error);
                }
            }
        }
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

    fn nullifiers_stream(&self, range: &RangeInclusive<u64>) -> Self::Stream {
        let client = self.client.clone();
        let range = range.clone();

        Box::pin(try_stream! {
            let mut stream = retry_with_backoff(|| {
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
                async move { client.get_block_range(request).await.map(tonic::Response::into_inner) }
            }).await?;

            let timeout_duration = Duration::from_secs(STREAM_MESSAGE_TIMEOUT_SECS);
            loop {
                let block = tokio::time::timeout(timeout_duration, stream.message())
                    .await
                    .map_err(|e| {
                        warn!("Timeout receiving block from lightwalletd: {e}");
                        LightWalletdError::StreamTimeout(STREAM_MESSAGE_TIMEOUT_SECS)
                    })??;

                let Some(block) = block else { break };

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

    /// This function is using `block_in_place` and requires a multi-threaded Tokio runtime.
    fn user_nullifiers<P: Parameters + Clone + Send + 'static>(
        &self,
        network: &P,
        start_height: u64,
        end_height: u64,
        orchard_fvk: &OrchardFvk,
        sapling_fvk: &DiversifiableFullViewingKey,
    ) -> Self::Stream {
        let network = network.clone();
        let client = self.client.clone();

        let sapling_viewing_keys = SaplingViewingKeys::from_dfvk(sapling_fvk);
        let orchard_viewing_keys = OrchardViewingKeys::from_fvk(orchard_fvk);

        let keys = ViewingKeys {
            sapling: Some(sapling_viewing_keys),
            orchard: Some(orchard_viewing_keys),
        };

        Box::pin(try_stream! {
            let mut stream = retry_with_backoff(|| {
                let mut client = client.clone();
                let request = BlockRange {
                    start: Some(BlockId {
                        height: start_height,
                        hash: vec![],
                    }),
                    end: Some(BlockId {
                        height: end_height,
                        hash: vec![],
                    }),
                };
                async move { client.get_block_range(request).await.map(tonic::Response::into_inner) }
            }).await?;

            let timeout_duration = Duration::from_secs(STREAM_MESSAGE_TIMEOUT_SECS);
            loop {
                let block = tokio::time::timeout(timeout_duration, stream.message())
                    .await
                    .map_err(|e| {
                        warn!("Timeout receiving block from lightwalletd: {e}");
                        LightWalletdError::StreamTimeout(STREAM_MESSAGE_TIMEOUT_SECS)
                    })??;

                let Some(block) = block else {
                    debug!("Lightwalletd block stream ended");
                    break
                };

                let notes = tokio::task::block_in_place(|| decrypt_compact_block(&network, &block, &keys))?;

                // Get the Sapling commitment tree size at the END of this block
                // This is reported in chain_metadata
                let sapling_tree_size_end = block
                    .chain_metadata
                    .as_ref()
                    .map_or(0, |m| m.sapling_commitment_tree_size);

                // Build a map of cumulative Sapling outputs per transaction
                // This helps us calculate the position of each output in the commitment tree
                let mut tx_sapling_start_positions = Vec::with_capacity(block.vtx.len());
                let mut cumulative = 0_u32;
                for tx in &block.vtx {
                    tx_sapling_start_positions.push(cumulative);
                    cumulative = cumulative
                        .checked_add(u32::try_from(tx.outputs.len())?)
                        .ok_or(LightWalletdError::OverflowError)?;
                }

                // The tree size at the start of the block is the end size minus all outputs in this block
                let sapling_tree_size_start = sapling_tree_size_end
                    .checked_sub(cumulative)
                    .ok_or(LightWalletdError::OverflowError)?;

                for note in notes {
                    match note {
                        DecryptedNote::Sapling(sapling_note) => {
                            // Calculate the note's position in the global Sapling commitment tree
                            // Position = tree_size_at_block_start + outputs_before_this_tx + output_index
                            let tx_start = tx_sapling_start_positions
                                .get(sapling_note.tx_index)
                                .ok_or(LightWalletdError::IndexError{
                                    index: sapling_note.tx_index,
                                    length: tx_sapling_start_positions.len(),
                                })?;
                            let position = u64::from(
                                sapling_tree_size_start
                                    .checked_add(*tx_start)
                                    .and_then(|v| v.checked_add(u32::try_from(sapling_note.output_index).ok()?))
                                    .ok_or(LightWalletdError::OverflowError)?,
                            );

                            // Failed silently if txid is not valid
                            // Txid does not affect note decryption or nullifier calculation
                            let txid = block.vtx.get(sapling_note.tx_index).map_or_else(
                                || TxId::NULL,
                                |tx| tx.txid(),
                            );

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
                            // Failed silently if txid is not valid
                            // Txid does not affect note decryption or nullifier calculation
                            let txid = block.vtx.get(orchard_note.tx_index).map_or_else(
                                || TxId::NULL,
                                |tx| tx.txid()
                            );

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
