//! Module for loading chain nullifiers from various sources.

use std::path::Path;
#[cfg(feature = "file-source")]
use std::path::PathBuf;
use std::pin::Pin;
use std::str::FromStr as _;

use eyre::Context;
use futures::{Stream, StreamExt as _};
use http::Uri;
use non_membership_proofs::chain_nullifiers::{ChainNullifiers as _, PoolNullifier};
#[cfg(feature = "file-source")]
use non_membership_proofs::source::file::FileSource;
use non_membership_proofs::source::light_walletd::LightWalletd;
use tracing::{debug, instrument};

use crate::CommonArgs;
use crate::cli::Source;

/// Stream of nullifiers with unified error type
type NullifierStream = Pin<Box<dyn Stream<Item = eyre::Result<PoolNullifier>> + Send>>;

/// Get a stream of nullifiers based on the configuration
pub async fn get_nullifiers(config: &CommonArgs) -> eyre::Result<NullifierStream> {
    match config.source.clone().try_into()? {
        Source::Lightwalletd { url } => {
            let uri = Uri::from_str(&url)?;
            debug!(?uri, "Connecting to lightwalletd");
            let source = LightWalletd::connect(uri).await?;
            Ok(Box::pin(
                source
                    .nullifiers_stream(&config.snapshot)
                    .map(|r| r.map_err(Into::into)),
            ))
        }
        #[cfg(feature = "file-source")]
        Source::File { orchard, sapling } => {
            debug!(
                "Loading nullifiers from files: sapling={:?}, orchard={:?}",
                sapling, orchard
            );
            let source = FileSource::new(sapling.map(PathBuf::from), orchard.map(PathBuf::from));
            Ok(Box::pin(
                source
                    .nullifiers_stream(&config.snapshot)
                    .map(|r| r.map_err(Into::into)),
            ))
        }
    }
}

/// Load nullifiers from a file
#[instrument(fields(path = ?path.as_ref()))]
pub async fn load_nullifiers_from_file(path: impl AsRef<Path>) -> eyre::Result<Vec<[u8; 32]>> {
    debug!("Loading nullifiers from file");

    let mut nullifiers = non_membership_proofs::read_raw_nullifiers(&path)
        .await
        .context(format!("Failed to read {:?}", path.as_ref()))?;
    if !nullifiers.is_sorted() {
        nullifiers.sort_unstable();
    }

    debug!("Read {} nullifiers from disk", nullifiers.len());

    Ok(nullifiers)
}
