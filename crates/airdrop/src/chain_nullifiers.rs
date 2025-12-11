use std::path::{Path, PathBuf};
use std::pin::Pin;

use futures::{Stream, StreamExt as _};
use non_membership_proofs::chain_nullifiers::{ChainNullifiers as _, PoolNullifier};
use non_membership_proofs::source::file::Source as FileSource;
use non_membership_proofs::source::light_walletd::LightWalletd;
use tracing::{debug, instrument};

use crate::CommonArgs;
use crate::cli::Source;

/// Stream of nullifiers with unified error type
type NullifierStream = Pin<Box<dyn Stream<Item = eyre::Result<PoolNullifier>> + Send>>;

/// Get a stream of nullifiers based on the configuration
pub(crate) async fn get_nullifiers(config: &CommonArgs) -> eyre::Result<NullifierStream> {
    match config.source.clone().try_into()? {
        Source::Lightwalletd { url } => {
            let source = LightWalletd::connect(&url).await?;
            Ok(Box::pin(
                source
                    .nullifiers_stream(&config.snapshot)
                    .map(|r| r.map_err(Into::into)),
            ))
        }
        Source::File { orchard, sapling } => {
            let source = FileSource::new(PathBuf::from(sapling), PathBuf::from(orchard));
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
pub(crate) async fn load_nullifiers_from_file(
    path: impl AsRef<Path>,
) -> eyre::Result<Vec<[u8; 32]>> {
    debug!("Loading nullifiers from file");

    let mut nullifiers = non_membership_proofs::read_raw_nullifiers(path).await?;
    nullifiers.sort_unstable();

    debug!("Read {} nullifiers from disk", nullifiers.len());

    Ok(nullifiers)
}
