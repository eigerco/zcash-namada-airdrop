//! Orchard setup utilities.

use std::path::PathBuf;

use tracing::info;
use zair_core::schema::config::ValueCommitmentScheme;

use super::orchard_params::generate_orchard_params_file;

/// Generate and persist Orchard Halo2 params.
///
/// This is a one-time setup step per `k` (which depends on the value commitment scheme).
///
/// # Errors
/// Returns an error if param generation fails.
pub async fn generate_orchard_params(
    params_out: PathBuf,
    scheme: ValueCommitmentScheme,
) -> eyre::Result<()> {
    let orchard_scheme: zair_orchard_proofs::ValueCommitmentScheme = scheme.into();
    let k = zair_orchard_proofs::k_for_scheme(orchard_scheme);
    info!(?scheme, k, file = ?params_out, "Generating Orchard Halo2 params...");
    info!("This may take a while (especially for sha256).");

    generate_orchard_params_file(params_out.clone(), orchard_scheme).await?;

    info!(file = ?params_out, "Orchard params ready");
    Ok(())
}
