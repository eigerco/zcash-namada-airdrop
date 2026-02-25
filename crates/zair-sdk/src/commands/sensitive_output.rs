//! Helpers for writing sensitive local output files.

use std::path::Path;

use tokio::io::AsyncWriteExt as _;

/// Write a sensitive output file.
///
/// On Unix this enforces owner-only permissions (`0o600`).
///
/// # Errors
/// Returns an error if the file cannot be created, written, flushed, or permission-adjusted.
pub(super) async fn write_sensitive_output(path: &Path, contents: &str) -> eyre::Result<()> {
    #[cfg(unix)]
    let mut file = {
        tokio::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .await?
    };

    #[cfg(not(unix))]
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)
        .await?;

    file.write_all(contents.as_bytes()).await?;
    file.flush().await?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await?;
    }

    Ok(())
}
