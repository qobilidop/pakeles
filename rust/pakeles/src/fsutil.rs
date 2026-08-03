//! Filesystem helpers for publishing generated artifacts without exposing
//! partially-written files to concurrent readers or leaving truncated output
//! behind after a failed generation.

use anyhow::{Context, Result};
use std::io::Write;
use std::path::Path;

/// Write one file through a sibling temporary file and atomically rename it
/// into place after the writer succeeds and the contents reach the filesystem.
pub fn atomic_write_with(
    path: &Path,
    write: impl FnOnce(&mut std::fs::File) -> Result<()>,
) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    let parent = parent.unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("creating temporary output beside {}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(path)
            .map(|metadata| metadata.permissions().mode())
            .unwrap_or(0o644);
        temporary
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(mode))?;
    }

    write(temporary.as_file_mut())?;
    temporary.as_file_mut().flush()?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("publishing output to {}", path.display()))?;
    Ok(())
}

/// Atomically replace `path` with `contents`.
pub fn atomic_write(path: &Path, contents: impl AsRef<[u8]>) -> Result<()> {
    atomic_write_with(path, |file| {
        file.write_all(contents.as_ref())?;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_write_preserves_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("artifact");
        std::fs::write(&path, "old").unwrap();

        let error = atomic_write_with(&path, |file| {
            file.write_all(b"partial")?;
            anyhow::bail!("generation failed")
        })
        .unwrap_err();

        assert!(error.to_string().contains("generation failed"));
        assert_eq!(std::fs::read_to_string(path).unwrap(), "old");
    }

    #[test]
    fn successful_write_replaces_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("artifact");
        std::fs::write(&path, "old").unwrap();
        atomic_write(&path, "new").unwrap();
        assert_eq!(std::fs::read_to_string(path).unwrap(), "new");
    }
}
