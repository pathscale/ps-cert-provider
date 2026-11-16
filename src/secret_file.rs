use std::io::{self, Write};
use std::path::{Path, PathBuf};

use tempfile::Builder;

pub(crate) async fn write_secret(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let path: PathBuf = path.to_owned();
    let bytes = bytes.to_vec();
    tokio::task::spawn_blocking(move || {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let mut builder = Builder::new();
        #[cfg(unix)]
        builder.permissions(std::fs::Permissions::from_mode(0o600));
        let mut staged = builder.tempfile_in(parent)?;
        #[cfg(unix)]
        staged
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
        staged.write_all(&bytes)?;
        staged.as_file().sync_all()?;
        staged.persist(&path).map_err(|error| error.error)?;
        #[cfg(unix)]
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    })
    .await
    .map_err(|error| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("secret file write task failed: {error}"),
        )
    })?
}

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[cfg(test)]
mod tests {
    use super::write_secret;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[cfg(unix)]
    fn mode(path: &std::path::Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[tokio::test]
    async fn creates_and_replaces_private_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("privkey.pem");
        write_secret(&path, b"new-key").await.unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new-key");
        #[cfg(unix)]
        assert_eq!(mode(&path), 0o600);
        std::fs::write(&path, b"old-key").unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_secret(&path, b"replacement-key").await.unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"replacement-key");
        #[cfg(unix)]
        assert_eq!(mode(&path), 0o600);
    }

    #[tokio::test]
    async fn concurrent_replacements_publish_one_complete_payload_and_clean_staging() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("privkey.pem");
        let a = vec![b'a'; 16_384];
        let b = vec![b'b'; 16_384];
        let (ra, rb) = tokio::join!(write_secret(&path, &a), write_secret(&path, &b));
        ra.unwrap();
        rb.unwrap();
        let actual = std::fs::read(&path).unwrap();
        assert!(actual == a || actual == b);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn replaces_symlink_entry_without_touching_target() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        let link = dir.path().join("privkey.pem");
        std::fs::write(&target, b"target-data").unwrap();
        symlink(&target, &link).unwrap();
        write_secret(&link, b"new-secret").await.unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"target-data");
        assert_eq!(std::fs::read(&link).unwrap(), b"new-secret");
        assert!(!std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(mode(&link), 0o600);
    }

    #[tokio::test]
    async fn persist_failure_preserves_directory_and_cleans_staging() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("privkey.pem");
        std::fs::create_dir(&destination).unwrap();
        std::fs::write(destination.join("keep"), b"intact").unwrap();
        let error = write_secret(&destination, b"secret").await.unwrap_err();
        assert_ne!(error.kind(), std::io::ErrorKind::NotFound);
        assert_eq!(std::fs::read(destination.join("keep")).unwrap(), b"intact");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}
