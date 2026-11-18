// SPDX-License-Identifier: LGPL-2.1-or-later

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TMP_ID: AtomicU64 = AtomicU64::new(0);

/// Creates `dir` (mode 0700) if missing, rejects symlinks and non-directories,
/// and refuses group/world access to an existing one.
pub(crate) fn ensure_private_dir(dir: &Path) -> io::Result<()> {
    match fs::symlink_metadata(dir) {
        Ok(meta) if meta.file_type().is_symlink() => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} must not be a symbolic link", dir.display()),
        )),
        Ok(meta) if meta.is_dir() => {
            if meta.permissions().mode() & 0o077 != 0 {
                fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
            }
            Ok(())
        }
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("{} exists and is not a directory", dir.display()),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir),
        Err(error) => Err(error),
    }
}

/// Syncs `dir` to ensure directory entry mutations (rename, unlink) are durable.
pub(crate) fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

/// Writes `contents` to `path` atomically: a unique `0600` temporary file
/// created with `O_CREAT | O_EXCL` in the same directory, fsync, rename,
/// fsync of the directory. Cleans up the temp file on any error.
pub(crate) fn write_atomic(path: &Path, contents: &[u8]) -> io::Result<()> {
    let dir = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let pid = std::process::id();
    let mut attempt = 0u32;
    let (tmp, mut file) = loop {
        let seq = NEXT_TMP_ID.fetch_add(1, Ordering::Relaxed);
        let tmp = dir.join(format!(".{}.{pid}.{seq}.tmp", file_name.to_string_lossy()));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
        {
            Ok(file) => break (tmp, file),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists && attempt < 16 => {
                attempt += 1;
            }
            Err(error) => return Err(error),
        }
    };
    let result = (|| -> io::Result<()> {
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, path)?;
        sync_dir(dir)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Removes `path` (ignoring `NotFound`) and fsyncs its parent directory.
pub(crate) fn remove_file_durable(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => {
            if let Some(dir) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                sync_dir(dir)?;
            }
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// Reads a regular, non-symlink file up to `max_bytes` into UTF-8 text.
pub(crate) fn read_regular_string(path: &Path, max_bytes: u64) -> io::Result<String> {
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", path.display()),
        ));
    }
    if meta.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} exceeds size limit ({max_bytes} bytes)", path.display()),
        ));
    }
    let file = File::open(path)?;
    let mut buf = Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0));
    file.take(max_bytes + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} exceeds size limit ({max_bytes} bytes)", path.display()),
        ));
    }
    String::from_utf8(buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_private_dir_creates_0700_and_tightens_loose_permissions() {
        let root = tempfile::tempdir().unwrap();
        let nested = root.path().join("a/b");
        ensure_private_dir(&nested).unwrap();
        let mode = fs::metadata(&nested).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);

        fs::set_permissions(&nested, fs::Permissions::from_mode(0o755)).unwrap();
        ensure_private_dir(&nested).unwrap();
        let tightened = fs::metadata(&nested).unwrap().permissions().mode() & 0o777;
        assert_eq!(tightened, 0o700);
    }

    #[test]
    fn ensure_private_dir_rejects_regular_file_and_symlink() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("not-a-dir");
        fs::write(&file, b"hello").unwrap();
        let err = ensure_private_dir(&file).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);

        let real_dir = root.path().join("real");
        fs::create_dir(&real_dir).unwrap();
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&real_dir, &link).unwrap();
        assert!(ensure_private_dir(&link).is_err());
    }

    #[test]
    fn write_atomic_sets_0600_overwrites_and_leaves_no_tmp() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("secret.bin");
        write_atomic(&target, b"first").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"first");
        let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        write_atomic(&target, b"second").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"second");
        let left: Vec<_> = fs::read_dir(root.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(left, vec!["secret.bin"]);
    }

    #[test]
    fn read_regular_string_rejects_symlinks_and_oversized_files() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("ok.toml");
        fs::write(&target, "hello").unwrap();
        assert_eq!(read_regular_string(&target, 16).unwrap(), "hello");
        assert!(read_regular_string(&target, 4).is_err());

        let link = root.path().join("link.toml");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(read_regular_string(&link, 16).is_err());
    }
}
