// SPDX-License-Identifier: LGPL-2.1-or-later

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::atomic::{
    ensure_private_dir, read_regular_string, remove_file_durable, sync_dir, write_atomic,
};
use kestrel_ports::{PortError, PortResult};

const SCHEMA_VERSION: u32 = 1;
const EXTENSION: &str = "toml";
const MAX_TOML_BYTES: u64 = 2 * 1024 * 1024;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Versioned<T> {
    version: u32,
    item: T,
}

#[derive(Debug, Clone)]
pub(crate) struct TomlDirectory {
    dir: PathBuf,
    kind: &'static str,
}

impl TomlDirectory {
    pub(crate) fn new(dir: impl Into<PathBuf>, kind: &'static str) -> Self {
        Self {
            dir: dir.into(),
            kind,
        }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.dir
    }

    pub(crate) fn file_for(&self, stem: &str) -> PathBuf {
        self.dir.join(format!("{stem}.{EXTENSION}"))
    }

    pub(crate) async fn load_all<T, F>(&self, expected_stem: F) -> PortResult<Vec<T>>
    where
        T: DeserializeOwned + Send + 'static,
        F: Fn(&T) -> Result<String, String> + Send + 'static,
    {
        let dir = self.dir.clone();
        let kind = self.kind;
        tokio::task::spawn_blocking(move || load_sync(&dir, kind, expected_stem))
            .await
            .map_err(|e| join_error(&e))?
            .map_err(|e| io_error(&e))
    }

    pub(crate) async fn load_one<T, F>(
        &self,
        stem: String,
        expected_stem: F,
    ) -> PortResult<Option<T>>
    where
        T: DeserializeOwned + Send + 'static,
        F: Fn(&T) -> Result<String, String> + Send + 'static,
    {
        let path = self.file_for(&stem);
        let kind = self.kind;
        tokio::task::spawn_blocking(move || match read_regular_string(&path, MAX_TOML_BYTES) {
            Ok(text) => {
                let item = parse_text::<T>(&text)
                    .and_then(|item| {
                        let expected = expected_stem(&item)?;
                        if stem != expected {
                            return Err(format!("file name does not match the {kind} id"));
                        }
                        Ok(item)
                    })
                    .map_err(|reason| io::Error::new(io::ErrorKind::InvalidData, reason))?;
                Ok(Some(item))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        })
        .await
        .map_err(|e| join_error(&e))?
        .map_err(|e| io_error(&e))
    }

    pub(crate) async fn save<T: Serialize + Send + Sync + 'static>(
        &self,
        stem: String,
        item: T,
    ) -> PortResult<()> {
        let text = toml::to_string(&Versioned {
            version: SCHEMA_VERSION,
            item,
        })
        .map_err(|e| PortError::Backend(e.to_string()))?;
        let dir = self.dir.clone();
        let path = self.file_for(&stem);
        tokio::task::spawn_blocking(move || {
            ensure_private_dir(&dir)?;
            write_atomic(&path, text.as_bytes())
        })
        .await
        .map_err(|e| join_error(&e))?
        .map_err(|e| io_error(&e))
    }

    pub(crate) async fn delete(&self, stem: String) -> PortResult<()> {
        let path = self.file_for(&stem);
        tokio::task::spawn_blocking(move || remove_file_durable(&path))
            .await
            .map_err(|e| join_error(&e))?
            .map_err(|e| io_error(&e))
    }
}

fn load_sync<T, F>(dir: &Path, kind: &str, expected_stem: F) -> io::Result<Vec<T>>
where
    T: DeserializeOwned,
    F: Fn(&T) -> Result<String, String>,
{
    ensure_private_dir(dir)?;
    let mut items = Vec::new();
    let mut entries: Vec<_> = fs::read_dir(dir)?.collect::<Result<_, _>>()?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some(EXTENSION) {
            continue;
        }
        let parsed = parse_file::<T>(&path).and_then(|(item, stem)| {
            let expected = expected_stem(&item)?;
            if stem.as_deref() != Some(expected.as_str()) {
                return Err(format!("file name does not match the {kind} id"));
            }
            Ok(item)
        });
        match parsed {
            Ok(item) => items.push(item),
            Err(reason) => {
                let quarantine = path.with_extension("invalid");
                tracing::error!(
                    file = %path.display(),
                    moved_to = %quarantine.display(),
                    %reason,
                    "quarantining invalid {kind}"
                );
                if let Err(error) = fs::rename(&path, &quarantine).and_then(|()| sync_dir(dir)) {
                    tracing::warn!(
                        file = %path.display(),
                        %error,
                        "cannot quarantine invalid {kind}; skipping"
                    );
                }
            }
        }
    }
    Ok(items)
}

fn parse_file<T: DeserializeOwned>(path: &Path) -> Result<(T, Option<String>), String> {
    let text = read_regular_string(path, MAX_TOML_BYTES).map_err(|e| e.to_string())?;
    let item = parse_text::<T>(&text)?;
    let stem = path.file_stem().and_then(|s| s.to_str()).map(str::to_owned);
    Ok((item, stem))
}

fn parse_text<T: DeserializeOwned>(text: &str) -> Result<T, String> {
    let file: Versioned<T> = toml::from_str(text).map_err(|e| e.to_string())?;
    if file.version != SCHEMA_VERSION {
        return Err(format!("unsupported schema version {}", file.version));
    }
    Ok(file.item)
}

fn io_error(error: &io::Error) -> PortError {
    match error.kind() {
        io::ErrorKind::PermissionDenied => PortError::PermissionDenied(error.to_string()),
        _ => PortError::Backend(error.to_string()),
    }
}

fn join_error(error: &tokio::task::JoinError) -> PortError {
    PortError::Backend(format!("storage task failed: {error}"))
}
