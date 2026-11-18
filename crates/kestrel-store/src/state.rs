// SPDX-License-Identifier: LGPL-2.1-or-later

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use kestrel_ports::store::StateStore;
use kestrel_ports::{PortError, PortResult};
use serde::{Deserialize, Serialize};

use crate::atomic::{ensure_private_dir, read_regular_string, sync_dir, write_atomic};

const SCHEMA_VERSION: u32 = 1;
const MAX_STATE_BYTES: u64 = 64 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedState {
    version: u32,
    wireless_enabled: bool,
}

/// Durable daemon state (such as the user's software wireless toggle),
/// stored atomically with mode 0600.
#[derive(Debug, Clone)]
pub struct StateFile {
    path: PathBuf,
}

impl StateFile {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn load_sync(&self) -> io::Result<Option<bool>> {
        let text = match read_regular_string(&self.path, MAX_STATE_BYTES) {
            Ok(text) => text,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        match toml::from_str::<PersistedState>(&text) {
            Ok(state) if state.version == SCHEMA_VERSION => Ok(Some(state.wireless_enabled)),
            Ok(state) => {
                self.quarantine(&format!("unsupported schema version {}", state.version));
                Ok(None)
            }
            Err(error) => {
                self.quarantine(&error.to_string());
                Ok(None)
            }
        }
    }

    fn quarantine(&self, reason: &str) {
        let quarantine = self.path.with_extension("toml.invalid");
        tracing::error!(
            file = %self.path.display(),
            moved_to = %quarantine.display(),
            %reason,
            "quarantining invalid state file"
        );
        let res = fs::rename(&self.path, &quarantine).and_then(|()| {
            if let Some(parent) = self.path.parent().filter(|p| !p.as_os_str().is_empty()) {
                sync_dir(parent)?;
            }
            Ok(())
        });
        if let Err(error) = res {
            tracing::warn!(
                file = %self.path.display(),
                %error,
                "cannot quarantine invalid state file"
            );
        }
    }

    fn save_sync(&self, wireless_enabled: bool) -> io::Result<()> {
        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            ensure_private_dir(parent)?;
        }
        let text = toml::to_string(&PersistedState {
            version: SCHEMA_VERSION,
            wireless_enabled,
        })
        .map_err(io::Error::other)?;
        write_atomic(&self.path, text.as_bytes())
    }
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

#[async_trait]
impl StateStore for StateFile {
    async fn wireless_enabled(&self) -> PortResult<Option<bool>> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || this.load_sync())
            .await
            .map_err(|e| join_error(&e))?
            .map_err(|e| io_error(&e))
    }

    async fn set_wireless_enabled(&self, enabled: bool) -> PortResult<()> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || this.save_sync(enabled))
            .await
            .map_err(|e| join_error(&e))?
            .map_err(|e| io_error(&e))
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[tokio::test]
    async fn round_trips_and_quarantines_invalid_state() {
        let tmp = tempfile::tempdir().unwrap();
        let file = StateFile::new(tmp.path().join("state/state.toml"));
        assert_eq!(file.wireless_enabled().await.unwrap(), None);

        file.set_wireless_enabled(false).await.unwrap();
        assert_eq!(file.wireless_enabled().await.unwrap(), Some(false));
        assert_eq!(
            fs::metadata(file.path()).unwrap().permissions().mode() & 0o777,
            0o600
        );

        file.set_wireless_enabled(true).await.unwrap();
        assert_eq!(file.wireless_enabled().await.unwrap(), Some(true));

        fs::write(file.path(), "nonsense = 1\n").unwrap();
        assert_eq!(file.wireless_enabled().await.unwrap(), None);
        assert!(file.path().with_extension("toml.invalid").exists());
    }
}
