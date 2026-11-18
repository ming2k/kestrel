// SPDX-License-Identifier: LGPL-2.1-or-later

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use kestrel_model::{P2pGroupId, P2pGroupProfile};
use kestrel_ports::store::P2pGroupStore;
use kestrel_ports::{PortError, PortResult};

use crate::toml_dir::TomlDirectory;

/// Persistent Wi-Fi Direct groups stored atomically as `<dir>/<group-id>.toml`.
#[derive(Debug, Clone)]
pub struct P2pGroupDirectory {
    inner: TomlDirectory,
}

impl P2pGroupDirectory {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            inner: TomlDirectory::new(dir, "p2p-group"),
        }
    }

    pub fn path(&self) -> &Path {
        self.inner.path()
    }
}

#[async_trait]
impl P2pGroupStore for P2pGroupDirectory {
    async fn load_all(&self) -> PortResult<Vec<P2pGroupProfile>> {
        self.inner
            .load_all(|group: &P2pGroupProfile| {
                group.validate().map_err(|e| e.to_string())?;
                Ok(group.id.simple())
            })
            .await
    }

    async fn save(&self, group: &P2pGroupProfile) -> PortResult<()> {
        group
            .validate()
            .map_err(|e| PortError::InvalidArgument(e.to_string()))?;
        self.inner.save(group.id.simple(), group.clone()).await
    }

    async fn delete(&self, id: P2pGroupId) -> PortResult<()> {
        self.inner.delete(id.simple()).await
    }
}
