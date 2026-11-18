// SPDX-License-Identifier: LGPL-2.1-or-later

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use kestrel_model::{CertId, Certificate};
use kestrel_ports::store::CertStore;
use kestrel_ports::{PortError, PortResult};

use crate::toml_dir::TomlDirectory;

/// Public X.509 PEM certificates stored atomically as `<dir>/<cert-id>.toml`.
#[derive(Debug, Clone)]
pub struct CertDirectory {
    inner: TomlDirectory,
}

impl CertDirectory {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            inner: TomlDirectory::new(dir, "certificate"),
        }
    }

    pub fn path(&self) -> &Path {
        self.inner.path()
    }
}

#[async_trait]
impl CertStore for CertDirectory {
    async fn load_all(&self) -> PortResult<Vec<Certificate>> {
        self.inner
            .load_all(|cert: &Certificate| {
                cert.validate().map_err(|e| e.to_string())?;
                Ok(cert.id.simple())
            })
            .await
    }

    async fn get(&self, id: CertId) -> PortResult<Option<Certificate>> {
        self.inner
            .load_one(id.simple(), |cert: &Certificate| {
                cert.validate().map_err(|e| e.to_string())?;
                Ok(cert.id.simple())
            })
            .await
    }

    async fn save(&self, cert: &Certificate) -> PortResult<()> {
        cert.validate()
            .map_err(|e| PortError::InvalidArgument(e.to_string()))?;
        self.inner.save(cert.id.simple(), cert.clone()).await
    }

    async fn delete(&self, id: CertId) -> PortResult<()> {
        self.inner.delete(id.simple()).await
    }
}
