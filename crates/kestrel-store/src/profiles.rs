// SPDX-License-Identifier: LGPL-2.1-or-later

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use kestrel_model::{ProfileId, WifiProfile};
use kestrel_ports::store::ProfileRepository;
use kestrel_ports::{PortError, PortResult};

use crate::toml_dir::TomlDirectory;

/// Profiles stored as `<dir>/<profile-id>.toml`.
///
/// A file that fails to parse or validate is renamed to `*.invalid` and
/// reported, so one bad file never prevents the other networks from
/// working, and nothing is overwritten silently.
#[derive(Debug, Clone)]
pub struct ProfileDirectory {
    inner: TomlDirectory,
}

impl ProfileDirectory {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            inner: TomlDirectory::new(dir, "profile"),
        }
    }

    pub fn path(&self) -> &Path {
        self.inner.path()
    }

    #[cfg(test)]
    fn file_for(&self, id: ProfileId) -> PathBuf {
        self.inner.file_for(&id.simple())
    }
}

#[async_trait]
impl ProfileRepository for ProfileDirectory {
    async fn load_all(&self) -> PortResult<Vec<WifiProfile>> {
        self.inner
            .load_all(|profile: &WifiProfile| {
                profile.validate().map_err(|e| e.to_string())?;
                Ok(profile.id.simple())
            })
            .await
    }

    async fn save(&self, profile: &WifiProfile) -> PortResult<()> {
        profile
            .validate()
            .map_err(|e| PortError::InvalidArgument(e.to_string()))?;
        self.inner.save(profile.id.simple(), profile.clone()).await
    }

    async fn delete(&self, id: ProfileId) -> PortResult<()> {
        self.inner.delete(id.simple()).await
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use kestrel_model::{L3Config, ProfileSecurity, Ssid};

    use super::*;

    #[tokio::test]
    async fn round_trips_with_private_permissions() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = ProfileDirectory::new(tmp.path().join("profiles"));
        let mut profile =
            WifiProfile::new(Ssid::new("home").unwrap(), ProfileSecurity::WpaPersonal);
        profile.priority = 5;
        profile.l3 = L3Config::Unmanaged;
        repo.save(&profile).await.unwrap();

        let file = repo.file_for(profile.id);
        assert_eq!(
            fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(repo.path()).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let text = fs::read_to_string(&file).unwrap();
        assert!(text.contains("version = 1"), "{text}");

        assert_eq!(repo.load_all().await.unwrap(), vec![profile.clone()]);
        repo.delete(profile.id).await.unwrap();
        repo.delete(profile.id).await.unwrap();
        assert_eq!(repo.load_all().await.unwrap(), vec![]);
    }

    #[tokio::test]
    async fn quarantines_invalid_files_and_keeps_the_rest() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = ProfileDirectory::new(tmp.path());
        let good = WifiProfile::new(Ssid::new("good").unwrap(), ProfileSecurity::Open);
        repo.save(&good).await.unwrap();

        let bad_id = ProfileId::generate();
        let bad = tmp.path().join(format!("{}.toml", bad_id.simple()));
        fs::write(&bad, "version = 1\n[item]\nnonsense = true\n").unwrap();
        let renamed = tmp
            .path()
            .join(format!("{}.toml", ProfileId::generate().simple()));
        fs::copy(repo.file_for(good.id), &renamed).unwrap();

        assert_eq!(repo.load_all().await.unwrap(), vec![good]);
        assert!(bad.with_extension("invalid").exists());
        assert!(renamed.with_extension("invalid").exists());
    }

    #[tokio::test]
    async fn rejects_invalid_profiles_on_save() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = ProfileDirectory::new(tmp.path());
        let mut profile = WifiProfile::new(Ssid::new("x").unwrap(), ProfileSecurity::Open);
        profile.name = String::new();
        assert!(matches!(
            repo.save(&profile).await,
            Err(PortError::InvalidArgument(_))
        ));
    }
}
