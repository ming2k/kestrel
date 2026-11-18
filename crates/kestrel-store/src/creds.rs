// SPDX-License-Identifier: LGPL-2.1-or-later

use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use async_trait::async_trait;
use kestrel_model::{ProfileSecrets, Secret, SecretKey};
use kestrel_ports::store::SecretStore;
use kestrel_ports::{PortError, PortResult};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use zeroize::{Zeroize, Zeroizing};

use crate::atomic::{ensure_private_dir, remove_file_durable, sync_dir, write_atomic};

const ENVELOPE_VERSION: u32 = 1;
const DEFAULT_CREDS_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CRED_FILE_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedEnvelope {
    v: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    passphrase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    private_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    private_key_password: Option<String>,
}

impl Drop for SealedEnvelope {
    fn drop(&mut self) {
        if let Some(s) = &mut self.passphrase {
            s.zeroize();
        }
        if let Some(s) = &mut self.private_key {
            s.zeroize();
        }
        if let Some(s) = &mut self.private_key_password {
            s.zeroize();
        }
    }
}

/// Which key `systemd-creds` seals credentials with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredsScope {
    /// The system key: TPM2 and/or `/var/lib/systemd/credential.secret`.
    /// Requires root. This is the production setting.
    Host,
    /// The calling user's key (`systemd-creds --user`). For session-bus
    /// development and tests.
    User,
}

/// Secrets encrypted with `systemd-creds`, one file per profile or P2P group.
///
/// Each credential is encrypted with the authenticated name
/// `kestrel-wifi-<profile-id>` or `kestrel-p2p-<group-id>`. `systemd-creds`
/// authenticates that name on decryption, so a credential file renamed to
/// another target is rejected.
#[derive(Debug, Clone)]
pub struct SystemdCredsStore {
    dir: PathBuf,
    scope: CredsScope,
    binary: PathBuf,
    timeout: Duration,
}

impl SystemdCredsStore {
    pub fn new(dir: impl Into<PathBuf>, scope: CredsScope) -> Self {
        let binary = if scope == CredsScope::Host && Path::new("/usr/bin/systemd-creds").is_file() {
            PathBuf::from("/usr/bin/systemd-creds")
        } else {
            PathBuf::from("systemd-creds")
        };
        Self {
            dir: dir.into(),
            scope,
            binary,
            timeout: DEFAULT_CREDS_TIMEOUT,
        }
    }

    /// Overrides the `systemd-creds` executable.
    #[must_use]
    pub fn with_binary(mut self, binary: impl Into<PathBuf>) -> Self {
        self.binary = binary.into();
        self
    }

    /// Overrides the per-invocation timeout for `systemd-creds`.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout.max(Duration::from_millis(50));
        self
    }

    pub fn path(&self) -> &Path {
        &self.dir
    }

    fn file_for(&self, key: SecretKey) -> PathBuf {
        self.dir.join(format!("{}.cred", key.file_stem()))
    }

    fn command(&self, verb: &str, key: SecretKey) -> Command {
        let mut command = Command::new(&self.binary);
        command.arg(verb).arg(format!("--name={}", key.cred_name()));
        if self.scope == CredsScope::User {
            command.arg("--user");
        }
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        command
    }
}

fn spawn_error(error: &io::Error) -> PortError {
    if error.kind() == io::ErrorKind::NotFound {
        PortError::Unavailable("systemd-creds is not installed".to_owned())
    } else {
        PortError::Backend(format!("cannot run systemd-creds: {error}"))
    }
}

/// Distinguishes permanent decryption/key/format failures (which warrant
/// quarantining the credential so the user is re-prompted) from transient
/// system or resource failures (which must NOT destroy a valid `.cred` file).
fn is_corrupt_decrypt_message(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    if lower.contains("no such file or directory")
        || lower.contains("resource temporarily unavailable")
        || lower.contains("cannot allocate memory")
        || lower.contains("too many open files")
        || lower.contains("device or resource busy")
        || lower.contains("timed out")
    {
        return false;
    }
    [
        "decrypt",
        "bad message",
        "invalid argument",
        "invalid credential",
        "invalid data",
        "corrupt",
        "authentication",
        "mismatch",
        "doesn't match",
        "does not match",
        "credential name",
        "name in credential",
        "host key",
        "tpm",
        "unseal",
        "unexpected eof",
        "too short",
        "header",
        "ciphertext",
        "signature",
        "not valid",
        "malformed",
        "key",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn failure(verb: &str, status: std::process::ExitStatus, stderr: &[u8]) -> PortError {
    use std::os::unix::process::ExitStatusExt;
    let message = String::from_utf8_lossy(stderr).trim().to_owned();
    if let Some(signal) = status.signal() {
        PortError::Backend(format!(
            "systemd-creds {verb} terminated by signal {signal}"
        ))
    } else if message.contains("InteractiveAuthenticationRequired") || message.contains("ermission")
    {
        PortError::PermissionDenied(format!("systemd-creds {verb}: {message}"))
    } else if verb == "decrypt" && is_corrupt_decrypt_message(&message) {
        PortError::CorruptSecret(format!("systemd-creds decrypt: {message}"))
    } else {
        PortError::Backend(format!("systemd-creds {verb}: {message}"))
    }
}

async fn quarantine(path: &Path, reason: &PortError) {
    let invalid = path.with_extension("cred.invalid");
    tracing::warn!(
        file = %path.display(),
        moved_to = %invalid.display(),
        %reason,
        "quarantining unsealable credential"
    );
    let src = path.to_owned();
    let dst = invalid;
    let _ = tokio::task::spawn_blocking(move || {
        if std::fs::rename(&src, &dst).is_ok()
            && let Some(parent) = src.parent().filter(|p| !p.as_os_str().is_empty())
        {
            let _ = sync_dir(parent);
        }
    })
    .await;
}

#[async_trait]
impl SecretStore for SystemdCredsStore {
    fn name(&self) -> &'static str {
        match self.scope {
            CredsScope::Host => "systemd-creds",
            CredsScope::User => "systemd-creds-user",
        }
    }

    async fn get(&self, key: SecretKey) -> PortResult<Option<ProfileSecrets>> {
        let path = self.file_for(key);
        let check_path = path.clone();
        let exists =
            tokio::task::spawn_blocking(move || match std::fs::symlink_metadata(&check_path) {
                Ok(meta) => {
                    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "credential path is not a regular file",
                        ));
                    }
                    if meta.len() > MAX_CRED_FILE_BYTES {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "credential file exceeds maximum size",
                        ));
                    }
                    Ok(true)
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
                Err(error) => Err(error),
            })
            .await
            .map_err(|e| PortError::Backend(e.to_string()))?
            .map_err(|e| PortError::Backend(e.to_string()))?;
        if !exists {
            return Ok(None);
        }

        let child = self
            .command("decrypt", key)
            .arg(&path)
            .arg("-")
            .spawn()
            .map_err(|e| spawn_error(&e))?;
        let output = tokio::time::timeout(self.timeout, child.wait_with_output())
            .await
            .map_err(|_| PortError::Backend("systemd-creds decrypt timed out".to_owned()))?
            .map_err(|e| PortError::Backend(e.to_string()))?;
        let stdout = Zeroizing::new(output.stdout);
        if !output.status.success() {
            let stderr_text = String::from_utf8_lossy(&output.stderr);
            if stderr_text
                .to_ascii_lowercase()
                .contains("no such file or directory")
            {
                return Ok(None);
            }
            let err = failure("decrypt", output.status, &output.stderr);
            if matches!(err, PortError::CorruptSecret(_)) {
                quarantine(&path, &err).await;
            }
            return Err(err);
        }
        let Ok(text) = std::str::from_utf8(&stdout) else {
            let err = PortError::CorruptSecret("decrypted secret is not UTF-8".to_owned());
            quarantine(&path, &err).await;
            return Err(err);
        };
        let mut envelope = match serde_json::from_str::<SealedEnvelope>(text) {
            Ok(env) if env.v == ENVELOPE_VERSION => env,
            Ok(env) => {
                let err = PortError::CorruptSecret(format!(
                    "unsupported credential envelope version {}",
                    env.v
                ));
                quarantine(&path, &err).await;
                return Err(err);
            }
            Err(error) => {
                let err = PortError::CorruptSecret(format!("invalid credential envelope: {error}"));
                quarantine(&path, &err).await;
                return Err(err);
            }
        };
        let secrets = ProfileSecrets {
            passphrase: envelope.passphrase.take().map(Secret::new),
            private_key: envelope.private_key.take().map(Secret::new),
            private_key_password: envelope.private_key_password.take().map(Secret::new),
        };
        Ok(Some(secrets))
    }

    async fn set(&self, key: SecretKey, secrets: &ProfileSecrets) -> PortResult<()> {
        let dir = self.dir.clone();
        tokio::task::spawn_blocking(move || ensure_private_dir(&dir))
            .await
            .map_err(|e| PortError::Backend(e.to_string()))?
            .map_err(|e| PortError::Backend(e.to_string()))?;
        let envelope = SealedEnvelope {
            v: ENVELOPE_VERSION,
            passphrase: secrets.passphrase.as_ref().map(|s| s.expose().to_owned()),
            private_key: secrets.private_key.as_ref().map(|s| s.expose().to_owned()),
            private_key_password: secrets
                .private_key_password
                .as_ref()
                .map(|s| s.expose().to_owned()),
        };
        let payload = Zeroizing::new(
            serde_json::to_string(&envelope).map_err(|e| PortError::Backend(e.to_string()))?,
        );
        drop(envelope);

        let mut child = self
            .command("encrypt", key)
            .arg("-")
            .arg("-")
            .spawn()
            .map_err(|e| spawn_error(&e))?;
        // The secret travels over a pipe, never argv or the environment.
        // Drive stdin concurrently with stdout/stderr draining to avoid pipe
        // deadlocks on large private keys, bounded by `self.timeout`.
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| PortError::Backend("no stdin for systemd-creds".to_owned()))?;
        let write_fut = async move {
            let res = stdin.write_all(payload.as_bytes()).await;
            drop(stdin);
            res
        };
        let (write_res, output_res) = tokio::time::timeout(self.timeout, async {
            tokio::join!(write_fut, child.wait_with_output())
        })
        .await
        .map_err(|_| PortError::Backend("systemd-creds encrypt timed out".to_owned()))?;
        let output = output_res.map_err(|e| PortError::Backend(e.to_string()))?;
        if !output.status.success() {
            return Err(failure("encrypt", output.status, &output.stderr));
        }
        write_res.map_err(|e| PortError::Backend(e.to_string()))?;

        let path = self.file_for(key);
        let ciphertext = output.stdout;
        tokio::task::spawn_blocking(move || write_atomic(&path, &ciphertext))
            .await
            .map_err(|e| PortError::Backend(e.to_string()))?
            .map_err(|e| PortError::Backend(e.to_string()))
    }

    async fn delete(&self, key: SecretKey) -> PortResult<()> {
        let path = self.file_for(key);
        tokio::task::spawn_blocking(move || remove_file_durable(&path))
            .await
            .map_err(|e| PortError::Backend(e.to_string()))?
            .map_err(|e| PortError::Backend(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use kestrel_model::ProfileId;

    use super::*;

    async fn user_store() -> Option<(tempfile::TempDir, SystemdCredsStore)> {
        let tmp = tempfile::tempdir().unwrap();
        let store = SystemdCredsStore::new(tmp.path().join("secrets"), CredsScope::User);
        match store
            .set(
                SecretKey::Profile(ProfileId::generate()),
                &ProfileSecrets::from_passphrase(Secret::new("probe-probe")),
            )
            .await
        {
            Ok(()) => Some((tmp, store)),
            Err(error) => {
                eprintln!("skipping: systemd-creds --user unavailable: {error}");
                None
            }
        }
    }

    #[tokio::test]
    async fn encrypts_round_trips_and_deletes() {
        let Some((_tmp, store)) = user_store().await else {
            return;
        };
        let id = SecretKey::Profile(ProfileId::generate());
        assert_eq!(store.get(id).await.unwrap(), None);
        let bundle = ProfileSecrets {
            passphrase: Some(Secret::new("correct horse battery staple")),
            private_key: Some(Secret::new(
                "-----BEGIN PRIVATE KEY-----\nMAowAwIBAQMDAAEC\n-----END PRIVATE KEY-----\n",
            )),
            private_key_password: Some(Secret::new("unlock")),
        };
        store.set(id, &bundle).await.unwrap();
        let file = store.file_for(id);
        let raw = std::fs::read(&file).unwrap();
        assert!(
            !raw.windows(5).any(|w| w == b"horse"),
            "secret stored in plaintext"
        );
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(store.get(id).await.unwrap().unwrap(), bundle);
        store.delete(id).await.unwrap();
        store.delete(id).await.unwrap();
        assert_eq!(store.get(id).await.unwrap(), None);
    }

    #[tokio::test]
    async fn credentials_are_bound_to_their_profile() {
        let Some((_tmp, store)) = user_store().await else {
            return;
        };
        let a = SecretKey::Profile(ProfileId::generate());
        let b = SecretKey::Profile(ProfileId::generate());
        store
            .set(
                a,
                &ProfileSecrets::from_passphrase(Secret::new("secret-of-a")),
            )
            .await
            .unwrap();
        std::fs::copy(store.file_for(a), store.file_for(b)).unwrap();
        assert!(
            matches!(store.get(b).await, Err(PortError::CorruptSecret(_))),
            "a swapped credential decrypted"
        );
        assert!(store.file_for(b).with_extension("cred.invalid").exists());
    }

    #[tokio::test]
    async fn missing_binary_is_reported_as_unavailable() {
        let tmp = tempfile::tempdir().unwrap();
        let store = SystemdCredsStore::new(tmp.path(), CredsScope::User)
            .with_binary("/nonexistent/systemd-creds");
        assert!(matches!(
            store
                .set(
                    SecretKey::Profile(ProfileId::generate()),
                    &ProfileSecrets::from_passphrase(Secret::new("whatever1"))
                )
                .await,
            Err(PortError::Unavailable(_))
        ));
    }

    #[tokio::test]
    async fn signal_interrupted_decrypt_does_not_quarantine_credential() {
        let tmp = tempfile::tempdir().unwrap();
        let script = tmp.path().join("fake-creds.sh");
        std::fs::write(&script, "#!/bin/sh\nkill -TERM $$\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

        let store = SystemdCredsStore::new(tmp.path().join("secrets"), CredsScope::User)
            .with_binary(script);
        let id = SecretKey::Profile(ProfileId::generate());
        std::fs::create_dir_all(store.path()).unwrap();
        std::fs::write(store.file_for(id), b"ciphertext").unwrap();

        assert!(matches!(store.get(id).await, Err(PortError::Backend(_))));
        assert!(
            store.file_for(id).exists(),
            "a signal-terminated decrypt must not quarantine the credential"
        );
        assert!(!store.file_for(id).with_extension("cred.invalid").exists());
    }

    #[tokio::test]
    async fn transient_decrypt_error_does_not_quarantine_credential() {
        let tmp = tempfile::tempdir().unwrap();
        let script = tmp.path().join("busy-creds.sh");
        std::fs::write(
            &script,
            "#!/bin/sh\necho 'Device or resource busy' >&2\nexit 1\n",
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

        let store = SystemdCredsStore::new(tmp.path().join("secrets"), CredsScope::User)
            .with_binary(script);
        let id = SecretKey::Profile(ProfileId::generate());
        std::fs::create_dir_all(store.path()).unwrap();
        std::fs::write(store.file_for(id), b"ciphertext").unwrap();

        assert!(matches!(store.get(id).await, Err(PortError::Backend(_))));
        assert!(store.file_for(id).exists());
        assert!(!store.file_for(id).with_extension("cred.invalid").exists());
    }

    #[tokio::test]
    async fn hung_subprocess_times_out() {
        let tmp = tempfile::tempdir().unwrap();
        let script = tmp.path().join("hang-creds.sh");
        std::fs::write(&script, "#!/bin/sh\nsleep 30\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

        let store = SystemdCredsStore::new(tmp.path().join("secrets"), CredsScope::User)
            .with_binary(script)
            .with_timeout(Duration::from_millis(100));
        let id = SecretKey::Profile(ProfileId::generate());
        let err = store
            .set(
                id,
                &ProfileSecrets::from_passphrase(Secret::new("whatever1")),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, PortError::Backend(msg) if msg.contains("timed out")));
    }
}
