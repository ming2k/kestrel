// SPDX-License-Identifier: LGPL-2.1-or-later

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use kestrel_model::ConnectionEvent;
use kestrel_ports::store::HistoryStore;
use kestrel_ports::{PortError, PortResult};

use crate::atomic::{ensure_private_dir, read_regular_string, write_atomic};

const MAX_HISTORY_BYTES: u64 = 4 * 1024 * 1024;

/// A bounded JSON Lines file of connection events.
///
/// Each record is small and the file is rewritten atomically, so a crash
/// never leaves a half-written line. Invalid lines are ignored and logged;
/// history is diagnostic data, not configuration.
#[derive(Debug, Clone)]
pub struct HistoryFile {
    path: PathBuf,
    capacity: usize,
    write_lock: Arc<Mutex<()>>,
}

impl HistoryFile {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            capacity: 256,
            write_lock: Arc::default(),
        }
    }

    #[must_use]
    pub fn with_capacity(mut self, capacity: usize) -> Self {
        self.capacity = capacity.max(1);
        self
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn load_sync(&self) -> io::Result<Vec<ConnectionEvent>> {
        let text = match read_regular_string(&self.path, MAX_HISTORY_BYTES) {
            Ok(text) => text,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        let mut events = Vec::new();
        for (line, text) in text.lines().enumerate() {
            if text.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<ConnectionEvent>(text) {
                Ok(event) => events.push(event),
                Err(error) => tracing::warn!(
                    file = %self.path.display(),
                    line = line + 1,
                    %error,
                    "ignoring invalid history entry"
                ),
            }
        }
        Ok(events)
    }

    fn record_sync(&self, event: &ConnectionEvent) -> io::Result<()> {
        let _guard = self
            .write_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            ensure_private_dir(parent)?;
        }
        let mut events = self.load_sync()?;
        events.push(event.clone());
        if events.len() > self.capacity {
            events.drain(..events.len() - self.capacity);
        }
        let mut text = String::new();
        for event in &events {
            let line = serde_json::to_string(event)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            text.push_str(&line);
            text.push('\n');
        }
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
impl HistoryStore for HistoryFile {
    async fn record(&self, event: &ConnectionEvent) -> PortResult<()> {
        let this = self.clone();
        let event = event.clone();
        tokio::task::spawn_blocking(move || this.record_sync(&event))
            .await
            .map_err(|e| join_error(&e))?
            .map_err(|e| io_error(&e))
    }

    async fn recent(&self, limit: usize) -> PortResult<Vec<ConnectionEvent>> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || this.load_sync())
            .await
            .map_err(|e| join_error(&e))?
            .map_err(|e| io_error(&e))
            .map(|events| events.into_iter().rev().take(limit).collect())
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use kestrel_model::ConnectionOutcome;

    use super::*;

    fn event(at: u64, ssid: &str) -> ConnectionEvent {
        ConnectionEvent {
            at,
            device: "wlp0s20f3".to_owned(),
            ssid: ssid.to_owned(),
            profile: None,
            outcome: ConnectionOutcome::Connected,
            detail: None,
        }
    }

    #[tokio::test]
    async fn records_and_returns_most_recent_first() {
        let tmp = tempfile::tempdir().unwrap();
        let history = HistoryFile::new(tmp.path().join("history.jsonl"));
        for at in 1..=3 {
            history.record(&event(at, "home")).await.unwrap();
        }
        assert_eq!(
            history
                .recent(2)
                .await
                .unwrap()
                .into_iter()
                .map(|e| e.at)
                .collect::<Vec<_>>(),
            vec![3, 2]
        );
        assert_eq!(
            std::fs::metadata(history.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[tokio::test]
    async fn keeps_only_the_capacity() {
        let tmp = tempfile::tempdir().unwrap();
        let history = HistoryFile::new(tmp.path().join("history.jsonl")).with_capacity(3);
        for at in 1..=10 {
            history.record(&event(at, "home")).await.unwrap();
        }
        assert_eq!(
            history
                .recent(10)
                .await
                .unwrap()
                .into_iter()
                .map(|e| e.at)
                .collect::<Vec<_>>(),
            vec![10, 9, 8]
        );
    }

    #[tokio::test]
    async fn ignores_invalid_lines() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("history.jsonl");
        let history = HistoryFile::new(&path);
        history.record(&event(1, "home")).await.unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, format!("{text}not json\n")).unwrap();
        let events = history.recent(10).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].at, 1);
    }

    #[tokio::test]
    async fn concurrent_records_are_not_lost() {
        let tmp = tempfile::tempdir().unwrap();
        let history = HistoryFile::new(tmp.path().join("history.jsonl")).with_capacity(64);
        let mut tasks = Vec::new();
        for at in 1..=20 {
            let history = history.clone();
            tasks.push(tokio::spawn(async move {
                history.record(&event(at, "home")).await.unwrap();
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        assert_eq!(history.recent(64).await.unwrap().len(), 20);
    }

    #[tokio::test]
    async fn missing_file_is_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let history = HistoryFile::new(tmp.path().join("history.jsonl"));
        assert_eq!(
            history.recent(10).await.unwrap(),
            Vec::<ConnectionEvent>::new()
        );
    }
}
