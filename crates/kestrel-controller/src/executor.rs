// SPDX-License-Identifier: LGPL-2.1-or-later

//! Generic per-entity FIFO command executor.

use std::future::Future;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// Runs submitted jobs strictly in submission order on a dedicated task.
#[derive(Debug)]
pub(crate) struct Executor<J> {
    tx: mpsc::UnboundedSender<J>,
    task: JoinHandle<()>,
}

impl<J: Send + 'static> Executor<J> {
    pub(crate) fn spawn<C, F, Fut>(context: C, mut run: F) -> Self
    where
        C: Clone + Send + 'static,
        F: FnMut(C, J) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let (tx, mut rx) = mpsc::unbounded_channel::<J>();
        let task = tokio::spawn(async move {
            while let Some(job) = rx.recv().await {
                run(context.clone(), job).await;
            }
        });
        Self { tx, task }
    }

    pub(crate) fn submit(&self, job: J) {
        if self.tx.send(job).is_err() {
            tracing::error!("executor stopped; job dropped");
        }
    }

    /// Stops accepting jobs. Queued jobs still run. Returns the task to
    /// await for completion.
    pub(crate) fn retire(self) -> JoinHandle<()> {
        drop(self.tx);
        self.task
    }
}
