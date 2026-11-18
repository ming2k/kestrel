// SPDX-License-Identifier: LGPL-2.1-or-later

use std::fmt;
use std::sync::Mutex;

use tokio::sync::mpsc;

/// Capacity of each subscriber's bounded queue.
const EVENT_BUS_CAPACITY: usize = 1024;

/// A stream of events from one adapter. Events from one adapter are
/// delivered in the order the backend produced them.
pub type Subscription<T> = mpsc::Receiver<T>;

/// Fan-out helper for adapters. Each subscriber gets a bounded queue of
/// events published after it subscribed. Closed subscribers are pruned on
/// publish.
pub struct EventBus<T> {
    subscribers: Mutex<Vec<mpsc::Sender<T>>>,
}

impl<T: Clone> EventBus<T> {
    pub const fn new() -> Self {
        Self {
            subscribers: Mutex::new(Vec::new()),
        }
    }

    pub fn subscribe(&self) -> Subscription<T> {
        let (sender, receiver) = mpsc::channel(EVENT_BUS_CAPACITY);
        self.subscribers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(sender);
        receiver
    }

    pub fn publish(&self, event: &T) {
        self.subscribers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|subscriber| match subscriber.try_send(event.clone()) {
                Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => true,
                Err(mpsc::error::TrySendError::Closed(_)) => false,
            });
    }
}

impl<T: Clone> Default for EventBus<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> fmt::Debug for EventBus<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let count = self.subscribers.lock().map_or(0, |s| s.len());
        f.debug_struct("EventBus")
            .field("subscribers", &count)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fans_out_and_prunes() {
        let bus = EventBus::new();
        let mut a = bus.subscribe();
        let b = bus.subscribe();
        drop(b);
        bus.publish(&1);
        assert_eq!(a.try_recv().unwrap(), 1);
        assert_eq!(bus.subscribers.lock().unwrap().len(), 1);
    }
}
