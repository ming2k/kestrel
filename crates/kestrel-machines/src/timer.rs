// SPDX-License-Identifier: LGPL-2.1-or-later

use std::collections::BTreeMap;

/// Identifies one arming of a timer. Expiries carrying an outdated token are
/// ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TimerToken(u64);

#[derive(Debug)]
pub(crate) struct Timers<K> {
    next: u64,
    armed: BTreeMap<K, u64>,
}

impl<K: Ord + Copy> Timers<K> {
    pub(crate) const fn new() -> Self {
        Self {
            next: 0,
            armed: BTreeMap::new(),
        }
    }

    pub(crate) fn arm(&mut self, kind: K) -> TimerToken {
        self.next = self.next.wrapping_add(1);
        self.armed.insert(kind, self.next);
        TimerToken(self.next)
    }

    pub(crate) fn cancel(&mut self, kind: K) {
        self.armed.remove(&kind);
    }

    /// Consumes an expiry. Returns `true` only for the current arming.
    pub(crate) fn fire(&mut self, kind: K, token: TimerToken) -> bool {
        if self.armed.get(&kind) == Some(&token.0) {
            self.armed.remove(&kind);
            true
        } else {
            false
        }
    }

    pub(crate) fn clear(&mut self) {
        self.armed.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_tokens_are_ignored() {
        let mut timers = Timers::new();
        let first = timers.arm(1u8);
        let second = timers.arm(1u8);
        assert!(!timers.fire(1, first));
        assert!(timers.fire(1, second));
        assert!(!timers.fire(1, second));
        let third = timers.arm(1u8);
        timers.cancel(1);
        assert!(!timers.fire(1, third));
    }
}
