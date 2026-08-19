use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const MAX_TRACKED_TRANSACTIONS: usize = 65_536;

type TransactionKey = (u64, u32, String);

/// `TransactionTracker` tracks the state of transactions to detect retransmissions.
pub struct TransactionTracker {
    retention_period: Duration,
    max_entries: usize,
    state: Mutex<TrackerState>,
}

struct TrackerState {
    transactions: HashMap<TransactionKey, TransactionState>,
    completed: VecDeque<(Instant, TransactionKey)>,
}

impl TransactionTracker {
    pub fn new(retention_period: Duration) -> Self {
        Self::new_with_capacity(retention_period, MAX_TRACKED_TRANSACTIONS)
    }

    fn new_with_capacity(retention_period: Duration, max_entries: usize) -> Self {
        assert!(
            max_entries > 0,
            "transaction tracker capacity must be positive"
        );
        Self {
            retention_period,
            max_entries,
            state: Mutex::new(TrackerState {
                transactions: HashMap::new(),
                completed: VecDeque::new(),
            }),
        }
    }

    /// Checks one transport-scoped transaction identity.
    pub fn is_retransmission(
        &self,
        connection_incarnation: u64,
        xid: u32,
        client_addr: &str,
    ) -> bool {
        let key = (connection_incarnation, xid, client_addr.to_string());
        let now = Instant::now();
        let mut state = self
            .state
            .lock()
            .expect("unable to unlock transactions mutex");
        state.expire_completed(now, self.retention_period);
        if state.transactions.contains_key(&key) {
            return true;
        }
        while state.transactions.len() >= self.max_entries {
            if !state.evict_oldest_completed() {
                // Production transport admission bounds in-flight RPCs far below
                // this hard cap. Fail closed if that invariant is ever violated.
                return true;
            }
        }
        state.transactions.insert(key, TransactionState::InProgress);
        false
    }

    pub fn mark_processed(&self, connection_incarnation: u64, xid: u32, client_addr: &str) {
        let key = (connection_incarnation, xid, client_addr.to_string());
        let completion_time = Instant::now();
        let mut state = self
            .state
            .lock()
            .expect("unable to unlock transactions mutex");
        if let Some(transaction) = state.transactions.get_mut(&key) {
            *transaction = TransactionState::Completed(completion_time);
            state.completed.push_back((completion_time, key));
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.state.lock().unwrap().transactions.len()
    }
}

impl TrackerState {
    fn expire_completed(&mut self, now: Instant, retention_period: Duration) {
        while self.completed.front().is_some_and(|(completed_at, _)| {
            now.saturating_duration_since(*completed_at) >= retention_period
        }) {
            self.evict_oldest_completed();
        }
    }

    fn evict_oldest_completed(&mut self) -> bool {
        while let Some((completed_at, key)) = self.completed.pop_front() {
            let is_current = matches!(
                self.transactions.get(&key),
                Some(TransactionState::Completed(current)) if *current == completed_at
            );
            if is_current {
                self.transactions.remove(&key);
                return true;
            }
        }
        false
    }
}

enum TransactionState {
    InProgress,
    Completed(Instant),
}

#[cfg(test)]
mod tests {
    use super::TransactionTracker;
    use std::time::Duration;

    #[test]
    fn connection_incarnation_partitions_transaction_identity() {
        let tracker = TransactionTracker::new_with_capacity(Duration::from_secs(60), 8);

        assert!(!tracker.is_retransmission(11, 7, "127.0.0.1:2049"));
        assert!(tracker.is_retransmission(11, 7, "127.0.0.1:2049"));
        assert!(!tracker.is_retransmission(12, 7, "127.0.0.1:2049"));
    }

    #[test]
    fn completed_transactions_are_evicted_at_the_hard_entry_cap() {
        let tracker = TransactionTracker::new_with_capacity(Duration::from_secs(60), 2);

        assert!(!tracker.is_retransmission(1, 1, "client"));
        tracker.mark_processed(1, 1, "client");
        assert!(!tracker.is_retransmission(1, 2, "client"));
        tracker.mark_processed(1, 2, "client");
        assert_eq!(tracker.len(), 2);

        assert!(!tracker.is_retransmission(1, 3, "client"));
        assert_eq!(tracker.len(), 2);
        assert!(tracker.is_retransmission(1, 2, "client"));
        assert!(
            !tracker.is_retransmission(1, 1, "client"),
            "the oldest completion should be evicted rather than exceeding the cap",
        );
        assert_eq!(tracker.len(), 2);
    }
}
