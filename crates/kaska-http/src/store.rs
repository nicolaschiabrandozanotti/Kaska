use crate::models::HttpTransaction;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

/// Maximum number of transactions kept in memory to maintain low RAM footprint
const DEFAULT_MAX_CAPACITY: usize = 10_000;

#[derive(Debug)]
pub struct TrafficStore {
    transactions: VecDeque<HttpTransaction>,
    next_id: u64,
    max_capacity: usize,
}

impl Default for TrafficStore {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_CAPACITY)
    }
}

impl TrafficStore {
    pub fn new(max_capacity: usize) -> Self {
        Self {
            transactions: VecDeque::new(),
            next_id: 1,
            max_capacity,
        }
    }

    pub fn insert(&mut self, mut transaction: HttpTransaction) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        transaction.id = id;

        if self.transactions.len() >= self.max_capacity {
            self.transactions.pop_front();
        }

        self.transactions.push_back(transaction);
        id
    }

    pub fn get_by_id(&self, id: u64) -> Option<&HttpTransaction> {
        self.transactions.iter().find(|t| t.id == id)
    }

    pub fn get_all(&self) -> Vec<HttpTransaction> {
        self.transactions.iter().cloned().collect()
    }

    pub fn count(&self) -> usize {
        self.transactions.len()
    }

    pub fn clear(&mut self) {
        self.transactions.clear();
    }
}

pub type SharedTrafficStore = Arc<Mutex<TrafficStore>>;

pub fn create_shared_store() -> SharedTrafficStore {
    Arc::new(Mutex::new(TrafficStore::default()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{HttpMethod, HttpRequest, TransactionState};

    #[test]
    fn test_traffic_store_insertion() {
        let mut store = TrafficStore::new(10);
        let tx = HttpTransaction {
            id: 0,
            timestamp_rfc3339: "2026-10-11T12:00:00Z".to_string(),
            request: HttpRequest {
                method: HttpMethod::Get,
                raw_url: "/".to_string(),
                host: "localhost".to_string(),
                path: "/".to_string(),
                query: "".to_string(),
                http_version: "HTTP/1.1".to_string(),
                headers: Vec::new(),
                body: Vec::new(),
            },
            response: None,
            duration_ms: 5,
            state: TransactionState::Completed,
        };

        let id = store.insert(tx);
        assert_eq!(id, 1);
        assert_eq!(store.count(), 1);
        assert!(store.get_by_id(1).is_some());
    }
}
