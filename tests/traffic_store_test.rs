use sentinel_desktop::core::models::{HttpMethod, HttpRequest, HttpTransaction, TransactionState};
use sentinel_desktop::history::store::TrafficStore;

#[test]
fn test_store_capacity_and_retrieval() {
    let mut store = TrafficStore::new(3);

    for i in 1..=4 {
        let tx = HttpTransaction {
            id: 0,
            timestamp_rfc3339: "2026-10-11T12:00:00Z".to_string(),
            request: HttpRequest {
                method: HttpMethod::Get,
                raw_url: format!("/item/{}", i),
                host: "127.0.0.1".to_string(),
                path: format!("/item/{}", i),
                query: "".to_string(),
                http_version: "HTTP/1.1".to_string(),
                headers: Vec::new(),
                body: Vec::new(),
            },
            response: None,
            duration_ms: 2,
            state: TransactionState::Completed,
        };
        store.insert(tx);
    }

    // Capacity is 3, so after 4 inserts the count should be 3
    assert_eq!(store.count(), 3);

    // Oldest transaction (id 1) was evicted
    assert!(store.get_by_id(1).is_none());
    assert!(store.get_by_id(4).is_some());

    store.clear();
    assert_eq!(store.count(), 0);
}
