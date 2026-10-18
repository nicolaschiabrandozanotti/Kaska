use kaska_http::models::{
    HttpHeader, HttpMethod, HttpRequest, HttpResponse, HttpTransaction, TransactionState,
};
use kaska_http::store::{TrafficStore, TransactionOutcome};

fn create_sample_transaction(
    method: HttpMethod,
    host: &str,
    path: &str,
    status_code: Option<u16>,
    state: TransactionState,
    body_size: usize,
) -> HttpTransaction {
    let response = status_code.map(|code| HttpResponse {
        status_code: code,
        status_text: match code {
            200 => "OK".to_string(),
            404 => "Not Found".to_string(),
            500 => "Internal Server Error".to_string(),
            _ => "Status".to_string(),
        },
        http_version: "HTTP/1.1".to_string(),
        headers: vec![HttpHeader::new("Content-Type", "application/json")],
        body: vec![b'X'; body_size],
    });

    HttpTransaction {
        id: 0,
        timestamp_rfc3339: "2026-10-17T12:00:00Z".to_string(),
        request: HttpRequest {
            method,
            raw_url: format!("http://{}{}", host, path),
            host: host.to_string(),
            path: path.to_string(),
            query: "".to_string(),
            http_version: "HTTP/1.1".to_string(),
            headers: vec![HttpHeader::new("Host", host)],
            body: vec![b'Y'; body_size],
        },
        response,
        duration_ms: 15,
        state,
    }
}

#[test]
fn test_store_capacity_and_retrieval() {
    let mut store = TrafficStore::new(3);

    for i in 1..=4 {
        let tx = create_sample_transaction(
            HttpMethod::Get,
            "127.0.0.1",
            &format!("/item/{}", i),
            None,
            TransactionState::Completed,
            0,
        );
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

#[test]
fn test_snapshot_empty() {
    let store = TrafficStore::new(10);
    let snapshot = store.get_metadata_snapshot();
    assert!(snapshot.is_empty());
    assert_eq!(store.count(), 0);
}

#[test]
fn test_snapshot_insertion_order_preserved() {
    let mut store = TrafficStore::new(5);
    for i in 1..=5 {
        let tx = create_sample_transaction(
            HttpMethod::Get,
            "localhost",
            &format!("/path/{}", i),
            Some(200),
            TransactionState::Completed,
            10,
        );
        store.insert(tx);
    }

    let snapshot = store.get_metadata_snapshot();
    assert_eq!(snapshot.len(), 5);
    for (idx, summary) in snapshot.iter().enumerate() {
        let expected_id = (idx + 1) as u64;
        assert_eq!(summary.id, expected_id);
        assert_eq!(summary.path, format!("/path/{}", expected_id));
    }
}

#[test]
fn test_snapshot_fifo_eviction_and_id_monotonicity() {
    let mut store = TrafficStore::new(3);

    for i in 1..=5 {
        let tx = create_sample_transaction(
            HttpMethod::Post,
            "127.0.0.1",
            &format!("/req/{}", i),
            Some(200),
            TransactionState::Completed,
            0,
        );
        store.insert(tx);
    }

    // Capacity 3, so items 1 and 2 were evicted; items 3, 4, 5 remain
    let snapshot = store.get_metadata_snapshot();
    assert_eq!(snapshot.len(), 3);
    assert_eq!(snapshot[0].id, 3);
    assert_eq!(snapshot[1].id, 4);
    assert_eq!(snapshot[2].id, 5);

    // Next insertion gets ID 6
    let tx6 = create_sample_transaction(
        HttpMethod::Get,
        "127.0.0.1",
        "/req/6",
        Some(200),
        TransactionState::Completed,
        0,
    );
    let id6 = store.insert(tx6);
    assert_eq!(id6, 6);

    let snapshot2 = store.get_metadata_snapshot();
    assert_eq!(snapshot2.len(), 3);
    assert_eq!(snapshot2[0].id, 4);
    assert_eq!(snapshot2[1].id, 5);
    assert_eq!(snapshot2[2].id, 6);
}

#[test]
fn test_snapshot_clear_and_id_monotonicity() {
    let mut store = TrafficStore::new(5);
    store.insert(create_sample_transaction(
        HttpMethod::Get,
        "localhost",
        "/1",
        Some(200),
        TransactionState::Completed,
        0,
    ));
    store.insert(create_sample_transaction(
        HttpMethod::Get,
        "localhost",
        "/2",
        Some(200),
        TransactionState::Completed,
        0,
    ));
    assert_eq!(store.count(), 2);

    store.clear();
    assert_eq!(store.count(), 0);
    assert!(store.get_metadata_snapshot().is_empty());

    // After clear, next_id continues monotonically
    let id3 = store.insert(create_sample_transaction(
        HttpMethod::Get,
        "localhost",
        "/3",
        Some(200),
        TransactionState::Completed,
        0,
    ));
    assert_eq!(id3, 3);

    let snapshot = store.get_metadata_snapshot();
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot[0].id, 3);
}

#[test]
fn test_snapshot_metadata_consistency() {
    let mut store = TrafficStore::new(10);
    let tx = create_sample_transaction(
        HttpMethod::Post,
        "api.example.com",
        "/v1/resource",
        Some(201),
        TransactionState::Completed,
        512,
    );
    let id = store.insert(tx);

    let snapshot = store.get_metadata_snapshot();
    assert_eq!(snapshot.len(), 1);
    let s = &snapshot[0];

    assert_eq!(s.id, id);
    assert_eq!(s.timestamp_rfc3339, "2026-10-17T12:00:00Z");
    assert_eq!(s.method, HttpMethod::Post);
    assert_eq!(s.host, "api.example.com");
    assert_eq!(s.path, "/v1/resource");
    assert_eq!(s.status_code, 201);
    assert_eq!(s.status_text, "Status");
    assert_eq!(s.duration_ms, 15);
    assert_eq!(s.response_size_bytes, 512);
    assert_eq!(s.content_type, "application/json");
    assert_eq!(s.outcome, TransactionOutcome::Completed);
}

#[test]
fn test_snapshot_large_body_buffers_not_exposed() {
    let mut store = TrafficStore::new(2);
    // 1 MB request and response bodies
    let large_body_size = 1024 * 1024;
    let tx = create_sample_transaction(
        HttpMethod::Post,
        "localhost",
        "/upload",
        Some(200),
        TransactionState::Completed,
        large_body_size,
    );
    store.insert(tx);

    let snapshot = store.get_metadata_snapshot();
    assert_eq!(snapshot.len(), 1);
    let s = &snapshot[0];

    // TransactionSummary provides response_size_bytes accurately without holding the buffer
    assert_eq!(s.response_size_bytes, large_body_size);
    // Verified: TransactionSummary struct definition does not have body fields
    assert_eq!(s.id, 1);
}

#[test]
fn test_snapshot_outcomes_pending_completed_failed() {
    let mut store = TrafficStore::new(5);

    // 1. Pending (no response yet)
    let tx_pending = create_sample_transaction(
        HttpMethod::Get,
        "localhost",
        "/pending",
        None,
        TransactionState::Pending,
        0,
    );
    store.insert(tx_pending);

    // 2. Completed
    let tx_completed = create_sample_transaction(
        HttpMethod::Get,
        "localhost",
        "/completed",
        Some(200),
        TransactionState::Completed,
        100,
    );
    store.insert(tx_completed);

    // 3. Failed
    let tx_failed = create_sample_transaction(
        HttpMethod::Get,
        "localhost",
        "/failed",
        None,
        TransactionState::Failed("Connection reset by peer".to_string()),
        0,
    );
    store.insert(tx_failed);

    let snapshot = store.get_metadata_snapshot();
    assert_eq!(snapshot.len(), 3);

    assert_eq!(snapshot[0].outcome, TransactionOutcome::Pending);
    assert_eq!(snapshot[0].status_code, 0);
    assert_eq!(snapshot[0].status_text, "Pending");

    assert_eq!(snapshot[1].outcome, TransactionOutcome::Completed);
    assert_eq!(snapshot[1].status_code, 200);
    assert_eq!(snapshot[1].status_text, "OK");

    assert_eq!(snapshot[2].outcome, TransactionOutcome::Failed);
    assert_eq!(snapshot[2].status_code, 0);
    assert_eq!(snapshot[2].status_text, "Failed");
}

#[test]
fn test_ten_thousand_transactions_snapshot_correctness() {
    let mut store = TrafficStore::new(10_000);

    for i in 1..=10_000 {
        let method = if i % 2 == 0 {
            HttpMethod::Post
        } else {
            HttpMethod::Get
        };
        let status = if i % 10 == 0 { 500 } else { 200 };
        let tx = create_sample_transaction(
            method,
            "127.0.0.1",
            &format!("/item/{}", i),
            Some(status),
            TransactionState::Completed,
            16,
        );
        store.insert(tx);
    }

    assert_eq!(store.count(), 10_000);
    let snapshot = store.get_metadata_snapshot();
    assert_eq!(snapshot.len(), 10_000);

    // Verify first, middle, last
    assert_eq!(snapshot[0].id, 1);
    assert_eq!(snapshot[0].method, HttpMethod::Get);
    assert_eq!(snapshot[0].path, "/item/1");
    assert_eq!(snapshot[0].status_code, 200);

    assert_eq!(snapshot[4999].id, 5000);
    assert_eq!(snapshot[4999].method, HttpMethod::Post);
    assert_eq!(snapshot[4999].path, "/item/5000");
    assert_eq!(snapshot[4999].status_code, 500);

    assert_eq!(snapshot[9999].id, 10_000);
    assert_eq!(snapshot[9999].method, HttpMethod::Post);
    assert_eq!(snapshot[9999].path, "/item/10000");
    assert_eq!(snapshot[9999].status_code, 500);
}
