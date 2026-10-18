use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use kaska_http::models::HttpMethod;
use kaska_http::proxy::NativeProxyServer;
use kaska_http::scope::AuditScope;
use kaska_http::store::create_shared_store;
use kaska_http::test_server::ControlledTestServer;

#[test]
fn test_real_local_http_proxy_capture() {
    let test_port = 28989;
    let proxy_port = 28080;

    // 1. Start local controlled test server
    let test_server = ControlledTestServer::new(test_port);
    test_server.start().expect("Test server failed to start");

    // 2. Start native capturing proxy
    let store = create_shared_store();
    let scope = Arc::new(AuditScope::default());
    let proxy = NativeProxyServer::new(proxy_port, Arc::clone(&store), scope, None);
    proxy.start().expect("Proxy failed to start");

    thread::sleep(Duration::from_millis(150));

    // 3. Connect real TCP client to proxy and send GET request
    let raw_get = format!(
        "GET http://127.0.0.1:{}/api/status HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nUser-Agent: SentinelAudit/1.0\r\nConnection: close\r\n\r\n",
        test_port, test_port
    );

    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
        .expect("Client failed to connect to proxy");
    stream
        .write_all(raw_get.as_bytes())
        .expect("Client failed to send request");
    stream.flush().unwrap();

    let mut response_buf = Vec::new();
    stream
        .read_to_end(&mut response_buf)
        .expect("Failed to read response");
    assert!(!response_buf.is_empty());

    let response_str = String::from_utf8_lossy(&response_buf);
    assert!(response_str.contains("200 OK"));
    assert!(response_str.contains("sentinel-core"));

    // 4. Send real POST request
    let raw_post = format!(
        "POST http://127.0.0.1:{}/api/echo HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: 16\r\nConnection: close\r\n\r\n{{\"audit\":\"live\"}}",
        test_port, test_port
    );

    let mut stream_post = TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
        .expect("Client failed to connect to proxy for POST");
    stream_post
        .write_all(raw_post.as_bytes())
        .expect("Client failed to send POST");
    stream_post.flush().unwrap();

    let mut post_resp_buf = Vec::new();
    stream_post
        .read_to_end(&mut post_resp_buf)
        .expect("Failed to read POST response");
    assert!(!post_resp_buf.is_empty());
    let post_resp_str = String::from_utf8_lossy(&post_resp_buf);
    assert!(post_resp_str.contains("200 OK"));
    assert!(post_resp_str.contains("{\"audit\":\"live\"}"));

    thread::sleep(Duration::from_millis(100));

    // 5. Verify captured transactions in TrafficStore
    let captured = store.lock().unwrap().get_all();
    assert_eq!(
        captured.len(),
        2,
        "Expected exactly 2 captured transactions"
    );

    // Verify first transaction (GET)
    let tx1 = &captured[0];
    assert_eq!(tx1.request.method, HttpMethod::Get);
    assert_eq!(tx1.request.path, "/api/status");
    assert_eq!(tx1.status_code(), 200);
    assert!(tx1.response.is_some());

    // Verify second transaction (POST)
    let tx2 = &captured[1];
    assert_eq!(tx2.request.method, HttpMethod::Post);
    assert_eq!(tx2.request.path, "/api/echo");
    assert_eq!(tx2.status_code(), 200);
    assert_eq!(tx2.request.body_as_utf8(), "{\"audit\":\"live\"}");

    test_server.stop();
    proxy.stop();
}

fn get_free_port() -> u16 {
    let listener =
        std::net::TcpListener::bind("127.0.0.1:0").expect("Failed to bind ephemeral port");
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

#[test]
fn test_proxy_notification_host_out_of_scope() {
    let proxy_port = get_free_port();
    let store = create_shared_store();
    let scope = Arc::new(AuditScope::default()); // only 127.0.0.1 / localhost allowed

    let notifications = Arc::new(std::sync::Mutex::new(Vec::new()));
    let notif_clone = Arc::clone(&notifications);

    let on_tx = Arc::new(move |tx: kaska_http::models::HttpTransaction| {
        notif_clone.lock().unwrap().push(tx);
    });

    let proxy = NativeProxyServer::new(proxy_port, Arc::clone(&store), scope, Some(on_tx));
    proxy.start().expect("Proxy failed to start");

    thread::sleep(Duration::from_millis(80));

    let raw_req = "GET http://unauthorized.evil.example.com/api HTTP/1.1\r\nHost: unauthorized.evil.example.com\r\nConnection: close\r\n\r\n";
    let mut stream =
        TcpStream::connect(format!("127.0.0.1:{}", proxy_port)).expect("Client connect failed");
    stream.write_all(raw_req.as_bytes()).unwrap();
    stream.flush().unwrap();

    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).unwrap();
    assert!(String::from_utf8_lossy(&resp).contains("403 Forbidden"));

    thread::sleep(Duration::from_millis(100));

    // 1. Verify notification callback called exactly once
    let received = notifications.lock().unwrap().clone();
    assert_eq!(
        received.len(),
        1,
        "Expected exactly 1 callback notification"
    );

    // 2. Verify TrafficStore contains exactly 1 transaction
    let stored = store.lock().unwrap().get_all();
    assert_eq!(stored.len(), 1, "Expected exactly 1 stored transaction");

    // 3. Verify ID and state match between callback and store
    assert_eq!(received[0].id, stored[0].id);
    assert_eq!(received[0].id, 1);
    assert!(matches!(
        received[0].state,
        kaska_http::models::TransactionState::Failed(_)
    ));
    assert_eq!(received[0].state, stored[0].state);

    proxy.stop();
}

#[test]
fn test_proxy_notification_upstream_connect_failed() {
    let proxy_port = get_free_port();
    // Allocate an ephemeral port and close it immediately to guarantee an unreachable port
    let dead_target_port = {
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("Failed to bind ephemeral port");
        listener.local_addr().unwrap().port()
    };

    let store = create_shared_store();
    let scope = Arc::new(AuditScope::default());

    let notifications = Arc::new(std::sync::Mutex::new(Vec::new()));
    let notif_clone = Arc::clone(&notifications);

    let on_tx = Arc::new(move |tx: kaska_http::models::HttpTransaction| {
        notif_clone.lock().unwrap().push(tx);
    });

    let proxy = NativeProxyServer::new(proxy_port, Arc::clone(&store), scope, Some(on_tx));
    proxy.start().expect("Proxy failed to start");

    thread::sleep(Duration::from_millis(80));

    let raw_req = format!(
        "GET http://127.0.0.1:{}/unavailable HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        dead_target_port, dead_target_port
    );
    let mut stream =
        TcpStream::connect(format!("127.0.0.1:{}", proxy_port)).expect("Client connect failed");
    stream.write_all(raw_req.as_bytes()).unwrap();
    stream.flush().unwrap();

    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).unwrap();
    assert!(String::from_utf8_lossy(&resp).contains("502 Bad Gateway"));

    thread::sleep(Duration::from_millis(100));

    // 1. Verify notification callback called exactly once
    let received = notifications.lock().unwrap().clone();
    assert_eq!(
        received.len(),
        1,
        "Expected exactly 1 callback notification"
    );

    // 2. Verify store
    let stored = store.lock().unwrap().get_all();
    assert_eq!(stored.len(), 1, "Expected exactly 1 stored transaction");

    // 3. Verify ID and state match
    assert_eq!(received[0].id, stored[0].id);
    assert_eq!(received[0].id, 1);
    assert!(matches!(
        received[0].state,
        kaska_http::models::TransactionState::Failed(_)
    ));
    assert_eq!(received[0].state, stored[0].state);

    proxy.stop();
}

#[test]
fn test_proxy_notification_connect_rejected_and_http_200_normal() {
    let test_port = get_free_port();
    let proxy_port = get_free_port();

    let test_server = ControlledTestServer::new(test_port);
    test_server.start().expect("Test server failed to start");

    let store = create_shared_store();
    let scope = Arc::new(AuditScope::default());

    let notifications = Arc::new(std::sync::Mutex::new(Vec::new()));
    let notif_clone = Arc::clone(&notifications);

    let on_tx = Arc::new(move |tx: kaska_http::models::HttpTransaction| {
        notif_clone.lock().unwrap().push(tx);
    });

    let proxy = NativeProxyServer::new(proxy_port, Arc::clone(&store), scope, Some(on_tx));
    proxy.start().expect("Proxy failed to start");

    thread::sleep(Duration::from_millis(80));

    // Request 1: CONNECT request (501 Not Implemented)
    let raw_connect = "CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n";
    let mut client_connect = TcpStream::connect(format!("127.0.0.1:{}", proxy_port)).unwrap();
    client_connect.write_all(raw_connect.as_bytes()).unwrap();
    client_connect.flush().unwrap();
    let mut connect_resp = Vec::new();
    client_connect.read_to_end(&mut connect_resp).unwrap();
    assert!(String::from_utf8_lossy(&connect_resp).contains("501 Not Implemented"));

    // Request 2: Normal GET request (200 OK)
    let raw_get = format!(
        "GET http://127.0.0.1:{}/api/status HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        test_port, test_port
    );
    let mut client_get = TcpStream::connect(format!("127.0.0.1:{}", proxy_port)).unwrap();
    client_get.write_all(raw_get.as_bytes()).unwrap();
    client_get.flush().unwrap();
    let mut get_resp = Vec::new();
    client_get.read_to_end(&mut get_resp).unwrap();
    assert!(String::from_utf8_lossy(&get_resp).contains("200 OK"));

    thread::sleep(Duration::from_millis(100));

    let received = notifications.lock().unwrap().clone();
    let stored = store.lock().unwrap().get_all();

    // Verify exactly 2 notifications (one for CONNECT, one for GET)
    assert_eq!(received.len(), 2, "Expected exactly 2 notifications");
    assert_eq!(stored.len(), 2, "Expected exactly 2 stored transactions");

    // Verify CONNECT (first)
    assert_eq!(received[0].id, 1);
    assert_eq!(stored[0].id, 1);
    assert_eq!(received[0].request.method, HttpMethod::Connect);
    assert!(matches!(
        received[0].state,
        kaska_http::models::TransactionState::Failed(_)
    ));

    // Verify GET (second)
    assert_eq!(received[1].id, 2);
    assert_eq!(stored[1].id, 2);
    assert_eq!(received[1].request.method, HttpMethod::Get);
    assert_eq!(
        received[1].state,
        kaska_http::models::TransactionState::Completed
    );

    test_server.stop();
    proxy.stop();
}

#[test]
fn test_proxy_notification_callback_runs_outside_store_lock() {
    let proxy_port = get_free_port();
    let store = create_shared_store();
    let scope = Arc::new(AuditScope::default());

    let store_clone = Arc::clone(&store);
    let lock_was_free = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let lock_was_free_clone = Arc::clone(&lock_was_free);

    // In the callback, attempt to acquire store lock immediately.
    // If the callback were executed while proxy holds store_guard, try_lock would fail or deadlock.
    let on_tx = Arc::new(move |_tx: kaska_http::models::HttpTransaction| {
        if let Ok(_guard) = store_clone.try_lock() {
            lock_was_free_clone.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    });

    let proxy = NativeProxyServer::new(proxy_port, Arc::clone(&store), scope, Some(on_tx));
    proxy.start().expect("Proxy failed to start");

    thread::sleep(Duration::from_millis(80));

    let raw_req = "GET http://forbidden.domain.test/ HTTP/1.1\r\nHost: forbidden.domain.test\r\nConnection: close\r\n\r\n";
    let mut stream =
        TcpStream::connect(format!("127.0.0.1:{}", proxy_port)).expect("Client connect failed");
    stream.write_all(raw_req.as_bytes()).unwrap();
    stream.flush().unwrap();

    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).unwrap();

    thread::sleep(Duration::from_millis(100));

    assert!(
        lock_was_free.load(std::sync::atomic::Ordering::SeqCst),
        "TrafficStore lock MUST be released before calling on_transaction callback"
    );

    proxy.stop();
}
