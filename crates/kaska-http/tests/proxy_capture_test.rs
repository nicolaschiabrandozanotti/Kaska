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
