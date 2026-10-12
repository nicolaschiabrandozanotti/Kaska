use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use kaska_http::models::{HttpMethod, TransactionState};
use kaska_http::proxy::NativeProxyServer;
use kaska_http::scope::AuditScope;
use kaska_http::store::create_shared_store;
use kaska_http::test_server::ControlledTestServer;

fn get_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind ephemeral port");
    listener.local_addr().unwrap().port()
}

#[test]
fn test_proxy_get_and_post_local() {
    let test_port = get_free_port();
    let proxy_port = get_free_port();

    let test_server = ControlledTestServer::new(test_port);
    test_server.start().expect("Test server failed to start");

    let store = create_shared_store();
    let scope = Arc::new(AuditScope::default());
    let proxy = NativeProxyServer::new(proxy_port, Arc::clone(&store), scope, None);
    proxy.start().expect("Proxy failed to start");

    thread::sleep(Duration::from_millis(80));

    // 1. GET request
    let raw_get = format!(
        "GET http://127.0.0.1:{}/api/status HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        test_port, test_port
    );
    let mut client = TcpStream::connect(format!("127.0.0.1:{}", proxy_port)).unwrap();
    client.write_all(raw_get.as_bytes()).unwrap();
    client.flush().unwrap();

    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    let resp_str = String::from_utf8_lossy(&response);
    assert!(resp_str.contains("200 OK"));
    assert!(resp_str.contains("sentinel-core"));

    // 2. POST request
    let raw_post = format!(
        "POST http://127.0.0.1:{}/api/echo HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: 18\r\nConnection: close\r\n\r\n{{\"audit\":\"passed\"}}",
        test_port, test_port
    );
    let mut client_post = TcpStream::connect(format!("127.0.0.1:{}", proxy_port)).unwrap();
    client_post.write_all(raw_post.as_bytes()).unwrap();
    client_post.flush().unwrap();

    let mut post_response = Vec::new();
    client_post.read_to_end(&mut post_response).unwrap();
    let post_resp_str = String::from_utf8_lossy(&post_response);
    assert!(post_resp_str.contains("200 OK"));
    assert!(post_resp_str.contains("{\"audit\":\"passed\"}"));

    test_server.stop();
    proxy.stop();
}

#[test]
fn test_proxy_localhost_resolution() {
    let test_port = get_free_port();
    let proxy_port = get_free_port();

    let test_server = ControlledTestServer::new(test_port);
    test_server.start().expect("Test server failed to start");

    let store = create_shared_store();
    let scope = Arc::new(AuditScope::default());
    let proxy = NativeProxyServer::new(proxy_port, Arc::clone(&store), scope, None);
    proxy.start().expect("Proxy failed to start");

    thread::sleep(Duration::from_millis(80));

    // Send request using 'localhost' hostname
    let raw_req = format!(
        "GET http://localhost:{}/api/status HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\n\r\n",
        test_port, test_port
    );
    let mut client = TcpStream::connect(format!("127.0.0.1:{}", proxy_port)).unwrap();
    client.write_all(raw_req.as_bytes()).unwrap();
    client.flush().unwrap();

    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    let resp_str = String::from_utf8_lossy(&response);
    assert!(resp_str.contains("200 OK"));

    test_server.stop();
    proxy.stop();
}

#[test]
fn test_proxy_invalid_hostname_fails_gracefully() {
    let proxy_port = get_free_port();

    let store = create_shared_store();
    let mut scope = AuditScope::default();
    // Allow the hostname in scope so it passes pre-resolution, but let DNS fail
    scope.add_host("nonexistent-invalid-host-999.test");
    let proxy = NativeProxyServer::new(proxy_port, Arc::clone(&store), Arc::new(scope), None);
    proxy.start().expect("Proxy failed to start");

    thread::sleep(Duration::from_millis(80));

    let raw_req = "GET http://nonexistent-invalid-host-999.test:80/ HTTP/1.1\r\nHost: nonexistent-invalid-host-999.test:80\r\nConnection: close\r\n\r\n";
    let mut client = TcpStream::connect(format!("127.0.0.1:{}", proxy_port)).unwrap();
    client.write_all(raw_req.as_bytes()).unwrap();
    client.flush().unwrap();

    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    let resp_str = String::from_utf8_lossy(&response);

    // Must return 502 Bad Gateway and not fallback to 127.0.0.1
    assert!(resp_str.contains("502 Bad Gateway"));
    assert!(resp_str.contains("DNS resolution failed"));

    proxy.stop();
}

#[test]
fn test_proxy_out_of_scope_rejected() {
    let proxy_port = get_free_port();

    let store = create_shared_store();
    let scope = Arc::new(AuditScope::default()); // default only allows 127.0.0.1, localhost, ::1
    let proxy = NativeProxyServer::new(proxy_port, Arc::clone(&store), scope, None);
    proxy.start().expect("Proxy failed to start");

    thread::sleep(Duration::from_millis(80));

    let raw_req = "GET http://unauthorized-external-domain.com/secret HTTP/1.1\r\nHost: unauthorized-external-domain.com\r\nConnection: close\r\n\r\n";
    let mut client = TcpStream::connect(format!("127.0.0.1:{}", proxy_port)).unwrap();
    client.write_all(raw_req.as_bytes()).unwrap();
    client.flush().unwrap();

    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    let resp_str = String::from_utf8_lossy(&response);

    // Must return 403 Forbidden
    assert!(resp_str.contains("403 Forbidden"));
    assert!(resp_str.contains("outside authorized scope"));

    let transactions = store.lock().unwrap().get_all();
    assert_eq!(transactions.len(), 1);
    assert!(matches!(transactions[0].state, TransactionState::Failed(_)));

    proxy.stop();
}

#[test]
fn test_proxy_connect_unsupported_explicit_501() {
    let proxy_port = get_free_port();

    let store = create_shared_store();
    let scope = Arc::new(AuditScope::default());
    let proxy = NativeProxyServer::new(proxy_port, Arc::clone(&store), scope, None);
    proxy.start().expect("Proxy failed to start");

    thread::sleep(Duration::from_millis(80));

    let raw_connect = "CONNECT 127.0.0.1:8443 HTTP/1.1\r\nHost: 127.0.0.1:8443\r\n\r\n";
    let mut client = TcpStream::connect(format!("127.0.0.1:{}", proxy_port)).unwrap();
    client.write_all(raw_connect.as_bytes()).unwrap();
    client.flush().unwrap();

    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    let resp_str = String::from_utf8_lossy(&response);

    assert!(resp_str.contains("501 Not Implemented"));
    assert!(resp_str.contains("CONNECT tunneling is not supported in Milestone 0.4"));

    let txs = store.lock().unwrap().get_all();
    assert_eq!(txs.len(), 1);
    assert_eq!(txs[0].request.method, HttpMethod::Connect);

    proxy.stop();
}

#[test]
fn test_proxy_chunked_with_extensions_and_trailers() {
    let test_port = get_free_port();
    let proxy_port = get_free_port();

    let test_server = ControlledTestServer::new(test_port);
    test_server.start().expect("Test server failed to start");

    let store = create_shared_store();
    let scope = Arc::new(AuditScope::default());
    let proxy = NativeProxyServer::new(proxy_port, Arc::clone(&store), scope, None);
    proxy.start().expect("Proxy failed to start");

    thread::sleep(Duration::from_millis(80));

    let raw_req = format!(
        "GET http://127.0.0.1:{}/api/chunked HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        test_port, test_port
    );
    let mut client = TcpStream::connect(format!("127.0.0.1:{}", proxy_port)).unwrap();
    client.write_all(raw_req.as_bytes()).unwrap();
    client.flush().unwrap();

    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    let resp_str = String::from_utf8_lossy(&response);

    assert!(resp_str.contains("200 OK"));
    assert!(resp_str.contains("Hello"));
    assert!(resp_str.contains("Chunk!"));

    // Verify stored transaction in traffic store
    let txs = store.lock().unwrap().get_all();
    assert_eq!(txs.len(), 1);
    let tx = &txs[0];
    assert_eq!(tx.status_code(), 200);
    let body_str = tx.response.as_ref().unwrap().body_as_utf8();
    assert_eq!(body_str, "Hello Chunk!");

    test_server.stop();
    proxy.stop();
}

#[test]
fn test_proxy_progressive_streaming() {
    let test_port = get_free_port();
    let proxy_port = get_free_port();

    let test_server = ControlledTestServer::new(test_port);
    test_server.start().expect("Test server failed to start");

    let store = create_shared_store();
    let scope = Arc::new(AuditScope::default());
    let proxy = NativeProxyServer::new(proxy_port, Arc::clone(&store), scope, None);
    proxy.start().expect("Proxy failed to start");

    thread::sleep(Duration::from_millis(80));

    let raw_req = format!(
        "GET http://127.0.0.1:{}/api/stream HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        test_port, test_port
    );
    let mut client = TcpStream::connect(format!("127.0.0.1:{}", proxy_port)).unwrap();
    client.write_all(raw_req.as_bytes()).unwrap();
    client.flush().unwrap();

    // Client reads chunks progressively
    let mut buffer = [0u8; 4096];
    let mut received = Vec::new();
    loop {
        match client.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                received.extend_from_slice(&buffer[..n]);
                if String::from_utf8_lossy(&received).contains("0\r\n\r\n") {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    let stream_resp = String::from_utf8_lossy(&received);
    assert!(stream_resp.contains("part1"));
    assert!(stream_resp.contains("part2"));
    assert!(stream_resp.contains("part3"));

    test_server.stop();
    proxy.stop();
}

#[test]
fn test_proxy_partial_content_206() {
    let test_port = get_free_port();
    let proxy_port = get_free_port();

    let test_server = ControlledTestServer::new(test_port);
    test_server.start().expect("Test server failed to start");

    let store = create_shared_store();
    let scope = Arc::new(AuditScope::default());
    let proxy = NativeProxyServer::new(proxy_port, Arc::clone(&store), scope, None);
    proxy.start().expect("Proxy failed to start");

    thread::sleep(Duration::from_millis(80));

    let raw_req = format!(
        "GET http://127.0.0.1:{}/api/range HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        test_port, test_port
    );
    let mut client = TcpStream::connect(format!("127.0.0.1:{}", proxy_port)).unwrap();
    client.write_all(raw_req.as_bytes()).unwrap();
    client.flush().unwrap();

    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    let resp_str = String::from_utf8_lossy(&response);

    assert!(resp_str.contains("206 Partial Content"));
    assert!(resp_str.contains("Content-Range: bytes 0-4/10"));
    assert!(resp_str.contains("01234"));

    test_server.stop();
    proxy.stop();
}

#[test]
fn test_proxy_connection_close_enforced() {
    let test_port = get_free_port();
    let proxy_port = get_free_port();

    let test_server = ControlledTestServer::new(test_port);
    test_server.start().expect("Test server failed to start");

    let store = create_shared_store();
    let scope = Arc::new(AuditScope::default());
    let proxy = NativeProxyServer::new(proxy_port, Arc::clone(&store), scope, None);
    proxy.start().expect("Proxy failed to start");

    thread::sleep(Duration::from_millis(80));

    // Send request with Connection: keep-alive
    let raw_req = format!(
        "GET http://127.0.0.1:{}/api/status HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: keep-alive\r\n\r\n",
        test_port, test_port
    );
    let mut client = TcpStream::connect(format!("127.0.0.1:{}", proxy_port)).unwrap();
    client.write_all(raw_req.as_bytes()).unwrap();
    client.flush().unwrap();

    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    let resp_str = String::from_utf8_lossy(&response);

    // Proxy must enforce Connection: close
    assert!(resp_str.contains("Connection: close"));

    test_server.stop();
    proxy.stop();
}

#[test]
fn test_proxy_malformed_and_conflicting_framing() {
    let proxy_port = get_free_port();

    let store = create_shared_store();
    let scope = Arc::new(AuditScope::default());
    let proxy = NativeProxyServer::new(proxy_port, Arc::clone(&store), scope, None);
    proxy.start().expect("Proxy failed to start");

    thread::sleep(Duration::from_millis(80));

    // Conflicting Content-Length and Transfer-Encoding in client request
    let raw_conflicting = "POST /api/test HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
    let mut client = TcpStream::connect(format!("127.0.0.1:{}", proxy_port)).unwrap();
    client.write_all(raw_conflicting.as_bytes()).unwrap();
    client.flush().unwrap();

    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    let resp_str = String::from_utf8_lossy(&response);

    assert!(resp_str.contains("400 Bad Request"));
    assert!(resp_str.contains("Conflicting Content-Length and Transfer-Encoding"));

    proxy.stop();
}

#[test]
fn test_proxy_start_stop_lifecycle_and_port_release() {
    let port = get_free_port();
    let store = create_shared_store();
    let scope = Arc::new(AuditScope::default());

    let proxy = NativeProxyServer::new(port, store, scope, None);
    assert!(!proxy.is_running());

    proxy.start().expect("Failed to start proxy");
    assert!(proxy.is_running());

    thread::sleep(Duration::from_millis(50));
    proxy.stop();
    thread::sleep(Duration::from_millis(80));
    assert!(!proxy.is_running());

    // Verify port is immediately reusable
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port));
    assert!(listener.is_ok(), "Port must be freed after stop()");
}
