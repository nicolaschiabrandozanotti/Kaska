use std::io::{Read, Write};
use std::net::{Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use kaska_http::models::{HttpHeader, HttpMethod};
use kaska_http::repeater::{
    HttpRepeaterEngine, RepeaterConfig, RepeaterError, RepeaterRequestSpec,
};
use kaska_http::scope::AuditScope;
use kaska_http::test_server::ControlledTestServer;

fn bind_ephemeral_v4() -> (TcpListener, u16) {
    let listener =
        TcpListener::bind("127.0.0.1:0").expect("Failed to bind ephemeral IPv4 loopback port");
    let port = listener.local_addr().unwrap().port();
    (listener, port)
}

/// Helper that reads a complete HTTP/1.1 request (headers + Content-Length body) from a stream
fn read_full_http_request(stream: &mut TcpStream) -> Vec<u8> {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(2000)));
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];

    let header_end_pos = loop {
        match stream.read(&mut chunk) {
            Ok(n) if n > 0 => {
                buf.extend_from_slice(&chunk[..n]);
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break pos + 4;
                }
            }
            _ => return buf,
        }
    };

    let header_str = String::from_utf8_lossy(&buf[..header_end_pos]);
    let content_len = header_str
        .lines()
        .find_map(|line| {
            let (k, v) = line.split_once(':')?;
            if k.trim().eq_ignore_ascii_case("content-length") {
                v.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);

    while buf.len() < header_end_pos + content_len {
        let remaining = (header_end_pos + content_len) - buf.len();
        let to_read = std::cmp::min(chunk.len(), remaining);
        match stream.read(&mut chunk[..to_read]) {
            Ok(n) if n > 0 => buf.extend_from_slice(&chunk[..n]),
            _ => break,
        }
    }

    buf
}

#[test]
fn test_repeater_get_and_post_against_controlled_server() {
    let (_, test_port) = bind_ephemeral_v4();
    let test_server = ControlledTestServer::new(test_port);
    test_server.start().expect("Failed to start test server");
    thread::sleep(Duration::from_millis(50));

    let engine = HttpRepeaterEngine::default();

    // 1. GET /api/status on 127.0.0.1
    let get_spec = RepeaterRequestSpec::new(
        HttpMethod::Get,
        format!("http://127.0.0.1:{}/api/status", test_port),
    )
    .with_headers(vec![HttpHeader::new("Accept", "application/json")]);

    let get_res = engine
        .execute(&get_spec, None)
        .expect("GET execution failed");
    assert_eq!(get_res.response.status_code, 200);
    assert!(!get_res.response_body_truncated);
    assert!(get_res.response.body_as_utf8().contains("sentinel-core"));
    assert_eq!(
        get_res.request.header_value("connection").as_deref(),
        Some("close")
    );

    // 2. POST /api/echo via localhost with edited body and stale Content-Length header
    let edited_body = br#"{"repeater":"active","edited":true,"items":[1,2,3]}"#.to_vec();
    let post_spec = RepeaterRequestSpec::new(
        HttpMethod::Post,
        format!("http://localhost:{}/api/echo", test_port),
    )
    .with_header("Content-Type", "application/json")
    .with_header("Content-Length", "5")
    .with_body(edited_body.clone());

    let post_res = engine
        .execute(&post_spec, None)
        .expect("POST execution failed");
    assert_eq!(post_res.response.status_code, 200);
    assert_eq!(post_res.response.body, edited_body);
    assert_eq!(
        post_res.request.content_length(),
        Some(edited_body.len()),
        "Repeater must recalculate Content-Length from actual body length"
    );

    test_server.stop();
}

#[test]
fn test_repeater_methods_query_and_large_body_framing() {
    let (listener, port) = bind_ephemeral_v4();

    let server_handle = thread::spawn(move || {
        for _ in 0..5 {
            if let Ok((mut stream, _)) = listener.accept() {
                let raw_req = read_full_http_request(&mut stream);
                let parsed = kaska_http::HttpParser::parse_request(&raw_req).unwrap();

                let body_out = format!(
                    "method={};path={};query={};host={};body_len={}",
                    parsed.method,
                    parsed.path,
                    parsed.query,
                    parsed.host,
                    parsed.body.len()
                );
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body_out.len(),
                    body_out
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.flush();
            }
        }
    });

    let engine = HttpRepeaterEngine::default();

    // 1. OPTIONS with query parameters
    let opt_spec = RepeaterRequestSpec::new(
        HttpMethod::Options,
        format!("http://127.0.0.1:{}/api/items?page=3&sort=asc", port),
    );
    let opt_res = engine.execute(&opt_spec, None).unwrap();
    assert_eq!(
        opt_res.response.body_as_utf8(),
        format!(
            "method=OPTIONS;path=/api/items;query=page=3&sort=asc;host=127.0.0.1:{};body_len=0",
            port
        )
    );

    // 2. PUT with 32 KiB payload (larger than 8 KiB single read buffer)
    let large_payload = vec![b'A'; 32 * 1024];
    let put_spec = RepeaterRequestSpec::new(
        HttpMethod::Put,
        format!("http://127.0.0.1:{}/api/upload", port),
    )
    .with_body(large_payload.clone());
    let put_res = engine.execute(&put_spec, None).unwrap();
    assert!(put_res
        .response
        .body_as_utf8()
        .contains("method=PUT;path=/api/upload;query=;"));
    assert!(put_res
        .response
        .body_as_utf8()
        .ends_with(&format!("body_len={}", large_payload.len())));

    // 3. PATCH
    let patch_spec = RepeaterRequestSpec::new(
        HttpMethod::Patch,
        format!("http://127.0.0.1:{}/api/item/7", port),
    )
    .with_body(b"{\"op\":\"replace\"}".to_vec());
    let patch_res = engine.execute(&patch_spec, None).unwrap();
    assert!(patch_res
        .response
        .body_as_utf8()
        .contains("method=PATCH;path=/api/item/7;query=;"));

    // 4. DELETE
    let del_spec = RepeaterRequestSpec::new(
        HttpMethod::Delete,
        format!("http://127.0.0.1:{}/api/item/7", port),
    );
    let del_res = engine.execute(&del_spec, None).unwrap();
    assert!(del_res
        .response
        .body_as_utf8()
        .contains("method=DELETE;path=/api/item/7;query=;"));

    // 5. HEAD (server sends Content-Length > 0, client must not block waiting for body)
    let head_spec = RepeaterRequestSpec::new(
        HttpMethod::Head,
        format!("http://127.0.0.1:{}/api/head-check", port),
    );
    let head_res = engine.execute(&head_spec, None).unwrap();
    assert_eq!(head_res.response.status_code, 200);
    assert!(
        head_res.response.body.is_empty(),
        "HEAD response must never accumulate body bytes"
    );

    server_handle.join().unwrap();
}

#[test]
fn test_repeater_ipv6_loopback_when_available() {
    let bind_v6 = TcpListener::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, 0)));
    let Ok(listener) = bind_v6 else {
        return;
    };
    let port = listener.local_addr().unwrap().port();

    let handle = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let _ = read_full_http_request(&mut stream);
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nIPv6-OK",
            );
            let _ = stream.flush();
        }
    });

    let engine = HttpRepeaterEngine::default();
    let spec =
        RepeaterRequestSpec::new(HttpMethod::Get, format!("http://[::1]:{}/ipv6-test", port))
            .with_header("Host", format!("[::1]:{}", port));

    let res = engine.execute(&spec, None).expect("IPv6 loopback failed");
    assert_eq!(res.response.status_code, 200);
    assert_eq!(res.response.body_as_utf8(), "IPv6-OK");
    assert!(res.remote_addr.ip().is_loopback());

    handle.join().unwrap();
}

#[test]
fn test_repeater_security_rejections_comprehensive() {
    let engine = HttpRepeaterEngine::default();

    for bad_url in [
        "http://127.0.0.1:0/api",
        "http://127.0.0.1:65536/api",
        "http://127.0.0.1:abc/api",
        "http://127.0.0.1:/api",
        "http://[::1]:0/api",
    ] {
        assert!(
            matches!(
                engine.execute(&RepeaterRequestSpec::new(HttpMethod::Get, bad_url), None),
                Err(RepeaterError::InvalidUrl(_))
            ),
            "Expected InvalidUrl for {}",
            bad_url
        );
    }

    for out_of_scope_url in [
        "http://example.com/api",
        "http://192.168.1.1:8080/api",
        "http://10.0.0.1/api",
        "http://127.0.0.2/api",
        "http://2130706433/api",
        "http://0177.0.0.1/api",
        "http://[::ffff:127.0.0.1]/api",
    ] {
        assert!(
            matches!(
                engine.execute(
                    &RepeaterRequestSpec::new(HttpMethod::Get, out_of_scope_url),
                    None
                ),
                Err(RepeaterError::HostOutOfScope(_))
            ),
            "Expected HostOutOfScope for {}",
            out_of_scope_url
        );
    }

    let mismatch = RepeaterRequestSpec::new(HttpMethod::Get, "http://127.0.0.1:8989/api")
        .with_header("Host", "127.0.0.1:9999");
    assert!(matches!(
        engine.execute(&mismatch, None),
        Err(RepeaterError::HostHeaderMismatch { .. })
    ));

    let mismatch_external = RepeaterRequestSpec::new(HttpMethod::Get, "http://127.0.0.1:8989/api")
        .with_header("Host", "attacker.com");
    assert!(matches!(
        engine.execute(&mismatch_external, None),
        Err(RepeaterError::HostHeaderMismatch { .. })
    ));

    let userinfo_spec =
        RepeaterRequestSpec::new(HttpMethod::Get, "http://user:pass@127.0.0.1:8989/api");
    assert!(matches!(
        engine.execute(&userinfo_spec, None),
        Err(RepeaterError::InvalidUrl(_))
    ));

    let crlf_url = RepeaterRequestSpec::new(
        HttpMethod::Get,
        "http://127.0.0.1:8989/api\r\nX-Injected: 1",
    );
    assert!(matches!(
        engine.execute(&crlf_url, None),
        Err(RepeaterError::InvalidUrl(_))
    ));

    let crlf_hdr = RepeaterRequestSpec::new(HttpMethod::Get, "http://127.0.0.1:8989/api")
        .with_header("X-Header", "val\nInjected: true");
    assert!(matches!(
        engine.execute(&crlf_hdr, None),
        Err(RepeaterError::InvalidHeader(_))
    ));

    assert!(matches!(
        RepeaterRequestSpec::from_raw_headers(
            HttpMethod::Get,
            "http://127.0.0.1:8989/api",
            "MalformedLineWithoutColon\r\n",
            Vec::new()
        ),
        Err(RepeaterError::InvalidHeader(_))
    ));

    let small_req_cfg = RepeaterConfig {
        max_request_body_bytes: 16,
        ..RepeaterConfig::default()
    };
    let small_req_engine = HttpRepeaterEngine::new(Arc::new(AuditScope::default()), small_req_cfg);
    let oversized_req = RepeaterRequestSpec::new(HttpMethod::Post, "http://127.0.0.1:8989/api")
        .with_body(vec![b'X'; 32]);
    assert!(matches!(
        small_req_engine.execute(&oversized_req, None),
        Err(RepeaterError::RequestBodyTooLarge {
            actual: 32,
            limit: 16
        })
    ));
}

#[test]
fn test_repeater_chunked_valid_and_malformed_or_incomplete() {
    let (_, test_port) = bind_ephemeral_v4();
    let test_server = ControlledTestServer::new(test_port);
    test_server.start().unwrap();
    thread::sleep(Duration::from_millis(50));

    let engine = HttpRepeaterEngine::default();

    let spec = RepeaterRequestSpec::new(
        HttpMethod::Get,
        format!("http://127.0.0.1:{}/api/chunked", test_port),
    );
    let res = engine.execute(&spec, None).unwrap();
    assert_eq!(res.response.status_code, 200);
    assert_eq!(res.response.body_as_utf8(), "Hello Chunk!");
    assert!(!res.response_body_truncated);

    test_server.stop();

    let (inc_listener, inc_port) = bind_ephemeral_v4();
    let inc_handle = thread::spawn(move || {
        if let Ok((mut stream, _)) = inc_listener.accept() {
            let _ = read_full_http_request(&mut stream);
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nHello\r\n",
            );
            let _ = stream.flush();
        }
    });

    let inc_spec = RepeaterRequestSpec::new(
        HttpMethod::Get,
        format!("http://127.0.0.1:{}/incomplete-chunked", inc_port),
    );
    assert!(matches!(
        engine.execute(&inc_spec, None),
        Err(RepeaterError::InvalidResponse(_))
    ));
    inc_handle.join().unwrap();

    let (mal_listener, mal_port) = bind_ephemeral_v4();
    let mal_handle = thread::spawn(move || {
        if let Ok((mut stream, _)) = mal_listener.accept() {
            let _ = read_full_http_request(&mut stream);
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nZZZ\r\nbad\r\n0\r\n\r\n",
            );
            let _ = stream.flush();
        }
    });

    let mal_spec = RepeaterRequestSpec::new(
        HttpMethod::Get,
        format!("http://127.0.0.1:{}/malformed-chunked", mal_port),
    );
    assert!(matches!(
        engine.execute(&mal_spec, None),
        Err(RepeaterError::InvalidResponse(_))
    ));
    mal_handle.join().unwrap();
}

#[test]
fn test_repeater_fragmented_content_length_1xx_204_304_and_redirect_not_followed() {
    let (listener, port) = bind_ephemeral_v4();
    let hit_count = Arc::new(AtomicUsize::new(0));
    let hit_count_srv = Arc::clone(&hit_count);

    let handle = thread::spawn(move || {
        for i in 0..4 {
            if let Ok((mut stream, _)) = listener.accept() {
                hit_count_srv.fetch_add(1, Ordering::SeqCst);
                let _ = read_full_http_request(&mut stream);
                match i {
                    0 => {
                        let _ = stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
                        let _ = stream.flush();
                        thread::sleep(Duration::from_millis(15));
                        let _ = stream.write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nHello",
                        );
                        let _ = stream.flush();
                        thread::sleep(Duration::from_millis(15));
                        let _ = stream.write_all(b" World");
                        let _ = stream.flush();
                    }
                    1 => {
                        let _ = stream
                            .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n");
                        let _ = stream.flush();
                    }
                    2 => {
                        let _ = stream.write_all(
                            b"HTTP/1.1 304 Not Modified\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n",
                        );
                        let _ = stream.flush();
                    }
                    3 => {
                        let _ = stream.write_all(
                            b"HTTP/1.1 302 Found\r\nLocation: http://external-unauthorized.example/login\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        );
                        let _ = stream.flush();
                    }
                    _ => unreachable!(),
                }
            }
        }
    });

    let engine = HttpRepeaterEngine::default();

    let res0 = engine
        .execute(
            &RepeaterRequestSpec::new(HttpMethod::Get, format!("http://127.0.0.1:{}/frag", port)),
            None,
        )
        .unwrap();
    assert_eq!(res0.response.status_code, 200);
    assert_eq!(res0.response.body_as_utf8(), "Hello World");

    let res1 = engine
        .execute(
            &RepeaterRequestSpec::new(HttpMethod::Get, format!("http://127.0.0.1:{}/204", port)),
            None,
        )
        .unwrap();
    assert_eq!(res1.response.status_code, 204);
    assert!(res1.response.body.is_empty());

    let res2 = engine
        .execute(
            &RepeaterRequestSpec::new(HttpMethod::Get, format!("http://127.0.0.1:{}/304", port)),
            None,
        )
        .unwrap();
    assert_eq!(res2.response.status_code, 304);
    assert!(res2.response.body.is_empty());

    let res3 = engine
        .execute(
            &RepeaterRequestSpec::new(HttpMethod::Get, format!("http://127.0.0.1:{}/redir", port)),
            None,
        )
        .unwrap();
    assert_eq!(res3.response.status_code, 302);
    assert_eq!(
        res3.response.header_value("location").as_deref(),
        Some("http://external-unauthorized.example/login")
    );
    assert_eq!(hit_count.load(Ordering::SeqCst), 4);

    handle.join().unwrap();
}

#[test]
fn test_repeater_response_body_truncation_when_exceeding_limit() {
    let (listener, port) = bind_ephemeral_v4();

    let handle = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let _ = read_full_http_request(&mut stream);
            let payload = vec![b'Z'; 512];
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                payload.len()
            );
            let _ = stream.write_all(headers.as_bytes());
            let _ = stream.write_all(&payload);
            let _ = stream.flush();
        }
    });

    let cfg = RepeaterConfig {
        max_response_body_bytes: 128,
        ..RepeaterConfig::default()
    };
    let engine = HttpRepeaterEngine::new(Arc::new(AuditScope::default()), cfg);

    let res = engine
        .execute(
            &RepeaterRequestSpec::new(
                HttpMethod::Get,
                format!("http://127.0.0.1:{}/large-resp", port),
            ),
            None,
        )
        .unwrap();

    assert_eq!(res.response.status_code, 200);
    assert_eq!(res.response.body.len(), 128);
    assert!(
        res.response_body_truncated,
        "Response exceeding max_response_body_bytes must be marked truncated"
    );

    handle.join().unwrap();
}

#[test]
fn test_repeater_timeout_and_cooperative_cancellation() {
    let (timeout_listener, timeout_port) = bind_ephemeral_v4();
    let timeout_srv = thread::spawn(move || {
        if let Ok((_stream, _)) = timeout_listener.accept() {
            thread::sleep(Duration::from_millis(600));
        }
    });

    let fast_timeout_cfg = RepeaterConfig {
        connect_timeout: Duration::from_millis(200),
        total_timeout: Duration::from_millis(250),
        io_slice_timeout: Duration::from_millis(30),
        ..RepeaterConfig::default()
    };
    let timeout_engine = HttpRepeaterEngine::new(Arc::new(AuditScope::default()), fast_timeout_cfg);

    let t0 = Instant::now();
    let err = timeout_engine
        .execute(
            &RepeaterRequestSpec::new(
                HttpMethod::Get,
                format!("http://127.0.0.1:{}/hang", timeout_port),
            ),
            None,
        )
        .expect_err("Expected timeout error");
    let elapsed_timeout = t0.elapsed();

    assert!(matches!(err, RepeaterError::Timeout(250)));
    assert!(elapsed_timeout < Duration::from_millis(1000));
    timeout_srv.join().unwrap();

    let (cancel_listener, cancel_port) = bind_ephemeral_v4();
    let cancel_srv = thread::spawn(move || {
        if let Ok((_stream, _)) = cancel_listener.accept() {
            thread::sleep(Duration::from_millis(600));
        }
    });

    let cancel_flag = Arc::new(AtomicBool::new(false));
    let cancel_flag_trigger = Arc::clone(&cancel_flag);
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(120));
        cancel_flag_trigger.store(true, Ordering::SeqCst);
    });

    let cancel_cfg = RepeaterConfig {
        total_timeout: Duration::from_millis(4000),
        io_slice_timeout: Duration::from_millis(30),
        ..RepeaterConfig::default()
    };
    let cancel_engine = HttpRepeaterEngine::new(Arc::new(AuditScope::default()), cancel_cfg);

    let c0 = Instant::now();
    let cancel_err = cancel_engine
        .execute(
            &RepeaterRequestSpec::new(
                HttpMethod::Get,
                format!("http://127.0.0.1:{}/cancel-me", cancel_port),
            ),
            Some(&cancel_flag),
        )
        .expect_err("Expected Cancelled error");
    let cancel_elapsed = c0.elapsed();

    assert_eq!(cancel_err, RepeaterError::Cancelled);
    assert!(
        cancel_elapsed < Duration::from_millis(1000),
        "Cancellation took too long: {:?}",
        cancel_elapsed
    );
    cancel_srv.join().unwrap();
}

#[test]
fn test_repeater_h1_chunked_metadata_and_trailer_limits_and_truncation() {
    let (listener, port) = bind_ephemeral_v4();

    let handle = thread::spawn(move || {
        for case_idx in 0..6 {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = read_full_http_request(&mut stream);
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                );
                match case_idx {
                    0 => {
                        // 1. Incomplete and overly long chunk-size line (> 256 bytes configured limit)
                        let huge_size_line = vec![b'F'; 512];
                        let _ = stream.write_all(&huge_size_line);
                        let _ = stream.flush();
                    }
                    1 => {
                        // 2. Unterminated chunk extension exceeding limit
                        let mut ext = b"4;ext=".to_vec();
                        ext.extend_from_slice(&[b'e'; 512]);
                        let _ = stream.write_all(&ext);
                        let _ = stream.flush();
                    }
                    2 => {
                        // 3. Single trailer line too long (> 256 bytes configured limit)
                        let mut trl = b"4\r\nData\r\n0\r\nX-Oversized-Trailer: ".to_vec();
                        trl.extend_from_slice(&[b'T'; 400]);
                        trl.extend_from_slice(b"\r\n\r\n");
                        let _ = stream.write_all(&trl);
                        let _ = stream.flush();
                    }
                    3 => {
                        // 4. Multiple trailers whose aggregate length exceeds max_header_bytes (256 bytes)
                        let mut agg = b"4\r\nData\r\n0\r\n".to_vec();
                        for i in 0..10 {
                            let line =
                                format!("X-Trailer-{}: 0123456789abcdef0123456789abcdef\r\n", i);
                            agg.extend_from_slice(line.as_bytes());
                        }
                        agg.extend_from_slice(b"\r\n");
                        let _ = stream.write_all(&agg);
                        let _ = stream.flush();
                    }
                    4 => {
                        // 5. Valid chunked with normal extensions and trailers
                        let valid = b"5;ext=ok\r\nAlpha\r\n4;second=1\r\nBeta\r\n0\r\nX-Check: pass\r\n\r\n";
                        let _ = stream.write_all(valid);
                        let _ = stream.flush();
                    }
                    5 => {
                        // 6. Legitimate chunked body exceeding max_response_body_bytes (64 bytes)
                        let chunk_payload = vec![b'B'; 100];
                        let chunk_hdr = format!("{:X}\r\n", chunk_payload.len());
                        let _ = stream.write_all(chunk_hdr.as_bytes());
                        let _ = stream.write_all(&chunk_payload);
                        let _ = stream.write_all(b"\r\n0\r\n\r\n");
                        let _ = stream.flush();
                    }
                    _ => unreachable!(),
                }
            }
        }
    });

    let cfg = RepeaterConfig {
        max_header_bytes: 256,
        max_response_body_bytes: 64,
        total_timeout: Duration::from_millis(2000),
        ..RepeaterConfig::default()
    };
    let engine = HttpRepeaterEngine::new(Arc::new(AuditScope::default()), cfg);
    let url = format!("http://127.0.0.1:{}/h1-chunked", port);

    // Cases 0..=3 must fail with InvalidResponse
    for case_idx in 0..4 {
        let res = engine.execute(&RepeaterRequestSpec::new(HttpMethod::Get, &url), None);
        assert!(
            matches!(res, Err(RepeaterError::InvalidResponse(_))),
            "H1 case {} should be rejected with InvalidResponse, got {:?}",
            case_idx,
            res
        );
    }

    // Case 4: Valid chunked with extensions and trailers
    let ok_res = engine
        .execute(&RepeaterRequestSpec::new(HttpMethod::Get, &url), None)
        .expect("Valid chunked should succeed");
    assert_eq!(ok_res.response.body_as_utf8(), "AlphaBeta");
    assert!(!ok_res.response_body_truncated);

    // Case 5: Legitimate chunked body exceeding max_response_body_bytes (64 bytes) -> controlled truncation
    let trunc_res = engine
        .execute(&RepeaterRequestSpec::new(HttpMethod::Get, &url), None)
        .expect("Oversized chunked body should truncate cleanly");
    assert_eq!(trunc_res.response.body.len(), 64);
    assert!(trunc_res.response_body_truncated);

    handle.join().unwrap();
}

#[test]
fn test_repeater_m1_strict_transfer_encoding_enforcement() {
    let (listener, port) = bind_ephemeral_v4();

    let handle = thread::spawn(move || {
        let responses: [&[u8]; 6] = [
            // 0. Valid Transfer-Encoding: chunked
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n8\r\nStrictOK\r\n0\r\n\r\n",
            // 1. Invalid substring match: xchunked
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: xchunked\r\nConnection: close\r\n\r\n8\r\nStrictOK\r\n0\r\n\r\n",
            // 2. Unsupported sequence: chunked, gzip
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\nConnection: close\r\n\r\n8\r\nStrictOK\r\n0\r\n\r\n",
            // 3. Unsupported sequence: gzip, chunked
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\nConnection: close\r\n\r\n8\r\nStrictOK\r\n0\r\n\r\n",
            // 4. Duplicate Transfer-Encoding headers
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n8\r\nStrictOK\r\n0\r\n\r\n",
            // 5. Conflicting Content-Length + Transfer-Encoding
            b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n8\r\nStrictOK\r\n0\r\n\r\n",
        ];

        for raw in responses {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = read_full_http_request(&mut stream);
                let _ = stream.write_all(raw);
                let _ = stream.flush();
            }
        }
    });

    let engine = HttpRepeaterEngine::default();
    let url = format!("http://127.0.0.1:{}/m1-te", port);

    // Case 0: Valid Transfer-Encoding: chunked
    let ok = engine
        .execute(&RepeaterRequestSpec::new(HttpMethod::Get, &url), None)
        .expect("Exact Transfer-Encoding: chunked must succeed");
    assert_eq!(ok.response.body_as_utf8(), "StrictOK");

    // Cases 1..=5: Must fail with RepeaterError::InvalidResponse
    for idx in 1..=5 {
        let res = engine.execute(&RepeaterRequestSpec::new(HttpMethod::Get, &url), None);
        assert!(
            matches!(res, Err(RepeaterError::InvalidResponse(_))),
            "M1 case {} must fail with InvalidResponse, got {:?}",
            idx,
            res
        );
    }

    handle.join().unwrap();
}

#[test]
fn test_repeater_m2_incremental_outgoing_header_limits_no_traffic_sent() {
    let (listener, port) = bind_ephemeral_v4();
    let accepted_connections = Arc::new(AtomicUsize::new(0));
    let accepted_srv = Arc::clone(&accepted_connections);

    let handle = thread::spawn(move || {
        // Only the 2 valid requests (below limit and exact limit) should ever connect
        for _ in 0..2 {
            if let Ok((mut stream, _)) = listener.accept() {
                accepted_srv.fetch_add(1, Ordering::SeqCst);
                let _ = read_full_http_request(&mut stream);
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
                );
                let _ = stream.flush();
            }
        }
    });

    let url = format!("http://127.0.0.1:{}/m2", port);
    // Calculate exact base header size for GET /m2 HTTP/1.1\r\n (18)
    // + Host: 127.0.0.1:<port>\r\n (16 + port_digits + 2)
    // + Connection: close\r\n (19) + \r\n (2)
    let port_digits = port.to_string().len();
    let base_bytes = 18 + (16 + port_digits + 2) + 19 + 2;
    // Header "X-Test: ABCD\r\n" is 6 + 2 + 4 + 2 = 14 bytes
    let exact_limit = base_bytes + 14;

    // 1. Just below limit (actual = exact_limit - 1 = base_bytes + 13)
    let engine_exact = HttpRepeaterEngine::new(
        Arc::new(AuditScope::default()),
        RepeaterConfig {
            max_header_bytes: exact_limit,
            ..RepeaterConfig::default()
        },
    );
    let below_spec = RepeaterRequestSpec::new(HttpMethod::Get, &url).with_header("X-Test", "ABC");
    let res_below = engine_exact
        .execute(&below_spec, None)
        .expect("Headers 1 byte below limit must succeed");
    assert_eq!(res_below.response.status_code, 200);
    assert_eq!(accepted_connections.load(Ordering::SeqCst), 1);

    // 2. Exact boundary (actual == exact_limit)
    let exact_spec = RepeaterRequestSpec::new(HttpMethod::Get, &url).with_header("X-Test", "ABCD");
    let res_exact = engine_exact
        .execute(&exact_spec, None)
        .expect("Headers at exact limit must succeed");
    assert_eq!(res_exact.response.status_code, 200);
    assert_eq!(accepted_connections.load(Ordering::SeqCst), 2);

    // 3. 1 byte over limit (actual == exact_limit + 1) -> rejected before connecting
    let over_by_one_spec =
        RepeaterRequestSpec::new(HttpMethod::Get, &url).with_header("X-Test", "ABCDE");
    assert_eq!(
        engine_exact.execute(&over_by_one_spec, None),
        Err(RepeaterError::RequestHeadersTooLarge {
            actual: exact_limit + 1,
            limit: exact_limit,
        })
    );
    assert_eq!(
        accepted_connections.load(Ordering::SeqCst),
        2,
        "No TCP connection may be opened when headers exceed limit"
    );

    // 4. Single oversized header
    let single_huge_spec = RepeaterRequestSpec::new(HttpMethod::Get, &url)
        .with_header("X-Huge", "A".repeat(exact_limit * 2));
    assert!(matches!(
        engine_exact.execute(&single_huge_spec, None),
        Err(RepeaterError::RequestHeadersTooLarge { .. })
    ));
    assert_eq!(accepted_connections.load(Ordering::SeqCst), 2);

    // 5. Many small headers whose sum exceeds limit
    let mut many_small_spec = RepeaterRequestSpec::new(HttpMethod::Get, &url);
    for i in 0..20 {
        many_small_spec = many_small_spec.with_header(format!("X-H{}", i), "1");
    }
    assert!(matches!(
        engine_exact.execute(&many_small_spec, None),
        Err(RepeaterError::RequestHeadersTooLarge { .. })
    ));
    assert_eq!(accepted_connections.load(Ordering::SeqCst), 2);

    handle.join().unwrap();
}
