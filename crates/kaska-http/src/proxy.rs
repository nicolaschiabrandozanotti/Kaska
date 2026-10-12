use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use crate::models::{HttpMethod, HttpResponse, HttpTransaction, TransactionState};
use crate::parser::{ChunkedTransferDecoder, HttpParseError, HttpParser};
use crate::scope::AuditScope;
use crate::store::SharedTrafficStore;

pub type OnTransactionCallback = Arc<dyn Fn(HttpTransaction) + Send + Sync + 'static>;

const MAX_HEADER_SIZE: usize = 65536; // 64 KB header safety limit
const MAX_INSPECTION_BODY_SIZE: usize = 2 * 1024 * 1024; // 2 MB inspection body cap

/// Native HTTP capture and forwarding proxy engine with streaming and RFC 9112 framing support
pub struct NativeProxyServer {
    port: u16,
    running: Arc<AtomicBool>,
    store: SharedTrafficStore,
    scope: Arc<AuditScope>,
    on_transaction: Option<OnTransactionCallback>,
}

impl NativeProxyServer {
    pub fn new(
        port: u16,
        store: SharedTrafficStore,
        scope: Arc<AuditScope>,
        on_transaction: Option<OnTransactionCallback>,
    ) -> Self {
        Self {
            port,
            running: Arc::new(AtomicBool::new(false)),
            store,
            scope,
            on_transaction,
        }
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Starts the native proxy listener in a background worker thread
    pub fn start(&self) -> Result<(), std::io::Error> {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", self.port))?;
        listener.set_nonblocking(true)?;

        let running = Arc::clone(&self.running);
        running.store(true, Ordering::SeqCst);

        let store = Arc::clone(&self.store);
        let scope = Arc::clone(&self.scope);
        let on_tx = self.on_transaction.clone();

        thread::spawn(move || {
            while running.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut client_stream, _)) => {
                        let store_ref = Arc::clone(&store);
                        let scope_ref = Arc::clone(&scope);
                        let on_tx_ref = on_tx.clone();

                        thread::spawn(move || {
                            let _ =
                                client_stream.set_read_timeout(Some(Duration::from_millis(3000)));
                            let _ =
                                client_stream.set_write_timeout(Some(Duration::from_millis(3000)));
                            Self::process_connection(
                                &mut client_stream,
                                store_ref,
                                scope_ref,
                                on_tx_ref,
                            );
                        });
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => {
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    fn process_connection(
        client: &mut TcpStream,
        store: SharedTrafficStore,
        scope: Arc<AuditScope>,
        on_transaction: Option<OnTransactionCallback>,
    ) {
        let start_time = Instant::now();
        let mut client_buffer = Vec::new();
        let mut chunk = [0u8; 8192];

        // 1. Read request headers from client until \r\n\r\n or \n\n
        loop {
            match client.read(&mut chunk) {
                Ok(n) if n > 0 => {
                    client_buffer.extend_from_slice(&chunk[..n]);
                    if client_buffer
                        .windows(4)
                        .position(|w| w == b"\r\n\r\n")
                        .is_some()
                        || client_buffer
                            .windows(2)
                            .position(|w| w == b"\n\n")
                            .is_some()
                    {
                        break;
                    }
                    if client_buffer.len() > MAX_HEADER_SIZE {
                        let _ = client.write_all(b"HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\n\r\n");
                        let _ = client.flush();
                        return;
                    }
                }
                _ => return,
            }
        }

        // Parse initial request headers
        let initial_req = match HttpParser::parse_request(&client_buffer) {
            Ok(r) => r,
            Err(HttpParseError::ConflictingFraming(_)) => {
                let err_msg = b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nKaska: Conflicting Content-Length and Transfer-Encoding (RFC 9112 violation)\r\n";
                let _ = client.write_all(err_msg);
                let _ = client.flush();
                return;
            }
            Err(_) => {
                let err_msg = b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nKaska: Malformed HTTP request\r\n";
                let _ = client.write_all(err_msg);
                let _ = client.flush();
                return;
            }
        };

        // 2. Handle HTTPS CONNECT explicitly (Milestone 0.4 does not implement MITM)
        if initial_req.method == HttpMethod::Connect {
            let err_body = b"HTTP/1.1 501 Not Implemented\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nKaska: HTTPS CONNECT tunneling is not supported in Milestone 0.4\r\n";
            let _ = client.write_all(err_body);
            let _ = client.flush();

            let tx = HttpTransaction {
                id: 0,
                timestamp_rfc3339: Self::format_timestamp(),
                request: initial_req,
                response: None,
                duration_ms: start_time.elapsed().as_millis() as u64,
                state: TransactionState::Failed(
                    "HTTPS CONNECT not implemented in Milestone 0.4".to_string(),
                ),
            };
            let mut store_guard = store.lock().unwrap();
            let assigned_id = store_guard.insert(tx.clone());
            drop(store_guard);

            if let Some(cb) = on_transaction {
                let mut tx_with_id = tx;
                tx_with_id.id = assigned_id;
                cb(tx_with_id);
            }
            return;
        }

        // 3. If request has Content-Length body, read remaining body bytes from client
        if let Some(content_len) = initial_req.content_length() {
            let (_header_bytes, body_bytes) = HttpParser::split_headers_and_body(&client_buffer);
            let mut current_body_len = body_bytes.len();
            while current_body_len < content_len {
                let to_read = std::cmp::min(8192, content_len - current_body_len);
                match client.read(&mut chunk[..to_read]) {
                    Ok(n) if n > 0 => {
                        client_buffer.extend_from_slice(&chunk[..n]);
                        current_body_len += n;
                    }
                    _ => break,
                }
            }
        }

        // Reparse to ensure full body is represented
        let req = match HttpParser::parse_request(&client_buffer) {
            Ok(r) => r,
            Err(_) => return,
        };

        let (target_host, target_port) = Self::parse_host_port(&req.host, 80);

        // 4. Pre-resolution destination validation against Audit Scope
        if !scope.is_allowed_host(&target_host) {
            let error_body = b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nKaska Security: Target Host is outside authorized scope.\r\n";
            let _ = client.write_all(error_body);
            let _ = client.flush();

            let tx = HttpTransaction {
                id: 0,
                timestamp_rfc3339: Self::format_timestamp(),
                request: req,
                response: None,
                duration_ms: start_time.elapsed().as_millis() as u64,
                state: TransactionState::Failed("Host outside authorized scope".to_string()),
            };
            store.lock().unwrap().insert(tx);
            return;
        }

        // 5. Hostname resolution without fallback to 127.0.0.1
        let resolved_addrs = match (target_host.as_str(), target_port).to_socket_addrs() {
            Ok(addrs) => addrs.collect::<Vec<_>>(),
            Err(e) => {
                let err_msg = format!(
                    "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nKaska: DNS resolution failed for target host '{}': {}\r\n",
                    target_host, e
                );
                let _ = client.write_all(err_msg.as_bytes());
                let _ = client.flush();

                let tx = HttpTransaction {
                    id: 0,
                    timestamp_rfc3339: Self::format_timestamp(),
                    request: req,
                    response: None,
                    duration_ms: start_time.elapsed().as_millis() as u64,
                    state: TransactionState::Failed(format!("DNS resolution failed: {}", e)),
                };
                store.lock().unwrap().insert(tx);
                return;
            }
        };

        // 6. Post-resolution IP validation (strictly loopback in Milestone 0.4)
        let validated_targets: Vec<_> = resolved_addrs
            .into_iter()
            .filter(|addr| scope.is_allowed_ip(&addr.ip()))
            .collect();

        if validated_targets.is_empty() {
            let error_body = b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nKaska Security: Resolved target IP is outside authorized loopback scope.\r\n";
            let _ = client.write_all(error_body);
            let _ = client.flush();

            let tx = HttpTransaction {
                id: 0,
                timestamp_rfc3339: Self::format_timestamp(),
                request: req,
                response: None,
                duration_ms: start_time.elapsed().as_millis() as u64,
                state: TransactionState::Failed(
                    "Resolved IP outside authorized loopback scope".to_string(),
                ),
            };
            store.lock().unwrap().insert(tx);
            return;
        }

        // 7. Connect to upstream target across validated loopback addresses
        let mut upstream_conn = None;
        let mut last_connect_err = String::new();

        for addr in &validated_targets {
            match TcpStream::connect_timeout(addr, Duration::from_millis(1500)) {
                Ok(s) => {
                    upstream_conn = Some(s);
                    break;
                }
                Err(e) => {
                    last_connect_err = format!("({}): {}", addr, e);
                }
            }
        }

        let mut upstream = match upstream_conn {
            Some(s) => s,
            None => {
                let err_msg = format!(
                    "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nKaska: Upstream connection failed ({}:{}): {}\r\n",
                    target_host, target_port, last_connect_err
                );
                let _ = client.write_all(err_msg.as_bytes());
                let _ = client.flush();

                let tx = HttpTransaction {
                    id: 0,
                    timestamp_rfc3339: Self::format_timestamp(),
                    request: req,
                    response: None,
                    duration_ms: start_time.elapsed().as_millis() as u64,
                    state: TransactionState::Failed(format!(
                        "Upstream connection failed: {}",
                        last_connect_err
                    )),
                };
                store.lock().unwrap().insert(tx);
                return;
            }
        };

        let _ = upstream.set_read_timeout(Some(Duration::from_millis(3000)));
        let _ = upstream.set_write_timeout(Some(Duration::from_millis(3000)));

        // 8. Forward request to upstream with Connection: close injected
        let (raw_req_headers, raw_req_body) = HttpParser::split_headers_and_body(&client_buffer);
        let modified_req_headers = Self::inject_connection_close(raw_req_headers);

        if upstream.write_all(&modified_req_headers).is_err() {
            return;
        }
        if !raw_req_body.is_empty() && upstream.write_all(raw_req_body).is_err() {
            return;
        }
        let _ = upstream.flush();

        // 9. Read response headers from upstream
        let mut resp_accum = Vec::new();
        let mut header_boundary = None;

        loop {
            match upstream.read(&mut chunk) {
                Ok(n) if n > 0 => {
                    resp_accum.extend_from_slice(&chunk[..n]);
                    if let Some(pos) = resp_accum.windows(4).position(|w| w == b"\r\n\r\n") {
                        header_boundary = Some((pos, 4));
                        break;
                    } else if let Some(pos) = resp_accum.windows(2).position(|w| w == b"\n\n") {
                        header_boundary = Some((pos, 2));
                        break;
                    }
                    if resp_accum.len() > MAX_HEADER_SIZE {
                        let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nKaska: Response headers exceeded limit\r\n");
                        let _ = client.flush();
                        return;
                    }
                }
                _ => break,
            }
        }

        let (header_end, sep_len) = match header_boundary {
            Some(b) => b,
            None => {
                let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nKaska: Incomplete upstream response headers\r\n");
                let _ = client.flush();
                return;
            }
        };

        let raw_resp_headers = &resp_accum[..header_end];
        let initial_body = &resp_accum[header_end + sep_len..];

        // Parse response headers
        let parsed_resp_headers = match HttpParser::parse_response(
            &resp_accum[..header_end + sep_len],
        ) {
            Ok(r) => r,
            Err(HttpParseError::ConflictingFraming(_)) => {
                let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nKaska: Upstream returned conflicting framing\r\n");
                let _ = client.flush();
                return;
            }
            Err(_) => {
                let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nKaska: Malformed upstream response headers\r\n");
                let _ = client.flush();
                return;
            }
        };

        // 10. Forward modified response headers (Connection: close injected) immediately to client
        let modified_resp_headers = Self::inject_connection_close(raw_resp_headers);
        if client.write_all(&modified_resp_headers).is_err() {
            return;
        }
        let _ = client.flush();

        // Forward initial body bytes immediately if present
        if !initial_body.is_empty() && client.write_all(initial_body).is_err() {
            return;
        }
        let _ = client.flush();

        // 11. Stream body incrementally to client while tracking framing and inspection buffer
        let is_chunked = parsed_resp_headers.is_chunked();
        let content_length = parsed_resp_headers.content_length();
        let is_head = req.method == HttpMethod::Head;
        let is_empty_body_status =
            parsed_resp_headers.status_code == 204 || parsed_resp_headers.status_code == 304;

        let mut inspected_body = Vec::new();

        if is_head || is_empty_body_status {
            // No body expected
        } else if is_chunked {
            let mut decoder = ChunkedTransferDecoder::new(MAX_INSPECTION_BODY_SIZE);
            if !initial_body.is_empty() {
                let _ = decoder.feed(initial_body);
            }

            while !decoder.is_complete() {
                match upstream.read(&mut chunk) {
                    Ok(n) if n > 0 => {
                        let slice = &chunk[..n];
                        // Incremental streaming to client
                        if client.write_all(slice).is_err() {
                            break;
                        }
                        let _ = client.flush();

                        // Feed to chunked decoder
                        if decoder.feed(slice).is_err() {
                            break;
                        }
                    }
                    _ => break,
                }
            }
            inspected_body = decoder.decoded_body().to_vec();
        } else if let Some(expected_len) = content_length {
            let mut forwarded = initial_body.len();
            if inspected_body.len() < MAX_INSPECTION_BODY_SIZE {
                let take = std::cmp::min(initial_body.len(), MAX_INSPECTION_BODY_SIZE);
                inspected_body.extend_from_slice(&initial_body[..take]);
            }

            while forwarded < expected_len {
                let to_read = std::cmp::min(8192, expected_len - forwarded);
                match upstream.read(&mut chunk[..to_read]) {
                    Ok(n) if n > 0 => {
                        let slice = &chunk[..n];
                        if client.write_all(slice).is_err() {
                            break;
                        }
                        let _ = client.flush();

                        if inspected_body.len() < MAX_INSPECTION_BODY_SIZE {
                            let can_take =
                                std::cmp::min(n, MAX_INSPECTION_BODY_SIZE - inspected_body.len());
                            inspected_body.extend_from_slice(&slice[..can_take]);
                        }
                        forwarded += n;
                    }
                    _ => break,
                }
            }
        } else {
            // Unspecified framing: read until upstream EOF
            if inspected_body.len() < MAX_INSPECTION_BODY_SIZE {
                let take = std::cmp::min(initial_body.len(), MAX_INSPECTION_BODY_SIZE);
                inspected_body.extend_from_slice(&initial_body[..take]);
            }

            loop {
                match upstream.read(&mut chunk) {
                    Ok(n) if n > 0 => {
                        let slice = &chunk[..n];
                        if client.write_all(slice).is_err() {
                            break;
                        }
                        let _ = client.flush();

                        if inspected_body.len() < MAX_INSPECTION_BODY_SIZE {
                            let can_take =
                                std::cmp::min(n, MAX_INSPECTION_BODY_SIZE - inspected_body.len());
                            inspected_body.extend_from_slice(&slice[..can_take]);
                        }
                    }
                    _ => break,
                }
            }
        }

        let _ = client.flush();
        let duration_ms = start_time.elapsed().as_millis() as u64;

        // Build captured response
        let captured_response = HttpResponse {
            status_code: parsed_resp_headers.status_code,
            status_text: parsed_resp_headers.status_text,
            http_version: parsed_resp_headers.http_version,
            headers: parsed_resp_headers.headers,
            body: inspected_body,
        };

        let tx = HttpTransaction {
            id: 0,
            timestamp_rfc3339: Self::format_timestamp(),
            request: req,
            response: Some(captured_response),
            duration_ms,
            state: TransactionState::Completed,
        };

        let mut store_guard = store.lock().unwrap();
        let assigned_id = store_guard.insert(tx.clone());
        drop(store_guard);

        let mut tx_with_id = tx;
        tx_with_id.id = assigned_id;

        if let Some(cb) = on_transaction {
            cb(tx_with_id);
        }
    }

    /// Rewrites or injects `Connection: close` into raw HTTP header block
    fn inject_connection_close(raw_headers: &[u8]) -> Vec<u8> {
        let text = String::from_utf8_lossy(raw_headers);
        let mut lines = text.lines();
        let first_line = lines.next().unwrap_or("");

        let mut out = String::with_capacity(raw_headers.len() + 32);
        out.push_str(first_line);
        out.push_str("\r\n");

        let mut has_connection = false;
        for line in lines {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some((name, _)) = trimmed.split_once(':') {
                if name.trim().eq_ignore_ascii_case("connection") {
                    has_connection = true;
                    out.push_str("Connection: close\r\n");
                    continue;
                }
            }
            out.push_str(trimmed);
            out.push_str("\r\n");
        }

        if !has_connection {
            out.push_str("Connection: close\r\n");
        }
        out.push_str("\r\n");
        out.into_bytes()
    }

    pub fn parse_host_port(host_str: &str, default_port: u16) -> (String, u16) {
        let trimmed = host_str.trim();
        if let Some(rest) = trimmed.strip_prefix('[') {
            if let Some((addr_part, port_part)) = rest.split_once(']') {
                let port = port_part
                    .strip_prefix(':')
                    .and_then(|p| p.parse().ok())
                    .unwrap_or(default_port);
                return (addr_part.to_string(), port);
            }
        }
        if trimmed.matches(':').count() > 1 {
            return (trimmed.to_string(), default_port);
        }
        if let Some((h, p_str)) = trimmed.split_once(':') {
            let port: u16 = p_str.parse().unwrap_or(default_port);
            (h.to_string(), port)
        } else {
            (trimmed.to_string(), default_port)
        }
    }

    fn format_timestamp() -> String {
        match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            Ok(d) => format!("{}.{:03}Z", d.as_secs(), d.subsec_millis()),
            Err(_) => "now".to_string(),
        }
    }
}
