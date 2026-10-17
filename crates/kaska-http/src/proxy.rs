use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use crate::models::{HttpMethod, HttpResponse, HttpTransaction, TransactionState};
use crate::parser::{ChunkedTransferDecoder, HttpParseError, HttpParser};
use crate::scope::AuditScope;
use crate::store::SharedTrafficStore;

pub type OnTransactionCallback = Arc<dyn Fn(HttpTransaction) + Send + Sync + 'static>;

const MAX_HEADER_SIZE: usize = 65536; // 64 KB header safety limit
const MAX_INSPECTION_BODY_SIZE: usize = 2 * 1024 * 1024; // 2 MB inspection body cap

/// Processing phase of a connection handled by the native proxy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyDiagnosticPhase {
    Accepted,
    WorkerStarted,
    ClientHeadersRead,
    ClientBodyRead,
    RequestParsed,
    UpstreamConnected,
    UpstreamHeadersWrite,
    UpstreamBodyWrite,
    UpstreamHeadersRead,
    ClientResponseWrite,
    Completed,
    EarlyReturn,
}

impl ProxyDiagnosticPhase {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Accepted => "ACCEPTED",
            Self::WorkerStarted => "WORKER_STARTED",
            Self::ClientHeadersRead => "CLIENT_HEADERS_READ",
            Self::ClientBodyRead => "CLIENT_BODY_READ",
            Self::RequestParsed => "REQUEST_PARSED",
            Self::UpstreamConnected => "UPSTREAM_CONNECTED",
            Self::UpstreamHeadersWrite => "UPSTREAM_HEADERS_WRITE",
            Self::UpstreamBodyWrite => "UPSTREAM_BODY_WRITE",
            Self::UpstreamHeadersRead => "UPSTREAM_HEADERS_READ",
            Self::ClientResponseWrite => "CLIENT_RESPONSE_WRITE",
            Self::Completed => "COMPLETED",
            Self::EarlyReturn => "EARLY_RETURN",
        }
    }
}

/// Typed termination reasons capturing exactly which code branch exited
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyTerminationReason {
    ClientHeadersTooLarge,            // HTTP 431 attempted
    ClientHeadersReadFailed,          // Silent return (line 133)
    RequestParseFailed,               // HTTP 400 attempted
    HttpsConnectNotSupported,         // HTTP 501 attempted
    ClientBodyReadFailed,             // Partial body read error
    RequestReparseFailed,             // Silent return (line 201)
    ScopeHostForbidden,               // HTTP 403 attempted
    DnsResolutionFailed,              // HTTP 502 attempted
    ScopeIpForbidden,                 // HTTP 403 attempted
    UpstreamConnectFailed,            // HTTP 502 attempted
    UpstreamHeadersWriteFailed,       // Silent return (line 323)
    UpstreamBodyWriteFailed,          // Silent return (line 326)
    UpstreamHeadersTooLarge,          // HTTP 502 attempted
    UpstreamHeadersIncomplete,        // HTTP 502 attempted
    UpstreamResponseParseFailed,      // HTTP 502 attempted
    ClientResponseHeadersWriteFailed, // Silent return (line 387)
    ClientResponseBodyWriteFailed,    // Silent return (line 393 / stream)
    CompletedSuccessfully,            // Normal completion
}

impl ProxyTerminationReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ClientHeadersTooLarge => "CLIENT_HEADERS_TOO_LARGE",
            Self::ClientHeadersReadFailed => "CLIENT_HEADERS_READ_FAILED",
            Self::RequestParseFailed => "REQUEST_PARSE_FAILED",
            Self::HttpsConnectNotSupported => "HTTPS_CONNECT_NOT_SUPPORTED",
            Self::ClientBodyReadFailed => "CLIENT_BODY_READ_FAILED",
            Self::RequestReparseFailed => "REQUEST_REPARSE_FAILED",
            Self::ScopeHostForbidden => "SCOPE_HOST_FORBIDDEN",
            Self::DnsResolutionFailed => "DNS_RESOLUTION_FAILED",
            Self::ScopeIpForbidden => "SCOPE_IP_FORBIDDEN",
            Self::UpstreamConnectFailed => "UPSTREAM_CONNECT_FAILED",
            Self::UpstreamHeadersWriteFailed => "UPSTREAM_HEADERS_WRITE_FAILED",
            Self::UpstreamBodyWriteFailed => "UPSTREAM_BODY_WRITE_FAILED",
            Self::UpstreamHeadersTooLarge => "UPSTREAM_HEADERS_TOO_LARGE",
            Self::UpstreamHeadersIncomplete => "UPSTREAM_HEADERS_INCOMPLETE",
            Self::UpstreamResponseParseFailed => "UPSTREAM_RESPONSE_PARSE_FAILED",
            Self::ClientResponseHeadersWriteFailed => "CLIENT_RESPONSE_HEADERS_WRITE_FAILED",
            Self::ClientResponseBodyWriteFailed => "CLIENT_RESPONSE_BODY_WRITE_FAILED",
            Self::CompletedSuccessfully => "COMPLETED_SUCCESSFULLY",
        }
    }
}

/// Result of an I/O read or write operation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IoOperationResult {
    Ok(usize),
    Err {
        kind: std::io::ErrorKind,
        os_code: Option<i32>,
    },
}

/// Technical diagnostic event emitted by the proxy engine
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyDiagnosticEvent {
    pub conn_id: u64,
    pub client_port: u16,
    pub phase: ProxyDiagnosticPhase,
    pub io_result: Option<IoOperationResult>,
    pub termination_reason: Option<ProxyTerminationReason>,
    pub http_response_attempted: Option<u16>,
    pub http_response_write_succeeded: Option<bool>,
}

pub type ProxyDiagnosticCallback = Arc<dyn Fn(ProxyDiagnosticEvent) + Send + Sync + 'static>;

/// Thread-safe, bounded, zero-panic diagnostic event recorder using a Drop-Newest retention policy.
/// Retains the earliest events up to max_events capacity, and increments dropped_count
/// for subsequent events when capacity is reached.
#[derive(Debug, Clone)]
pub struct BoundedProxyObserver {
    max_events: usize,
    events: Arc<Mutex<Vec<ProxyDiagnosticEvent>>>,
    dropped_count: Arc<AtomicUsize>,
}

impl BoundedProxyObserver {
    pub fn new(max_events: usize) -> Self {
        Self {
            max_events,
            events: Arc::new(Mutex::new(Vec::with_capacity(std::cmp::min(
                max_events, 256,
            )))),
            dropped_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn record(&self, event: ProxyDiagnosticEvent) {
        if let Ok(mut lock) = self.events.lock() {
            if lock.len() < self.max_events {
                lock.push(event);
            } else {
                self.dropped_count.fetch_add(1, Ordering::Relaxed);
            }
        } else {
            self.dropped_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn capacity(&self) -> usize {
        self.max_events
    }

    pub fn events(&self) -> Vec<ProxyDiagnosticEvent> {
        self.events.lock().map(|g| g.clone()).unwrap_or_default()
    }

    pub fn snapshot(&self) -> Vec<ProxyDiagnosticEvent> {
        self.events()
    }

    pub fn total_captured(&self) -> usize {
        let in_buf = self.events.lock().map(|g| g.len()).unwrap_or(0);
        in_buf + self.dropped_count()
    }

    pub fn dropped_count(&self) -> usize {
        self.dropped_count.load(Ordering::Relaxed)
    }

    pub fn to_callback(&self) -> ProxyDiagnosticCallback {
        let obs = self.clone();
        Arc::new(move |event| {
            obs.record(event);
        })
    }
}

/// Native HTTP capture and forwarding proxy engine with streaming and RFC 9112 framing support
pub struct NativeProxyServer {
    port: u16,
    running: Arc<AtomicBool>,
    store: SharedTrafficStore,
    scope: Arc<AuditScope>,
    on_transaction: Option<OnTransactionCallback>,
    diagnostic_observer: Option<ProxyDiagnosticCallback>,
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
            diagnostic_observer: None,
        }
    }

    pub fn with_diagnostic_observer(
        port: u16,
        store: SharedTrafficStore,
        scope: Arc<AuditScope>,
        on_transaction: Option<OnTransactionCallback>,
        diagnostic_observer: Option<ProxyDiagnosticCallback>,
    ) -> Self {
        Self {
            port,
            running: Arc::new(AtomicBool::new(false)),
            store,
            scope,
            on_transaction,
            diagnostic_observer,
        }
    }

    pub fn set_diagnostic_observer(&mut self, observer: Option<ProxyDiagnosticCallback>) {
        self.diagnostic_observer = observer;
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
        let diag_obs = self.diagnostic_observer.clone();
        let conn_counter = Arc::new(AtomicU64::new(0));

        thread::spawn(move || {
            while running.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut client_stream, peer_addr)) => {
                        let conn_id = conn_counter.fetch_add(1, Ordering::SeqCst) + 1;
                        let client_port = peer_addr.port();
                        let store_ref = Arc::clone(&store);
                        let scope_ref = Arc::clone(&scope);
                        let on_tx_ref = on_tx.clone();
                        let diag_obs_ref = diag_obs.clone();

                        if let Some(ref obs) = diag_obs_ref {
                            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                obs(ProxyDiagnosticEvent {
                                    conn_id,
                                    client_port,
                                    phase: ProxyDiagnosticPhase::Accepted,
                                    io_result: None,
                                    termination_reason: None,
                                    http_response_attempted: None,
                                    http_response_write_succeeded: None,
                                });
                            }));
                        }

                        thread::spawn(move || {
                            let _ =
                                client_stream.set_read_timeout(Some(Duration::from_millis(3000)));
                            let _ =
                                client_stream.set_write_timeout(Some(Duration::from_millis(3000)));
                            Self::process_connection(
                                &mut client_stream,
                                conn_id,
                                client_port,
                                store_ref,
                                scope_ref,
                                on_tx_ref,
                                diag_obs_ref,
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
        conn_id: u64,
        client_port: u16,
        store: SharedTrafficStore,
        scope: Arc<AuditScope>,
        on_transaction: Option<OnTransactionCallback>,
        diag_obs: Option<ProxyDiagnosticCallback>,
    ) {
        let emit = |phase: ProxyDiagnosticPhase,
                    io_result: Option<IoOperationResult>,
                    term_reason: Option<ProxyTerminationReason>,
                    resp_attempted: Option<u16>,
                    resp_succeeded: Option<bool>| {
            if let Some(ref obs) = diag_obs {
                let event = ProxyDiagnosticEvent {
                    conn_id,
                    client_port,
                    phase,
                    io_result,
                    termination_reason: term_reason,
                    http_response_attempted: resp_attempted,
                    http_response_write_succeeded: resp_succeeded,
                };
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    obs(event);
                }));
            }
        };

        emit(ProxyDiagnosticPhase::WorkerStarted, None, None, None, None);
        let start_time = Instant::now();
        let mut client_buffer = Vec::new();
        let mut chunk = [0u8; 8192];

        // 1. Read request headers from client until \r\n\r\n or \n\n
        loop {
            match client.read(&mut chunk) {
                Ok(0) => {
                    emit(
                        ProxyDiagnosticPhase::EarlyReturn,
                        Some(IoOperationResult::Ok(0)),
                        Some(ProxyTerminationReason::ClientHeadersReadFailed),
                        None,
                        None,
                    );
                    return;
                }
                Ok(n) => {
                    client_buffer.extend_from_slice(&chunk[..n]);
                    emit(
                        ProxyDiagnosticPhase::ClientHeadersRead,
                        Some(IoOperationResult::Ok(n)),
                        None,
                        None,
                        None,
                    );
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
                        let msg = b"HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\n\r\n";
                        let write_res = client.write_all(msg);
                        let succ = write_res.is_ok();
                        let io_res = match write_res {
                            Ok(_) => IoOperationResult::Ok(msg.len()),
                            Err(ref e) => IoOperationResult::Err {
                                kind: e.kind(),
                                os_code: e.raw_os_error(),
                            },
                        };
                        let _ = client.flush();
                        emit(
                            ProxyDiagnosticPhase::EarlyReturn,
                            Some(io_res),
                            Some(ProxyTerminationReason::ClientHeadersTooLarge),
                            Some(431),
                            Some(succ),
                        );
                        return;
                    }
                }
                Err(ref e) => {
                    emit(
                        ProxyDiagnosticPhase::EarlyReturn,
                        Some(IoOperationResult::Err {
                            kind: e.kind(),
                            os_code: e.raw_os_error(),
                        }),
                        Some(ProxyTerminationReason::ClientHeadersReadFailed),
                        None,
                        None,
                    );
                    return;
                }
            }
        }

        // Parse initial request headers
        let initial_req = match HttpParser::parse_request(&client_buffer) {
            Ok(r) => {
                emit(ProxyDiagnosticPhase::RequestParsed, None, None, None, None);
                r
            }
            Err(HttpParseError::ConflictingFraming(_)) => {
                let err_msg = b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nKaska: Conflicting Content-Length and Transfer-Encoding (RFC 9112 violation)\r\n";
                let write_res = client.write_all(err_msg);
                let succ = write_res.is_ok();
                let io_res = match write_res {
                    Ok(_) => IoOperationResult::Ok(err_msg.len()),
                    Err(ref e) => IoOperationResult::Err {
                        kind: e.kind(),
                        os_code: e.raw_os_error(),
                    },
                };
                let _ = client.flush();
                emit(
                    ProxyDiagnosticPhase::EarlyReturn,
                    Some(io_res),
                    Some(ProxyTerminationReason::RequestParseFailed),
                    Some(400),
                    Some(succ),
                );
                return;
            }
            Err(_) => {
                let err_msg = b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nKaska: Malformed HTTP request\r\n";
                let write_res = client.write_all(err_msg);
                let succ = write_res.is_ok();
                let io_res = match write_res {
                    Ok(_) => IoOperationResult::Ok(err_msg.len()),
                    Err(ref e) => IoOperationResult::Err {
                        kind: e.kind(),
                        os_code: e.raw_os_error(),
                    },
                };
                let _ = client.flush();
                emit(
                    ProxyDiagnosticPhase::EarlyReturn,
                    Some(io_res),
                    Some(ProxyTerminationReason::RequestParseFailed),
                    Some(400),
                    Some(succ),
                );
                return;
            }
        };

        // 2. Handle HTTPS CONNECT explicitly (Milestone 0.4 does not implement MITM)
        if initial_req.method == HttpMethod::Connect {
            let err_body = b"HTTP/1.1 501 Not Implemented\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nKaska: HTTPS CONNECT tunneling is not supported in Milestone 0.4\r\n";
            let write_res = client.write_all(err_body);
            let succ = write_res.is_ok();
            let io_res = match write_res {
                Ok(_) => IoOperationResult::Ok(err_body.len()),
                Err(ref e) => IoOperationResult::Err {
                    kind: e.kind(),
                    os_code: e.raw_os_error(),
                },
            };
            let _ = client.flush();
            emit(
                ProxyDiagnosticPhase::EarlyReturn,
                Some(io_res),
                Some(ProxyTerminationReason::HttpsConnectNotSupported),
                Some(501),
                Some(succ),
            );

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
                    Ok(0) => {
                        emit(
                            ProxyDiagnosticPhase::ClientBodyRead,
                            Some(IoOperationResult::Ok(0)),
                            None,
                            None,
                            None,
                        );
                        break;
                    }
                    Ok(n) => {
                        client_buffer.extend_from_slice(&chunk[..n]);
                        current_body_len += n;
                        emit(
                            ProxyDiagnosticPhase::ClientBodyRead,
                            Some(IoOperationResult::Ok(n)),
                            None,
                            None,
                            None,
                        );
                    }
                    Err(ref e) => {
                        emit(
                            ProxyDiagnosticPhase::ClientBodyRead,
                            Some(IoOperationResult::Err {
                                kind: e.kind(),
                                os_code: e.raw_os_error(),
                            }),
                            None,
                            None,
                            None,
                        );
                        break;
                    }
                }
            }
        }

        // Reparse to ensure full body is represented
        let req = match HttpParser::parse_request(&client_buffer) {
            Ok(r) => r,
            Err(_) => {
                emit(
                    ProxyDiagnosticPhase::EarlyReturn,
                    None,
                    Some(ProxyTerminationReason::RequestReparseFailed),
                    None,
                    None,
                );
                return;
            }
        };

        let (target_host, target_port) = Self::parse_host_port(&req.host, 80);

        // 4. Pre-resolution destination validation against Audit Scope
        if !scope.is_allowed_host(&target_host) {
            let error_body = b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nKaska Security: Target Host is outside authorized scope.\r\n";
            let write_res = client.write_all(error_body);
            let succ = write_res.is_ok();
            let io_res = match write_res {
                Ok(_) => IoOperationResult::Ok(error_body.len()),
                Err(ref e) => IoOperationResult::Err {
                    kind: e.kind(),
                    os_code: e.raw_os_error(),
                },
            };
            let _ = client.flush();
            emit(
                ProxyDiagnosticPhase::EarlyReturn,
                Some(io_res),
                Some(ProxyTerminationReason::ScopeHostForbidden),
                Some(403),
                Some(succ),
            );

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
                let write_res = client.write_all(err_msg.as_bytes());
                let succ = write_res.is_ok();
                let io_res = match write_res {
                    Ok(_) => IoOperationResult::Ok(err_msg.len()),
                    Err(ref e_w) => IoOperationResult::Err {
                        kind: e_w.kind(),
                        os_code: e_w.raw_os_error(),
                    },
                };
                let _ = client.flush();
                emit(
                    ProxyDiagnosticPhase::EarlyReturn,
                    Some(io_res),
                    Some(ProxyTerminationReason::DnsResolutionFailed),
                    Some(502),
                    Some(succ),
                );

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
            let write_res = client.write_all(error_body);
            let succ = write_res.is_ok();
            let io_res = match write_res {
                Ok(_) => IoOperationResult::Ok(error_body.len()),
                Err(ref e) => IoOperationResult::Err {
                    kind: e.kind(),
                    os_code: e.raw_os_error(),
                },
            };
            let _ = client.flush();
            emit(
                ProxyDiagnosticPhase::EarlyReturn,
                Some(io_res),
                Some(ProxyTerminationReason::ScopeIpForbidden),
                Some(403),
                Some(succ),
            );

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
            Some(s) => {
                emit(
                    ProxyDiagnosticPhase::UpstreamConnected,
                    None,
                    None,
                    None,
                    None,
                );
                s
            }
            None => {
                let err_msg = format!(
                    "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nKaska: Upstream connection failed ({}:{}): {}\r\n",
                    target_host, target_port, last_connect_err
                );
                let write_res = client.write_all(err_msg.as_bytes());
                let succ = write_res.is_ok();
                let io_res = match write_res {
                    Ok(_) => IoOperationResult::Ok(err_msg.len()),
                    Err(ref e_w) => IoOperationResult::Err {
                        kind: e_w.kind(),
                        os_code: e_w.raw_os_error(),
                    },
                };
                let _ = client.flush();
                emit(
                    ProxyDiagnosticPhase::EarlyReturn,
                    Some(io_res),
                    Some(ProxyTerminationReason::UpstreamConnectFailed),
                    Some(502),
                    Some(succ),
                );

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

        if let Err(ref e) = upstream.write_all(&modified_req_headers) {
            let io_res = IoOperationResult::Err {
                kind: e.kind(),
                os_code: e.raw_os_error(),
            };
            emit(
                ProxyDiagnosticPhase::EarlyReturn,
                Some(io_res),
                Some(ProxyTerminationReason::UpstreamHeadersWriteFailed),
                None,
                None,
            );
            return;
        }
        emit(
            ProxyDiagnosticPhase::UpstreamHeadersWrite,
            Some(IoOperationResult::Ok(modified_req_headers.len())),
            None,
            None,
            None,
        );

        if !raw_req_body.is_empty() {
            if let Err(ref e) = upstream.write_all(raw_req_body) {
                let io_res = IoOperationResult::Err {
                    kind: e.kind(),
                    os_code: e.raw_os_error(),
                };
                emit(
                    ProxyDiagnosticPhase::EarlyReturn,
                    Some(io_res),
                    Some(ProxyTerminationReason::UpstreamBodyWriteFailed),
                    None,
                    None,
                );
                return;
            }
            emit(
                ProxyDiagnosticPhase::UpstreamBodyWrite,
                Some(IoOperationResult::Ok(raw_req_body.len())),
                None,
                None,
                None,
            );
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
                        let msg = b"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nKaska: Response headers exceeded limit\r\n";
                        let write_res = client.write_all(msg);
                        let succ = write_res.is_ok();
                        let io_res = match write_res {
                            Ok(_) => IoOperationResult::Ok(msg.len()),
                            Err(ref e) => IoOperationResult::Err {
                                kind: e.kind(),
                                os_code: e.raw_os_error(),
                            },
                        };
                        let _ = client.flush();
                        emit(
                            ProxyDiagnosticPhase::EarlyReturn,
                            Some(io_res),
                            Some(ProxyTerminationReason::UpstreamHeadersTooLarge),
                            Some(502),
                            Some(succ),
                        );
                        return;
                    }
                }
                _ => break,
            }
        }

        let (header_end, sep_len) = match header_boundary {
            Some(b) => b,
            None => {
                let msg = b"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nKaska: Incomplete upstream response headers\r\n";
                let write_res = client.write_all(msg);
                let succ = write_res.is_ok();
                let io_res = match write_res {
                    Ok(_) => IoOperationResult::Ok(msg.len()),
                    Err(ref e) => IoOperationResult::Err {
                        kind: e.kind(),
                        os_code: e.raw_os_error(),
                    },
                };
                let _ = client.flush();
                emit(
                    ProxyDiagnosticPhase::EarlyReturn,
                    Some(io_res),
                    Some(ProxyTerminationReason::UpstreamHeadersIncomplete),
                    Some(502),
                    Some(succ),
                );
                return;
            }
        };

        let raw_resp_headers = &resp_accum[..header_end];
        let initial_body = &resp_accum[header_end + sep_len..];

        // Parse response headers
        let parsed_resp_headers = match HttpParser::parse_response(
            &resp_accum[..header_end + sep_len],
        ) {
            Ok(r) => {
                emit(
                    ProxyDiagnosticPhase::UpstreamHeadersRead,
                    Some(IoOperationResult::Ok(header_end + sep_len)),
                    None,
                    None,
                    None,
                );
                r
            }
            Err(HttpParseError::ConflictingFraming(_)) => {
                let msg = b"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nKaska: Upstream returned conflicting framing\r\n";
                let write_res = client.write_all(msg);
                let succ = write_res.is_ok();
                let io_res = match write_res {
                    Ok(_) => IoOperationResult::Ok(msg.len()),
                    Err(ref e) => IoOperationResult::Err {
                        kind: e.kind(),
                        os_code: e.raw_os_error(),
                    },
                };
                let _ = client.flush();
                emit(
                    ProxyDiagnosticPhase::EarlyReturn,
                    Some(io_res),
                    Some(ProxyTerminationReason::UpstreamResponseParseFailed),
                    Some(502),
                    Some(succ),
                );
                return;
            }
            Err(_) => {
                let msg = b"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nKaska: Malformed upstream response headers\r\n";
                let write_res = client.write_all(msg);
                let succ = write_res.is_ok();
                let io_res = match write_res {
                    Ok(_) => IoOperationResult::Ok(msg.len()),
                    Err(ref e) => IoOperationResult::Err {
                        kind: e.kind(),
                        os_code: e.raw_os_error(),
                    },
                };
                let _ = client.flush();
                emit(
                    ProxyDiagnosticPhase::EarlyReturn,
                    Some(io_res),
                    Some(ProxyTerminationReason::UpstreamResponseParseFailed),
                    Some(502),
                    Some(succ),
                );
                return;
            }
        };

        // 10. Forward modified response headers (Connection: close injected) immediately to client
        let modified_resp_headers = Self::inject_connection_close(raw_resp_headers);
        if let Err(ref e) = client.write_all(&modified_resp_headers) {
            let io_res = IoOperationResult::Err {
                kind: e.kind(),
                os_code: e.raw_os_error(),
            };
            emit(
                ProxyDiagnosticPhase::EarlyReturn,
                Some(io_res),
                Some(ProxyTerminationReason::ClientResponseHeadersWriteFailed),
                Some(parsed_resp_headers.status_code),
                Some(false),
            );
            return;
        }
        let _ = client.flush();
        emit(
            ProxyDiagnosticPhase::ClientResponseWrite,
            Some(IoOperationResult::Ok(modified_resp_headers.len())),
            None,
            Some(parsed_resp_headers.status_code),
            Some(true),
        );

        // Forward initial body bytes immediately if present
        if !initial_body.is_empty() {
            if let Err(ref e) = client.write_all(initial_body) {
                let io_res = IoOperationResult::Err {
                    kind: e.kind(),
                    os_code: e.raw_os_error(),
                };
                emit(
                    ProxyDiagnosticPhase::EarlyReturn,
                    Some(io_res),
                    Some(ProxyTerminationReason::ClientResponseBodyWriteFailed),
                    Some(parsed_resp_headers.status_code),
                    Some(false),
                );
                return;
            }
            let _ = client.flush();
        }

        // 11. Stream body incrementally to client while tracking framing and inspection buffer
        let is_chunked = parsed_resp_headers.is_chunked();
        let content_length = parsed_resp_headers.content_length();
        let is_head = req.method == HttpMethod::Head;
        let is_empty_body_status =
            parsed_resp_headers.status_code == 204 || parsed_resp_headers.status_code == 304;

        let mut inspected_body = Vec::new();
        let mut streaming_write_failed = false;

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
                            streaming_write_failed = true;
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
                            streaming_write_failed = true;
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
                            streaming_write_failed = true;
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
        let resp_status = parsed_resp_headers.status_code;
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

        // Emit Completed diagnostic event strictly AFTER TrafficStore insertion and callback
        let write_succeeded = if streaming_write_failed {
            Some(false)
        } else {
            Some(true)
        };
        emit(
            ProxyDiagnosticPhase::Completed,
            None,
            Some(ProxyTerminationReason::CompletedSuccessfully),
            Some(resp_status),
            write_succeeded,
        );
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::create_shared_store;
    use crate::{HttpMethod, HttpRequest, TransactionState};

    #[test]
    fn test_observer_disabled_by_default() {
        let store = create_shared_store();
        let scope = Arc::new(AuditScope::default());
        let proxy = NativeProxyServer::new(18080, store, scope, None);
        assert_eq!(proxy.port(), 18080);
        assert!(!proxy.is_running());
        assert!(proxy.diagnostic_observer.is_none());
    }

    #[test]
    fn test_observer_compatibility_original_constructor() {
        let store = create_shared_store();
        let scope = Arc::new(AuditScope::default());
        let mut proxy = NativeProxyServer::new(18081, Arc::clone(&store), scope.clone(), None);
        assert!(proxy.diagnostic_observer.is_none());

        let obs = BoundedProxyObserver::new(10);
        proxy.set_diagnostic_observer(Some(obs.to_callback()));
        assert!(proxy.diagnostic_observer.is_some());
    }

    #[test]
    fn test_observer_correlation_by_conn_id_and_port() {
        let obs = BoundedProxyObserver::new(100);
        obs.record(ProxyDiagnosticEvent {
            conn_id: 11,
            client_port: 52140,
            phase: ProxyDiagnosticPhase::Accepted,
            io_result: None,
            termination_reason: None,
            http_response_attempted: None,
            http_response_write_succeeded: None,
        });
        obs.record(ProxyDiagnosticEvent {
            conn_id: 11,
            client_port: 52140,
            phase: ProxyDiagnosticPhase::UpstreamHeadersWrite,
            io_result: Some(IoOperationResult::Ok(160)),
            termination_reason: None,
            http_response_attempted: None,
            http_response_write_succeeded: None,
        });

        let events = obs.events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].conn_id, 11);
        assert_eq!(events[0].client_port, 52140);
        assert_eq!(events[0].phase, ProxyDiagnosticPhase::Accepted);
        assert_eq!(events[1].phase, ProxyDiagnosticPhase::UpstreamHeadersWrite);
    }

    #[test]
    fn test_observer_read_and_write_events() {
        let obs = BoundedProxyObserver::new(10);
        obs.record(ProxyDiagnosticEvent {
            conn_id: 1,
            client_port: 50000,
            phase: ProxyDiagnosticPhase::ClientHeadersRead,
            io_result: Some(IoOperationResult::Ok(128)),
            termination_reason: None,
            http_response_attempted: None,
            http_response_write_succeeded: None,
        });
        obs.record(ProxyDiagnosticEvent {
            conn_id: 1,
            client_port: 50000,
            phase: ProxyDiagnosticPhase::EarlyReturn,
            io_result: Some(IoOperationResult::Err {
                kind: std::io::ErrorKind::ConnectionReset,
                os_code: Some(10054),
            }),
            termination_reason: Some(ProxyTerminationReason::UpstreamHeadersWriteFailed),
            http_response_attempted: None,
            http_response_write_succeeded: None,
        });

        let events = obs.events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].io_result, Some(IoOperationResult::Ok(128)));
        assert_eq!(
            events[1].io_result,
            Some(IoOperationResult::Err {
                kind: std::io::ErrorKind::ConnectionReset,
                os_code: Some(10054),
            })
        );
        assert_eq!(
            events[1].termination_reason,
            Some(ProxyTerminationReason::UpstreamHeadersWriteFailed)
        );
    }

    #[test]
    fn test_observer_optional_errorkind_and_os_code() {
        let res_with_os = IoOperationResult::Err {
            kind: std::io::ErrorKind::BrokenPipe,
            os_code: Some(32),
        };
        let res_without_os = IoOperationResult::Err {
            kind: std::io::ErrorKind::TimedOut,
            os_code: None,
        };

        match res_with_os {
            IoOperationResult::Err { kind, os_code } => {
                assert_eq!(kind, std::io::ErrorKind::BrokenPipe);
                assert_eq!(os_code, Some(32));
            }
            _ => panic!("Expected Err"),
        }

        match res_without_os {
            IoOperationResult::Err { kind, os_code } => {
                assert_eq!(kind, std::io::ErrorKind::TimedOut);
                assert_eq!(os_code, None);
            }
            _ => panic!("Expected Err"),
        }
    }

    #[test]
    fn test_observer_typed_termination_reasons() {
        let reasons = [
            (
                ProxyTerminationReason::ClientHeadersTooLarge,
                "CLIENT_HEADERS_TOO_LARGE",
            ),
            (
                ProxyTerminationReason::ClientHeadersReadFailed,
                "CLIENT_HEADERS_READ_FAILED",
            ),
            (
                ProxyTerminationReason::RequestParseFailed,
                "REQUEST_PARSE_FAILED",
            ),
            (
                ProxyTerminationReason::HttpsConnectNotSupported,
                "HTTPS_CONNECT_NOT_SUPPORTED",
            ),
            (
                ProxyTerminationReason::ClientBodyReadFailed,
                "CLIENT_BODY_READ_FAILED",
            ),
            (
                ProxyTerminationReason::RequestReparseFailed,
                "REQUEST_REPARSE_FAILED",
            ),
            (
                ProxyTerminationReason::ScopeHostForbidden,
                "SCOPE_HOST_FORBIDDEN",
            ),
            (
                ProxyTerminationReason::DnsResolutionFailed,
                "DNS_RESOLUTION_FAILED",
            ),
            (
                ProxyTerminationReason::ScopeIpForbidden,
                "SCOPE_IP_FORBIDDEN",
            ),
            (
                ProxyTerminationReason::UpstreamConnectFailed,
                "UPSTREAM_CONNECT_FAILED",
            ),
            (
                ProxyTerminationReason::UpstreamHeadersWriteFailed,
                "UPSTREAM_HEADERS_WRITE_FAILED",
            ),
            (
                ProxyTerminationReason::UpstreamBodyWriteFailed,
                "UPSTREAM_BODY_WRITE_FAILED",
            ),
            (
                ProxyTerminationReason::UpstreamHeadersTooLarge,
                "UPSTREAM_HEADERS_TOO_LARGE",
            ),
            (
                ProxyTerminationReason::UpstreamHeadersIncomplete,
                "UPSTREAM_HEADERS_INCOMPLETE",
            ),
            (
                ProxyTerminationReason::UpstreamResponseParseFailed,
                "UPSTREAM_RESPONSE_PARSE_FAILED",
            ),
            (
                ProxyTerminationReason::ClientResponseHeadersWriteFailed,
                "CLIENT_RESPONSE_HEADERS_WRITE_FAILED",
            ),
            (
                ProxyTerminationReason::ClientResponseBodyWriteFailed,
                "CLIENT_RESPONSE_BODY_WRITE_FAILED",
            ),
            (
                ProxyTerminationReason::CompletedSuccessfully,
                "COMPLETED_SUCCESSFULLY",
            ),
        ];

        for (reason, expected_str) in reasons {
            assert_eq!(reason.as_str(), expected_str);
        }
    }

    #[test]
    fn test_observer_difference_attempted_vs_successful_write() {
        let attempted_and_failed = ProxyDiagnosticEvent {
            conn_id: 1,
            client_port: 50001,
            phase: ProxyDiagnosticPhase::EarlyReturn,
            io_result: Some(IoOperationResult::Err {
                kind: std::io::ErrorKind::BrokenPipe,
                os_code: None,
            }),
            termination_reason: Some(ProxyTerminationReason::UpstreamConnectFailed),
            http_response_attempted: Some(502),
            http_response_write_succeeded: Some(false),
        };

        let attempted_and_succeeded = ProxyDiagnosticEvent {
            conn_id: 2,
            client_port: 50002,
            phase: ProxyDiagnosticPhase::EarlyReturn,
            io_result: Some(IoOperationResult::Ok(100)),
            termination_reason: Some(ProxyTerminationReason::UpstreamConnectFailed),
            http_response_attempted: Some(502),
            http_response_write_succeeded: Some(true),
        };

        let silent_return = ProxyDiagnosticEvent {
            conn_id: 3,
            client_port: 50003,
            phase: ProxyDiagnosticPhase::EarlyReturn,
            io_result: Some(IoOperationResult::Err {
                kind: std::io::ErrorKind::ConnectionReset,
                os_code: None,
            }),
            termination_reason: Some(ProxyTerminationReason::UpstreamHeadersWriteFailed),
            http_response_attempted: None,
            http_response_write_succeeded: None,
        };

        assert_eq!(attempted_and_failed.http_response_attempted, Some(502));
        assert_eq!(
            attempted_and_failed.http_response_write_succeeded,
            Some(false)
        );

        assert_eq!(attempted_and_succeeded.http_response_attempted, Some(502));
        assert_eq!(
            attempted_and_succeeded.http_response_write_succeeded,
            Some(true)
        );

        assert_eq!(silent_return.http_response_attempted, None);
        assert_eq!(silent_return.http_response_write_succeeded, None);
    }

    #[test]
    fn test_observer_event_limit_and_dropped_signaling() {
        let obs = BoundedProxyObserver::new(3);

        for i in 1..=5 {
            obs.record(ProxyDiagnosticEvent {
                conn_id: i,
                client_port: 50000 + i as u16,
                phase: ProxyDiagnosticPhase::Accepted,
                io_result: None,
                termination_reason: None,
                http_response_attempted: None,
                http_response_write_succeeded: None,
            });
        }

        assert_eq!(obs.events().len(), 3);
        assert_eq!(obs.dropped_count(), 2);
    }

    #[test]
    fn test_observer_absence_of_sensitive_content() {
        let event = ProxyDiagnosticEvent {
            conn_id: 42,
            client_port: 51234,
            phase: ProxyDiagnosticPhase::RequestParsed,
            io_result: None,
            termination_reason: None,
            http_response_attempted: None,
            http_response_write_succeeded: None,
        };

        let debug_str = format!("{:?}", event);
        assert!(!debug_str.contains("Authorization"));
        assert!(!debug_str.contains("Cookie"));
        assert!(!debug_str.contains("Bearer"));
        assert!(!debug_str.contains("http://"));
        assert!(!debug_str.contains("password"));
        assert!(!debug_str.contains("token"));
    }

    #[test]
    fn test_observer_zero_panic_guarantee() {
        let store = create_shared_store();
        let scope = Arc::new(AuditScope::default());
        let panic_observer: ProxyDiagnosticCallback = Arc::new(|_| {
            panic!("Diagnostic observer synthetic panic");
        });

        let proxy = NativeProxyServer::with_diagnostic_observer(
            18082,
            store,
            scope,
            None,
            Some(panic_observer),
        );
        assert!(proxy.diagnostic_observer.is_some());
    }

    #[test]
    fn test_client_body_read_intermediate_event_no_termination_reason() {
        let obs = BoundedProxyObserver::new(10);
        let obs_cb = obs.to_callback();

        // Simulate the event emitted on body loop break (partial read / Ok(0) / WouldBlock)
        obs_cb(ProxyDiagnosticEvent {
            conn_id: 42,
            client_port: 12345,
            phase: ProxyDiagnosticPhase::ClientBodyRead,
            io_result: Some(IoOperationResult::Ok(0)),
            termination_reason: None,
            http_response_attempted: None,
            http_response_write_succeeded: None,
        });

        let events = obs.snapshot();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].phase, ProxyDiagnosticPhase::ClientBodyRead);
        assert_eq!(events[0].termination_reason, None);
        assert!(matches!(
            events[0].io_result,
            Some(IoOperationResult::Ok(0))
        ));
    }

    #[test]
    fn test_write_all_ok_flush_err_not_classified_as_write_failure() {
        // Simulates the pattern implemented across all response branches:
        // write_all succeeded (Ok), flush failed (Err).
        // http_response_write_succeeded must be Some(true), not false.
        let msg = b"HTTP/1.1 502 Bad Gateway\r\n\r\n";
        let write_ok: std::io::Result<()> = Ok(());
        let _flush_err: std::io::Result<()> = Err(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "simulated flush failure",
        ));

        let succ = write_ok.is_ok();
        let io_res = match write_ok {
            Ok(_) => IoOperationResult::Ok(msg.len()),
            Err(ref e) => IoOperationResult::Err {
                kind: e.kind(),
                os_code: e.raw_os_error(),
            },
        };

        let event = ProxyDiagnosticEvent {
            conn_id: 100,
            client_port: 54321,
            phase: ProxyDiagnosticPhase::EarlyReturn,
            io_result: Some(io_res),
            termination_reason: Some(ProxyTerminationReason::UpstreamConnectFailed),
            http_response_attempted: Some(502),
            http_response_write_succeeded: Some(succ),
        };

        assert_eq!(event.http_response_write_succeeded, Some(true));
        assert!(matches!(event.io_result, Some(IoOperationResult::Ok(_))));
    }

    #[test]
    fn test_write_all_err_preserves_error_kind_and_false() {
        // 1. Simulates write_all failing with a portable ErrorKind (ConnectionReset)
        let original_error =
            std::io::Error::new(std::io::ErrorKind::ConnectionReset, "connection reset");
        let expected_kind = original_error.kind();
        let expected_os_code = original_error.raw_os_error(); // None for synthetic error

        let write_err: std::io::Result<()> = Err(original_error);
        let succ = write_err.is_ok();
        let io_res = match write_err {
            Ok(_) => IoOperationResult::Ok(100),
            Err(ref e) => IoOperationResult::Err {
                kind: e.kind(),
                os_code: e.raw_os_error(),
            },
        };

        let event = ProxyDiagnosticEvent {
            conn_id: 101,
            client_port: 54322,
            phase: ProxyDiagnosticPhase::EarlyReturn,
            io_result: Some(io_res),
            termination_reason: Some(ProxyTerminationReason::ClientResponseHeadersWriteFailed),
            http_response_attempted: Some(200),
            http_response_write_succeeded: Some(succ),
        };

        assert_eq!(event.http_response_write_succeeded, Some(false));
        match event.io_result {
            Some(IoOperationResult::Err { kind, os_code }) => {
                assert_eq!(kind, expected_kind);
                assert_eq!(kind, std::io::ErrorKind::ConnectionReset);
                assert_eq!(os_code, expected_os_code);
            }
            _ => panic!("Expected IoOperationResult::Err"),
        }

        // 2. Separately verifies raw_os_error preservation without assuming platform-specific mapping
        let test_os_code = 42;
        let os_err = std::io::Error::from_raw_os_error(test_os_code);
        let expected_os_kind = os_err.kind();
        let io_res_os = IoOperationResult::Err {
            kind: os_err.kind(),
            os_code: os_err.raw_os_error(),
        };
        match io_res_os {
            IoOperationResult::Err { kind, os_code } => {
                assert_eq!(kind, expected_os_kind);
                assert_eq!(os_code, Some(test_os_code));
            }
            _ => panic!("Expected IoOperationResult::Err"),
        }
    }

    #[test]
    fn test_completed_event_order_strictly_after_store_insertion() {
        // Verifies the ordering invariant: when CompletedSuccessfully is observed,
        // the store already contains the transaction.
        let store = create_shared_store();
        let store_clone = Arc::clone(&store);

        let order_verified = Arc::new(AtomicBool::new(false));
        let order_clone = Arc::clone(&order_verified);

        let observer_cb: ProxyDiagnosticCallback = Arc::new(move |ev| {
            if ev.phase == ProxyDiagnosticPhase::Completed
                && ev.termination_reason == Some(ProxyTerminationReason::CompletedSuccessfully)
            {
                // Invariant: store must already have at least 1 transaction
                let count = store_clone.lock().unwrap().count();
                if count > 0 {
                    order_clone.store(true, Ordering::SeqCst);
                }
            }
        });

        // Simulates the end of handle_client:
        // 1. Store insertion
        let tx = HttpTransaction {
            id: 0,
            timestamp_rfc3339: "now".to_string(),
            request: HttpRequest {
                method: HttpMethod::Get,
                raw_url: "http://127.0.0.1/".to_string(),
                host: "127.0.0.1".to_string(),
                path: "/".to_string(),
                query: String::new(),
                http_version: "HTTP/1.1".to_string(),
                headers: vec![],
                body: vec![],
            },
            response: None,
            duration_ms: 1,
            state: TransactionState::Completed,
        };
        store.lock().unwrap().insert(tx);

        // 2. Completed diagnostic emission
        observer_cb(ProxyDiagnosticEvent {
            conn_id: 1,
            client_port: 12345,
            phase: ProxyDiagnosticPhase::Completed,
            io_result: None,
            termination_reason: Some(ProxyTerminationReason::CompletedSuccessfully),
            http_response_attempted: Some(200),
            http_response_write_succeeded: Some(true),
        });

        assert!(order_verified.load(Ordering::SeqCst));
    }
}
