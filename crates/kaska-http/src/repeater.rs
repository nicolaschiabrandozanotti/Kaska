use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use thiserror::Error;

use crate::models::{HttpHeader, HttpMethod, HttpRequest, HttpResponse};
use crate::parser::{HttpParseError, HttpParser};
use crate::scope::AuditScope;

/// Default safety limit for HTTP request and response header sections (64 KiB)
pub const DEFAULT_MAX_HEADER_BYTES: usize = 64 * 1024;
/// Default safety limit for outgoing HTTP request body (1 MiB)
pub const DEFAULT_MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;
/// Default safety limit for incoming HTTP response body inspection (2 MiB)
pub const DEFAULT_MAX_RESPONSE_BODY_BYTES: usize = 2 * 1024 * 1024;
/// Default per-address TCP connect timeout (1500 ms)
pub const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 1500;
/// Default total execution deadline budget (5000 ms)
pub const DEFAULT_TOTAL_TIMEOUT_MS: u64 = 5000;
/// Default short I/O slice timeout used to poll cancellation and monotonic deadline (50 ms)
pub const DEFAULT_IO_SLICE_TIMEOUT_MS: u64 = 50;
/// Maximum number of 1xx informational responses tolerated before final status
const MAX_INFORMATIONAL_RESPONSES: usize = 4;
/// Hard ceiling for a single chunk-size + chunk-extension line (including CRLF)
const MAX_CHUNK_HEADER_LINE_BYTES: usize = 4096;
/// Hard ceiling for the chunk-extension portion (`;ext=val`) within a chunk-size line
const MAX_CHUNK_EXTENSION_BYTES: usize = 2048;
/// Hard ceiling for a single trailer header line (including CRLF)
const MAX_SINGLE_TRAILER_LINE_BYTES: usize = 8192;
/// Base framing overhead allowance for chunked wire encoding (64 KiB)
const CHUNKED_WIRE_OVERHEAD_BASE_BYTES: usize = 64 * 1024;

/// Configuration and resource boundaries for the native HTTP/1.1 Repeater engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepeaterConfig {
    pub max_header_bytes: usize,
    pub max_request_body_bytes: usize,
    pub max_response_body_bytes: usize,
    pub connect_timeout: Duration,
    pub total_timeout: Duration,
    pub io_slice_timeout: Duration,
}

impl Default for RepeaterConfig {
    fn default() -> Self {
        Self {
            max_header_bytes: DEFAULT_MAX_HEADER_BYTES,
            max_request_body_bytes: DEFAULT_MAX_REQUEST_BODY_BYTES,
            max_response_body_bytes: DEFAULT_MAX_RESPONSE_BODY_BYTES,
            connect_timeout: Duration::from_millis(DEFAULT_CONNECT_TIMEOUT_MS),
            total_timeout: Duration::from_millis(DEFAULT_TOTAL_TIMEOUT_MS),
            io_slice_timeout: Duration::from_millis(DEFAULT_IO_SLICE_TIMEOUT_MS),
        }
    }
}

/// Structured input specification for an HTTP/1.1 Repeater dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepeaterRequestSpec {
    pub method: HttpMethod,
    pub target_url: String,
    pub headers: Vec<HttpHeader>,
    pub body: Vec<u8>,
}

impl RepeaterRequestSpec {
    pub fn new(method: HttpMethod, target_url: impl Into<String>) -> Self {
        Self {
            method,
            target_url: target_url.into(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub fn with_headers(mut self, headers: Vec<HttpHeader>) -> Self {
        self.headers = headers;
        self
    }

    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push(HttpHeader::new(name, value));
        self
    }

    pub fn with_body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    /// Parses a multi-line raw header block (`Key: Value` per line) into a validated `RepeaterRequestSpec`.
    /// Rejects any non-empty line missing a `:` separator or containing embedded CR/LF characters.
    pub fn from_raw_headers(
        method: HttpMethod,
        target_url: impl Into<String>,
        raw_headers: &str,
        body: impl Into<Vec<u8>>,
    ) -> Result<Self, RepeaterError> {
        let headers = Self::parse_header_block(raw_headers)?;
        Ok(Self {
            method,
            target_url: target_url.into(),
            headers,
            body: body.into(),
        })
    }

    /// Parses raw header lines strictly into `Vec<HttpHeader>`.
    pub fn parse_header_block(raw_headers: &str) -> Result<Vec<HttpHeader>, RepeaterError> {
        let mut headers = Vec::new();
        for raw_line in raw_headers.split('\n') {
            let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
            if line.trim().is_empty() {
                continue;
            }
            if line.contains('\r') || line.contains('\0') {
                return Err(RepeaterError::InvalidHeader(
                    "Header line contains forbidden CR or NUL character".to_string(),
                ));
            }
            let (name, value) = line.split_once(':').ok_or_else(|| {
                RepeaterError::InvalidHeader(format!("Malformed header line missing ':': {}", line))
            })?;
            headers.push(HttpHeader::new(name.trim(), value.trim()));
        }
        Ok(headers)
    }
}

/// Complete result of a single HTTP/1.1 Repeater execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepeaterExecutionResult {
    pub request: HttpRequest,
    pub response: HttpResponse,
    pub duration_ms: u64,
    pub response_body_truncated: bool,
    pub remote_addr: SocketAddr,
}

/// Typed errors produced by the HTTP/1.1 Repeater engine.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RepeaterError {
    #[error("Invalid target URL: {0}")]
    InvalidUrl(String),

    #[error("Unsupported URL scheme '{0}': only http:// is permitted in Milestone 1.1")]
    UnsupportedScheme(String),

    #[error("HTTP method '{0}' is not permitted in Repeater")]
    UnsupportedMethod(String),

    #[error("Target host '{0}' is outside authorized loopback scope")]
    HostOutOfScope(String),

    #[error("Host header '{header_host}' does not match target URL authority '{url_host}'")]
    HostHeaderMismatch {
        url_host: String,
        header_host: String,
    },

    #[error("Resolved IP '{0}' is outside authorized loopback scope")]
    IpOutOfScope(String),

    #[error("Invalid HTTP header: {0}")]
    InvalidHeader(String),

    #[error("Request validation failed: {0}")]
    RequestValidation(String),

    #[error("Request headers exceed maximum size limit ({actual} bytes > {limit} bytes)")]
    RequestHeadersTooLarge { actual: usize, limit: usize },

    #[error("Request body exceeds maximum size limit ({actual} bytes > {limit} bytes)")]
    RequestBodyTooLarge { actual: usize, limit: usize },

    #[error("Response headers exceed maximum size limit ({limit} bytes)")]
    ResponseHeadersTooLarge { limit: usize },

    #[error("Connection to loopback target failed: {0}")]
    ConnectionFailed(String),

    #[error("Malformed or incomplete upstream HTTP/1.1 response: {0}")]
    InvalidResponse(String),

    #[error("Repeater execution timed out after {0} ms")]
    Timeout(u64),

    #[error("Repeater execution cancelled")]
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedTargetUrl {
    canonical_host: String,
    port: u16,
    explicit_port: bool,
    path: String,
    query: String,
}

impl ParsedTargetUrl {
    fn request_target(&self) -> String {
        if self.query.is_empty() {
            self.path.clone()
        } else {
            format!("{}?{}", self.path, self.query)
        }
    }

    fn normalized_host_header(&self) -> String {
        let host_repr = if self.canonical_host == "::1" {
            "[::1]".to_string()
        } else {
            self.canonical_host.clone()
        };

        if self.explicit_port || self.port != 80 {
            format!("{}:{}", host_repr, self.port)
        } else {
            host_repr
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum BoundedChunkedState {
    ReadingSizeLine,
    ReadingData { remaining: usize },
    ReadingDataCr,
    ReadingDataLf,
    ReadingTrailers,
    Complete,
}

/// Linear-time, memory-bounded RFC 9112 chunked transfer decoder for the Repeater.
/// Enforces explicit limits on:
/// 1. Decoded body bytes (`max_body_bytes`)
/// 2. Chunk header line bytes (`max_chunk_line_bytes`)
/// 3. Chunk extension bytes (`max_extension_bytes`)
/// 4. Single trailer line bytes (`max_single_trailer_bytes`)
/// 5. Aggregate trailer section bytes (`max_total_trailer_bytes`)
/// 6. Pending line parse buffer (`line_buf`, bounded by `max(max_chunk_line_bytes, max_single_trailer_bytes)`)
/// 7. Total encoded wire bytes admitted (`max_encoded_wire_bytes`)
struct BoundedChunkedDecoder {
    state: BoundedChunkedState,
    line_buf: Vec<u8>,
    decoded: Vec<u8>,
    max_body_bytes: usize,
    max_chunk_line_bytes: usize,
    max_extension_bytes: usize,
    max_single_trailer_bytes: usize,
    max_total_trailer_bytes: usize,
    max_encoded_wire_bytes: usize,
    total_decoded_bytes: usize,
    total_trailer_bytes: usize,
    total_encoded_bytes: usize,
}

impl BoundedChunkedDecoder {
    fn new(max_body_bytes: usize, max_header_bytes: usize) -> Self {
        let max_chunk_line_bytes =
            std::cmp::min(MAX_CHUNK_HEADER_LINE_BYTES, max_header_bytes).max(64);
        let max_extension_bytes = std::cmp::min(
            MAX_CHUNK_EXTENSION_BYTES,
            max_chunk_line_bytes.saturating_sub(4),
        );
        let max_single_trailer_bytes =
            std::cmp::min(MAX_SINGLE_TRAILER_LINE_BYTES, max_header_bytes).max(64);
        let max_total_trailer_bytes = max_header_bytes;
        let max_encoded_wire_bytes = max_body_bytes
            .saturating_add(max_body_bytes / 2)
            .saturating_add(max_header_bytes)
            .saturating_add(CHUNKED_WIRE_OVERHEAD_BASE_BYTES);

        Self {
            state: BoundedChunkedState::ReadingSizeLine,
            line_buf: Vec::with_capacity(256),
            decoded: Vec::new(),
            max_body_bytes,
            max_chunk_line_bytes,
            max_extension_bytes,
            max_single_trailer_bytes,
            max_total_trailer_bytes,
            max_encoded_wire_bytes,
            total_decoded_bytes: 0,
            total_trailer_bytes: 0,
            total_encoded_bytes: 0,
        }
    }

    fn is_complete(&self) -> bool {
        self.state == BoundedChunkedState::Complete
    }

    fn total_decoded_bytes(&self) -> usize {
        self.total_decoded_bytes
    }

    fn into_decoded(self) -> Vec<u8> {
        self.decoded
    }

    fn feed(&mut self, mut input: &[u8]) -> Result<(), RepeaterError> {
        self.total_encoded_bytes = self
            .total_encoded_bytes
            .checked_add(input.len())
            .ok_or_else(|| {
                RepeaterError::InvalidResponse(
                    "Chunked encoded stream byte counter overflow".to_string(),
                )
            })?;

        if self.total_encoded_bytes > self.max_encoded_wire_bytes {
            return Err(RepeaterError::InvalidResponse(format!(
                "Chunked stream exceeded maximum encoded wire budget ({} bytes)",
                self.max_encoded_wire_bytes
            )));
        }

        while !input.is_empty() {
            match self.state {
                BoundedChunkedState::ReadingSizeLine => {
                    let newline_pos = input.iter().position(|&b| b == b'\n');
                    let take_len = newline_pos.map_or(input.len(), |p| p + 1);

                    if self.line_buf.len().saturating_add(take_len) > self.max_chunk_line_bytes {
                        return Err(RepeaterError::InvalidResponse(format!(
                            "Chunk size/extension line exceeds maximum limit ({} bytes)",
                            self.max_chunk_line_bytes
                        )));
                    }

                    self.line_buf.extend_from_slice(&input[..take_len]);
                    input = &input[take_len..];

                    if newline_pos.is_some() {
                        let chunk_size =
                            Self::parse_chunk_size_line(&self.line_buf, self.max_extension_bytes)?;
                        self.line_buf.clear();

                        if chunk_size == 0 {
                            self.state = BoundedChunkedState::ReadingTrailers;
                        } else {
                            self.state = BoundedChunkedState::ReadingData {
                                remaining: chunk_size,
                            };
                        }
                    }
                }
                BoundedChunkedState::ReadingData { ref mut remaining } => {
                    let to_consume = std::cmp::min(input.len(), *remaining);
                    let data_slice = &input[..to_consume];
                    input = &input[to_consume..];
                    *remaining -= to_consume;

                    self.total_decoded_bytes = self
                        .total_decoded_bytes
                        .checked_add(to_consume)
                        .ok_or_else(|| {
                            RepeaterError::InvalidResponse(
                                "Decoded chunked body size overflow".to_string(),
                            )
                        })?;

                    if self.decoded.len() < self.max_body_bytes {
                        let can_take =
                            std::cmp::min(to_consume, self.max_body_bytes - self.decoded.len());
                        self.decoded.extend_from_slice(&data_slice[..can_take]);
                    }

                    if *remaining == 0 {
                        self.state = BoundedChunkedState::ReadingDataCr;
                    }

                    if self.total_decoded_bytes > self.max_body_bytes {
                        // Body limit exceeded after valid chunk header; caller will stop and report truncation
                        break;
                    }
                }
                BoundedChunkedState::ReadingDataCr => {
                    let b = input[0];
                    input = &input[1..];
                    if b == b'\r' {
                        self.state = BoundedChunkedState::ReadingDataLf;
                    } else if b == b'\n' {
                        self.state = BoundedChunkedState::ReadingSizeLine;
                    } else {
                        return Err(RepeaterError::InvalidResponse(
                            "Invalid chunk framing: expected CRLF after chunk data".to_string(),
                        ));
                    }
                }
                BoundedChunkedState::ReadingDataLf => {
                    let b = input[0];
                    input = &input[1..];
                    if b == b'\n' {
                        self.state = BoundedChunkedState::ReadingSizeLine;
                    } else {
                        return Err(RepeaterError::InvalidResponse(
                            "Invalid chunk framing: expected LF after CR at end of chunk data"
                                .to_string(),
                        ));
                    }
                }
                BoundedChunkedState::ReadingTrailers => {
                    let newline_pos = input.iter().position(|&b| b == b'\n');
                    let take_len = newline_pos.map_or(input.len(), |p| p + 1);

                    if self.line_buf.len().saturating_add(take_len) > self.max_single_trailer_bytes
                    {
                        return Err(RepeaterError::InvalidResponse(format!(
                            "Chunked trailer line exceeds maximum line limit ({} bytes)",
                            self.max_single_trailer_bytes
                        )));
                    }

                    self.total_trailer_bytes = self
                        .total_trailer_bytes
                        .checked_add(take_len)
                        .ok_or_else(|| {
                            RepeaterError::InvalidResponse(
                                "Chunked trailer byte counter overflow".to_string(),
                            )
                        })?;

                    if self.total_trailer_bytes > self.max_total_trailer_bytes {
                        return Err(RepeaterError::InvalidResponse(format!(
                            "Chunked trailer section exceeds maximum total limit ({} bytes)",
                            self.max_total_trailer_bytes
                        )));
                    }

                    self.line_buf.extend_from_slice(&input[..take_len]);
                    input = &input[take_len..];

                    if newline_pos.is_some() {
                        let is_terminal = Self::validate_trailer_line(&self.line_buf)?;
                        self.line_buf.clear();
                        if is_terminal {
                            self.state = BoundedChunkedState::Complete;
                            if !input.is_empty() {
                                return Err(RepeaterError::InvalidResponse(
                                    "Unexpected trailing bytes after terminal chunked CRLF"
                                        .to_string(),
                                ));
                            }
                            break;
                        }
                    }
                }
                BoundedChunkedState::Complete => {
                    if !input.is_empty() {
                        return Err(RepeaterError::InvalidResponse(
                            "Unexpected trailing bytes after complete chunked message".to_string(),
                        ));
                    }
                    break;
                }
            }
        }

        Ok(())
    }

    fn parse_chunk_size_line(
        raw_line: &[u8],
        max_extension_bytes: usize,
    ) -> Result<usize, RepeaterError> {
        let without_lf = raw_line.strip_suffix(b"\n").ok_or_else(|| {
            RepeaterError::InvalidResponse("Incomplete chunk size line".to_string())
        })?;
        let line_bytes = without_lf.strip_suffix(b"\r").unwrap_or(without_lf);

        if line_bytes.is_empty() {
            return Err(RepeaterError::InvalidResponse(
                "Empty chunk size line in chunked body".to_string(),
            ));
        }

        // Reject any embedded CR, LF, NUL, or control chars in chunk header line
        for &b in line_bytes {
            if b == b'\r' || b == b'\n' || b == 0x00 || (b < 0x20 && b != b'\t') || b == 0x7F {
                return Err(RepeaterError::InvalidResponse(
                    "Chunk size line contains forbidden control character".to_string(),
                ));
            }
        }

        let line_str = std::str::from_utf8(line_bytes).map_err(|_| {
            RepeaterError::InvalidResponse("Chunk size line is not valid ASCII/UTF-8".to_string())
        })?;

        let (hex_part, ext_opt) = match line_str.split_once(';') {
            Some((h, ext)) => (h, Some(ext)),
            None => (line_str, None),
        };

        if let Some(ext) = ext_opt {
            if ext.len() > max_extension_bytes {
                return Err(RepeaterError::InvalidResponse(format!(
                    "Chunk extension exceeds maximum allowed length ({} bytes > {} bytes)",
                    ext.len(),
                    max_extension_bytes
                )));
            }
        }

        let hex_trimmed = hex_part.trim();
        if hex_trimmed.is_empty()
            || hex_trimmed.len() > 16
            || !hex_trimmed.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(RepeaterError::InvalidResponse(format!(
                "Invalid chunk hex size '{}'",
                hex_trimmed
            )));
        }

        usize::from_str_radix(hex_trimmed, 16).map_err(|_| {
            RepeaterError::InvalidResponse(format!("Unparseable chunk hex size '{}'", hex_trimmed))
        })
    }

    fn validate_trailer_line(raw_line: &[u8]) -> Result<bool, RepeaterError> {
        let without_lf = raw_line.strip_suffix(b"\n").ok_or_else(|| {
            RepeaterError::InvalidResponse("Incomplete chunked trailer line".to_string())
        })?;
        let line_bytes = without_lf.strip_suffix(b"\r").unwrap_or(without_lf);

        if line_bytes.is_empty() {
            return Ok(true);
        }

        let line_str = std::str::from_utf8(line_bytes).map_err(|_| {
            RepeaterError::InvalidResponse("Trailer line contains invalid UTF-8".to_string())
        })?;

        let (name, value) = line_str.split_once(':').ok_or_else(|| {
            RepeaterError::InvalidResponse(format!(
                "Malformed chunked trailer line missing ':': '{}'",
                line_str
            ))
        })?;

        let name_trimmed = name.trim();
        let value_trimmed = value.trim();
        HttpRepeaterEngine::validate_header_name(name_trimmed).map_err(|_| {
            RepeaterError::InvalidResponse(format!(
                "Invalid trailer header name '{}'",
                name_trimmed
            ))
        })?;
        HttpRepeaterEngine::validate_header_value(name_trimmed, value_trimmed).map_err(|_| {
            RepeaterError::InvalidResponse(format!(
                "Invalid trailer header value for '{}'",
                name_trimmed
            ))
        })?;

        Ok(false)
    }
}

/// Native, Slint-independent HTTP/1.1 Repeater engine restricted to loopback targets.
#[derive(Debug, Clone)]
pub struct HttpRepeaterEngine {
    scope: Arc<AuditScope>,
    config: RepeaterConfig,
}

impl Default for HttpRepeaterEngine {
    fn default() -> Self {
        Self::new(Arc::new(AuditScope::default()), RepeaterConfig::default())
    }
}

impl HttpRepeaterEngine {
    pub fn new(scope: Arc<AuditScope>, config: RepeaterConfig) -> Self {
        Self { scope, config }
    }

    pub fn config(&self) -> &RepeaterConfig {
        &self.config
    }

    pub fn scope(&self) -> &AuditScope {
        &self.scope
    }

    /// Executes an HTTP/1.1 request synchronously (intended to be called from a worker thread).
    /// Enforces all URL, method, scope, header, framing, timeout, and cancellation invariants.
    pub fn execute(
        &self,
        spec: &RepeaterRequestSpec,
        cancel_flag: Option<&AtomicBool>,
    ) -> Result<RepeaterExecutionResult, RepeaterError> {
        let start_time = Instant::now();
        let deadline = start_time + self.config.total_timeout;

        self.check_budget(deadline, cancel_flag)?;

        // 1. Validate HTTP method
        Self::validate_method(&spec.method)?;

        // 2. Validate request body size limit before allocating wire buffer
        if spec.body.len() > self.config.max_request_body_bytes {
            return Err(RepeaterError::RequestBodyTooLarge {
                actual: spec.body.len(),
                limit: self.config.max_request_body_bytes,
            });
        }

        // 3. Parse and validate target URL + scope + deterministic loopback SocketAddrs
        let parsed_url = Self::parse_and_validate_url(&spec.target_url, &self.scope)?;
        let candidate_addrs = Self::resolve_loopback_targets(&parsed_url, &self.scope)?;

        // 4. Validate and normalize headers incrementally against max_header_bytes, then serialize wire request bytes
        let (wire_bytes, normalized_request) =
            self.build_and_validate_wire_request(spec, &parsed_url)?;

        self.check_budget(deadline, cancel_flag)?;

        // 5. Connect to validated loopback SocketAddr within connect & total budget
        let (mut stream, remote_addr) =
            self.connect_loopback(&candidate_addrs, deadline, cancel_flag)?;

        // Ensure socket shutdown on all exit paths
        let result = (|| {
            // 6. Send wire request handling partial writes, timeouts, and cancellation
            self.write_all_bounded(&mut stream, &wire_bytes, deadline, cancel_flag)?;
            let _ = stream.flush();

            // 7. Read and decode HTTP/1.1 response with framing awareness and limits
            let (response, response_body_truncated) =
                self.read_http_response(&mut stream, &spec.method, deadline, cancel_flag)?;

            let duration_ms = start_time.elapsed().as_millis() as u64;

            Ok(RepeaterExecutionResult {
                request: normalized_request,
                response,
                duration_ms,
                response_body_truncated,
                remote_addr,
            })
        })();

        let _ = stream.shutdown(Shutdown::Both);
        result
    }

    fn check_budget(
        &self,
        deadline: Instant,
        cancel_flag: Option<&AtomicBool>,
    ) -> Result<Duration, RepeaterError> {
        if cancel_flag.is_some_and(|flag| flag.load(Ordering::SeqCst)) {
            return Err(RepeaterError::Cancelled);
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(RepeaterError::Timeout(
                self.config.total_timeout.as_millis() as u64,
            ));
        }
        Ok(deadline.duration_since(now))
    }

    fn validate_method(method: &HttpMethod) -> Result<(), RepeaterError> {
        match method {
            HttpMethod::Get
            | HttpMethod::Post
            | HttpMethod::Put
            | HttpMethod::Delete
            | HttpMethod::Patch
            | HttpMethod::Head
            | HttpMethod::Options => Ok(()),
            HttpMethod::Connect => Err(RepeaterError::UnsupportedMethod("CONNECT".to_string())),
            HttpMethod::Custom(other) => Err(RepeaterError::UnsupportedMethod(other.clone())),
        }
    }

    fn parse_and_validate_url(
        raw_url: &str,
        scope: &AuditScope,
    ) -> Result<ParsedTargetUrl, RepeaterError> {
        if raw_url.is_empty() {
            return Err(RepeaterError::InvalidUrl("URL cannot be empty".to_string()));
        }

        // Reject any control character, whitespace, or backslash anywhere in URL
        for ch in raw_url.chars() {
            if ch.is_control() || ch.is_whitespace() || ch == '\\' {
                return Err(RepeaterError::InvalidUrl(
                    "URL contains forbidden control, whitespace, or backslash characters"
                        .to_string(),
                ));
            }
        }

        // Reject fragments (#) to prevent ambiguous target parsing
        if raw_url.contains('#') {
            return Err(RepeaterError::InvalidUrl(
                "URL fragments ('#') are not permitted in Repeater target URL".to_string(),
            ));
        }

        // Check scheme
        let Some((scheme_raw, after_scheme)) = raw_url.split_once("://") else {
            return Err(RepeaterError::InvalidUrl(
                "Target URL must be an absolute URL starting with http://".to_string(),
            ));
        };

        let scheme_lower = scheme_raw.to_ascii_lowercase();
        if scheme_lower != "http" {
            return Err(RepeaterError::UnsupportedScheme(scheme_lower));
        }

        if after_scheme.is_empty() {
            return Err(RepeaterError::InvalidUrl(
                "Missing authority in target URL".to_string(),
            ));
        }

        // Split authority and path/query
        let (authority, raw_path_and_query) = match after_scheme.find('/') {
            Some(slash_idx) => (&after_scheme[..slash_idx], &after_scheme[slash_idx..]),
            None => {
                if after_scheme.contains('?') {
                    return Err(RepeaterError::InvalidUrl(
                        "Ambiguous query delimiter '?' in authority without '/' path".to_string(),
                    ));
                }
                (after_scheme, "/")
            }
        };

        if authority.is_empty() {
            return Err(RepeaterError::InvalidUrl(
                "Empty authority in target URL".to_string(),
            ));
        }

        // Reject userinfo (user:pass@host)
        if authority.contains('@') {
            return Err(RepeaterError::InvalidUrl(
                "Userinfo ('@') is not permitted in target URL".to_string(),
            ));
        }

        let (canonical_host, port, explicit_port) = Self::parse_authority_strict(authority, scope)?;

        let (path, query) = match raw_path_and_query.split_once('?') {
            Some((p, q)) => (p.to_string(), q.to_string()),
            None => (raw_path_and_query.to_string(), String::new()),
        };

        if !path.starts_with('/') {
            return Err(RepeaterError::InvalidUrl(
                "Normalized path must start with '/'".to_string(),
            ));
        }

        Ok(ParsedTargetUrl {
            canonical_host,
            port,
            explicit_port,
            path,
            query,
        })
    }

    fn parse_authority_strict(
        authority: &str,
        scope: &AuditScope,
    ) -> Result<(String, u16, bool), RepeaterError> {
        if authority.is_empty()
            || authority
                .chars()
                .any(|c| c.is_control() || c.is_whitespace())
        {
            return Err(RepeaterError::InvalidUrl(
                "Invalid authority format".to_string(),
            ));
        }

        let (host_str, port_opt) = if let Some(rest) = authority.strip_prefix('[') {
            let Some((ipv6_inner, after_bracket)) = rest.split_once(']') else {
                return Err(RepeaterError::InvalidUrl(
                    "Unclosed IPv6 bracket in authority".to_string(),
                ));
            };
            if ipv6_inner.is_empty() || ipv6_inner.contains('[') || ipv6_inner.contains(']') {
                return Err(RepeaterError::InvalidUrl(
                    "Malformed IPv6 literal in authority".to_string(),
                ));
            }
            let port_opt = if after_bracket.is_empty() {
                None
            } else if let Some(port_str) = after_bracket.strip_prefix(':') {
                Some(Self::parse_port_strict(port_str)?)
            } else {
                return Err(RepeaterError::InvalidUrl(
                    "Unexpected characters after IPv6 bracket in authority".to_string(),
                ));
            };

            let parsed_v6: Ipv6Addr = ipv6_inner.parse().map_err(|_| {
                RepeaterError::InvalidUrl(format!("Invalid IPv6 literal '[{}]'", ipv6_inner))
            })?;
            if parsed_v6 != Ipv6Addr::LOCALHOST || ipv6_inner != "::1" {
                return Err(RepeaterError::HostOutOfScope(format!("[{}]", ipv6_inner)));
            }
            ("::1".to_string(), port_opt)
        } else {
            if authority.contains('[') || authority.contains(']') {
                return Err(RepeaterError::InvalidUrl(
                    "Misplaced brackets in authority".to_string(),
                ));
            }
            if authority.matches(':').count() > 1 {
                return Err(RepeaterError::InvalidUrl(
                    "IPv6 literal in URL must be enclosed in brackets '[::1]'".to_string(),
                ));
            }
            if let Some((h, p_str)) = authority.split_once(':') {
                if h.is_empty() {
                    return Err(RepeaterError::InvalidUrl(
                        "Empty host before port".to_string(),
                    ));
                }
                let port = Self::parse_port_strict(p_str)?;
                (h.to_ascii_lowercase(), Some(port))
            } else {
                (authority.to_ascii_lowercase(), None)
            }
        };

        let is_milestone_loopback_host =
            matches!(host_str.as_str(), "127.0.0.1" | "localhost" | "::1");
        if !is_milestone_loopback_host || !scope.is_allowed_host(&host_str) {
            return Err(RepeaterError::HostOutOfScope(host_str));
        }

        let explicit_port = port_opt.is_some();
        let port = port_opt.unwrap_or(80);

        Ok((host_str, port, explicit_port))
    }

    fn parse_port_strict(port_str: &str) -> Result<u16, RepeaterError> {
        if port_str.is_empty() || !port_str.bytes().all(|b| b.is_ascii_digit()) {
            return Err(RepeaterError::InvalidUrl(format!(
                "Invalid port '{}': must be numeric between 1 and 65535",
                port_str
            )));
        }
        let port: u16 = port_str.parse().map_err(|_| {
            RepeaterError::InvalidUrl(format!(
                "Port '{}' out of range (must be 1..=65535)",
                port_str
            ))
        })?;
        if port == 0 {
            return Err(RepeaterError::InvalidUrl(
                "Port 0 is not permitted in target URL".to_string(),
            ));
        }
        Ok(port)
    }

    /// Maps the validated loopback host to deterministic loopback SocketAddrs without arbitrary DNS queries.
    fn resolve_loopback_targets(
        parsed_url: &ParsedTargetUrl,
        scope: &AuditScope,
    ) -> Result<Vec<SocketAddr>, RepeaterError> {
        let raw_candidates: Vec<IpAddr> = match parsed_url.canonical_host.as_str() {
            "127.0.0.1" => vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            "::1" => vec![IpAddr::V6(Ipv6Addr::LOCALHOST)],
            "localhost" => vec![
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            ],
            other => return Err(RepeaterError::HostOutOfScope(other.to_string())),
        };

        let mut validated = Vec::with_capacity(raw_candidates.len());
        for ip in raw_candidates {
            if !ip.is_loopback() || !scope.is_allowed_ip(&ip) {
                return Err(RepeaterError::IpOutOfScope(ip.to_string()));
            }
            validated.push(SocketAddr::new(ip, parsed_url.port));
        }

        if validated.is_empty() {
            return Err(RepeaterError::IpOutOfScope(
                parsed_url.canonical_host.clone(),
            ));
        }

        Ok(validated)
    }

    fn is_valid_header_name_char(b: u8) -> bool {
        b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'!' | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'.'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'|'
                    | b'~'
            )
    }

    fn validate_header_name(name: &str) -> Result<(), RepeaterError> {
        if name.is_empty() {
            return Err(RepeaterError::InvalidHeader(
                "Header name cannot be empty".to_string(),
            ));
        }
        if !name.bytes().all(Self::is_valid_header_name_char) {
            return Err(RepeaterError::InvalidHeader(format!(
                "Invalid characters in header name '{}'",
                name
            )));
        }
        Ok(())
    }

    fn validate_header_value(name: &str, value: &str) -> Result<(), RepeaterError> {
        for b in value.bytes() {
            if b == b'\r' || b == b'\n' || b == 0x00 || (b < 0x20 && b != b'\t') || b == 0x7F {
                return Err(RepeaterError::InvalidHeader(format!(
                    "Header '{}' contains forbidden control or CR/LF character",
                    name
                )));
            }
        }
        Ok(())
    }

    fn validate_host_header_matches_url(
        header_val: &str,
        parsed_url: &ParsedTargetUrl,
        scope: &AuditScope,
    ) -> Result<(), RepeaterError> {
        let trimmed = header_val.trim();
        if trimmed.is_empty()
            || trimmed.contains('@')
            || trimmed.contains('/')
            || trimmed.contains('?')
        {
            return Err(RepeaterError::HostHeaderMismatch {
                url_host: parsed_url.normalized_host_header(),
                header_host: header_val.to_string(),
            });
        }

        let (hdr_host, hdr_port, hdr_explicit_port) =
            match Self::parse_authority_strict(trimmed, scope) {
                Ok(parsed) => parsed,
                Err(_) => {
                    return Err(RepeaterError::HostHeaderMismatch {
                        url_host: parsed_url.normalized_host_header(),
                        header_host: header_val.to_string(),
                    })
                }
            };

        let port_matches =
            hdr_port == parsed_url.port && (parsed_url.port == 80 || hdr_explicit_port);
        if hdr_host != parsed_url.canonical_host || !port_matches {
            return Err(RepeaterError::HostHeaderMismatch {
                url_host: parsed_url.normalized_host_header(),
                header_host: header_val.to_string(),
            });
        }

        Ok(())
    }

    fn add_header_budget(
        current: usize,
        addition: usize,
        limit: usize,
    ) -> Result<usize, RepeaterError> {
        let updated =
            current
                .checked_add(addition)
                .ok_or(RepeaterError::RequestHeadersTooLarge {
                    actual: usize::MAX,
                    limit,
                })?;
        if updated > limit {
            return Err(RepeaterError::RequestHeadersTooLarge {
                actual: updated,
                limit,
            });
        }
        Ok(updated)
    }

    fn build_and_validate_wire_request(
        &self,
        spec: &RepeaterRequestSpec,
        parsed_url: &ParsedTargetUrl,
    ) -> Result<(Vec<u8>, HttpRequest), RepeaterError> {
        let limit = self.config.max_header_bytes;
        let request_target = parsed_url.request_target();
        if request_target.contains('\r')
            || request_target.contains('\n')
            || request_target.contains(' ')
        {
            return Err(RepeaterError::RequestValidation(
                "Request target contains invalid characters".to_string(),
            ));
        }

        let normalized_host = parsed_url.normalized_host_header();

        // Incremental header byte accounting BEFORE allocating the serialized header block:
        // 1. Request-line: "<METHOD> <TARGET> HTTP/1.1\r\n"
        let request_line_bytes = spec
            .method
            .as_str()
            .len()
            .saturating_add(1)
            .saturating_add(request_target.len())
            .saturating_add(b" HTTP/1.1\r\n".len());
        // 2. Host header: "Host: <normalized_host>\r\n"
        let host_header_bytes = b"Host: "
            .len()
            .saturating_add(normalized_host.len())
            .saturating_add(b"\r\n".len());
        // 3. Connection header: "Connection: close\r\n" (19 bytes) + terminal CRLF "\r\n" (2 bytes)
        let connection_and_crlf_bytes = b"Connection: close\r\n".len() + b"\r\n".len();

        let mut running_header_bytes = 0usize;
        running_header_bytes =
            Self::add_header_budget(running_header_bytes, request_line_bytes, limit)?;
        running_header_bytes =
            Self::add_header_budget(running_header_bytes, host_header_bytes, limit)?;
        running_header_bytes =
            Self::add_header_budget(running_header_bytes, connection_and_crlf_bytes, limit)?;

        let mut seen_host = false;
        let mut seen_content_length = false;
        let mut filtered_headers: Vec<HttpHeader> = Vec::new();

        for hdr in &spec.headers {
            let name = hdr.name.trim();
            let value = hdr.value.trim();

            Self::validate_header_name(name)?;
            Self::validate_header_value(name, value)?;

            let name_lower = name.to_ascii_lowercase();
            match name_lower.as_str() {
                "host" => {
                    if seen_host {
                        return Err(RepeaterError::RequestValidation(
                            "Duplicate Host header is not permitted".to_string(),
                        ));
                    }
                    seen_host = true;
                    Self::validate_host_header_matches_url(value, parsed_url, &self.scope)?;
                }
                "content-length" => {
                    if seen_content_length {
                        return Err(RepeaterError::RequestValidation(
                            "Duplicate Content-Length header is not permitted".to_string(),
                        ));
                    }
                    seen_content_length = true;
                    if value.is_empty()
                        || !value.bytes().all(|b| b.is_ascii_digit())
                        || value.parse::<usize>().is_err()
                    {
                        return Err(RepeaterError::RequestValidation(format!(
                            "Invalid Content-Length header value '{}'",
                            value
                        )));
                    }
                }
                "transfer-encoding" => {
                    return Err(RepeaterError::RequestValidation(
                        "Outgoing Transfer-Encoding header is not permitted in Repeater"
                            .to_string(),
                    ));
                }
                "expect" => {
                    return Err(RepeaterError::RequestValidation(
                        "Expect header (e.g. 100-continue) is not supported in Milestone 1.1"
                            .to_string(),
                    ));
                }
                "upgrade"
                | "proxy-connection"
                | "proxy-authorization"
                | "te"
                | "trailer"
                | "http2-settings" => {
                    return Err(RepeaterError::RequestValidation(format!(
                        "Header '{}' is not permitted in Milestone 1.1 Repeater",
                        name
                    )));
                }
                "connection" => {
                    if value.to_ascii_lowercase().contains("upgrade") {
                        return Err(RepeaterError::RequestValidation(
                            "Connection: upgrade is not permitted in Repeater".to_string(),
                        ));
                    }
                }
                _ => {
                    // "<Name>: <Value>\r\n" -> name.len() + 2 + value.len() + 2
                    let line_bytes = name
                        .len()
                        .checked_add(2)
                        .and_then(|n| n.checked_add(value.len()))
                        .and_then(|n| n.checked_add(2))
                        .ok_or(RepeaterError::RequestHeadersTooLarge {
                            actual: usize::MAX,
                            limit,
                        })?;
                    running_header_bytes =
                        Self::add_header_budget(running_header_bytes, line_bytes, limit)?;
                    filtered_headers.push(HttpHeader::new(name, value));
                }
            }
        }

        let needs_content_length = !spec.body.is_empty()
            || seen_content_length
            || matches!(
                spec.method,
                HttpMethod::Post | HttpMethod::Put | HttpMethod::Patch
            );

        let content_length_str = if needs_content_length {
            let s = spec.body.len().to_string();
            // "Content-Length: <s_len>\r\n" -> 16 + s.len() + 2
            let cl_line_bytes = 16usize.saturating_add(s.len()).saturating_add(2);
            running_header_bytes =
                Self::add_header_budget(running_header_bytes, cl_line_bytes, limit)?;
            Some(s)
        } else {
            None
        };

        let mut final_headers = Vec::with_capacity(filtered_headers.len() + 3);
        final_headers.push(HttpHeader::new("Host", normalized_host.clone()));
        final_headers.extend(filtered_headers);
        if let Some(cl_val) = content_length_str {
            final_headers.push(HttpHeader::new("Content-Length", cl_val));
        }
        final_headers.push(HttpHeader::new("Connection", "close"));

        // Allocate the exact validated byte budget for the serialized header block
        let mut header_block = String::with_capacity(running_header_bytes);
        header_block.push_str(spec.method.as_str());
        header_block.push(' ');
        header_block.push_str(&request_target);
        header_block.push_str(" HTTP/1.1\r\n");

        for h in &final_headers {
            header_block.push_str(&h.name);
            header_block.push_str(": ");
            header_block.push_str(&h.value);
            header_block.push_str("\r\n");
        }
        header_block.push_str("\r\n");

        debug_assert_eq!(header_block.len(), running_header_bytes);
        if header_block.len() > limit {
            return Err(RepeaterError::RequestHeadersTooLarge {
                actual: header_block.len(),
                limit,
            });
        }

        let total_wire_len = header_block
            .len()
            .checked_add(spec.body.len())
            .ok_or_else(|| {
                RepeaterError::RequestValidation("Total wire request size overflow".to_string())
            })?;
        let mut wire_bytes = Vec::with_capacity(total_wire_len);
        wire_bytes.extend_from_slice(header_block.as_bytes());
        wire_bytes.extend_from_slice(&spec.body);

        let parsed_req = HttpParser::parse_request(&wire_bytes).map_err(|e| {
            RepeaterError::RequestValidation(format!(
                "Serialized request failed parser check: {}",
                e
            ))
        })?;

        let normalized_request = HttpRequest {
            method: spec.method.clone(),
            raw_url: spec.target_url.clone(),
            host: normalized_host,
            path: parsed_url.path.clone(),
            query: parsed_url.query.clone(),
            http_version: parsed_req.http_version,
            headers: final_headers,
            body: spec.body.clone(),
        };

        Ok((wire_bytes, normalized_request))
    }

    fn connect_loopback(
        &self,
        candidates: &[SocketAddr],
        deadline: Instant,
        cancel_flag: Option<&AtomicBool>,
    ) -> Result<(TcpStream, SocketAddr), RepeaterError> {
        let mut last_err = String::new();

        for &addr in candidates {
            if !addr.ip().is_loopback() || !self.scope.is_allowed_ip(&addr.ip()) {
                return Err(RepeaterError::IpOutOfScope(addr.ip().to_string()));
            }

            let remaining = self.check_budget(deadline, cancel_flag)?;
            let attempt_timeout = std::cmp::min(self.config.connect_timeout, remaining);

            match TcpStream::connect_timeout(&addr, attempt_timeout) {
                Ok(stream) => {
                    self.check_budget(deadline, cancel_flag)?;
                    return Ok((stream, addr));
                }
                Err(e) => {
                    self.check_budget(deadline, cancel_flag)?;
                    last_err = format!("{}: {}", addr, e);
                }
            }
        }

        Err(RepeaterError::ConnectionFailed(last_err))
    }

    fn write_all_bounded(
        &self,
        stream: &mut TcpStream,
        mut buf: &[u8],
        deadline: Instant,
        cancel_flag: Option<&AtomicBool>,
    ) -> Result<(), RepeaterError> {
        while !buf.is_empty() {
            let remaining = self.check_budget(deadline, cancel_flag)?;
            let slice_timeout = std::cmp::min(self.config.io_slice_timeout, remaining)
                .max(Duration::from_millis(1));
            let _ = stream.set_write_timeout(Some(slice_timeout));

            match stream.write(buf) {
                Ok(0) => {
                    return Err(RepeaterError::ConnectionFailed(
                        "Socket closed while sending request bytes".to_string(),
                    ));
                }
                Ok(n) => {
                    buf = &buf[n..];
                }
                Err(ref e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    continue;
                }
                Err(e) => {
                    return Err(RepeaterError::ConnectionFailed(format!(
                        "Failed writing to socket: {}",
                        e
                    )));
                }
            }
        }
        Ok(())
    }

    fn read_chunk_bounded(
        &self,
        stream: &mut TcpStream,
        buf: &mut [u8],
        deadline: Instant,
        cancel_flag: Option<&AtomicBool>,
    ) -> Result<usize, RepeaterError> {
        loop {
            let remaining = self.check_budget(deadline, cancel_flag)?;
            let slice_timeout = std::cmp::min(self.config.io_slice_timeout, remaining)
                .max(Duration::from_millis(1));
            let _ = stream.set_read_timeout(Some(slice_timeout));

            match stream.read(buf) {
                Ok(n) => return Ok(n),
                Err(ref e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    continue;
                }
                Err(e) => {
                    return Err(RepeaterError::InvalidResponse(format!(
                        "Socket read error: {}",
                        e
                    )));
                }
            }
        }
    }

    fn find_header_delimiter(bytes: &[u8]) -> Option<(usize, usize)> {
        if let Some(pos) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            return Some((pos, 4));
        }
        if let Some(pos) = bytes.windows(2).position(|w| w == b"\n\n") {
            return Some((pos, 2));
        }
        None
    }

    fn read_http_response(
        &self,
        stream: &mut TcpStream,
        request_method: &HttpMethod,
        deadline: Instant,
        cancel_flag: Option<&AtomicBool>,
    ) -> Result<(HttpResponse, bool), RepeaterError> {
        let mut accum = Vec::with_capacity(4096);
        let mut chunk = [0u8; 8192];
        let mut info_count = 0usize;

        let (parsed_headers, initial_body) = loop {
            let (header_end, sep_len) = loop {
                if let Some(found) = Self::find_header_delimiter(&accum) {
                    if found.0 > self.config.max_header_bytes {
                        return Err(RepeaterError::ResponseHeadersTooLarge {
                            limit: self.config.max_header_bytes,
                        });
                    }
                    break found;
                }

                if accum.len() > self.config.max_header_bytes {
                    return Err(RepeaterError::ResponseHeadersTooLarge {
                        limit: self.config.max_header_bytes,
                    });
                }

                let n = self.read_chunk_bounded(stream, &mut chunk, deadline, cancel_flag)?;
                if n == 0 {
                    if accum.is_empty() {
                        return Err(RepeaterError::InvalidResponse(
                            "Upstream closed connection without sending a response".to_string(),
                        ));
                    } else {
                        return Err(RepeaterError::InvalidResponse(
                            "Upstream closed connection before completing response headers"
                                .to_string(),
                        ));
                    }
                }
                accum.extend_from_slice(&chunk[..n]);
            };

            let header_section = &accum[..header_end + sep_len];
            Self::validate_raw_response_headers(header_section)?;

            let parsed = HttpParser::parse_response(header_section).map_err(|e| match e {
                HttpParseError::ConflictingFraming(msg) => RepeaterError::InvalidResponse(msg),
                other => RepeaterError::InvalidResponse(other.to_string()),
            })?;

            // Validate Transfer-Encoding and Content-Length strictly on every response header block
            let _ = Self::extract_strict_transfer_encoding(&parsed.headers)?;
            let _ = Self::extract_strict_content_length(&parsed.headers)?;

            // Handle 1xx informational status codes per RFC 9112 §6.3
            if (100..200).contains(&parsed.status_code) {
                if parsed.status_code == 101 {
                    return Err(RepeaterError::InvalidResponse(
                        "Unexpected 101 Switching Protocols response".to_string(),
                    ));
                }
                info_count += 1;
                if info_count > MAX_INFORMATIONAL_RESPONSES {
                    return Err(RepeaterError::InvalidResponse(
                        "Exceeded maximum number of 1xx informational responses".to_string(),
                    ));
                }
                accum.drain(..header_end + sep_len);
                continue;
            }

            let remainder = accum[header_end + sep_len..].to_vec();
            break (parsed, remainder);
        };

        let is_chunked = Self::extract_strict_transfer_encoding(&parsed_headers.headers)?;
        let content_length = Self::extract_strict_content_length(&parsed_headers.headers)?;
        if is_chunked && content_length.is_some() {
            return Err(RepeaterError::InvalidResponse(
                "Response contains conflicting Content-Length and Transfer-Encoding headers"
                    .to_string(),
            ));
        }

        // Determine response body framing per RFC 9112 §6.3
        let is_head = *request_method == HttpMethod::Head;
        let is_no_body_status =
            parsed_headers.status_code == 204 || parsed_headers.status_code == 304;

        if is_head || is_no_body_status {
            return Ok((
                HttpResponse {
                    status_code: parsed_headers.status_code,
                    status_text: parsed_headers.status_text,
                    http_version: parsed_headers.http_version,
                    headers: parsed_headers.headers,
                    body: Vec::new(),
                },
                false,
            ));
        }

        let max_body = self.config.max_response_body_bytes;

        let (body, truncated) = if is_chunked {
            self.read_chunked_response_body(stream, &initial_body, max_body, deadline, cancel_flag)?
        } else if let Some(expected_len) = content_length {
            self.read_content_length_response_body(
                stream,
                &initial_body,
                expected_len,
                max_body,
                deadline,
                cancel_flag,
            )?
        } else {
            self.read_eof_response_body(stream, &initial_body, max_body, deadline, cancel_flag)?
        };

        Ok((
            HttpResponse {
                status_code: parsed_headers.status_code,
                status_text: parsed_headers.status_text,
                http_version: parsed_headers.http_version,
                headers: parsed_headers.headers,
                body,
            },
            truncated,
        ))
    }

    fn validate_raw_response_headers(header_section: &[u8]) -> Result<(), RepeaterError> {
        let text = std::str::from_utf8(header_section).map_err(|_| {
            RepeaterError::InvalidResponse("Response headers contain invalid UTF-8".to_string())
        })?;
        let mut lines = text.lines();
        let status_line = lines.next().ok_or_else(|| {
            RepeaterError::InvalidResponse("Empty response status line".to_string())
        })?;

        let mut parts = status_line.split_whitespace();
        let version = parts.next().ok_or_else(|| {
            RepeaterError::InvalidResponse("Missing HTTP version in status line".to_string())
        })?;
        if version != "HTTP/1.1" && version != "HTTP/1.0" {
            return Err(RepeaterError::InvalidResponse(format!(
                "Unsupported HTTP version in response: '{}'",
                version
            )));
        }

        let code_str = parts.next().ok_or_else(|| {
            RepeaterError::InvalidResponse("Missing status code in status line".to_string())
        })?;
        let code: u16 = code_str.parse().map_err(|_| {
            RepeaterError::InvalidResponse(format!("Invalid status code '{}'", code_str))
        })?;
        if !(100..=599).contains(&code) {
            return Err(RepeaterError::InvalidResponse(format!(
                "Out-of-range HTTP status code: {}",
                code
            )));
        }

        for line in lines {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let (name, _) = trimmed.split_once(':').ok_or_else(|| {
                RepeaterError::InvalidResponse(format!(
                    "Malformed response header line: '{}'",
                    trimmed
                ))
            })?;
            Self::validate_header_name(name.trim()).map_err(|_| {
                RepeaterError::InvalidResponse(format!(
                    "Invalid response header name: '{}'",
                    name.trim()
                ))
            })?;
        }

        Ok(())
    }

    /// Strictly validates `Transfer-Encoding` headers in an HTTP/1.1 response.
    /// Only a single `Transfer-Encoding: chunked` header (with exact token `"chunked"`, case-insensitive)
    /// is accepted in Milestone 1.1. Any unknown coding (`xchunked`), multiple codings (`chunked, gzip`,
    /// `gzip, chunked`), parameters, or duplicate `Transfer-Encoding` header lines are rejected.
    fn extract_strict_transfer_encoding(headers: &[HttpHeader]) -> Result<bool, RepeaterError> {
        let mut seen_te = false;
        for h in headers {
            if h.name.eq_ignore_ascii_case("transfer-encoding") {
                if seen_te {
                    return Err(RepeaterError::InvalidResponse(
                        "Duplicate Transfer-Encoding headers are not permitted".to_string(),
                    ));
                }
                seen_te = true;

                let raw_val = h.value.trim();
                if raw_val.is_empty() {
                    return Err(RepeaterError::InvalidResponse(
                        "Empty Transfer-Encoding header in response".to_string(),
                    ));
                }

                // Reject multiple comma-separated transfer codings or parameters
                let mut tokens = raw_val.split(',');
                let first_token = tokens.next().unwrap_or("").trim();
                if tokens.next().is_some() || !first_token.eq_ignore_ascii_case("chunked") {
                    return Err(RepeaterError::InvalidResponse(format!(
                        "Unsupported or ambiguous Transfer-Encoding '{}': only exact 'chunked' is supported",
                        h.value
                    )));
                }
            }
        }
        Ok(seen_te)
    }

    fn extract_strict_content_length(
        headers: &[HttpHeader],
    ) -> Result<Option<usize>, RepeaterError> {
        let mut found: Option<usize> = None;
        for h in headers {
            if h.name.eq_ignore_ascii_case("content-length") {
                let val_trimmed = h.value.trim();
                if val_trimmed.is_empty() || !val_trimmed.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(RepeaterError::InvalidResponse(format!(
                        "Invalid Content-Length header in response: '{}'",
                        h.value
                    )));
                }
                let parsed: usize = val_trimmed.parse().map_err(|_| {
                    RepeaterError::InvalidResponse(format!(
                        "Unparseable Content-Length header in response: '{}'",
                        h.value
                    ))
                })?;
                if let Some(prev) = found {
                    if prev != parsed {
                        return Err(RepeaterError::InvalidResponse(
                            "Conflicting duplicate Content-Length headers in response".to_string(),
                        ));
                    }
                }
                found = Some(parsed);
            }
        }
        Ok(found)
    }

    fn read_chunked_response_body(
        &self,
        stream: &mut TcpStream,
        initial_body: &[u8],
        max_body: usize,
        deadline: Instant,
        cancel_flag: Option<&AtomicBool>,
    ) -> Result<(Vec<u8>, bool), RepeaterError> {
        let mut decoder = BoundedChunkedDecoder::new(max_body, self.config.max_header_bytes);
        if !initial_body.is_empty() {
            decoder.feed(initial_body)?;
        }

        let mut chunk = [0u8; 8192];
        while !decoder.is_complete() {
            if decoder.total_decoded_bytes() > max_body {
                return Ok((decoder.into_decoded(), true));
            }

            let n = self.read_chunk_bounded(stream, &mut chunk, deadline, cancel_flag)?;
            if n == 0 {
                return Err(RepeaterError::InvalidResponse(
                    "Incomplete chunked response: upstream closed connection before terminal chunk"
                        .to_string(),
                ));
            }

            decoder.feed(&chunk[..n])?;

            if decoder.total_decoded_bytes() > max_body {
                return Ok((decoder.into_decoded(), true));
            }
        }

        let truncated = decoder.total_decoded_bytes() > max_body;
        Ok((decoder.into_decoded(), truncated))
    }

    fn read_content_length_response_body(
        &self,
        stream: &mut TcpStream,
        initial_body: &[u8],
        expected_len: usize,
        max_body: usize,
        deadline: Instant,
        cancel_flag: Option<&AtomicBool>,
    ) -> Result<(Vec<u8>, bool), RepeaterError> {
        if expected_len == 0 {
            return Ok((Vec::new(), false));
        }

        let target_read = std::cmp::min(expected_len, max_body);
        let mut body = Vec::with_capacity(target_read);
        let mut total_received = initial_body.len();

        let initial_take = std::cmp::min(initial_body.len(), target_read);
        body.extend_from_slice(&initial_body[..initial_take]);

        if expected_len > max_body && total_received >= max_body {
            return Ok((body, true));
        }

        let mut chunk = [0u8; 8192];
        while total_received < expected_len {
            let remaining_needed = if expected_len > max_body {
                max_body.saturating_sub(total_received)
            } else {
                expected_len - total_received
            };

            if remaining_needed == 0 {
                return Ok((body, true));
            }

            let to_read = std::cmp::min(chunk.len(), remaining_needed);
            let n =
                self.read_chunk_bounded(stream, &mut chunk[..to_read], deadline, cancel_flag)?;
            if n == 0 {
                return Err(RepeaterError::InvalidResponse(format!(
                    "Incomplete response body: Content-Length expected {} bytes, received {}",
                    expected_len, total_received
                )));
            }

            if body.len() < max_body {
                let can_take = std::cmp::min(n, max_body - body.len());
                body.extend_from_slice(&chunk[..can_take]);
            }
            total_received += n;

            if expected_len > max_body && total_received >= max_body {
                return Ok((body, true));
            }
        }

        Ok((body, expected_len > max_body))
    }

    fn read_eof_response_body(
        &self,
        stream: &mut TcpStream,
        initial_body: &[u8],
        max_body: usize,
        deadline: Instant,
        cancel_flag: Option<&AtomicBool>,
    ) -> Result<(Vec<u8>, bool), RepeaterError> {
        let mut body = Vec::new();
        if initial_body.len() > max_body {
            body.extend_from_slice(&initial_body[..max_body]);
            return Ok((body, true));
        }
        body.extend_from_slice(initial_body);

        let mut chunk = [0u8; 8192];
        loop {
            let n = self.read_chunk_bounded(stream, &mut chunk, deadline, cancel_flag)?;
            if n == 0 {
                break;
            }
            if body.len() + n > max_body {
                let can_take = max_body - body.len();
                body.extend_from_slice(&chunk[..can_take]);
                return Ok((body, true));
            }
            body.extend_from_slice(&chunk[..n]);
        }

        Ok((body, false))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_validation_allows_loopback_targets() {
        let scope = AuditScope::default();

        let u1 = HttpRepeaterEngine::parse_and_validate_url(
            "http://127.0.0.1:8989/api/status?x=1",
            &scope,
        )
        .unwrap();
        assert_eq!(u1.canonical_host, "127.0.0.1");
        assert_eq!(u1.port, 8989);
        assert_eq!(u1.path, "/api/status");
        assert_eq!(u1.query, "x=1");
        assert_eq!(u1.normalized_host_header(), "127.0.0.1:8989");

        let u2 =
            HttpRepeaterEngine::parse_and_validate_url("http://localhost/health", &scope).unwrap();
        assert_eq!(u2.canonical_host, "localhost");
        assert_eq!(u2.port, 80);
        assert_eq!(u2.normalized_host_header(), "localhost");

        let u3 = HttpRepeaterEngine::parse_and_validate_url("http://[::1]:9000/v1/test", &scope)
            .unwrap();
        assert_eq!(u3.canonical_host, "::1");
        assert_eq!(u3.port, 9000);
        assert_eq!(u3.normalized_host_header(), "[::1]:9000");
    }

    #[test]
    fn test_url_validation_rejects_invalid_and_unsafe_urls() {
        let scope = AuditScope::default();

        assert!(matches!(
            HttpRepeaterEngine::parse_and_validate_url("https://127.0.0.1:8989/api", &scope),
            Err(RepeaterError::UnsupportedScheme(s)) if s == "https"
        ));

        assert!(matches!(
            HttpRepeaterEngine::parse_and_validate_url("ftp://127.0.0.1/file", &scope),
            Err(RepeaterError::UnsupportedScheme(s)) if s == "ftp"
        ));

        assert!(matches!(
            HttpRepeaterEngine::parse_and_validate_url("/api/status", &scope),
            Err(RepeaterError::InvalidUrl(_))
        ));

        assert!(matches!(
            HttpRepeaterEngine::parse_and_validate_url(
                "http://admin:secret@127.0.0.1:8080/",
                &scope
            ),
            Err(RepeaterError::InvalidUrl(_))
        ));

        assert!(matches!(
            HttpRepeaterEngine::parse_and_validate_url("http://127.0.0.1:8080/path#frag", &scope),
            Err(RepeaterError::InvalidUrl(_))
        ));

        assert!(matches!(
            HttpRepeaterEngine::parse_and_validate_url("http://127.0.0.1:0/api", &scope),
            Err(RepeaterError::InvalidUrl(_))
        ));
        assert!(matches!(
            HttpRepeaterEngine::parse_and_validate_url("http://127.0.0.1:70000/api", &scope),
            Err(RepeaterError::InvalidUrl(_))
        ));

        let mut custom_scope = AuditScope::default();
        custom_scope.add_host("example.com");
        assert!(matches!(
            HttpRepeaterEngine::parse_and_validate_url("http://example.com/api", &custom_scope),
            Err(RepeaterError::HostOutOfScope(_))
        ));
    }

    #[test]
    fn test_header_and_framing_security_validations() {
        let engine = HttpRepeaterEngine::default();

        let crlf_spec = RepeaterRequestSpec::new(HttpMethod::Get, "http://127.0.0.1:8989/api")
            .with_header("X-Test", "ok\r\nX-Injected: pwned");
        assert!(matches!(
            engine.execute(&crlf_spec, None),
            Err(RepeaterError::InvalidHeader(_))
        ));

        let bad_name_spec = RepeaterRequestSpec::new(HttpMethod::Get, "http://127.0.0.1:8989/api")
            .with_header("Bad Name", "val");
        assert!(matches!(
            engine.execute(&bad_name_spec, None),
            Err(RepeaterError::InvalidHeader(_))
        ));

        let dup_host_spec = RepeaterRequestSpec::new(HttpMethod::Get, "http://127.0.0.1:8989/api")
            .with_header("Host", "127.0.0.1:8989")
            .with_header("Host", "127.0.0.1:8989");
        assert!(matches!(
            engine.execute(&dup_host_spec, None),
            Err(RepeaterError::RequestValidation(_))
        ));

        let mismatch_host_spec =
            RepeaterRequestSpec::new(HttpMethod::Get, "http://127.0.0.1:8989/api")
                .with_header("Host", "localhost:8989");
        assert!(matches!(
            engine.execute(&mismatch_host_spec, None),
            Err(RepeaterError::HostHeaderMismatch { .. })
        ));

        let dup_cl_spec = RepeaterRequestSpec::new(HttpMethod::Post, "http://127.0.0.1:8989/api")
            .with_header("Content-Length", "4")
            .with_header("Content-Length", "4")
            .with_body(b"test".to_vec());
        assert!(matches!(
            engine.execute(&dup_cl_spec, None),
            Err(RepeaterError::RequestValidation(_))
        ));

        let te_spec = RepeaterRequestSpec::new(HttpMethod::Post, "http://127.0.0.1:8989/api")
            .with_header("Transfer-Encoding", "chunked")
            .with_body(b"test".to_vec());
        assert!(matches!(
            engine.execute(&te_spec, None),
            Err(RepeaterError::RequestValidation(_))
        ));

        let expect_spec = RepeaterRequestSpec::new(HttpMethod::Post, "http://127.0.0.1:8989/api")
            .with_header("Expect", "100-continue")
            .with_body(b"test".to_vec());
        assert!(matches!(
            engine.execute(&expect_spec, None),
            Err(RepeaterError::RequestValidation(_))
        ));

        let connect_spec = RepeaterRequestSpec::new(HttpMethod::Connect, "http://127.0.0.1:8989/");
        assert!(matches!(
            engine.execute(&connect_spec, None),
            Err(RepeaterError::UnsupportedMethod(_))
        ));
        let trace_spec = RepeaterRequestSpec::new(
            HttpMethod::Custom("TRACE".to_string()),
            "http://127.0.0.1:8989/",
        );
        assert!(matches!(
            engine.execute(&trace_spec, None),
            Err(RepeaterError::UnsupportedMethod(_))
        ));
    }

    #[test]
    fn test_strict_transfer_encoding_validator() {
        // Valid single chunked coding
        let ok_headers = vec![HttpHeader::new("Transfer-Encoding", "chunked")];
        assert_eq!(
            HttpRepeaterEngine::extract_strict_transfer_encoding(&ok_headers),
            Ok(true)
        );

        // Absent Transfer-Encoding
        let empty_headers = vec![HttpHeader::new("Content-Type", "text/plain")];
        assert_eq!(
            HttpRepeaterEngine::extract_strict_transfer_encoding(&empty_headers),
            Ok(false)
        );

        // Invalid/ambiguous transfer codings rejected
        for invalid in [
            vec![HttpHeader::new("Transfer-Encoding", "xchunked")],
            vec![HttpHeader::new("Transfer-Encoding", "chunked, gzip")],
            vec![HttpHeader::new("Transfer-Encoding", "gzip, chunked")],
            vec![HttpHeader::new("Transfer-Encoding", "gzip")],
            vec![HttpHeader::new("Transfer-Encoding", "")],
            vec![
                HttpHeader::new("Transfer-Encoding", "chunked"),
                HttpHeader::new("Transfer-Encoding", "chunked"),
            ],
            vec![
                HttpHeader::new("Transfer-Encoding", "gzip"),
                HttpHeader::new("Transfer-Encoding", "chunked"),
            ],
        ] {
            assert!(
                matches!(
                    HttpRepeaterEngine::extract_strict_transfer_encoding(&invalid),
                    Err(RepeaterError::InvalidResponse(_))
                ),
                "Expected InvalidResponse for {:?}",
                invalid
            );
        }
    }

    #[test]
    fn test_bounded_chunked_decoder_limits_metadata_and_trailers() {
        // 1. Oversized chunk-size line without newline rejected immediately
        let mut dec_line = BoundedChunkedDecoder::new(1024, 256);
        let huge_line = vec![b'0'; 300];
        assert!(matches!(
            dec_line.feed(&huge_line),
            Err(RepeaterError::InvalidResponse(_))
        ));

        // 2. Oversized chunk extension rejected
        let mut dec_ext = BoundedChunkedDecoder::new(1024, 4096);
        let mut ext_line = b"4;ext=".to_vec();
        ext_line.extend_from_slice(&[b'a'; MAX_CHUNK_EXTENSION_BYTES + 10]);
        ext_line.extend_from_slice(b"\r\nWiki\r\n0\r\n\r\n");
        assert!(matches!(
            dec_ext.feed(&ext_line),
            Err(RepeaterError::InvalidResponse(_))
        ));

        // 3. Single trailer line exceeding limit rejected
        let mut dec_trl = BoundedChunkedDecoder::new(1024, 128);
        let mut bad_trailer = b"0\r\nX-Long: ".to_vec();
        bad_trailer.extend_from_slice(&[b'v'; 200]);
        bad_trailer.extend_from_slice(b"\r\n\r\n");
        assert!(matches!(
            dec_trl.feed(&bad_trailer),
            Err(RepeaterError::InvalidResponse(_))
        ));

        // 4. Aggregate trailers exceeding max_header_bytes rejected
        let mut dec_agg = BoundedChunkedDecoder::new(1024, 100);
        let agg_trailers =
            b"0\r\nX-T1: 123456789012345678901234567890\r\nX-T2: 123456789012345678901234567890\r\nX-T3: 123456789012345678901234567890\r\n\r\n";
        assert!(matches!(
            dec_agg.feed(agg_trailers),
            Err(RepeaterError::InvalidResponse(_))
        ));
    }

    #[test]
    fn test_incremental_outgoing_header_budget_boundaries() {
        let scope = AuditScope::default();
        let url = "http://127.0.0.1:8989/a";
        let parsed = HttpRepeaterEngine::parse_and_validate_url(url, &scope).unwrap();

        // Base bytes for GET /a HTTP/1.1\r\n (17) + Host: 127.0.0.1:8989\r\n (22) + Connection: close\r\n (19) + \r\n (2) = 60 bytes
        // Adding header "X-Pad: 1234\r\n" adds 5 + 2 + 4 + 2 = 13 bytes -> total = 73 bytes.
        let spec = RepeaterRequestSpec::new(HttpMethod::Get, url).with_header("X-Pad", "1234");

        // Exact boundary (73 bytes) succeeds
        let exact_engine = HttpRepeaterEngine::new(
            Arc::new(scope.clone()),
            RepeaterConfig {
                max_header_bytes: 73,
                ..RepeaterConfig::default()
            },
        );
        let (wire, _) = exact_engine
            .build_and_validate_wire_request(&spec, &parsed)
            .expect("Exact header limit should succeed");
        assert_eq!(wire.len(), 73);

        // Just below limit (limit = 74, actual = 73) succeeds
        let below_engine = HttpRepeaterEngine::new(
            Arc::new(scope.clone()),
            RepeaterConfig {
                max_header_bytes: 74,
                ..RepeaterConfig::default()
            },
        );
        assert!(below_engine
            .build_and_validate_wire_request(&spec, &parsed)
            .is_ok());

        // 1 byte over limit (limit = 72, actual = 73) fails with RequestHeadersTooLarge
        let over_engine = HttpRepeaterEngine::new(
            Arc::new(scope),
            RepeaterConfig {
                max_header_bytes: 72,
                ..RepeaterConfig::default()
            },
        );
        assert_eq!(
            over_engine.build_and_validate_wire_request(&spec, &parsed),
            Err(RepeaterError::RequestHeadersTooLarge {
                actual: 73,
                limit: 72
            })
        );
    }
}
