use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;

use thiserror::Error;

use kaska_http::models::{HttpMethod, HttpRequest, HttpResponse};
use kaska_http::repeater::{
    HttpRepeaterEngine, RepeaterConfig, RepeaterError, RepeaterExecutionResult, RepeaterRequestSpec,
};
use kaska_http::scope::AuditScope;

/// Default UTF-8 or formatted byte size rendered into `RepeaterViewState::response_body_preview`
/// so that full 2 MiB HTTP response buffers are never cloned onto the UI event loop by default.
pub const DEFAULT_MAX_BODY_PREVIEW_BYTES: usize = 64 * 1024;

/// Minimum allowed byte budget for `format_response_body_preview` (256 bytes).
pub const MIN_BODY_PREVIEW_BYTES: usize = 256;

/// Defensive hard ceiling for `format_response_body_preview` (256 KiB) so callers cannot
/// accidentally disable the preview cap.
pub const MAX_BODY_PREVIEW_BYTES: usize = 256 * 1024;

/// Maximum length of the HTTP method token accepted by the adapter before validation.
pub const MAX_INPUT_METHOD_BYTES: usize = 16;

/// Maximum raw target URL input length accepted before attempting engine parsing.
pub const MAX_INPUT_URL_BYTES: usize = 8 * 1024;

/// Slint-independent user input model for composing an HTTP Repeater request.
///
/// Note: In Milestone 1.2B-1, editable request bodies are restricted to valid UTF-8 strings
/// (`body_utf8`). Arbitrary raw binary request body composition is out of scope for this increment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepeaterUiInput {
    pub method: String,
    pub target_url: String,
    pub headers_raw: String,
    pub body_utf8: String,
}

impl Default for RepeaterUiInput {
    fn default() -> Self {
        Self {
            method: "GET".to_string(),
            target_url: "http://127.0.0.1:8989/api/status".to_string(),
            headers_raw:
                "Host: 127.0.0.1:8989\nUser-Agent: Kaska-Repeater/0.1\nAccept: application/json"
                    .to_string(),
            body_utf8: String::new(),
        }
    }
}

impl RepeaterUiInput {
    pub fn new(
        method: impl Into<String>,
        target_url: impl Into<String>,
        headers_raw: impl Into<String>,
        body_utf8: impl Into<String>,
    ) -> Self {
        Self {
            method: method.into(),
            target_url: target_url.into(),
            headers_raw: headers_raw.into(),
            body_utf8: body_utf8.into(),
        }
    }

    /// Strict whitelist parser for HTTP methods supported by the Desktop Repeater adapter.
    /// Enforces `MAX_INPUT_METHOD_BYTES` before allocating or uppercasing, and rejects empty
    /// values, `CONNECT`, `TRACE`, and any unknown/custom token so that `HttpMethod::Custom`
    /// never crosses the adapter boundary.
    pub fn parse_supported_method(raw_method: &str) -> Result<HttpMethod, RepeaterAdapterError> {
        let trimmed = raw_method.trim();
        if trimmed.is_empty() {
            return Err(RepeaterAdapterError::EmptyMethod);
        }
        if trimmed.len() > MAX_INPUT_METHOD_BYTES {
            return Err(RepeaterAdapterError::MethodTooLarge {
                actual: trimmed.len(),
                limit: MAX_INPUT_METHOD_BYTES,
            });
        }

        match trimmed.to_ascii_uppercase().as_str() {
            "GET" => Ok(HttpMethod::Get),
            "POST" => Ok(HttpMethod::Post),
            "PUT" => Ok(HttpMethod::Put),
            "DELETE" => Ok(HttpMethod::Delete),
            "PATCH" => Ok(HttpMethod::Patch),
            "HEAD" => Ok(HttpMethod::Head),
            "OPTIONS" => Ok(HttpMethod::Options),
            other => Err(RepeaterAdapterError::UnsupportedMethod(other.to_string())),
        }
    }

    /// Validates raw input byte boundaries (method, URL, headers, and body) prior to any
    /// cloning or header/body allocation.
    pub fn validate_bounds(&self, config: &RepeaterConfig) -> Result<(), RepeaterAdapterError> {
        let method_trimmed = self.method.trim();
        if method_trimmed.is_empty() {
            return Err(RepeaterAdapterError::EmptyMethod);
        }
        if method_trimmed.len() > MAX_INPUT_METHOD_BYTES {
            return Err(RepeaterAdapterError::MethodTooLarge {
                actual: method_trimmed.len(),
                limit: MAX_INPUT_METHOD_BYTES,
            });
        }

        let url_trimmed = self.target_url.trim();
        if url_trimmed.is_empty() {
            return Err(RepeaterAdapterError::EmptyTargetUrl);
        }
        if url_trimmed.len() > MAX_INPUT_URL_BYTES {
            return Err(RepeaterAdapterError::TargetUrlTooLarge {
                actual: url_trimmed.len(),
                limit: MAX_INPUT_URL_BYTES,
            });
        }

        if self.headers_raw.len() > config.max_header_bytes {
            return Err(RepeaterAdapterError::InputHeadersTooLarge {
                actual: self.headers_raw.len(),
                limit: config.max_header_bytes,
            });
        }

        if self.body_utf8.len() > config.max_request_body_bytes {
            return Err(RepeaterAdapterError::InputBodyTooLarge {
                actual: self.body_utf8.len(),
                limit: config.max_request_body_bytes,
            });
        }

        Ok(())
    }

    /// Validates input boundaries prior to large allocations and builds a `RepeaterRequestSpec`
    /// using the strict header parser from `kaska_http::repeater::RepeaterRequestSpec`.
    /// Deep validation of URL syntax, `Host` matching, loopback scope, and wire framing remains
    /// under the sole authority of `HttpRepeaterEngine`.
    pub fn to_request_spec(
        &self,
        config: &RepeaterConfig,
    ) -> Result<RepeaterRequestSpec, RepeaterAdapterError> {
        self.validate_bounds(config)?;
        let method = Self::parse_supported_method(&self.method)?;
        let url_trimmed = self.target_url.trim();

        let headers = RepeaterRequestSpec::parse_header_block(&self.headers_raw)
            .map_err(RepeaterAdapterError::Engine)?;

        Ok(RepeaterRequestSpec {
            method,
            target_url: url_trimmed.to_string(),
            headers,
            body: self.body_utf8.as_bytes().to_vec(),
        })
    }
}

/// Typed errors produced by the Desktop Repeater adapter and coordinator.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RepeaterAdapterError {
    #[error("HTTP method cannot be empty")]
    EmptyMethod,

    #[error("HTTP method token exceeds maximum length ({actual} bytes > {limit} bytes)")]
    MethodTooLarge { actual: usize, limit: usize },

    #[error("HTTP method '{0}' is not permitted in Repeater (allowed: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS)")]
    UnsupportedMethod(String),

    #[error("Target URL cannot be empty")]
    EmptyTargetUrl,

    #[error("Target URL exceeds maximum input length ({actual} bytes > {limit} bytes)")]
    TargetUrlTooLarge { actual: usize, limit: usize },

    #[error("Raw request headers exceed maximum input limit ({actual} bytes > {limit} bytes)")]
    InputHeadersTooLarge { actual: usize, limit: usize },

    #[error("Request body exceeds maximum input limit ({actual} bytes > {limit} bytes)")]
    InputBodyTooLarge { actual: usize, limit: usize },

    #[error("Another Repeater request is already in flight")]
    AlreadyRunning,

    #[error("Failed to spawn Repeater background worker thread: {0}")]
    WorkerSpawnFailed(String),

    #[error("Repeater background worker terminated unexpectedly")]
    WorkerPanicked,

    #[error("Repeater execution cancelled")]
    Cancelled,

    #[error("{0}")]
    Engine(#[from] RepeaterError),
}

impl RepeaterAdapterError {
    /// Returns an explicit, deterministic, user-safe message mapped by error category.
    ///
    /// Security invariant (M1): Never echoes raw user-supplied header lines, header values,
    /// `Authorization` / `Cookie` tokens, URLs with embedded credentials/queries, request bodies,
    /// or low-level payload fragments.
    pub fn safe_display_message(&self) -> String {
        match self {
            RepeaterAdapterError::EmptyMethod => "HTTP method cannot be empty.".to_string(),
            RepeaterAdapterError::MethodTooLarge { actual, limit } => format!(
                "HTTP method token exceeds maximum length ({} bytes > {} bytes).",
                actual, limit
            ),
            RepeaterAdapterError::UnsupportedMethod(_) => {
                "Unsupported HTTP method. Allowed methods: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS."
                    .to_string()
            }
            RepeaterAdapterError::EmptyTargetUrl => "Target URL cannot be empty.".to_string(),
            RepeaterAdapterError::TargetUrlTooLarge { actual, limit } => format!(
                "Target URL exceeds maximum input length ({} bytes > {} bytes).",
                actual, limit
            ),
            RepeaterAdapterError::InputHeadersTooLarge { actual, limit } => format!(
                "Request headers exceed maximum input size ({} bytes > {} bytes).",
                actual, limit
            ),
            RepeaterAdapterError::InputBodyTooLarge { actual, limit } => format!(
                "Request body exceeds maximum input size ({} bytes > {} bytes).",
                actual, limit
            ),
            RepeaterAdapterError::AlreadyRunning => {
                "Another Repeater request is already running.".to_string()
            }
            RepeaterAdapterError::WorkerSpawnFailed(_) => {
                "Failed to start background worker thread for Repeater execution.".to_string()
            }
            RepeaterAdapterError::WorkerPanicked => {
                "Repeater background worker terminated unexpectedly.".to_string()
            }
            RepeaterAdapterError::Cancelled => "Repeater execution cancelled.".to_string(),
            RepeaterAdapterError::Engine(engine_err) => Self::safe_engine_error_message(engine_err),
        }
    }

    fn safe_engine_error_message(err: &RepeaterError) -> String {
        match err {
            RepeaterError::InvalidUrl(_) => {
                "Invalid target URL. Expected an http:// loopback URL without credentials, fragments, or control characters."
                    .to_string()
            }
            RepeaterError::UnsupportedScheme(_) => {
                "Unsupported URL scheme: only http:// is permitted in Repeater.".to_string()
            }
            RepeaterError::UnsupportedMethod(_) => {
                "Unsupported HTTP method. Allowed methods: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS."
                    .to_string()
            }
            RepeaterError::HostOutOfScope(_) => {
                "Target host is outside the authorized loopback scope (allowed: 127.0.0.1, localhost, [::1])."
                    .to_string()
            }
            RepeaterError::HostHeaderMismatch { .. } => {
                "Host header does not match the target URL authority and port.".to_string()
            }
            RepeaterError::IpOutOfScope(_) => {
                "Resolved target IP address is outside the authorized loopback scope.".to_string()
            }
            RepeaterError::InvalidHeader(_) => {
                "Invalid HTTP header syntax or forbidden characters. Use 'Name: Value' per line."
                    .to_string()
            }
            RepeaterError::RequestValidation(_) => {
                "HTTP request validation failed due to invalid or disallowed protocol headers."
                    .to_string()
            }
            RepeaterError::RequestHeadersTooLarge { actual, limit } => format!(
                "Serialized request headers exceed maximum size limit ({} bytes > {} bytes).",
                actual, limit
            ),
            RepeaterError::RequestBodyTooLarge { actual, limit } => format!(
                "Request body exceeds maximum size limit ({} bytes > {} bytes).",
                actual, limit
            ),
            RepeaterError::ResponseHeadersTooLarge { limit } => format!(
                "Upstream response headers exceed maximum size limit ({} bytes).",
                limit
            ),
            RepeaterError::ConnectionFailed(_) => {
                "Connection to loopback target failed or was refused.".to_string()
            }
            RepeaterError::InvalidResponse(_) => {
                "Received a malformed or incomplete HTTP/1.1 response from the target.".to_string()
            }
            RepeaterError::Timeout(ms) => {
                format!("Repeater execution timed out after {} ms.", ms)
            }
            RepeaterError::Cancelled => "Repeater execution cancelled.".to_string(),
        }
    }
}

/// Lifecycle phase of the Repeater state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepeaterLifecycle {
    Idle,
    Running,
    Completed,
    Failed,
    Cancelled,
}

/// Formatted representation of an HTTP response body for safe text presentation in the UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormattedBodyPreview {
    /// Safe UTF-8 text preview whose final UTF-8 byte length is strictly `<= clamp_preview_limit(preview_limit_bytes)`.
    pub preview_text: String,
    /// Total byte length of the response body returned by `HttpRepeaterEngine`.
    pub received_body_bytes: usize,
    /// `true` if the payload contained invalid UTF-8 sequences or binary control characters.
    pub is_binary: bool,
    /// `true` if the engine truncated the HTTP response stream at `max_response_body_bytes` (e.g. 2 MiB).
    pub http_body_truncated: bool,
    /// `true` if the text preview was clipped to fit within the preview byte budget.
    pub preview_truncated: bool,
}

/// Clamps any caller-supplied preview byte budget into `[MIN_BODY_PREVIEW_BYTES, MAX_BODY_PREVIEW_BYTES]`.
pub fn clamp_preview_limit(preview_limit_bytes: usize) -> usize {
    preview_limit_bytes.clamp(MIN_BODY_PREVIEW_BYTES, MAX_BODY_PREVIEW_BYTES)
}

/// Inspects raw response bytes and produces a bounded, UI-safe text preview without
/// silently disguising binary data as lossless UTF-8.
///
/// Invariant (M5): `preview_text.as_bytes().len() <= clamp_preview_limit(preview_limit_bytes)`
/// always holds, accounting for headers, hex/ASCII lines, and truncation notices.
pub fn format_response_body_preview(
    raw_body: &[u8],
    http_body_truncated: bool,
    preview_limit_bytes: usize,
) -> FormattedBodyPreview {
    let received_body_bytes = raw_body.len();
    let effective_limit = clamp_preview_limit(preview_limit_bytes);
    let is_binary = is_binary_or_unsafe_control_payload(raw_body);

    if !is_binary {
        let valid_str = std::str::from_utf8(raw_body).unwrap_or("");
        if valid_str.len() <= effective_limit {
            return FormattedBodyPreview {
                preview_text: valid_str.to_string(),
                received_body_bytes,
                is_binary: false,
                http_body_truncated,
                preview_truncated: false,
            };
        }

        // Reserve space for the truncation footer so `preview_text.len() <= effective_limit`.
        // First compute an upper-bound footer using `effective_limit` as the byte count digit width,
        // then slice on a valid UTF-8 boundary and format the exact footer.
        let sample_footer = format_utf8_truncation_footer(
            effective_limit,
            received_body_bytes,
            http_body_truncated,
        );
        let max_body_slice = effective_limit.saturating_sub(sample_footer.len());
        let boundary = floor_utf8_char_boundary(valid_str, max_body_slice);
        let exact_footer =
            format_utf8_truncation_footer(boundary, received_body_bytes, http_body_truncated);

        let mut preview_text = String::with_capacity(boundary + exact_footer.len());
        preview_text.push_str(&valid_str[..boundary]);
        preview_text.push_str(&exact_footer);
        debug_assert!(preview_text.len() <= effective_limit);

        return FormattedBodyPreview {
            preview_text,
            received_body_bytes,
            is_binary: false,
            http_body_truncated,
            preview_truncated: true,
        };
    }

    // Binary or control-character payload: each 16-byte row formats to exactly 75 ASCII bytes:
    //   "{:06x}: " (8) + 16 * "{:02x} " (48) + " |" (2) + up to 16 ASCII chars + "|\n" (2) = 76 bytes max.
    const MAX_HEX_LINE_BYTES: usize = 76;

    // Reserve worst-case header size first to determine how many full 16-byte rows fit in `effective_limit`.
    let worst_case_header = format_binary_preview_header(
        received_body_bytes,
        http_body_truncated,
        true,
        received_body_bytes,
    );
    let available_for_rows = effective_limit.saturating_sub(worst_case_header.len());
    let max_rows = available_for_rows / MAX_HEX_LINE_BYTES;
    let max_raw_bytes_to_render = max_rows.saturating_mul(16);

    let slice_len = raw_body.len().min(max_raw_bytes_to_render);
    let preview_truncated = raw_body.len() > slice_len;

    let header = format_binary_preview_header(
        received_body_bytes,
        http_body_truncated,
        preview_truncated,
        slice_len,
    );

    let mut out = String::with_capacity(header.len() + (slice_len / 16 + 1) * MAX_HEX_LINE_BYTES);
    out.push_str(&header);

    for (chunk_idx, chunk) in raw_body[..slice_len].chunks(16).enumerate() {
        let mut line = String::with_capacity(MAX_HEX_LINE_BYTES);
        let offset = chunk_idx * 16;
        line.push_str(&format!("{:06x}: ", offset));
        for i in 0..16 {
            if i < chunk.len() {
                line.push_str(&format!("{:02x} ", chunk[i]));
            } else {
                line.push_str("   ");
            }
        }
        line.push_str(" |");
        for &b in chunk {
            if (0x20..=0x7E).contains(&b) {
                line.push(b as char);
            } else {
                line.push('.');
            }
        }
        line.push_str("|\n");

        if out.len() + line.len() > effective_limit {
            break;
        }
        out.push_str(&line);
    }

    debug_assert!(out.len() <= effective_limit);

    FormattedBodyPreview {
        preview_text: out,
        received_body_bytes,
        is_binary: true,
        http_body_truncated,
        preview_truncated,
    }
}

fn format_utf8_truncation_footer(
    shown_bytes: usize,
    received_body_bytes: usize,
    http_body_truncated: bool,
) -> String {
    format!(
        "\n\n[Preview truncated at {} bytes of {} bytes received{}]",
        shown_bytes,
        received_body_bytes,
        if http_body_truncated {
            "; HTTP response also truncated at engine limit"
        } else {
            ""
        }
    )
}

fn format_binary_preview_header(
    received_body_bytes: usize,
    http_body_truncated: bool,
    preview_truncated: bool,
    shown_bytes: usize,
) -> String {
    format!(
        "[Binary / non-textual payload ({} bytes received{}{}) — lossy hex/ASCII preview]\n",
        received_body_bytes,
        if http_body_truncated {
            ", HTTP stream truncated at engine limit"
        } else {
            ""
        },
        if preview_truncated {
            format!(", showing first {} bytes", shown_bytes)
        } else {
            String::new()
        }
    )
}

fn is_binary_or_unsafe_control_payload(bytes: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return true;
    };
    text.bytes()
        .any(|b| (b < 0x20 && b != b'\r' && b != b'\n' && b != b'\t') || b == 0x7F)
}

fn floor_utf8_char_boundary(s: &str, max_bytes: usize) -> usize {
    if max_bytes >= s.len() {
        return s.len();
    }
    let mut idx = max_bytes;
    while idx > 0 && !s.is_char_boundary(idx) {
        idx -= 1;
    }
    idx
}

/// Independent state model for the Repeater view, completely isolated from `SharedTrafficStore`
/// and decoupled from provisional Slint widget property names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepeaterViewState {
    pub input: RepeaterUiInput,
    pub lifecycle: RepeaterLifecycle,
    pub active_request_id: u64,
    pub status_code: Option<u16>,
    pub status_text: String,
    pub duration_ms: Option<u64>,
    pub sent_request_headers: String,
    pub response_headers: String,
    pub response_body_preview: String,
    pub received_body_bytes: usize,
    pub body_is_binary: bool,
    pub http_body_truncated: bool,
    pub preview_truncated: bool,
    pub last_error: Option<RepeaterAdapterError>,
    pub error_message: String,
    pub preview_limit_bytes: usize,
}

impl Default for RepeaterViewState {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_BODY_PREVIEW_BYTES)
    }
}

impl RepeaterViewState {
    pub fn new(preview_limit_bytes: usize) -> Self {
        Self {
            input: RepeaterUiInput::default(),
            lifecycle: RepeaterLifecycle::Idle,
            active_request_id: 0,
            status_code: None,
            status_text: String::new(),
            duration_ms: None,
            sent_request_headers: String::new(),
            response_headers: String::new(),
            response_body_preview: String::new(),
            received_body_bytes: 0,
            body_is_binary: false,
            http_body_truncated: false,
            preview_truncated: false,
            last_error: None,
            error_message: String::new(),
            preview_limit_bytes: clamp_preview_limit(preview_limit_bytes),
        }
    }

    /// Strict state-machine transition rules (M2):
    /// - Any event with `request_id == 0` or `request_id < self.active_request_id` is rejected (`false`).
    /// - `RepeaterEvent::Started { request_id }` is accepted ONLY when `request_id > self.active_request_id`
    ///   (a brand-new request) and transitions the state to `Running`. A duplicate `Started` for an
    ///   already-active or already-terminated `request_id` is rejected (`false`).
    /// - Terminal events (`Completed`, `Failed`, `Cancelled`) are accepted ONLY when
    ///   `request_id == self.active_request_id` AND `self.lifecycle == RepeaterLifecycle::Running`.
    ///   Once an execution has reached a terminal state (`Completed`, `Failed`, or `Cancelled`), any
    ///   subsequent or duplicate event for the same `request_id` is rejected (`false`).
    pub fn apply_event(&mut self, event: &RepeaterEvent) -> bool {
        let event_id = event.request_id();
        if event_id == 0 || event_id < self.active_request_id {
            return false;
        }

        match event {
            RepeaterEvent::Started { request_id } => {
                if *request_id <= self.active_request_id {
                    return false;
                }
                self.active_request_id = *request_id;
                self.lifecycle = RepeaterLifecycle::Running;
                self.status_code = None;
                self.status_text.clear();
                self.duration_ms = None;
                self.sent_request_headers.clear();
                self.response_headers.clear();
                self.response_body_preview.clear();
                self.received_body_bytes = 0;
                self.body_is_binary = false;
                self.http_body_truncated = false;
                self.preview_truncated = false;
                self.last_error = None;
                self.error_message.clear();
                true
            }
            RepeaterEvent::Completed { request_id, result } => {
                if *request_id != self.active_request_id
                    || self.lifecycle != RepeaterLifecycle::Running
                {
                    return false;
                }
                self.lifecycle = RepeaterLifecycle::Completed;
                self.status_code = Some(result.response.status_code);
                self.status_text = result.response.status_text.clone();
                self.duration_ms = Some(result.duration_ms);
                self.sent_request_headers = format_wire_request_headers(&result.request);
                self.response_headers = format_wire_response_headers(&result.response);

                let formatted = format_response_body_preview(
                    &result.response.body,
                    result.response_body_truncated,
                    self.preview_limit_bytes,
                );
                self.response_body_preview = formatted.preview_text;
                self.received_body_bytes = formatted.received_body_bytes;
                self.body_is_binary = formatted.is_binary;
                self.http_body_truncated = formatted.http_body_truncated;
                self.preview_truncated = formatted.preview_truncated;
                self.last_error = None;
                self.error_message.clear();
                true
            }
            RepeaterEvent::Failed { request_id, error } => {
                if *request_id != self.active_request_id
                    || self.lifecycle != RepeaterLifecycle::Running
                {
                    return false;
                }
                self.lifecycle = RepeaterLifecycle::Failed;
                self.status_code = None;
                self.status_text.clear();
                self.duration_ms = None;
                self.response_headers.clear();
                self.response_body_preview.clear();
                self.received_body_bytes = 0;
                self.body_is_binary = false;
                self.http_body_truncated = false;
                self.preview_truncated = false;
                self.error_message = error.safe_display_message();
                self.last_error = Some(error.clone());
                true
            }
            RepeaterEvent::Cancelled { request_id } => {
                if *request_id != self.active_request_id
                    || self.lifecycle != RepeaterLifecycle::Running
                {
                    return false;
                }
                self.lifecycle = RepeaterLifecycle::Cancelled;
                self.status_code = None;
                self.status_text.clear();
                self.duration_ms = None;
                self.last_error = Some(RepeaterAdapterError::Cancelled);
                self.error_message = RepeaterAdapterError::Cancelled.safe_display_message();
                true
            }
        }
    }
}

fn format_wire_request_headers(req: &HttpRequest) -> String {
    let target = if req.query.is_empty() {
        req.path.clone()
    } else {
        format!("{}?{}", req.path, req.query)
    };
    let mut out = format!("{} {} {}\n", req.method, target, req.http_version);
    out.push_str(&req.headers_raw_text());
    out
}

fn format_wire_response_headers(resp: &HttpResponse) -> String {
    let mut out = if resp.status_text.is_empty() {
        format!("{} {}\n", resp.http_version, resp.status_code)
    } else {
        format!(
            "{} {} {}\n",
            resp.http_version, resp.status_code, resp.status_text
        )
    };
    out.push_str(&resp.headers_raw_text());
    out
}

/// Typed event contract emitted by the background worker to any registered consumer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepeaterEvent {
    Started {
        request_id: u64,
    },
    Completed {
        request_id: u64,
        result: Box<RepeaterExecutionResult>,
    },
    Failed {
        request_id: u64,
        error: RepeaterAdapterError,
    },
    Cancelled {
        request_id: u64,
    },
}

impl RepeaterEvent {
    pub fn request_id(&self) -> u64 {
        match self {
            RepeaterEvent::Started { request_id }
            | RepeaterEvent::Completed { request_id, .. }
            | RepeaterEvent::Failed { request_id, .. }
            | RepeaterEvent::Cancelled { request_id } => *request_id,
        }
    }
}

/// Abstract consumer interface for receiving `RepeaterEvent` notifications from the worker thread.
/// In tests or headless mode this can be backed by `std::sync::mpsc::Sender<RepeaterEvent>` or a closure;
/// in the future Slint binding increment it will bridge into `slint::invoke_from_event_loop`.
pub trait RepeaterEventSink: Send + Sync + 'static {
    fn on_event(&self, event: RepeaterEvent);
}

impl RepeaterEventSink for Sender<RepeaterEvent> {
    fn on_event(&self, event: RepeaterEvent) {
        let _ = self.send(event);
    }
}

impl<F> RepeaterEventSink for F
where
    F: Fn(RepeaterEvent) + Send + Sync + 'static,
{
    fn on_event(&self, event: RepeaterEvent) {
        self(event);
    }
}

#[derive(Debug, Clone)]
struct ActiveExecutionSlot {
    request_id: u64,
    cancel_flag: Arc<AtomicBool>,
}

/// RAII cleanup guard ensuring that when a worker thread exits (normally, via early return, or panic),
/// `in_flight` is released, `active_slot` is cleared ONLY if its `request_id` still matches the worker's
/// `request_id`, and `view_state` is never stranded in `RepeaterLifecycle::Running` (M4).
struct WorkerFlightGuard {
    request_id: u64,
    in_flight: Arc<AtomicBool>,
    active_slot: Arc<Mutex<Option<ActiveExecutionSlot>>>,
    view_state: Arc<Mutex<RepeaterViewState>>,
    released: bool,
}

impl WorkerFlightGuard {
    fn new(
        request_id: u64,
        in_flight: Arc<AtomicBool>,
        active_slot: Arc<Mutex<Option<ActiveExecutionSlot>>>,
        view_state: Arc<Mutex<RepeaterViewState>>,
    ) -> Self {
        Self {
            request_id,
            in_flight,
            active_slot,
            view_state,
            released: false,
        }
    }

    fn release_now(&mut self) {
        self.release_now_with_fallback(None);
    }

    fn release_now_with_fallback(&mut self, fallback_error: Option<RepeaterAdapterError>) {
        if self.released {
            return;
        }
        self.released = true;

        // M4 recovery: if the worker is exiting without having transitioned `view_state` out of
        // `Running` for `self.request_id` (e.g. due to an unexpected panic), transition it to
        // `Failed` before releasing `in_flight`.
        if let Some(err) = fallback_error {
            let mut state_guard = match self.view_state.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            if state_guard.active_request_id == self.request_id
                && state_guard.lifecycle == RepeaterLifecycle::Running
            {
                let fallback_event = RepeaterEvent::Failed {
                    request_id: self.request_id,
                    error: err,
                };
                state_guard.apply_event(&fallback_event);
            }
            drop(state_guard);
        }

        let mut slot_guard = match self.active_slot.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if slot_guard
            .as_ref()
            .is_some_and(|slot| slot.request_id == self.request_id)
        {
            *slot_guard = None;
        }
        drop(slot_guard);

        self.in_flight.store(false, Ordering::SeqCst);
    }
}

impl Drop for WorkerFlightGuard {
    fn drop(&mut self) {
        self.release_now_with_fallback(Some(RepeaterAdapterError::WorkerPanicked));
    }
}

/// Thread-safe coordinator that dispatches `HttpRepeaterEngine` off the UI thread,
/// enforces single-flight execution via `compare_exchange`, tracks monotonic `request_id`s,
/// and supports cooperative cancellation and explicit shutdown.
pub struct RepeaterTaskController {
    engine: HttpRepeaterEngine,
    in_flight: Arc<AtomicBool>,
    next_request_id: Arc<AtomicU64>,
    active_slot: Arc<Mutex<Option<ActiveExecutionSlot>>>,
    view_state: Arc<Mutex<RepeaterViewState>>,
}

impl RepeaterTaskController {
    pub fn new(scope: Arc<AuditScope>, config: RepeaterConfig) -> Self {
        Self {
            engine: HttpRepeaterEngine::new(scope, config),
            in_flight: Arc::new(AtomicBool::new(false)),
            next_request_id: Arc::new(AtomicU64::new(1)),
            active_slot: Arc::new(Mutex::new(None)),
            view_state: Arc::new(Mutex::new(RepeaterViewState::default())),
        }
    }

    pub fn with_default_config(scope: Arc<AuditScope>) -> Self {
        Self::new(scope, RepeaterConfig::default())
    }

    pub fn config(&self) -> &RepeaterConfig {
        self.engine.config()
    }

    pub fn scope(&self) -> &AuditScope {
        self.engine.scope()
    }

    pub fn is_in_flight(&self) -> bool {
        self.in_flight.load(Ordering::SeqCst)
    }

    pub fn active_request_id(&self) -> Option<u64> {
        self.active_slot
            .lock()
            .ok()
            .and_then(|guard| guard.as_ref().map(|slot| slot.request_id))
    }

    pub fn snapshot_state(&self) -> RepeaterViewState {
        match self.view_state.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    pub fn set_preview_limit_bytes(&self, limit_bytes: usize) {
        let mut state = match self.view_state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.preview_limit_bytes = clamp_preview_limit(limit_bytes);
    }

    /// Validates `input` and spawns a background worker thread to execute `HttpRepeaterEngine`.
    /// Returns the assigned monotonic `request_id` on success.
    ///
    /// Guarantees:
    /// - Single-flight via `compare_exchange` on `in_flight`.
    /// - Early input validation (`to_request_spec`) BEFORE cloning `input` into `RepeaterViewState` (M3).
    /// - Explicit handling of `thread::Builder::spawn` failure (M6) and worker panics (M4) without leaking `in_flight`
    ///   or leaving `RepeaterViewState` permanently in `Running`.
    /// - Zero locks held while `HttpRepeaterEngine::execute` performs network I/O.
    pub fn dispatch(
        &self,
        input: RepeaterUiInput,
        sink: Option<Arc<dyn RepeaterEventSink>>,
    ) -> Result<u64, RepeaterAdapterError> {
        let engine = self.engine.clone();
        self.dispatch_with_executor(input, sink, move |spec, cancel_flag| {
            engine.execute(spec, Some(cancel_flag))
        })
    }

    fn dispatch_with_executor<E>(
        &self,
        input: RepeaterUiInput,
        sink: Option<Arc<dyn RepeaterEventSink>>,
        executor: E,
    ) -> Result<u64, RepeaterAdapterError>
    where
        E: FnOnce(
                &RepeaterRequestSpec,
                &AtomicBool,
            ) -> Result<RepeaterExecutionResult, RepeaterError>
            + Send
            + 'static,
    {
        if self
            .in_flight
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(RepeaterAdapterError::AlreadyRunning);
        }

        let request_id = self.next_request_id.fetch_add(1, Ordering::SeqCst);
        let cancel_flag = Arc::new(AtomicBool::new(false));

        {
            let mut slot_guard = match self.active_slot.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            *slot_guard = Some(ActiveExecutionSlot {
                request_id,
                cancel_flag: Arc::clone(&cancel_flag),
            });
        }

        let mut flight_guard = WorkerFlightGuard::new(
            request_id,
            Arc::clone(&self.in_flight),
            Arc::clone(&self.active_slot),
            Arc::clone(&self.view_state),
        );

        let started_event = RepeaterEvent::Started { request_id };

        // M3: Validate input boundaries, method whitelist, and strict header syntax BEFORE
        // cloning `input` into `view_state` so oversized payloads are never duplicated in memory.
        let spec = match input.to_request_spec(self.engine.config()) {
            Ok(spec) => spec,
            Err(validation_err) => {
                let failed_event = RepeaterEvent::Failed {
                    request_id,
                    error: validation_err.clone(),
                };
                {
                    let mut state = match self.view_state.lock() {
                        Ok(guard) => guard,
                        Err(poisoned) => poisoned.into_inner(),
                    };
                    state.apply_event(&started_event);
                    state.apply_event(&failed_event);
                }
                flight_guard.release_now();
                if let Some(ref s) = sink {
                    let _ = catch_unwind(AssertUnwindSafe(|| {
                        s.on_event(started_event);
                        s.on_event(failed_event);
                    }));
                }
                return Err(validation_err);
            }
        };

        // Input is now guaranteed to be within size limits; move `input` into `view_state` without extra cloning.
        {
            let mut state = match self.view_state.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            state.input = input;
            state.apply_event(&started_event);
        }

        // Notify sink of `Started`. If the external sink panics before worker spawn, catch it,
        // transition `view_state` to `Failed(WorkerPanicked)`, release `in_flight`, and return an error.
        if let Some(ref s) = sink {
            if catch_unwind(AssertUnwindSafe(|| s.on_event(started_event))).is_err() {
                let err = RepeaterAdapterError::WorkerPanicked;
                let failed_event = RepeaterEvent::Failed {
                    request_id,
                    error: err.clone(),
                };
                {
                    let mut state = match self.view_state.lock() {
                        Ok(guard) => guard,
                        Err(poisoned) => poisoned.into_inner(),
                    };
                    state.apply_event(&failed_event);
                }
                flight_guard.release_now();
                return Err(err);
            }
        }

        let view_state_ref = Arc::clone(&self.view_state);
        let worker_sink = sink.clone();

        let spawn_result = thread::Builder::new()
            .name(format!("kaska-repeater-{}", request_id))
            .spawn(move || {
                let mut worker_guard = flight_guard;

                // M4: Catch any unexpected panic inside the execution boundary without exposing
                // raw panic payloads to the user or leaving `view_state` stuck in `Running`.
                // Note: `std::panic::catch_unwind` does not disable the standard Rust panic hook
                // on `stderr`, but prevents thread unwinding from escaping or poisoning state.
                let outcome =
                    catch_unwind(AssertUnwindSafe(|| executor(&spec, cancel_flag.as_ref())));

                let terminal_event = match outcome {
                    Ok(Ok(result)) => RepeaterEvent::Completed {
                        request_id,
                        result: Box::new(result),
                    },
                    Ok(Err(RepeaterError::Cancelled)) => RepeaterEvent::Cancelled { request_id },
                    Ok(Err(engine_err)) => RepeaterEvent::Failed {
                        request_id,
                        error: RepeaterAdapterError::Engine(engine_err),
                    },
                    Err(_panic_payload) => RepeaterEvent::Failed {
                        request_id,
                        error: RepeaterAdapterError::WorkerPanicked,
                    },
                };

                {
                    let mut state = match view_state_ref.lock() {
                        Ok(guard) => guard,
                        Err(poisoned) => poisoned.into_inner(),
                    };
                    state.apply_event(&terminal_event);
                }

                // Release `active_slot` and `in_flight` BEFORE notifying the external consumer
                // so a listener reacting immediately to `Completed`/`Failed`/`Cancelled` can
                // dispatch the next request without hitting a transient `AlreadyRunning` race,
                // and so a panicking `EventSink` after completion cannot affect the recorded terminal state.
                worker_guard.release_now();

                if let Some(s) = worker_sink {
                    let _ = catch_unwind(AssertUnwindSafe(|| {
                        s.on_event(terminal_event);
                    }));
                }
            });

        match spawn_result {
            Ok(_handle) => Ok(request_id),
            Err(io_err) => {
                Err(self.finalize_spawn_failure(request_id, io_err.to_string(), sink.as_ref()))
            }
        }
    }

    /// M6: Associates thread creation failure with the exact `request_id` that failed to spawn.
    ///
    /// When `thread::Builder::spawn` fails, the unspawned closure is dropped first, causing
    /// `WorkerFlightGuard::drop` to transition `view_state` (for `request_id`) to `Failed(WorkerPanicked)`
    /// and release `in_flight`. A concurrent caller on another thread could immediately acquire
    /// `in_flight` and start `request_id + 1` before `finalize_spawn_failure` acquires `view_state.lock()`.
    ///
    /// Therefore, `finalize_spawn_failure` checks `state.active_request_id == request_id` before
    /// updating `view_state` to `Failed(WorkerSpawnFailed)`. If `state.active_request_id` has already
    /// advanced to a newer request, `view_state` is left completely untouched.
    fn finalize_spawn_failure(
        &self,
        request_id: u64,
        cause: String,
        sink: Option<&Arc<dyn RepeaterEventSink>>,
    ) -> RepeaterAdapterError {
        let err = RepeaterAdapterError::WorkerSpawnFailed(cause);
        let failed_event = RepeaterEvent::Failed {
            request_id,
            error: err.clone(),
        };
        {
            let mut state = match self.view_state.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            if state.active_request_id == request_id {
                state.lifecycle = RepeaterLifecycle::Failed;
                state.status_code = None;
                state.status_text.clear();
                state.duration_ms = None;
                state.response_headers.clear();
                state.response_body_preview.clear();
                state.received_body_bytes = 0;
                state.body_is_binary = false;
                state.http_body_truncated = false;
                state.preview_truncated = false;
                state.error_message = err.safe_display_message();
                state.last_error = Some(err.clone());
            }
        }
        if let Some(s) = sink {
            let _ = catch_unwind(AssertUnwindSafe(|| {
                s.on_event(failed_event);
            }));
        }
        err
    }

    /// Signals cooperative cancellation for the currently active request (if any),
    /// returning the `request_id` that was signalled.
    ///
    /// Cancellation timing semantics:
    /// - During active socket read/write loops, `HttpRepeaterEngine` polls `cancel_flag` on each
    ///   `io_slice_timeout` (50 ms by default, subject to OS thread scheduling).
    /// - During `TcpStream::connect_timeout`, the OS syscall blocks up to the remaining `connect_timeout`
    ///   budget before `cancel_flag` can be observed.
    pub fn cancel_active(&self) -> Option<u64> {
        let guard = match self.active_slot.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let slot = guard.as_ref()?;
        slot.cancel_flag.store(true, Ordering::SeqCst);
        Some(slot.request_id)
    }

    /// Cancels a specific `request_id` if and only if it is still the active execution.
    pub fn cancel_request(&self, target_request_id: u64) -> bool {
        let guard = match self.active_slot.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(slot) = guard.as_ref() {
            if slot.request_id == target_request_id {
                slot.cancel_flag.store(true, Ordering::SeqCst);
                return true;
            }
        }
        false
    }

    /// Explicit shutdown hook reusable by the application lifecycle (e.g. window close handler).
    /// Signals cooperative cancellation on any active Repeater execution without blocking the caller thread.
    pub fn shutdown(&self) {
        let _ = self.cancel_active();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaska_http::models::HttpHeader;
    use kaska_http::store::create_shared_store;
    use std::io::{Read, Write};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
    use std::sync::mpsc;
    use std::sync::Barrier;
    use std::time::Duration;

    fn default_config() -> RepeaterConfig {
        RepeaterConfig::default()
    }

    fn dummy_execution_result(status_code: u16, body: &[u8]) -> Box<RepeaterExecutionResult> {
        Box::new(RepeaterExecutionResult {
            request: HttpRequest {
                method: HttpMethod::Get,
                raw_url: "http://127.0.0.1:8989/test".to_string(),
                host: "127.0.0.1:8989".to_string(),
                path: "/test".to_string(),
                query: String::new(),
                http_version: "HTTP/1.1".to_string(),
                headers: vec![HttpHeader::new("Host", "127.0.0.1:8989")],
                body: Vec::new(),
            },
            response: HttpResponse {
                status_code,
                status_text: "OK".to_string(),
                http_version: "HTTP/1.1".to_string(),
                headers: vec![HttpHeader::new("Content-Length", body.len().to_string())],
                body: body.to_vec(),
            },
            duration_ms: 4,
            response_body_truncated: false,
            remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8989),
        })
    }

    #[test]
    fn test_method_validation_accepts_only_supported_methods() {
        for (raw, expected) in [
            ("GET", HttpMethod::Get),
            ("  get ", HttpMethod::Get),
            ("POST", HttpMethod::Post),
            ("Put", HttpMethod::Put),
            ("DELETE", HttpMethod::Delete),
            ("PATCH", HttpMethod::Patch),
            ("HEAD", HttpMethod::Head),
            ("OPTIONS", HttpMethod::Options),
        ] {
            assert_eq!(
                RepeaterUiInput::parse_supported_method(raw),
                Ok(expected),
                "Expected method {} to be accepted",
                raw
            );
        }

        assert_eq!(
            RepeaterUiInput::parse_supported_method(""),
            Err(RepeaterAdapterError::EmptyMethod)
        );
        assert_eq!(
            RepeaterUiInput::parse_supported_method("   "),
            Err(RepeaterAdapterError::EmptyMethod)
        );

        for forbidden in ["CONNECT", "TRACE", "PROPFIND", "CUSTOM", "GET POST"] {
            assert!(
                matches!(
                    RepeaterUiInput::parse_supported_method(forbidden),
                    Err(RepeaterAdapterError::UnsupportedMethod(_))
                ),
                "Expected method '{}' to be rejected",
                forbidden
            );
        }
    }

    #[test]
    fn test_m1_safe_display_message_redacts_secrets_and_raw_user_values() {
        let secret_marker = "SUPER_SECRET_TOKEN_VALUE_987654321";

        // 1. Malformed Authorization header line (missing ':') parsed via strict header parser
        let bad_auth_input = RepeaterUiInput::new(
            "GET",
            "http://127.0.0.1:8989/api",
            format!("Authorization Bearer {}", secret_marker),
            "",
        );
        let auth_err = bad_auth_input
            .to_request_spec(&default_config())
            .expect_err("Malformed Authorization header must fail");
        // Verify raw error contains the secret, whereas safe_display_message() does NOT
        assert!(auth_err.to_string().contains(secret_marker));
        let safe_auth_msg = auth_err.safe_display_message();
        assert!(
            !safe_auth_msg.contains(secret_marker),
            "safe_display_message leaked Authorization secret: {}",
            safe_auth_msg
        );

        // 2. Malformed Cookie header line (missing ':' or containing NUL/CR)
        let bad_cookie_input = RepeaterUiInput::new(
            "GET",
            "http://127.0.0.1:8989/api",
            format!("Cookie session_id={}", secret_marker),
            "",
        );
        let cookie_err = bad_cookie_input
            .to_request_spec(&default_config())
            .expect_err("Malformed Cookie header must fail");
        assert!(cookie_err.to_string().contains(secret_marker));
        let safe_cookie_msg = cookie_err.safe_display_message();
        assert!(
            !safe_cookie_msg.contains(secret_marker),
            "safe_display_message leaked Cookie secret: {}",
            safe_cookie_msg
        );

        // 3. Engine validation/URL/method errors carrying user-provided values
        for err in [
            RepeaterAdapterError::UnsupportedMethod(secret_marker.to_string()),
            RepeaterAdapterError::WorkerSpawnFailed(secret_marker.to_string()),
            RepeaterAdapterError::Engine(RepeaterError::InvalidUrl(format!(
                "http://admin:{}@127.0.0.1:8989/api",
                secret_marker
            ))),
            RepeaterAdapterError::Engine(RepeaterError::RequestValidation(format!(
                "Invalid Content-Length header value '{}'",
                secret_marker
            ))),
            RepeaterAdapterError::Engine(RepeaterError::HostHeaderMismatch {
                url_host: "127.0.0.1:8989".to_string(),
                header_host: secret_marker.to_string(),
            }),
            RepeaterAdapterError::Engine(RepeaterError::HostOutOfScope(secret_marker.to_string())),
            RepeaterAdapterError::Engine(RepeaterError::ConnectionFailed(
                secret_marker.to_string(),
            )),
            RepeaterAdapterError::Engine(RepeaterError::InvalidResponse(secret_marker.to_string())),
        ] {
            let msg = err.safe_display_message();
            assert!(
                !msg.contains(secret_marker),
                "safe_display_message leaked secret for {:?}: {}",
                err,
                msg
            );
            assert!(!msg.is_empty());
        }
    }

    #[test]
    fn test_m2_lifecycle_transitions_reject_duplicate_started_and_stale_events() {
        let mut state = RepeaterViewState::default();
        assert_eq!(state.lifecycle, RepeaterLifecycle::Idle);
        assert_eq!(state.active_request_id, 0);

        // 1. Started(1) -> Completed(1) -> duplicate Started(1) must be rejected
        assert!(state.apply_event(&RepeaterEvent::Started { request_id: 1 }));
        assert_eq!(state.lifecycle, RepeaterLifecycle::Running);
        assert_eq!(state.active_request_id, 1);

        let completed_1 = RepeaterEvent::Completed {
            request_id: 1,
            result: dummy_execution_result(200, b"first-ok"),
        };
        assert!(state.apply_event(&completed_1));
        assert_eq!(state.lifecycle, RepeaterLifecycle::Completed);
        assert_eq!(state.status_code, Some(200));

        // Duplicate Started(1) after Completed(1) MUST return false and keep Completed
        assert!(!state.apply_event(&RepeaterEvent::Started { request_id: 1 }));
        assert_eq!(state.lifecycle, RepeaterLifecycle::Completed);
        assert_eq!(state.status_code, Some(200));

        // Duplicate terminal events on completed request_id = 1 MUST also be rejected
        assert!(!state.apply_event(&RepeaterEvent::Cancelled { request_id: 1 }));
        assert_eq!(state.lifecycle, RepeaterLifecycle::Completed);

        // 2. Normal advancement to request_id = 2: Started(2) -> Cancelled(2) -> duplicate Started(2)
        assert!(state.apply_event(&RepeaterEvent::Started { request_id: 2 }));
        assert_eq!(state.lifecycle, RepeaterLifecycle::Running);
        assert_eq!(state.active_request_id, 2);
        assert_eq!(state.status_code, None);

        assert!(state.apply_event(&RepeaterEvent::Cancelled { request_id: 2 }));
        assert_eq!(state.lifecycle, RepeaterLifecycle::Cancelled);

        // Duplicate Started(2) after Cancelled(2) MUST return false and remain Cancelled
        assert!(!state.apply_event(&RepeaterEvent::Started { request_id: 2 }));
        assert_eq!(state.lifecycle, RepeaterLifecycle::Cancelled);

        // 3. Advancement to request_id = 3: Started(3) -> Failed(3) -> duplicate Started(3)
        assert!(state.apply_event(&RepeaterEvent::Started { request_id: 3 }));
        assert_eq!(state.lifecycle, RepeaterLifecycle::Running);
        assert_eq!(state.active_request_id, 3);

        let failed_3 = RepeaterEvent::Failed {
            request_id: 3,
            error: RepeaterAdapterError::EmptyTargetUrl,
        };
        assert!(state.apply_event(&failed_3));
        assert_eq!(state.lifecycle, RepeaterLifecycle::Failed);

        // Duplicate Started(3) after Failed(3) MUST return false and remain Failed
        assert!(!state.apply_event(&RepeaterEvent::Started { request_id: 3 }));
        assert_eq!(state.lifecycle, RepeaterLifecycle::Failed);

        // 4. Stale terminal events from earlier request_ids (1, 2, 3) after Started(4)
        assert!(state.apply_event(&RepeaterEvent::Started { request_id: 4 }));
        assert_eq!(state.lifecycle, RepeaterLifecycle::Running);
        assert_eq!(state.active_request_id, 4);

        for stale_id in [0, 1, 2, 3] {
            assert!(!state.apply_event(&RepeaterEvent::Started {
                request_id: stale_id
            }));
            assert!(!state.apply_event(&RepeaterEvent::Completed {
                request_id: stale_id,
                result: dummy_execution_result(200, b"stale"),
            }));
            assert!(!state.apply_event(&RepeaterEvent::Failed {
                request_id: stale_id,
                error: RepeaterAdapterError::EmptyMethod,
            }));
            assert!(!state.apply_event(&RepeaterEvent::Cancelled {
                request_id: stale_id
            }));
        }
        assert_eq!(state.lifecycle, RepeaterLifecycle::Running);
        assert_eq!(state.active_request_id, 4);

        // Complete request #4 normally
        assert!(state.apply_event(&RepeaterEvent::Completed {
            request_id: 4,
            result: dummy_execution_result(204, b""),
        }));
        assert_eq!(state.lifecycle, RepeaterLifecycle::Completed);
        assert_eq!(state.status_code, Some(204));
    }

    #[test]
    fn test_m3_early_bounds_validation_before_cloning_and_in_flight_release() {
        let cfg = RepeaterConfig {
            max_header_bytes: 128,
            max_request_body_bytes: 64,
            ..default_config()
        };
        let scope = Arc::new(AuditScope::default());
        let controller = RepeaterTaskController::new(scope, cfg);

        let sentinel_default_url = controller.snapshot_state().input.target_url.clone();

        // 1. Oversized Method
        let bad_method = RepeaterUiInput::new(
            "M".repeat(MAX_INPUT_METHOD_BYTES + 5),
            "http://127.0.0.1:8989/api",
            "",
            "",
        );
        let res_method = controller.dispatch(bad_method, None);
        assert!(matches!(
            res_method,
            Err(RepeaterAdapterError::MethodTooLarge { .. })
        ));
        assert!(!controller.is_in_flight());
        assert_eq!(
            controller.snapshot_state().lifecycle,
            RepeaterLifecycle::Failed
        );
        // Confirm the oversized input was NOT cloned into `view_state.input`
        assert_eq!(
            controller.snapshot_state().input.target_url,
            sentinel_default_url
        );

        // 2. Oversized URL
        let huge_url = format!("http://127.0.0.1:8989/{}", "u".repeat(MAX_INPUT_URL_BYTES));
        let bad_url = RepeaterUiInput::new("GET", huge_url, "", "");
        let res_url = controller.dispatch(bad_url, None);
        assert!(matches!(
            res_url,
            Err(RepeaterAdapterError::TargetUrlTooLarge { .. })
        ));
        assert!(!controller.is_in_flight());
        assert_eq!(
            controller.snapshot_state().input.target_url,
            sentinel_default_url
        );

        // 3. Oversized Headers
        let huge_headers = format!("X-Oversized: {}", "h".repeat(200));
        let bad_headers =
            RepeaterUiInput::new("GET", "http://127.0.0.1:8989/changed", huge_headers, "");
        let res_headers = controller.dispatch(bad_headers, None);
        assert!(matches!(
            res_headers,
            Err(RepeaterAdapterError::InputHeadersTooLarge { .. })
        ));
        assert!(!controller.is_in_flight());
        assert!(controller.snapshot_state().input.headers_raw.len() <= 128);

        // 4. Oversized Body
        let huge_body = "b".repeat(120);
        let bad_body = RepeaterUiInput::new("POST", "http://127.0.0.1:8989/changed", "", huge_body);
        let res_body = controller.dispatch(bad_body, None);
        assert!(matches!(
            res_body,
            Err(RepeaterAdapterError::InputBodyTooLarge { .. })
        ));
        assert!(!controller.is_in_flight());
        assert!(controller.snapshot_state().input.body_utf8.is_empty());
    }

    #[test]
    fn test_m4_worker_panic_recovery_transitions_state_and_releases_in_flight() {
        let scope = Arc::new(AuditScope::default());
        let controller = RepeaterTaskController::with_default_config(scope);

        let (tx, rx) = mpsc::channel();
        let valid_input = RepeaterUiInput::new("GET", "http://127.0.0.1:8989/panic-test", "", "");

        // Inject a deterministic panic inside the worker execution closure
        let req_id_1 = controller
            .dispatch_with_executor(valid_input, Some(Arc::new(tx)), |_spec, _cancel| {
                panic!("simulated internal worker panic containing SENSITIVE_PANIC_STRING");
            })
            .expect("Worker should spawn cleanly");
        assert_eq!(req_id_1, 1);

        let ev_started = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(ev_started, RepeaterEvent::Started { request_id: 1 });

        let ev_terminal = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(
            ev_terminal,
            RepeaterEvent::Failed {
                request_id: 1,
                error: RepeaterAdapterError::WorkerPanicked,
            }
        );

        // Verify in_flight and active_slot are released, and view_state is Failed (not stuck in Running)
        assert!(!controller.is_in_flight());
        assert_eq!(controller.active_request_id(), None);
        let snap1 = controller.snapshot_state();
        assert_eq!(snap1.lifecycle, RepeaterLifecycle::Failed);
        assert_eq!(snap1.last_error, Some(RepeaterAdapterError::WorkerPanicked));
        assert!(!snap1.error_message.contains("SENSITIVE_PANIC_STRING"));

        // Verify that a subsequent request can be dispatched immediately and succeeds
        let (tx2, rx2) = mpsc::channel();
        let next_input = RepeaterUiInput::new("GET", "http://127.0.0.1:8989/recovery-ok", "", "");
        let req_id_2 = controller
            .dispatch_with_executor(next_input, Some(Arc::new(tx2)), |_spec, _cancel| {
                Ok(*dummy_execution_result(200, b"Recovered"))
            })
            .expect("Second request after worker panic must succeed");
        assert_eq!(req_id_2, 2);

        let _ = rx2.recv_timeout(Duration::from_secs(2)).unwrap();
        let ev_done_2 = rx2.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(
            ev_done_2,
            RepeaterEvent::Completed { request_id: 2, .. }
        ));
        assert!(!controller.is_in_flight());
        assert_eq!(
            controller.snapshot_state().lifecycle,
            RepeaterLifecycle::Completed
        );
        assert_eq!(controller.snapshot_state().status_code, Some(200));
    }

    #[test]
    fn test_m5_exact_preview_byte_budget_for_binary_and_multibyte_utf8() {
        // 1. Small binary payload fits well within MIN_BODY_PREVIEW_BYTES
        let small_bin = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0xFF];
        let small_res = format_response_body_preview(&small_bin, false, MIN_BODY_PREVIEW_BYTES);
        assert!(small_res.is_binary);
        assert!(!small_res.preview_truncated);
        assert!(!small_res.http_body_truncated);
        assert!(
            small_res.preview_text.len() <= MIN_BODY_PREVIEW_BYTES,
            "Small binary preview ({} bytes) exceeded limit ({} bytes)",
            small_res.preview_text.len(),
            MIN_BODY_PREVIEW_BYTES
        );
        assert!(small_res.preview_text.contains("89 50 4e 47"));

        // 2. Binary payload larger than limit at various budgets (including MIN_BODY_PREVIEW_BYTES)
        let large_bin: Vec<u8> = (0..4096).map(|i| (i % 256) as u8).collect();
        for budget in [MIN_BODY_PREVIEW_BYTES, 300, 512, 1024, 4096] {
            let bin_res = format_response_body_preview(&large_bin, true, budget);
            let clamped = clamp_preview_limit(budget);
            assert!(bin_res.is_binary);
            assert!(bin_res.preview_truncated);
            assert!(bin_res.http_body_truncated);
            assert!(
                bin_res.preview_text.len() <= clamped,
                "Binary preview_text ({} bytes) exceeded budget ({} bytes)",
                bin_res.preview_text.len(),
                clamped
            );
            // Verify every hex row is complete (ends with "|\n")
            for line in bin_res.preview_text.lines().skip(1) {
                assert!(
                    line.ends_with('|'),
                    "Broken hex line formatting: '{}'",
                    line
                );
            }
        }

        // 3. Multibyte UTF-8 payload (4-byte emojis '🦀' and 3-byte '€') clipped at exact limit
        let multibyte_utf8 = "🦀€".repeat(300); // 7 bytes per repetition = 2100 bytes
        for budget in [MIN_BODY_PREVIEW_BYTES, 257, 258, 259, 512, 1024] {
            let utf8_res = format_response_body_preview(multibyte_utf8.as_bytes(), true, budget);
            let clamped = clamp_preview_limit(budget);
            assert!(!utf8_res.is_binary);
            assert!(utf8_res.preview_truncated);
            assert!(utf8_res.http_body_truncated);
            assert!(
                utf8_res.preview_text.len() <= clamped,
                "UTF-8 preview_text ({} bytes) exceeded budget ({} bytes)",
                utf8_res.preview_text.len(),
                clamped
            );
        }

        // 4. Below-minimum and above-maximum limits are clamped to [MIN_BODY_PREVIEW_BYTES, MAX_BODY_PREVIEW_BYTES]
        assert_eq!(clamp_preview_limit(0), MIN_BODY_PREVIEW_BYTES);
        assert_eq!(clamp_preview_limit(10), MIN_BODY_PREVIEW_BYTES);
        assert_eq!(clamp_preview_limit(usize::MAX), MAX_BODY_PREVIEW_BYTES);
        let huge_utf8 = "A".repeat(MAX_BODY_PREVIEW_BYTES + 10_000);
        let max_res = format_response_body_preview(huge_utf8.as_bytes(), false, usize::MAX);
        assert!(max_res.preview_truncated);
        assert!(max_res.preview_text.len() <= MAX_BODY_PREVIEW_BYTES);
    }

    #[test]
    fn test_real_get_and_post_execution_without_mutating_traffic_store() {
        let store = create_shared_store();
        assert_eq!(store.lock().unwrap().count(), 0);

        let listener = TcpListener::bind("127.0.0.1:0").expect("Bind ephemeral loopback listener");
        let port = listener.local_addr().unwrap().port();

        let server_thread = thread::spawn(move || {
            // 1st connection: GET
            let (mut stream1, _) = listener.accept().expect("Accept GET");
            stream1
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut buf1 = [0u8; 2048];
            let n1 = stream1.read(&mut buf1).unwrap();
            let req1_str = String::from_utf8_lossy(&buf1[..n1]).to_string();
            assert!(req1_str.starts_with("GET /hello?mode=test HTTP/1.1\r\n"));
            let resp1 = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 15\r\nConnection: close\r\n\r\n{\"hello\":\"get\"}";
            stream1.write_all(resp1).unwrap();

            // 2nd connection: POST with exact body verification
            let (mut stream2, _) = listener.accept().expect("Accept POST");
            stream2
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut raw2 = Vec::new();
            let mut chunk = [0u8; 1024];
            loop {
                let n = stream2.read(&mut chunk).unwrap();
                if n == 0 {
                    break;
                }
                raw2.extend_from_slice(&chunk[..n]);
                if let Some(pos) = raw2.windows(4).position(|w| w == b"\r\n\r\n") {
                    let body_len = raw2.len() - (pos + 4);
                    if body_len >= 27 {
                        break;
                    }
                }
            }
            let req2_str = String::from_utf8_lossy(&raw2).to_string();
            assert!(req2_str.starts_with("POST /submit HTTP/1.1\r\n"));
            assert!(req2_str.contains("Content-Length: 27\r\n"));
            assert!(req2_str.ends_with("{\"action\":\"verify_payload\"}"));

            let resp2 = b"HTTP/1.1 201 Created\r\nX-Confirmed: true\r\nContent-Length: 16\r\nConnection: close\r\n\r\n{\"created\":true}";
            stream2.write_all(resp2).unwrap();
        });

        let scope = Arc::new(AuditScope::default());
        let controller = RepeaterTaskController::with_default_config(scope);

        // Execute GET
        let (tx1, rx1) = mpsc::channel();
        let get_input = RepeaterUiInput::new(
            "GET",
            format!("http://127.0.0.1:{}/hello?mode=test", port),
            format!("Host: 127.0.0.1:{}\nX-Custom: alpha", port),
            "",
        );
        let req_id_1 = controller
            .dispatch(get_input, Some(Arc::new(tx1)))
            .expect("Dispatch GET");
        assert_eq!(req_id_1, 1);

        let ev_start_1 = rx1.recv_timeout(Duration::from_secs(3)).unwrap();
        assert!(matches!(
            ev_start_1,
            RepeaterEvent::Started { request_id: 1 }
        ));
        let ev_done_1 = rx1.recv_timeout(Duration::from_secs(3)).unwrap();
        match ev_done_1 {
            RepeaterEvent::Completed { request_id, result } => {
                assert_eq!(request_id, 1);
                assert_eq!(result.response.status_code, 200);
                assert_eq!(result.response.body, b"{\"hello\":\"get\"}");
            }
            other => panic!("Expected Completed event for GET, got {:?}", other),
        }

        let snap1 = controller.snapshot_state();
        assert_eq!(snap1.lifecycle, RepeaterLifecycle::Completed);
        assert_eq!(snap1.status_code, Some(200));
        assert_eq!(snap1.response_body_preview, "{\"hello\":\"get\"}");
        assert!(!snap1.body_is_binary);
        assert!(!snap1.http_body_truncated);
        assert!(!snap1.preview_truncated);

        // Execute POST
        let (tx2, rx2) = mpsc::channel();
        let post_input = RepeaterUiInput::new(
            "POST",
            format!("http://127.0.0.1:{}/submit", port),
            "Content-Type: application/json",
            "{\"action\":\"verify_payload\"}",
        );
        let req_id_2 = controller
            .dispatch(post_input, Some(Arc::new(tx2)))
            .expect("Dispatch POST");
        assert_eq!(req_id_2, 2);

        let _ = rx2.recv_timeout(Duration::from_secs(3)).unwrap();
        let ev_done_2 = rx2.recv_timeout(Duration::from_secs(3)).unwrap();
        match ev_done_2 {
            RepeaterEvent::Completed { request_id, result } => {
                assert_eq!(request_id, 2);
                assert_eq!(result.response.status_code, 201);
                assert_eq!(result.response.body, b"{\"created\":true}");
            }
            other => panic!("Expected Completed event for POST, got {:?}", other),
        }

        server_thread.join().unwrap();

        // Confirm SharedTrafficStore was never mutated
        assert_eq!(store.lock().unwrap().count(), 0);
    }

    #[test]
    fn test_scope_error_and_connection_error_release_in_flight() {
        let scope = Arc::new(AuditScope::default());
        let controller = RepeaterTaskController::with_default_config(scope);

        // 1. Out-of-scope host
        let (tx_scope, rx_scope) = mpsc::channel();
        let bad_scope_input = RepeaterUiInput::new("GET", "http://example.com:80/api", "", "");
        let req_id_1 = controller
            .dispatch(bad_scope_input, Some(Arc::new(tx_scope)))
            .expect("Worker spawned for engine scope check");
        assert_eq!(req_id_1, 1);

        let _ = rx_scope.recv_timeout(Duration::from_secs(2)).unwrap();
        let term_1 = rx_scope.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(
            term_1,
            RepeaterEvent::Failed {
                request_id: 1,
                error: RepeaterAdapterError::Engine(RepeaterError::HostOutOfScope(_))
            }
        ));
        assert!(!controller.is_in_flight());
        assert_eq!(
            controller.snapshot_state().lifecycle,
            RepeaterLifecycle::Failed
        );

        // 2. Connection refused on closed loopback port
        let temp_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let closed_port = temp_listener.local_addr().unwrap().port();
        drop(temp_listener);

        let (tx_conn, rx_conn) = mpsc::channel();
        let conn_input = RepeaterUiInput::new(
            "GET",
            format!("http://127.0.0.1:{}/status", closed_port),
            "",
            "",
        );
        let req_id_2 = controller
            .dispatch(conn_input, Some(Arc::new(tx_conn)))
            .expect("Worker spawned for connection check");
        assert_eq!(req_id_2, 2);

        let _ = rx_conn.recv_timeout(Duration::from_secs(3)).unwrap();
        let term_2 = rx_conn.recv_timeout(Duration::from_secs(3)).unwrap();
        assert!(matches!(
            term_2,
            RepeaterEvent::Failed {
                request_id: 2,
                error: RepeaterAdapterError::Engine(RepeaterError::ConnectionFailed(_))
            }
        ));
        assert!(!controller.is_in_flight());
    }

    #[test]
    fn test_single_flight_guard_and_cooperative_cancellation() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let (accepted_tx, accepted_rx) = mpsc::channel();
        let (release_server_tx, release_server_rx) = mpsc::channel();

        let server_thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 512];
            let _ = stream.read(&mut buf);
            // Notify test that request headers have been read and server is holding response open
            let _ = accepted_tx.send(());
            // Hold socket open until test finishes overlap & cancellation assertions
            let _ = release_server_rx.recv_timeout(Duration::from_secs(5));
        });

        let scope = Arc::new(AuditScope::default());
        let controller = RepeaterTaskController::with_default_config(scope);

        let (event_tx, event_rx) = mpsc::channel();
        let input1 = RepeaterUiInput::new("GET", format!("http://127.0.0.1:{}/slow", port), "", "");
        let id1 = controller
            .dispatch(input1.clone(), Some(Arc::new(event_tx)))
            .expect("First request dispatches");
        assert_eq!(id1, 1);

        // Wait deterministically until server has accepted the connection
        accepted_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(controller.is_in_flight());

        // Second overlapping dispatch MUST fail deterministically with AlreadyRunning
        let overlap_res = controller.dispatch(input1, None);
        assert_eq!(overlap_res, Err(RepeaterAdapterError::AlreadyRunning));

        // Cancel with a wrong request_id must return false and not cancel request #1
        assert!(!controller.cancel_request(999));

        // Cancel active request #1
        assert_eq!(controller.cancel_active(), Some(1));

        // Wait for Started and Cancelled events
        let ev1 = event_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        assert_eq!(ev1, RepeaterEvent::Started { request_id: 1 });
        let ev2 = event_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        assert_eq!(ev2, RepeaterEvent::Cancelled { request_id: 1 });

        assert!(!controller.is_in_flight());
        assert_eq!(
            controller.snapshot_state().lifecycle,
            RepeaterLifecycle::Cancelled
        );

        let _ = release_server_tx.send(());
        server_thread.join().unwrap();
    }

    #[test]
    fn test_worker_completes_safely_when_event_consumer_is_dropped() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let barrier = Arc::new(Barrier::new(2));
        let barrier_server = Arc::clone(&barrier);

        let server_thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 512];
            let _ = stream.read(&mut buf);
            // Wait until test has dropped the mpsc::Receiver
            barrier_server.wait();
            let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK";
            let _ = stream.write_all(resp);
        });

        let scope = Arc::new(AuditScope::default());
        let controller = RepeaterTaskController::with_default_config(scope);

        let (tx, rx) = mpsc::channel();
        let input =
            RepeaterUiInput::new("GET", format!("http://127.0.0.1:{}/drop-rx", port), "", "");
        let _ = controller.dispatch(input, Some(Arc::new(tx))).unwrap();

        // Receive Started event, then immediately drop the Receiver before worker finishes
        let first = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(first, RepeaterEvent::Started { request_id: 1 });
        drop(rx);

        // Unblock server response
        barrier.wait();
        server_thread.join().unwrap();

        // Wait briefly via state check for worker to finish cleanly without panicking
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while controller.is_in_flight() && std::time::Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }

        assert!(!controller.is_in_flight());
        assert_eq!(
            controller.snapshot_state().lifecycle,
            RepeaterLifecycle::Completed
        );
        assert_eq!(controller.snapshot_state().status_code, Some(200));
    }

    #[test]
    fn test_m6_spawn_failure_does_not_overwrite_subsequent_request() {
        let scope = Arc::new(AuditScope::default());
        let controller = RepeaterTaskController::with_default_config(scope);

        // Part 1: When ONLY Request A (request_id = 1) is active and its thread spawn fails:
        // Simulate the exact sequence up to `thread::Builder::spawn` failing:
        assert!(!controller.is_in_flight());
        controller.in_flight.store(true, Ordering::SeqCst);
        let req_id_a = controller.next_request_id.fetch_add(1, Ordering::SeqCst);
        assert_eq!(req_id_a, 1);

        let cancel_a = Arc::new(AtomicBool::new(false));
        *controller.active_slot.lock().unwrap() = Some(ActiveExecutionSlot {
            request_id: req_id_a,
            cancel_flag: Arc::clone(&cancel_a),
        });

        let guard_a = WorkerFlightGuard::new(
            req_id_a,
            Arc::clone(&controller.in_flight),
            Arc::clone(&controller.active_slot),
            Arc::clone(&controller.view_state),
        );

        let input_a = RepeaterUiInput::new("GET", "http://127.0.0.1:8989/req-a", "", "");
        {
            let mut state = controller.view_state.lock().unwrap();
            state.input = input_a.clone();
            assert!(state.apply_event(&RepeaterEvent::Started {
                request_id: req_id_a
            }));
        }

        // Unspawned closure is dropped when `spawn` fails -> `guard_a` drops first
        drop(guard_a);
        assert!(!controller.is_in_flight());
        assert_eq!(controller.active_request_id(), None);

        // `finalize_spawn_failure` runs while `active_request_id` is still 1 (no overlapping Request B yet)
        let (sink_a_tx, sink_a_rx) = mpsc::channel();
        let sink_a: Arc<dyn RepeaterEventSink> = Arc::new(sink_a_tx);
        let err_a = controller.finalize_spawn_failure(
            req_id_a,
            "simulated OS thread exhaustion".to_string(),
            Some(&sink_a),
        );
        assert!(matches!(err_a, RepeaterAdapterError::WorkerSpawnFailed(_)));

        // Verify `WorkerSpawnFailed` (not `WorkerPanicked`) is recorded when Request A is still current
        let snap_a = controller.snapshot_state();
        assert_eq!(snap_a.active_request_id, 1);
        assert_eq!(snap_a.lifecycle, RepeaterLifecycle::Failed);
        assert_eq!(
            snap_a.last_error,
            Some(RepeaterAdapterError::WorkerSpawnFailed(
                "simulated OS thread exhaustion".to_string()
            ))
        );
        assert_eq!(snap_a.error_message, err_a.safe_display_message());

        let sink_ev_a = sink_a_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(
            sink_ev_a,
            RepeaterEvent::Failed {
                request_id: 1,
                error: err_a,
            }
        );

        // Part 2: Interleaved race — Request A2 (request_id = 2) fails to spawn, its `WorkerFlightGuard`
        // drops and releases `in_flight`, Request B (request_id = 3) starts and enters `Running`,
        // and ONLY THEN does `finalize_spawn_failure` for Request A2 execute.
        controller.in_flight.store(true, Ordering::SeqCst);
        let req_id_a2 = controller.next_request_id.fetch_add(1, Ordering::SeqCst);
        assert_eq!(req_id_a2, 2);

        let cancel_a2 = Arc::new(AtomicBool::new(false));
        *controller.active_slot.lock().unwrap() = Some(ActiveExecutionSlot {
            request_id: req_id_a2,
            cancel_flag: Arc::clone(&cancel_a2),
        });

        let guard_a2 = WorkerFlightGuard::new(
            req_id_a2,
            Arc::clone(&controller.in_flight),
            Arc::clone(&controller.active_slot),
            Arc::clone(&controller.view_state),
        );

        let input_a2 = RepeaterUiInput::new("GET", "http://127.0.0.1:8989/req-a2", "", "");
        {
            let mut state = controller.view_state.lock().unwrap();
            state.input = input_a2;
            assert!(state.apply_event(&RepeaterEvent::Started {
                request_id: req_id_a2
            }));
        }

        // `spawn` fails for A2 -> closure drops -> `guard_a2` releases `in_flight`
        drop(guard_a2);
        assert!(!controller.is_in_flight());

        // Before `finalize_spawn_failure(req_id_a2)` runs, Request B (request_id = 3) is dispatched
        // and held in `Running` via a deterministic barrier
        let worker_started = Arc::new(Barrier::new(2));
        let worker_started_clone = Arc::clone(&worker_started);
        let allow_worker_finish = Arc::new(Barrier::new(2));
        let allow_worker_finish_clone = Arc::clone(&allow_worker_finish);

        let (sink_b_tx, sink_b_rx) = mpsc::channel();
        let input_b = RepeaterUiInput::new(
            "POST",
            "http://127.0.0.1:8989/req-b",
            "Content-Type: text/plain",
            "payload-b",
        );
        let req_id_b = controller
            .dispatch_with_executor(
                input_b.clone(),
                Some(Arc::new(sink_b_tx)),
                move |_spec, cancel_flag| {
                    worker_started_clone.wait();
                    allow_worker_finish_clone.wait();
                    assert!(
                        !cancel_flag.load(Ordering::SeqCst),
                        "Late spawn failure of A2 must not cancel Request B"
                    );
                    Ok(*dummy_execution_result(200, b"response-b"))
                },
            )
            .expect("Request B should dispatch cleanly");
        assert_eq!(req_id_b, 3);

        // Wait until Request B's worker is actively running
        worker_started.wait();
        let ev_b_started = sink_b_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(ev_b_started, RepeaterEvent::Started { request_id: 3 });

        // Now execute the delayed `finalize_spawn_failure` for Request A2 (request_id = 2)
        let (late_sink_tx, late_sink_rx) = mpsc::channel();
        let late_sink: Arc<dyn RepeaterEventSink> = Arc::new(late_sink_tx);
        let late_err_a2 = controller.finalize_spawn_failure(
            req_id_a2,
            "late thread spawn error".to_string(),
            Some(&late_sink),
        );
        assert!(matches!(
            late_err_a2,
            RepeaterAdapterError::WorkerSpawnFailed(_)
        ));

        // Verify Request B's `view_state` was NOT overwritten by A2's delayed spawn failure
        let snap_during_b = controller.snapshot_state();
        assert_eq!(snap_during_b.active_request_id, 3);
        assert_eq!(snap_during_b.lifecycle, RepeaterLifecycle::Running);
        assert_eq!(snap_during_b.input, input_b);
        assert_eq!(snap_during_b.last_error, None);
        assert!(snap_during_b.error_message.is_empty());
        assert!(controller.is_in_flight());
        assert_eq!(controller.active_request_id(), Some(3));

        // Verify the late sink notification carries `request_id = 2` and is rejected as stale by a consumer state
        let late_sink_ev = late_sink_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(late_sink_ev.request_id(), 2);
        let mut consumer_view = snap_during_b.clone();
        assert!(!consumer_view.apply_event(&late_sink_ev));
        assert_eq!(consumer_view.active_request_id, 3);
        assert_eq!(consumer_view.lifecycle, RepeaterLifecycle::Running);

        // Allow Request B to finish and verify normal completion
        allow_worker_finish.wait();
        let ev_b_done = sink_b_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(
            ev_b_done,
            RepeaterEvent::Completed { request_id: 3, .. }
        ));
        assert!(!controller.is_in_flight());
        let snap_after_b = controller.snapshot_state();
        assert_eq!(snap_after_b.active_request_id, 3);
        assert_eq!(snap_after_b.lifecycle, RepeaterLifecycle::Completed);
        assert_eq!(snap_after_b.status_code, Some(200));
        assert_eq!(snap_after_b.response_body_preview, "response-b");
    }
}
