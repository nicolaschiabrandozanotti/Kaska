//! Pure domain conversion engine bridging Inspector captured transactions
//! to normalized, editable Repeater input specifications.
//!
//! # Architecture and Invariants
//! 1. **Pure Conversion:** Operates strictly on in-memory representations; never sends network traffic.
//! 2. **Fail-Closed Verification:** Rejects incomplete captures, conflicting/ambiguous framing,
//!    unsupported methods/schemes, and authority/scope mismatches.
//! 3. **Normalized Output:** Produces an editable specification; does NOT claim byte-for-byte wire equality.
//! 4. **Opaque Error Reporting:** `BridgeError` never leaks raw user data, tokens, URLs, or request bodies.
//! 5. **Privacy Enforcement:** Respects `BridgePrivacyPolicy` (defaults to `ExcludeSensitiveHeaders`).

use std::fmt;
use thiserror::Error;

use kaska_http::models::{HttpHeader, HttpMethod, HttpRequest, HttpTransaction, TransactionState};
use kaska_http::repeater::RepeaterConfig;
use kaska_http::scope::AuditScope;

use crate::controller::repeater_adapter::RepeaterUiInput;
use crate::privacy;

/// Policy controlling whether sensitive headers are stripped or retained during bridge conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BridgePrivacyPolicy {
    /// Strips all identified sensitive headers (Authorization, Cookie, API keys, etc.).
    #[default]
    ExcludeSensitiveHeaders,
    /// Retains sensitive headers in the converted draft (requires explicit operator confirmation).
    IncludeSensitiveHeaders,
}

/// Opaque error types for the Inspector -> Repeater bridge.
///
/// **Security Invariant:** No variant includes raw URLs, header values, tokens, or body contents.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BridgeError {
    #[error("Transaction is in pending state")]
    TransactionPending,

    #[error("Transaction failed during capture")]
    TransactionFailed,

    #[error("Request contains Transfer-Encoding framing which cannot be verified for capture completeness")]
    UnsupportedTransferEncoding,

    #[error("Conflicting framing: both Content-Length and Transfer-Encoding headers are present")]
    ConflictingFramingHeaders,

    #[error("Multiple or conflicting Content-Length headers present")]
    DuplicateContentLengthHeader,

    #[error("Invalid Content-Length header format")]
    InvalidContentLengthHeader,

    #[error("Content-Length does not match retained buffer length")]
    ContentLengthMismatch,

    #[error("Non-empty request body present without explicit Content-Length framing")]
    MissingFramingForBody,

    #[error("Request body is empty for a method requiring explicit payload")]
    UnexpectedEmptyBody,

    #[error("Request body exceeds Repeater maximum capacity limit")]
    RequestBodyTooLarge,

    #[error("Request body contains invalid UTF-8 sequences")]
    NonUtf8RequestBody,

    #[error("Request body contains binary control characters")]
    BinaryControlCharactersInBody,

    #[error("HTTPS scheme, CONNECT, or unsupported scheme cannot be bridged to HTTP Repeater")]
    UnsupportedSchemeOrMethod,

    #[error("Target URL authority does not match Host header or request.host")]
    AuthorityMismatch,

    #[error("Target host or port is outside authorized loopback scope or Repeater whitelist")]
    TargetHostOutOfScope,

    #[error("Missing host authority in request")]
    MissingHostAuthority,

    #[error("Multiple conflicting Host headers detected")]
    DuplicateHostHeader,

    #[error("Invalid characters or inconsistent path/query in target URL")]
    InvalidTargetUrl,

    #[error("Malformed header line detected")]
    MalformedHeader,

    #[error("Aggregated headers exceed Repeater budget limit")]
    HeadersTooLarge,

    #[error("HTTP method is not supported by Repeater")]
    UnsupportedMethod,

    #[error("Repeater draft changed concurrently during confirmation")]
    DraftConflict,

    #[error("Repeater engine validation rejected the converted specification")]
    EngineRejected,
}

/// Immutable snapshot of the four fields of the Repeater editor used for exact in-memory comparison.
///
/// **Security Invariant:** Does NOT derive `Debug` with raw fields to prevent leaking sensitive
/// bodies, URLs, or credentials in logs. Implements an explicit redacted `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct RepeaterDraftSnapshot {
    pub method: String,
    pub target_url: String,
    pub headers_raw: String,
    pub body_utf8: String,
}

impl fmt::Debug for RepeaterDraftSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RepeaterDraftSnapshot")
            .field("method_len", &self.method.len())
            .field("target_url_len", &self.target_url.len())
            .field("headers_len", &self.headers_raw.len())
            .field("body_len", &self.body_utf8.len())
            .field("content", &"[REDACTED_DRAFT_CONTENT]")
            .finish()
    }
}

impl RepeaterDraftSnapshot {
    /// Creates a snapshot from current `RepeaterUiInput`.
    pub fn from_ui(input: &RepeaterUiInput) -> Self {
        Self {
            method: input.method.clone(),
            target_url: input.target_url.clone(),
            headers_raw: input.headers_raw.clone(),
            body_utf8: input.body_utf8.clone(),
        }
    }

    /// Checks if this snapshot exactly matches the clean default input of Kaska Repeater.
    pub fn is_clean_default(&self) -> bool {
        let def = RepeaterUiInput::default();
        self.method == def.method
            && self.target_url == def.target_url
            && self.headers_raw == def.headers_raw
            && self.body_utf8 == def.body_utf8
    }
}

/// Ephemeral in-memory intent for a two-step confirmation.
///
/// **Security Invariant:** Does NOT persist converted bodies or sensitive credentials.
#[derive(Clone, PartialEq, Eq)]
pub struct StagedBridgeIntent {
    pub transaction_id: u64,
    pub privacy_policy: BridgePrivacyPolicy,
    pub expected_draft: RepeaterDraftSnapshot,
}

impl fmt::Debug for StagedBridgeIntent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StagedBridgeIntent")
            .field("transaction_id", &self.transaction_id)
            .field("privacy_policy", &self.privacy_policy)
            .field("expected_draft", &self.expected_draft)
            .finish()
    }
}

/// Parsed, validated host and port representing an HTTP target authority.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedAuthority {
    /// Canonical host without brackets or port (e.g. `127.0.0.1`, `localhost`, `::1`).
    canonical_host: String,
    /// Effective TCP port number (defaulting to 80 for HTTP).
    port: u16,
    /// Whether the port was explicitly declared.
    explicit_port: bool,
}

impl ParsedAuthority {
    /// Parses an authority string (`host` or `host:port`) with support for bracketed IPv6.
    fn parse(raw: &str) -> Result<Self, BridgeError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(BridgeError::MissingHostAuthority);
        }

        // Reject userinfo (@) in authority
        if trimmed.contains('@') {
            return Err(BridgeError::AuthorityMismatch);
        }

        if let Some(rest) = trimmed.strip_prefix('[') {
            // Bracketed IPv6: "[::1]" or "[::1]:8080"
            let close_bracket = rest.find(']').ok_or(BridgeError::AuthorityMismatch)?;
            let ip_str = &rest[..close_bracket];
            let after = &rest[close_bracket + 1..];

            let (port, explicit_port) = if after.is_empty() {
                (80, false)
            } else if let Some(port_str) = after.strip_prefix(':') {
                let p = port_str
                    .parse::<u16>()
                    .map_err(|_| BridgeError::AuthorityMismatch)?;
                if p == 0 {
                    return Err(BridgeError::AuthorityMismatch);
                }
                (p, true)
            } else {
                return Err(BridgeError::AuthorityMismatch);
            };

            // Validate that ip_str is valid IPv6
            if ip_str.parse::<std::net::Ipv6Addr>().is_err() {
                return Err(BridgeError::AuthorityMismatch);
            }

            Ok(Self {
                canonical_host: ip_str.to_lowercase(),
                port,
                explicit_port,
            })
        } else {
            // IPv4 or hostname
            if let Some((h, p_str)) = trimmed.rsplit_once(':') {
                if !h.contains(':') {
                    // host:port
                    let p = p_str
                        .parse::<u16>()
                        .map_err(|_| BridgeError::AuthorityMismatch)?;
                    if p == 0 {
                        return Err(BridgeError::AuthorityMismatch);
                    }
                    Ok(Self {
                        canonical_host: h.trim().to_ascii_lowercase(),
                        port: p,
                        explicit_port: true,
                    })
                } else {
                    // Raw IPv6 without brackets but with colons is invalid in authority
                    Err(BridgeError::AuthorityMismatch)
                }
            } else {
                // Host without explicit port
                Ok(Self {
                    canonical_host: trimmed.to_ascii_lowercase(),
                    port: 80,
                    explicit_port: false,
                })
            }
        }
    }

    /// Formats authority as normalized for RFC 9112 Host header (`host` or `host:port`).
    fn to_host_header_value(&self) -> String {
        let is_ipv6 = self.canonical_host.contains(':');
        let host_repr = if is_ipv6 {
            format!("[{}]", self.canonical_host)
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

/// Converts a captured `HttpTransaction` into a validated `RepeaterUiInput`.
///
/// # Guarantees
/// - Pure function: Zero side-effects, no network sockets.
/// - Full verification of HTTP framing and life-cycle state.
/// - Preserves sensitive headers ONLY if `privacy == BridgePrivacyPolicy::IncludeSensitiveHeaders`.
/// - Excludes `Content-Length`, `Transfer-Encoding`, hop-by-hop headers, and dynamic Connection members.
pub fn convert_transaction_to_repeater_input(
    tx: &HttpTransaction,
    privacy: BridgePrivacyPolicy,
    scope: &AuditScope,
    config: &RepeaterConfig,
) -> Result<RepeaterUiInput, BridgeError> {
    // 1. Transaction Life-Cycle State check
    match &tx.state {
        TransactionState::Pending => return Err(BridgeError::TransactionPending),
        TransactionState::Failed(_) => return Err(BridgeError::TransactionFailed),
        TransactionState::Completed => {}
    }

    let req = &tx.request;

    // 2. HTTP Method validation
    let method_str = match &req.method {
        HttpMethod::Get => "GET",
        HttpMethod::Post => "POST",
        HttpMethod::Put => "PUT",
        HttpMethod::Delete => "DELETE",
        HttpMethod::Patch => "PATCH",
        HttpMethod::Head => "HEAD",
        HttpMethod::Options => "OPTIONS",
        HttpMethod::Connect => return Err(BridgeError::UnsupportedSchemeOrMethod),
        HttpMethod::Custom(_) => return Err(BridgeError::UnsupportedMethod),
    };

    // 3. Pre-filter header validation: All headers must be structurally valid before any stripping
    validate_all_raw_headers(&req.headers)?;

    // 4. Framing and Content-Length / Transfer-Encoding audit
    verify_framing_and_body_integrity(req, config)?;

    // 5. Authority, Host header, URL, and Scope reconciliation
    let (authority, path_and_query) = reconcile_authority_and_target_url(req, scope)?;

    // Construct normalized target URL: http://authority/path?query
    let target_url = format!(
        "http://{}{}",
        authority.to_host_header_value(),
        path_and_query
    );

    // 6. Header transformation and incremental budget accounting
    let headers_raw = transform_headers(&req.headers, &authority, privacy, config)?;

    // 7. Body encoding verification
    let body_utf8 = verify_and_extract_body(&req.body, config)?;

    // 8. Construct RepeaterUiInput
    let input = RepeaterUiInput::new(method_str, target_url, headers_raw, body_utf8);

    // 9. Secondary sanity check against Repeater bounds
    input
        .validate_bounds(config)
        .map_err(|_| BridgeError::EngineRejected)?;

    Ok(input)
}

/// Checks whether a byte is a valid RFC 9110 token character for header names.
#[inline]
fn is_token_char(b: u8) -> bool {
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

/// Validates that all headers are well-formed before any exclusion is performed.
fn validate_all_raw_headers(headers: &[HttpHeader]) -> Result<(), BridgeError> {
    for h in headers {
        let name = h.name.trim();
        if name.is_empty() {
            return Err(BridgeError::MalformedHeader);
        }
        // Name must be composed strictly of RFC 9110 token characters
        if !name.bytes().all(is_token_char) {
            return Err(BridgeError::MalformedHeader);
        }
        // Value must not contain CR, LF, NUL, controls < 0x20 except TAB, or DEL 0x7F
        for b in h.value.bytes() {
            if b == b'\r' || b == b'\n' || b == 0x00 || (b < 0x20 && b != b'\t') || b == 0x7F {
                return Err(BridgeError::MalformedHeader);
            }
        }
    }
    Ok(())
}

/// Verifies framing integrity of the request according to RFC 9112 and Milestone 1.4C rules.
fn verify_framing_and_body_integrity(
    req: &HttpRequest,
    config: &RepeaterConfig,
) -> Result<(), BridgeError> {
    let mut cl_count = 0usize;
    let mut cl_value: Option<usize> = None;
    let mut has_te = false;

    for h in &req.headers {
        let lower = h.name.trim().to_ascii_lowercase();
        if lower == "content-length" {
            cl_count += 1;
            let val_str = h.value.trim();
            if val_str.is_empty() {
                return Err(BridgeError::InvalidContentLengthHeader);
            }
            if val_str.contains(',') {
                return Err(BridgeError::DuplicateContentLengthHeader);
            }
            // Strict decimal: non-empty sequence of ASCII digits 0-9 only (no signs, letters, or hex)
            if !val_str.bytes().all(|b| b.is_ascii_digit()) {
                return Err(BridgeError::InvalidContentLengthHeader);
            }
            let parsed = val_str
                .parse::<usize>()
                .map_err(|_| BridgeError::InvalidContentLengthHeader)?;
            cl_value = Some(parsed);
        } else if lower == "transfer-encoding" {
            has_te = true;
        }
    }

    if cl_count > 1 {
        return Err(BridgeError::DuplicateContentLengthHeader);
    }

    if has_te && cl_count > 0 {
        return Err(BridgeError::ConflictingFramingHeaders);
    }

    if has_te {
        // Any Transfer-Encoding (including chunked) cannot be verified for capture completeness
        return Err(BridgeError::UnsupportedTransferEncoding);
    }

    let body_len = req.body.len();

    if let Some(expected_cl) = cl_value {
        if expected_cl != body_len {
            return Err(BridgeError::ContentLengthMismatch);
        }
    } else {
        // Neither Content-Length nor Transfer-Encoding is present
        if body_len > 0 {
            return Err(BridgeError::MissingFramingForBody);
        }
        // Body is empty: verify if method permits empty payload without framing
        match req.method {
            HttpMethod::Post | HttpMethod::Put | HttpMethod::Patch => {
                return Err(BridgeError::UnexpectedEmptyBody);
            }
            _ => {}
        }
    }

    if body_len > config.max_request_body_bytes {
        return Err(BridgeError::RequestBodyTooLarge);
    }

    Ok(())
}

/// Reconciles authority between `raw_url`, `request.host`, and the `Host` header.
fn reconcile_authority_and_target_url(
    req: &HttpRequest,
    scope: &AuditScope,
) -> Result<(ParsedAuthority, String), BridgeError> {
    let raw_url = req.raw_url.as_str();
    if raw_url.is_empty() {
        return Err(BridgeError::InvalidTargetUrl);
    }

    // Reject control characters, whitespace, backslash, and fragments in raw_url
    if raw_url
        .chars()
        .any(|ch| ch.is_control() || ch.is_whitespace() || ch == '\\' || ch == '#')
    {
        return Err(BridgeError::InvalidTargetUrl);
    }

    // Reject control characters, whitespace, backslash, and fragments in req.path and req.query
    if req
        .path
        .chars()
        .any(|ch| ch.is_control() || ch.is_whitespace() || ch == '\\' || ch == '#')
    {
        return Err(BridgeError::InvalidTargetUrl);
    }
    if req
        .query
        .chars()
        .any(|ch| ch.is_control() || ch.is_whitespace() || ch == '\\' || ch == '#')
    {
        return Err(BridgeError::InvalidTargetUrl);
    }

    // 1. Audit Host headers
    let mut host_header_count = 0usize;
    let mut host_header_val: Option<&str> = None;

    for h in &req.headers {
        if h.name.trim().eq_ignore_ascii_case("host") {
            host_header_count += 1;
            host_header_val = Some(h.value.trim());
        }
    }

    if host_header_count == 0 {
        return Err(BridgeError::MissingHostAuthority);
    }
    if host_header_count > 1 {
        return Err(BridgeError::DuplicateHostHeader);
    }

    let host_header = host_header_val.unwrap();
    let auth_from_header = ParsedAuthority::parse(host_header)?;

    // 2. Parse request.host
    let auth_from_req_host = ParsedAuthority::parse(&req.host)?;

    // Compare canonical host and port
    if auth_from_header.canonical_host != auth_from_req_host.canonical_host
        || auth_from_header.port != auth_from_req_host.port
    {
        return Err(BridgeError::AuthorityMismatch);
    }

    // 3. Absolute-form vs origin-form check on raw_url
    let (target_path, target_query) =
        if let Some((scheme_raw, after_scheme)) = raw_url.split_once("://") {
            let scheme_lower = scheme_raw.to_ascii_lowercase();
            if scheme_lower == "https" {
                return Err(BridgeError::UnsupportedSchemeOrMethod);
            }
            if scheme_lower != "http" {
                return Err(BridgeError::UnsupportedSchemeOrMethod);
            }

            if after_scheme.is_empty() {
                return Err(BridgeError::InvalidTargetUrl);
            }

            let (raw_auth, raw_path_and_query) = match after_scheme.find('/') {
                Some(slash_idx) => (&after_scheme[..slash_idx], &after_scheme[slash_idx..]),
                None => {
                    if after_scheme.contains('?') {
                        return Err(BridgeError::InvalidTargetUrl);
                    }
                    (after_scheme, "/")
                }
            };

            if raw_auth.is_empty() {
                return Err(BridgeError::MissingHostAuthority);
            }

            if raw_auth.contains('@') {
                return Err(BridgeError::AuthorityMismatch);
            }

            let auth_from_raw_url = ParsedAuthority::parse(raw_auth)?;
            if auth_from_raw_url.canonical_host != auth_from_header.canonical_host
                || auth_from_raw_url.port != auth_from_header.port
            {
                return Err(BridgeError::AuthorityMismatch);
            }

            let (extracted_path, extracted_query) = match raw_path_and_query.split_once('?') {
                Some((p, q)) => (p, q),
                None => (raw_path_and_query, ""),
            };

            (extracted_path.to_string(), extracted_query.to_string())
        } else {
            // Origin-form: must start with '/'
            if !raw_url.starts_with('/') {
                return Err(BridgeError::InvalidTargetUrl);
            }

            let (extracted_path, extracted_query) = match raw_url.split_once('?') {
                Some((p, q)) => (p, q),
                None => (raw_url, ""),
            };

            (extracted_path.to_string(), extracted_query.to_string())
        };

    // Coherence check with structured fields req.path and req.query
    let expected_path = if req.path.is_empty() {
        "/"
    } else {
        req.path.as_str()
    };
    if target_path != expected_path {
        return Err(BridgeError::InvalidTargetUrl);
    }
    if target_query != req.query {
        return Err(BridgeError::InvalidTargetUrl);
    }

    // Path must start with '/'
    if !target_path.starts_with('/') {
        return Err(BridgeError::InvalidTargetUrl);
    }

    // Preserve explicit query:
    // If raw_url ends with '?' and query is empty, preserve the trailing '?' (e.g. /api? -> /api?)
    let path_and_query = if target_query.is_empty() {
        if raw_url.contains('?') {
            format!("{}?", target_path)
        } else {
            target_path
        }
    } else {
        format!("{}?{}", target_path, target_query)
    };

    // 4. Verify scope enforcement
    if !scope.is_allowed_host(&auth_from_header.canonical_host) {
        return Err(BridgeError::TargetHostOutOfScope);
    }

    // 5. Intersect with HttpRepeaterEngine strict whitelist:
    // Only "127.0.0.1", "localhost", "::1" are permitted.
    let h = auth_from_header.canonical_host.as_str();
    if h != "127.0.0.1" && h != "localhost" && h != "::1" {
        return Err(BridgeError::TargetHostOutOfScope);
    }

    Ok((auth_from_header, path_and_query))
}

/// Transforms headers by stripping hop-by-hop, dynamic connection members, framing,
/// and credentials (if policy dictates). Emits Host as the first header line.
///
/// Incremental byte accounting enforces `config.max_header_bytes` before allocation.
fn transform_headers(
    headers: &[HttpHeader],
    authority: &ParsedAuthority,
    privacy: BridgePrivacyPolicy,
    config: &RepeaterConfig,
) -> Result<String, BridgeError> {
    // 1. Collect dynamic tokens from Connection headers
    let mut dynamic_connection_tokens = Vec::new();
    for h in headers {
        if h.name.trim().eq_ignore_ascii_case("connection") {
            for token in h.value.split(',') {
                let t = token.trim().to_ascii_lowercase();
                if !t.is_empty() {
                    dynamic_connection_tokens.push(t);
                }
            }
        }
    }

    // 2. Filter retained headers and track their (name, value) references
    let mut retained_headers: Vec<(&str, &str)> = Vec::new();

    for h in headers {
        let name_trimmed = h.name.trim();
        let lower = name_trimmed.to_ascii_lowercase();

        // Always skip Host because it is prepended canonically
        if lower == "host" {
            continue;
        }

        // Always skip framing headers (Content-Length and Transfer-Encoding)
        if lower == "content-length" || lower == "transfer-encoding" {
            continue;
        }

        // Always skip hop-by-hop and proxy headers
        if matches!(
            lower.as_str(),
            "connection"
                | "keep-alive"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "te"
                | "trailer"
                | "upgrade"
                | "proxy-connection"
                | "expect"
                | "http2-settings"
        ) {
            continue;
        }

        // Always skip dynamic members nominated in Connection
        if dynamic_connection_tokens.iter().any(|t| t == &lower) {
            continue;
        }

        // Privacy check
        if privacy == BridgePrivacyPolicy::ExcludeSensitiveHeaders
            && privacy::is_sensitive_header(name_trimmed)
        {
            continue;
        }

        retained_headers.push((name_trimmed, h.value.trim()));
    }

    // 3. Incremental accounting with checked arithmetic
    // Host line: "Host: <authority.to_host_header_value()>"
    let auth_str = authority.to_host_header_value();
    let host_line_len = 6usize
        .checked_add(auth_str.len())
        .ok_or(BridgeError::HeadersTooLarge)?;

    if host_line_len > config.max_header_bytes {
        return Err(BridgeError::HeadersTooLarge);
    }

    let mut total_bytes = host_line_len;

    for (name, val) in &retained_headers {
        // Line addition adds separating '\n', name, ": ", and val
        let line_content_len = name
            .len()
            .checked_add(2)
            .ok_or(BridgeError::HeadersTooLarge)?
            .checked_add(val.len())
            .ok_or(BridgeError::HeadersTooLarge)?;
        let line_with_delim = line_content_len
            .checked_add(1) // for separating '\n'
            .ok_or(BridgeError::HeadersTooLarge)?;

        let new_total = total_bytes
            .checked_add(line_with_delim)
            .ok_or(BridgeError::HeadersTooLarge)?;

        if new_total > config.max_header_bytes {
            return Err(BridgeError::HeadersTooLarge);
        }
        total_bytes = new_total;
    }

    // 4. Construct output string in exact pre-allocated buffer
    let mut out = String::with_capacity(total_bytes);
    out.push_str("Host: ");
    out.push_str(&auth_str);

    for (name, val) in retained_headers {
        out.push('\n');
        out.push_str(name);
        out.push_str(": ");
        out.push_str(val);
    }

    debug_assert_eq!(out.len(), total_bytes);

    Ok(out)
}

/// Validates that body contains valid UTF-8 and no binary control characters.
fn verify_and_extract_body(body: &[u8], config: &RepeaterConfig) -> Result<String, BridgeError> {
    if body.is_empty() {
        return Ok(String::new());
    }

    if body.len() > config.max_request_body_bytes {
        return Err(BridgeError::RequestBodyTooLarge);
    }

    let text = std::str::from_utf8(body).map_err(|_| BridgeError::NonUtf8RequestBody)?;

    // Reject binary control characters (< 0x20 except \r, \n, \t, or DEL 0x7F)
    if text
        .bytes()
        .any(|b| (b < 0x20 && b != b'\r' && b != b'\n' && b != b'\t') || b == 0x7F)
    {
        return Err(BridgeError::BinaryControlCharactersInBody);
    }

    Ok(text.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaska_http::models::HttpHeader;

    fn make_test_tx(
        method: HttpMethod,
        raw_url: &str,
        host: &str,
        headers: Vec<HttpHeader>,
        body: Vec<u8>,
        state: TransactionState,
    ) -> HttpTransaction {
        let path_and_query = if let Some((_scheme, rest)) = raw_url.split_once("://") {
            match rest.find('/') {
                Some(idx) => &rest[idx..],
                None => "/",
            }
        } else {
            raw_url
        };
        let (path, query) = match path_and_query.split_once('?') {
            Some((p, q)) => (p.to_string(), q.to_string()),
            None => (path_and_query.to_string(), String::new()),
        };

        HttpTransaction {
            id: 1,
            timestamp_rfc3339: "2026-10-21T00:00:00Z".to_string(),
            request: HttpRequest {
                method,
                raw_url: raw_url.to_string(),
                host: host.to_string(),
                path,
                query,
                http_version: "HTTP/1.1".to_string(),
                headers,
                body,
            },
            response: None,
            duration_ms: 10,
            state,
        }
    }

    #[test]
    fn test_t01_get_request_normalization_omits_content_length() {
        let scope = AuditScope::default();
        let config = RepeaterConfig::default();

        let tx = make_test_tx(
            HttpMethod::Get,
            "/api/status?verbose=true",
            "127.0.0.1:8989",
            vec![
                HttpHeader::new("Host", "127.0.0.1:8989"),
                HttpHeader::new("Accept", "application/json"),
            ],
            vec![],
            TransactionState::Completed,
        );

        let res = convert_transaction_to_repeater_input(
            &tx,
            BridgePrivacyPolicy::ExcludeSensitiveHeaders,
            &scope,
            &config,
        )
        .expect("T-01 should succeed");

        assert_eq!(res.method, "GET");
        assert_eq!(
            res.target_url,
            "http://127.0.0.1:8989/api/status?verbose=true"
        );
        assert!(res.headers_raw.starts_with("Host: 127.0.0.1:8989"));
        assert!(res.headers_raw.contains("Accept: application/json"));
        assert!(!res.headers_raw.contains("Content-Length"));
        assert_eq!(res.body_utf8, "");
    }

    #[test]
    fn test_t02_post_request_body_utf8_retained_content_length_omitted() {
        let scope = AuditScope::default();
        let config = RepeaterConfig::default();
        let payload = "{\"status\":\"ok\"}";

        let tx = make_test_tx(
            HttpMethod::Post,
            "/api/submit",
            "127.0.0.1:8989",
            vec![
                HttpHeader::new("Host", "127.0.0.1:8989"),
                HttpHeader::new("Content-Type", "application/json"),
                HttpHeader::new("Content-Length", payload.len().to_string()),
            ],
            payload.as_bytes().to_vec(),
            TransactionState::Completed,
        );

        let res = convert_transaction_to_repeater_input(
            &tx,
            BridgePrivacyPolicy::ExcludeSensitiveHeaders,
            &scope,
            &config,
        )
        .expect("T-02 should succeed");

        assert_eq!(res.method, "POST");
        assert_eq!(res.body_utf8, payload);
        // RepeaterUiInput headers_raw must NOT contain Content-Length
        assert!(!res.headers_raw.contains("Content-Length"));
    }

    #[test]
    fn test_t03_rejects_pending_transaction() {
        let scope = AuditScope::default();
        let config = RepeaterConfig::default();

        let tx = make_test_tx(
            HttpMethod::Get,
            "/api",
            "127.0.0.1:8989",
            vec![HttpHeader::new("Host", "127.0.0.1:8989")],
            vec![],
            TransactionState::Pending,
        );

        let err = convert_transaction_to_repeater_input(
            &tx,
            BridgePrivacyPolicy::ExcludeSensitiveHeaders,
            &scope,
            &config,
        )
        .unwrap_err();

        assert_eq!(err, BridgeError::TransactionPending);
    }

    #[test]
    fn test_t04_rejects_failed_transaction_without_data_leak() {
        let scope = AuditScope::default();
        let config = RepeaterConfig::default();

        let tx = make_test_tx(
            HttpMethod::Get,
            "/api",
            "127.0.0.1:8989",
            vec![HttpHeader::new("Host", "127.0.0.1:8989")],
            vec![],
            TransactionState::Failed("Sensitive OS I/O error trace with tokens".to_string()),
        );

        let err = convert_transaction_to_repeater_input(
            &tx,
            BridgePrivacyPolicy::ExcludeSensitiveHeaders,
            &scope,
            &config,
        )
        .unwrap_err();

        assert_eq!(err, BridgeError::TransactionFailed);
        // Verify Display does not leak inner string
        assert_eq!(err.to_string(), "Transaction failed during capture");
    }

    #[test]
    fn test_t05_content_length_mismatch_rejected() {
        let scope = AuditScope::default();
        let config = RepeaterConfig::default();

        let tx = make_test_tx(
            HttpMethod::Post,
            "/api",
            "127.0.0.1:8989",
            vec![
                HttpHeader::new("Host", "127.0.0.1:8989"),
                HttpHeader::new("Content-Length", "100"),
            ],
            b"short body".to_vec(), // 10 bytes != 100
            TransactionState::Completed,
        );

        let err = convert_transaction_to_repeater_input(
            &tx,
            BridgePrivacyPolicy::ExcludeSensitiveHeaders,
            &scope,
            &config,
        )
        .unwrap_err();

        assert_eq!(err, BridgeError::ContentLengthMismatch);
    }

    #[test]
    fn test_t06_transfer_encoding_chunked_rejected() {
        let scope = AuditScope::default();
        let config = RepeaterConfig::default();

        let tx = make_test_tx(
            HttpMethod::Post,
            "/api",
            "127.0.0.1:8989",
            vec![
                HttpHeader::new("Host", "127.0.0.1:8989"),
                HttpHeader::new("Transfer-Encoding", "chunked"),
            ],
            b"decoded chunk".to_vec(),
            TransactionState::Completed,
        );

        let err = convert_transaction_to_repeater_input(
            &tx,
            BridgePrivacyPolicy::ExcludeSensitiveHeaders,
            &scope,
            &config,
        )
        .unwrap_err();

        assert_eq!(err, BridgeError::UnsupportedTransferEncoding);
    }

    #[test]
    fn test_t07_conflicting_framing_rejected() {
        let scope = AuditScope::default();
        let config = RepeaterConfig::default();

        let tx = make_test_tx(
            HttpMethod::Post,
            "/api",
            "127.0.0.1:8989",
            vec![
                HttpHeader::new("Host", "127.0.0.1:8989"),
                HttpHeader::new("Content-Length", "5"),
                HttpHeader::new("Transfer-Encoding", "chunked"),
            ],
            b"12345".to_vec(),
            TransactionState::Completed,
        );

        let err = convert_transaction_to_repeater_input(
            &tx,
            BridgePrivacyPolicy::ExcludeSensitiveHeaders,
            &scope,
            &config,
        )
        .unwrap_err();

        assert_eq!(err, BridgeError::ConflictingFramingHeaders);
    }

    #[test]
    fn test_t08_duplicate_content_length_rejected() {
        let scope = AuditScope::default();
        let config = RepeaterConfig::default();

        let tx = make_test_tx(
            HttpMethod::Post,
            "/api",
            "127.0.0.1:8989",
            vec![
                HttpHeader::new("Host", "127.0.0.1:8989"),
                HttpHeader::new("Content-Length", "5"),
                HttpHeader::new("Content-Length", "5"),
            ],
            b"12345".to_vec(),
            TransactionState::Completed,
        );

        let err = convert_transaction_to_repeater_input(
            &tx,
            BridgePrivacyPolicy::ExcludeSensitiveHeaders,
            &scope,
            &config,
        )
        .unwrap_err();

        assert_eq!(err, BridgeError::DuplicateContentLengthHeader);
    }

    #[test]
    fn test_t09_non_empty_body_without_framing_rejected() {
        let scope = AuditScope::default();
        let config = RepeaterConfig::default();

        let tx = make_test_tx(
            HttpMethod::Post,
            "/api",
            "127.0.0.1:8989",
            vec![HttpHeader::new("Host", "127.0.0.1:8989")],
            b"unframed payload".to_vec(),
            TransactionState::Completed,
        );

        let err = convert_transaction_to_repeater_input(
            &tx,
            BridgePrivacyPolicy::ExcludeSensitiveHeaders,
            &scope,
            &config,
        )
        .unwrap_err();

        assert_eq!(err, BridgeError::MissingFramingForBody);
    }

    #[test]
    fn test_t10_non_utf8_body_rejected() {
        let scope = AuditScope::default();
        let config = RepeaterConfig::default();
        let invalid_utf8 = vec![0xFF, 0xFE, 0xFD];

        let tx = make_test_tx(
            HttpMethod::Post,
            "/api",
            "127.0.0.1:8989",
            vec![
                HttpHeader::new("Host", "127.0.0.1:8989"),
                HttpHeader::new("Content-Length", "3"),
            ],
            invalid_utf8,
            TransactionState::Completed,
        );

        let err = convert_transaction_to_repeater_input(
            &tx,
            BridgePrivacyPolicy::ExcludeSensitiveHeaders,
            &scope,
            &config,
        )
        .unwrap_err();

        assert_eq!(err, BridgeError::NonUtf8RequestBody);
    }

    #[test]
    fn test_t11_binary_control_characters_in_body_rejected() {
        let scope = AuditScope::default();
        let config = RepeaterConfig::default();
        let binary_control = b"hello\x00world";

        let tx = make_test_tx(
            HttpMethod::Post,
            "/api",
            "127.0.0.1:8989",
            vec![
                HttpHeader::new("Host", "127.0.0.1:8989"),
                HttpHeader::new("Content-Length", binary_control.len().to_string()),
            ],
            binary_control.to_vec(),
            TransactionState::Completed,
        );

        let err = convert_transaction_to_repeater_input(
            &tx,
            BridgePrivacyPolicy::ExcludeSensitiveHeaders,
            &scope,
            &config,
        )
        .unwrap_err();

        assert_eq!(err, BridgeError::BinaryControlCharactersInBody);
    }

    #[test]
    fn test_t12_body_too_large_rejected() {
        let scope = AuditScope::default();
        let config = RepeaterConfig {
            max_request_body_bytes: 100,
            ..Default::default()
        };

        let large_body = vec![b'A'; 150];

        let tx = make_test_tx(
            HttpMethod::Post,
            "/api",
            "127.0.0.1:8989",
            vec![
                HttpHeader::new("Host", "127.0.0.1:8989"),
                HttpHeader::new("Content-Length", "150"),
            ],
            large_body,
            TransactionState::Completed,
        );

        let err = convert_transaction_to_repeater_input(
            &tx,
            BridgePrivacyPolicy::ExcludeSensitiveHeaders,
            &scope,
            &config,
        )
        .unwrap_err();

        assert_eq!(err, BridgeError::RequestBodyTooLarge);
    }

    #[test]
    fn test_t13_https_and_connect_rejected() {
        let scope = AuditScope::default();
        let config = RepeaterConfig::default();

        let tx_https = make_test_tx(
            HttpMethod::Get,
            "https://127.0.0.1:8443/api",
            "127.0.0.1:8443",
            vec![HttpHeader::new("Host", "127.0.0.1:8443")],
            vec![],
            TransactionState::Completed,
        );

        let err1 = convert_transaction_to_repeater_input(
            &tx_https,
            BridgePrivacyPolicy::ExcludeSensitiveHeaders,
            &scope,
            &config,
        )
        .unwrap_err();
        assert_eq!(err1, BridgeError::UnsupportedSchemeOrMethod);

        let tx_connect = make_test_tx(
            HttpMethod::Connect,
            "127.0.0.1:8080",
            "127.0.0.1:8080",
            vec![HttpHeader::new("Host", "127.0.0.1:8080")],
            vec![],
            TransactionState::Completed,
        );

        let err2 = convert_transaction_to_repeater_input(
            &tx_connect,
            BridgePrivacyPolicy::ExcludeSensitiveHeaders,
            &scope,
            &config,
        )
        .unwrap_err();
        assert_eq!(err2, BridgeError::UnsupportedSchemeOrMethod);
    }

    #[test]
    fn test_t14_out_of_scope_or_non_whitelisted_loopback_rejected() {
        let scope = AuditScope::default();
        let config = RepeaterConfig::default();

        // 127.0.0.99 is in loopback subnet but NOT in Repeater whitelist
        let tx = make_test_tx(
            HttpMethod::Get,
            "/api",
            "127.0.0.99:8080",
            vec![HttpHeader::new("Host", "127.0.0.99:8080")],
            vec![],
            TransactionState::Completed,
        );

        let err = convert_transaction_to_repeater_input(
            &tx,
            BridgePrivacyPolicy::ExcludeSensitiveHeaders,
            &scope,
            &config,
        )
        .unwrap_err();

        assert_eq!(err, BridgeError::TargetHostOutOfScope);
    }

    #[test]
    fn test_t15_authority_or_port_mismatch_rejected() {
        let scope = AuditScope::default();
        let config = RepeaterConfig::default();

        // Host header port 8989 vs request.host port 9999
        let tx = make_test_tx(
            HttpMethod::Get,
            "/api",
            "127.0.0.1:9999",
            vec![HttpHeader::new("Host", "127.0.0.1:8989")],
            vec![],
            TransactionState::Completed,
        );

        let err = convert_transaction_to_repeater_input(
            &tx,
            BridgePrivacyPolicy::ExcludeSensitiveHeaders,
            &scope,
            &config,
        )
        .unwrap_err();

        assert_eq!(err, BridgeError::AuthorityMismatch);
    }

    #[test]
    fn test_t16_hop_by_hop_and_connection_members_stripped() {
        let scope = AuditScope::default();
        let config = RepeaterConfig::default();

        let tx = make_test_tx(
            HttpMethod::Get,
            "/api",
            "127.0.0.1:8989",
            vec![
                HttpHeader::new("Host", "127.0.0.1:8989"),
                HttpHeader::new("Connection", "close, X-Custom-Remove"),
                HttpHeader::new("Keep-Alive", "timeout=5"),
                HttpHeader::new("Proxy-Connection", "keep-alive"),
                HttpHeader::new("Expect", "100-continue"),
                HttpHeader::new("HTTP2-Settings", "token"),
                HttpHeader::new("X-Custom-Remove", "drop_me"),
                HttpHeader::new("X-Retained", "keep_me"),
            ],
            vec![],
            TransactionState::Completed,
        );

        let res = convert_transaction_to_repeater_input(
            &tx,
            BridgePrivacyPolicy::ExcludeSensitiveHeaders,
            &scope,
            &config,
        )
        .expect("T-16 should succeed");

        assert!(!res.headers_raw.contains("Connection:"));
        assert!(!res.headers_raw.contains("Keep-Alive:"));
        assert!(!res.headers_raw.contains("Proxy-Connection:"));
        assert!(!res.headers_raw.contains("Expect:"));
        assert!(!res.headers_raw.contains("HTTP2-Settings:"));
        assert!(!res.headers_raw.contains("X-Custom-Remove:"));
        assert!(res.headers_raw.contains("X-Retained: keep_me"));
    }

    #[test]
    fn test_t17_malformed_header_with_cr_or_nul_rejected_before_filtering() {
        let scope = AuditScope::default();
        let config = RepeaterConfig::default();

        let tx = make_test_tx(
            HttpMethod::Get,
            "/api",
            "127.0.0.1:8989",
            vec![
                HttpHeader::new("Host", "127.0.0.1:8989"),
                HttpHeader::new("X-Bad-Header\r\nInjected", "value"),
            ],
            vec![],
            TransactionState::Completed,
        );

        let err = convert_transaction_to_repeater_input(
            &tx,
            BridgePrivacyPolicy::ExcludeSensitiveHeaders,
            &scope,
            &config,
        )
        .unwrap_err();

        assert_eq!(err, BridgeError::MalformedHeader);
    }

    #[test]
    fn test_t18_exclude_sensitive_headers_policy() {
        let scope = AuditScope::default();
        let config = RepeaterConfig::default();

        let tx = make_test_tx(
            HttpMethod::Get,
            "/api",
            "127.0.0.1:8989",
            vec![
                HttpHeader::new("Host", "127.0.0.1:8989"),
                HttpHeader::new("Authorization", "Bearer secret_token"),
                HttpHeader::new("Cookie", "session=admin_123"),
                HttpHeader::new("X-Auth-Token", "jwt_xyz"),
                HttpHeader::new("X-Safe-Header", "public"),
            ],
            vec![],
            TransactionState::Completed,
        );

        let res = convert_transaction_to_repeater_input(
            &tx,
            BridgePrivacyPolicy::ExcludeSensitiveHeaders,
            &scope,
            &config,
        )
        .expect("T-18 should succeed");

        assert!(!res.headers_raw.contains("Authorization"));
        assert!(!res.headers_raw.contains("Cookie"));
        assert!(!res.headers_raw.contains("X-Auth-Token"));
        assert!(res.headers_raw.contains("X-Safe-Header: public"));
    }

    #[test]
    fn test_t19_include_sensitive_headers_policy() {
        let scope = AuditScope::default();
        let config = RepeaterConfig::default();

        let tx = make_test_tx(
            HttpMethod::Get,
            "/api",
            "127.0.0.1:8989",
            vec![
                HttpHeader::new("Host", "127.0.0.1:8989"),
                HttpHeader::new("Authorization", "Bearer secret_token"),
                HttpHeader::new("Cookie", "session=admin_123"),
                HttpHeader::new("Proxy-Authorization", "Basic hop_by_hop"), // hop-by-hop is always stripped
            ],
            vec![],
            TransactionState::Completed,
        );

        let res = convert_transaction_to_repeater_input(
            &tx,
            BridgePrivacyPolicy::IncludeSensitiveHeaders,
            &scope,
            &config,
        )
        .expect("T-19 should succeed");

        assert!(res
            .headers_raw
            .contains("Authorization: Bearer secret_token"));
        assert!(res.headers_raw.contains("Cookie: session=admin_123"));
        assert!(!res.headers_raw.contains("Proxy-Authorization"));
    }

    #[test]
    fn test_t20_headers_too_large_rejected() {
        let scope = AuditScope::default();
        let config = RepeaterConfig {
            max_header_bytes: 120,
            ..Default::default()
        };

        let tx = make_test_tx(
            HttpMethod::Get,
            "/api",
            "127.0.0.1:8989",
            vec![
                HttpHeader::new("Host", "127.0.0.1:8989"),
                HttpHeader::new("X-Large", "A".repeat(150)),
            ],
            vec![],
            TransactionState::Completed,
        );

        let err = convert_transaction_to_repeater_input(
            &tx,
            BridgePrivacyPolicy::ExcludeSensitiveHeaders,
            &scope,
            &config,
        )
        .unwrap_err();

        assert_eq!(err, BridgeError::HeadersTooLarge);
    }

    #[test]
    fn test_t21_t24_draft_snapshot_equality_and_redaction() {
        let input1 =
            RepeaterUiInput::new("GET", "http://127.0.0.1:8989/a", "Host: 127.0.0.1\n", "");
        let input2 =
            RepeaterUiInput::new("GET", "http://127.0.0.1:8989/b", "Host: 127.0.0.1\n", ""); // Same len, different url

        let snap1 = RepeaterDraftSnapshot::from_ui(&input1);
        let snap2 = RepeaterDraftSnapshot::from_ui(&input2);

        // Exact comparison ensures different content with same lengths is not equal
        assert_ne!(snap1, snap2);

        // Test debug formatting redaction
        let debug_str = format!("{:?}", snap1);
        assert!(debug_str.contains("[REDACTED_DRAFT_CONTENT]"));
        assert!(!debug_str.contains("http://127.0.0.1:8989/a"));

        // Default clean check
        let def_snap = RepeaterDraftSnapshot::from_ui(&RepeaterUiInput::default());
        assert!(def_snap.is_clean_default());
        assert!(!snap1.is_clean_default());
    }

    #[test]
    fn test_ipv6_bracketed_authority_normalized() {
        let scope = AuditScope::default();
        let config = RepeaterConfig::default();

        let tx = make_test_tx(
            HttpMethod::Get,
            "/api/test",
            "[::1]:8080",
            vec![HttpHeader::new("Host", "[::1]:8080")],
            vec![],
            TransactionState::Completed,
        );

        let res = convert_transaction_to_repeater_input(
            &tx,
            BridgePrivacyPolicy::ExcludeSensitiveHeaders,
            &scope,
            &config,
        )
        .expect("IPv6 target should succeed");

        assert_eq!(res.target_url, "http://[::1]:8080/api/test");
        assert!(res.headers_raw.starts_with("Host: [::1]:8080"));
    }

    // =========================================================================
    // Rework 1.4C-1R Tests: BR-01 to BR-05
    // =========================================================================

    #[test]
    fn test_br01_url_validation_negative_cases() {
        let scope = AuditScope::default();
        let config = RepeaterConfig::default();

        // 1. Fragment '#' rejected
        let mut tx = make_test_tx(
            HttpMethod::Get,
            "/api#fragment",
            "127.0.0.1:8989",
            vec![HttpHeader::new("Host", "127.0.0.1:8989")],
            vec![],
            TransactionState::Completed,
        );
        let err = convert_transaction_to_repeater_input(
            &tx,
            BridgePrivacyPolicy::ExcludeSensitiveHeaders,
            &scope,
            &config,
        )
        .unwrap_err();
        assert_eq!(err, BridgeError::InvalidTargetUrl);

        // 2. Spaces in URL rejected
        tx.request.raw_url = "/api with spaces".to_string();
        tx.request.path = "/api with spaces".to_string();
        let err = convert_transaction_to_repeater_input(
            &tx,
            BridgePrivacyPolicy::ExcludeSensitiveHeaders,
            &scope,
            &config,
        )
        .unwrap_err();
        assert_eq!(err, BridgeError::InvalidTargetUrl);

        // 3. Backslash in URL rejected
        tx.request.raw_url = "/api\\test".to_string();
        tx.request.path = "/api\\test".to_string();
        let err = convert_transaction_to_repeater_input(
            &tx,
            BridgePrivacyPolicy::ExcludeSensitiveHeaders,
            &scope,
            &config,
        )
        .unwrap_err();
        assert_eq!(err, BridgeError::InvalidTargetUrl);

        // 4. raw_url /safe with path /different rejected
        tx.request.raw_url = "/safe".to_string();
        tx.request.path = "/different".to_string();
        let err = convert_transaction_to_repeater_input(
            &tx,
            BridgePrivacyPolicy::ExcludeSensitiveHeaders,
            &scope,
            &config,
        )
        .unwrap_err();
        assert_eq!(err, BridgeError::InvalidTargetUrl);

        // 5. raw_url /safe?a=1 with query a=2 rejected
        tx.request.raw_url = "/safe?a=1".to_string();
        tx.request.path = "/safe".to_string();
        tx.request.query = "a=2".to_string();
        let err = convert_transaction_to_repeater_input(
            &tx,
            BridgePrivacyPolicy::ExcludeSensitiveHeaders,
            &scope,
            &config,
        )
        .unwrap_err();
        assert_eq!(err, BridgeError::InvalidTargetUrl);

        // 6. Absolute URL whose path does not match structured path
        tx.request.raw_url = "http://127.0.0.1:8989/actual".to_string();
        tx.request.path = "/mismatched".to_string();
        tx.request.query = String::new();
        let err = convert_transaction_to_repeater_input(
            &tx,
            BridgePrivacyPolicy::ExcludeSensitiveHeaders,
            &scope,
            &config,
        )
        .unwrap_err();
        assert_eq!(err, BridgeError::InvalidTargetUrl);

        // 7. Disallowed schemes (e.g. ftp://)
        tx.request.raw_url = "ftp://127.0.0.1:8989/api".to_string();
        tx.request.path = "/api".to_string();
        let err = convert_transaction_to_repeater_input(
            &tx,
            BridgePrivacyPolicy::ExcludeSensitiveHeaders,
            &scope,
            &config,
        )
        .unwrap_err();
        assert_eq!(err, BridgeError::UnsupportedSchemeOrMethod);

        // 8. Discordant Host / port
        tx.request.raw_url = "http://127.0.0.1:9999/api".to_string();
        tx.request.host = "127.0.0.1:8989".to_string();
        tx.request.headers = vec![HttpHeader::new("Host", "127.0.0.1:8989")];
        let err = convert_transaction_to_repeater_input(
            &tx,
            BridgePrivacyPolicy::ExcludeSensitiveHeaders,
            &scope,
            &config,
        )
        .unwrap_err();
        assert_eq!(err, BridgeError::AuthorityMismatch);

        // 9. Userinfo in authority rejected
        tx.request.raw_url = "http://user:pass@127.0.0.1:8989/api".to_string();
        let err = convert_transaction_to_repeater_input(
            &tx,
            BridgePrivacyPolicy::ExcludeSensitiveHeaders,
            &scope,
            &config,
        )
        .unwrap_err();
        assert_eq!(err, BridgeError::AuthorityMismatch);
    }

    #[test]
    fn test_br01_explicit_empty_query_preservation() {
        let scope = AuditScope::default();
        let config = RepeaterConfig::default();

        let tx = make_test_tx(
            HttpMethod::Get,
            "/api/items?",
            "127.0.0.1:8989",
            vec![HttpHeader::new("Host", "127.0.0.1:8989")],
            vec![],
            TransactionState::Completed,
        );

        let res = convert_transaction_to_repeater_input(
            &tx,
            BridgePrivacyPolicy::ExcludeSensitiveHeaders,
            &scope,
            &config,
        )
        .expect("Explicit empty query should succeed");

        assert_eq!(res.target_url, "http://127.0.0.1:8989/api/items?");
    }

    #[test]
    fn test_br01_raw_url_whitespace_regression() {
        let scope = AuditScope::default();
        let config = RepeaterConfig::default();

        let mut tx = make_test_tx(
            HttpMethod::Get,
            "/api",
            "127.0.0.1:8989",
            vec![HttpHeader::new("Host", "127.0.0.1:8989")],
            vec![],
            TransactionState::Completed,
        );

        // 1. Trailing space in raw_url
        tx.request.raw_url = "/api ".to_string();
        tx.request.path = "/api".to_string();
        let err1 = convert_transaction_to_repeater_input(
            &tx,
            BridgePrivacyPolicy::ExcludeSensitiveHeaders,
            &scope,
            &config,
        )
        .unwrap_err();
        assert_eq!(err1, BridgeError::InvalidTargetUrl);

        // 2. Leading space in raw_url
        tx.request.raw_url = " /api".to_string();
        tx.request.path = "/api".to_string();
        let err2 = convert_transaction_to_repeater_input(
            &tx,
            BridgePrivacyPolicy::ExcludeSensitiveHeaders,
            &scope,
            &config,
        )
        .unwrap_err();
        assert_eq!(err2, BridgeError::InvalidTargetUrl);

        // 3. Trailing tab in raw_url
        tx.request.raw_url = "/api\t".to_string();
        tx.request.path = "/api".to_string();
        let err3 = convert_transaction_to_repeater_input(
            &tx,
            BridgePrivacyPolicy::ExcludeSensitiveHeaders,
            &scope,
            &config,
        )
        .unwrap_err();
        assert_eq!(err3, BridgeError::InvalidTargetUrl);

        // 4. Trailing newline in raw_url
        tx.request.raw_url = "/api\n".to_string();
        tx.request.path = "/api".to_string();
        let err4 = convert_transaction_to_repeater_input(
            &tx,
            BridgePrivacyPolicy::ExcludeSensitiveHeaders,
            &scope,
            &config,
        )
        .unwrap_err();
        assert_eq!(err4, BridgeError::InvalidTargetUrl);

        // 5. Valid URL /api succeeds
        tx.request.raw_url = "/api".to_string();
        tx.request.path = "/api".to_string();
        let res_valid = convert_transaction_to_repeater_input(
            &tx,
            BridgePrivacyPolicy::ExcludeSensitiveHeaders,
            &scope,
            &config,
        )
        .expect("Valid /api should succeed");
        assert_eq!(res_valid.target_url, "http://127.0.0.1:8989/api");

        // 6. Explicit empty query /api? succeeds
        tx.request.raw_url = "/api?".to_string();
        tx.request.path = "/api".to_string();
        tx.request.query = String::new();
        let res_query = convert_transaction_to_repeater_input(
            &tx,
            BridgePrivacyPolicy::ExcludeSensitiveHeaders,
            &scope,
            &config,
        )
        .expect("Explicit empty query /api? should succeed");
        assert_eq!(res_query.target_url, "http://127.0.0.1:8989/api?");
    }

    #[test]
    fn test_br02_strict_header_validation_token_and_control_chars() {
        let scope = AuditScope::default();
        let config = RepeaterConfig::default();

        // 1. Header name with '@' rejected
        let tx1 = make_test_tx(
            HttpMethod::Get,
            "/api",
            "127.0.0.1:8989",
            vec![
                HttpHeader::new("Host", "127.0.0.1:8989"),
                HttpHeader::new("X-User@Domain", "value"),
            ],
            vec![],
            TransactionState::Completed,
        );
        let err1 = convert_transaction_to_repeater_input(
            &tx1,
            BridgePrivacyPolicy::ExcludeSensitiveHeaders,
            &scope,
            &config,
        )
        .unwrap_err();
        assert_eq!(err1, BridgeError::MalformedHeader);

        // 2. Header name with parentheses rejected
        let tx2 = make_test_tx(
            HttpMethod::Get,
            "/api",
            "127.0.0.1:8989",
            vec![
                HttpHeader::new("Host", "127.0.0.1:8989"),
                HttpHeader::new("X-Header(Name)", "value"),
            ],
            vec![],
            TransactionState::Completed,
        );
        let err2 = convert_transaction_to_repeater_input(
            &tx2,
            BridgePrivacyPolicy::ExcludeSensitiveHeaders,
            &scope,
            &config,
        )
        .unwrap_err();
        assert_eq!(err2, BridgeError::MalformedHeader);

        // 3. Header value with DEL (0x7F) rejected
        let tx3 = make_test_tx(
            HttpMethod::Get,
            "/api",
            "127.0.0.1:8989",
            vec![
                HttpHeader::new("Host", "127.0.0.1:8989"),
                HttpHeader::new("X-Custom", "val\x7Fbad"),
            ],
            vec![],
            TransactionState::Completed,
        );
        let err3 = convert_transaction_to_repeater_input(
            &tx3,
            BridgePrivacyPolicy::ExcludeSensitiveHeaders,
            &scope,
            &config,
        )
        .unwrap_err();
        assert_eq!(err3, BridgeError::MalformedHeader);

        // 4. Header value with control character BEL (0x07) rejected
        let tx4 = make_test_tx(
            HttpMethod::Get,
            "/api",
            "127.0.0.1:8989",
            vec![
                HttpHeader::new("Host", "127.0.0.1:8989"),
                HttpHeader::new("X-Custom", "val\x07bell"),
            ],
            vec![],
            TransactionState::Completed,
        );
        let err4 = convert_transaction_to_repeater_input(
            &tx4,
            BridgePrivacyPolicy::ExcludeSensitiveHeaders,
            &scope,
            &config,
        )
        .unwrap_err();
        assert_eq!(err4, BridgeError::MalformedHeader);

        // 5. Hop-by-hop header with malformed value rejected BEFORE filtering
        let tx5 = make_test_tx(
            HttpMethod::Get,
            "/api",
            "127.0.0.1:8989",
            vec![
                HttpHeader::new("Host", "127.0.0.1:8989"),
                HttpHeader::new("Connection", "close\x7F"),
            ],
            vec![],
            TransactionState::Completed,
        );
        let err5 = convert_transaction_to_repeater_input(
            &tx5,
            BridgePrivacyPolicy::ExcludeSensitiveHeaders,
            &scope,
            &config,
        )
        .unwrap_err();
        assert_eq!(err5, BridgeError::MalformedHeader);

        // 6. Sensitive header with malformed value rejected BEFORE filtering
        let tx6 = make_test_tx(
            HttpMethod::Get,
            "/api",
            "127.0.0.1:8989",
            vec![
                HttpHeader::new("Host", "127.0.0.1:8989"),
                HttpHeader::new("Authorization", "Bearer\x00secret"),
            ],
            vec![],
            TransactionState::Completed,
        );
        let err6 = convert_transaction_to_repeater_input(
            &tx6,
            BridgePrivacyPolicy::ExcludeSensitiveHeaders,
            &scope,
            &config,
        )
        .unwrap_err();
        assert_eq!(err6, BridgeError::MalformedHeader);
    }

    #[test]
    fn test_br03_incremental_header_budget_early_rejection_and_exact_boundary() {
        let scope = AuditScope::default();

        // Host line: "Host: 127.0.0.1:8989" (20 bytes)
        // Header line: "X-A: 1" (6 bytes)
        // Separating newline: 1 byte
        // Total exact: 20 + 1 + 6 = 27 bytes
        let tx = make_test_tx(
            HttpMethod::Get,
            "/api",
            "127.0.0.1:8989",
            vec![
                HttpHeader::new("Host", "127.0.0.1:8989"),
                HttpHeader::new("X-A", "1"),
            ],
            vec![],
            TransactionState::Completed,
        );

        // Exact boundary: 27 bytes permitted -> succeeds
        let config_exact = RepeaterConfig {
            max_header_bytes: 27,
            ..Default::default()
        };
        let res = convert_transaction_to_repeater_input(
            &tx,
            BridgePrivacyPolicy::ExcludeSensitiveHeaders,
            &scope,
            &config_exact,
        )
        .expect("Exact 27 bytes budget should succeed");
        assert_eq!(res.headers_raw.len(), 27);

        // 1 byte below boundary: 26 bytes permitted -> fails with HeadersTooLarge
        let config_below = RepeaterConfig {
            max_header_bytes: 26,
            ..Default::default()
        };
        let err1 = convert_transaction_to_repeater_input(
            &tx,
            BridgePrivacyPolicy::ExcludeSensitiveHeaders,
            &scope,
            &config_below,
        )
        .unwrap_err();
        assert_eq!(err1, BridgeError::HeadersTooLarge);

        // Budget smaller than Host line itself: 15 bytes -> fails early
        let config_too_small = RepeaterConfig {
            max_header_bytes: 15,
            ..Default::default()
        };
        let err2 = convert_transaction_to_repeater_input(
            &tx,
            BridgePrivacyPolicy::ExcludeSensitiveHeaders,
            &scope,
            &config_too_small,
        )
        .unwrap_err();
        assert_eq!(err2, BridgeError::HeadersTooLarge);
    }

    #[test]
    fn test_br04_debug_security_synthetic_markers() {
        let sensitive_method = "SYNTH_METHOD_SECRET";
        let sensitive_url = "http://127.0.0.1:8989/SYNTH_URL_SECRET";
        let sensitive_header = "Host: 127.0.0.1:8989\nSYNTH_HEADER_SECRET: val";
        let sensitive_body = "SYNTH_BODY_SECRET";

        let input = RepeaterUiInput::new(
            sensitive_method,
            sensitive_url,
            sensitive_header,
            sensitive_body,
        );
        let snap = RepeaterDraftSnapshot::from_ui(&input);
        let intent = StagedBridgeIntent {
            transaction_id: 42,
            privacy_policy: BridgePrivacyPolicy::ExcludeSensitiveHeaders,
            expected_draft: snap.clone(),
        };

        let debug_snap = format!("{:?}", snap);
        let debug_intent = format!("{:?}", intent);

        // Ensure neither method nor any free-form string leaks in Debug
        for debug_output in [&debug_snap, &debug_intent] {
            assert!(
                !debug_output.contains(sensitive_method),
                "Debug leaked method: {}",
                debug_output
            );
            assert!(
                !debug_output.contains(sensitive_url),
                "Debug leaked target_url: {}",
                debug_output
            );
            assert!(
                !debug_output.contains("SYNTH_HEADER_SECRET"),
                "Debug leaked header: {}",
                debug_output
            );
            assert!(
                !debug_output.contains(sensitive_body),
                "Debug leaked body: {}",
                debug_output
            );
        }
    }

    #[test]
    fn test_br05_strict_decimal_content_length() {
        let scope = AuditScope::default();
        let config = RepeaterConfig::default();

        let test_cases = [
            ("+10", BridgeError::InvalidContentLengthHeader),
            ("-10", BridgeError::InvalidContentLengthHeader),
            ("10abc", BridgeError::InvalidContentLengthHeader),
            ("0x10", BridgeError::InvalidContentLengthHeader),
            ("", BridgeError::InvalidContentLengthHeader),
            (
                "184467440737095516150",
                BridgeError::InvalidContentLengthHeader,
            ), // overflow
        ];

        for (val, expected_err) in test_cases {
            let tx = make_test_tx(
                HttpMethod::Post,
                "/api",
                "127.0.0.1:8989",
                vec![
                    HttpHeader::new("Host", "127.0.0.1:8989"),
                    HttpHeader::new("Content-Length", val),
                ],
                vec![b'x'; 10],
                TransactionState::Completed,
            );

            let err = convert_transaction_to_repeater_input(
                &tx,
                BridgePrivacyPolicy::ExcludeSensitiveHeaders,
                &scope,
                &config,
            )
            .unwrap_err();

            assert_eq!(
                err, expected_err,
                "Case '{}' expected {:?}, got {:?}",
                val, expected_err, err
            );
        }

        // Exact decimal succeeds
        let valid_tx = make_test_tx(
            HttpMethod::Post,
            "/api",
            "127.0.0.1:8989",
            vec![
                HttpHeader::new("Host", "127.0.0.1:8989"),
                HttpHeader::new("Content-Length", "5"),
            ],
            b"hello".to_vec(),
            TransactionState::Completed,
        );

        let res = convert_transaction_to_repeater_input(
            &valid_tx,
            BridgePrivacyPolicy::ExcludeSensitiveHeaders,
            &scope,
            &config,
        )
        .expect("Valid decimal Content-Length should succeed");

        assert_eq!(res.body_utf8, "hello");
    }
}
