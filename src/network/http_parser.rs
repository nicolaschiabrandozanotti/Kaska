use crate::core::models::{HttpHeader, HttpMethod, HttpRequest, HttpResponse};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HttpParseError {
    #[error("Empty HTTP stream")]
    EmptyStream,

    #[error("Malformed start line: {0}")]
    MalformedStartLine(String),

    #[error("Incomplete headers")]
    IncompleteHeaders,

    #[error("Invalid header line: {0}")]
    InvalidHeader(String),

    #[error("Invalid status code: {0}")]
    InvalidStatusCode(String),

    #[error("Conflicting framing: {0}")]
    ConflictingFraming(String),

    #[error("Invalid chunk framing: {0}")]
    InvalidChunk(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkedDecoderState {
    ReadingHeader,
    ReadingData { remaining: usize },
    ReadingDataCrlf,
    ReadingTrailers,
    Complete,
}

/// Robust RFC 9112 streaming chunked transfer decoder
pub struct ChunkedTransferDecoder {
    state: ChunkedDecoderState,
    buffer: Vec<u8>,
    decoded: Vec<u8>,
    max_body_size: usize,
    total_decoded_bytes: usize,
}

impl Default for ChunkedTransferDecoder {
    fn default() -> Self {
        Self::new(2 * 1024 * 1024) // 2 MB default safety inspection limit
    }
}

impl ChunkedTransferDecoder {
    pub fn new(max_body_size: usize) -> Self {
        Self {
            state: ChunkedDecoderState::ReadingHeader,
            buffer: Vec::new(),
            decoded: Vec::new(),
            max_body_size,
            total_decoded_bytes: 0,
        }
    }

    pub fn is_complete(&self) -> bool {
        self.state == ChunkedDecoderState::Complete
    }

    pub fn decoded_body(&self) -> &[u8] {
        &self.decoded
    }

    pub fn total_decoded_bytes(&self) -> usize {
        self.total_decoded_bytes
    }

    pub fn state(&self) -> &ChunkedDecoderState {
        &self.state
    }

    /// Feeds raw chunked bytes from TCP stream into the state machine
    pub fn feed(&mut self, chunk: &[u8]) -> Result<(), HttpParseError> {
        self.buffer.extend_from_slice(chunk);

        loop {
            match self.state {
                ChunkedDecoderState::ReadingHeader => {
                    if let Some(pos) = self.buffer.iter().position(|&b| b == b'\n') {
                        let line_str = String::from_utf8_lossy(&self.buffer[..pos]).to_string();
                        let trimmed = line_str.trim();

                        if trimmed.is_empty() {
                            // Empty line before chunk header, discard
                            self.buffer.drain(..pos + 1);
                            continue;
                        }

                        // Chunk extension handling: size[;extension=val]
                        let hex_str = trimmed.split(';').next().unwrap_or(trimmed).trim();
                        let chunk_size = usize::from_str_radix(hex_str, 16).map_err(|_| {
                            HttpParseError::InvalidChunk(format!(
                                "Invalid chunk hex size: '{}'",
                                hex_str
                            ))
                        })?;

                        self.buffer.drain(..pos + 1);

                        if chunk_size == 0 {
                            self.state = ChunkedDecoderState::ReadingTrailers;
                        } else {
                            self.state = ChunkedDecoderState::ReadingData {
                                remaining: chunk_size,
                            };
                        }
                    } else {
                        // Incomplete chunk header line, await more bytes
                        break;
                    }
                }
                ChunkedDecoderState::ReadingData { ref mut remaining } => {
                    let available = self.buffer.len();
                    let to_consume = std::cmp::min(available, *remaining);

                    if to_consume > 0 {
                        let data_slice = &self.buffer[..to_consume];
                        self.total_decoded_bytes += to_consume;

                        if self.decoded.len() < self.max_body_size {
                            let can_take =
                                std::cmp::min(to_consume, self.max_body_size - self.decoded.len());
                            self.decoded.extend_from_slice(&data_slice[..can_take]);
                        }

                        self.buffer.drain(..to_consume);
                        *remaining -= to_consume;
                    }

                    if *remaining == 0 {
                        self.state = ChunkedDecoderState::ReadingDataCrlf;
                    } else {
                        // Need more body bytes
                        break;
                    }
                }
                ChunkedDecoderState::ReadingDataCrlf => {
                    if self.buffer.is_empty() {
                        break;
                    }
                    if self.buffer.starts_with(b"\r\n") {
                        self.buffer.drain(..2);
                        self.state = ChunkedDecoderState::ReadingHeader;
                    } else if self.buffer.starts_with(b"\n") {
                        self.buffer.drain(..1);
                        self.state = ChunkedDecoderState::ReadingHeader;
                    } else if self.buffer.len() == 1 && self.buffer[0] == b'\r' {
                        // Partial CRLF, wait for \n
                        break;
                    } else {
                        return Err(HttpParseError::InvalidChunk(
                            "Expected CRLF at end of chunk data".to_string(),
                        ));
                    }
                }
                ChunkedDecoderState::ReadingTrailers => {
                    if let Some(pos) = self.buffer.iter().position(|&b| b == b'\n') {
                        let line_str = String::from_utf8_lossy(&self.buffer[..pos]).to_string();
                        let is_empty = line_str.trim().is_empty();

                        self.buffer.drain(..pos + 1);

                        if is_empty {
                            // Terminal empty line marks complete chunked message
                            self.state = ChunkedDecoderState::Complete;
                            break;
                        }
                        // Non-empty trailer header; loop to consume next trailer
                    } else {
                        // Incomplete trailer line
                        break;
                    }
                }
                ChunkedDecoderState::Complete => {
                    break;
                }
            }
        }

        Ok(())
    }
}

/// Native zero-dependency RFC-compliant HTTP/1.1 stream parser
pub struct HttpParser;

impl HttpParser {
    /// Parses an HTTP request from raw bytes
    pub fn parse_request(raw_bytes: &[u8]) -> Result<HttpRequest, HttpParseError> {
        if raw_bytes.is_empty() {
            return Err(HttpParseError::EmptyStream);
        }

        // Find header-body boundary \r\n\r\n or \n\n
        let (header_bytes, body_bytes) = Self::split_headers_and_body(raw_bytes);
        let header_str = String::from_utf8_lossy(header_bytes);
        let mut lines = header_str.lines();

        // 1. Request Line: e.g. "GET /api/data?foo=bar HTTP/1.1" or "CONNECT host:port HTTP/1.1"
        let request_line = lines.next().ok_or(HttpParseError::EmptyStream)?;
        let mut parts = request_line.split_whitespace();

        let method_str = parts
            .next()
            .ok_or_else(|| HttpParseError::MalformedStartLine(request_line.to_string()))?;
        let uri_str = parts
            .next()
            .ok_or_else(|| HttpParseError::MalformedStartLine(request_line.to_string()))?;
        let version_str = parts.next().unwrap_or("HTTP/1.1");

        let method = HttpMethod::from_str_prefix(method_str);

        // 2. Parse Headers
        let mut headers = Vec::new();
        let mut has_content_length = false;
        let mut has_transfer_encoding = false;

        for line in lines {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some((name, val)) = trimmed.split_once(':') {
                let name_trimmed = name.trim();
                let val_trimmed = val.trim();

                if name_trimmed.eq_ignore_ascii_case("content-length") {
                    has_content_length = true;
                }
                if name_trimmed.eq_ignore_ascii_case("transfer-encoding") {
                    has_transfer_encoding = true;
                }

                headers.push(HttpHeader::new(name_trimmed, val_trimmed));
            }
        }

        // RFC 9112 §6.1 framing check: A message MUST NOT contain both Content-Length and Transfer-Encoding
        if has_content_length && has_transfer_encoding {
            return Err(HttpParseError::ConflictingFraming(
                "Request contains conflicting Content-Length and Transfer-Encoding headers".into(),
            ));
        }

        // 3. Resolve Host, Path, Query
        let (host, path, query) = Self::decompose_uri(uri_str, &headers, &method);

        // 4. Resolve Body (decode chunked if transfer-encoding is chunked)
        let final_body = if has_transfer_encoding
            && headers.iter().any(|h| {
                h.name.eq_ignore_ascii_case("transfer-encoding")
                    && h.value.to_lowercase().contains("chunked")
            }) {
            Self::decode_chunked_body(body_bytes)?
        } else {
            body_bytes.to_vec()
        };

        Ok(HttpRequest {
            method,
            raw_url: uri_str.to_string(),
            host,
            path,
            query,
            http_version: version_str.to_string(),
            headers,
            body: final_body,
        })
    }

    /// Parses an HTTP response from raw bytes
    pub fn parse_response(raw_bytes: &[u8]) -> Result<HttpResponse, HttpParseError> {
        if raw_bytes.is_empty() {
            return Err(HttpParseError::EmptyStream);
        }

        let (header_bytes, body_bytes) = Self::split_headers_and_body(raw_bytes);
        let header_str = String::from_utf8_lossy(header_bytes);
        let mut lines = header_str.lines();

        // 1. Status Line: e.g. "HTTP/1.1 200 OK"
        let status_line = lines.next().ok_or(HttpParseError::EmptyStream)?;
        let mut parts = status_line.split_whitespace();

        let version = parts
            .next()
            .ok_or_else(|| HttpParseError::MalformedStartLine(status_line.to_string()))?;
        let code_str = parts
            .next()
            .ok_or_else(|| HttpParseError::MalformedStartLine(status_line.to_string()))?;
        let code: u16 = code_str
            .parse()
            .map_err(|_| HttpParseError::InvalidStatusCode(code_str.to_string()))?;

        // Status text is the remainder of the line
        let status_text = parts.collect::<Vec<_>>().join(" ");

        // 2. Parse Headers
        let mut headers = Vec::new();
        let mut has_content_length = false;
        let mut has_transfer_encoding = false;

        for line in lines {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some((name, val)) = trimmed.split_once(':') {
                let name_trimmed = name.trim();
                let val_trimmed = val.trim();

                if name_trimmed.eq_ignore_ascii_case("content-length") {
                    has_content_length = true;
                }
                if name_trimmed.eq_ignore_ascii_case("transfer-encoding") {
                    has_transfer_encoding = true;
                }

                headers.push(HttpHeader::new(name_trimmed, val_trimmed));
            }
        }

        // RFC 9112 §6.1 framing check
        if has_content_length && has_transfer_encoding {
            return Err(HttpParseError::ConflictingFraming(
                "Response contains conflicting Content-Length and Transfer-Encoding headers".into(),
            ));
        }

        // 3. Resolve Body (decode chunked if applicable)
        let final_body = if has_transfer_encoding
            && headers.iter().any(|h| {
                h.name.eq_ignore_ascii_case("transfer-encoding")
                    && h.value.to_lowercase().contains("chunked")
            }) {
            Self::decode_chunked_body(body_bytes)?
        } else {
            body_bytes.to_vec()
        };

        Ok(HttpResponse {
            status_code: code,
            status_text: if status_text.is_empty() {
                "OK".to_string()
            } else {
                status_text
            },
            http_version: version.to_string(),
            headers,
            body: final_body,
        })
    }

    /// Splits headers and body at first occurrence of CRLF CRLF (or LF LF)
    pub fn split_headers_and_body(bytes: &[u8]) -> (&[u8], &[u8]) {
        if let Some(pos) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            return (&bytes[..pos], &bytes[pos + 4..]);
        }
        if let Some(pos) = bytes.windows(2).position(|w| w == b"\n\n") {
            return (&bytes[..pos], &bytes[pos + 2..]);
        }
        (bytes, &[])
    }

    /// Decodes a complete chunked body
    pub fn decode_chunked_body(chunked_bytes: &[u8]) -> Result<Vec<u8>, HttpParseError> {
        if chunked_bytes.is_empty() {
            return Ok(Vec::new());
        }
        let mut decoder = ChunkedTransferDecoder::default();
        decoder.feed(chunked_bytes)?;
        Ok(decoder.decoded_body().to_vec())
    }

    fn decompose_uri(
        uri: &str,
        headers: &[HttpHeader],
        method: &HttpMethod,
    ) -> (String, String, String) {
        let mut host = String::new();
        let mut path_and_query = uri;

        // If method is CONNECT, URI is in authority-form (e.g. "example.com:443")
        if *method == HttpMethod::Connect {
            return (uri.to_string(), "/".to_string(), String::new());
        }

        // If URI is absolute (e.g. "http://example.com:8080/path?q=1")
        if let Some(stripped) = uri.strip_prefix("http://") {
            if let Some(slash_idx) = stripped.find('/') {
                host = stripped[..slash_idx].to_string();
                path_and_query = &stripped[slash_idx..];
            } else {
                host = stripped.to_string();
                path_and_query = "/";
            }
        } else if let Some(stripped) = uri.strip_prefix("https://") {
            if let Some(slash_idx) = stripped.find('/') {
                host = stripped[..slash_idx].to_string();
                path_and_query = &stripped[slash_idx..];
            } else {
                host = stripped.to_string();
                path_and_query = "/";
            }
        }

        // If host was not in absolute URI, get it from Host header
        if host.is_empty() {
            if let Some(h) = headers.iter().find(|h| h.name.eq_ignore_ascii_case("host")) {
                host = h.value.clone();
            } else {
                host = "127.0.0.1".to_string();
            }
        }

        // Split path and query
        let (path, query) = if let Some((p, q)) = path_and_query.split_once('?') {
            (p.to_string(), q.to_string())
        } else {
            (path_and_query.to_string(), String::new())
        };

        (host, path, query)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_get_request() {
        let raw = b"GET /api/v1/users?page=2 HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nUser-Agent: Sentinel/1.0\r\n\r\n";
        let req = HttpParser::parse_request(raw).expect("Failed to parse GET");

        assert_eq!(req.method, HttpMethod::Get);
        assert_eq!(req.path, "/api/v1/users");
        assert_eq!(req.query, "page=2");
        assert_eq!(req.host, "127.0.0.1:8080");
        assert_eq!(req.headers.len(), 2);
        assert!(req.body.is_empty());
    }

    #[test]
    fn test_parse_connect_request() {
        let raw = b"CONNECT 127.0.0.1:8443 HTTP/1.1\r\nHost: 127.0.0.1:8443\r\n\r\n";
        let req = HttpParser::parse_request(raw).expect("Failed to parse CONNECT");

        assert_eq!(req.method, HttpMethod::Connect);
        assert_eq!(req.host, "127.0.0.1:8443");
        assert_eq!(req.path, "/");
    }

    #[test]
    fn test_reject_conflicting_framing() {
        let raw = b"POST /submit HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10\r\nTransfer-Encoding: chunked\r\n\r\n0123456789";
        let err = HttpParser::parse_request(raw).expect_err("Should reject conflicting framing");
        assert!(matches!(err, HttpParseError::ConflictingFraming(_)));
    }

    #[test]
    fn test_chunked_decoder_with_extensions_and_trailers() {
        let raw = b"4\r\nWiki\r\n6;ext=value\r\npedia \r\nE\r\nin \r\n\r\nchunks.\r\n0\r\nChecksum: abc123\r\n\r\n";
        let mut decoder = ChunkedTransferDecoder::default();
        decoder.feed(raw).expect("Feeding chunked bytes");
        assert!(decoder.is_complete());
        assert_eq!(decoder.decoded_body(), b"Wikipedia in \r\n\r\nchunks.");
    }

    #[test]
    fn test_chunked_decoder_fragmented_tcp() {
        let mut decoder = ChunkedTransferDecoder::default();
        // Feed byte by byte to simulate extreme TCP fragmentation
        let raw = b"5\r\nHello\r\n6\r\n World\r\n0\r\n\r\n";
        for b in raw {
            decoder.feed(&[*b]).expect("Single byte feed failed");
        }
        assert!(decoder.is_complete());
        assert_eq!(decoder.decoded_body(), b"Hello World");
    }

    #[test]
    fn test_parse_response_ok() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nServer: SentinelTest\r\n\r\nHello World";
        let res = HttpParser::parse_response(raw).expect("Failed to parse response");

        assert_eq!(res.status_code, 200);
        assert_eq!(res.status_text, "OK");
        assert_eq!(res.body_as_utf8(), "Hello World");
    }
}
