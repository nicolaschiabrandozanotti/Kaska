use kaska_http::models::{HttpRequest, HttpResponse};

/// Default maximum UTF-8 byte length for the formatted preview text rendered in the Inspector UI.
pub const DEFAULT_PREVIEW_BUDGET: usize = 64 * 1024;

/// Minimum allowed preview budget (256 bytes) to ensure headers, footers and content fit safely.
pub const MIN_PREVIEW_BUDGET: usize = 256;

/// Defensive maximum ceiling for preview budget (256 KiB) preventing accidental unbounded allocations.
pub const MAX_PREVIEW_BUDGET: usize = 256 * 1024;

/// Status of capture-level truncation based strictly on explicit evidence from the capture engine.
///
/// Note (TRUNC-01): The relationship between Content-Length and retained buffer length does NOT
/// constitute evidence of capture truncation (e.g. HEAD 200, 304 Not Modified, partial transfers,
/// or chunked encoding). When the underlying model does not provide an explicit engine-level
/// truncation indicator, this status is strictly `Unknown`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CaptureTruncation {
    /// Explicit evidence exists that the capture engine truncated the stream at an engine limit.
    Truncated { limit_bytes: usize },
    /// Explicit evidence exists that the stream was completely captured without engine truncation.
    NotTruncated,
    /// The current capture model does not provide an explicit engine truncation indicator;
    /// capture truncation status is therefore unknown.
    #[default]
    Unknown,
}

/// Bounded, UI-safe inspection preview of an HTTP body for the Inspector view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectorBodyPreview {
    /// Safe UTF-8 text preview whose byte length is strictly `<= clamp_preview_budget(budget_bytes)`.
    pub text: String,
    /// Total number of raw body bytes present in the retained buffer.
    pub retained_bytes: usize,
    /// Number of raw bytes from the retained buffer actually represented in `text`.
    pub rendered_bytes: usize,
    /// Declared Content-Length header value from protocol metadata, if present.
    /// Note: This is protocol metadata, NOT evidence of capture truncation.
    pub declared_content_length: Option<usize>,
    /// `true` if the payload contains invalid UTF-8 sequences, null bytes, or binary control characters.
    pub is_binary: bool,
    /// `true` if the formatted preview was truncated to fit within the preview budget.
    pub preview_truncated: bool,
    /// Capture truncation status based strictly on explicit engine evidence.
    pub capture_truncation: CaptureTruncation,
}

/// Clamps any caller-supplied preview budget into `[MIN_PREVIEW_BUDGET, MAX_PREVIEW_BUDGET]`.
pub fn clamp_preview_budget(budget_bytes: usize) -> usize {
    budget_bytes.clamp(MIN_PREVIEW_BUDGET, MAX_PREVIEW_BUDGET)
}

/// Determines whether a byte buffer contains binary data, null bytes, or unsafe control characters.
///
/// Returns `false` ONLY if the buffer is valid UTF-8 and all characters are printable, spaces,
/// tabs (`\t`), newlines (`\n`), or carriage returns (`\r`).
pub fn is_binary_payload(bytes: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return true;
    };
    text.bytes()
        .any(|b| (b < 0x20 && b != b'\r' && b != b'\n' && b != b'\t') || b == 0x7F)
}

/// Finds the largest char boundary in `s` that is `<= max_bytes`.
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

/// Formats the truncation footer for text payloads.
fn format_text_truncation_footer(
    shown_bytes: usize,
    retained_bytes: usize,
    capture_truncation: CaptureTruncation,
) -> String {
    let capture_clause = match capture_truncation {
        CaptureTruncation::Truncated { limit_bytes } => {
            format!(
                "; capture truncated at engine limit ({} bytes)",
                limit_bytes
            )
        }
        CaptureTruncation::NotTruncated | CaptureTruncation::Unknown => String::new(),
    };

    format!(
        "\n\n[Preview truncated: showing {} of {} retained bytes{}]",
        shown_bytes, retained_bytes, capture_clause
    )
}

/// Formats the informative header for binary payloads.
fn format_binary_preview_header(
    retained_bytes: usize,
    capture_truncation: CaptureTruncation,
    preview_truncated: bool,
    shown_bytes: usize,
) -> String {
    let capture_clause = match capture_truncation {
        CaptureTruncation::Truncated { limit_bytes } => {
            format!(
                ", capture truncated at engine limit ({} bytes)",
                limit_bytes
            )
        }
        CaptureTruncation::NotTruncated | CaptureTruncation::Unknown => String::new(),
    };

    let preview_clause = if preview_truncated {
        format!(", showing first {} bytes", shown_bytes)
    } else {
        String::new()
    };

    format!(
        "[Binary / non-textual payload ({} bytes retained{}{}) — hex/ASCII preview]\n",
        retained_bytes, capture_clause, preview_clause
    )
}

/// Formats a raw HTTP body into a bounded, UI-safe text preview with optional protocol metadata.
///
/// Invariants:
/// - Visual output size: `result.text.len() <= clamp_preview_budget(budget_bytes)` under all inputs.
/// - Memory footprint: Output string allocation is strictly bounded by the effective preview budget.
/// - Hex construction: Formats strictly the number of rows fitting within the budget.
pub fn format_inspector_body_preview_with_meta(
    raw_body: &[u8],
    declared_content_length: Option<usize>,
    capture_truncation: CaptureTruncation,
    budget_bytes: usize,
) -> InspectorBodyPreview {
    let retained_bytes = raw_body.len();

    // 1. Empty body
    if retained_bytes == 0 {
        return InspectorBodyPreview {
            text: String::new(),
            retained_bytes: 0,
            rendered_bytes: 0,
            declared_content_length,
            is_binary: false,
            preview_truncated: false,
            capture_truncation,
        };
    }

    let effective_budget = clamp_preview_budget(budget_bytes);
    let is_binary = is_binary_payload(raw_body);

    // 2. Valid UTF-8 text payload
    if !is_binary {
        let valid_str = std::str::from_utf8(raw_body).unwrap_or("");
        if valid_str.len() <= effective_budget {
            return InspectorBodyPreview {
                text: valid_str.to_string(),
                retained_bytes,
                rendered_bytes: retained_bytes,
                declared_content_length,
                is_binary: false,
                preview_truncated: false,
                capture_truncation,
            };
        }

        // Bounded text truncation with UTF-8 character boundary preservation
        let sample_footer =
            format_text_truncation_footer(effective_budget, retained_bytes, capture_truncation);
        let max_body_slice = effective_budget.saturating_sub(sample_footer.len());
        let boundary = floor_utf8_char_boundary(valid_str, max_body_slice);
        let exact_footer =
            format_text_truncation_footer(boundary, retained_bytes, capture_truncation);

        let mut preview_text = String::with_capacity(boundary + exact_footer.len());
        preview_text.push_str(&valid_str[..boundary]);
        preview_text.push_str(&exact_footer);

        debug_assert!(preview_text.len() <= effective_budget);

        return InspectorBodyPreview {
            text: preview_text,
            retained_bytes,
            rendered_bytes: boundary,
            declared_content_length,
            is_binary: false,
            preview_truncated: true,
            capture_truncation,
        };
    }

    // 3. Binary or unsafe control payload (Hex dump with offset and ASCII column)
    // Each 16-byte row consumes at most 76 bytes:
    //   "{:06x}: " (8) + 16 * "{:02x} " (48) + " |" (2) + 16 chars (16) + "|\n" (2) = 76 bytes
    const MAX_HEX_LINE_BYTES: usize = 76;

    let sample_header =
        format_binary_preview_header(retained_bytes, capture_truncation, true, retained_bytes);
    let available_for_rows = effective_budget.saturating_sub(sample_header.len());
    let max_rows = available_for_rows / MAX_HEX_LINE_BYTES;
    let max_raw_bytes = max_rows.saturating_mul(16);

    let slice_len = raw_body.len().min(max_raw_bytes);
    let preview_truncated = raw_body.len() > slice_len;

    let exact_header = format_binary_preview_header(
        retained_bytes,
        capture_truncation,
        preview_truncated,
        slice_len,
    );

    let mut out =
        String::with_capacity(exact_header.len() + (slice_len / 16 + 1) * MAX_HEX_LINE_BYTES);
    out.push_str(&exact_header);

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

        if out.len() + line.len() > effective_budget {
            break;
        }
        out.push_str(&line);
    }

    debug_assert!(out.len() <= effective_budget);

    InspectorBodyPreview {
        text: out,
        retained_bytes,
        rendered_bytes: slice_len,
        declared_content_length,
        is_binary: true,
        preview_truncated,
        capture_truncation,
    }
}

/// Formats a raw HTTP body into a bounded, UI-safe text preview.
pub fn format_inspector_body_preview(
    raw_body: &[u8],
    capture_truncation: CaptureTruncation,
    budget_bytes: usize,
) -> InspectorBodyPreview {
    format_inspector_body_preview_with_meta(raw_body, None, capture_truncation, budget_bytes)
}

/// Convenience formatter using the default 64 KiB preview budget and unknown capture truncation.
pub fn format_inspector_body(raw_body: &[u8]) -> InspectorBodyPreview {
    format_inspector_body_preview(raw_body, CaptureTruncation::Unknown, DEFAULT_PREVIEW_BUDGET)
}

/// Formats an HttpRequest body with default budget and Content-Length protocol metadata.
///
/// Since the current HTTP model provides no explicit engine capture truncation flag,
/// `capture_truncation` is strictly reported as `CaptureTruncation::Unknown`.
pub fn format_request_body_preview(req: &HttpRequest) -> InspectorBodyPreview {
    format_inspector_body_preview_with_meta(
        &req.body,
        req.content_length(),
        CaptureTruncation::Unknown,
        DEFAULT_PREVIEW_BUDGET,
    )
}

/// Formats an HttpResponse body with default budget and Content-Length protocol metadata.
///
/// Since the current HTTP model provides no explicit engine capture truncation flag,
/// `capture_truncation` is strictly reported as `CaptureTruncation::Unknown`.
pub fn format_response_body_preview(resp: &HttpResponse) -> InspectorBodyPreview {
    format_inspector_body_preview_with_meta(
        &resp.body,
        resp.content_length(),
        CaptureTruncation::Unknown,
        DEFAULT_PREVIEW_BUDGET,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaska_http::models::{HttpHeader, HttpMethod};

    #[test]
    fn test_empty_body() {
        let preview = format_inspector_body(b"");
        assert_eq!(preview.text, "");
        assert_eq!(preview.retained_bytes, 0);
        assert_eq!(preview.rendered_bytes, 0);
        assert_eq!(preview.declared_content_length, None);
        assert!(!preview.is_binary);
        assert!(!preview.preview_truncated);
        assert_eq!(preview.capture_truncation, CaptureTruncation::Unknown);
    }

    #[test]
    fn test_ascii_body_within_budget() {
        let input = b"Hello, Kaska Inspector! Status: OK";
        let preview = format_inspector_body(input);
        assert_eq!(preview.text, "Hello, Kaska Inspector! Status: OK");
        assert_eq!(preview.retained_bytes, input.len());
        assert_eq!(preview.rendered_bytes, input.len());
        assert!(!preview.is_binary);
        assert!(!preview.preview_truncated);
    }

    #[test]
    fn test_multibyte_utf8_preservation() {
        let input = "Café con leche ☕ y tostadas con ñandú 🦀";
        let preview = format_inspector_body(input.as_bytes());
        assert_eq!(preview.text, input);
        assert_eq!(preview.retained_bytes, input.len());
        assert_eq!(preview.rendered_bytes, input.len());
        assert!(!preview.is_binary);
        assert!(!preview.preview_truncated);
    }

    #[test]
    fn test_utf8_char_boundary_truncation_no_split() {
        // Multi-byte character '🦀' (4 bytes: F0 9F A6 80)
        let crab = "🦀";
        let repeated = crab.repeat(200); // 800 bytes
        let budget = 300;
        let preview =
            format_inspector_body_preview(repeated.as_bytes(), CaptureTruncation::Unknown, budget);

        assert!(preview.preview_truncated);
        assert!(!preview.is_binary);
        assert!(preview.text.len() <= budget);
        // Ensure the preview text is strictly valid UTF-8
        assert!(std::str::from_utf8(preview.text.as_bytes()).is_ok());
        assert!(preview.text.contains("[Preview truncated: showing"));
        // Check that rendered bytes is an exact multiple of 4 (crab char size)
        assert_eq!(preview.rendered_bytes % 4, 0);
    }

    #[test]
    fn test_body_just_below_budget() {
        let budget = 1000;
        let input = "A".repeat(budget - 1);
        let preview =
            format_inspector_body_preview(input.as_bytes(), CaptureTruncation::Unknown, budget);
        assert_eq!(preview.text.len(), budget - 1);
        assert!(!preview.preview_truncated);
        assert_eq!(preview.rendered_bytes, budget - 1);
    }

    #[test]
    fn test_body_exact_budget() {
        let budget = 1000;
        let input = "A".repeat(budget);
        let preview =
            format_inspector_body_preview(input.as_bytes(), CaptureTruncation::Unknown, budget);
        assert_eq!(preview.text.len(), budget);
        assert!(!preview.preview_truncated);
        assert_eq!(preview.rendered_bytes, budget);
    }

    #[test]
    fn test_body_exceeding_budget() {
        let budget = 500;
        let input = "A".repeat(2000);
        let preview =
            format_inspector_body_preview(input.as_bytes(), CaptureTruncation::Unknown, budget);
        assert!(preview.preview_truncated);
        assert!(preview.text.len() <= budget);
        assert!(preview.text.contains("[Preview truncated: showing"));
        assert_eq!(preview.retained_bytes, 2000);
        assert!(preview.rendered_bytes < 500);
    }

    #[test]
    fn test_large_2mib_binary_payload() {
        // 2 MiB payload with arbitrary binary values
        let large_binary = vec![0xABu8; 2 * 1024 * 1024];
        let preview = format_inspector_body_preview(
            &large_binary,
            CaptureTruncation::Unknown,
            DEFAULT_PREVIEW_BUDGET,
        );

        assert!(preview.is_binary);
        assert!(preview.preview_truncated);
        assert_eq!(preview.retained_bytes, 2 * 1024 * 1024);
        assert!(preview.text.len() <= DEFAULT_PREVIEW_BUDGET);
        assert!(preview
            .text
            .contains("[Binary / non-textual payload (2097152 bytes retained"));
        assert!(preview.text.contains("000000: ab ab ab ab"));
    }

    #[test]
    fn test_null_byte_detected_as_binary() {
        let input = b"Hello\x00World";
        let preview = format_inspector_body(input);
        assert!(preview.is_binary);
        assert!(preview
            .text
            .contains("000000: 48 65 6c 6c 6f 00 57 6f 72 6c 64"));
        assert!(preview.text.contains("|Hello.World|"));
    }

    #[test]
    fn test_crlf_and_tabs_preserved_as_text() {
        let input = b"Line 1\r\n\tIndented Line 2\r\nLine 3\n";
        let preview = format_inspector_body(input);
        assert!(!preview.is_binary);
        assert_eq!(preview.text, "Line 1\r\n\tIndented Line 2\r\nLine 3\n");
    }

    #[test]
    fn test_unsafe_control_chars_detected_as_binary() {
        // Bell character (0x07), Escape (0x1B), and DEL (0x7F)
        assert!(is_binary_payload(b"Audio alert \x07"));
        assert!(is_binary_payload(b"Terminal escape \x1b[31m"));
        assert!(is_binary_payload(b"Delete char \x7F"));

        let preview = format_inspector_body(b"Escape\x1Bseq");
        assert!(preview.is_binary);
        assert!(preview.text.contains("hex/ASCII preview"));
    }

    #[test]
    fn test_hex_dump_exact_offsets_and_ascii() {
        let input = b"abcdefghijklmnop\x00123456789";
        let preview = format_inspector_body_preview(input, CaptureTruncation::Unknown, 1000);
        assert!(preview.is_binary);
        let text = &preview.text;
        assert!(text.contains(
            "000000: 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70  |abcdefghijklmnop|"
        ));
        assert!(text.contains("000010: 00 31 32 33 34 35 36 37 38 39"));
        assert!(text.contains(".123456789"));
    }

    #[test]
    fn test_budget_strictly_enforced_including_footer() {
        for budget in [MIN_PREVIEW_BUDGET, 300, 500, 1024, 4096, 65536] {
            // Text payload larger than budget
            let text_input = "Hello world! Test text truncation boundary.\n".repeat(200);
            let text_preview = format_inspector_body_preview(
                text_input.as_bytes(),
                CaptureTruncation::Unknown,
                budget,
            );
            assert!(
                text_preview.text.len() <= budget,
                "Text preview length {} exceeded budget {}",
                text_preview.text.len(),
                budget
            );

            // Binary payload larger than budget
            let bin_input: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();
            let bin_preview =
                format_inspector_body_preview(&bin_input, CaptureTruncation::Unknown, budget);
            assert!(
                bin_preview.text.len() <= budget,
                "Binary preview length {} exceeded budget {}",
                bin_preview.text.len(),
                budget
            );
        }
    }

    #[test]
    fn test_preview_determinism() {
        let input = b"Deterministic payload check \x00 with mixed bytes";
        let p1 = format_inspector_body(input);
        let p2 = format_inspector_body(input);
        assert_eq!(p1, p2);
    }

    #[test]
    fn test_no_accidental_full_body_exposure() {
        // Massive 1 MiB text body
        let massive_text = "SecureDataPayload-Line\n".repeat(50_000);
        let preview = format_inspector_body(massive_text.as_bytes());
        assert!(preview.preview_truncated);
        assert!(preview.text.len() <= DEFAULT_PREVIEW_BUDGET);
        assert!(preview.text.len() < massive_text.len());
    }

    #[test]
    fn test_request_and_response_projection_integration() {
        let req = HttpRequest {
            method: HttpMethod::Post,
            raw_url: "/api/submit".to_string(),
            host: "127.0.0.1:8080".to_string(),
            path: "/api/submit".to_string(),
            query: String::new(),
            http_version: "HTTP/1.1".to_string(),
            headers: vec![HttpHeader::new("Content-Length", "25")],
            body: b"{\"status\":\"test_request\"}".to_vec(),
        };
        let req_preview = format_request_body_preview(&req);
        assert_eq!(req_preview.text, "{\"status\":\"test_request\"}");
        assert_eq!(req_preview.declared_content_length, Some(25));
        assert_eq!(req_preview.retained_bytes, 25);
        assert_eq!(req_preview.capture_truncation, CaptureTruncation::Unknown);

        let resp = HttpResponse {
            status_code: 200,
            status_text: "OK".to_string(),
            http_version: "HTTP/1.1".to_string(),
            headers: vec![HttpHeader::new("Content-Length", "100")],
            body: b"Partial".to_vec(), // 7 bytes vs declared 100
        };
        let resp_preview = format_response_body_preview(&resp);
        assert_eq!(resp_preview.text, "Partial");
        assert_eq!(resp_preview.declared_content_length, Some(100));
        assert_eq!(resp_preview.retained_bytes, 7);
        // TRUNC-01: Must be Unknown, NOT Truncated!
        assert_eq!(resp_preview.capture_truncation, CaptureTruncation::Unknown);
    }

    // --- REWORK R1 Specific Tests (TRUNC-01) ---

    #[test]
    fn test_head_response_with_positive_content_length_and_empty_body() {
        let resp = HttpResponse {
            status_code: 200,
            status_text: "OK".to_string(),
            http_version: "HTTP/1.1".to_string(),
            headers: vec![HttpHeader::new("Content-Length", "4096")],
            body: Vec::new(),
        };
        let preview = format_response_body_preview(&resp);
        assert_eq!(preview.text, "");
        assert_eq!(preview.retained_bytes, 0);
        assert_eq!(preview.rendered_bytes, 0);
        assert_eq!(preview.declared_content_length, Some(4096));
        assert!(!preview.preview_truncated);
        // Must be Unknown, NO false truncation alert
        assert_eq!(preview.capture_truncation, CaptureTruncation::Unknown);
        assert!(!preview.text.contains("truncated"));
    }

    #[test]
    fn test_304_not_modified_response_with_positive_content_length_and_empty_body() {
        let resp = HttpResponse {
            status_code: 304,
            status_text: "Not Modified".to_string(),
            http_version: "HTTP/1.1".to_string(),
            headers: vec![HttpHeader::new("Content-Length", "1024")],
            body: Vec::new(),
        };
        let preview = format_response_body_preview(&resp);
        assert_eq!(preview.text, "");
        assert_eq!(preview.retained_bytes, 0);
        assert_eq!(preview.rendered_bytes, 0);
        assert_eq!(preview.declared_content_length, Some(1024));
        assert!(!preview.preview_truncated);
        assert_eq!(preview.capture_truncation, CaptureTruncation::Unknown);
        assert!(!preview.text.contains("truncated"));
    }

    #[test]
    fn test_response_200_content_length_greater_than_retained_len() {
        // Premature EOF or network error: server promised 5000 bytes but sent only 100
        let resp = HttpResponse {
            status_code: 200,
            status_text: "OK".to_string(),
            http_version: "HTTP/1.1".to_string(),
            headers: vec![HttpHeader::new("Content-Length", "5000")],
            body: vec![b'X'; 100],
        };
        let preview = format_response_body_preview(&resp);
        assert_eq!(preview.retained_bytes, 100);
        assert_eq!(preview.declared_content_length, Some(5000));
        assert_eq!(preview.capture_truncation, CaptureTruncation::Unknown);
        assert!(!preview.preview_truncated);
        assert_eq!(preview.text, "X".repeat(100));
        assert!(!preview.text.contains("capture truncated"));
    }

    #[test]
    fn test_content_length_equal_to_retained_len() {
        let resp = HttpResponse {
            status_code: 200,
            status_text: "OK".to_string(),
            http_version: "HTTP/1.1".to_string(),
            headers: vec![HttpHeader::new("Content-Length", "10")],
            body: b"0123456789".to_vec(),
        };
        let preview = format_response_body_preview(&resp);
        assert_eq!(preview.retained_bytes, 10);
        assert_eq!(preview.declared_content_length, Some(10));
        assert_eq!(preview.capture_truncation, CaptureTruncation::Unknown);
        assert!(!preview.preview_truncated);
        assert_eq!(preview.text, "0123456789");
    }

    #[test]
    fn test_content_length_less_than_retained_len() {
        let resp = HttpResponse {
            status_code: 200,
            status_text: "OK".to_string(),
            http_version: "HTTP/1.1".to_string(),
            headers: vec![HttpHeader::new("Content-Length", "5")],
            body: b"0123456789".to_vec(),
        };
        let preview = format_response_body_preview(&resp);
        assert_eq!(preview.retained_bytes, 10);
        assert_eq!(preview.declared_content_length, Some(5));
        assert_eq!(preview.capture_truncation, CaptureTruncation::Unknown);
        assert!(!preview.preview_truncated);
    }

    #[test]
    fn test_content_length_absent() {
        let resp = HttpResponse {
            status_code: 200,
            status_text: "OK".to_string(),
            http_version: "HTTP/1.1".to_string(),
            headers: vec![HttpHeader::new("Server", "Test")],
            body: b"Hello".to_vec(),
        };
        let preview = format_response_body_preview(&resp);
        assert_eq!(preview.declared_content_length, None);
        assert_eq!(preview.retained_bytes, 5);
        assert_eq!(preview.capture_truncation, CaptureTruncation::Unknown);
    }

    #[test]
    fn test_chunked_transfer_encoding() {
        let resp = HttpResponse {
            status_code: 200,
            status_text: "OK".to_string(),
            http_version: "HTTP/1.1".to_string(),
            headers: vec![HttpHeader::new("Transfer-Encoding", "chunked")],
            body: b"Decoded chunked data".to_vec(),
        };
        let preview = format_response_body_preview(&resp);
        assert_eq!(preview.declared_content_length, None);
        assert_eq!(preview.retained_bytes, 20);
        assert_eq!(preview.capture_truncation, CaptureTruncation::Unknown);
        assert_eq!(preview.text, "Decoded chunked data");
    }

    #[test]
    fn test_visual_truncation_independent_of_capture_truncation() {
        // 100 KiB payload exceeding default 64 KiB budget
        let large_payload = "DataLine: 1234567890\n".repeat(5000); // 105,000 bytes
        let preview = format_inspector_body(large_payload.as_bytes());

        // Visual truncation MUST be true
        assert!(preview.preview_truncated);
        assert!(preview.text.len() <= DEFAULT_PREVIEW_BUDGET);
        assert_eq!(preview.capture_truncation, CaptureTruncation::Unknown);

        // Footer MUST explain preview truncation WITHOUT false claims of capture truncation
        assert!(preview.text.contains("[Preview truncated: showing"));
        assert!(preview.text.contains("retained bytes]"));
        assert!(!preview.text.contains("capture truncated"));
    }

    #[test]
    fn test_explicit_capture_truncation_when_provided() {
        let data = "Some payload data".as_bytes();
        let preview = format_inspector_body_preview(
            data,
            CaptureTruncation::Truncated {
                limit_bytes: 2 * 1024 * 1024,
            },
            DEFAULT_PREVIEW_BUDGET,
        );
        assert_eq!(
            preview.capture_truncation,
            CaptureTruncation::Truncated {
                limit_bytes: 2 * 1024 * 1024
            }
        );
    }

    #[test]
    fn test_qa_synthetic_json_payload_formatting() {
        let mut json = String::from("{\"items\": [");
        for i in 0..1000 {
            if i > 0 {
                json.push_str(", ");
            }
            json.push_str(&format!(
                "{{\"id\": {}, \"name\": \"SYNTHETIC_ITEM_{:04}\", \"active\": true}}",
                i, i
            ));
        }
        json.push_str("]}");
        assert!(json.len() > 10_000 && json.len() < DEFAULT_PREVIEW_BUDGET);

        let preview = format_inspector_body(json.as_bytes());
        assert!(!preview.is_binary);
        assert!(!preview.preview_truncated);
        assert_eq!(preview.rendered_bytes, json.len());
        assert_eq!(preview.text, json);
    }

    #[test]
    fn test_qa_embedded_invalid_utf8_sequence_triggers_hexdump() {
        let mut payload =
            b"GET /api/v1/test HTTP/1.1\r\nContent-Type: application/octet-stream\r\n\r\n".to_vec();
        payload.extend_from_slice(&[0xFF, 0xFE, 0xC0, 0xAF]); // Invalid UTF-8 bytes
        payload.extend_from_slice(b"Footer data line");

        let preview = format_inspector_body(&payload);
        assert!(preview.is_binary);
        assert!(preview.text.contains("Binary / non-textual payload"));
        assert!(preview.text.contains("000000: "));
        assert!(preview.text.contains("ff fe c0 af"));
    }

    #[test]
    fn test_qa_body_preview_budget_bounds_clamping() {
        assert_eq!(clamp_preview_budget(0), MIN_PREVIEW_BUDGET);
        assert_eq!(clamp_preview_budget(100), MIN_PREVIEW_BUDGET);
        assert_eq!(clamp_preview_budget(500), 500);
        assert_eq!(clamp_preview_budget(1_000_000), MAX_PREVIEW_BUDGET);

        let data = "A".repeat(5000);
        let preview_min = format_inspector_body_preview(
            data.as_bytes(),
            CaptureTruncation::Unknown,
            MIN_PREVIEW_BUDGET,
        );
        assert!(preview_min.preview_truncated);
        assert!(preview_min.text.len() <= MIN_PREVIEW_BUDGET);
        assert!(preview_min.text.contains("[Preview truncated: showing"));
    }
}
