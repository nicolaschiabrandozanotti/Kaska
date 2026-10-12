use sentinel_desktop::core::models::HttpMethod;
use sentinel_desktop::network::http_parser::{HttpParseError, HttpParser};

#[test]
fn test_parse_valid_http_get() {
    let raw = b"GET /audit/endpoints?filter=all HTTP/1.1\r\nHost: target-api.local:8080\r\nUser-Agent: Sentinel/0.1\r\nAccept: application/json\r\n\r\n";
    let req = HttpParser::parse_request(raw).expect("Should parse GET request");

    assert_eq!(req.method, HttpMethod::Get);
    assert_eq!(req.path, "/audit/endpoints");
    assert_eq!(req.query, "filter=all");
    assert_eq!(req.host, "target-api.local:8080");
    assert_eq!(req.headers.len(), 3);
    assert_eq!(
        req.header_value("user-agent"),
        Some("Sentinel/0.1".to_string())
    );
    assert!(req.body.is_empty());
}

#[test]
fn test_parse_valid_http_post() {
    let raw = b"POST /api/authenticate HTTP/1.1\r\nHost: 127.0.0.1:8989\r\nContent-Type: application/json\r\nContent-Length: 21\r\n\r\n{\"token\":\"secret123\"}";
    let req = HttpParser::parse_request(raw).expect("Should parse POST request");

    assert_eq!(req.method, HttpMethod::Post);
    assert_eq!(req.path, "/api/authenticate");
    assert_eq!(req.content_type(), "application/json");
    assert_eq!(req.body_as_utf8(), "{\"token\":\"secret123\"}");
}

#[test]
fn test_parse_http_response() {
    let raw = b"HTTP/1.1 200 OK\r\nServer: SentinelTestServer/1.0\r\nContent-Type: application/json\r\nContent-Length: 17\r\n\r\n{\"status\":\"live\"}";
    let resp = HttpParser::parse_response(raw).expect("Should parse response");

    assert_eq!(resp.status_code, 200);
    assert_eq!(resp.status_text, "OK");
    assert_eq!(resp.content_type(), "application/json");
    assert_eq!(resp.body_as_utf8(), "{\"status\":\"live\"}");
}

#[test]
fn test_parse_empty_stream_fails() {
    let result = HttpParser::parse_request(b"");
    assert_eq!(result, Err(HttpParseError::EmptyStream));
}
