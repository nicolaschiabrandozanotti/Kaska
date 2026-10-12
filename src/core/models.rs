use std::fmt;

/// HTTP request methods supported by the native engine
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options,
    Connect,
    Custom(String),
}

impl HttpMethod {
    pub fn from_str_prefix(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "GET" => HttpMethod::Get,
            "POST" => HttpMethod::Post,
            "PUT" => HttpMethod::Put,
            "DELETE" => HttpMethod::Delete,
            "PATCH" => HttpMethod::Patch,
            "HEAD" => HttpMethod::Head,
            "OPTIONS" => HttpMethod::Options,
            "CONNECT" => HttpMethod::Connect,
            other => HttpMethod::Custom(other.to_string()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Delete => "DELETE",
            HttpMethod::Patch => "PATCH",
            HttpMethod::Head => "HEAD",
            HttpMethod::Options => "OPTIONS",
            HttpMethod::Connect => "CONNECT",
            HttpMethod::Custom(s) => s.as_str(),
        }
    }
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// HTTP header key-value pair
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

impl HttpHeader {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

/// Structured representation of an incoming/captured HTTP Request
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub raw_url: String,
    pub host: String,
    pub path: String,
    pub query: String,
    pub http_version: String,
    pub headers: Vec<HttpHeader>,
    pub body: Vec<u8>,
}

impl HttpRequest {
    pub fn content_type(&self) -> String {
        self.header_value("content-type")
            .unwrap_or_else(|| "-".to_string())
    }

    pub fn header_value(&self, key: &str) -> Option<String> {
        let key_lower = key.to_lowercase();
        self.headers
            .iter()
            .find(|h| h.name.to_lowercase() == key_lower)
            .map(|h| h.value.clone())
    }

    pub fn headers_raw_text(&self) -> String {
        let mut out = String::new();
        for h in &self.headers {
            out.push_str(&format!("{}: {}\n", h.name, h.value));
        }
        out
    }

    pub fn body_as_utf8(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }

    pub fn content_length(&self) -> Option<usize> {
        self.header_value("content-length")
            .and_then(|v| v.trim().parse::<usize>().ok())
    }

    pub fn is_chunked(&self) -> bool {
        self.header_value("transfer-encoding")
            .map(|v| v.to_lowercase().contains("chunked"))
            .unwrap_or(false)
    }
}

/// Structured representation of an HTTP Response
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status_code: u16,
    pub status_text: String,
    pub http_version: String,
    pub headers: Vec<HttpHeader>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn content_type(&self) -> String {
        self.header_value("content-type")
            .unwrap_or_else(|| "-".to_string())
    }

    pub fn header_value(&self, key: &str) -> Option<String> {
        let key_lower = key.to_lowercase();
        self.headers
            .iter()
            .find(|h| h.name.to_lowercase() == key_lower)
            .map(|h| h.value.clone())
    }

    pub fn content_length(&self) -> Option<usize> {
        self.header_value("content-length")
            .and_then(|v| v.trim().parse::<usize>().ok())
    }

    pub fn is_chunked(&self) -> bool {
        self.header_value("transfer-encoding")
            .map(|v| v.to_lowercase().contains("chunked"))
            .unwrap_or(false)
    }

    pub fn headers_raw_text(&self) -> String {
        let mut out = String::new();
        for h in &self.headers {
            out.push_str(&format!("{}: {}\n", h.name, h.value));
        }
        out
    }

    pub fn body_as_utf8(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }
}

/// Lifecycle state of an HTTP transaction
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionState {
    Pending,
    Completed,
    Failed(String),
}

/// A complete captured HTTP transaction combining request, response and timing
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpTransaction {
    pub id: u64,
    pub timestamp_rfc3339: String,
    pub request: HttpRequest,
    pub response: Option<HttpResponse>,
    pub duration_ms: u64,
    pub state: TransactionState,
}

impl HttpTransaction {
    pub fn is_error(&self) -> bool {
        match &self.response {
            Some(res) => res.status_code >= 400,
            None => true,
        }
    }

    pub fn status_code(&self) -> u16 {
        self.response.as_ref().map(|r| r.status_code).unwrap_or(0)
    }

    pub fn status_text(&self) -> &str {
        self.response
            .as_ref()
            .map(|r| r.status_text.as_str())
            .unwrap_or(match &self.state {
                TransactionState::Pending => "Pending",
                TransactionState::Failed(_) => "Failed",
                TransactionState::Completed => "-",
            })
    }

    pub fn content_type(&self) -> String {
        self.response
            .as_ref()
            .map(|r| r.content_type())
            .unwrap_or_else(|| self.request.content_type())
    }

    pub fn response_size_bytes(&self) -> usize {
        self.response.as_ref().map(|r| r.body.len()).unwrap_or(0)
    }
}
