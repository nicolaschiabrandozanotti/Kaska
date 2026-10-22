//! Canonical detection of sensitive HTTP headers for Kaska.
//!
//! Provides a single, centralized implementation for identifying authentication tokens,
//! session cookies, and API keys across the Inspector and Repeater subsystems.
//!
//! Note on coverage: This detector employs conservative matching for common credential header
//! patterns, but does NOT claim exhaustive detection of every possible proprietary secret header.

/// Determines whether an HTTP header name corresponds to known sensitive credentials.
///
/// Matching is strictly case-insensitive and trims surrounding whitespace.
/// Covers:
/// - Exact matches: `authorization`, `proxy-authorization`, `cookie`, `set-cookie`,
///   `x-api-key`, `api-key`, `proxy-authenticate`, `www-authenticate`.
/// - Pattern matches: headers starting with `x-auth-`, ending with `-api-key`,
///   or containing `token` or `secret` substrings.
pub fn is_sensitive_header(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "authorization"
            | "proxy-authorization"
            | "cookie"
            | "set-cookie"
            | "x-api-key"
            | "api-key"
            | "proxy-authenticate"
            | "www-authenticate"
    ) || lower.starts_with("x-auth-")
        || lower.ends_with("-api-key")
        || lower.contains("token")
        || lower.contains("secret")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonical_sensitive_header_exact_matches() {
        let exact_cases = [
            "Authorization",
            "authorization",
            "AUTHORIZATION",
            "Proxy-Authorization",
            "proxy-authorization",
            "Cookie",
            "cookie",
            "Set-Cookie",
            "set-cookie",
            "X-Api-Key",
            "x-api-key",
            "Api-Key",
            "api-key",
            "Proxy-Authenticate",
            "proxy-authenticate",
            "Www-Authenticate",
            "www-authenticate",
        ];
        for name in exact_cases {
            assert!(
                is_sensitive_header(name),
                "Expected '{}' to be sensitive",
                name
            );
            assert!(
                is_sensitive_header(&format!("  {}  ", name)),
                "Expected trimmed '{}' to be sensitive",
                name
            );
        }
    }

    #[test]
    fn test_canonical_sensitive_header_pattern_matches() {
        let pattern_cases = [
            "X-Auth-Token",
            "x-auth-signature",
            "Custom-Api-Key",
            "Service-api-key",
            "App-Token-Header",
            "session-token",
            "Client-Secret",
            "shared-secret-id",
        ];
        for name in pattern_cases {
            assert!(
                is_sensitive_header(name),
                "Expected pattern match '{}' to be sensitive",
                name
            );
        }
    }

    #[test]
    fn test_canonical_sensitive_header_non_sensitive() {
        let non_sensitive = [
            "Host",
            "User-Agent",
            "Accept",
            "Accept-Encoding",
            "Content-Type",
            "Content-Length",
            "X-Requested-With",
            "Origin",
            "Referer",
            "Cache-Control",
        ];
        for name in non_sensitive {
            assert!(
                !is_sensitive_header(name),
                "Expected '{}' to NOT be sensitive",
                name
            );
        }
    }
}
