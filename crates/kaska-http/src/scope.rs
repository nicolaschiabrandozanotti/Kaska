use std::net::IpAddr;

/// Audit Scope rules to prevent unintended requests and unauthorized lateral movement.
/// In Milestone 0.4, scope is strictly restricted to loopback destinations.
#[derive(Debug, Clone)]
pub struct AuditScope {
    pub name: String,
    pub allowed_hosts: Vec<String>,
    pub strict_enforcement: bool,
}

impl Default for AuditScope {
    fn default() -> Self {
        Self {
            name: "Authorized Localhost Lab".to_string(),
            allowed_hosts: vec![
                "127.0.0.1".to_string(),
                "localhost".to_string(),
                "::1".to_string(),
            ],
            strict_enforcement: true,
        }
    }
}

impl AuditScope {
    /// Extracts clean host without port or brackets.
    pub fn clean_host(host: &str) -> String {
        let trimmed = host.trim();
        if let Some(rest) = trimmed.strip_prefix('[') {
            if let Some(end) = rest.find(']') {
                return rest[..end].to_lowercase();
            }
        }
        if trimmed.matches(':').count() > 1 {
            return trimmed.to_lowercase();
        }
        trimmed
            .split(':')
            .next()
            .unwrap_or(trimmed)
            .trim()
            .to_lowercase()
    }

    /// Pre-resolution check: verifies that the target host name is in the allowed scope.
    pub fn is_allowed_host(&self, host: &str) -> bool {
        if !self.strict_enforcement {
            return true;
        }

        let host_clean = Self::clean_host(host);
        self.allowed_hosts
            .iter()
            .any(|allowed| Self::clean_host(allowed) == host_clean)
    }

    /// Post-resolution check: ensures resolved IP address is strictly loopback (127.0.0.0/8 or ::1).
    pub fn is_allowed_ip(&self, ip: &IpAddr) -> bool {
        if !self.strict_enforcement {
            // Milestone 0.4 baseline: even if strict_enforcement is toggled off,
            // external networking is not enabled until authorized in future milestones.
            return ip.is_loopback();
        }
        ip.is_loopback()
    }

    /// General host check, backwards compatible with previous callers.
    pub fn is_allowed(&self, host: &str) -> bool {
        self.is_allowed_host(host)
    }

    pub fn add_host(&mut self, host: impl Into<String>) {
        self.allowed_hosts.push(host.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_scope_allows_localhost() {
        let scope = AuditScope::default();
        assert!(scope.is_allowed("127.0.0.1:8080"));
        assert!(scope.is_allowed("localhost"));
        assert!(scope.is_allowed("[::1]:8080"));
        assert!(scope.is_allowed("::1"));
        assert!(!scope.is_allowed("unauthorized-victim.com"));
        assert!(!scope.is_allowed("192.168.1.100"));
        assert!(!scope.is_allowed("example.com:80"));
    }

    #[test]
    fn test_scope_ip_validation() {
        let scope = AuditScope::default();
        assert!(scope.is_allowed_ip(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(scope.is_allowed_ip(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))));
        assert!(scope.is_allowed_ip(&IpAddr::V6(Ipv6Addr::LOCALHOST)));

        // External IPs must be rejected
        assert!(!scope.is_allowed_ip(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(!scope.is_allowed_ip(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!scope.is_allowed_ip(&IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))));
    }
}
