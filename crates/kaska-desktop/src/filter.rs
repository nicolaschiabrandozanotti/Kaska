use kaska_http::models::HttpMethod;
use kaska_http::scope::AuditScope;
use kaska_http::store::TransactionSummary;

/// HTTP method filter criteria for the Inspector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MethodFilter {
    #[default]
    All,
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options,
    Connect,
    Other,
}

impl MethodFilter {
    /// Evaluates whether a given `HttpMethod` matches this method filter.
    pub fn matches(&self, method: &HttpMethod) -> bool {
        match self {
            MethodFilter::All => true,
            MethodFilter::Get => *method == HttpMethod::Get,
            MethodFilter::Post => *method == HttpMethod::Post,
            MethodFilter::Put => *method == HttpMethod::Put,
            MethodFilter::Delete => *method == HttpMethod::Delete,
            MethodFilter::Patch => *method == HttpMethod::Patch,
            MethodFilter::Head => *method == HttpMethod::Head,
            MethodFilter::Options => *method == HttpMethod::Options,
            MethodFilter::Connect => *method == HttpMethod::Connect,
            MethodFilter::Other => matches!(method, HttpMethod::Custom(_)),
        }
    }
}

/// HTTP status code filter criteria for the Inspector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HttpStatusFilter {
    #[default]
    All,
    Status1xx,
    Status2xx,
    Status3xx,
    Status4xx,
    Status5xx,
    NoResponse,
}

impl HttpStatusFilter {
    /// Evaluates whether a numeric status code matches this status filter.
    ///
    /// Status code 0 indicates no response was received.
    pub fn matches(&self, status_code: u16) -> bool {
        match self {
            HttpStatusFilter::All => true,
            HttpStatusFilter::Status1xx => (100..=199).contains(&status_code),
            HttpStatusFilter::Status2xx => (200..=299).contains(&status_code),
            HttpStatusFilter::Status3xx => (300..=399).contains(&status_code),
            HttpStatusFilter::Status4xx => (400..=499).contains(&status_code),
            HttpStatusFilter::Status5xx => (500..=599).contains(&status_code),
            HttpStatusFilter::NoResponse => status_code == 0,
        }
    }
}

/// Transaction outcome filter criteria for the Inspector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutcomeFilter {
    #[default]
    All,
    Pending,
    Completed,
    Failed,
}

impl OutcomeFilter {
    /// Evaluates whether a transaction outcome matches this filter.
    pub fn matches(&self, outcome: kaska_http::store::TransactionOutcome) -> bool {
        match self {
            OutcomeFilter::All => true,
            OutcomeFilter::Pending => outcome == kaska_http::store::TransactionOutcome::Pending,
            OutcomeFilter::Completed => outcome == kaska_http::store::TransactionOutcome::Completed,
            OutcomeFilter::Failed => outcome == kaska_http::store::TransactionOutcome::Failed,
        }
    }
}

/// Complete typed filter state for the Inspector list view.
///
/// Defaults to neutral state: all filters inactive, providing full visibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterState {
    pub search_query: String,
    pub method: MethodFilter,
    pub status: HttpStatusFilter,
    pub outcome: OutcomeFilter,
    pub only_in_scope: bool,
    pub hide_connect: bool,
    pub hide_failed: bool,
}

impl Default for FilterState {
    fn default() -> Self {
        Self {
            search_query: String::new(),
            method: MethodFilter::All,
            status: HttpStatusFilter::All,
            outcome: OutcomeFilter::All,
            only_in_scope: false,
            hide_connect: false,
            hide_failed: false,
        }
    }
}

impl FilterState {
    /// Resets all filter criteria to their neutral defaults (full visibility)
    /// without touching transaction data.
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// Evaluates whether a single transaction summary matches all active filter criteria.
    ///
    /// Rules:
    /// 1. All active criteria combine with logical AND.
    /// 2. Empty or whitespace-only search queries match everything.
    /// 3. Search query matches host or path via case-insensitive substring search.
    /// 4. MethodFilter::Other matches custom methods.
    /// 5. Status 1xx-5xx covers explicit HTTP ranges; NoResponse covers status_code == 0.
    /// 6. Outcome filter checks transaction outcome (Pending, Completed, Failed).
    /// 7. `hide_failed` excludes exclusively Failed transactions (completed 4xx/5xx remain visible).
    /// 8. `hide_connect` excludes CONNECT methods regardless of `method` filter.
    /// 9. `only_in_scope` visual classification uses `AuditScope::is_allowed_host()` without modifying scope.
    pub fn matches(&self, summary: &TransactionSummary, scope: &AuditScope) -> bool {
        // 1. hide_connect check
        if self.hide_connect && summary.method == HttpMethod::Connect {
            return false;
        }

        // 2. hide_failed check (only excludes TransactionOutcome::Failed)
        if self.hide_failed && summary.outcome == kaska_http::store::TransactionOutcome::Failed {
            return false;
        }

        // 3. Method check
        if !self.method.matches(&summary.method) {
            return false;
        }

        // 4. Status check
        if !self.status.matches(summary.status_code) {
            return false;
        }

        // 5. Outcome check
        if !self.outcome.matches(summary.outcome) {
            return false;
        }

        // 6. Search query check (case-insensitive substring on host or path)
        let trimmed_query = self.search_query.trim();
        if !trimmed_query.is_empty() {
            let query_lower = trimmed_query.to_lowercase();
            let host_match = summary.host.to_lowercase().contains(&query_lower);
            let path_match = summary.path.to_lowercase().contains(&query_lower);
            if !host_match && !path_match {
                return false;
            }
        }

        // 7. Scope check
        if self.only_in_scope && !scope.is_allowed_host(&summary.host) {
            return false;
        }

        true
    }

    /// Applies the filter state across an iterator of `TransactionSummary` items,
    /// returning a `Vec` of references to matching items.
    pub fn filter<'a>(
        &self,
        summaries: &'a [TransactionSummary],
        scope: &AuditScope,
    ) -> Vec<&'a TransactionSummary> {
        summaries
            .iter()
            .filter(|s| self.matches(s, scope))
            .collect()
    }

    /// Applies the filter state across a slice of `TransactionSummary` items,
    /// returning a `Vec<u64>` containing only the matching canonical transaction IDs.
    pub fn filter_to_ids(&self, summaries: &[TransactionSummary], scope: &AuditScope) -> Vec<u64> {
        summaries
            .iter()
            .filter(|s| self.matches(s, scope))
            .map(|s| s.id)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaska_http::models::HttpMethod;
    use kaska_http::scope::AuditScope;
    use kaska_http::store::{TransactionOutcome, TransactionSummary};

    fn dummy_summary(
        id: u64,
        method: HttpMethod,
        host: &str,
        path: &str,
        status: u16,
        outcome: TransactionOutcome,
    ) -> TransactionSummary {
        TransactionSummary {
            id,
            timestamp_rfc3339: "2026-10-17T12:00:00Z".to_string(),
            method,
            host: host.to_string(),
            path: path.to_string(),
            status_code: status,
            status_text: if status == 0 {
                "Pending".to_string()
            } else {
                "OK".to_string()
            },
            duration_ms: 10,
            response_size_bytes: 100,
            content_type: "text/plain".to_string(),
            outcome,
        }
    }

    #[test]
    fn test_filter_defaults_neutral() {
        let filter = FilterState::default();
        let scope = AuditScope::default();
        let s = dummy_summary(
            1,
            HttpMethod::Get,
            "localhost",
            "/api",
            200,
            TransactionOutcome::Completed,
        );
        assert!(filter.matches(&s, &scope));
    }

    #[test]
    fn test_filter_search_host_path_case_insensitive() {
        let mut filter = FilterState::default();
        let scope = AuditScope::default();
        let s = dummy_summary(
            1,
            HttpMethod::Get,
            "LocalHost",
            "/Api/Users",
            200,
            TransactionOutcome::Completed,
        );

        // Host substring match (case insensitive)
        filter.search_query = "LOCAL".to_string();
        assert!(filter.matches(&s, &scope));

        // Path substring match (case insensitive)
        filter.search_query = "users".to_string();
        assert!(filter.matches(&s, &scope));

        // Whitespace only does not filter
        filter.search_query = "   ".to_string();
        assert!(filter.matches(&s, &scope));

        // Non-matching query
        filter.search_query = "products".to_string();
        assert!(!filter.matches(&s, &scope));
    }

    #[test]
    fn test_filter_methods() {
        let scope = AuditScope::default();
        let s_get = dummy_summary(
            1,
            HttpMethod::Get,
            "127.0.0.1",
            "/",
            200,
            TransactionOutcome::Completed,
        );
        let s_custom = dummy_summary(
            2,
            HttpMethod::Custom("PROPFIND".to_string()),
            "127.0.0.1",
            "/",
            200,
            TransactionOutcome::Completed,
        );
        let s_connect = dummy_summary(
            3,
            HttpMethod::Connect,
            "127.0.0.1",
            "/",
            200,
            TransactionOutcome::Completed,
        );

        let mut filter = FilterState {
            method: MethodFilter::Get,
            ..Default::default()
        };
        assert!(filter.matches(&s_get, &scope));
        assert!(!filter.matches(&s_custom, &scope));
        assert!(!filter.matches(&s_connect, &scope));

        filter.method = MethodFilter::Other;
        assert!(!filter.matches(&s_get, &scope));
        assert!(filter.matches(&s_custom, &scope));

        filter.method = MethodFilter::Connect;
        assert!(filter.matches(&s_connect, &scope));
    }

    #[test]
    fn test_filter_status_codes_and_no_response() {
        let scope = AuditScope::default();
        let s_101 = dummy_summary(
            1,
            HttpMethod::Get,
            "127.0.0.1",
            "/",
            101,
            TransactionOutcome::Completed,
        );
        let s_200 = dummy_summary(
            2,
            HttpMethod::Get,
            "127.0.0.1",
            "/",
            200,
            TransactionOutcome::Completed,
        );
        let s_301 = dummy_summary(
            3,
            HttpMethod::Get,
            "127.0.0.1",
            "/",
            301,
            TransactionOutcome::Completed,
        );
        let s_404 = dummy_summary(
            4,
            HttpMethod::Get,
            "127.0.0.1",
            "/",
            404,
            TransactionOutcome::Completed,
        );
        let s_500 = dummy_summary(
            5,
            HttpMethod::Get,
            "127.0.0.1",
            "/",
            500,
            TransactionOutcome::Completed,
        );
        let s_none = dummy_summary(
            6,
            HttpMethod::Get,
            "127.0.0.1",
            "/",
            0,
            TransactionOutcome::Pending,
        );

        let mut filter = FilterState {
            status: HttpStatusFilter::Status1xx,
            ..Default::default()
        };
        assert!(filter.matches(&s_101, &scope));
        assert!(!filter.matches(&s_200, &scope));

        filter.status = HttpStatusFilter::Status2xx;
        assert!(filter.matches(&s_200, &scope));

        filter.status = HttpStatusFilter::Status3xx;
        assert!(filter.matches(&s_301, &scope));

        filter.status = HttpStatusFilter::Status4xx;
        assert!(filter.matches(&s_404, &scope));

        filter.status = HttpStatusFilter::Status5xx;
        assert!(filter.matches(&s_500, &scope));

        filter.status = HttpStatusFilter::NoResponse;
        assert!(filter.matches(&s_none, &scope));
        assert!(!filter.matches(&s_200, &scope));
    }

    #[test]
    fn test_filter_hide_failed_retains_completed_404_500() {
        let scope = AuditScope::default();
        let s_404 = dummy_summary(
            1,
            HttpMethod::Get,
            "127.0.0.1",
            "/",
            404,
            TransactionOutcome::Completed,
        );
        let s_500 = dummy_summary(
            2,
            HttpMethod::Get,
            "127.0.0.1",
            "/",
            500,
            TransactionOutcome::Completed,
        );
        let s_failed = dummy_summary(
            3,
            HttpMethod::Get,
            "127.0.0.1",
            "/",
            0,
            TransactionOutcome::Failed,
        );

        let filter = FilterState {
            hide_failed: true,
            ..Default::default()
        };

        // Completed 404 and 500 MUST remain visible even when hide_failed is active
        assert!(filter.matches(&s_404, &scope));
        assert!(filter.matches(&s_500, &scope));

        // Exclusively TransactionOutcome::Failed is excluded
        assert!(!filter.matches(&s_failed, &scope));
    }

    #[test]
    fn test_filter_hide_connect() {
        let scope = AuditScope::default();
        let s_connect = dummy_summary(
            1,
            HttpMethod::Connect,
            "example.com:443",
            "/",
            200,
            TransactionOutcome::Completed,
        );
        let s_get = dummy_summary(
            2,
            HttpMethod::Get,
            "127.0.0.1",
            "/",
            200,
            TransactionOutcome::Completed,
        );

        let filter = FilterState {
            hide_connect: true,
            ..Default::default()
        };
        assert!(!filter.matches(&s_connect, &scope));
        assert!(filter.matches(&s_get, &scope));
    }

    #[test]
    fn test_filter_only_in_scope() {
        let scope = AuditScope::default(); // allows localhost, 127.0.0.1, ::1
        let s_local = dummy_summary(
            1,
            HttpMethod::Get,
            "127.0.0.1",
            "/",
            200,
            TransactionOutcome::Completed,
        );
        let s_external = dummy_summary(
            2,
            HttpMethod::Get,
            "evil.com",
            "/",
            200,
            TransactionOutcome::Completed,
        );

        let filter = FilterState {
            only_in_scope: true,
            ..Default::default()
        };
        assert!(filter.matches(&s_local, &scope));
        assert!(!filter.matches(&s_external, &scope));
    }

    #[test]
    fn test_filter_conjunction_and_empty_result() {
        let scope = AuditScope::default();
        let s = dummy_summary(
            1,
            HttpMethod::Post,
            "127.0.0.1",
            "/login",
            200,
            TransactionOutcome::Completed,
        );

        let filter = FilterState {
            search_query: "login".to_string(),
            method: MethodFilter::Post,
            status: HttpStatusFilter::Status2xx,
            outcome: OutcomeFilter::Completed,
            only_in_scope: true,
            hide_connect: false,
            hide_failed: false,
        };
        assert!(filter.matches(&s, &scope));

        // Contradictory method -> 0 results
        let mut filter_empty = filter.clone();
        filter_empty.method = MethodFilter::Get;
        assert!(!filter_empty.matches(&s, &scope));
    }
}
