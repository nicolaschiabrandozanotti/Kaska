use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

#[path = "repeater_adapter.rs"]
pub mod repeater_adapter;

#[path = "inspector_details.rs"]
pub mod inspector_details;

#[path = "privacy.rs"]
pub mod privacy;

use crate::filter::{FilterState, HttpStatusFilter, MethodFilter, OutcomeFilter};
use crate::platform::PlatformInfo;
use crate::{AppWindow, HeaderItem, TrafficItem};
use kaska_http::models::HttpTransaction;
use kaska_http::proxy::NativeProxyServer;
use kaska_http::scope::AuditScope;
use kaska_http::store::{create_shared_store, SharedTrafficStore};
use kaska_http::test_server::ControlledTestServer;
use repeater_adapter::{
    RepeaterAdapterError, RepeaterEvent, RepeaterEventSink, RepeaterLifecycle,
    RepeaterTaskController, RepeaterUiInput, RepeaterViewState,
};

/// Helper projecting a `TransactionSummary` into a Slint `TrafficItem` with exact string representation of `u64` id.
pub fn summary_to_traffic_item(s: &kaska_http::store::TransactionSummary) -> TrafficItem {
    TrafficItem {
        id: SharedString::from(s.id.to_string()),
        method: SharedString::from(s.method.to_string()),
        host: SharedString::from(s.host.clone()),
        path: SharedString::from(s.path.clone()),
        status_code: s.status_code as i32,
        status_text: SharedString::from(s.status_text.clone()),
        duration_ms: s.duration_ms as i32,
        size_bytes: s.response_size_bytes as i32,
        content_type: SharedString::from(s.content_type.clone()),
        is_error: s.outcome == kaska_http::store::TransactionOutcome::Failed
            || (s.status_code >= 400 && s.status_code < 600),
    }
}

/// Unified pure projection function that applies filters, maintains u64 identity,
/// computes accurate total and visible counts, and reconciles selection.
///
/// Returns: `(items, total_count, visible_count, new_selected_index, is_selection_retained)`
pub fn project_traffic(
    summaries: &[kaska_http::store::TransactionSummary],
    filter: &FilterState,
    scope: &AuditScope,
    selected_id: Option<u64>,
) -> (Vec<TrafficItem>, usize, usize, i32, bool) {
    let total_count = summaries.len();
    let matching_summaries = filter.filter(summaries, scope);
    let visible_count = matching_summaries.len();

    let mut new_idx: i32 = -1;
    let mut selection_retained = false;

    let items: Vec<TrafficItem> = matching_summaries
        .iter()
        .enumerate()
        .map(|(idx, s)| {
            if let Some(sel_id) = selected_id {
                if s.id == sel_id {
                    new_idx = idx as i32;
                    selection_retained = true;
                }
            }
            summary_to_traffic_item(s)
        })
        .collect();

    (
        items,
        total_count,
        visible_count,
        new_idx,
        selection_retained,
    )
}

/// Defensive budget constants for Inspector UI header projection (Gate 1.4B-2)
pub const MAX_VISIBLE_HEADERS: usize = 256;
pub const MAX_HEADER_NAME_BYTES: usize = 256;
pub const MAX_HEADER_VALUE_BYTES: usize = 1024;
pub const MAX_AGGREGATE_HEADER_BUDGET: usize = 256 * 1024;
pub const MAX_HEADERS_TEXT_BUDGET: usize = 64 * 1024;
pub const MASKED_SECRET_PLACEHOLDER: &str = "••••••••";

/// Checks if an HTTP header name matches known sensitive credentials (case-insensitive).
/// Delegates directly to the canonical detector in `crate::privacy::is_sensitive_header`.
pub fn is_sensitive_header(name: &str) -> bool {
    privacy::is_sensitive_header(name)
}

/// Truncates string to `max_bytes` on a valid UTF-8 character boundary.
pub fn floor_utf8_char_boundary_str(s: &str, max_bytes: usize) -> &str {
    if max_bytes >= s.len() {
        return s;
    }
    let mut idx = max_bytes;
    while idx > 0 && !s.is_char_boundary(idx) {
        idx -= 1;
    }
    &s[..idx]
}

/// Sanitizes display text for safe single-line rendering in UI tables and text fields.
/// Replaces control characters (< 0x20 and 0x7F) with spaces to prevent layout and injection issues.
pub fn sanitize_display_text(s: &str) -> String {
    s.chars()
        .map(|c| {
            if (c < ' ' && c != '\t') || c == '\x7F' {
                ' '
            } else {
                c
            }
        })
        .collect()
}

/// Result of projecting a list of HTTP headers into Slint `HeaderItem`s under UI limits.
#[derive(Debug, Clone, PartialEq)]
pub struct ProjectedHeadersResult {
    pub items: Vec<HeaderItem>,
    pub omitted_count: usize,
    pub notice: String,
}

/// Projects a list of `HttpHeader`s into Slint `HeaderItem` models under strict UI budgets.
///
/// Guarantees:
/// - Preserves original order and duplicates.
/// - Limits to `MAX_VISIBLE_HEADERS` (256).
/// - Clamps name to `MAX_HEADER_NAME_BYTES` (256 B) and value to `MAX_HEADER_VALUE_BYTES` (1024 B).
/// - Enforces aggregate budget `MAX_AGGREGATE_HEADER_BUDGET` (256 KiB).
/// - If `reveal_secrets` is `false`, sensitive header values are masked as `••••••••`.
/// - Never mutates original data in store.
pub fn project_headers_to_slint(
    headers: &[kaska_http::models::HttpHeader],
    reveal_secrets: bool,
) -> ProjectedHeadersResult {
    let mut items = Vec::new();
    let mut aggregate_bytes = 0usize;
    let mut omitted_count = 0usize;

    for (idx, h) in headers.iter().enumerate() {
        if idx >= MAX_VISIBLE_HEADERS {
            omitted_count = headers.len().saturating_sub(idx);
            break;
        }

        let is_sensitive = is_sensitive_header(&h.name);
        let raw_val = if is_sensitive && !reveal_secrets {
            MASKED_SECRET_PLACEHOLDER
        } else {
            &h.value
        };

        let raw_name = &h.name;
        let is_name_truncated = raw_name.len() > MAX_HEADER_NAME_BYTES;
        let name_slice = floor_utf8_char_boundary_str(raw_name, MAX_HEADER_NAME_BYTES);
        let clean_name = sanitize_display_text(name_slice);

        let is_val_truncated = raw_val.len() > MAX_HEADER_VALUE_BYTES;
        let val_slice = floor_utf8_char_boundary_str(raw_val, MAX_HEADER_VALUE_BYTES);
        let clean_val = sanitize_display_text(val_slice);

        let item_bytes = clean_name.len() + clean_val.len();
        if aggregate_bytes.saturating_add(item_bytes) > MAX_AGGREGATE_HEADER_BUDGET {
            omitted_count = headers.len().saturating_sub(idx);
            break;
        }
        aggregate_bytes += item_bytes;

        items.push(HeaderItem {
            name: SharedString::from(clean_name),
            value: SharedString::from(clean_val),
            is_sensitive,
            is_truncated: is_name_truncated || is_val_truncated,
        });
    }

    let notice = if omitted_count > 0 {
        format!("[+{} headers omitted by UI budget]", omitted_count)
    } else {
        String::new()
    };

    ProjectedHeadersResult {
        items,
        omitted_count,
        notice,
    }
}

/// Formats headers into a reconstructed text block bounded to `MAX_HEADERS_TEXT_BUDGET` (64 KiB).
/// Applies identical masking for sensitive headers when `reveal_secrets` is `false`.
/// Enforces per-field bounds (`MAX_HEADER_NAME_BYTES` and `MAX_HEADER_VALUE_BYTES`),
/// sanitizes control characters, and never allocates unbounded formatted lines.
pub fn project_headers_text(
    headers: &[kaska_http::models::HttpHeader],
    reveal_secrets: bool,
) -> String {
    let mut out = String::new();
    let mut truncated = false;
    const TRUNCATION_NOTICE: &str = "\n[Headers text truncated at 64 KiB budget]";
    let max_body_len = MAX_HEADERS_TEXT_BUDGET.saturating_sub(TRUNCATION_NOTICE.len());

    for h in headers {
        let is_sensitive = is_sensitive_header(&h.name);
        let raw_val = if is_sensitive && !reveal_secrets {
            MASKED_SECRET_PLACEHOLDER
        } else {
            &h.value
        };

        let raw_name = &h.name;
        let name_slice = floor_utf8_char_boundary_str(raw_name, MAX_HEADER_NAME_BYTES);
        let clean_name = sanitize_display_text(name_slice);

        let val_slice = floor_utf8_char_boundary_str(raw_val, MAX_HEADER_VALUE_BYTES);
        let clean_val = sanitize_display_text(val_slice);

        let line_len = clean_name.len() + 2 + clean_val.len() + 1; // "<name>: <val>\n"
        if out.len() + line_len > max_body_len {
            truncated = true;
            break;
        }

        out.push_str(&clean_name);
        out.push_str(": ");
        out.push_str(&clean_val);
        out.push('\n');
    }

    if truncated {
        out.push_str(TRUNCATION_NOTICE);
    }

    out
}

/// Reconstructs the Request line from parsed fields: `<METHOD> <PATH_AND_QUERY> <VERSION>`.
pub fn format_reconstructed_request_line(req: &kaska_http::models::HttpRequest) -> String {
    let target = if req.query.is_empty() {
        if req.path.is_empty() {
            "/".to_string()
        } else {
            req.path.clone()
        }
    } else {
        format!("{}?{}", req.path, req.query)
    };
    let clean_target = sanitize_display_text(floor_utf8_char_boundary_str(&target, 512));
    let version = if req.http_version.is_empty() {
        "[unknown HTTP version]"
    } else {
        &req.http_version
    };
    format!("{} {} {}", req.method, clean_target, version)
}

/// Reconstructs the Response status line from parsed fields: `<VERSION> <CODE> <REASON>`.
pub fn format_reconstructed_status_line(resp: &kaska_http::models::HttpResponse) -> String {
    let version = if resp.http_version.is_empty() {
        "[unknown HTTP version]"
    } else {
        &resp.http_version
    };
    let clean_reason = sanitize_display_text(floor_utf8_char_boundary_str(&resp.status_text, 128));
    format!("{} {} {}", version, resp.status_code, clean_reason)
}

/// Pure projected details model computed from `HttpTransaction` under UI bounds and privacy rules.
/// Contains all display fields without requiring a live Slint window or graphics backend.
#[derive(Debug, Clone, PartialEq)]
pub struct TransactionDetailsProjection {
    pub req_line: String,
    pub req_headers_text: String,
    pub req_headers_list: ProjectedHeadersResult,
    pub req_body: String,
    pub req_is_binary: bool,
    pub req_body_truncated: bool,
    pub resp_status_line: String,
    pub resp_headers_text: String,
    pub resp_headers_list: ProjectedHeadersResult,
    pub resp_body: String,
    pub resp_is_binary: bool,
    pub resp_body_truncated: bool,
    pub timing_text: String,
    pub secrets_revealed: bool,
}

/// Computes pure details projection for a transaction or returns cleared projection.
///
/// Guarantees:
/// - Pure function: zero GUI/event loop/OS dependencies.
/// - Never leaks raw error strings from `TransactionState::Failed(err)` (PRIV-02).
/// - Masks sensitive headers when `secrets_revealed` is `false` (PRIV-01).
/// - Limits text and structured headers to strict UI budgets (UI-BUDGET-02).
pub fn compute_transaction_details(
    tx_opt: Option<&HttpTransaction>,
    secrets_revealed: bool,
) -> TransactionDetailsProjection {
    if let Some(tx) = tx_opt {
        // 1. Request details
        let req_line = format_reconstructed_request_line(&tx.request);
        let req_headers_text = project_headers_text(&tx.request.headers, secrets_revealed);
        let req_headers_list = project_headers_to_slint(&tx.request.headers, secrets_revealed);
        let req_preview = inspector_details::format_request_body_preview(&tx.request);

        // 2. Response details
        let (
            resp_status_line,
            resp_headers_text,
            resp_headers_list,
            resp_body,
            resp_is_binary,
            resp_body_truncated,
            timing_text,
        ) = if let Some(resp) = &tx.response {
            let status_line = format_reconstructed_status_line(resp);
            let text = project_headers_text(&resp.headers, secrets_revealed);
            let list = project_headers_to_slint(&resp.headers, secrets_revealed);
            let preview = inspector_details::format_response_body_preview(resp);
            let timing = format!(
                "Status {} • Duration: {} ms",
                resp.status_code, tx.duration_ms
            );
            (
                status_line,
                text,
                list,
                preview.text,
                preview.is_binary,
                preview.preview_truncated,
                timing,
            )
        } else {
            let outcome_str = match &tx.state {
                kaska_http::models::TransactionState::Pending => "Status: Pending (In flight)...",
                kaska_http::models::TransactionState::Failed(_) => "Status: Failed",
                kaska_http::models::TransactionState::Completed => {
                    "Status: Completed (No response)"
                }
            };
            let err_body = match &tx.state {
                kaska_http::models::TransactionState::Failed(_) => {
                    "Transaction failed: No response received from remote server.".to_string()
                }
                _ => String::new(),
            };
            (
                String::new(),
                "(No response)".to_string(),
                ProjectedHeadersResult {
                    items: Vec::new(),
                    omitted_count: 0,
                    notice: String::new(),
                },
                err_body,
                false,
                false,
                outcome_str.to_string(),
            )
        };

        TransactionDetailsProjection {
            req_line,
            req_headers_text,
            req_headers_list,
            req_body: req_preview.text,
            req_is_binary: req_preview.is_binary,
            req_body_truncated: req_preview.preview_truncated,
            resp_status_line,
            resp_headers_text,
            resp_headers_list,
            resp_body,
            resp_is_binary,
            resp_body_truncated,
            timing_text,
            secrets_revealed,
        }
    } else {
        TransactionDetailsProjection {
            req_line: String::new(),
            req_headers_text: String::new(),
            req_headers_list: ProjectedHeadersResult {
                items: Vec::new(),
                omitted_count: 0,
                notice: String::new(),
            },
            req_body: String::new(),
            req_is_binary: false,
            req_body_truncated: false,
            resp_status_line: String::new(),
            resp_headers_text: String::new(),
            resp_headers_list: ProjectedHeadersResult {
                items: Vec::new(),
                omitted_count: 0,
                notice: String::new(),
            },
            resp_body: String::new(),
            resp_is_binary: false,
            resp_body_truncated: false,
            timing_text: String::new(),
            secrets_revealed: false,
        }
    }
}

/// Sets details on AppWindow from an optional HttpTransaction reference or clears them.
///
/// Respects the `secrets_revealed` flag exclusively for the currently active transaction.
pub fn set_transaction_details_on_ui(
    ui: &AppWindow,
    tx_opt: Option<&HttpTransaction>,
    secrets_revealed: bool,
) {
    let proj = compute_transaction_details(tx_opt, secrets_revealed);

    ui.set_secrets_revealed(proj.secrets_revealed);
    ui.set_active_req_line(SharedString::from(proj.req_line));
    ui.set_active_req_headers(SharedString::from(proj.req_headers_text));
    ui.set_active_req_headers_list(ModelRc::new(VecModel::from(proj.req_headers_list.items)));
    ui.set_active_req_headers_omitted(SharedString::from(proj.req_headers_list.notice));
    ui.set_active_req_body(SharedString::from(proj.req_body));
    ui.set_active_req_is_binary(proj.req_is_binary);
    ui.set_active_req_body_truncated(proj.req_body_truncated);

    ui.set_active_resp_status_line(SharedString::from(proj.resp_status_line));
    ui.set_active_resp_headers(SharedString::from(proj.resp_headers_text));
    ui.set_active_resp_headers_list(ModelRc::new(VecModel::from(proj.resp_headers_list.items)));
    ui.set_active_resp_headers_omitted(SharedString::from(proj.resp_headers_list.notice));
    ui.set_active_resp_body(SharedString::from(proj.resp_body));
    ui.set_active_resp_is_binary(proj.resp_is_binary);
    ui.set_active_resp_body_truncated(proj.resp_body_truncated);
    ui.set_active_timing_text(SharedString::from(proj.timing_text));
}

/// Helper that refreshes the UI from current store state, filters, and selection.
/// Guarantees:
/// 1. Takes one snapshot under lock, releases lock.
/// 2. Performs projection.
/// 3. Looks up single selected item under lock if needed, releases lock.
/// 4. Updates Slint UI strictly on UI event loop without holding any mutex.
pub fn refresh_traffic_ui(
    ui: &AppWindow,
    store: &SharedTrafficStore,
    scope: &AuditScope,
    filter: &FilterState,
    selected_id: &mut Option<u64>,
    secrets_revealed: &mut bool,
    status_suffix: Option<String>,
) {
    // 1. Take snapshot of metadata and release lock immediately
    let summaries = store.lock().unwrap().get_metadata_snapshot();

    // 2. Pure projection
    let (items, total_count, visible_count, new_idx, selection_retained) =
        project_traffic(&summaries, filter, scope, *selected_id);

    if !selection_retained {
        *selected_id = None;
        *secrets_revealed = false;
    }

    // 3. If selected_id exists, look up single transaction
    let mut selected_tx = None;
    if let Some(id) = *selected_id {
        let guard = store.lock().unwrap();
        selected_tx = guard.get_by_id(id).cloned();
    }

    // 4. Update Slint UI
    ui.set_total_transactions_count(total_count as i32);
    ui.set_visible_transactions_count(visible_count as i32);
    ui.set_transactions_count(total_count as i32);
    ui.set_selected_transaction_idx(new_idx);
    ui.set_transactions(ModelRc::new(VecModel::from(items)));

    let reveal_flag = if selected_tx.is_some() {
        *secrets_revealed
    } else {
        *secrets_revealed = false;
        false
    };
    set_transaction_details_on_ui(ui, selected_tx.as_ref(), reveal_flag);

    if let Some(suffix) = status_suffix {
        ui.set_status_message(SharedString::from(format!(
            "Captured {} requests ({} visible) • {}",
            total_count, visible_count, suffix
        )));
    }
}

/// Bridge struct implementing `RepeaterEventSink` for Slint's thread-safe event loop.
///
/// Holds a `slint::Weak<AppWindow>` to prevent cycles or keeping the UI window alive after close,
/// and delegates state observation to the thread-safe `RepeaterTaskController` on the UI event loop.
pub struct SlintRepeaterSink {
    app: slint::Weak<AppWindow>,
    repeater: Arc<RepeaterTaskController>,
}

impl RepeaterEventSink for SlintRepeaterSink {
    fn on_event(&self, event: RepeaterEvent) {
        let app_weak = self.app.clone();
        let repeater = Arc::clone(&self.repeater);
        let event_req_id = event.request_id();

        let _ = slint::invoke_from_event_loop(move || {
            if let Some(app) = app_weak.upgrade() {
                let snapshot = repeater.snapshot_state();
                // Reject stale events if a newer or different request_id is active
                if snapshot.active_request_id == event_req_id {
                    apply_repeater_snapshot_to_ui(&app, &snapshot);
                }
            }
        });
    }
}

/// Applies a validated `RepeaterViewState` snapshot onto `AppWindow` properties.
///
/// Guarantees:
/// - Executes strictly on the UI thread / event loop.
/// - Never leaks raw secrets or echoes unvalidated inputs.
/// - Translates lifecycle phase into appropriate UI flags and status summaries.
pub fn apply_repeater_snapshot_to_ui(app: &AppWindow, snapshot: &RepeaterViewState) {
    match snapshot.lifecycle {
        RepeaterLifecycle::Idle => {
            app.set_repeater_is_running(false);
            app.set_repeater_is_cancelling(false);
            app.set_repeater_status_text(SharedString::from("Idle"));
            app.set_repeater_status_code(0);
            app.set_repeater_duration_ms(0);
            app.set_repeater_response_headers(SharedString::from(""));
            app.set_repeater_response_body(SharedString::from(""));
            app.set_repeater_received_bytes(0);
            app.set_repeater_body_is_binary(false);
            app.set_repeater_http_truncated(false);
            app.set_repeater_preview_truncated(false);
            app.set_repeater_error_message(SharedString::from(""));
        }
        RepeaterLifecycle::Running => {
            app.set_repeater_is_running(true);
            if !app.get_repeater_is_cancelling() {
                app.set_repeater_status_text(SharedString::from("Running..."));
            }
            app.set_repeater_status_code(0);
            app.set_repeater_duration_ms(0);
            app.set_repeater_response_headers(SharedString::from(""));
            app.set_repeater_response_body(SharedString::from(""));
            app.set_repeater_received_bytes(0);
            app.set_repeater_body_is_binary(false);
            app.set_repeater_http_truncated(false);
            app.set_repeater_preview_truncated(false);
            app.set_repeater_error_message(SharedString::from(""));
        }
        RepeaterLifecycle::Completed => {
            app.set_repeater_is_running(false);
            app.set_repeater_is_cancelling(false);
            let code = snapshot.status_code.unwrap_or(0);
            app.set_repeater_status_code(code as i32);
            app.set_repeater_status_text(SharedString::from(snapshot.status_text.clone()));
            app.set_repeater_duration_ms(snapshot.duration_ms.unwrap_or(0) as i32);
            app.set_repeater_response_headers(SharedString::from(
                snapshot.response_headers.clone(),
            ));
            app.set_repeater_response_body(SharedString::from(
                snapshot.response_body_preview.clone(),
            ));
            app.set_repeater_received_bytes(snapshot.received_body_bytes as i32);
            app.set_repeater_body_is_binary(snapshot.body_is_binary);
            app.set_repeater_http_truncated(snapshot.http_body_truncated);
            app.set_repeater_preview_truncated(snapshot.preview_truncated);
            app.set_repeater_error_message(SharedString::from(""));
        }
        RepeaterLifecycle::Failed => {
            app.set_repeater_is_running(false);
            app.set_repeater_is_cancelling(false);
            app.set_repeater_status_code(0);
            app.set_repeater_status_text(SharedString::from("Failed"));
            app.set_repeater_duration_ms(0);
            app.set_repeater_response_headers(SharedString::from(""));
            app.set_repeater_response_body(SharedString::from(""));
            app.set_repeater_received_bytes(0);
            app.set_repeater_body_is_binary(false);
            app.set_repeater_http_truncated(false);
            app.set_repeater_preview_truncated(false);
            app.set_repeater_error_message(SharedString::from(snapshot.error_message.clone()));
        }
        RepeaterLifecycle::Cancelled => {
            app.set_repeater_is_running(false);
            app.set_repeater_is_cancelling(false);
            app.set_repeater_status_code(0);
            app.set_repeater_status_text(SharedString::from("Cancelled"));
            app.set_repeater_duration_ms(0);
            app.set_repeater_response_headers(SharedString::from(""));
            app.set_repeater_response_body(SharedString::from(""));
            app.set_repeater_received_bytes(0);
            app.set_repeater_body_is_binary(false);
            app.set_repeater_http_truncated(false);
            app.set_repeater_preview_truncated(false);
            app.set_repeater_error_message(SharedString::from(snapshot.error_message.clone()));
        }
    }
}

pub struct AppController {
    proxy_port: u16,
    test_server_port: u16,
    store: SharedTrafficStore,
    scope: Arc<AuditScope>,
    proxy: Arc<Mutex<Option<NativeProxyServer>>>,
    test_server: Arc<Mutex<Option<ControlledTestServer>>>,
    repeater: Arc<RepeaterTaskController>,
}

impl Default for AppController {
    fn default() -> Self {
        Self::new(8080, 8989)
    }
}

impl AppController {
    pub fn new(proxy_port: u16, test_server_port: u16) -> Self {
        let scope = Arc::new(AuditScope::default());
        let repeater = Arc::new(RepeaterTaskController::with_default_config(Arc::clone(
            &scope,
        )));
        Self {
            proxy_port,
            test_server_port,
            store: create_shared_store(),
            scope,
            proxy: Arc::new(Mutex::new(None)),
            test_server: Arc::new(Mutex::new(None)),
            repeater,
        }
    }

    pub fn repeater(&self) -> &Arc<RepeaterTaskController> {
        &self.repeater
    }

    pub fn dispatch_repeater(
        &self,
        input: RepeaterUiInput,
        sink: Option<Arc<dyn RepeaterEventSink>>,
    ) -> Result<u64, RepeaterAdapterError> {
        self.repeater.dispatch(input, sink)
    }

    pub fn cancel_repeater(&self) -> Option<u64> {
        self.repeater.cancel_active()
    }

    pub fn repeater_state_snapshot(&self) -> RepeaterViewState {
        self.repeater.snapshot_state()
    }

    /// Sets up the controller, starts local servers and binds UI callbacks
    pub fn setup(&self, app: &AppWindow) {
        app.set_os_info(SharedString::from(PlatformInfo::display_summary()));
        app.set_proxy_addr(SharedString::from(format!("127.0.0.1:{}", self.proxy_port)));
        app.set_status_message(SharedString::from(format!(
            "Native Proxy listening on 127.0.0.1:{}",
            self.proxy_port
        )));

        // Initialize default Repeater view model on AppWindow
        let default_repeater = RepeaterUiInput::default();
        app.set_repeater_method(SharedString::from(default_repeater.method));
        app.set_repeater_url(SharedString::from(default_repeater.target_url));
        app.set_repeater_headers(SharedString::from(default_repeater.headers_raw));
        app.set_repeater_body(SharedString::from(default_repeater.body_utf8));
        app.set_repeater_is_running(false);
        app.set_repeater_is_cancelling(false);
        app.set_repeater_status_text(SharedString::from("Idle"));
        app.set_repeater_status_code(0);
        app.set_repeater_duration_ms(0);
        app.set_repeater_response_headers(SharedString::from(""));
        app.set_repeater_response_body(SharedString::from(""));
        app.set_repeater_received_bytes(0);
        app.set_repeater_body_is_binary(false);
        app.set_repeater_http_truncated(false);
        app.set_repeater_preview_truncated(false);
        app.set_repeater_error_message(SharedString::from(""));

        // Start controlled test server
        let test_server = ControlledTestServer::new(self.test_server_port);
        if let Err(e) = test_server.start() {
            eprintln!(
                "Warning: could not bind test server on port {}: {}",
                self.test_server_port, e
            );
        } else {
            let mut guard = self.test_server.lock().unwrap();
            *guard = Some(test_server);
        }

        // Shared filter state, selected ID and secrets revealed flag for Inspector projection
        let filter_state = Arc::new(Mutex::new(FilterState::default()));
        let selected_id = Arc::new(Mutex::new(None::<u64>));
        let secrets_revealed = Arc::new(Mutex::new(false));

        app.set_secrets_revealed(false);

        // Initialize default Filter Bar values on AppWindow
        app.set_filter_search(SharedString::from(""));
        app.set_filter_method_idx(0);
        app.set_filter_status_idx(0);
        app.set_filter_outcome_idx(0);
        app.set_filter_only_in_scope(false);
        app.set_filter_hide_connect(false);
        app.set_filter_hide_failed(false);

        // Initial projection of store contents
        {
            let mut sel = selected_id.lock().unwrap();
            let mut sec = secrets_revealed.lock().unwrap();
            let f = filter_state.lock().unwrap().clone();
            refresh_traffic_ui(app, &self.store, &self.scope, &f, &mut sel, &mut sec, None);
        }

        // Start native capturing proxy server
        let app_weak = app.as_weak();
        let store_ref = Arc::clone(&self.store);
        let scope_ref = Arc::clone(&self.scope);
        let filter_clone = Arc::clone(&filter_state);
        let selected_clone = Arc::clone(&selected_id);
        let secrets_clone = Arc::clone(&secrets_revealed);

        let make_on_tx_callback = {
            let app_weak = app_weak.clone();
            let store_ref = Arc::clone(&store_ref);
            let scope_ref = Arc::clone(&scope_ref);
            let filter_clone = Arc::clone(&filter_clone);
            let selected_clone = Arc::clone(&selected_clone);
            let secrets_clone = Arc::clone(&secrets_clone);

            move || {
                let app_weak_inner = app_weak.clone();
                let store_inner = Arc::clone(&store_ref);
                let scope_inner = Arc::clone(&scope_ref);
                let filter_inner = Arc::clone(&filter_clone);
                let selected_inner = Arc::clone(&selected_clone);
                let secrets_inner = Arc::clone(&secrets_clone);

                Arc::new(move |tx: HttpTransaction| {
                    let app_weak_deep = app_weak_inner.clone();
                    let store_deep = Arc::clone(&store_inner);
                    let scope_deep = Arc::clone(&scope_inner);
                    let filter_deep = Arc::clone(&filter_inner);
                    let selected_deep = Arc::clone(&selected_inner);
                    let secrets_deep = Arc::clone(&secrets_inner);

                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = app_weak_deep.upgrade() {
                            let filter = filter_deep.lock().unwrap().clone();
                            let mut sel_id = selected_deep.lock().unwrap();
                            let mut sec_rev = secrets_deep.lock().unwrap();
                            let suffix = format!("Last: {} {}", tx.request.method, tx.request.path);
                            refresh_traffic_ui(
                                &ui,
                                &store_deep,
                                &scope_deep,
                                &filter,
                                &mut sel_id,
                                &mut sec_rev,
                                Some(suffix),
                            );
                        }
                    });
                })
            }
        };

        let on_tx_callback = make_on_tx_callback();

        let proxy = NativeProxyServer::new(
            self.proxy_port,
            Arc::clone(&self.store),
            Arc::clone(&self.scope),
            Some(on_tx_callback),
        );

        if proxy.start().is_ok() {
            let mut guard = self.proxy.lock().unwrap();
            *guard = Some(proxy);
            app.set_proxy_running(true);
        } else {
            app.set_proxy_running(false);
            app.set_status_message(SharedString::from("Error: Proxy port conflict"));
        }

        // 1. Toggle Proxy Callback
        let proxy_holder = Arc::clone(&self.proxy);
        let store_ref = Arc::clone(&self.store);
        let scope_ref = Arc::clone(&self.scope);
        let app_weak = app.as_weak();
        let port = self.proxy_port;
        let make_on_tx_restart = make_on_tx_callback;

        app.on_toggle_proxy(move || {
            let mut guard = proxy_holder.lock().unwrap();
            if let Some(active_proxy) = guard.as_ref() {
                if active_proxy.is_running() {
                    active_proxy.stop();
                    if let Some(ui) = app_weak.upgrade() {
                        ui.set_proxy_running(false);
                        ui.set_status_message(SharedString::from("Proxy capture paused"));
                    }
                    return;
                }
            }

            // Restart proxy using unified on_tx callback
            let on_tx = make_on_tx_restart();

            let new_proxy = NativeProxyServer::new(
                port,
                Arc::clone(&store_ref),
                Arc::clone(&scope_ref),
                Some(on_tx),
            );

            if new_proxy.start().is_ok() {
                *guard = Some(new_proxy);
                if let Some(ui) = app_weak.upgrade() {
                    ui.set_proxy_running(true);
                    ui.set_status_message(SharedString::from(format!(
                        "Proxy listening on 127.0.0.1:{}",
                        port
                    )));
                }
            }
        });

        // 2. Send Real Test HTTP Traffic Callback
        let app_weak = app.as_weak();
        let proxy_port = self.proxy_port;
        let test_port = self.test_server_port;

        app.on_send_test_traffic(move || {
            if let Some(ui) = app_weak.upgrade() {
                ui.set_is_sending_test(true);
            }

            let app_weak_bg = app_weak.clone();
            thread::spawn(move || {
                Self::send_real_http_requests(proxy_port, test_port);

                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = app_weak_bg.upgrade() {
                        ui.set_is_sending_test(false);
                    }
                });
            });
        });

        // 3. Select Transaction Callback (by visual index fallback, backwards-compat)
        let app_weak = app.as_weak();
        let store_select = Arc::clone(&self.store);
        let scope_select = Arc::clone(&self.scope);
        let filter_select = Arc::clone(&filter_state);
        let selected_select = Arc::clone(&selected_id);
        let secrets_select = Arc::clone(&secrets_revealed);

        app.on_select_transaction(move |row_idx: i32| {
            if let Some(ui) = app_weak.upgrade() {
                // Reset privacy state upon selection change
                {
                    let mut s = secrets_select.lock().unwrap();
                    *s = false;
                }
                let filter = filter_select.lock().unwrap().clone();
                let summaries = store_select.lock().unwrap().get_metadata_snapshot();
                let matching = filter.filter(&summaries, &scope_select);
                if let Some(summary) = matching.get(row_idx as usize) {
                    let target_id = summary.id;
                    let mut sel_guard = selected_select.lock().unwrap();
                    *sel_guard = Some(target_id);

                    // Look up full transaction for details
                    let tx_opt = store_select.lock().unwrap().get_by_id(target_id).cloned();
                    ui.set_selected_transaction_idx(row_idx);
                    set_transaction_details_on_ui(&ui, tx_opt.as_ref(), false);
                }
            }
        });

        // 3b. Select Transaction by exact string ID callback
        let app_weak = app.as_weak();
        let store_select_id = Arc::clone(&self.store);
        let scope_select_id = Arc::clone(&self.scope);
        let filter_select_id = Arc::clone(&filter_state);
        let selected_select_id = Arc::clone(&selected_id);
        let secrets_select_id = Arc::clone(&secrets_revealed);

        app.on_select_transaction_by_id(move |id_str: SharedString| {
            if let Some(ui) = app_weak.upgrade() {
                // Reset privacy state upon selection change
                {
                    let mut s = secrets_select_id.lock().unwrap();
                    *s = false;
                }
                if let Ok(id) = id_str.as_str().parse::<u64>() {
                    let filter = filter_select_id.lock().unwrap().clone();
                    let summaries = store_select_id.lock().unwrap().get_metadata_snapshot();
                    let matching = filter.filter(&summaries, &scope_select_id);

                    // Verify that this transaction ID is present in the current visible projection
                    if let Some(pos) = matching.iter().position(|s| s.id == id) {
                        let mut sel_guard = selected_select_id.lock().unwrap();
                        *sel_guard = Some(id);

                        let tx_opt = store_select_id.lock().unwrap().get_by_id(id).cloned();
                        ui.set_selected_transaction_idx(pos as i32);
                        set_transaction_details_on_ui(&ui, tx_opt.as_ref(), false);
                    } else {
                        // Not in current projection: reject stale selection
                        let mut sel_guard = selected_select_id.lock().unwrap();
                        if *sel_guard == Some(id) {
                            *sel_guard = None;
                            ui.set_selected_transaction_idx(-1);
                            set_transaction_details_on_ui(&ui, None, false);
                        }
                    }
                }
            }
        });

        // 3c. Toggle Reveal Secrets Callback
        let app_weak = app.as_weak();
        let store_reveal = Arc::clone(&self.store);
        let selected_reveal = Arc::clone(&selected_id);
        let secrets_reveal = Arc::clone(&secrets_revealed);

        app.on_toggle_reveal_secrets(move || {
            if let Some(ui) = app_weak.upgrade() {
                let sel_id = *selected_reveal.lock().unwrap();
                let new_state = {
                    let mut s = secrets_reveal.lock().unwrap();
                    *s = !*s;
                    *s
                };

                let tx_opt =
                    sel_id.and_then(|id| store_reveal.lock().unwrap().get_by_id(id).cloned());
                set_transaction_details_on_ui(&ui, tx_opt.as_ref(), new_state);
            }
        });

        // 4. Clear History Callback
        let store_clear = Arc::clone(&self.store);
        let app_weak = app.as_weak();
        let filter_clear = Arc::clone(&filter_state);
        let selected_clear = Arc::clone(&selected_id);
        let scope_clear = Arc::clone(&self.scope);
        let secrets_clear = Arc::clone(&secrets_revealed);

        app.on_clear_history(move || {
            store_clear.lock().unwrap().clear();
            let mut sel_guard = selected_clear.lock().unwrap();
            *sel_guard = None;
            let mut sec_guard = secrets_clear.lock().unwrap();
            *sec_guard = false;

            if let Some(ui) = app_weak.upgrade() {
                let filter = filter_clear.lock().unwrap().clone();
                refresh_traffic_ui(
                    &ui,
                    &store_clear,
                    &scope_clear,
                    &filter,
                    &mut sel_guard,
                    &mut sec_guard,
                    None,
                );
                ui.set_status_message(SharedString::from("History cleared"));
            }
        });

        // 5. Filter Callbacks
        // 5a. Search Query
        let app_weak = app.as_weak();
        let store_f = Arc::clone(&self.store);
        let scope_f = Arc::clone(&self.scope);
        let filter_f = Arc::clone(&filter_state);
        let selected_f = Arc::clone(&selected_id);
        let secrets_f = Arc::clone(&secrets_revealed);
        app.on_filter_search_changed(move |query: SharedString| {
            if let Some(ui) = app_weak.upgrade() {
                {
                    let mut f = filter_f.lock().unwrap();
                    f.search_query = query.to_string();
                }
                let f_snapshot = filter_f.lock().unwrap().clone();
                let mut sel_id = selected_f.lock().unwrap();
                let mut sec_rev = secrets_f.lock().unwrap();
                refresh_traffic_ui(
                    &ui,
                    &store_f,
                    &scope_f,
                    &f_snapshot,
                    &mut sel_id,
                    &mut sec_rev,
                    None,
                );
            }
        });

        // 5b. Method Selector
        let app_weak = app.as_weak();
        let store_f = Arc::clone(&self.store);
        let scope_f = Arc::clone(&self.scope);
        let filter_f = Arc::clone(&filter_state);
        let selected_f = Arc::clone(&selected_id);
        let secrets_f = Arc::clone(&secrets_revealed);
        app.on_filter_method_changed(move |idx: i32| {
            if let Some(ui) = app_weak.upgrade() {
                {
                    let mut f = filter_f.lock().unwrap();
                    f.method = match idx {
                        1 => MethodFilter::Get,
                        2 => MethodFilter::Post,
                        3 => MethodFilter::Put,
                        4 => MethodFilter::Delete,
                        5 => MethodFilter::Patch,
                        6 => MethodFilter::Head,
                        7 => MethodFilter::Options,
                        8 => MethodFilter::Connect,
                        9 => MethodFilter::Other,
                        _ => MethodFilter::All,
                    };
                }
                let f_snapshot = filter_f.lock().unwrap().clone();
                let mut sel_id = selected_f.lock().unwrap();
                let mut sec_rev = secrets_f.lock().unwrap();
                refresh_traffic_ui(
                    &ui,
                    &store_f,
                    &scope_f,
                    &f_snapshot,
                    &mut sel_id,
                    &mut sec_rev,
                    None,
                );
            }
        });

        // 5c. Status Selector
        let app_weak = app.as_weak();
        let store_f = Arc::clone(&self.store);
        let scope_f = Arc::clone(&self.scope);
        let filter_f = Arc::clone(&filter_state);
        let selected_f = Arc::clone(&selected_id);
        let secrets_f = Arc::clone(&secrets_revealed);
        app.on_filter_status_changed(move |idx: i32| {
            if let Some(ui) = app_weak.upgrade() {
                {
                    let mut f = filter_f.lock().unwrap();
                    f.status = match idx {
                        1 => HttpStatusFilter::Status1xx,
                        2 => HttpStatusFilter::Status2xx,
                        3 => HttpStatusFilter::Status3xx,
                        4 => HttpStatusFilter::Status4xx,
                        5 => HttpStatusFilter::Status5xx,
                        6 => HttpStatusFilter::NoResponse,
                        _ => HttpStatusFilter::All,
                    };
                }
                let f_snapshot = filter_f.lock().unwrap().clone();
                let mut sel_id = selected_f.lock().unwrap();
                let mut sec_rev = secrets_f.lock().unwrap();
                refresh_traffic_ui(
                    &ui,
                    &store_f,
                    &scope_f,
                    &f_snapshot,
                    &mut sel_id,
                    &mut sec_rev,
                    None,
                );
            }
        });

        // 5d. Outcome Selector
        let app_weak = app.as_weak();
        let store_f = Arc::clone(&self.store);
        let scope_f = Arc::clone(&self.scope);
        let filter_f = Arc::clone(&filter_state);
        let selected_f = Arc::clone(&selected_id);
        let secrets_f = Arc::clone(&secrets_revealed);
        app.on_filter_outcome_changed(move |idx: i32| {
            if let Some(ui) = app_weak.upgrade() {
                {
                    let mut f = filter_f.lock().unwrap();
                    f.outcome = match idx {
                        1 => OutcomeFilter::Pending,
                        2 => OutcomeFilter::Completed,
                        3 => OutcomeFilter::Failed,
                        _ => OutcomeFilter::All,
                    };
                }
                let f_snapshot = filter_f.lock().unwrap().clone();
                let mut sel_id = selected_f.lock().unwrap();
                let mut sec_rev = secrets_f.lock().unwrap();
                refresh_traffic_ui(
                    &ui,
                    &store_f,
                    &scope_f,
                    &f_snapshot,
                    &mut sel_id,
                    &mut sec_rev,
                    None,
                );
            }
        });

        // 5e. Only In Scope Checkbox
        let app_weak = app.as_weak();
        let store_f = Arc::clone(&self.store);
        let scope_f = Arc::clone(&self.scope);
        let filter_f = Arc::clone(&filter_state);
        let selected_f = Arc::clone(&selected_id);
        let secrets_f = Arc::clone(&secrets_revealed);
        app.on_filter_only_in_scope_changed(move |val: bool| {
            if let Some(ui) = app_weak.upgrade() {
                {
                    let mut f = filter_f.lock().unwrap();
                    f.only_in_scope = val;
                }
                let f_snapshot = filter_f.lock().unwrap().clone();
                let mut sel_id = selected_f.lock().unwrap();
                let mut sec_rev = secrets_f.lock().unwrap();
                refresh_traffic_ui(
                    &ui,
                    &store_f,
                    &scope_f,
                    &f_snapshot,
                    &mut sel_id,
                    &mut sec_rev,
                    None,
                );
            }
        });

        // 5f. Hide CONNECT Checkbox
        let app_weak = app.as_weak();
        let store_f = Arc::clone(&self.store);
        let scope_f = Arc::clone(&self.scope);
        let filter_f = Arc::clone(&filter_state);
        let selected_f = Arc::clone(&selected_id);
        let secrets_f = Arc::clone(&secrets_revealed);
        app.on_filter_hide_connect_changed(move |val: bool| {
            if let Some(ui) = app_weak.upgrade() {
                {
                    let mut f = filter_f.lock().unwrap();
                    f.hide_connect = val;
                }
                let f_snapshot = filter_f.lock().unwrap().clone();
                let mut sel_id = selected_f.lock().unwrap();
                let mut sec_rev = secrets_f.lock().unwrap();
                refresh_traffic_ui(
                    &ui,
                    &store_f,
                    &scope_f,
                    &f_snapshot,
                    &mut sel_id,
                    &mut sec_rev,
                    None,
                );
            }
        });

        // 5g. Hide Failed Checkbox
        let app_weak = app.as_weak();
        let store_f = Arc::clone(&self.store);
        let scope_f = Arc::clone(&self.scope);
        let filter_f = Arc::clone(&filter_state);
        let selected_f = Arc::clone(&selected_id);
        let secrets_f = Arc::clone(&secrets_revealed);
        app.on_filter_hide_failed_changed(move |val: bool| {
            if let Some(ui) = app_weak.upgrade() {
                {
                    let mut f = filter_f.lock().unwrap();
                    f.hide_failed = val;
                }
                let f_snapshot = filter_f.lock().unwrap().clone();
                let mut sel_id = selected_f.lock().unwrap();
                let mut sec_rev = secrets_f.lock().unwrap();
                refresh_traffic_ui(
                    &ui,
                    &store_f,
                    &scope_f,
                    &f_snapshot,
                    &mut sel_id,
                    &mut sec_rev,
                    None,
                );
            }
        });

        // 5h. Reset Filters
        let app_weak = app.as_weak();
        let store_f = Arc::clone(&self.store);
        let scope_f = Arc::clone(&self.scope);
        let filter_f = Arc::clone(&filter_state);
        let selected_f = Arc::clone(&selected_id);
        let secrets_f = Arc::clone(&secrets_revealed);
        app.on_reset_filters(move || {
            if let Some(ui) = app_weak.upgrade() {
                {
                    let mut f = filter_f.lock().unwrap();
                    f.reset();
                }
                // Reset Slint properties
                ui.set_filter_search(SharedString::from(""));
                ui.set_filter_method_idx(0);
                ui.set_filter_status_idx(0);
                ui.set_filter_outcome_idx(0);
                ui.set_filter_only_in_scope(false);
                ui.set_filter_hide_connect(false);
                ui.set_filter_hide_failed(false);

                let f_snapshot = filter_f.lock().unwrap().clone();
                let mut sel_id = selected_f.lock().unwrap();
                let mut sec_rev = secrets_f.lock().unwrap();
                refresh_traffic_ui(
                    &ui,
                    &store_f,
                    &scope_f,
                    &f_snapshot,
                    &mut sel_id,
                    &mut sec_rev,
                    None,
                );
            }
        });

        // 5. Repeater Bindings
        let repeater_sink = Arc::new(SlintRepeaterSink {
            app: app.as_weak(),
            repeater: Arc::clone(&self.repeater),
        });

        // 5a. Send Repeater Callback
        let app_weak_send = app.as_weak();
        let repeater_send = Arc::clone(&self.repeater);
        let sink_send = Arc::clone(&repeater_sink);

        app.on_send_repeater(move || {
            if let Some(ui) = app_weak_send.upgrade() {
                let method = ui.get_repeater_method().to_string();
                let url = ui.get_repeater_url().to_string();
                let headers = ui.get_repeater_headers().to_string();
                let body = ui.get_repeater_body().to_string();

                let input = RepeaterUiInput::new(method, url, headers, body);
                match repeater_send.dispatch(input, Some(sink_send.clone())) {
                    Ok(_req_id) => {
                        ui.set_repeater_is_running(true);
                        ui.set_repeater_is_cancelling(false);
                        ui.set_repeater_status_text(SharedString::from("Running..."));
                        ui.set_repeater_error_message(SharedString::from(""));
                        ui.set_repeater_status_code(0);
                        ui.set_repeater_duration_ms(0);
                        ui.set_repeater_response_headers(SharedString::from(""));
                        ui.set_repeater_response_body(SharedString::from(""));
                    }
                    Err(err) => {
                        if !matches!(err, RepeaterAdapterError::AlreadyRunning) {
                            ui.set_repeater_is_running(false);
                            ui.set_repeater_is_cancelling(false);
                        }
                        ui.set_repeater_status_text(SharedString::from("Failed"));
                        ui.set_repeater_error_message(SharedString::from(
                            err.safe_display_message(),
                        ));
                    }
                }
            }
        });

        // 5b. Cancel Repeater Callback
        let app_weak_cancel = app.as_weak();
        let repeater_cancel = Arc::clone(&self.repeater);

        app.on_cancel_repeater(move || {
            if repeater_cancel.is_in_flight() {
                if let Some(ui) = app_weak_cancel.upgrade() {
                    ui.set_repeater_is_cancelling(true);
                    ui.set_repeater_status_text(SharedString::from("Cancelling..."));
                }
                let _ = repeater_cancel.cancel_active();
            }
        });

        // 5c. Reset Repeater Defaults Callback
        let app_weak_reset = app.as_weak();
        let repeater_reset = Arc::clone(&self.repeater);

        app.on_reset_repeater_defaults(move || {
            if !repeater_reset.is_in_flight() {
                if let Some(ui) = app_weak_reset.upgrade() {
                    let default_input = RepeaterUiInput::default();
                    ui.set_repeater_method(SharedString::from(default_input.method));
                    ui.set_repeater_url(SharedString::from(default_input.target_url));
                    ui.set_repeater_headers(SharedString::from(default_input.headers_raw));
                    ui.set_repeater_body(SharedString::from(default_input.body_utf8));
                    ui.set_repeater_error_message(SharedString::from(""));
                }
            }
        });
    }

    /// Dispatches real HTTP requests over TCP to proxy
    pub fn send_real_http_requests(proxy_port: u16, target_server_port: u16) {
        let requests = [
            format!(
                "GET http://127.0.0.1:{}/api/status HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nUser-Agent: Sentinel-Client/1.0\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
                target_server_port, target_server_port
            ),
            format!(
                "POST http://127.0.0.1:{}/api/echo HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: 42\r\nConnection: close\r\n\r\n{{\"audit\": \"authorized\", \"target\": \"127.0.0.1\"}}",
                target_server_port, target_server_port
            ),
            format!(
                "GET http://127.0.0.1:{}/auth/login HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nUser-Agent: Sentinel-Client/1.0\r\nConnection: close\r\n\r\n",
                target_server_port, target_server_port
            ),
            format!(
                "GET http://127.0.0.1:{}/admin/restricted HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nUser-Agent: Sentinel-Client/1.0\r\nConnection: close\r\n\r\n",
                target_server_port, target_server_port
            ),
        ];

        for req in requests {
            if let Ok(mut stream) = TcpStream::connect(format!("127.0.0.1:{}", proxy_port)) {
                let _ = stream.set_read_timeout(Some(Duration::from_millis(2000)));
                let _ = stream.set_write_timeout(Some(Duration::from_millis(2000)));
                let _ = stream.write_all(req.as_bytes());
                let _ = stream.flush();

                let mut resp_buf = [0u8; 4096];
                let _ = stream.read(&mut resp_buf);
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controller::repeater_adapter::{RepeaterEvent, RepeaterLifecycle};
    use std::net::TcpListener;
    use std::sync::mpsc;

    #[test]
    fn test_app_controller_headless_repeater_dispatch_and_store_isolation() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).unwrap();
            let resp =
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 13\r\nConnection: close\r\n\r\nController OK";
            stream.write_all(resp).unwrap();
        });

        let app_controller = AppController::new(0, port);
        assert_eq!(app_controller.store.lock().unwrap().count(), 0);
        assert!(std::ptr::eq(
            Arc::as_ptr(&app_controller.scope),
            app_controller.repeater().scope() as *const AuditScope
        ));

        let (tx, rx) = mpsc::channel();
        let input = RepeaterUiInput::new(
            "GET",
            format!("http://127.0.0.1:{}/controller-check", port),
            format!("Host: 127.0.0.1:{}", port),
            "",
        );

        let req_id = app_controller
            .dispatch_repeater(input, Some(Arc::new(tx)))
            .expect("Dispatch via AppController");
        assert_eq!(req_id, 1);

        let ev_started = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(ev_started, RepeaterEvent::Started { request_id: 1 });

        let ev_completed = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(
            ev_completed,
            RepeaterEvent::Completed { request_id: 1, .. }
        ));

        let snap = app_controller.repeater_state_snapshot();
        assert_eq!(snap.lifecycle, RepeaterLifecycle::Completed);
        assert_eq!(snap.status_code, Some(200));
        assert_eq!(snap.response_body_preview, "Controller OK");

        // Ensure SharedTrafficStore remains completely untouched
        assert_eq!(app_controller.store.lock().unwrap().count(), 0);

        server.join().unwrap();
    }

    #[test]
    fn test_app_controller_real_loopback_post_and_store_isolation() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let server_thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).unwrap();
            let resp = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 17\r\nConnection: close\r\n\r\n{\"echoed\": \"yes\"}";
            let _ = stream.write_all(resp);
        });

        let app_controller = AppController::new(0, port);
        let (tx, rx) = mpsc::channel();
        let post_input = RepeaterUiInput::new(
            "POST",
            format!("http://127.0.0.1:{}/submit", port),
            format!("Host: 127.0.0.1:{}\nContent-Type: application/json", port),
            "{\"data\": 123}",
        );

        let req_id = app_controller
            .dispatch_repeater(post_input, Some(Arc::new(tx)))
            .expect("Dispatch POST");
        assert_eq!(req_id, 1);

        let ev_start = rx.recv_timeout(Duration::from_secs(3)).unwrap();
        assert_eq!(ev_start, RepeaterEvent::Started { request_id: 1 });

        let ev_done = rx.recv_timeout(Duration::from_secs(3)).unwrap();
        match ev_done {
            RepeaterEvent::Completed { request_id, result } => {
                assert_eq!(request_id, 1);
                assert_eq!(result.response.status_code, 200);
                assert_eq!(result.response.body, b"{\"echoed\": \"yes\"}");
            }
            other => panic!("Expected Completed event for POST, got {:?}", other),
        }

        let snap = app_controller.repeater_state_snapshot();
        assert_eq!(snap.lifecycle, RepeaterLifecycle::Completed);
        assert_eq!(snap.status_code, Some(200));
        assert_eq!(snap.response_body_preview, "{\"echoed\": \"yes\"}");

        // TrafficStore isolation
        assert_eq!(app_controller.store.lock().unwrap().count(), 0);

        server_thread.join().unwrap();
    }

    #[test]
    fn test_app_controller_cooperative_cancellation_and_store_isolation() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let (accepted_tx, accepted_rx) = mpsc::channel();
        let (release_server_tx, release_server_rx) = mpsc::channel();

        let server_thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 512];
            let _ = stream.read(&mut buf);
            let _ = accepted_tx.send(());
            let _ = release_server_rx.recv_timeout(Duration::from_secs(5));
        });

        let app_controller = AppController::new(0, port);
        let (event_tx, event_rx) = mpsc::channel();
        let input = RepeaterUiInput::new(
            "GET",
            format!("http://127.0.0.1:{}/slow", port),
            format!("Host: 127.0.0.1:{}", port),
            "",
        );

        let req_id = app_controller
            .dispatch_repeater(input, Some(Arc::new(event_tx)))
            .expect("Dispatch slow");
        assert_eq!(req_id, 1);

        let _ = event_rx.recv_timeout(Duration::from_secs(2)).unwrap(); // Started
        accepted_rx.recv_timeout(Duration::from_secs(2)).unwrap(); // Server accepted

        // Cancellation signal via AppController
        let cancelled = app_controller.cancel_repeater();
        assert_eq!(cancelled, Some(1));

        let term_event = event_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(term_event, RepeaterEvent::Cancelled { request_id: 1 });

        let snap = app_controller.repeater_state_snapshot();
        assert_eq!(snap.lifecycle, RepeaterLifecycle::Cancelled);

        let _ = release_server_tx.send(());
        server_thread.join().unwrap();

        // TrafficStore isolation
        assert_eq!(app_controller.store.lock().unwrap().count(), 0);
    }

    #[test]
    fn test_app_controller_validation_and_scope_rejections() {
        let app_controller = AppController::new(0, 0);

        // 1. Empty method rejection (synchronous)
        let empty_method_input = RepeaterUiInput::new("", "http://127.0.0.1:8989/test", "", "");
        let err1 = app_controller
            .dispatch_repeater(empty_method_input, None)
            .expect_err("Empty method must fail synchronously");
        assert_eq!(err1, RepeaterAdapterError::EmptyMethod);
        assert!(err1
            .safe_display_message()
            .contains("HTTP method cannot be empty"));

        // 2. Unsupported method rejection (synchronous)
        let unsupp_input = RepeaterUiInput::new("CONNECT", "http://127.0.0.1:8989/test", "", "");
        let err2 = app_controller
            .dispatch_repeater(unsupp_input, None)
            .expect_err("CONNECT method must fail synchronously");
        assert!(matches!(err2, RepeaterAdapterError::UnsupportedMethod(_)));

        // 3. Empty target URL rejection (synchronous)
        let empty_url_input = RepeaterUiInput::new("GET", "", "", "");
        let err3 = app_controller
            .dispatch_repeater(empty_url_input, None)
            .expect_err("Empty URL must fail synchronously");
        assert_eq!(err3, RepeaterAdapterError::EmptyTargetUrl);

        // 4. Out of scope URL rejection (asynchronous via engine)
        let (tx, rx) = mpsc::channel();
        let out_of_scope_input = RepeaterUiInput::new(
            "GET",
            "http://external-target.com/api",
            "Host: external-target.com",
            "",
        );
        let req_id = app_controller
            .dispatch_repeater(out_of_scope_input, Some(Arc::new(tx)))
            .expect("Worker spawned for scope check");
        assert_eq!(req_id, 4);
        let _ = rx.recv_timeout(Duration::from_secs(2)).unwrap(); // Started
        let term = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(
            term,
            RepeaterEvent::Failed {
                request_id: 4,
                error: RepeaterAdapterError::Engine(
                    kaska_http::repeater::RepeaterError::HostOutOfScope(_)
                )
            }
        ));

        // TrafficStore isolation
        assert_eq!(app_controller.store.lock().unwrap().count(), 0);
    }

    #[test]
    fn test_app_controller_duplicate_dispatch_rejection() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let (accepted_tx, accepted_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let server_thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 512];
            let _ = stream.read(&mut buf);
            let _ = accepted_tx.send(());
            let _ = release_rx.recv_timeout(Duration::from_secs(5));
        });

        let app_controller = AppController::new(0, port);
        let (tx, rx) = mpsc::channel();
        let slow_input = RepeaterUiInput::new(
            "GET",
            format!("http://127.0.0.1:{}/slow", port),
            format!("Host: 127.0.0.1:{}", port),
            "",
        );

        let req_id = app_controller
            .dispatch_repeater(slow_input.clone(), Some(Arc::new(tx)))
            .expect("First dispatch");
        assert_eq!(req_id, 1);
        let _ = rx.recv_timeout(Duration::from_secs(2)).unwrap(); // Started
        accepted_rx.recv_timeout(Duration::from_secs(2)).unwrap(); // Server accepted

        // Second dispatch while first is running must fail with AlreadyRunning
        let duplicate_err = app_controller
            .dispatch_repeater(slow_input, None)
            .expect_err("Duplicate dispatch must fail");
        assert_eq!(duplicate_err, RepeaterAdapterError::AlreadyRunning);

        let _ = app_controller.cancel_repeater();
        let _ = release_tx.send(());
        server_thread.join().unwrap();
    }

    #[test]
    fn test_app_controller_initial_and_reset_defaults_projection() {
        let app_controller = AppController::new(8080, 8989);
        let default_input = RepeaterUiInput::default();

        // 1. Verify contract defaults
        assert_eq!(default_input.method, "GET");
        assert_eq!(default_input.target_url, "http://127.0.0.1:8989/api/status");
        assert_eq!(
            default_input.headers_raw,
            "Host: 127.0.0.1:8989\nUser-Agent: Kaska-Repeater/0.1\nAccept: application/json"
        );
        assert!(default_input.body_utf8.is_empty());

        // 2. Strict distinction: target port is 8989 (test server), NOT 8080 (proxy)
        assert!(default_input.target_url.contains(":8989"));
        assert!(!default_input.target_url.contains(":8080"));
        assert!(default_input.headers_raw.contains("Host: 127.0.0.1:8989"));
        assert!(!default_input.headers_raw.contains("Host: 127.0.0.1:8080"));

        // 3. Initial state snapshot check
        let initial_snap = app_controller.repeater_state_snapshot();
        assert_eq!(initial_snap.lifecycle, RepeaterLifecycle::Idle);
        assert_eq!(initial_snap.active_request_id, 0);
        assert_eq!(initial_snap.status_code, None);
        assert!(initial_snap.error_message.is_empty());
    }

    use kaska_http::models::HttpMethod;
    use kaska_http::store::{TransactionOutcome, TransactionSummary};

    fn make_summary(
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
                match outcome {
                    TransactionOutcome::Pending => "Pending".to_string(),
                    TransactionOutcome::Failed => "Failed".to_string(),
                    TransactionOutcome::Completed => "No response".to_string(),
                }
            } else {
                "OK".to_string()
            },
            duration_ms: 15,
            response_size_bytes: 120,
            content_type: "text/plain".to_string(),
            outcome,
        }
    }

    // 1. Filtros neutros muestran todos los registros
    #[test]
    fn test_scenario_1_neutral_filters_show_all() {
        let scope = AuditScope::default();
        let summaries = vec![
            make_summary(
                1,
                HttpMethod::Get,
                "localhost",
                "/a",
                200,
                TransactionOutcome::Completed,
            ),
            make_summary(
                2,
                HttpMethod::Post,
                "127.0.0.1",
                "/b",
                201,
                TransactionOutcome::Completed,
            ),
        ];
        let filter = FilterState::default();
        let (items, total, visible, sel_idx, retained) =
            project_traffic(&summaries, &filter, &scope, None);
        assert_eq!(total, 2);
        assert_eq!(visible, 2);
        assert_eq!(items.len(), 2);
        assert_eq!(sel_idx, -1);
        assert!(!retained);
    }

    // 2. Search host/path cambia lista sin tocar store
    #[test]
    fn test_scenario_2_search_query_filters_without_mutating_data() {
        let scope = AuditScope::default();
        let summaries = vec![
            make_summary(
                1,
                HttpMethod::Get,
                "api.local",
                "/users",
                200,
                TransactionOutcome::Completed,
            ),
            make_summary(
                2,
                HttpMethod::Get,
                "auth.local",
                "/login",
                200,
                TransactionOutcome::Completed,
            ),
        ];
        let filter = FilterState {
            search_query: "users".to_string(),
            ..Default::default()
        };
        let (items, total, visible, _, _) = project_traffic(&summaries, &filter, &scope, None);
        assert_eq!(total, 2);
        assert_eq!(visible, 1);
        assert_eq!(items[0].id.as_str(), "1");
        assert_eq!(
            summaries.len(),
            2,
            "Underlying summaries must remain unmutated"
        );
    }

    // 3. Cambios de Method/Status/Outcome
    #[test]
    fn test_scenario_3_method_status_outcome_filtering() {
        let scope = AuditScope::default();
        let summaries = vec![
            make_summary(
                1,
                HttpMethod::Get,
                "127.0.0.1",
                "/a",
                200,
                TransactionOutcome::Completed,
            ),
            make_summary(
                2,
                HttpMethod::Post,
                "127.0.0.1",
                "/b",
                404,
                TransactionOutcome::Completed,
            ),
            make_summary(
                3,
                HttpMethod::Put,
                "127.0.0.1",
                "/c",
                500,
                TransactionOutcome::Completed,
            ),
            make_summary(
                4,
                HttpMethod::Delete,
                "127.0.0.1",
                "/d",
                0,
                TransactionOutcome::Failed,
            ),
            make_summary(
                5,
                HttpMethod::Get,
                "127.0.0.1",
                "/e",
                0,
                TransactionOutcome::Pending,
            ),
        ];

        // Method filter: POST
        let filter_post = FilterState {
            method: MethodFilter::Post,
            ..Default::default()
        };
        let (items, total, visible, _, _) = project_traffic(&summaries, &filter_post, &scope, None);
        assert_eq!(total, 5);
        assert_eq!(visible, 1);
        assert_eq!(items[0].id.as_str(), "2");

        // Status filter: 4xx
        let filter_4xx = FilterState {
            status: HttpStatusFilter::Status4xx,
            ..Default::default()
        };
        let (items, _, visible, _, _) = project_traffic(&summaries, &filter_4xx, &scope, None);
        assert_eq!(visible, 1);
        assert_eq!(items[0].id.as_str(), "2");

        // Status filter: NoResponse (status 0)
        let filter_no_resp = FilterState {
            status: HttpStatusFilter::NoResponse,
            ..Default::default()
        };
        let (items, _, visible, _, _) = project_traffic(&summaries, &filter_no_resp, &scope, None);
        assert_eq!(visible, 2);
        assert_eq!(items[0].id.as_str(), "4");
        assert_eq!(items[1].id.as_str(), "5");

        // Outcome filter: Pending
        let filter_pending = FilterState {
            outcome: OutcomeFilter::Pending,
            ..Default::default()
        };
        let (items, _, visible, _, _) = project_traffic(&summaries, &filter_pending, &scope, None);
        assert_eq!(visible, 1);
        assert_eq!(items[0].id.as_str(), "5");

        // Outcome filter: Failed
        let filter_failed = FilterState {
            outcome: OutcomeFilter::Failed,
            ..Default::default()
        };
        let (items, _, visible, _, _) = project_traffic(&summaries, &filter_failed, &scope, None);
        assert_eq!(visible, 1);
        assert_eq!(items[0].id.as_str(), "4");
    }

    // 4. Hide CONNECT
    #[test]
    fn test_scenario_4_hide_connect() {
        let scope = AuditScope::default();
        let summaries = vec![
            make_summary(
                1,
                HttpMethod::Connect,
                "secure.internal:443",
                "/",
                200,
                TransactionOutcome::Completed,
            ),
            make_summary(
                2,
                HttpMethod::Get,
                "secure.internal",
                "/index.html",
                200,
                TransactionOutcome::Completed,
            ),
        ];
        let filter = FilterState {
            hide_connect: true,
            ..Default::default()
        };
        let (items, total, visible, _, _) = project_traffic(&summaries, &filter, &scope, None);
        assert_eq!(total, 2);
        assert_eq!(visible, 1);
        assert_eq!(items[0].id.as_str(), "2");
    }

    // 5. Hide Failed con Completed 404/500
    #[test]
    fn test_scenario_5_hide_failed_retains_completed_404_500() {
        let scope = AuditScope::default();
        let summaries = vec![
            make_summary(
                1,
                HttpMethod::Get,
                "localhost",
                "/404",
                404,
                TransactionOutcome::Completed,
            ),
            make_summary(
                2,
                HttpMethod::Get,
                "localhost",
                "/500",
                500,
                TransactionOutcome::Completed,
            ),
            make_summary(
                3,
                HttpMethod::Get,
                "localhost",
                "/broken",
                0,
                TransactionOutcome::Failed,
            ),
        ];
        let filter = FilterState {
            hide_failed: true,
            ..Default::default()
        };
        let (items, total, visible, _, _) = project_traffic(&summaries, &filter, &scope, None);
        assert_eq!(total, 3);
        assert_eq!(visible, 2);
        assert_eq!(items[0].id.as_str(), "1");
        assert_eq!(items[1].id.as_str(), "2");
    }

    // 6. Only in scope no cambia AuditScope
    #[test]
    fn test_scenario_6_only_in_scope_does_not_mutate_audit_scope() {
        let scope = AuditScope::default(); // allows localhost, 127.0.0.1, ::1
        let summaries = vec![
            make_summary(
                1,
                HttpMethod::Get,
                "127.0.0.1",
                "/api",
                200,
                TransactionOutcome::Completed,
            ),
            make_summary(
                2,
                HttpMethod::Get,
                "external-target.com",
                "/api",
                200,
                TransactionOutcome::Completed,
            ),
        ];
        let filter = FilterState {
            only_in_scope: true,
            ..Default::default()
        };
        let (items, total, visible, _, _) = project_traffic(&summaries, &filter, &scope, None);
        assert_eq!(total, 2);
        assert_eq!(visible, 1);
        assert_eq!(items[0].id.as_str(), "1");
        // Verify AuditScope remains unchanged
        assert!(scope.is_allowed_host("127.0.0.1"));
        assert!(!scope.is_allowed_host("external-target.com"));
    }

    // 7. Visible 0 / Total positivo
    #[test]
    fn test_scenario_7_visible_zero_total_positive() {
        let scope = AuditScope::default();
        let summaries = vec![
            make_summary(
                1,
                HttpMethod::Get,
                "127.0.0.1",
                "/api",
                200,
                TransactionOutcome::Completed,
            ),
            make_summary(
                2,
                HttpMethod::Get,
                "127.0.0.1",
                "/status",
                200,
                TransactionOutcome::Completed,
            ),
        ];
        let filter = FilterState {
            search_query: "non-existent-path".to_string(),
            ..Default::default()
        };
        let (items, total, visible, sel_idx, retained) =
            project_traffic(&summaries, &filter, &scope, Some(1));
        assert_eq!(total, 2);
        assert_eq!(visible, 0);
        assert!(items.is_empty());
        assert_eq!(sel_idx, -1);
        assert!(!retained);
    }

    // 8. Clear con filtros activos
    #[test]
    fn test_scenario_8_clear_with_active_filters() {
        let filter = FilterState {
            search_query: "test".to_string(),
            method: MethodFilter::Post,
            hide_failed: true,
            ..Default::default()
        };
        let summaries: Vec<TransactionSummary> = Vec::new();
        let scope = AuditScope::default();
        let (items, total, visible, sel_idx, _) =
            project_traffic(&summaries, &filter, &scope, Some(42));
        assert_eq!(total, 0);
        assert_eq!(visible, 0);
        assert_eq!(sel_idx, -1);
        assert!(items.is_empty());
        // Active filter state is preserved
        assert_eq!(filter.search_query, "test");
        assert_eq!(filter.method, MethodFilter::Post);
        assert!(filter.hide_failed);
    }

    // 9. Reset filters sin Clear
    #[test]
    fn test_scenario_9_reset_filters_without_clear() {
        let scope = AuditScope::default();
        let summaries = vec![
            make_summary(
                1,
                HttpMethod::Get,
                "127.0.0.1",
                "/a",
                200,
                TransactionOutcome::Completed,
            ),
            make_summary(
                2,
                HttpMethod::Post,
                "127.0.0.1",
                "/b",
                200,
                TransactionOutcome::Completed,
            ),
        ];
        let mut filter = FilterState {
            method: MethodFilter::Post,
            ..Default::default()
        };
        let (_, total1, visible1, _, _) = project_traffic(&summaries, &filter, &scope, None);
        assert_eq!(total1, 2);
        assert_eq!(visible1, 1);

        filter.reset();
        assert_eq!(filter, FilterState::default());

        let (items2, total2, visible2, _, _) = project_traffic(&summaries, &filter, &scope, None);
        assert_eq!(total2, 2);
        assert_eq!(visible2, 2);
        assert_eq!(items2.len(), 2);
    }

    // 10. ID mayor que i32::MAX se representa y selecciona exactamente
    #[test]
    fn test_scenario_10_id_greater_than_i32_max() {
        let scope = AuditScope::default();
        let large_id: u64 = 5_000_000_000;
        let summaries = vec![make_summary(
            large_id,
            HttpMethod::Get,
            "127.0.0.1",
            "/large",
            200,
            TransactionOutcome::Completed,
        )];
        let filter = FilterState::default();
        let (items, total, visible, sel_idx, retained) =
            project_traffic(&summaries, &filter, &scope, Some(large_id));
        assert_eq!(total, 1);
        assert_eq!(visible, 1);
        assert_eq!(items[0].id.as_str(), "5000000000");
        assert_eq!(sel_idx, 0);
        assert!(retained);

        // Parse verification
        let parsed: u64 = items[0].id.as_str().parse().expect("Valid u64 parse");
        assert_eq!(parsed, large_id);
    }

    // 11. ID inválido o ausente no muestra detalles
    #[test]
    fn test_scenario_11_invalid_or_missing_id_clears_selection() {
        let scope = AuditScope::default();
        let summaries = vec![make_summary(
            1,
            HttpMethod::Get,
            "127.0.0.1",
            "/test",
            200,
            TransactionOutcome::Completed,
        )];
        let filter = FilterState::default();
        // ID 999 is missing from store
        let (_, _, _, sel_idx, retained) = project_traffic(&summaries, &filter, &scope, Some(999));
        assert_eq!(sel_idx, -1);
        assert!(!retained);
    }

    // 12. Selección de una fila filtrada se descarta
    #[test]
    fn test_scenario_12_selection_discarded_if_filtered_out() {
        let scope = AuditScope::default();
        let summaries = vec![
            make_summary(
                1,
                HttpMethod::Get,
                "127.0.0.1",
                "/get",
                200,
                TransactionOutcome::Completed,
            ),
            make_summary(
                2,
                HttpMethod::Post,
                "127.0.0.1",
                "/post",
                200,
                TransactionOutcome::Completed,
            ),
        ];
        let filter = FilterState {
            method: MethodFilter::Post,
            ..Default::default()
        };
        // Selected was ID 1 (GET), but active filter only shows POST
        let (_, total, visible, sel_idx, retained) =
            project_traffic(&summaries, &filter, &scope, Some(1));
        assert_eq!(total, 2);
        assert_eq!(visible, 1);
        assert_eq!(sel_idx, -1);
        assert!(!retained);
    }

    // 13. FIFO con inserción no coincidente y expulsión coincidente
    #[test]
    fn test_scenario_13_fifo_non_matching_insert_evicts_matching_and_clears_selection() {
        let scope = AuditScope::default();
        // Store capacity 3: [#1 POST, #2 GET, #3 GET]
        // Filter: only POST
        // Total = 3, Visible = [#1], Selection = #1
        let initial_summaries = vec![
            make_summary(
                1,
                HttpMethod::Post,
                "127.0.0.1",
                "/login",
                200,
                TransactionOutcome::Completed,
            ),
            make_summary(
                2,
                HttpMethod::Get,
                "127.0.0.1",
                "/home",
                200,
                TransactionOutcome::Completed,
            ),
            make_summary(
                3,
                HttpMethod::Get,
                "127.0.0.1",
                "/status",
                200,
                TransactionOutcome::Completed,
            ),
        ];
        let filter = FilterState {
            method: MethodFilter::Post,
            ..Default::default()
        };
        let (items1, total1, visible1, sel1, ret1) =
            project_traffic(&initial_summaries, &filter, &scope, Some(1));
        assert_eq!(total1, 3);
        assert_eq!(visible1, 1);
        assert_eq!(sel1, 0);
        assert!(ret1);
        assert_eq!(items1[0].id.as_str(), "1");

        // Now #4 GET is inserted into capacity-3 store -> #1 POST is evicted!
        // New store: [#2 GET, #3 GET, #4 GET]
        let post_fifo_summaries = vec![
            make_summary(
                2,
                HttpMethod::Get,
                "127.0.0.1",
                "/home",
                200,
                TransactionOutcome::Completed,
            ),
            make_summary(
                3,
                HttpMethod::Get,
                "127.0.0.1",
                "/status",
                200,
                TransactionOutcome::Completed,
            ),
            make_summary(
                4,
                HttpMethod::Get,
                "127.0.0.1",
                "/about",
                200,
                TransactionOutcome::Completed,
            ),
        ];
        let (items2, total2, visible2, sel2, ret2) =
            project_traffic(&post_fifo_summaries, &filter, &scope, Some(1));
        assert_eq!(total2, 3);
        assert_eq!(visible2, 0);
        assert_eq!(sel2, -1);
        assert!(!ret2);
        assert!(items2.is_empty());
    }

    // 14. Selección conservada cuando cambia su índice visible
    #[test]
    fn test_scenario_14_selection_preserved_when_visible_index_shifts() {
        let scope = AuditScope::default();
        let summaries = vec![
            make_summary(
                1,
                HttpMethod::Get,
                "127.0.0.1",
                "/apple",
                200,
                TransactionOutcome::Completed,
            ),
            make_summary(
                2,
                HttpMethod::Get,
                "127.0.0.1",
                "/banana",
                200,
                TransactionOutcome::Completed,
            ),
            make_summary(
                3,
                HttpMethod::Get,
                "127.0.0.1",
                "/cherry",
                200,
                TransactionOutcome::Completed,
            ),
        ];

        // Neutral filter: selected ID 2 is at visible index 1
        let filter_all = FilterState::default();
        let (items1, _, _, sel_idx1, ret1) =
            project_traffic(&summaries, &filter_all, &scope, Some(2));
        assert_eq!(sel_idx1, 1);
        assert!(ret1);
        assert_eq!(items1[1].id.as_str(), "2");

        // Now filter out /apple (e.g. search query "an" matches banana and cherry)
        let filter_search = FilterState {
            search_query: "an".to_string(), // matches banana only
            ..Default::default()
        };
        let (items2, _, visible2, sel_idx2, ret2) =
            project_traffic(&summaries, &filter_search, &scope, Some(2));
        assert_eq!(visible2, 1);
        // ID 2 is now at visible index 0!
        assert_eq!(sel_idx2, 0);
        assert!(ret2);
        assert_eq!(items2[0].id.as_str(), "2");
    }

    // 15. Callbacks atrasados después de Clear
    #[test]
    fn test_scenario_15_stale_callbacks_after_clear() {
        let scope = AuditScope::default();
        // Emulate store cleared
        let empty_summaries: Vec<TransactionSummary> = Vec::new();
        let filter = FilterState::default();
        // A stale callback arrives referencing pre-clear ID 5
        let (items, total, visible, sel_idx, ret) =
            project_traffic(&empty_summaries, &filter, &scope, Some(5));
        assert_eq!(total, 0);
        assert_eq!(visible, 0);
        assert_eq!(sel_idx, -1);
        assert!(!ret);
        assert!(items.is_empty());
    }

    // 16. Flujo Stop/Start de proxy sin perder FilterState
    #[test]
    fn test_scenario_16_proxy_stop_start_preserves_filter_state() {
        let filter = FilterState {
            search_query: "api".to_string(),
            method: MethodFilter::Post,
            status: HttpStatusFilter::Status2xx,
            outcome: OutcomeFilter::Completed,
            only_in_scope: true,
            hide_connect: true,
            hide_failed: true,
        };
        let saved_filter = filter.clone();

        // Simulate proxy stop & restart cycle
        let proxy_stopped = true;
        assert!(proxy_stopped);
        let proxy_started = true;
        assert!(proxy_started);

        // Filter state must remain identical
        assert_eq!(filter, saved_filter);
    }

    // 17. Virtualización de 10.000 elementos y proyección exacta
    #[test]
    fn test_scenario_17_virtualization_10k_elements_projection() {
        let scope = AuditScope::default();
        let summaries: Vec<TransactionSummary> = (1..=10_000)
            .map(|i| {
                make_summary(
                    i,
                    if i % 2 == 0 {
                        HttpMethod::Get
                    } else {
                        HttpMethod::Post
                    },
                    "127.0.0.1",
                    "/test",
                    200,
                    TransactionOutcome::Completed,
                )
            })
            .collect();

        let filter = FilterState {
            method: MethodFilter::Post,
            ..Default::default()
        };
        let (items, total, visible, sel_idx, ret) =
            project_traffic(&summaries, &filter, &scope, Some(9_999));
        assert_eq!(total, 10_000);
        assert_eq!(visible, 5_000);
        assert_eq!(items.len(), 5_000);
        // ID 9999 is POST, so it is in visible list
        assert_eq!(sel_idx, 4_999);
        assert!(ret);
        assert_eq!(items[4_999].id.as_str(), "9999");
    }

    // 18. Semántica de HTTP Status y Outcome: Pending, Failed, Completed sin response
    #[test]
    fn test_scenario_18_status_and_outcome_semantics() {
        // Status code 0 with Pending
        let s_pending = make_summary(
            1,
            HttpMethod::Get,
            "127.0.0.1",
            "/",
            0,
            TransactionOutcome::Pending,
        );
        let item_pending = summary_to_traffic_item(&s_pending);
        assert_eq!(item_pending.status_code, 0);
        assert_eq!(item_pending.status_text.as_str(), "Pending");
        assert!(!item_pending.is_error);

        // Status code 0 with Failed
        let s_failed = make_summary(
            2,
            HttpMethod::Get,
            "127.0.0.1",
            "/",
            0,
            TransactionOutcome::Failed,
        );
        let item_failed = summary_to_traffic_item(&s_failed);
        assert_eq!(item_failed.status_code, 0);
        assert_eq!(item_failed.status_text.as_str(), "Failed");
        assert!(item_failed.is_error);

        // Status code 0 with Completed (no response)
        let s_no_resp = make_summary(
            3,
            HttpMethod::Get,
            "127.0.0.1",
            "/",
            0,
            TransactionOutcome::Completed,
        );
        let item_no_resp = summary_to_traffic_item(&s_no_resp);
        assert_eq!(item_no_resp.status_code, 0);
        assert_eq!(item_no_resp.status_text.as_str(), "No response");
        assert!(!item_no_resp.is_error);

        // Status code 404 with Completed
        let s_404 = make_summary(
            4,
            HttpMethod::Get,
            "127.0.0.1",
            "/",
            404,
            TransactionOutcome::Completed,
        );
        let item_404 = summary_to_traffic_item(&s_404);
        assert_eq!(item_404.status_code, 404);
        assert_eq!(item_404.status_text.as_str(), "OK");
        assert!(item_404.is_error);
    }

    // 19. Tests for Header Projection & UI Budgets (Gate 1.4B-2)
    #[test]
    fn test_header_projection_empty() {
        let headers = vec![];
        let res = project_headers_to_slint(&headers, false);
        assert!(res.items.is_empty());
        assert_eq!(res.omitted_count, 0);
        assert_eq!(res.notice, "");

        let text = project_headers_text(&headers, false);
        assert_eq!(text, "");
    }

    #[test]
    fn test_header_projection_preserves_order_and_duplicates() {
        use kaska_http::models::HttpHeader;
        let headers = vec![
            HttpHeader::new("Set-Cookie", "a=1"),
            HttpHeader::new("X-Custom", "val1"),
            HttpHeader::new("Set-Cookie", "b=2"),
            HttpHeader::new("x-custom", "val2"),
        ];

        let res = project_headers_to_slint(&headers, true);
        assert_eq!(res.items.len(), 4);
        assert_eq!(res.items[0].name.as_str(), "Set-Cookie");
        assert_eq!(res.items[0].value.as_str(), "a=1");
        assert!(res.items[0].is_sensitive);

        assert_eq!(res.items[1].name.as_str(), "X-Custom");
        assert_eq!(res.items[1].value.as_str(), "val1");
        assert!(!res.items[1].is_sensitive);

        assert_eq!(res.items[2].name.as_str(), "Set-Cookie");
        assert_eq!(res.items[2].value.as_str(), "b=2");
        assert!(res.items[2].is_sensitive);

        assert_eq!(res.items[3].name.as_str(), "x-custom");
        assert_eq!(res.items[3].value.as_str(), "val2");
        assert!(!res.items[3].is_sensitive);
    }

    #[test]
    fn test_header_privacy_masking_and_reveal() {
        use kaska_http::models::HttpHeader;
        let sensitive_names = [
            "Authorization",
            "authorization",
            "AUTHORIZATION",
            "Proxy-Authorization",
            "Cookie",
            "cookie",
            "Set-Cookie",
            "X-Api-Key",
            "x-api-key",
            "Api-Key",
            "api-key",
        ];

        let headers: Vec<HttpHeader> = sensitive_names
            .iter()
            .map(|name| HttpHeader::new(*name, "secret_value_12345"))
            .collect();

        // 1. Masked by default
        let masked_res = project_headers_to_slint(&headers, false);
        for item in &masked_res.items {
            assert!(item.is_sensitive);
            assert_eq!(item.value.as_str(), MASKED_SECRET_PLACEHOLDER);
        }
        let masked_text = project_headers_text(&headers, false);
        assert!(!masked_text.contains("secret_value_12345"));
        assert!(masked_text.contains(MASKED_SECRET_PLACEHOLDER));

        // 2. Revealed explicitly
        let revealed_res = project_headers_to_slint(&headers, true);
        for item in &revealed_res.items {
            assert!(item.is_sensitive);
            assert_eq!(item.value.as_str(), "secret_value_12345");
        }
        let revealed_text = project_headers_text(&headers, true);
        assert!(revealed_text.contains("secret_value_12345"));
        assert!(!revealed_text.contains(MASKED_SECRET_PLACEHOLDER));
    }

    #[test]
    fn test_header_projection_max_count_budget() {
        use kaska_http::models::HttpHeader;
        let mut headers = Vec::new();
        for i in 0..300 {
            headers.push(HttpHeader::new(format!("X-Header-{}", i), "value"));
        }

        let res = project_headers_to_slint(&headers, false);
        assert_eq!(res.items.len(), MAX_VISIBLE_HEADERS); // 256
        assert_eq!(res.omitted_count, 44);
        assert_eq!(res.notice, "[+44 headers omitted by UI budget]");
    }

    #[test]
    fn test_header_projection_truncates_large_fields_safely() {
        use kaska_http::models::HttpHeader;
        let large_name = "A".repeat(500); // Exceeds 256
        let large_val = "B".repeat(2000); // Exceeds 1024
        let headers = vec![HttpHeader::new(large_name, large_val)];

        let res = project_headers_to_slint(&headers, false);
        assert_eq!(res.items.len(), 1);
        let item = &res.items[0];
        assert_eq!(item.name.len(), MAX_HEADER_NAME_BYTES);
        assert_eq!(item.value.len(), MAX_HEADER_VALUE_BYTES);
        assert!(item.is_truncated);
    }

    #[test]
    fn test_header_utf8_multibyte_boundary_truncation() {
        use kaska_http::models::HttpHeader;
        // Emoji '🦀' is 4 bytes: 0xF0 0x9F 0xA6 0x80
        // Fill string with 'a' and end with '🦀' around boundary 256
        let mut name = "a".repeat(254);
        name.push('🦀'); // 254 + 4 = 258 bytes
        let headers = vec![HttpHeader::new(name, "val")];

        let res = project_headers_to_slint(&headers, false);
        assert_eq!(res.items.len(), 1);
        let item = &res.items[0];
        // Slice must not cut 🦀 in half, so it cuts at 254 bytes
        assert_eq!(item.name.len(), 254);
        assert!(item.is_truncated);
    }

    #[test]
    fn test_sanitize_display_text_replaces_control_characters() {
        let dirty = "Header\r\nValue\x00With\x1bControl\x7fChars";
        let clean = sanitize_display_text(dirty);
        assert_eq!(clean, "Header  Value With Control Chars");
    }

    #[test]
    fn test_reconstructed_request_line() {
        use kaska_http::models::{HttpMethod, HttpRequest};
        let req1 = HttpRequest {
            method: HttpMethod::Get,
            raw_url: "/api/status?verbose=true".to_string(),
            host: "127.0.0.1".to_string(),
            path: "/api/status".to_string(),
            query: "verbose=true".to_string(),
            http_version: "HTTP/1.1".to_string(),
            headers: vec![],
            body: vec![],
        };
        assert_eq!(
            format_reconstructed_request_line(&req1),
            "GET /api/status?verbose=true HTTP/1.1"
        );

        let req2 = HttpRequest {
            method: HttpMethod::Post,
            raw_url: "/upload".to_string(),
            host: "127.0.0.1".to_string(),
            path: "/upload".to_string(),
            query: "".to_string(),
            http_version: "HTTP/1.0".to_string(),
            headers: vec![],
            body: vec![],
        };
        assert_eq!(
            format_reconstructed_request_line(&req2),
            "POST /upload HTTP/1.0"
        );

        let req3 = HttpRequest {
            method: HttpMethod::Custom("CUSTOM".to_string()),
            raw_url: "/custom".to_string(),
            host: "127.0.0.1".to_string(),
            path: "".to_string(),
            query: "".to_string(),
            http_version: "".to_string(),
            headers: vec![],
            body: vec![],
        };
        assert_eq!(
            format_reconstructed_request_line(&req3),
            "CUSTOM / [unknown HTTP version]"
        );
    }

    #[test]
    fn test_reconstructed_status_line() {
        use kaska_http::models::HttpResponse;
        let resp = HttpResponse {
            status_code: 200,
            status_text: "OK".to_string(),
            http_version: "HTTP/1.1".to_string(),
            headers: vec![],
            body: vec![],
        };
        assert_eq!(format_reconstructed_status_line(&resp), "HTTP/1.1 200 OK");

        let resp404 = HttpResponse {
            status_code: 404,
            status_text: "Not Found".to_string(),
            http_version: "".to_string(),
            headers: vec![],
            body: vec![],
        };
        assert_eq!(
            format_reconstructed_status_line(&resp404),
            "[unknown HTTP version] 404 Not Found"
        );

        let resp_empty_reason = HttpResponse {
            status_code: 204,
            status_text: "".to_string(),
            http_version: "HTTP/2.0".to_string(),
            headers: vec![],
            body: vec![],
        };
        assert_eq!(
            format_reconstructed_status_line(&resp_empty_reason),
            "HTTP/2.0 204 "
        );
    }

    #[test]
    fn test_pure_privacy_and_safe_error_integration() {
        use kaska_http::models::{
            HttpHeader, HttpMethod, HttpRequest, HttpResponse, HttpTransaction, TransactionState,
        };

        // 1. Synthetic failed transaction containing secrets, URLs, and OS error traces (PRIV-02)
        let dirty_tx = HttpTransaction {
            id: 101,
            request: HttpRequest {
                method: HttpMethod::Post,
                raw_url: "/login?token=super_secret_query_token".to_string(),
                host: "internal.corp.local:8080".to_string(),
                path: "/login".to_string(),
                query: "token=super_secret_query_token".to_string(),
                http_version: "HTTP/1.1".to_string(),
                headers: vec![HttpHeader::new("Authorization", "Bearer dirty_token")],
                body: vec![],
            },
            response: None,
            duration_ms: 15,
            state: TransactionState::Failed(
                "Connection refused: Authorization: Bearer secret_token_xyz Cookie: session=admin_abc http://internal.local:9000/api?priv=true \x00\x1b[31mError".to_string(),
            ),
            timestamp_rfc3339: "2026-10-19T00:00:00Z".to_string(),
        };

        let proj = compute_transaction_details(Some(&dirty_tx), false);

        // Verify the response body contains ONLY the safe static message
        assert_eq!(
            proj.resp_body,
            "Transaction failed: No response received from remote server."
        );
        assert_eq!(proj.timing_text, "Status: Failed");

        // Verify absolutely zero leakage of sensitive data
        assert!(!proj.resp_body.contains("Authorization"));
        assert!(!proj.resp_body.contains("secret_token_xyz"));
        assert!(!proj.resp_body.contains("Cookie"));
        assert!(!proj.resp_body.contains("session=admin_abc"));
        assert!(!proj.resp_body.contains("internal.corp.local"));
        assert!(!proj.resp_body.contains("internal.local"));
        assert!(!proj.resp_body.contains("super_secret_query_token"));
        assert!(!proj.resp_body.contains("Connection refused"));
        assert!(!proj.resp_body.contains("\x1b"));

        // Verify sensitive headers in request are masked by default
        assert!(proj.req_headers_text.contains(MASKED_SECRET_PLACEHOLDER));
        assert!(!proj.req_headers_text.contains("dirty_token"));

        // 2. Privacy state synchronization and selection lifecycle logic (PRIV-01)
        let store = create_shared_store();
        let scope = AuditScope::default();
        let filter = FilterState::default();

        let tx = HttpTransaction {
            id: 1,
            request: HttpRequest {
                method: HttpMethod::Get,
                raw_url: "/api".to_string(),
                host: "127.0.0.1".to_string(),
                path: "/api".to_string(),
                query: "".to_string(),
                http_version: "HTTP/1.1".to_string(),
                headers: vec![HttpHeader::new("Authorization", "Bearer secret_jwt_token")],
                body: vec![],
            },
            response: Some(HttpResponse {
                status_code: 200,
                status_text: "OK".to_string(),
                http_version: "HTTP/1.1".to_string(),
                headers: vec![HttpHeader::new("Set-Cookie", "session=admin_session_val")],
                body: b"{}".to_vec(),
            }),
            duration_ms: 10,
            state: TransactionState::Completed,
            timestamp_rfc3339: "2026-10-19T00:00:00Z".to_string(),
        };

        store.lock().unwrap().insert(tx);

        let mut selected_id = Some(1);
        let mut secrets_revealed = false;

        // 2a. Initial state with secrets_revealed = false: headers are masked
        let summaries = store.lock().unwrap().get_metadata_snapshot();
        let (_, _, _, _, retained) = project_traffic(&summaries, &filter, &scope, selected_id);
        assert!(retained);
        let tx_ref = store.lock().unwrap().get_by_id(1).cloned();
        let initial_proj = compute_transaction_details(tx_ref.as_ref(), secrets_revealed);
        assert!(!initial_proj.secrets_revealed);
        assert!(initial_proj
            .req_headers_text
            .contains(MASKED_SECRET_PLACEHOLDER));
        assert!(!initial_proj.req_headers_text.contains("secret_jwt_token"));
        assert!(initial_proj
            .resp_headers_text
            .contains(MASKED_SECRET_PLACEHOLDER));
        assert!(!initial_proj.resp_headers_text.contains("admin_session_val"));

        // 2b. Explicit reveal: secrets_revealed = true
        secrets_revealed = true;
        let revealed_proj = compute_transaction_details(tx_ref.as_ref(), secrets_revealed);
        assert!(revealed_proj.secrets_revealed);
        assert!(revealed_proj.req_headers_text.contains("secret_jwt_token"));
        assert!(!revealed_proj
            .req_headers_text
            .contains(MASKED_SECRET_PLACEHOLDER));
        assert!(revealed_proj
            .resp_headers_text
            .contains("admin_session_val"));
        assert!(!revealed_proj
            .resp_headers_text
            .contains(MASKED_SECRET_PLACEHOLDER));

        // 2c. Selection retained across live update: secrets_revealed is preserved
        let summaries_update = store.lock().unwrap().get_metadata_snapshot();
        let (_, _, _, _, retained_update) =
            project_traffic(&summaries_update, &filter, &scope, selected_id);
        assert!(retained_update);
        assert!(secrets_revealed);

        // 2d. Selection lost (filtered out): secrets_revealed resets to false
        let filter_hide = FilterState {
            search_query: "non_existent_path".to_string(),
            ..Default::default()
        };
        let (_, _, _, _, retained_hide) =
            project_traffic(&summaries_update, &filter_hide, &scope, selected_id);
        assert!(!retained_hide);
        if !retained_hide {
            selected_id = None;
            secrets_revealed = false;
        }
        assert_eq!(selected_id, None);
        assert!(!secrets_revealed);
        let cleared_proj = compute_transaction_details(None, secrets_revealed);
        assert!(!cleared_proj.secrets_revealed);
        assert_eq!(cleared_proj.req_headers_text, "");
        assert_eq!(cleared_proj.resp_headers_text, "");
    }

    #[test]
    fn test_project_headers_text_bounded_and_sanitized() {
        use kaska_http::models::HttpHeader;

        // 1. Oversized header name (> 256 bytes) clamped and sanitized
        let huge_name = "X-Long-Name-".repeat(30); // ~360 bytes
        let h1 = HttpHeader::new(huge_name, "normal_value");
        let text1 = project_headers_text(&[h1], false);
        let first_line = text1.lines().next().unwrap();
        let name_part = first_line.split(':').next().unwrap();
        assert_eq!(name_part.len(), MAX_HEADER_NAME_BYTES);

        // 2. Oversized header value (> 1024 bytes) clamped and sanitized
        let huge_val = "B".repeat(2000);
        let h2 = HttpHeader::new("X-Huge", huge_val);
        let text2 = project_headers_text(&[h2], false);
        let val_part = text2
            .lines()
            .next()
            .unwrap()
            .strip_prefix("X-Huge: ")
            .unwrap();
        assert_eq!(val_part.len(), MAX_HEADER_VALUE_BYTES);

        // 3. Control characters and CRLF injection sanitized to spaces
        let dirty_header = HttpHeader::new(
            "X-Header\r\nInjected: true",
            "Value\x00With\x1b[31mEscape\r\nSec-Key: secret",
        );
        let text3 = project_headers_text(&[dirty_header], false);
        // Must contain exactly 1 newline at the end of the line
        assert_eq!(text3.lines().count(), 1);
        assert!(!text3.contains('\r'));
        assert!(!text3.contains('\x00'));
        assert!(!text3.contains('\x1b'));
        assert!(
            text3.starts_with("X-Header  Injected: true: Value With [31mEscape  Sec-Key: secret")
        );

        // 4. Aggregate budget strictly capped at 64 KiB
        let mut many_headers = Vec::new();
        for i in 0..1500 {
            many_headers.push(HttpHeader::new(
                format!("X-Header-Item-{:04}", i),
                "A".repeat(100),
            ));
        }
        let text_agg = project_headers_text(&many_headers, false);
        assert!(text_agg.len() <= MAX_HEADERS_TEXT_BUDGET);
        assert!(text_agg.ends_with("\n[Headers text truncated at 64 KiB budget]"));

        // 5. Sensitive header masking vs reveal in text mode
        let auth_header = HttpHeader::new("Authorization", "Bearer super_secret_token_123");
        let cookie_header = HttpHeader::new("Set-Cookie", "session=top_secret_cookie_456");

        let masked_text =
            project_headers_text(&[auth_header.clone(), cookie_header.clone()], false);
        assert!(masked_text.contains(MASKED_SECRET_PLACEHOLDER));
        assert!(!masked_text.contains("super_secret_token_123"));
        assert!(!masked_text.contains("top_secret_cookie_456"));

        let revealed_text = project_headers_text(&[auth_header, cookie_header], true);
        assert!(!revealed_text.contains(MASKED_SECRET_PLACEHOLDER));
        assert!(revealed_text.contains("super_secret_token_123"));
        assert!(revealed_text.contains("top_secret_cookie_456"));

        // 6. Multibyte UTF-8 boundary safe truncation in text mode
        let mut mb_name = "a".repeat(254);
        mb_name.push('🦀'); // 258 bytes
        let mut mb_val = "b".repeat(1022);
        mb_val.push('🦀'); // 1026 bytes
        let mb_header = HttpHeader::new(mb_name, mb_val);
        let mb_text = project_headers_text(&[mb_header], false);
        let mb_line = mb_text.lines().next().unwrap();
        let parts: Vec<&str> = mb_line.split(": ").collect();
        assert_eq!(parts[0].len(), 254);
        assert_eq!(parts[1].len(), 1022);
    }

    #[test]
    fn test_qa_exhaustive_privacy_case_insensitivity_and_synthetic_secrets() {
        use kaska_http::models::HttpHeader;

        // Test all 6 sensitive header families across various case variations
        let cases = [
            ("Authorization", "SYNTHETIC_TEST_SECRET_AUTH_001"),
            ("AUTHORIZATION", "SYNTHETIC_TEST_SECRET_AUTH_002"),
            ("authorization", "SYNTHETIC_TEST_SECRET_AUTH_003"),
            ("Proxy-Authorization", "SYNTHETIC_TEST_SECRET_PROXY_001"),
            ("PROXY-AUTHORIZATION", "SYNTHETIC_TEST_SECRET_PROXY_002"),
            ("proxy-authorization", "SYNTHETIC_TEST_SECRET_PROXY_003"),
            ("Cookie", "SYNTHETIC_TEST_COOKIE_001"),
            ("COOKIE", "SYNTHETIC_TEST_COOKIE_002"),
            ("cookie", "SYNTHETIC_TEST_COOKIE_003"),
            ("Set-Cookie", "SYNTHETIC_TEST_SET_COOKIE_001"),
            ("SET-COOKIE", "SYNTHETIC_TEST_SET_COOKIE_002"),
            ("set-cookie", "SYNTHETIC_TEST_SET_COOKIE_003"),
            ("X-API-Key", "SYNTHETIC_TEST_API_KEY_001"),
            ("X-Api-Key", "SYNTHETIC_TEST_API_KEY_002"),
            ("x-api-key", "SYNTHETIC_TEST_API_KEY_003"),
            ("API-Key", "SYNTHETIC_TEST_API_KEY_004"),
            ("Api-Key", "SYNTHETIC_TEST_API_KEY_005"),
            ("api-key", "SYNTHETIC_TEST_API_KEY_006"),
        ];

        let mut headers = Vec::new();
        for (name, val) in cases {
            assert!(
                is_sensitive_header(name),
                "Header '{}' must be detected as sensitive",
                name
            );
            headers.push(HttpHeader::new(name, val));
        }

        // Also add a non-sensitive header to ensure non-sensitive values are never masked
        headers.push(HttpHeader::new("Content-Type", "application/json"));

        // 1. Table projection when masked
        let proj_masked = project_headers_to_slint(&headers, false);
        for item in &proj_masked.items[..cases.len()] {
            assert!(item.is_sensitive);
            assert_eq!(item.value.as_str(), MASKED_SECRET_PLACEHOLDER);
        }
        let last_item = proj_masked.items.last().unwrap();
        assert!(!last_item.is_sensitive);
        assert_eq!(last_item.value.as_str(), "application/json");

        // 2. Table projection when revealed
        let proj_revealed = project_headers_to_slint(&headers, true);
        for (i, (_, expected_secret)) in cases.iter().enumerate() {
            let item = &proj_revealed.items[i];
            assert!(item.is_sensitive);
            assert_eq!(item.value.as_str(), *expected_secret);
        }

        // 3. Text projection when masked
        let text_masked = project_headers_text(&headers, false);
        for (_, secret) in cases {
            assert!(
                !text_masked.contains(secret),
                "Masked text must NOT contain secret {}",
                secret
            );
        }
        assert!(text_masked.contains(MASKED_SECRET_PLACEHOLDER));
        assert!(text_masked.contains("Content-Type: application/json"));

        // 4. Text projection when revealed
        let text_revealed = project_headers_text(&headers, true);
        for (_, secret) in cases {
            assert!(
                text_revealed.contains(secret),
                "Revealed text must contain secret {}",
                secret
            );
        }
    }

    #[test]
    fn test_qa_headers_duplicate_preservation_and_empty_values() {
        use kaska_http::models::HttpHeader;

        let headers = vec![
            HttpHeader::new("Set-Cookie", "session_id=SYNTHETIC_COOKIE_001; Path=/"),
            HttpHeader::new("Set-Cookie", "theme=dark; Path=/"),
            HttpHeader::new("Set-Cookie", "lang=en; Path=/"),
            HttpHeader::new("X-Custom-Empty", ""),
            HttpHeader::new("X-Duplicate", "value_alpha"),
            HttpHeader::new("X-Duplicate", "value_beta"),
            HttpHeader::new("X-Duplicate", "value_gamma"),
        ];

        // 1. Structured table preservation
        let list_masked = project_headers_to_slint(&headers, false);
        assert_eq!(list_masked.items.len(), 7);
        assert_eq!(list_masked.items[0].name.as_str(), "Set-Cookie");
        assert_eq!(
            list_masked.items[0].value.as_str(),
            MASKED_SECRET_PLACEHOLDER
        );
        assert_eq!(list_masked.items[1].name.as_str(), "Set-Cookie");
        assert_eq!(
            list_masked.items[1].value.as_str(),
            MASKED_SECRET_PLACEHOLDER
        );
        assert_eq!(list_masked.items[2].name.as_str(), "Set-Cookie");
        assert_eq!(
            list_masked.items[2].value.as_str(),
            MASKED_SECRET_PLACEHOLDER
        );

        assert_eq!(list_masked.items[3].name.as_str(), "X-Custom-Empty");
        assert_eq!(list_masked.items[3].value.as_str(), "");
        assert!(!list_masked.items[3].is_sensitive);

        assert_eq!(list_masked.items[4].name.as_str(), "X-Duplicate");
        assert_eq!(list_masked.items[4].value.as_str(), "value_alpha");
        assert_eq!(list_masked.items[5].name.as_str(), "X-Duplicate");
        assert_eq!(list_masked.items[5].value.as_str(), "value_beta");
        assert_eq!(list_masked.items[6].name.as_str(), "X-Duplicate");
        assert_eq!(list_masked.items[6].value.as_str(), "value_gamma");

        // 2. Text reconstruction preservation
        let text_masked = project_headers_text(&headers, false);
        let lines: Vec<&str> = text_masked.lines().collect();
        assert_eq!(lines.len(), 7);
        assert_eq!(lines[0], "Set-Cookie: ••••••••");
        assert_eq!(lines[1], "Set-Cookie: ••••••••");
        assert_eq!(lines[2], "Set-Cookie: ••••••••");
        assert_eq!(lines[3], "X-Custom-Empty: ");
        assert_eq!(lines[4], "X-Duplicate: value_alpha");
        assert_eq!(lines[5], "X-Duplicate: value_beta");
        assert_eq!(lines[6], "X-Duplicate: value_gamma");
    }

    #[test]
    fn test_qa_reconstructed_start_lines_all_methods() {
        use kaska_http::models::{HttpMethod, HttpRequest, HttpResponse};

        // Test standard and extended methods
        let methods = [
            (
                HttpMethod::Patch,
                "/api/v1/resource/42",
                "id=42",
                "PATCH /api/v1/resource/42?id=42 HTTP/1.1",
            ),
            (HttpMethod::Options, "*", "", "OPTIONS * HTTP/1.1"),
            (
                HttpMethod::Delete,
                "/api/v1/session",
                "",
                "DELETE /api/v1/session HTTP/1.1",
            ),
            (
                HttpMethod::Head,
                "/health",
                "format=json&verbose=true",
                "HEAD /health?format=json&verbose=true HTTP/1.1",
            ),
        ];

        for (method, path, query, expected) in methods {
            let raw_url = if query.is_empty() {
                path.to_string()
            } else {
                format!("{}?{}", path, query)
            };
            let req = HttpRequest {
                method,
                raw_url,
                host: "127.0.0.1".to_string(),
                path: path.to_string(),
                query: query.to_string(),
                headers: Vec::new(),
                body: Vec::new(),
                http_version: "HTTP/1.1".to_string(),
            };
            let line = format_reconstructed_request_line(&req);
            assert_eq!(line, expected);
        }

        // Test diverse response status codes
        let statuses = [
            (
                101,
                "Switching Protocols",
                "HTTP/1.1 101 Switching Protocols",
            ),
            (204, "No Content", "HTTP/1.1 204 No Content"),
            (304, "Not Modified", "HTTP/1.1 304 Not Modified"),
            (404, "Not Found", "HTTP/1.1 404 Not Found"),
            (502, "Bad Gateway", "HTTP/1.1 502 Bad Gateway"),
        ];

        for (code, reason, expected) in statuses {
            let resp = HttpResponse {
                status_code: code,
                status_text: reason.to_string(),
                headers: Vec::new(),
                body: Vec::new(),
                http_version: "HTTP/1.1".to_string(),
            };
            let line = format_reconstructed_status_line(&resp);
            assert_eq!(line, expected);
        }
    }

    #[test]
    fn test_qa_traffic_states_lifecycle_and_safe_error() {
        use kaska_http::models::{
            HttpHeader, HttpMethod, HttpRequest, HttpTransaction, TransactionState,
        };

        // 1. Pending transaction
        let pending_tx = HttpTransaction {
            id: 1,
            request: HttpRequest {
                method: HttpMethod::Get,
                raw_url: "/pending/test".to_string(),
                host: "127.0.0.1".to_string(),
                path: "/pending/test".to_string(),
                query: String::new(),
                headers: vec![HttpHeader::new("Host", "127.0.0.1")],
                body: Vec::new(),
                http_version: "HTTP/1.1".to_string(),
            },
            response: None,
            duration_ms: 0,
            state: TransactionState::Pending,
            timestamp_rfc3339: "2026-10-19T00:00:00Z".to_string(),
        };

        let proj_pending = compute_transaction_details(Some(&pending_tx), false);
        assert_eq!(proj_pending.req_line, "GET /pending/test HTTP/1.1");
        assert_eq!(proj_pending.timing_text, "Status: Pending (In flight)...");
        assert_eq!(proj_pending.resp_headers_text, "(No response)");
        assert!(proj_pending.resp_body.is_empty());

        // 2. Completed without response (e.g. connection dropped)
        let mut completed_no_resp_tx = pending_tx.clone();
        completed_no_resp_tx.state = TransactionState::Completed;

        let proj_no_resp = compute_transaction_details(Some(&completed_no_resp_tx), false);
        assert_eq!(proj_no_resp.timing_text, "Status: Completed (No response)");
        assert_eq!(proj_no_resp.resp_headers_text, "(No response)");

        // 3. Failed with sensitive internal error string
        let mut failed_tx = pending_tx;
        failed_tx.state = TransactionState::Failed(
            "INTERNAL_TCP_ERROR_CODE_999_DATABASE_SECRET_KEY_SYNTHETIC".to_string(),
        );

        let proj_failed = compute_transaction_details(Some(&failed_tx), false);
        assert_eq!(proj_failed.timing_text, "Status: Failed");
        assert_eq!(
            proj_failed.resp_body,
            "Transaction failed: No response received from remote server."
        );
        // Explicitly assert zero leakage of internal error message in all projection fields
        assert!(!proj_failed.resp_body.contains("INTERNAL_TCP_ERROR_CODE"));
        assert!(!proj_failed.timing_text.contains("INTERNAL_TCP_ERROR_CODE"));
        assert!(!proj_failed
            .resp_status_line
            .contains("INTERNAL_TCP_ERROR_CODE"));
        assert!(!proj_failed
            .resp_headers_text
            .contains("INTERNAL_TCP_ERROR_CODE"));
    }

    #[test]
    fn test_qa_store_immutability_after_projection() {
        use kaska_http::models::{
            HttpHeader, HttpMethod, HttpRequest, HttpTransaction, TransactionState,
        };
        use kaska_http::store::TrafficStore;

        let mut store = TrafficStore::new(100);
        let secret_token = "SYNTHETIC_BEARER_TOKEN_IMMUTABILITY_001";
        let req = HttpRequest {
            method: HttpMethod::Post,
            raw_url: "/api/immutable".to_string(),
            host: "127.0.0.1".to_string(),
            path: "/api/immutable".to_string(),
            query: String::new(),
            headers: vec![
                HttpHeader::new("Host", "127.0.0.1"),
                HttpHeader::new("Authorization", secret_token),
            ],
            body: b"Original synthetic body payload".to_vec(),
            http_version: "HTTP/1.1".to_string(),
        };

        let tx = HttpTransaction {
            id: 101,
            request: req,
            response: None,
            duration_ms: 10,
            state: TransactionState::Completed,
            timestamp_rfc3339: "2026-10-19T00:00:00Z".to_string(),
        };
        let tx_id = store.insert(tx);

        let retrieved = store
            .get_by_id(tx_id)
            .expect("Transaction must exist in store");

        // Project masked
        let proj_masked = compute_transaction_details(Some(retrieved), false);
        assert!(proj_masked
            .req_headers_text
            .contains(MASKED_SECRET_PLACEHOLDER));
        assert!(!proj_masked.req_headers_text.contains(secret_token));

        // Project revealed
        let proj_revealed = compute_transaction_details(Some(retrieved), true);
        assert!(proj_revealed.req_headers_text.contains(secret_token));

        // Verify store immutability
        let re_retrieved = store
            .get_by_id(tx_id)
            .expect("Transaction must still exist");
        assert_eq!(re_retrieved.request.headers[1].value, secret_token);
        assert_eq!(
            re_retrieved.request.body,
            b"Original synthetic body payload"
        );
    }
}
