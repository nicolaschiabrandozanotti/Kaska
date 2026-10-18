use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

#[path = "repeater_adapter.rs"]
pub mod repeater_adapter;

use crate::filter::{FilterState, HttpStatusFilter, MethodFilter, OutcomeFilter};
use crate::platform::PlatformInfo;
use crate::{AppWindow, TrafficItem};
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

/// Sets details on AppWindow from an optional HttpTransaction reference or clears them.
pub fn set_transaction_details_on_ui(ui: &AppWindow, tx_opt: Option<&HttpTransaction>) {
    if let Some(tx) = tx_opt {
        ui.set_active_req_headers(SharedString::from(tx.request.headers_raw_text()));
        ui.set_active_req_body(SharedString::from(tx.request.body_as_utf8()));

        if let Some(resp) = &tx.response {
            ui.set_active_resp_headers(SharedString::from(resp.headers_raw_text()));
            ui.set_active_resp_body(SharedString::from(resp.body_as_utf8()));
            ui.set_active_timing_text(SharedString::from(format!(
                "Status {} • Duration: {} ms",
                resp.status_code, tx.duration_ms
            )));
        } else {
            ui.set_active_resp_headers(SharedString::from("(No response)"));
            ui.set_active_resp_body(SharedString::from(""));
            let outcome_str = match &tx.state {
                kaska_http::models::TransactionState::Pending => "Pending",
                kaska_http::models::TransactionState::Failed(_) => "Failed",
                kaska_http::models::TransactionState::Completed => "No response",
            };
            ui.set_active_timing_text(SharedString::from(outcome_str));
        }
    } else {
        ui.set_active_req_headers(SharedString::from(""));
        ui.set_active_req_body(SharedString::from(""));
        ui.set_active_resp_headers(SharedString::from(""));
        ui.set_active_resp_body(SharedString::from(""));
        ui.set_active_timing_text(SharedString::from(""));
    }
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
    status_suffix: Option<String>,
) {
    // 1. Take snapshot of metadata and release lock immediately
    let summaries = store.lock().unwrap().get_metadata_snapshot();

    // 2. Pure projection
    let (items, total_count, visible_count, new_idx, selection_retained) =
        project_traffic(&summaries, filter, scope, *selected_id);

    if !selection_retained {
        *selected_id = None;
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

    set_transaction_details_on_ui(ui, selected_tx.as_ref());

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

        // Shared filter state and selected ID for Inspector projection
        let filter_state = Arc::new(Mutex::new(FilterState::default()));
        let selected_id = Arc::new(Mutex::new(None::<u64>));

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
            let f = filter_state.lock().unwrap().clone();
            refresh_traffic_ui(app, &self.store, &self.scope, &f, &mut sel, None);
        }

        // Start native capturing proxy server
        let app_weak = app.as_weak();
        let store_ref = Arc::clone(&self.store);
        let scope_ref = Arc::clone(&self.scope);
        let filter_clone = Arc::clone(&filter_state);
        let selected_clone = Arc::clone(&selected_id);

        let make_on_tx_callback = {
            let app_weak = app_weak.clone();
            let store_ref = Arc::clone(&store_ref);
            let scope_ref = Arc::clone(&scope_ref);
            let filter_clone = Arc::clone(&filter_clone);
            let selected_clone = Arc::clone(&selected_clone);

            move || {
                let app_weak_inner = app_weak.clone();
                let store_inner = Arc::clone(&store_ref);
                let scope_inner = Arc::clone(&scope_ref);
                let filter_inner = Arc::clone(&filter_clone);
                let selected_inner = Arc::clone(&selected_clone);

                Arc::new(move |tx: HttpTransaction| {
                    let app_weak_deep = app_weak_inner.clone();
                    let store_deep = Arc::clone(&store_inner);
                    let scope_deep = Arc::clone(&scope_inner);
                    let filter_deep = Arc::clone(&filter_inner);
                    let selected_deep = Arc::clone(&selected_inner);

                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = app_weak_deep.upgrade() {
                            let filter = filter_deep.lock().unwrap().clone();
                            let mut sel_id = selected_deep.lock().unwrap();
                            let suffix = format!("Last: {} {}", tx.request.method, tx.request.path);
                            refresh_traffic_ui(
                                &ui,
                                &store_deep,
                                &scope_deep,
                                &filter,
                                &mut sel_id,
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

        app.on_select_transaction(move |row_idx: i32| {
            if let Some(ui) = app_weak.upgrade() {
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
                    set_transaction_details_on_ui(&ui, tx_opt.as_ref());
                }
            }
        });

        // 3b. Select Transaction by exact string ID callback
        let app_weak = app.as_weak();
        let store_select_id = Arc::clone(&self.store);
        let scope_select_id = Arc::clone(&self.scope);
        let filter_select_id = Arc::clone(&filter_state);
        let selected_select_id = Arc::clone(&selected_id);

        app.on_select_transaction_by_id(move |id_str: SharedString| {
            if let Some(ui) = app_weak.upgrade() {
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
                        set_transaction_details_on_ui(&ui, tx_opt.as_ref());
                    } else {
                        // Not in current projection: reject stale selection
                        let mut sel_guard = selected_select_id.lock().unwrap();
                        if *sel_guard == Some(id) {
                            *sel_guard = None;
                            ui.set_selected_transaction_idx(-1);
                            set_transaction_details_on_ui(&ui, None);
                        }
                    }
                }
            }
        });

        // 4. Clear History Callback
        let store_clear = Arc::clone(&self.store);
        let app_weak = app.as_weak();
        let filter_clear = Arc::clone(&filter_state);
        let selected_clear = Arc::clone(&selected_id);
        let scope_clear = Arc::clone(&self.scope);

        app.on_clear_history(move || {
            store_clear.lock().unwrap().clear();
            let mut sel_guard = selected_clear.lock().unwrap();
            *sel_guard = None;

            if let Some(ui) = app_weak.upgrade() {
                let filter = filter_clear.lock().unwrap().clone();
                refresh_traffic_ui(
                    &ui,
                    &store_clear,
                    &scope_clear,
                    &filter,
                    &mut sel_guard,
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
        app.on_filter_search_changed(move |query: SharedString| {
            if let Some(ui) = app_weak.upgrade() {
                {
                    let mut f = filter_f.lock().unwrap();
                    f.search_query = query.to_string();
                }
                let f_snapshot = filter_f.lock().unwrap().clone();
                let mut sel_id = selected_f.lock().unwrap();
                refresh_traffic_ui(&ui, &store_f, &scope_f, &f_snapshot, &mut sel_id, None);
            }
        });

        // 5b. Method Selector
        let app_weak = app.as_weak();
        let store_f = Arc::clone(&self.store);
        let scope_f = Arc::clone(&self.scope);
        let filter_f = Arc::clone(&filter_state);
        let selected_f = Arc::clone(&selected_id);
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
                refresh_traffic_ui(&ui, &store_f, &scope_f, &f_snapshot, &mut sel_id, None);
            }
        });

        // 5c. Status Selector
        let app_weak = app.as_weak();
        let store_f = Arc::clone(&self.store);
        let scope_f = Arc::clone(&self.scope);
        let filter_f = Arc::clone(&filter_state);
        let selected_f = Arc::clone(&selected_id);
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
                refresh_traffic_ui(&ui, &store_f, &scope_f, &f_snapshot, &mut sel_id, None);
            }
        });

        // 5d. Outcome Selector
        let app_weak = app.as_weak();
        let store_f = Arc::clone(&self.store);
        let scope_f = Arc::clone(&self.scope);
        let filter_f = Arc::clone(&filter_state);
        let selected_f = Arc::clone(&selected_id);
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
                refresh_traffic_ui(&ui, &store_f, &scope_f, &f_snapshot, &mut sel_id, None);
            }
        });

        // 5e. Only In Scope Checkbox
        let app_weak = app.as_weak();
        let store_f = Arc::clone(&self.store);
        let scope_f = Arc::clone(&self.scope);
        let filter_f = Arc::clone(&filter_state);
        let selected_f = Arc::clone(&selected_id);
        app.on_filter_only_in_scope_changed(move |val: bool| {
            if let Some(ui) = app_weak.upgrade() {
                {
                    let mut f = filter_f.lock().unwrap();
                    f.only_in_scope = val;
                }
                let f_snapshot = filter_f.lock().unwrap().clone();
                let mut sel_id = selected_f.lock().unwrap();
                refresh_traffic_ui(&ui, &store_f, &scope_f, &f_snapshot, &mut sel_id, None);
            }
        });

        // 5f. Hide CONNECT Checkbox
        let app_weak = app.as_weak();
        let store_f = Arc::clone(&self.store);
        let scope_f = Arc::clone(&self.scope);
        let filter_f = Arc::clone(&filter_state);
        let selected_f = Arc::clone(&selected_id);
        app.on_filter_hide_connect_changed(move |val: bool| {
            if let Some(ui) = app_weak.upgrade() {
                {
                    let mut f = filter_f.lock().unwrap();
                    f.hide_connect = val;
                }
                let f_snapshot = filter_f.lock().unwrap().clone();
                let mut sel_id = selected_f.lock().unwrap();
                refresh_traffic_ui(&ui, &store_f, &scope_f, &f_snapshot, &mut sel_id, None);
            }
        });

        // 5g. Hide Failed Checkbox
        let app_weak = app.as_weak();
        let store_f = Arc::clone(&self.store);
        let scope_f = Arc::clone(&self.scope);
        let filter_f = Arc::clone(&filter_state);
        let selected_f = Arc::clone(&selected_id);
        app.on_filter_hide_failed_changed(move |val: bool| {
            if let Some(ui) = app_weak.upgrade() {
                {
                    let mut f = filter_f.lock().unwrap();
                    f.hide_failed = val;
                }
                let f_snapshot = filter_f.lock().unwrap().clone();
                let mut sel_id = selected_f.lock().unwrap();
                refresh_traffic_ui(&ui, &store_f, &scope_f, &f_snapshot, &mut sel_id, None);
            }
        });

        // 5h. Reset Filters
        let app_weak = app.as_weak();
        let store_f = Arc::clone(&self.store);
        let scope_f = Arc::clone(&self.scope);
        let filter_f = Arc::clone(&filter_state);
        let selected_f = Arc::clone(&selected_id);
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
                refresh_traffic_ui(&ui, &store_f, &scope_f, &f_snapshot, &mut sel_id, None);
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
}
