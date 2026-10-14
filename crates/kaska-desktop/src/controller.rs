use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

#[path = "repeater_adapter.rs"]
pub mod repeater_adapter;

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

        // Start native capturing proxy server
        let app_weak = app.as_weak();
        let store_ref = Arc::clone(&self.store);

        let on_tx_callback = Arc::new(move |tx: HttpTransaction| {
            let app_weak_clone = app_weak.clone();
            let store_clone = Arc::clone(&store_ref);

            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = app_weak_clone.upgrade() {
                    let all_txs = store_clone.lock().unwrap().get_all();
                    let items: Vec<TrafficItem> = all_txs
                        .into_iter()
                        .map(|t| TrafficItem {
                            id: t.id as i32,
                            method: SharedString::from(t.request.method.to_string()),
                            host: SharedString::from(t.request.host.clone()),
                            path: SharedString::from(t.request.path.clone()),
                            status_code: t.status_code() as i32,
                            status_text: SharedString::from(t.status_text()),
                            duration_ms: t.duration_ms as i32,
                            size_bytes: t.response_size_bytes() as i32,
                            content_type: SharedString::from(t.content_type()),
                            is_error: t.is_error(),
                        })
                        .collect();

                    let count = items.len();
                    ui.set_transactions_count(count as i32);
                    ui.set_transactions(ModelRc::new(VecModel::from(items)));
                    ui.set_status_message(SharedString::from(format!(
                        "Captured {} requests • Last: {} {}",
                        count, tx.request.method, tx.request.path
                    )));
                }
            });
        });

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

            // Restart proxy
            let app_weak_inner = app_weak.clone();
            let store_inner = Arc::clone(&store_ref);
            let on_tx = Arc::new(move |tx: HttpTransaction| {
                let app_weak_deep = app_weak_inner.clone();
                let store_deep = Arc::clone(&store_inner);
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = app_weak_deep.upgrade() {
                        let all_txs = store_deep.lock().unwrap().get_all();
                        let items: Vec<TrafficItem> = all_txs
                            .into_iter()
                            .map(|t| TrafficItem {
                                id: t.id as i32,
                                method: SharedString::from(t.request.method.to_string()),
                                host: SharedString::from(t.request.host.clone()),
                                path: SharedString::from(t.request.path.clone()),
                                status_code: t.status_code() as i32,
                                status_text: SharedString::from(t.status_text()),
                                duration_ms: t.duration_ms as i32,
                                size_bytes: t.response_size_bytes() as i32,
                                content_type: SharedString::from(t.content_type()),
                                is_error: t.is_error(),
                            })
                            .collect();

                        let count = items.len();
                        ui.set_transactions_count(count as i32);
                        ui.set_transactions(ModelRc::new(VecModel::from(items)));
                        ui.set_status_message(SharedString::from(format!(
                            "Captured {} requests • Last: {} {}",
                            count, tx.request.method, tx.request.path
                        )));
                    }
                });
            });

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

        // 3. Select Transaction Item Callback
        let app_weak = app.as_weak();
        let store_lookup = Arc::clone(&self.store);

        app.on_select_transaction(move |row_idx: i32| {
            if let Some(ui) = app_weak.upgrade() {
                let store = store_lookup.lock().unwrap();
                let txs = store.get_all();
                if let Some(tx) = txs.get(row_idx as usize) {
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
                        ui.set_active_timing_text(SharedString::from("Pending / Failed"));
                    }
                }
            }
        });

        // 4. Clear History Callback
        let store_clear = Arc::clone(&self.store);
        let app_weak = app.as_weak();

        app.on_clear_history(move || {
            store_clear.lock().unwrap().clear();
            if let Some(ui) = app_weak.upgrade() {
                ui.set_transactions(ModelRc::new(VecModel::from(Vec::new())));
                ui.set_transactions_count(0);
                ui.set_selected_transaction_idx(-1);
                ui.set_active_req_headers(SharedString::from(""));
                ui.set_active_req_body(SharedString::from(""));
                ui.set_active_resp_headers(SharedString::from(""));
                ui.set_active_resp_body(SharedString::from(""));
                ui.set_active_timing_text(SharedString::from(""));
                ui.set_status_message(SharedString::from("History cleared"));
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
}
