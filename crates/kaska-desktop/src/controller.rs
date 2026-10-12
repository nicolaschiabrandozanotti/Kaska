use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::platform::PlatformInfo;
use crate::{AppWindow, TrafficItem};
use kaska_http::models::HttpTransaction;
use kaska_http::proxy::NativeProxyServer;
use kaska_http::scope::AuditScope;
use kaska_http::store::{create_shared_store, SharedTrafficStore};
use kaska_http::test_server::ControlledTestServer;

pub struct AppController {
    proxy_port: u16,
    test_server_port: u16,
    store: SharedTrafficStore,
    scope: Arc<AuditScope>,
    proxy: Arc<Mutex<Option<NativeProxyServer>>>,
    test_server: Arc<Mutex<Option<ControlledTestServer>>>,
}

impl Default for AppController {
    fn default() -> Self {
        Self::new(8080, 8989)
    }
}

impl AppController {
    pub fn new(proxy_port: u16, test_server_port: u16) -> Self {
        Self {
            proxy_port,
            test_server_port,
            store: create_shared_store(),
            scope: Arc::new(AuditScope::default()),
            proxy: Arc::new(Mutex::new(None)),
            test_server: Arc::new(Mutex::new(None)),
        }
    }

    /// Sets up the controller, starts local servers and binds UI callbacks
    pub fn setup(&self, app: &AppWindow) {
        app.set_os_info(SharedString::from(PlatformInfo::display_summary()));
        app.set_proxy_addr(SharedString::from(format!("127.0.0.1:{}", self.proxy_port)));
        app.set_status_message(SharedString::from(format!(
            "Native Proxy listening on 127.0.0.1:{}",
            self.proxy_port
        )));

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
