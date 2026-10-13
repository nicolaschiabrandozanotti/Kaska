pub mod controller;
pub mod platform;

slint::include_modules!();

use controller::AppController;
use kaska_http::proxy::NativeProxyServer;
use kaska_http::scope::AuditScope;
use kaska_http::store::create_shared_store;
use kaska_http::test_server::ControlledTestServer;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    // Headless Verification Mode: executes REAL local HTTP capture over TCP sockets without GUI
    if args.iter().any(|arg| arg == "--headless-test") {
        println!("========================================================");
        println!("Kaska Native HTTP Inspector — Headless Verification");
        println!("OS / Arch: {}", platform::PlatformInfo::display_summary());
        println!("========================================================");

        let test_port = 18989;
        let proxy_port = 18080;

        // 1. Start Controlled Local Test Server
        let test_server = ControlledTestServer::new(test_port);
        test_server.start()?;
        println!(
            "1. Controlled Test Server started on 127.0.0.1:{}",
            test_port
        );

        // 2. Start Native Capturing Proxy
        let store = create_shared_store();
        let scope = Arc::new(AuditScope::default());
        let proxy = NativeProxyServer::new(proxy_port, Arc::clone(&store), scope, None);
        proxy.start()?;
        println!(
            "2. Native Capturing Proxy started on 127.0.0.1:{}",
            proxy_port
        );

        // Allow sockets to bind
        thread::sleep(Duration::from_millis(150));

        // 3. Dispatch Real HTTP Requests over TCP through the proxy
        println!("3. Sending real HTTP transactions over TCP through proxy...");
        AppController::send_real_http_requests(proxy_port, test_port);

        thread::sleep(Duration::from_millis(250));

        // 4. Verify Captured Transactions from store
        let captured = store.lock().unwrap().get_all();
        println!(
            "4. Transactions captured in memory store: {}",
            captured.len()
        );

        for tx in &captured {
            let status_code = tx.response.as_ref().map(|r| r.status_code).unwrap_or(0);
            println!(
                "   -> [#{}] {} {} -> Status: {} ({} ms, {} bytes)",
                tx.id,
                tx.request.method,
                tx.request.path,
                status_code,
                tx.duration_ms,
                tx.response_size_bytes()
            );
        }

        assert!(
            !captured.is_empty(),
            "Error: No transactions captured by native proxy"
        );
        println!("========================================================");
        println!("VERIFICATION SUCCESS: Real HTTP traffic captured and parsed.");
        println!("========================================================");

        test_server.stop();
        proxy.stop();
        return Ok(());
    }

    let app = AppWindow::new()?;
    app.global::<AppTheme>()
        .set_mono_font(slint::SharedString::from(if cfg!(target_os = "windows") {
            "Consolas"
        } else {
            "monospace"
        }));
    app.show()?;
    platform::fit_initial_window(app.window());
    let controller = AppController::new(8080, 8989);
    controller.setup(&app);

    app.run()?;

    Ok(())
}
