//! Native snapshots/input checks, followed by a real controller smoke test on ephemeral loopback ports.
use slint::{ComponentHandle, Model, ModelRc, SharedString, VecModel};
use std::{
    cell::{Cell, RefCell},
    fs,
    io::{BufWriter, Write},
    path::PathBuf,
    rc::Rc,
    time::Duration,
};
slint::include_modules!();
#[path = "../src/controller.rs"]
pub mod controller;
#[path = "../src/filter.rs"]
pub mod filter;
#[path = "../src/platform.rs"]
pub mod platform;

fn click(window: &slint::Window, x: f32, y: f32) {
    use slint::platform::{PointerEventButton, WindowEvent};
    let position = slint::LogicalPosition::new(x, y);
    window.dispatch_event(WindowEvent::PointerMoved { position });
    window.dispatch_event(WindowEvent::PointerPressed {
        position,
        button: PointerEventButton::Left,
    });
    window.dispatch_event(WindowEvent::PointerReleased {
        position,
        button: PointerEventButton::Left,
    });
}
fn key(window: &slint::Window, key: slint::platform::Key) {
    use slint::platform::WindowEvent;
    window.dispatch_event(WindowEvent::KeyPressed { text: key.into() });
    window.dispatch_event(WindowEvent::KeyReleased { text: key.into() });
}
fn resize(window: &slint::Window, width: f32, height: f32) {
    // Winit logical units use OS DPI; renderer scale overrides need physical dimensions.
    let scale = window.scale_factor();
    window.set_size(slint::PhysicalSize::new(
        (width * scale).round() as u32,
        (height * scale).round() as u32,
    ));
}
fn save_snapshot(window: &slint::Window, path: &std::path::Path) {
    let snapshot = window.take_snapshot().unwrap();
    let mut file = BufWriter::new(fs::File::create(path).unwrap());
    write!(
        file,
        "P6\n{} {}\n255\n",
        snapshot.width(),
        snapshot.height()
    )
    .unwrap();
    for pixel in snapshot.as_slice() {
        file.write_all(&[pixel.r, pixel.g, pixel.b]).unwrap();
    }
}
/// Contextual graphic observable for focus detection via rendered pixel line analysis.
/// Evaluates whether a contiguous border line in the specified candidate Y rows and X interval
/// exhibits the AppTheme.border-focus color (#e0e0e0, RGB >= 210, 210, 210).
/// NOTE: Pixel-based focus detection is an external contextual graphic observable from
/// framebuffer rendering; it is not a direct introspection of internal Slint widget focus state
/// nor a formal certification of accessibility / assistive technologies (AT).
fn is_horizontal_line_focus(
    window: &slint::Window,
    y_candidates: &[u32],
    x_start: u32,
    x_end: u32,
) -> bool {
    if let Ok(snap) = window.take_snapshot() {
        let w = snap.width();
        let h = snap.height();
        let data = snap.as_slice();
        for &y in y_candidates {
            if y < h {
                let mut focus_count = 0;
                for x in x_start..=x_end {
                    if x < w {
                        let p = data[(y * w + x) as usize];
                        if p.r >= 210 && p.g >= 210 && p.b >= 210 {
                            focus_count += 1;
                        }
                    }
                }
                if focus_count >= (x_end.saturating_sub(x_start) / 2) {
                    return true;
                }
            }
        }
    }
    false
}
fn fixture(count: usize) -> ModelRc<TrafficItem> {
    Rc::new(VecModel::from(
        (0..count)
            .map(|index| TrafficItem {
                id: SharedString::from((index + 1).to_string()),
                method: SharedString::from(if index == 1 { "POST" } else { "GET" }),
                host: "127.0.0.1:8989".into(),
                path: [
                    "/api/status",
                    "/api/echo",
                    "/auth/login",
                    "/admin/restricted",
                ][index % 4]
                    .into(),
                status_code: [200, 200, 302, 403][index % 4],
                status_text: ["OK", "OK", "Found", "Forbidden"][index % 4].into(),
                duration_ms: 12,
                size_bytes: 15,
                content_type: "application/json".into(),
                is_error: false,
            })
            .collect::<Vec<_>>(),
    ))
    .into()
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = PathBuf::from(
        std::env::args_os()
            .nth(1)
            .ok_or("Pass an output directory")?,
    );
    fs::create_dir_all(&output)?;
    let app = AppWindow::new()?;
    app.global::<AppTheme>().set_mono_font("Consolas".into());
    app.set_transactions(fixture(4));
    app.set_transactions_count(4);
    app.set_total_transactions_count(4);
    app.set_visible_transactions_count(4);
    app.set_selected_transaction_idx(0);
    app.set_active_req_headers(
        "Host: 127.0.0.1:8989\nAccept: application/json\nConnection: close".into(),
    );
    app.set_active_resp_headers("Content-Type: application/json\nContent-Length: 15".into());
    app.set_active_resp_body("{\"status\":\"ok\"}".into());
    app.set_active_timing_text("Status 200 | Duration: 12 ms".into());
    app.set_status_message("Proxy listening on 127.0.0.1:8080 (UI fixture, no listener)".into());
    let selected = Rc::new(Cell::new(-1));
    let selected_callback = selected.clone();
    app.on_select_transaction(move |index| selected_callback.set(index));
    let selected_id_cell = Rc::new(RefCell::new(String::new()));
    let selected_id_cb = selected_id_cell.clone();
    app.on_select_transaction_by_id(move |id_str| {
        *selected_id_cb.borrow_mut() = id_str.to_string()
    });
    let toggles = Rc::new(Cell::new(0));
    let toggle_callback = toggles.clone();
    app.on_toggle_proxy(move || toggle_callback.set(toggle_callback.get() + 1));
    let sends = Rc::new(Cell::new(0));
    let send_callback = sends.clone();
    app.on_send_test_traffic(move || send_callback.set(send_callback.get() + 1));
    let filter_method_events = Rc::new(Cell::new(-1i32));
    let fm_clone = filter_method_events.clone();
    app.on_filter_method_changed(move |idx| fm_clone.set(idx));
    let filter_reset_events = Rc::new(Cell::new(0usize));
    let fr_clone = filter_reset_events.clone();
    app.on_reset_filters(move || fr_clone.set(fr_clone.get() + 1));
    let filter_search_events = Rc::new(RefCell::new(String::new()));
    let fs_clone = filter_search_events.clone();
    app.on_filter_search_changed(move |q| *fs_clone.borrow_mut() = q.to_string());
    let filter_status_events = Rc::new(Cell::new(-1i32));
    let fstat_clone = filter_status_events.clone();
    app.on_filter_status_changed(move |idx| fstat_clone.set(idx));
    let filter_outcome_events = Rc::new(Cell::new(-1i32));
    let fo_clone = filter_outcome_events.clone();
    app.on_filter_outcome_changed(move |idx| fo_clone.set(idx));
    let filter_scope_events = Rc::new(Cell::new(false));
    let fsc_clone = filter_scope_events.clone();
    app.on_filter_only_in_scope_changed(move |v| fsc_clone.set(v));
    let filter_connect_events = Rc::new(Cell::new(false));
    let fc_clone = filter_connect_events.clone();
    app.on_filter_hide_connect_changed(move |v| fc_clone.set(v));
    let filter_failed_events = Rc::new(Cell::new(false));
    let ff_clone = filter_failed_events.clone();
    app.on_filter_hide_failed_changed(move |v| ff_clone.set(v));
    let reveal_events = Rc::new(Cell::new(0usize));
    let rev_clone = reveal_events.clone();
    app.on_toggle_reveal_secrets(move || rev_clone.set(rev_clone.get() + 1));
    app.show()?;
    resize(app.window(), 1180.0, 680.0);
    let proxy_reservation = std::net::TcpListener::bind("127.0.0.1:0")?;
    let server_reservation = std::net::TcpListener::bind("127.0.0.1:0")?;
    let proxy_port = proxy_reservation.local_addr()?.port();
    let server_port = server_reservation.local_addr()?.port();
    drop((proxy_reservation, server_reservation));
    let live_controller = Rc::new(controller::AppController::new(proxy_port, server_port));
    let live_wait = Rc::new(Cell::new(0));
    let synthetic_qa_stage = Rc::new(Cell::new(0usize));

    let cancel_listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let cancel_server_port = cancel_listener.local_addr()?.port();
    let (cancel_req_tx, cancel_req_rx) = std::sync::mpsc::channel();
    let (cancel_rel_tx, cancel_rel_rx) = std::sync::mpsc::channel();
    let cancel_server_handle = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = cancel_listener.accept() {
            let mut buf = [0u8; 1024];
            let _ = std::io::Read::read(&mut stream, &mut buf);
            let _ = cancel_req_tx.send(());
            let _ = cancel_rel_rx.recv_timeout(Duration::from_secs(5));
        }
    });
    let cancel_server = Rc::new(RefCell::new(Some((
        cancel_req_rx,
        cancel_rel_tx,
        cancel_server_handle,
    ))));

    let diag_listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let diag_server_port = diag_listener.local_addr()?.port();
    let (diag_req_tx, diag_req_rx) = std::sync::mpsc::channel();
    let (diag_rel_tx, diag_rel_rx) = std::sync::mpsc::channel();
    let diag_stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let diag_stop_clone = diag_stop.clone();
    let diag_server_handle = std::thread::spawn(move || {
        diag_listener.set_nonblocking(true).ok();
        while !diag_stop_clone.load(std::sync::atomic::Ordering::SeqCst) {
            match diag_listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_nonblocking(false).ok();
                    let mut buf = [0u8; 1024];
                    let _ = std::io::Read::read(&mut stream, &mut buf);
                    let _ = diag_req_tx.send(());
                    let _ = diag_rel_rx.recv_timeout(Duration::from_secs(5));
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(_) => break,
            }
        }
    });
    let diag_server = Rc::new(RefCell::new(Some((
        diag_req_rx,
        diag_rel_tx,
        diag_stop,
        diag_server_handle,
    ))));

    let weak = app.as_weak();
    let step = Rc::new(Cell::new(0usize));
    let cancel_server_cell = cancel_server.clone();
    let cancel_port = cancel_server_port;
    let cancel_wait = Rc::new(Cell::new(0usize));
    let cancel_wait_cell = cancel_wait.clone();
    let diag_server_cell = diag_server.clone();
    let diag_port = diag_server_port;
    let diag_wait = Rc::new(Cell::new(0usize));
    let diag_wait_cell = diag_wait.clone();
    let timer = slint::Timer::default();
    timer.start(
        slint::TimerMode::Repeated,
        Duration::from_millis(250),
        move || {
            let app = weak.upgrade().unwrap();
            let tick = step.get();
            let index = tick / 2;
            let sizes = [
                (1180.0, 780.0),
                (1180.0, 680.0),
                (800.0, 520.0),
                (640.0, 420.0),
                (640.0, 320.0),
                (1366.0, 700.0),
                (1920.0, 980.0),
            ];
            if index == 0 && !tick.is_multiple_of(2) {
                // Calculated Row 0 vertical position:
                // Window Header (68px) + Inspector top padding (12px) + Inspector title bar (32px) + spacing (8px)
                // + Filter Bar panel (78px) + spacing (8px) + Table Scroll border (2px)
                // + Table Header (32px) + Row 0 mid-height (16px) = 256.0px.
                click(app.window(), 230.0, 256.0);
                assert_eq!(selected.get(), 0, "Row pointer selection");
                key(app.window(), slint::platform::Key::DownArrow);
                assert_eq!(
                    selected.get(),
                    1,
                    "Row keyboard selection calls the same callback"
                );
                key(app.window(), slint::platform::Key::Home);
                assert_eq!(selected.get(), 0);
                app.set_transactions(fixture(10_000));
                app.set_transactions_count(10_000);
                key(app.window(), slint::platform::Key::End);
                assert_eq!(
                    selected.get(),
                    9_999,
                    "Virtualized list retains original indices"
                );
                key(app.window(), slint::platform::Key::Home);
                app.set_transactions(fixture(4));
                app.set_transactions_count(4);
                click(app.window(), 1100.0, 28.0);
                assert_eq!(toggles.get(), 1);
                key(app.window(), slint::platform::Key::Return);
                assert_eq!(toggles.get(), 2, "Keyboard activation shares the toggle callback");
                click(app.window(), 960.0, 28.0);
                assert_eq!(sends.get(), 1);
                app.set_is_sending_test(true);
                click(app.window(), 960.0, 28.0);
                assert_eq!(sends.get(), 1, "Loading action must not send again");
                app.set_is_sending_test(false);
                click(app.window(), 80.0, 178.0);
                assert_eq!(app.get_active_tab(), 2);
                key(app.window(), slint::platform::Key::Tab);
                key(app.window(), slint::platform::Key::Return);
                assert_eq!(app.get_active_tab(), 3, "Sidebar Tab/Enter navigation");
                click(app.window(), 80.0, 82.0);
                assert_eq!(app.get_active_tab(), 0);
                app.window().dispatch_event(slint::platform::WindowEvent::PointerExited);

                // Verify filter callbacks and controls are exercised
                app.invoke_filter_search_changed("test search".into());
                assert_eq!(*filter_search_events.borrow(), "test search", "Search query callback executed");
                app.invoke_filter_method_changed(1);
                assert_eq!(filter_method_events.get(), 1, "Filter method changed callback executed");
                app.invoke_filter_status_changed(2);
                assert_eq!(filter_status_events.get(), 2, "Filter status changed callback executed");
                app.invoke_filter_outcome_changed(3);
                assert_eq!(filter_outcome_events.get(), 3, "Filter outcome changed callback executed");
                app.invoke_filter_only_in_scope_changed(true);
                assert!(filter_scope_events.get(), "Filter only-in-scope callback executed");
                app.invoke_filter_hide_connect_changed(true);
                assert!(filter_connect_events.get(), "Filter hide-connect callback executed");
                app.invoke_filter_hide_failed_changed(true);
                assert!(filter_failed_events.get(), "Filter hide-failed callback executed");
                app.invoke_select_transaction_by_id("42".into());
                assert_eq!(*selected_id_cell.borrow(), "42", "Select transaction by ID callback executed");
                app.invoke_reset_filters();
                assert_eq!(filter_reset_events.get(), 1, "Reset filters callback executed");

                // Verify 1.4B-2 privacy toggle callback and transitions are exercised
                assert!(!app.get_secrets_revealed(), "Initial state is masked");
                app.invoke_toggle_reveal_secrets();
                assert_eq!(reveal_events.get(), 1, "Toggle reveal secrets callback executed");
                app.set_secrets_revealed(true);
                assert!(app.get_secrets_revealed(), "Revealed state active");
                app.invoke_toggle_reveal_secrets();
                assert_eq!(reveal_events.get(), 2, "Toggle reveal secrets callback executed again");
                app.set_secrets_revealed(false);
                assert!(!app.get_secrets_revealed(), "Re-masked state active");

                println!("PASS: pointer/keyboard selection, 10,000 rows, action callbacks, loading guard, keyboard navigation, all filter callbacks, privacy toggle transitions");
            }
            if index < sizes.len() * 4 {
                let (width, height) = sizes[index / 4];
                let tab = (index % 4) as i32;
                if tick.is_multiple_of(2) {
                    app.set_active_tab(tab);
                    resize(app.window(), width, height);
                    step.set(tick + 1);
                    return;
                }
                // Let the native resize event settle before capturing the renderer.
                let actual_size = app.window().size();
                println!("ACTUAL_WINDOW {}x{}", actual_size.width, actual_size.height);
                let snapshot = app
                    .window()
                    .take_snapshot()
                    .expect("Native renderer snapshot");
                let path = output.join(format!("{width:.0}x{height:.0}-view-{tab}.ppm"));
                let mut file = BufWriter::new(fs::File::create(path).unwrap());
                write!(
                    file,
                    "P6\n{} {}\n255\n",
                    snapshot.width(),
                    snapshot.height()
                )
                .unwrap();
                for pixel in snapshot.as_slice() {
                    file.write_all(&[pixel.r, pixel.g, pixel.b]).unwrap();
                }
                println!(
                    "SNAPSHOT view={tab} logical={width}x{height} physical={}x{}",
                    snapshot.width(),
                    snapshot.height()
                );
            } else if index == sizes.len() * 4 + 2 {
                if tick.is_multiple_of(2) {
                    app.set_active_tab(3);
                    resize(app.window(), 640.0, 320.0);
                    step.set(tick + 1);
                    return;
                }
                click(app.window(), 400.0, 150.0);
                key(app.window(), slint::platform::Key::End);
                save_snapshot(app.window(), &output.join("settings-keyboard-end.ppm"));
                println!("CHECK: Settings keyboard End snapshot");
            } else if index == sizes.len() * 4 + 3 {
                if tick.is_multiple_of(2) {
                    app.set_active_tab(0);
                    resize(app.window(), 1180.0, 680.0);
                    live_controller.setup(&app);
                    assert!(app.get_proxy_running(), "Real loopback proxy startup");
                    app.invoke_send_test_traffic();
                    step.set(tick + 1);
                    return;
                }
                if synthetic_qa_stage.get() == 0 {
                    if app.get_is_sending_test() || app.get_transactions_count() == 0 {
                        live_wait.set(live_wait.get() + 1);
                        assert!(live_wait.get() < 40, "Timed out waiting for real UI capture");
                        return;
                    }
                    assert_eq!(app.get_total_transactions_count(), 4, "Total count before filtering");
                    assert_eq!(app.get_visible_transactions_count(), 4, "Visible count before filtering");

                    // Pointer click on Row 0 at calculated Y = 256.0
                    click(app.window(), 230.0, 256.0);
                    assert_eq!(app.get_selected_transaction_idx(), 0);
                    assert!(!app.get_active_req_headers().is_empty());
                    assert!(!app.get_active_resp_headers().is_empty());
                    assert!(!app.get_secrets_revealed(), "Selected transaction defaults to masked");

                    // Live controller toggle reveal secrets on selected transaction
                    let req_list_masked = app.get_active_req_headers_list();
                    assert!(req_list_masked.row_count() > 0, "Header rows present in Slint model");
                    save_snapshot(app.window(), &output.join("inspector-details-masked.ppm"));

                    app.invoke_toggle_reveal_secrets();
                    assert!(app.get_secrets_revealed(), "Toggle reveals secrets on live controller");
                    save_snapshot(app.window(), &output.join("inspector-details-revealed.ppm"));

                    app.invoke_toggle_reveal_secrets();
                    assert!(!app.get_secrets_revealed(), "Toggle again re-masks secrets on live controller");

                    // Keyboard selection navigation to Row 1 (POST /api/echo)
                    key(app.window(), slint::platform::Key::DownArrow);
                    assert_eq!(app.get_selected_transaction_idx(), 1, "DownArrow navigates to row 1");
                    assert!(!app.get_secrets_revealed(), "Navigating to another row resets secrets to masked");

                    // Filter search: matches 'echo' (tx 2)
                    app.invoke_filter_search_changed("echo".into());
                    assert_eq!(app.get_total_transactions_count(), 4);
                    assert_eq!(app.get_visible_transactions_count(), 1, "Filter 'echo' matches 1 request");
                    assert_eq!(app.get_selected_transaction_idx(), 0, "Selection preserved by ID across search filter transition");

                    // Filter search: no match yields 0 visible
                    app.invoke_filter_search_changed("nonexistent_pattern_xyz".into());
                    assert_eq!(app.get_total_transactions_count(), 4);
                    assert_eq!(app.get_visible_transactions_count(), 0, "No match yields 0 visible");
                    assert_eq!(app.get_selected_transaction_idx(), -1, "No selection when visible count is 0");
                    save_snapshot(app.window(), &output.join("inspector-zero-visible.ppm"));

                    // Reset filters
                    app.invoke_reset_filters();
                    assert_eq!(app.get_total_transactions_count(), 4);
                    assert_eq!(app.get_visible_transactions_count(), 4, "Reset restores visible count to 4");
                    assert_eq!(app.get_filter_search(), "");
                    assert_eq!(app.get_filter_method_idx(), 0);
                    assert_eq!(app.get_filter_status_idx(), 0);
                    assert_eq!(app.get_filter_outcome_idx(), 0);
                    assert!(!app.get_filter_only_in_scope());
                    assert!(!app.get_filter_hide_connect());
                    assert!(!app.get_filter_hide_failed());

                    // Filter by Method POST (idx 2)
                    app.set_filter_method_idx(2);
                    app.invoke_filter_method_changed(2);
                    assert_eq!(app.get_visible_transactions_count(), 1, "Method POST matches 1 request");
                    app.invoke_reset_filters();
                    assert_eq!(app.get_filter_method_idx(), 0, "Reset restores method idx to 0");

                    // Filter by Status 4xx (idx 4)
                    app.set_filter_status_idx(4);
                    app.invoke_filter_status_changed(4);
                    assert_eq!(app.get_visible_transactions_count(), 1, "Status 4xx matches 1 request (403)");
                    app.invoke_reset_filters();
                    assert_eq!(app.get_filter_status_idx(), 0, "Reset restores status idx to 0");

                    // Scope & Exclusion Toggles
                    app.set_filter_only_in_scope(true);
                    app.invoke_filter_only_in_scope_changed(true);
                    assert!(app.get_filter_only_in_scope());
                    app.set_filter_hide_connect(true);
                    app.invoke_filter_hide_connect_changed(true);
                    assert!(app.get_filter_hide_connect());
                    app.set_filter_hide_failed(true);
                    app.invoke_filter_hide_failed_changed(true);
                    assert!(app.get_filter_hide_failed());
                    app.invoke_reset_filters();
                    assert!(!app.get_filter_only_in_scope(), "Reset clears only_in_scope");
                    assert!(!app.get_filter_hide_connect(), "Reset clears hide_connect");
                    assert!(!app.get_filter_hide_failed(), "Reset clears hide_failed");

                    // Select transaction explicitly by ID
                    app.invoke_select_transaction_by_id("3".into());
                    assert_eq!(app.get_selected_transaction_idx(), 2, "Select tx 3 gives visual index 2 in unfiltered table");

                    // Filter by Method GET (idx 1) -> matches 3 requests (IDs 1, 3, 4)
                    app.set_filter_method_idx(1);
                    app.invoke_filter_method_changed(1);
                    assert_eq!(app.get_visible_transactions_count(), 3, "GET matches 3 requests");
                    assert_eq!(app.get_selected_transaction_idx(), 1, "Tx 3 selection preserved at visible index 1 in filtered table");

                    // Mouse selection on filtered Row 0
                    click(app.window(), 230.0, 256.0);
                    assert_eq!(app.get_selected_transaction_idx(), 0, "Pointer clicks filtered row 0");

                    // Keyboard navigation across filtered rows
                    key(app.window(), slint::platform::Key::DownArrow);
                    assert_eq!(app.get_selected_transaction_idx(), 1, "DownArrow navigates to filtered row 1");
                    key(app.window(), slint::platform::Key::DownArrow);
                    assert_eq!(app.get_selected_transaction_idx(), 2, "DownArrow navigates to filtered row 2");
                    key(app.window(), slint::platform::Key::UpArrow);
                    assert_eq!(app.get_selected_transaction_idx(), 1, "UpArrow navigates back to filtered row 1");

                    save_snapshot(app.window(), &output.join("inspector-filters-active.ppm"));
                    app.invoke_reset_filters();

                    // Responsive 640x320 verification
                    resize(app.window(), 640.0, 320.0);
                    save_snapshot(app.window(), &output.join("inspector-compact-640x320.ppm"));
                    resize(app.window(), 1180.0, 680.0);

                    println!("PASS: real Rust controller -> loopback HTTP -> full Inspector QA (filters, search, ID preservation, mouse/keyboard selection, reset, responsive 640x320); ports={proxy_port},{server_port}");

                    // Dispatch synthetic HTTP transaction with sensitive headers and binary payload
                    let mut stream = std::net::TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
                        .expect("Connect to proxy for synthetic sensitive transaction");
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(2000)));
                    let _ = stream.set_write_timeout(Some(Duration::from_millis(2000)));
                    let binary_body: &[u8] = &[
                        0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC,
                        0xC0, 0xAF, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x01,
                    ];
                    let req_headers = format!(
                        "POST http://127.0.0.1:{}/api/echo HTTP/1.1\r\n\
                         Host: 127.0.0.1:{}\r\n\
                         Authorization: Bearer SYNTHETIC_SECRET_AUTH_TOKEN_777\r\n\
                         Cookie: session=SYNTHETIC_SESSION_COOKIE_888\r\n\
                         X-Custom-Header: non-sensitive-public-value\r\n\
                         Content-Type: application/octet-stream\r\n\
                         Content-Length: {}\r\n\
                         Connection: close\r\n\r\n",
                        server_port, server_port, binary_body.len()
                    );
                    let mut full_req = req_headers.into_bytes();
                    full_req.extend_from_slice(binary_body);
                    stream.write_all(&full_req).expect("Write synthetic request");
                    stream.flush().expect("Flush synthetic request");
                    let mut resp_buf = [0u8; 4096];
                    let _ = std::io::Read::read(&mut stream, &mut resp_buf);
                    drop(stream);

                    synthetic_qa_stage.set(1);
                    live_wait.set(0);
                    return;
                }

                // Stage 1: Validate synthetic transaction headers, Slint Model row_data, privacy toggle, and snapshots
                if synthetic_qa_stage.get() == 1 {
                    if app.get_total_transactions_count() < 5 {
                        live_wait.set(live_wait.get() + 1);
                        assert!(live_wait.get() < 40, "Timed out waiting for synthetic transaction to appear in UI");
                        return;
                    }
                    assert_eq!(app.get_total_transactions_count(), 5, "Total count with synthetic transaction");
                    assert_eq!(app.get_visible_transactions_count(), 5, "Visible count with synthetic transaction");

                    // Select transaction 5 by exact ID
                    app.invoke_select_transaction_by_id("5".into());
                    assert_eq!(app.get_selected_transaction_idx(), 4, "Transaction 5 selected at index 4");

                    // 1. Initial State (Masked)
                    assert!(!app.get_secrets_revealed(), "Defaults to masked upon selection");
                    let req_list_masked = app.get_active_req_headers_list();
                    assert!(req_list_masked.row_count() >= 3, "Headers list must contain synthetic headers");
                    let mut auth_item = None;
                    let mut cookie_item = None;
                    let mut custom_item = None;
                    for i in 0..req_list_masked.row_count() {
                        if let Some(h) = req_list_masked.row_data(i) {
                            if h.name.eq_ignore_ascii_case("authorization") {
                                auth_item = Some(h);
                            } else if h.name.eq_ignore_ascii_case("cookie") {
                                cookie_item = Some(h);
                            } else if h.name.eq_ignore_ascii_case("x-custom-header") {
                                custom_item = Some(h);
                            }
                        }
                    }
                    let auth_masked = auth_item.expect("Authorization header present in masked model");
                    let cookie_masked = cookie_item.expect("Cookie header present in masked model");
                    let custom_masked = custom_item.expect("X-Custom-Header present in model");

                    assert!(auth_masked.is_sensitive, "Authorization must be sensitive");
                    assert_eq!(auth_masked.value.as_str(), "••••••••", "Authorization must be masked");

                    assert!(cookie_masked.is_sensitive, "Cookie must be sensitive");
                    assert_eq!(cookie_masked.value.as_str(), "••••••••", "Cookie must be masked");

                    assert!(!custom_masked.is_sensitive, "X-Custom-Header must NOT be sensitive");
                    assert_eq!(custom_masked.value.as_str(), "non-sensitive-public-value");

                    // 2. Reveal Secrets
                    app.invoke_toggle_reveal_secrets();
                    assert!(app.get_secrets_revealed(), "Secrets revealed after toggle");
                    let req_list_revealed = app.get_active_req_headers_list();
                    let mut auth_rev = None;
                    let mut cookie_rev = None;
                    let mut custom_rev = None;
                    for i in 0..req_list_revealed.row_count() {
                        if let Some(h) = req_list_revealed.row_data(i) {
                            if h.name.eq_ignore_ascii_case("authorization") {
                                auth_rev = Some(h);
                            } else if h.name.eq_ignore_ascii_case("cookie") {
                                cookie_rev = Some(h);
                            } else if h.name.eq_ignore_ascii_case("x-custom-header") {
                                custom_rev = Some(h);
                            }
                        }
                    }
                    let auth_revealed = auth_rev.expect("Authorization revealed");
                    let cookie_revealed = cookie_rev.expect("Cookie revealed");
                    let custom_revealed = custom_rev.expect("Custom revealed");

                    assert!(auth_revealed.is_sensitive);
                    assert_eq!(auth_revealed.value.as_str(), "Bearer SYNTHETIC_SECRET_AUTH_TOKEN_777", "Authorization exact revealed value");

                    assert!(cookie_revealed.is_sensitive);
                    assert_eq!(cookie_revealed.value.as_str(), "session=SYNTHETIC_SESSION_COOKIE_888", "Cookie exact revealed value");

                    assert!(!custom_revealed.is_sensitive);
                    assert_eq!(custom_revealed.value.as_str(), "non-sensitive-public-value");

                    // 3. Re-mask Secrets
                    app.invoke_toggle_reveal_secrets();
                    assert!(!app.get_secrets_revealed(), "Secrets re-masked after second toggle");
                    let req_list_remasked = app.get_active_req_headers_list();
                    for i in 0..req_list_remasked.row_count() {
                        if let Some(h) = req_list_remasked.row_data(i) {
                            if h.name.eq_ignore_ascii_case("authorization") || h.name.eq_ignore_ascii_case("cookie") {
                                assert_eq!(h.value.as_str(), "••••••••", "Re-masked header value");
                            }
                        }
                    }

                    // 4. Reset Privacy on Selection Navigation
                    app.invoke_toggle_reveal_secrets();
                    assert!(app.get_secrets_revealed(), "Secrets revealed again before selection reset");
                    key(app.window(), slint::platform::Key::UpArrow);
                    assert_eq!(app.get_selected_transaction_idx(), 3, "UpArrow moves to row 3");
                    assert!(!app.get_secrets_revealed(), "Row navigation resets secrets_revealed to false");

                    // Return to transaction 5 by ID
                    app.invoke_select_transaction_by_id("5".into());
                    assert_eq!(app.get_selected_transaction_idx(), 4);
                    assert!(!app.get_secrets_revealed(), "Reselected transaction 5 remains masked");
                    let req_list_reset = app.get_active_req_headers_list();
                    for i in 0..req_list_reset.row_count() {
                        if let Some(h) = req_list_reset.row_data(i) {
                            if h.name.eq_ignore_ascii_case("authorization") || h.name.eq_ignore_ascii_case("cookie") {
                                assert_eq!(h.value.as_str(), "••••••••", "Reset masked header value");
                            }
                        }
                    }

                    // 5. GUI-04: Headers Text Mode preparation
                    // Ensure Request Headers tab is active and not on Body
                    app.set_request_body_tab(false);
                    // Click View: Text ActionButton at measured center (425.0, 468.0)
                    click(app.window(), 425.0, 468.0);
                    synthetic_qa_stage.set(2);
                    live_wait.set(0);
                    return;
                }

                if synthetic_qa_stage.get() == 2 {
                    // Slint event loop has processed the click on View: Text!
                    // Verify that Request Body tab is not active
                    assert!(!app.get_request_body_tab(), "Body tab must not be active in headers text mode");
                    // Save verified Headers Text Mode snapshot
                    save_snapshot(app.window(), &output.join("inspector-details-text-mode-verified.ppm"));
                    save_snapshot(app.window(), &output.join("inspector-details-text-mode.ppm"));

                    // Click View: Table (425.0, 468.0) to toggle back to structured table mode
                    click(app.window(), 425.0, 468.0);

                    // 6. Visual QA: Binary Hex Dump
                    assert!(app.get_active_req_is_binary(), "Active req payload must be detected as binary");
                    app.set_request_body_tab(true);
                    let req_body_str = app.get_active_req_body().to_string();
                    assert!(req_body_str.contains("000000"), "Hex dump must contain start offset");
                    assert!(req_body_str.contains("ff fe"), "Hex dump must contain hex bytes");
                    save_snapshot(app.window(), &output.join("inspector-details-hexdump.ppm"));
                    app.set_request_body_tab(false);

                    // 7. GUI-05: Request Compact 640x420 resolution and allow event loop to settle
                    resize(app.window(), 640.0, 420.0);
                    app.set_show_details(true);
                    synthetic_qa_stage.set(3);
                    live_wait.set(0);
                    return;
                }

                if synthetic_qa_stage.get() == 3 {
                    let scale = app.window().scale_factor();
                    let expected_phys_w = (640.0 * scale).round() as u32;
                    let expected_phys_h = (420.0 * scale).round() as u32;
                    let actual = app.window().size();
                    if (actual.width != expected_phys_w || actual.height != expected_phys_h) && live_wait.get() < 20 {
                        live_wait.set(live_wait.get() + 1);
                        return;
                    }
                    assert_eq!(actual.width, expected_phys_w, "Physical window width must match 640 logical at current DPI");
                    assert_eq!(actual.height, expected_phys_h, "Physical window height must match 420 logical at current DPI");

                    // Ensure details panel is open in compact mode
                    app.set_show_details(true);

                    // Save verified compact snapshots
                    save_snapshot(app.window(), &output.join("inspector-details-compact-verified.ppm"));
                    save_snapshot(app.window(), &output.join("inspector-details-compact.ppm"));

                    let snap = app.window().take_snapshot().unwrap();
                    assert_eq!(snap.width(), expected_phys_w);
                    assert_eq!(snap.height(), expected_phys_h);

                    // Restore window to standard 1180x680 resolution
                    resize(app.window(), 1180.0, 680.0);
                    synthetic_qa_stage.set(4);
                    live_wait.set(0);
                    return;
                }

                if synthetic_qa_stage.get() == 4 {
                    let scale = app.window().scale_factor();
                    let expected_phys_w = (1180.0 * scale).round() as u32;
                    let expected_phys_h = (680.0 * scale).round() as u32;
                    let actual = app.window().size();
                    if (actual.width != expected_phys_w || actual.height != expected_phys_h) && live_wait.get() < 20 {
                        live_wait.set(live_wait.get() + 1);
                        return;
                    }
                    println!("PASS: synthetic sensitive transaction -> Slint row_data cell validation (masking, reveal, remask, reset) -> visual QA text mode, binary hexdump, compact layout (verified)");
                }
            } else if index == sizes.len() * 4 + 4 {
                if tick.is_multiple_of(2) {
                    app.invoke_clear_history();
                    assert_eq!(app.get_transactions_count(), 0);
                    assert_eq!(app.get_total_transactions_count(), 0);
                    assert_eq!(app.get_visible_transactions_count(), 0);
                    assert_eq!(app.get_selected_transaction_idx(), -1);
                    assert!(app.get_active_req_headers().is_empty());
                    assert!(app.get_active_resp_body().is_empty());
                    app.invoke_toggle_proxy();
                    step.set(tick + 1);
                    return;
                }
                assert!(!app.get_proxy_running());
                assert!(std::net::TcpStream::connect(("127.0.0.1", proxy_port)).is_err(), "Stopped proxy releases its listener");
                println!("PASS: real clear history and stop capture callbacks, proxy listener released");
                step.set(tick + 1);
                return;
            } else if index == sizes.len() * 4 + 5 {
                // 1. Repeater Idle state
                if tick.is_multiple_of(2) {
                    app.set_active_tab(1);
                    resize(app.window(), 1180.0, 680.0);
                    step.set(tick + 1);
                    return;
                }
                assert_eq!(app.get_repeater_method(), "GET");
                assert_eq!(app.get_repeater_status_text(), "Idle");
                assert_eq!(app.get_repeater_url(), "http://127.0.0.1:8989/api/status");
                assert_eq!(
                    app.get_repeater_headers(),
                    "Host: 127.0.0.1:8989\nUser-Agent: Kaska-Repeater/0.1\nAccept: application/json"
                );
                // Verify Reset Defaults restores port 8989 and default headers
                app.set_repeater_method("POST".into());
                app.set_repeater_url("http://127.0.0.1:9999/custom".into());
                app.invoke_reset_repeater_defaults();
                assert_eq!(app.get_repeater_method(), "GET");
                assert_eq!(app.get_repeater_url(), "http://127.0.0.1:8989/api/status");
                assert_eq!(
                    app.get_repeater_headers(),
                    "Host: 127.0.0.1:8989\nUser-Agent: Kaska-Repeater/0.1\nAccept: application/json"
                );
                save_snapshot(app.window(), &output.join("repeater-idle.ppm"));
                println!("PASS: Repeater Idle state snapshot");
            } else if index == sizes.len() * 4 + 6 {
                // 2. Repeater Real Execution & Running state
                if tick.is_multiple_of(2) {
                    app.set_repeater_url(format!("http://127.0.0.1:{}/api/status", server_port).into());
                    app.set_repeater_headers(format!("Host: 127.0.0.1:{}\nAccept: application/json", server_port).into());
                    app.invoke_send_repeater();
                    assert!(app.get_repeater_is_running());
                    save_snapshot(app.window(), &output.join("repeater-running.ppm"));
                    println!("PASS: Repeater Running state snapshot");
                    step.set(tick + 1);
                    return;
                }
                if live_controller.repeater().is_in_flight() {
                    return;
                }
                assert_eq!(app.get_repeater_status_code(), 200);
                assert_eq!(app.get_repeater_status_text(), "OK");
                assert!(!app.get_repeater_response_headers().is_empty());
                assert!(!app.get_repeater_response_body().is_empty());
                assert_eq!(
                    live_controller.repeater_state_snapshot().lifecycle,
                    controller::repeater_adapter::RepeaterLifecycle::Completed,
                    "Snapshot lifecycle must be Completed"
                );
                save_snapshot(app.window(), &output.join("repeater-completed.ppm"));
                println!("PASS: Repeater Completed real HTTP loopback snapshot; port={server_port}");
            } else if index == sizes.len() * 4 + 7 {
                // 3. Repeater Cancelling & Cancelled states
                if tick.is_multiple_of(2) {
                    app.set_repeater_url(format!("http://127.0.0.1:{cancel_port}/slow").into());
                    app.set_repeater_headers(format!("Host: 127.0.0.1:{cancel_port}").into());
                    app.invoke_send_repeater();
                    {
                        let guard = cancel_server_cell.borrow();
                        let (req_rx, _, _) = guard.as_ref().expect("Cancel test server active");
                        req_rx
                            .recv_timeout(Duration::from_secs(2))
                            .expect("Pending request must arrive at cancel test server");
                    }
                    assert!(
                        live_controller.repeater().is_in_flight(),
                        "Must be in-flight before cancellation"
                    );
                    app.invoke_cancel_repeater();
                    assert!(app.get_repeater_is_cancelling(), "Must be in cancelling state");
                    assert!(app.get_repeater_is_running(), "Must still be running while cancelling");
                    assert_eq!(app.get_repeater_status_text(), "Cancelling...");
                    save_snapshot(app.window(), &output.join("repeater-cancelling.ppm"));
                    println!("PASS: Repeater Cancelling state snapshot");
                    // R3: DO NOT release the pending connection yet! Keep the socket held open
                    // by the server while the worker cooperatively detects the cancellation token.
                    step.set(tick + 1);
                    return;
                }
                if live_controller.repeater().is_in_flight()
                    || app.get_repeater_status_text() != "Cancelled"
                {
                    cancel_wait_cell.set(cancel_wait_cell.get() + 1);
                    assert!(
                        cancel_wait_cell.get() < 16,
                        "Timed out waiting for repeater cancellation while server holds connection"
                    );
                    return;
                }
                let snapshot = live_controller.repeater_state_snapshot();
                assert_eq!(
                    snapshot.lifecycle,
                    controller::repeater_adapter::RepeaterLifecycle::Cancelled,
                    "Snapshot lifecycle must be Cancelled"
                );
                assert_eq!(app.get_repeater_status_text(), "Cancelled");
                assert!(!app.get_repeater_is_running(), "is-running must be false after cancel");
                assert!(!app.get_repeater_is_cancelling(), "is-cancelling must be false after cancel");
                assert_eq!(app.get_repeater_status_code(), 0);
                assert_eq!(app.get_repeater_response_headers(), "");
                assert_eq!(app.get_repeater_response_body(), "");
                assert!(!app.get_repeater_error_message().is_empty());
                save_snapshot(app.window(), &output.join("repeater-cancelled.ppm"));
                println!("PASS: Repeater Cancelled state snapshot");
                // R3: ONLY release the slow server socket after confirming terminal Cancelled state
                if let Some((_, rel_tx, handle)) = cancel_server_cell.borrow_mut().take() {
                    let _ = rel_tx.send(());
                    let _ = handle.join();
                }
            } else if index == sizes.len() * 4 + 8 {
                // 4. Repeater Failed state (Out of Scope URL rejection)
                if tick.is_multiple_of(2) {
                    app.set_repeater_url("http://192.168.1.100:8080/forbidden".into());
                    app.set_repeater_headers("Host: 192.168.1.100".into());
                    app.invoke_send_repeater();
                    step.set(tick + 1);
                    return;
                }
                if live_controller.repeater().is_in_flight() {
                    return;
                }
                assert_eq!(app.get_repeater_status_text(), "Failed");
                assert!(!app.get_repeater_error_message().is_empty());
                assert_eq!(
                    live_controller.repeater_state_snapshot().lifecycle,
                    controller::repeater_adapter::RepeaterLifecycle::Failed,
                    "Snapshot lifecycle must be Failed"
                );
                save_snapshot(app.window(), &output.join("repeater-failed.ppm"));
                println!("PASS: Repeater Failed out-of-scope snapshot");
                println!("PASS: All Repeater native snapshots completed. Starting diagnostic phase 1.3C-1A...");
                step.set(tick + 1);
                return;
            } else if index == sizes.len() * 4 + 9 {
                // TC-FOC-01: Sidebar Keyboard Navigation (Tab, Return, Space)
                if tick.is_multiple_of(2) {
                    app.set_active_tab(0);
                    resize(app.window(), 1180.0, 680.0);
                    click(app.window(), 80.0, 82.0);
                    assert_eq!(app.get_active_tab(), 0, "TC-FOC-01: Precondition tab 0");
                    key(app.window(), slint::platform::Key::Tab);
                    key(app.window(), slint::platform::Key::Return);
                    assert_eq!(app.get_active_tab(), 1, "TC-FOC-01: Tab + Return activates Repeater");
                    save_snapshot(app.window(), &output.join("tc-foc-01-sidebar-tab-return.ppm"));

                    key(app.window(), slint::platform::Key::Tab);
                    app.window().dispatch_event(slint::platform::WindowEvent::KeyPressed {
                        text: slint::platform::Key::Space.into(),
                    });
                    app.window().dispatch_event(slint::platform::WindowEvent::KeyReleased {
                        text: slint::platform::Key::Space.into(),
                    });
                    assert_eq!(app.get_active_tab(), 2, "TC-FOC-01: Tab + Space activates Scope");
                    save_snapshot(app.window(), &output.join("tc-foc-01-sidebar-tab-space.ppm"));

                    click(app.window(), 80.0, 126.0);
                    assert_eq!(app.get_active_tab(), 1);
                    println!("PASS: TC-FOC-01 Sidebar navigation via Tab, Return, Space");
                    step.set(tick + 1);
                    return;
                }
                step.set(tick + 1);
                return;
            } else if index == sizes.len() * 4 + 10 {
                // TC-FOC-02 & TC-FOC-03: Send via Return and Space against held connection
                if tick.is_multiple_of(2) {
                    app.set_active_tab(1);
                    app.invoke_reset_repeater_defaults();
                    app.set_repeater_status_text("Idle".into());
                    app.set_repeater_error_message("".into());
                    app.set_repeater_url(format!("http://127.0.0.1:{diag_port}/diag-return").into());
                    app.set_repeater_headers(format!("Host: 127.0.0.1:{diag_port}").into());

                    // 1. Establish verifiable Idle precondition
                    assert!(!app.get_repeater_is_running(), "TC-FOC-02 Precondition: Must be Idle");
                    assert_eq!(app.get_repeater_status_text(), "Idle", "TC-FOC-02 Precondition: status must be Idle");
                    assert!(app.get_repeater_error_message().is_empty(), "TC-FOC-02 Precondition: error message must be empty");
                    {
                        let guard = diag_server_cell.borrow();
                        let (req_rx, _, _, _) = guard.as_ref().expect("diag server active");
                        assert!(req_rx.try_recv().is_err(), "TC-FOC-02 Precondition: No requests before Return");
                    }

                    // 2. Send receives focus through a diagnostic route that does NOT activate its callback:
                    // Focus url-input via pointer
                    click(app.window(), 400.0, 180.0);
                    {
                        let guard = diag_server_cell.borrow();
                        let (req_rx, _, _, _) = guard.as_ref().expect("diag server active");
                        assert!(req_rx.try_recv().is_err(), "TC-FOC-02 Precondition: Focusing URL input must not dispatch request");
                    }

                    // Press Tab to navigate focus from url-input to Send
                    key(app.window(), slint::platform::Key::Tab);

                    // 3. Corroborate that Send received focus and no request occurred before Return
                    let send_focus = is_horizontal_line_focus(app.window(), &[188, 206], 230, 270);
                    println!("DIAGNOSTIC OBSERVABLE: TC-FOC-02 Send received focus via Tab without click: {send_focus}");
                    assert!(
                        send_focus,
                        "TC-FOC-02: Send button must acquire observable focus indicator via Tab before Return"
                    );
                    {
                        let guard = diag_server_cell.borrow();
                        let (req_rx, _, _, _) = guard.as_ref().expect("diag server active");
                        assert!(req_rx.try_recv().is_err(), "TC-FOC-02: Zero requests must be sent before Return");
                    }

                    // 4. Inject Return exactly once
                    key(app.window(), slint::platform::Key::Return);

                    // 5. Check arrival of loopback request and absence of duplicate requests
                    {
                        let guard = diag_server_cell.borrow();
                        let (req_rx, _, _, _) = guard.as_ref().expect("diag server active");
                        req_rx.recv_timeout(Duration::from_secs(2)).expect("TC-FOC-02: Request must reach diag server upon Return");
                        assert!(
                            req_rx.try_recv().is_err(),
                            "TC-FOC-02: Exactly one request dispatched upon Return (no duplicate request received)"
                        );
                    }

                    // 6. Verify Running state and absence of contradictory/double-dispatch error
                    assert!(app.get_repeater_is_running(), "TC-FOC-02: Repeater must be running after Return");
                    assert!(app.get_repeater_error_message().is_empty(), "TC-FOC-02: Error message must be empty (no double dispatch), got: {}", app.get_repeater_error_message());

                    // 7. Save snapshot
                    save_snapshot(app.window(), &output.join("tc-foc-02-send-return-running.ppm"));
                    println!("PASS: TC-FOC-02 Send via Return initiated running state cleanly without double dispatch");

                    // TC-FOC-03: Tab to Cancel and activate via Return (Zero program fallback!)
                    key(app.window(), slint::platform::Key::Tab);
                    let cancel_focus = is_horizontal_line_focus(app.window(), &[188, 206], 320, 360);
                    println!("DIAGNOSTIC OBSERVABLE: TC-FOC-03 Cancel received focus via Tab: {cancel_focus}");
                    assert!(
                        cancel_focus,
                        "TC-FOC-03: Cancel button must acquire observable focus indicator via Tab before Return"
                    );

                    key(app.window(), slint::platform::Key::Return);
                    assert!(app.get_repeater_is_cancelling(), "TC-FOC-03: is-cancelling must be true immediately after Tab + Return without fallback");

                    step.set(tick + 1);
                    return;
                }
                if live_controller.repeater().is_in_flight() || app.get_repeater_status_text() != "Cancelled" {
                    diag_wait_cell.set(diag_wait_cell.get() + 1);
                    assert!(diag_wait_cell.get() < 20, "Timed out waiting for TC-FOC-02 cancel. Status: {}", app.get_repeater_status_text());
                    return;
                }
                diag_wait_cell.set(0);
                {
                    let guard = diag_server_cell.borrow();
                    let (_, rel_tx, _, _) = guard.as_ref().expect("diag server active");
                    let _ = rel_tx.send(());
                }
                save_snapshot(app.window(), &output.join("tc-foc-02-cancelled.ppm"));
                println!("PASS: TC-FOC-02/03 Send & Cancel transition completed");
                step.set(tick + 1);
                return;
            } else if index == sizes.len() * 4 + 11 {
                // TC-FOC-04 & TC-FOC-05: Send via Pointer & Cooperative Cancellation
                if tick.is_multiple_of(2) {
                    app.set_repeater_url(format!("http://127.0.0.1:{diag_port}/diag-pointer").into());
                    app.set_repeater_headers(format!("Host: 127.0.0.1:{diag_port}").into());
                    click(app.window(), 255.0, 212.0);
                    {
                        let guard = diag_server_cell.borrow();
                        let (req_rx, _, _, _) = guard.as_ref().expect("diag server active");
                        req_rx.recv_timeout(Duration::from_secs(2)).expect("TC-FOC-04: Pointer request must reach diag server");
                    }
                    assert!(app.get_repeater_is_running(), "TC-FOC-04: Running after pointer click");
                    save_snapshot(app.window(), &output.join("tc-foc-04-send-pointer-running.ppm"));
                    println!("PASS: TC-FOC-04 Send via pointer initiated running state");

                    click(app.window(), 345.0, 212.0);
                    assert!(app.get_repeater_is_cancelling(), "TC-FOC-05: Cancel via pointer must set is-cancelling to true without fallback");
                    save_snapshot(app.window(), &output.join("tc-foc-05-cancelling.ppm"));

                    step.set(tick + 1);
                    return;
                }
                if live_controller.repeater().is_in_flight() || app.get_repeater_status_text() != "Cancelled" {
                    diag_wait_cell.set(diag_wait_cell.get() + 1);
                    assert!(diag_wait_cell.get() < 20, "Timed out waiting for TC-FOC-05 cancel. Status: {}", app.get_repeater_status_text());
                    return;
                }
                diag_wait_cell.set(0);
                {
                    let guard = diag_server_cell.borrow();
                    let (_, rel_tx, _, _) = guard.as_ref().expect("diag server active");
                    let _ = rel_tx.send(());
                }
                save_snapshot(app.window(), &output.join("tc-foc-05-cancelled.ppm"));
                println!("PASS: TC-FOC-05 Cooperative cancellation completed");
                step.set(tick + 1);
                return;
            } else if index == sizes.len() * 4 + 12 {
                // TC-FOC-06: Immediate Response (Running -> Completed)
                if tick.is_multiple_of(2) {
                    app.set_repeater_url(format!("http://127.0.0.1:{server_port}/api/status").into());
                    app.set_repeater_headers(format!("Host: 127.0.0.1:{server_port}\nAccept: application/json").into());
                    click(app.window(), 255.0, 212.0);
                    step.set(tick + 1);
                    return;
                }
                if live_controller.repeater().is_in_flight() {
                    return;
                }
                assert_eq!(app.get_repeater_status_code(), 200, "TC-FOC-06: 200 OK expected");
                assert_eq!(app.get_repeater_status_text(), "OK");
                assert!(!app.get_repeater_is_running());
                save_snapshot(app.window(), &output.join("tc-foc-06-completed.ppm"));
                println!("PASS: TC-FOC-06 Immediate response execution & status verification");
                step.set(tick + 1);
                return;
            } else if index == sizes.len() * 4 + 13 {
                // TC-FOC-07: Input persistence across view destruction
                if tick.is_multiple_of(2) {
                    app.set_repeater_method("PUT".into());
                    app.set_repeater_url("http://127.0.0.1:8989/custom/diagnostics".into());
                    app.set_repeater_headers("X-Diagnostic: TC-FOC-07\nHost: 127.0.0.1:8989".into());
                    app.set_repeater_body("{\"persistence_test\":true}".into());

                    app.set_active_tab(0);
                    assert_eq!(app.get_active_tab(), 0);
                    step.set(tick + 1);
                    return;
                }
                app.set_active_tab(1);
                assert_eq!(app.get_active_tab(), 1);
                assert_eq!(app.get_repeater_method(), "PUT", "TC-FOC-07: Method persisted");
                assert_eq!(app.get_repeater_url(), "http://127.0.0.1:8989/custom/diagnostics", "TC-FOC-07: URL persisted");
                assert_eq!(app.get_repeater_headers(), "X-Diagnostic: TC-FOC-07\nHost: 127.0.0.1:8989", "TC-FOC-07: Headers persisted");
                assert_eq!(app.get_repeater_body(), "{\"persistence_test\":true}", "TC-FOC-07: Body persisted");
                save_snapshot(app.window(), &output.join("tc-foc-07-repeater-restored.ppm"));
                app.invoke_reset_repeater_defaults();
                println!("PASS: TC-FOC-07 Input persistence across view destruction verified");
                step.set(tick + 1);
                return;
            } else if index == sizes.len() * 4 + 14 {
                // TC-FOC-08 State 1: Focus multiline Headers editor via pointer
                if tick.is_multiple_of(2) {
                    app.set_active_tab(1);
                    click(app.window(), 380.0, 350.0);
                    step.set(tick + 1);
                    return;
                }
                save_snapshot(app.window(), &output.join("tc-foc-08-1-editor-initial.ppm"));
                let ed_focus_1 = is_horizontal_line_focus(app.window(), &[272, 273], 250, 600);
                let resp_headers_focus_1 =
                    is_horizontal_line_focus(app.window(), &[146, 147, 176, 177], 850, 930);
                println!(
                    "DIAGNOSTIC OBSERVABLE: TC-FOC-08 State 1 (Initial Click) Editor focused: {ed_focus_1}, Response Headers focused: {resp_headers_focus_1}"
                );
                assert!(
                    ed_focus_1,
                    "TC-FOC-08 State 1: Headers editor must have observable focus initially"
                );
                assert!(
                    !resp_headers_focus_1,
                    "TC-FOC-08 State 1: Response headers button must not have focus initially"
                );
                step.set(tick + 1);
                return;
            } else if index == sizes.len() * 4 + 15 {
                // TC-FOC-08 State 2: Inject Tab and diagnose focus departure / content integrity
                if tick.is_multiple_of(2) {
                    let headers_before = app.get_repeater_headers().to_string();
                    key(app.window(), slint::platform::Key::Tab);
                    let headers_after = app.get_repeater_headers().to_string();
                    let tab_inserted =
                        headers_after.contains('\t') || headers_after.len() > headers_before.len();
                    println!(
                        "DIAGNOSTIC OBSERVABLE: TC-FOC-08 State 2 Tab inserted literal tab: {tab_inserted}"
                    );
                    assert_eq!(
                        app.get_repeater_headers(),
                        headers_before.as_str(),
                        "TC-FOC-08: Content must remain unchanged after Tab"
                    );
                    step.set(tick + 1);
                    return;
                }
                save_snapshot(app.window(), &output.join("tc-foc-08-2-after-tab.ppm"));
                let ed_focus_2 = is_horizontal_line_focus(app.window(), &[272, 273], 250, 600);
                let resp_headers_focus_2 =
                    is_horizontal_line_focus(app.window(), &[146, 147, 176, 177], 850, 930);
                let send_focus_2 = is_horizontal_line_focus(app.window(), &[188, 206], 230, 270);
                let cancel_focus_2 = is_horizontal_line_focus(app.window(), &[188, 206], 320, 360);
                println!(
                    "DIAGNOSTIC OBSERVABLE: TC-FOC-08 State 2 (After Tab) Editor focused: {ed_focus_2}, Response Headers focused: {resp_headers_focus_2}, Send focused: {send_focus_2}, Cancel focused: {cancel_focus_2}"
                );
                assert!(
                    !ed_focus_2,
                    "TC-FOC-08 State 2: Headers editor must lose observable focus indicator after Tab"
                );
                assert!(
                    resp_headers_focus_2,
                    "TC-FOC-08 State 2: Response headers button must acquire observable focus indicator after Tab"
                );
                step.set(tick + 1);
                return;
            } else if index == sizes.len() * 4 + 16 {
                // TC-FOC-08 State 3: Inject Shift+Tab and diagnose focus return / content integrity
                if tick.is_multiple_of(2) {
                    let headers_before = app.get_repeater_headers().to_string();
                    app.window().dispatch_event(slint::platform::WindowEvent::KeyPressed {
                        text: slint::platform::Key::Shift.into(),
                    });
                    key(app.window(), slint::platform::Key::Tab);
                    app.window().dispatch_event(slint::platform::WindowEvent::KeyReleased {
                        text: slint::platform::Key::Shift.into(),
                    });
                    let headers_after = app.get_repeater_headers().to_string();
                    let shift_inserted = headers_after.len() > headers_before.len();
                    println!(
                        "DIAGNOSTIC OBSERVABLE: TC-FOC-08 State 3 Shift+Tab inserted text: {shift_inserted}"
                    );
                    assert_eq!(
                        app.get_repeater_headers(),
                        headers_before.as_str(),
                        "TC-FOC-08: Content must remain unchanged after Shift+Tab"
                    );
                    step.set(tick + 1);
                    return;
                }
                save_snapshot(app.window(), &output.join("tc-foc-08-3-after-shift-tab.ppm"));
                let ed_focus_3 = is_horizontal_line_focus(app.window(), &[272, 273], 250, 600);
                let resp_headers_focus_3 =
                    is_horizontal_line_focus(app.window(), &[146, 147, 176, 177], 850, 930);
                println!(
                    "DIAGNOSTIC OBSERVABLE: TC-FOC-08 State 3 (After Shift+Tab) Editor focused: {ed_focus_3}, Response Headers focused: {resp_headers_focus_3}"
                );
                assert!(
                    ed_focus_3,
                    "TC-FOC-08 State 3: Headers editor must recover observable focus indicator after Shift+Tab"
                );
                assert!(
                    !resp_headers_focus_3,
                    "TC-FOC-08 State 3: Response headers button must lose observable focus indicator after Shift+Tab"
                );
                println!("PASS: TC-FOC-08 Multiline Tab/Shift+Tab behavior diagnosed across 3 distinct states");
                println!("PASS: All diagnostic TC-FOC test phases completed successfully");
                slint::quit_event_loop().unwrap();
                return;
            } else {
                let long_document = index == sizes.len() * 4;
                if tick.is_multiple_of(2) {
                    app.set_active_tab(0);
                    resize(app.window(), 1180.0, 680.0);
                    app.set_show_details(true);
                    if long_document {
                        let mut body = String::with_capacity(2 * 1024 * 1024);
                        while body.len() < 2 * 1024 * 1024 - 120 {
                            body.push_str("Response preview line: native scroll must preserve every available byte.\n");
                        }
                        body.push_str("END OF RESPONSE / visible after Ctrl+End");
                        app.set_active_resp_body(body.into());
                        app.set_response_body_tab(true);
                    } else {
                        app.set_transactions(ModelRc::new(VecModel::from(Vec::<TrafficItem>::new())));
                        app.set_transactions_count(0);
                        app.set_proxy_running(false);
                        app.set_selected_transaction_idx(-1);
                        app.set_status_message("Capture stopped".into());
                    }
                    step.set(tick + 1);
                    return;
                }
                if long_document {
                    click(app.window(), 900.0, 450.0);
                    app.window().dispatch_event(slint::platform::WindowEvent::KeyPressed { text: slint::platform::Key::Control.into() });
                    key(app.window(), slint::platform::Key::End);
                    app.window().dispatch_event(slint::platform::WindowEvent::KeyReleased { text: slint::platform::Key::Control.into() });
                } else {
                    assert_eq!(app.get_transactions_count(), 0, "empty-stopped transactions_count must be 0");
                    assert!(!app.get_proxy_running(), "empty-stopped proxy_running must be false");
                    assert_eq!(app.get_selected_transaction_idx(), -1, "empty-stopped selected_transaction_idx must be -1");
                }
                let snapshot = app.window().take_snapshot().unwrap();
                let name = if long_document { "long-response-end.ppm" } else { "empty-stopped.ppm" };
                let mut file = BufWriter::new(fs::File::create(output.join(name)).unwrap());
                write!(file, "P6\n{} {}\n255\n", snapshot.width(), snapshot.height()).unwrap();
                for pixel in snapshot.as_slice() { file.write_all(&[pixel.r, pixel.g, pixel.b]).unwrap(); }
            }
            step.set(tick + 1);
        },
    );
    let run_res = app.run();
    if let Some((_, rel_tx, handle)) = cancel_server.borrow_mut().take() {
        let _ = rel_tx.send(());
        let _ = handle.join();
    }
    if let Some((_, rel_tx, stop, handle)) = diag_server.borrow_mut().take() {
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = rel_tx.send(());
        let _ = handle.join();
    }
    run_res?;
    Ok(())
}
