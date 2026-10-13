//! Native snapshots/input checks, followed by a real controller smoke test on ephemeral loopback ports.
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};
use std::{
    cell::Cell,
    fs,
    io::{BufWriter, Write},
    path::PathBuf,
    rc::Rc,
    time::Duration,
};
slint::include_modules!();
#[path = "../src/controller.rs"]
pub mod controller;
#[path = "../src/platform.rs"]
pub mod platform;

fn click(window: &slint::Window, x: f32, y: f32) {
    use slint::platform::{PointerEventButton, WindowEvent};
    let position = slint::LogicalPosition::new(x, y);
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
fn fixture(count: usize) -> ModelRc<TrafficItem> {
    Rc::new(VecModel::from(
        (0..count)
            .map(|index| TrafficItem {
                id: index as i32 + 1,
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
    let toggles = Rc::new(Cell::new(0));
    let toggle_callback = toggles.clone();
    app.on_toggle_proxy(move || toggle_callback.set(toggle_callback.get() + 1));
    let sends = Rc::new(Cell::new(0));
    let send_callback = sends.clone();
    app.on_send_test_traffic(move || send_callback.set(send_callback.get() + 1));
    app.show()?;
    resize(app.window(), 1180.0, 680.0);
    let proxy_reservation = std::net::TcpListener::bind("127.0.0.1:0")?;
    let server_reservation = std::net::TcpListener::bind("127.0.0.1:0")?;
    let proxy_port = proxy_reservation.local_addr()?.port();
    let server_port = server_reservation.local_addr()?.port();
    drop((proxy_reservation, server_reservation));
    let live_controller = Rc::new(controller::AppController::new(proxy_port, server_port));
    let live_wait = Rc::new(Cell::new(0));
    let weak = app.as_weak();
    let step = Rc::new(Cell::new(0usize));
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
                click(app.window(), 230.0, 168.0);
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
                println!("PASS: pointer/keyboard selection, 10,000 rows, action callbacks, loading guard, keyboard navigation");
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
                if app.get_is_sending_test() || app.get_transactions_count() == 0 {
                    live_wait.set(live_wait.get() + 1);
                    assert!(live_wait.get() < 40, "Timed out waiting for real UI capture");
                    return;
                }
                click(app.window(), 230.0, 168.0);
                assert_eq!(app.get_selected_transaction_idx(), 0);
                assert!(!app.get_active_req_headers().is_empty());
                assert!(!app.get_active_resp_headers().is_empty());
                println!("PASS: real Rust controller -> loopback HTTP -> Slint traffic model and selected details; ports={proxy_port},{server_port}");
            } else if index == sizes.len() * 4 + 4 {
                if tick.is_multiple_of(2) {
                    app.invoke_clear_history();
                    assert_eq!(app.get_transactions_count(), 0);
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
                slint::quit_event_loop().unwrap();
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
    app.run()?;
    Ok(())
}
