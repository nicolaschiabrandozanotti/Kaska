/// Information about the current operating system and architecture
pub struct PlatformInfo;

impl PlatformInfo {
    pub const OS_NAME: &'static str = if cfg!(target_os = "windows") {
        "Windows"
    } else if cfg!(target_os = "linux") {
        "Linux"
    } else {
        "Other"
    };

    pub const ARCH: &'static str = if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "unknown"
    };

    pub fn display_summary() -> String {
        format!("{} {}", Self::OS_NAME, Self::ARCH)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_info() {
        assert!(!PlatformInfo::OS_NAME.is_empty());
        assert!(!PlatformInfo::ARCH.is_empty());
    }
}

/// Fit the first window inside its Windows monitor's work area without changing OS settings.
#[cfg(target_os = "windows")]
pub fn fit_initial_window(window: &slint::Window) {
    use std::ffi::c_void;
    #[repr(C)]
    #[derive(Default)]
    struct Rect {
        left: i32,
        top: i32,
        right: i32,
        bottom: i32,
    }
    #[repr(C)]
    struct Point {
        x: i32,
        y: i32,
    }
    #[repr(C)]
    struct MonitorInfo {
        size: u32,
        monitor: Rect,
        work: Rect,
        flags: u32,
    }
    #[link(name = "user32")]
    extern "system" {
        fn MonitorFromPoint(point: Point, flags: u32) -> *mut c_void;
        fn GetMonitorInfoW(monitor: *mut c_void, info: *mut MonitorInfo) -> i32;
    }
    let position = window.position();
    let mut info = MonitorInfo {
        size: std::mem::size_of::<MonitorInfo>() as u32,
        monitor: Rect::default(),
        work: Rect::default(),
        flags: 0,
    };
    // SAFETY: Win32 C layouts, valid initialized output buffer, no ownership transfer.
    let found = unsafe {
        let monitor = MonitorFromPoint(
            Point {
                x: position.x,
                y: position.y,
            },
            2,
        );
        !monitor.is_null() && GetMonitorInfoW(monitor, &mut info) != 0
    };
    if !found {
        return;
    }
    let scale = window.scale_factor();
    let available_width = (info.work.right - info.work.left).max(1) as u32;
    let available_height = (info.work.bottom - info.work.top).max(1) as u32;
    let (width, height) = initial_size(available_width, available_height, scale);
    window.set_size(slint::PhysicalSize::new(width, height));
    window.set_position(slint::PhysicalPosition::new(
        info.work.left + ((available_width - width) / 2) as i32,
        info.work.top + ((available_height - height) / 2) as i32,
    ));
}

#[cfg(not(target_os = "windows"))]
pub fn fit_initial_window(_window: &slint::Window) {}

#[cfg(any(target_os = "windows", test))]
fn initial_size(width: u32, height: u32, scale: f32) -> (u32, u32) {
    // Reserve physical space for native decorations and a small outer margin.
    let margin_x = (24.0 * scale) as u32;
    let margin_y = (44.0 * scale) as u32;
    (
        ((1180.0 * scale) as u32).min(width.saturating_sub(margin_x).max(1)),
        ((680.0 * scale) as u32).min(height.saturating_sub(margin_y).max(1)),
    )
}

#[cfg(test)]
mod window_size_tests {
    #[test]
    fn initial_window_fits_small_work_areas_at_high_dpi() {
        for scale in [1.0, 1.25, 1.5, 2.0] {
            let (width, height) = super::initial_size(1366, 720, scale);
            assert!(width < 1366 && height < 720);
            assert!(width as f32 / scale >= 640.0);
            assert!(height as f32 / scale >= 300.0);
        }
        assert_eq!(super::initial_size(1920, 1040, 1.0), (1180, 680));
    }
}
