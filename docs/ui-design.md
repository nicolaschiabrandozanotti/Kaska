# Native desktop redesign

Approved direction: neutral charcoal from the supplied reference. Background/editor #181818; shell/panels #202020; hover #262626; selection/separators #363636. No blue surfaces or saturated primary actions. Text #f2f2f2, #c6c6c6 and #a0a0a0. Essential control boundary #808080 and focus #e0e0e0.

## Presentation boundaries

Integrated baseline across PR #4 (Repeater desktop adapter), PR #5 (native UI redesign) and PR #6 (native Slint bindings). The application exposes four primary tools in the navigation sidebar: Network Inspector, HTTP Repeater, Target Scope, and Settings & About. The underlying network controller, HTTP parsing crate, scope enforcement and existing proxy capture callbacks operate alongside the interactive Repeater subsystem. Scope describes the fixed localhost lab (read-only informative model), and proxy ports in Settings remain read-only configurations. The official AboutSlint component and third-party notices remain intact.

Repeater provides an interactive HTTP/1.1 loopback request composer and replay engine wired via native Slint callbacks (`on_send_repeater`, `on_cancel_repeater`, `on_reset_repeater_defaults`). Single-line `TextInput` components provide editable HTTP Method and Target URL fields, while `RepeaterEditorView` components provide multiline text editing for Request Headers and UTF-8 Request Body. Dispatched requests execute asynchronously on a dedicated native background thread (`thread::Builder::spawn`) coordinated by `RepeaterTaskController` with single-flight locking, non-blocking UI synchronization, and cooperative cancellation tokens (`cancel_flag`).

The Repeater engine strictly enforces HTTP/1.1 over local loopback (`127.0.0.1`, `localhost`, `[::1]`). Requests targeting non-loopback hosts or unpermitted schemes/methods are rejected before transmission, and errors are sanitized via `safe_display_message()` to prevent header or credential leakage.

Repeater execution state is governed by five Rust lifecycle phases in `RepeaterLifecycle` (`Idle`, `Running`, `Completed`, `Failed`, `Cancelled`). The UI additionally models a transient `Cancelling` state (`repeater_is_cancelling: true`) while awaiting cooperative worker cancellation. Response Headers and Response Body are presented in read-only `DocumentView` viewports. Response body preview is capped to a default UI budget of 64 KiB (with a defensive hard limit of 256 KiB) to prevent event-loop memory pressure, independent of the 2 MiB HTTP engine stream ceiling. Payloads containing binary sequences or control characters are automatically formatted as bounded hex/ASCII dumps. Truncation indicators (`http-truncated` and `preview-truncated`) explicitly notify when engine stream or UI preview limits are reached.

## Adaptive layouts

Initial preferred client size 1180x680 logical pixels; minimum 640x300 for limited work areas. The Windows startup path queries the current monitor work area through User32 and bounds initial physical size using Slint's scale factor. No OS proxy, firewall, DPI or global settings are changed. Linux retains toolkit/window-manager initial sizing until native verification is available.

Sidebar is 192 logical pixels, or 120 below 1050. Header actions move to a second/third row according to available width. Inspector uses table/detail split above 340 workspace pixels; shorter windows switch between Traffic and Details. Narrow detail areas switch Request/Response without discarding content. Short layouts combine Request/Response and Headers/Body selectors above one document viewport. Repeater uses a page scroll when vertical space is constrained; its editor and document viewports retain readable minimum heights. Table columns remain available by horizontal scroll. Header and rows share the horizontal viewport; ListView virtualizes the row list. Document viewports measure actual text extent, support both scroll directions and use read-only selectable TextInput. Settings and Scope use a page ScrollView sized by content.

Slint 1.18.1 intrinsic-layout analysis rejects/warns about responsive geometry feeding back into native size constraints. AppWindow samples its size via changed width/height callbacks before binding shell geometry; this breaks the dependency cycle while preserving native resize behavior.

## Integrated architecture modules

1. `theme.slint`, `action_button.slint`, `document_view.slint`, `key_value_row.slint`, `assets/icons`, notices.
2. `appwindow.slint`, `sidebar.slint`, `header.slint`, `status_bar.slint`, initial Windows monitor fit (`platform.rs`).
3. `inspector.slint`: virtual traffic table (`ListView`), keyboard selection (`FocusScope`), adjustable splitter (`table-ratio`).
4. `inspector.slint` and `document_view.slint`: sub-tabs, long document scrolling, compact and short layouts.
5. `repeater.slint` and `repeater_adapter.rs`: editable inputs (`RepeaterEditorView`), lifecycle bindings, safe preview formatting, cooperative cancellation.
6. `scope.slint`, `settings.slint`: read-only target and configuration displays, AboutSlint credit.

## SVG provenance

Eight Lucide SVGs are vendored at commit 440a1e1dfb1e712505308da46bead3c28b1f1398. repeat.svg is stored as repeat-2.svg and trash.svg as trash-2.svg; currentColor is normalized to white then recolored by Slint. Full ISC/Feather MIT licenses are stored beside the icons. No runtime icon or font dependency was added.
