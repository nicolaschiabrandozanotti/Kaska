# Desktop accessibility

## Implemented

- High contrast neutral text, explicit selection marker, 2px keyboard focus borders.
- Navigation and actions expose names, roles and default actions.
- ActionButton handles Enter/Space, blocks disabled input and drops pressed state when focus is lost.
- The traffic list is one keyboard stop. Up/Down, Home/End and PageUp/PageDown select original model indices and call the existing Rust callback. Rows expose selected state, index and an accessible label.
- The table/detail splitter is keyboard-adjustable and exposes a slider value/default range and increment/decrement actions.
- Informative pages expose a focusable region with arrows, PageUp/PageDown, Home/End scrolling.
- Read-only text documents remain selectable; keyboard cursor movement keeps their viewport in view.
- Empty capture, stopped capture, no selection, empty body and unavailable replay are distinct messages. The StatusBar does not imply success with a permanently green indicator.
- AboutSlint is the official toolkit component, not a locally reconstructed credit.

## Toolkit limits and validation boundaries

Slint 1.18.1 has FocusScope, accessible properties/actions and AccessKit. Default crate features enable accessibility; a role alone does not implement complete grid semantics. The traffic view is exposed as a list of transaction summaries, not a complete accessible cell grid. Toolkit AboutSlint internals are preserved. Tooltips are supplemental and are not the only source of essential labels.

Native renderer and dispatched-input smoke tests do not prove NVDA/Narrator or Orca compatibility. Screen-reader behavior, mixed-monitor DPI migration and Linux window-manager behavior require direct platform testing. No WCAG compliance certification is claimed. High-contrast OS modes are not automatically mapped into the approved custom theme.

## Contrast

Solid sRGB pairs: #a0a0a0 on #202020 = 6.23:1; #808080 boundary on #202020 = 4.13:1; #e0e0e0 focus on #363636 = 9.15:1; #f2f2f2 on selected #363636 = 10.79:1. #808080 is reserved for disabled text, not normal instructions.

## Reproduce native snapshots

`cargo run -p kaska-desktop --example ui_snapshots --locked --jobs 2 -- <output-directory>` opens a Windows native Slint window with deterministic UI fixtures. Its render fixtures do not open sockets. After capturing the visual matrix, it exercises the unchanged AppController against a controlled loopback server on ephemeral ports: capture, selection, clear, stop and port release. It checks pointer/keyboard selection with 10,000 rows and saves real renderer pixels as PPM. Use SLINT_SCALE_FACTOR for process-local scale testing; it does not change OS settings. Convert PPM to PNG for visual review. The existing suite and release headless test provide additional network coverage.
