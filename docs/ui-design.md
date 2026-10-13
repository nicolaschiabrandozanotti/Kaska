# Native desktop redesign

Approved direction: neutral charcoal from the supplied reference. Background/editor #181818; shell/panels #202020; hover #262626; selection/separators #363636. No blue surfaces or saturated primary actions. Text #f2f2f2, #c6c6c6 and #a0a0a0. Essential control boundary #808080 and focus #e0e0e0.

## Presentation boundaries

Based on develop 0587743, including the new Rust Repeater engine and desktop adapter. The network controller, HTTP crate, scope enforcement and existing callbacks are unchanged relative to that base. Repeater remains a read-only example with Send disabled because Slint has no replay callback binding yet; the upstream engine and adapter are preserved. Scope describes the fixed localhost lab, not an editable runtime model. Ports in Settings are read-only. The official AboutSlint component and existing notices remain intact.

Headers are headers, not a reconstructed raw message. Response bodies are limited to 2 MiB by the existing engine; UTF-8 replacement is an existing display limitation. The UI does not infer per-transaction truncation.

## Adaptive layouts

Initial preferred client size 1180x680 logical pixels; minimum 640x300 for limited work areas. The Windows startup path queries the current monitor work area through User32 and bounds initial physical size using Slint's scale factor. No OS proxy, firewall, DPI or global settings are changed. Linux retains toolkit/window-manager initial sizing until native verification is available.

Sidebar is 192 logical pixels, or 120 below 1050. Header actions move to a second/third row according to available width. Inspector uses table/detail split above 340 workspace pixels; shorter windows switch between Traffic and Details. Narrow detail areas switch Request/Response without discarding content. Short layouts combine Request/Response and Headers/Body selectors above one document viewport. Repeater uses a page scroll when the read-only example cannot fit; its document viewport retains a readable minimum. Table columns remain available by horizontal scroll. Header and rows share the horizontal viewport; ListView virtualizes the row list. Document viewports measure actual text extent, support both scroll directions and use a read-only selectable TextInput. Settings and Scope use a page ScrollView sized by content.

Slint 1.18.1 intrinsic-layout analysis rejects/warns about responsive geometry feeding back into native size constraints. AppWindow samples its size via changed width/height callbacks before binding shell geometry; this breaks the dependency cycle while preserving native resize behavior.

## Reviewable delivery modules

1. theme.slint, action_button.slint, document_view.slint, key_value_row.slint, assets/icons, notices.
2. appwindow.slint, sidebar/header/status_bar, initial Windows fit.
3. inspector.slint: virtual traffic table and keyboard selection.
4. inspector.slint and document_view.slint: tabs, splitter, long documents, compact views.
5. repeater.slint and scope.slint: explicit read-only availability.
6. settings.slint, accessibility and native validation documentation/examples.

This working tree has no commits or published PRs. Each delivery needs its own authorized staging/commit/publication step. Files shared by deliveries 3/4 require selective patches when forming separate commits.

## SVG provenance

Eight Lucide SVGs are vendored at commit 440a1e1dfb1e712505308da46bead3c28b1f1398. repeat.svg is stored as repeat-2.svg and trash.svg as trash-2.svg; currentColor is normalized to white then recolored by Slint. Full ISC/Feather MIT licenses are stored beside the icons. No runtime icon or font dependency was added.
