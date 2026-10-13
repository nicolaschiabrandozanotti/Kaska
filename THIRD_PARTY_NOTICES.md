# Third-Party Notices and Attribution

**Kaska** original source code is dual-licensed under the **MIT License** ([LICENSE-MIT](LICENSE-MIT)) or the **Apache License, Version 2.0** ([LICENSE-APACHE](LICENSE-APACHE)), at your option.

Kaska depends on third-party software and libraries that remain under their respective copyright holders and licenses. Kaska does not claim ownership over or relicense any third-party components.

---

## 1. Slint (`slint` & `slint-build`)

- **Crates:** `slint` (`1.18.1`), `slint-build` (`1.18.1`)
- **Used in:** `crates/kaska-desktop` (`kaska-http` has zero dependency on Slint)
- **Copyright:** Copyright © SixtyFPS GmbH
- **Official Website:** [https://slint.dev](https://slint.dev)
- **Licensing Model:** Slint is available under three licensing options offered by SixtyFPS GmbH:
  1. **Slint Royalty-Free Desktop License (Version 2.0)**
  2. **GNU General Public License v3.0 (GPLv3)**
  3. **Commercial Paid License**
- **Usage & Attribution in Kaska:**
  - The user interface of `kaska-desktop` is built with [**Slint**](https://slint.dev), a declarative GUI toolkit for Rust, C++, JavaScript, and Python developed by SixtyFPS GmbH.
  - For non-GPL desktop usage of `kaska-desktop`, Kaska relies on the **Slint Royalty-Free Desktop License 2.0** and provides official attribution in its repository documentation ([README.md](README.md)) and notices.
  - Kaska is an independent open-source project and is not affiliated with, endorsed by, or sponsored by SixtyFPS GmbH or Slint.
  - Full terms and conditions for Slint licensing are available at: [https://slint.dev/terms-and-conditions](https://slint.dev/terms-and-conditions).
  - *Note for binary distributions:* Prior to distributing precompiled desktop binaries under the Slint Royalty-Free Desktop License, binary builds must either maintain prominent project-page attribution or include the official `AboutSlint` component in the application UI in accordance with the Slint Royalty-Free Desktop License terms.

---

## 2. Direct Rust Ecosystem Dependencies

### `thiserror` (`2.0`)
- **Author / Copyright:** Copyright (c) David Tolnay (`dtolnay`)
- **Repository:** [https://github.com/dtolnay/thiserror](https://github.com/dtolnay/thiserror)
- **License:** `MIT OR Apache-2.0`

### `regex` (`1.11`)
- **Author / Copyright:** Copyright (c) The Rust Project Developers
- **Repository:** [https://github.com/rust-lang/regex](https://github.com/rust-lang/regex)
- **License:** `MIT OR Apache-2.0`

---

## 3. Transitive Dependencies

All transitive Cargo dependencies resolved in `Cargo.lock` remain governed by their respective upstream open-source licenses as published on [crates.io](https://crates.io). You can inspect the complete dependency graph and license metadata locally using `cargo metadata`.

## Lucide SVG icons

- Source: https://github.com/lucide-icons/lucide/tree/440a1e1dfb1e712505308da46bead3c28b1f1398/icons
- Copyright (c) 2026 Lucide Icons and Contributors. ISC license.
- Feather-derived icons retain Copyright (c) 2013-present Cole Bemis and MIT license.
- Complete ISC and MIT terms: `crates/kaska-desktop/ui/assets/icons/LICENSE`.
- Vendored files: network, repeat (stored as repeat-2), shield-check, settings, play, square, flask-conical, trash (stored as trash-2).
- Modification: currentColor replaced with white; Slint applies the neutral theme through Image.colorize. No icon runtime dependency.
