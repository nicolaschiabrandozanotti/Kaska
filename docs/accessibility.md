# Desktop accessibility

## Implemented

- High contrast neutral text, explicit selection marker, 2px keyboard focus borders.
- Navigation and actions expose names, roles and default actions.
- ActionButton handles Enter/Space, blocks disabled input and drops pressed state when focus is lost.
- The traffic list is one keyboard stop. Up/Down, Home/End and PageUp/PageDown select original model indices and call the existing Rust callback. Rows expose selected state, index and an accessible label.
- The table/detail splitter is keyboard-adjustable and exposes a slider value/default range and increment/decrement actions.
- Informative pages expose a focusable region with arrows, PageUp/PageDown, Home/End scrolling.
- Read-only text documents remain selectable; keyboard cursor movement keeps their viewport in view.
- Empty capture, stopped capture, no selection, empty body, and distinct Repeater states (Idle, Running, Cancelling, Cancelled, Completed, Failed) provide clear contextual messages. The Rust engine coordinates five lifecycle phases (`Idle`, `Running`, `Completed`, `Failed`, `Cancelled`), while the UI surfaces a transient `Cancelling` state while awaiting worker cancellation. The StatusBar does not imply success with a permanently green indicator.
- AboutSlint is the official toolkit component, not a locally reconstructed credit.

## Toolkit limits and validation boundaries

- **Validaciones reales realizadas:** Se han verificado formalmente la navegación y captura de foco por teclado (`FocusScope` en lista virtualizada de transacciones, ajuste de splitter con teclado, manejo de Enter/Space y pérdida de foco en `ActionButton`), junto con la ejecución del arnés nativo `ui_snapshots` en Windows con despacho de eventos sintéticos y fixtures determinísticos.
- **Límites de la evidencia visual:** Los snapshots visuales (PPM/PNG) aportan evidencia de renderizado y comportamiento observado bajo configuraciones ensayadas (escalado DPI relativo y contraste estático de la paleta en Windows); no prueban corrección universal, accesibilidad semántica ni certificación WCAG. Asimismo, la evidencia visual no examina el árbol de accesibilidad del sistema operativo, eventos de accesibilidad ni anuncios hablados.
- **Comportamiento específico de plataforma (Windows frente a Linux):** En Windows, Slint se integra con AccessKit mediante UI Automation (UIA) y el arranque ajusta las cotas iniciales con User32. En Linux, la pila de accesibilidad depende de AT-SPI sobre DBus y la interacción con gestores de ventanas (X11 / Wayland) no ha sido verificada en un entorno interactivo real.
- **Linux X11/Wayland como validación gráfica pendiente:** La ejecución de la interfaz gráfica interactiva bajo servidores X11 o compositores Wayland en Linux permanece clasificada como validación gráfica pendiente de comprobación funcional directa (el CI y el modo `--headless-test` operan sin servidor de display).
- **Lectores de pantalla pendientes de pruebas reales:** No se han realizado pruebas de interoperabilidad con lectores de pantalla reales (NVDA, Narrator en Windows u Orca en Linux). Su compatibilidad operativa no está demostrada ni afirmada.
- **Alto contraste dinámico del sistema no demostrado:** El tema aprobado es un esquema fijo neutral de carbón con ratios estáticos de contraste sRGB. No existe mapeo ni conmutación dinámica ante modos de alto contraste del sistema operativo (como Windows High Contrast Mode o temas accesibles del entorno de escritorio).
- **Ausencia de certificaciones:** No se certifica conformidad con estándares WCAG (niveles A, AA o AAA) ni compatibilidad semántica completa con AccessKit más allá de los roles y acciones provistos por defecto por Slint 1.18.1. La tabla de tráfico se expone como una lista de resúmenes de transacciones y no como una cuadrícula de celdas accesible completa. Tooltips y badges son complementarios y no reemplazan etiquetas esenciales.

## Contrast

Solid sRGB pairs: #a0a0a0 on #202020 = 6.23:1; #808080 boundary on #202020 = 4.13:1; #e0e0e0 focus on #363636 = 9.15:1; #f2f2f2 on selected #363636 = 10.79:1. #808080 is reserved for disabled text, not normal instructions.

## Reproduce native snapshots

`cargo run -p kaska-desktop --example ui_snapshots --locked --jobs 2 -- <output-directory>` opens a Windows native Slint window with deterministic UI fixtures. Its render fixtures do not open sockets. After capturing the visual matrix across seven window sizes and four main views, it exercises the AppController against controlled loopback listeners on ephemeral ports: capture, selection, clear, stop, and port release. It verifies pointer/keyboard selection with 10,000 virtual rows, executes real loopback HTTP requests in Repeater, and captures all six visible states (Idle, Running, Completed, Cancelling, Cancelled, and Failed), validating real response display, cooperative cancellation against held sockets, and out-of-scope rejection. Real renderer pixels are saved as PPM. Use SLINT_SCALE_FACTOR for process-local scale testing; it does not change OS settings. Convert PPM to PNG for visual review. The existing suite and release headless test provide additional network coverage.
