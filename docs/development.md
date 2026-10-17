# Guía de Desarrollo Local — Kaska

Esta guía proporciona las instrucciones necesarias para clonar, compilar, ejecutar, probar y depurar **Kaska** en entornos de desarrollo Windows y Linux.

---

## 1. Requisitos Previos

- **Rust:** Versión estable 1.85+ (edición 2021). Instalar mediante [rustup](https://rustup.rs/):
  ```bash
  rustup update stable
  rustup component add rustfmt clippy
  ```
- **Windows:** Visual Studio 2022 Build Tools con soporte de C++ (MSVC toolchain x86_64).
- **Linux (Ubuntu/Debian):**
  - **Dependencias de compilación y enlace (necesarias para Cargo y Slint):**
    ```bash
    sudo apt-get update
    sudo apt-get install -y --no-install-recommends pkg-config libfontconfig1-dev libxkbcommon-dev
    ```
  - **Dependencias para ejecución de interfaz gráfica interactiva (X11 / Wayland):** Servidor gráfico activo (X11 o compositor Wayland) y bibliotecas de ventanas/input (`libx11-dev`, `libx11-xcb-dev`, `libfreetype6-dev`).
  - **Modo headless (`--headless-test`):** No requiere servidor gráfico ni display en runtime (bifurca antes de la inicialización de ventana Slint).

> [!NOTE]
> **Estado de verificación de plataformas y niveles de validación:**
> - **CI Windows / Ubuntu (GitHub Actions):** Flujo automatizado en `.github/workflows/ci.yml` ejecutado en cada `push` y `pull_request` a las ramas `main` y `develop` sobre runners `windows-latest` y `ubuntu-latest`. La ejecución postmerge del PR #10 certificó 100% de tests unitarios y de integración pasando en ambas plataformas (`cargo test --workspace --locked --jobs 2 -- --test-threads=2`), `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --jobs 2 -- -D warnings`, builds dev/release, smoke test headless (`--headless-test`), verificación estricta de sockets libres y análisis semántico de workflows mediante `actionlint` v1.7.12 en Ubuntu (con verificación de suma SHA-256).
> - **Tests Headless (`--headless-test`):** Validación funcional autónoma que no requiere entorno gráfico ni display en runtime. Arranca sockets TCP locales en loopback, procesa transacciones HTTP y valida aislamiento y captura sin inicializar la ventana Slint.
> - **Pruebas con Renderer Real (`ui_snapshots`):** Validación visual interactiva en Windows abriendo una ventana nativa de Slint con fixtures determinísticos en siete tamaños y cuatro vistas principales. Ejercita el AppController contra listeners loopback efímeros (captura, selección, limpieza, detención y liberación de sockets), verifica selección con 10.000 filas virtuales y ejecuta solicitudes HTTP reales en Repeater validando sus seis estados visibles (Idle, Running, Completed, Cancelling, Cancelled, Failed) con volcado de píxeles PPM.
> - **Benchmark y Pilotos de Rendimiento (`perf_baseline`):** Arnés de rendimiento con microbenchmarks sintéticos (modelos, parser, store, controller) y pilotos end-to-end N=5, N=25 y N=100 sobre bucle local controlado con recolección de métricas de proceso (WorkingSet, Pagefile y CPU en Windows; VmRSS y RssAnon en Linux).
> - **Pruebas Gráficas en Linux (Pendientes):** El soporte visual e interactivo bajo sesión de escritorio Linux real (X11 o compositor Wayland con display activo) permanece clasificado como **pendiente de validación funcional interactiva directa** (los tests en CI y el modo headless ejecutan sin display).
> - **Comportamiento de `--locked`:** El flag `--locked` no deshabilita el acceso a la red por sí mismo (a diferencia de `--offline`), sino que exige que Cargo respete estrictamente el archivo `Cargo.lock` sin actualizar ni recalcular versiones de dependencias.

---

## 2. Flujo de Compilación

Siempre limite la concurrencia de compilación para no saturar el equipo de desarrollo:

```bash
# Compilar todo el workspace
cargo build --workspace --jobs 2

# Compilar en modo Release optimizado
cargo build --workspace --release --jobs 2
```

---

## 3. Ejecución de la Aplicación

### Modo Desarrollo (GUI Slint)
```bash
cargo run -p kaska-desktop --jobs 2
```

### Modo Verificación Headless (Sin interfaz gráfica)
Ideal para verificar la captura real de tráfico HTTP sobre sockets TCP en servidores sin pantalla o en integración continua:
```bash
cargo run -p kaska-desktop --jobs 2 -- --headless-test
```

---

## 4. Pruebas y Control de Calidad

### 4.1. Suite Estándar y Linter (Integración Continua)
```bash
# Ejecutar todos los tests unitarios y de integración con hilos acotados y lockfile estricto
cargo test --workspace --locked --jobs 2 -- --test-threads=2

# Verificar formato con rustfmt
cargo fmt --all -- --check

# Análisis estricto con Clippy sin advertencias
cargo clippy --workspace --all-targets --jobs 2 -- -D warnings
```

### 4.2. Modo Verificación Headless (Sin Display)
Ejecutable en entornos sin servidor gráfico (CI, servidores Linux remotos):
```bash
cargo run -p kaska-desktop --jobs 2 -- --headless-test
```

### 4.3. Verificación Visual de UI con Renderer Real (`ui_snapshots`)
Abre una ventana Slint nativa en Windows, recorre la matriz visual completa (siete tamaños y cuatro vistas principales), comprueba interacción de foco y selección virtualizada con 10.000 filas, y valida los seis estados visibles de Repeater sobre listeners loopback efímeros guardando snapshots PPM:
```bash
cargo run -p kaska-desktop --example ui_snapshots --locked --jobs 2 -- <directorio-de-salida>
```

### 4.4. Arnés de Rendimiento y Microbenchmarks (`perf_baseline`)
Ejecuta microbenchmarks sintéticos (modelos, parsing, store, controller) y pilotos end-to-end sobre loopback controlado (N=5, N=25, N=100) con captura de métricas de proceso:
```bash
# Validación de microbenchmarks
cargo run -p kaska-desktop --example perf_baseline --locked --jobs 2 -- --validate [--output-dir <directorio>]

# Pilotos loopback controlados (N=5, N=25, N=100)
cargo run -p kaska-desktop --example perf_baseline --locked --jobs 2 -- --pilot-5 [--output-dir <directorio>]
cargo run -p kaska-desktop --example perf_baseline --locked --jobs 2 -- --pilot-25 [--output-dir <directorio>]
cargo run -p kaska-desktop --example perf_baseline --locked --jobs 2 -- --pilot-100 [--output-dir <directorio>]

# Suite completa de microbenchmarks y pilotos N=5 y N=25
cargo run -p kaska-desktop --example perf_baseline --locked --jobs 2 -- --all [--output-dir <directorio>]
```
> [!IMPORTANT]
> Los directorios de salida para `ui_snapshots` y `perf_baseline` deben ubicarse estrictamente fuera del repositorio y de los worktrees protegidos para prevenir la creación de archivos no rastreados accidentales. No ejecutar estos examples durante gates de sincronización documental.

---

## 5. Diagnóstico de Problemas Comunes

1. **Error de enlace en Linux: `cannot find -lfontconfig` o `-lfreetype`:**
   - *Causa:* Faltan dependencias de desarrollo de fuentes utilizadas por Slint.
   - *Solución:* Instalar `libfontconfig1-dev` y `libfreetype6-dev`.
2. **Error `Address already in use` (os error 10048 / 98):**
   - *Causa:* Una instancia previa de Kaska o de otra herramienta continúa escuchando en el puerto 8080 o 8989.
   - *Solución:* Identificar el proceso mediante `netstat -ano | findstr 8080` (Windows) o `ss -tulpn | grep 8080` (Linux) y terminarlo.
3. **Fallo de conexión a `localhost` en servidores IPv4-only:**
   - *Causa:* En Windows, `localhost` resuelve prioritariamente a `::1` (IPv6).
   - *Solución:* Kaska implementa resolución dual-stack con fallback automático a `127.0.0.1` si el listener es IPv4-only.
