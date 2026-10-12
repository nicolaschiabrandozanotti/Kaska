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
> **Estado de verificación de plataformas y CI:**
> - **Tests locales Windows:** Verificados al 100% en host Windows x86_64.
> - **CI Windows / Linux (GitHub Actions):** Flujo definido en `.github/workflows/ci.yml`, pendiente de primera ejecución remota real en runners.
> - **Validación Semántica `actionlint`:** GitHub Actions no ejecuta `actionlint` por defecto; el gate semántico de `actionlint` permanece **PENDING** hasta que se ejecute explícitamente en un entorno que disponga de la herramienta.
> - **Soporte visual Slint en Linux:** Pendiente de comprobación funcional interactiva sobre sesión de escritorio Linux real.
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

```bash
# 1. Ejecutar todos los tests unitarios y de integración con hilos acotados y lockfile estricto
cargo test --workspace --locked --jobs 2 -- --test-threads=2

# 2. Verificar formato con rustfmt
cargo fmt --all -- --check

# 3. Análisis de linter estricto con Clippy
cargo clippy --workspace --all-targets --jobs 2 -- -D warnings
```

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
