# Sentinel — Native Security & Network Inspection Platform

**Sentinel** es una plataforma nativa de escritorio para auditoría de seguridad informática, inspección de tráfico e investigación técnica, desarrollada íntegramente en **Rust** con interfaz gráfica moderna en **Slint**.

---

## 🎯 Visión y Principios del Producto

Sentinel **no es un wrapper ni un frontend** de herramientas de terceros (Burp, Nmap, ffuf, etc.). Es una **plataforma con capacidades nativas propias** escritas en Rust, inspirada en las mejores prácticas de herramientas de la industria:
- **De Chrome DevTools Network & Burp HTTP History:** Inspección estructurada de solicitudes y respuestas HTTP en tiempo real, análisis de headers, cookies, parámetros y métricas de latencia.
- **De Burp Suite Repeater:** Motor nativo de composición manual y reenvío de solicitudes HTTP.
- **De Nmap & scanners:** Descubrimiento nativo de hosts, puertos y servicios en Rust (Hitos futuros).
- **De ffuf / Gobuster:** Fuzzing y descubrimiento de recursos con concurrencia nativa en Rust (Hitos futuros).

**Principios fundamentales:**
1. **100% Nativo:** Cero Electron, Chromium embebido o entornos web pesados.
2. **Cero Dependencia Externa:** No requiere tener instalado Burp, Nmap ni Python. Todo el motor corre en código Rust nativo compilado.
3. **Uso Ético y Ámbito Restringido:** Diseñado para laboratorios propios, educación en ciberseguridad, CTF y auditorías con autorización contractual. El alcance (*Target Scope*) se define explícitamente y bloquea tráfico no autorizado.
4. **Open Source y Libre:** Desarrollado como proyecto personal abierto a contribuciones de la comunidad.

---

## 📋 Requisitos de Sistema

### Entornos Soportados (x86_64)
- **Windows:** Windows 10 / 11 (MSVC x64 toolchain).
- **Linux:** Distribuciones modernas (Ubuntu, Fedora, Arch, Debian) con X11 o Wayland.

### Requisitos de Compilación
- **Rust:** Versión estable 1.80+ (probado con `rustc 1.95.0`).
- **Cargo:** Incluido en la instalación de Rust.

---

## 🚀 Compilación y Ejecución

### 1. Clonar y Compilar
```bash
git clone <repo-url>
cd adventurous-mendeleev
cargo build --release
```

### 2. Ejecutar la Aplicación Desktop
```bash
# Ejecutar en modo desarrollo
cargo run

# O ejecutar el binario release generado
./target/release/sentinel-desktop
```

### 3. Prueba de Captura HTTP Real (Modo Headless / CI)
Sentinel incluye un modo de prueba autónomo que arranca un servidor de prueba controlado local, levanta el proxy nativo sobre sockets TCP reales, envía tráfico HTTP real y verifica la captura sin necesidad de abrir la ventana gráfica:
```bash
cargo run -- --headless-test
```

### 4. Ejecutar la Suite Completa de Tests
```bash
cargo test
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

---

## 🔍 Funcionalidades del Hito 0 (Network Inspector)

1. **Proxy HTTP Nativo:**
   - Listener local en `127.0.0.1:8080`.
   - Intercepta y reenvía tráfico HTTP/1.1 entre clientes locales y destinos dentro del alcance.
2. **Servidor de Pruebas Controlado:**
   - Servidor local en `127.0.0.1:8989` con endpoints `/api/status`, `/api/echo`, `/auth/login` y `/admin/restricted`.
   - Botón directo en la barra superior: **"⚡ Test Local Capture"** para generar tráfico HTTP real y ver su captura inmediata en vivo.
3. **Network Inspector (Tabla y Panel Dividido):**
   - Tabla reactiva con columnas: `#`, `Method`, `Status`, `Host`, `Path`, `Latency (ms)`, `Size (bytes)`, `Content-Type`.
   - Selección de filas con visor detallado de:
     - Headers crudos de la solicitud.
     - Payload del cuerpo de la solicitud.
     - Headers crudos de la respuesta.
     - Payload del cuerpo de la respuesta.
     - Métrica de latencia y estado.
4. **Target Scope:**
   - Reglas de alcance configurables (`127.0.0.1`, `localhost`, etc.) para prevenir fugas accidentales de tráfico fuera del laboratorio.
5. **Base Arquitectónica del Repeater:**
   - Pestaña de compositor manual de solicitudes lista para incorporar el replay interactivo en el Hito 1.
6. **Acerca de y Licencias:**
   - Reconocimiento explícito del toolkit Slint (Royalty-Free Desktop License y GPLv3).

---

## ⚖️ Licenciamiento y Atribución

- **Sentinel Core & UI:** Preparado para distribución Open Source libre bajo **GNU GPLv3** (o arquitectura dual con librerías base en MIT/Apache-2.0).
- **Slint UI Toolkit:** Desarrollado por SixtyFPS GmbH (https://slint.dev). Sentinel muestra con orgullo la atribución correspondiente en cumplimiento con la Royalty-Free Desktop License y GPLv3.
