# Kaska — Native Security & Network Inspection Platform

**Kaska** es una plataforma nativa de escritorio para auditoría de seguridad informática, inspección de tráfico de red e investigación técnica, desarrollada íntegramente en **Rust** con interfaz gráfica en **Slint**.

---

## 🎯 Visión y Principios del Producto

Kaska **no es un wrapper ni un frontend** de herramientas de terceros (Burp Suite, Nmap, ffuf, Gobuster, etc.). Es una **plataforma modular con capacidades nativas propias** escritas en Rust:

- **Network Inspector:** Inspección estructurada de solicitudes y respuestas HTTP/1.1 en tiempo real, análisis de cabeceras, cookies, cuerpos, estados de framing RFC 9112 y latencia.
- **Proxy de Captura y Streaming:** Motor proxy nativo con soporte de chunked transfer, desacoplamiento entre buffer de transmisión e inspección, y protección de alcance loopback.
- **Target Scope:** Control estricto pre y post-resolución DNS que confina el tráfico exclusivamente al laboratorio autorizado (`127.0.0.1`, `localhost`, `::1`).
- **Compositor Repeater:** Base para composición manual e inspección interactiva.
- **Herramientas de red nativas:** Diseñado para incorporar gradualmente descubrimiento de puertos, escaneo y fuzzing sin depender de binarios externos.

**Principios fundamentales:**
1. **100% Nativo:** Cero dependencias de Electron, NodeJS embebido o navegadores pesados.
2. **Cero Dependencia Externa:** No requiere tener instalado Burp, Nmap ni Python. Todo el motor corre en código Rust nativo compilado.
3. **Uso Ético y Ámbito Restringido:** Diseñado para laboratorios propios, educación en ciberseguridad, CTF y auditorías con autorización contractual.
4. **Open Source y Modular:** Desarrollado como proyecto personal abierto a contribuciones, organizado en un Cargo Workspace desacoplado.

---

## 🏗️ Arquitectura del Workspace

El proyecto está estructurado como un Cargo Workspace modular:

```text
Kaska/
├── crates/
│   ├── kaska-http/       # Motor HTTP, parser RFC 9112, proxy de streaming, store y test server
│   └── kaska-desktop/    # Aplicación binaria, ventana Slint, controller y bridge de UI
├── docs/                 # Documentación de arquitectura, módulos, desarrollo y ADRs
├── AGENTS.md             # Directivas operativas para agentes automatizados e IA
├── CONTRIBUTING.md       # Guía de contribución, GitFlow y Conventional Commits
└── SECURITY.md           # Política de seguridad y uso ético autorizado
```

---

## 📋 Requisitos de Sistema

### Entornos Soportados (x86_64)
- **Windows:** Windows 10 / 11 (MSVC x64 toolchain).
- **Linux:** Distribuciones modernas (Ubuntu, Fedora, Arch, Debian) con X11 o Wayland.

### Requisitos de Compilación
- **Rust:** Versión estable 1.85+ (probado con `rustc 1.95.0`).
- **Cargo:** Incluido en la instalación de Rust.
- **Dependencias del sistema (Linux para Slint):**
  ```bash
  sudo apt-get install -y libfontconfig1-dev libfreetype6-dev libx11-dev libx11-xcb-dev libxkbcommon-dev
  ```

---

## 🚀 Compilación y Ejecución

### 1. Compilación
```bash
# Compilación controlada con concurrencia acotada
cargo build --workspace --jobs 2
```

### 2. Ejecutar la Aplicación Desktop
```bash
# Ejecutar en modo desarrollo
cargo run -p kaska-desktop --jobs 2

# O ejecutar el binario release generado
./target/release/kaska-desktop
```

### 3. Prueba Headless de Captura Real (Modo Verificación / CI)
Kaska incluye un modo de verificación autónomo que arranca un servidor de pruebas controlado local, inicia el proxy nativo sobre sockets TCP reales, despacha transacciones HTTP y valida la captura sin necesidad de abrir entorno gráfico:
```bash
cargo run -p kaska-desktop --jobs 2 -- --headless-test
```

### 4. Ejecutar la Suite de Pruebas
```bash
cargo test --workspace --jobs 2 -- --test-threads=2
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --jobs 2 -- -D warnings
```

---

## ⚖️ Licenciamiento y Atribución

- **Kaska:** Desarrollado como proyecto de código abierto para educación y auditoría técnica. La selección de la licencia definitiva del repositorio (GPLv3 vs. modelo dual con permisiva) se encuentra documentada y pendiente de formalización.
- **Slint UI Toolkit:** Desarrollado por SixtyFPS GmbH (https://slint.dev). Kaska incluye con orgullo los créditos y cumple las condiciones de la Royalty-Free Desktop License y GPLv3.
