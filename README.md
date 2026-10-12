# Kaska — Native Security & Network Inspection Platform

**Kaska** es una plataforma nativa de escritorio para auditoría de seguridad informática, inspección de tráfico de red e investigación técnica, desarrollada íntegramente en **Rust** con interfaz gráfica en **Slint**.

---

## 🎯 Visión y Principios del Producto

Kaska **no es un wrapper ni un frontend** de herramientas de terceros (Burp Suite, Nmap, ffuf, Gobuster, etc.). Es una **plataforma modular con capacidades nativas propias** escritas en Rust:

- **Network Inspector:** Inspección estructurada de solicitudes y respuestas HTTP/1.1 en tiempo real, análisis de cabeceras, cookies, cuerpos, estados de framing RFC 9112 y latencia.
- **Proxy de Captura y Streaming:** Motor proxy nativo con soporte de chunked transfer, desacoplamiento entre buffer de transmisión e inspección, y protección de alcance loopback.
- **Target Scope:** Control estricto pre y post-resolución DNS que confina el tráfico exclusivamente al laboratorio autorizado (`127.0.0.1`, `localhost`, `::1`).
- **Compositor Repeater (Preliminar):** Vista de composición manual e inspección en interfaz gráfica (actualmente en estado de compositor preliminar de UI; el despacho activo de solicitudes de red desde Repeater se implementará en hitos posteriores).
- **Herramientas de red nativas:** Arquitectura preparada para incorporar gradualmente capacidades adicionales sin depender de binarios externos.

### ⚠️ Estado Actual del Proyecto (Experimental / Pre-1.0)
Kaska se encuentra en **desarrollo activo y estado experimental**:
- **Alcance actual:** Centrado exclusivamente en captura, streaming e inspección de tráfico **HTTP/1.1 local/loopback controlado** (`127.0.0.1`, `localhost`, `::1`).
- **HTTPS / TLS MITM:** **No implementado todavía.** Las solicitudes `CONNECT` reciben respuesta explícita `501 Not Implemented`.
- **Repeater:** Actualmente opera como **compositor preliminar de UI** sin despacho de red activo.

**Principios fundamentales:**
1. **100% Nativo:** Cero dependencias de Electron, NodeJS embebido o navegadores pesados.
2. **Cero Dependencia Externa:** No requiere tener instalado Burp, Nmap ni Python. Todo el motor corre en código Rust nativo compilado.
3. **Uso Ético y Ámbito Restringido:** Diseñado para laboratorios propios, educación en ciberseguridad, CTF y auditorías con autorización contractual.
4. **Open Source y Modular:** Desarrollado como proyecto abierto a la comunidad bajo licencia dual permisiva (`MIT OR Apache-2.0`), organizado en un Cargo Workspace desacoplado.

---

## 🏗️ Arquitectura del Workspace

El proyecto está estructurado como un Cargo Workspace modular:

```text
Kaska/
├── crates/
│   ├── kaska-http/              # Motor HTTP, parser RFC 9112, proxy de streaming, store y test server
│   └── kaska-desktop/           # Aplicación binaria, ventana Slint, controller y bridge de UI
├── docs/                        # Documentación de arquitectura, módulos, desarrollo y ADRs
├── AGENTS.md                    # Directivas operativas para agentes automatizados e IA
├── CONTRIBUTING.md              # Guía de contribución, GitFlow y Conventional Commits
├── SECURITY.md                  # Política de seguridad y uso ético autorizado
├── THIRD_PARTY_NOTICES.md       # Avisos de terceros y atribuciones de licencias
├── LICENSE-MIT                  # Texto completo de la licencia MIT
└── LICENSE-APACHE               # Texto completo de la licencia Apache 2.0
```

---

## 📋 Requisitos de Sistema

### Entornos Soportados (x86_64)
- **Windows:** Windows 10 / 11 (MSVC x64 toolchain).
- **Linux:** Distribuciones modernas (Ubuntu, Fedora, Arch, Debian) con X11 o Wayland.

### Requisitos de Compilación
- **Rust:** Versión estable 1.85+ (probado con `rustc 1.95.0`).
- **Cargo:** Incluido en la instalación de Rust.
- **Dependencias del sistema (Linux para compilación de Slint):**
  ```bash
  sudo apt-get install -y --no-install-recommends pkg-config libfontconfig1-dev libxkbcommon-dev
  ```
  *(Nota: Para ejecutar la interfaz gráfica interactiva en Linux se requiere un servidor X11 o Wayland activo; el modo headless `--headless-test` no requiere display en runtime).*

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
cargo test --workspace --locked --jobs 2 -- --test-threads=2
cargo fmt --all --check
cargo clippy --workspace --all-targets --jobs 2 -- -D warnings
```

---

## ⚖️ Licencia

El código fuente original de **Kaska** se distribuye bajo licencia dual, a tu elección:

- **MIT License** ([LICENSE-MIT](LICENSE-MIT) o https://choosealicense.com/licenses/mit/)
- **Apache License, Version 2.0** ([LICENSE-APACHE](LICENSE-APACHE) o https://choosealicense.com/licenses/apache-2.0/)

Salvo que se indique explícitamente lo contrario, cualquier contribución enviada intencionalmente para su inclusión en Kaska se licenciará bajo los mismos términos duales (`MIT OR Apache-2.0`), sin condiciones adicionales.

Consulta [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) para el detalle de licencias de componentes de terceros.

---

## 🖥️ Atribución de Interfaz Gráfica (Slint UI) y Terceros

La interfaz gráfica de escritorio de `kaska-desktop` está construida con [**Slint**](https://slint.dev), un toolkit declarativo de interfaz de usuario desarrollado por **SixtyFPS GmbH**.

- Sitio oficial de Slint: [https://slint.dev](https://slint.dev)
- Términos y licencias de Slint: [https://slint.dev/terms-and-conditions](https://slint.dev/terms-and-conditions)

**Aviso legal sobre Slint:**
- Slint mantiene sus propias licencias (*Slint Royalty-Free Desktop License 2.0*, *GPLv3* o *Comercial*) y derechos de autor (Copyright © SixtyFPS GmbH). Kaska no relicencia Slint ni otros componentes de terceros.
- Para el uso desktop no-GPL de Slint en `kaska-desktop`, el proyecto se acoge a la modalidad **Slint Royalty-Free Desktop License 2.0**, cumpliendo sus condiciones oficiales de atribución pública.
- **Kaska es un proyecto independiente y no está afiliado, respaldado ni patrocinado por SixtyFPS GmbH ni por Slint.**
- *Nota para futuras distribuciones de binarios:* Antes de publicar ejecutables precompilados, se deberá mantener esta atribución oficial visible o integrar el componente `AboutSlint` en la interfaz gráfica conforme a los términos de la licencia Royalty-Free Desktop de Slint.
