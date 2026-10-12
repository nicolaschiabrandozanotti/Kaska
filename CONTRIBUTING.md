# Guía de Contribución a Kaska

¡Gracias por tu interés en contribuir a **Kaska**! Este documento detalla las directrices de arquitectura, flujo de trabajo Git y estándares de calidad para mantener la estabilidad del proyecto.

---

## 1. Código de Conducta y Alcance Ético

Kaska es una plataforma de ingeniería de seguridad y educación en ciberseguridad open source. Toda contribución debe alinearse con fines defensivos, educativos, de laboratorio controlado o auditorías estrictamente autorizadas.

---

## 2. Flujo de Trabajo Git (GitFlow Simplificado)

Operamos con dos ramas de larga duración y ramas de corta duración según el propósito del cambio:

- **`main`**: Rama de producción que contiene releases estables y verificadas.
- **`develop`**: Rama base para el desarrollo diario e integración de cambios.
- **Ramas de trabajo temporales (creadas siempre desde `develop`):**
  - `feature/<nombre>`: Nuevas capacidades y funcionalidades.
  - `fix/<nombre>`: Correcciones de bugs o anomalías.
  - `refactor/<nombre>`: Mejoras arquitectónicas o reorganización interna sin cambio funcional.
  - `docs/<nombre>`: Documentación, guías y ADRs.
  - `hotfix/<nombre>`: Correcciones críticas urgentes (creadas desde `main`).

---

## 3. Convención de Commits (Conventional Commits)

Todos los mensajes de commit deben seguir la especificación [Conventional Commits](https://www.conventionalcommits.org/):

```text
<tipo>(<alcance opcional>): <descripción concisa en imperativo>

[cuerpo explicativo opcional]

[notas de pie / referencias a issues opcionales]
```

### Tipos admitidos:
- **`feat`**: Nueva funcionalidad (ej. `feat(http): add streaming chunk parser`).
- **`fix`**: Corrección de un fallo (ej. `fix(proxy): handle dual-stack localhost resolution`).
- **`refactor`**: Refactorización de código sin alterar comportamiento.
- **`docs`**: Cambios exclusivos en documentación.
- **`test`**: Incorporación o corrección de pruebas automatizadas.
- **`chore`**: Tareas de mantenimiento, dependencias o herramientas.
- **`perf`**: Optimizaciones de rendimiento.

---

## 4. Requisitos y Configuración Local

- **Compilador:** Rust estable (versión 1.85+ recomendada, compatible con edición 2021).
- **Herramientas:** `rustfmt` y `clippy`.
- **Dependencias del sistema (Linux para compilar Slint):** Para compilar el workspace en Linux, se requieren las bibliotecas de desarrollo de Fontconfig, pkg-config y xkbcommon:
  ```bash
  sudo apt-get install -y --no-install-recommends pkg-config libfontconfig1-dev libxkbcommon-dev
  ```

---

## 5. Control de Recursos y Compilación

Para evitar saturar la CPU o la memoria durante compilaciones paralelas intensivas de crates y plantillas Slint, limite siempre los jobs simultáneos de Cargo:

```bash
# En bash / Linux:
CARGO_BUILD_JOBS=2 cargo build

# En PowerShell / Windows:
$env:CARGO_BUILD_JOBS = '2'; cargo build

# O pasando la opción directamente:
cargo build --jobs 2
```

---

## 6. Verificación Obligatoria Pre-Pull Request

Antes de enviar un Pull Request o proponer cambios, asegúrese de que todos los siguientes checks se ejecuten limpiamente sin errores ni advertencias:

1. **Formato de Código:**
   ```bash
   cargo fmt --all -- --check
   ```
2. **Análisis Estático (Clippy estricto):**
   ```bash
   cargo clippy --workspace --all-targets --jobs 2 -- -D warnings
   ```
3. **Suite Completa de Tests:**
   ```bash
   cargo test --workspace --locked --jobs 2 -- --test-threads=2
   ```
4. **Prueba Headless de la Aplicación:**
   ```bash
   cargo run -p kaska-desktop --jobs 2 -- --headless-test
   ```
5. **Comprobación de Whitespace en Git:**
   ```bash
   git diff --check
   ```

---

## 7. Proceso de Pull Request y Revisión de Código

1. Bifurque (fork) o cree una rama con el prefijo apropiado desde `develop`.
2. Mantenga los cambios atómicos, enfocados y acompañados de sus tests unitarios/integrales correspondientes.
3. No incluya archivos `.agents/`, binarios compilados en `target/`, capturas de tráfico `.pcap` ni credenciales privadas.
4. Abra el Pull Request apuntando a la rama `develop`.
5. Todos los checks de CI automatizados deben concluir en estado verde (PASS).
