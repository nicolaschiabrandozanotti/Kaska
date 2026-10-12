# ADR 0002: Modularización en Cargo Workspace

## Estado
Aceptado

## Contexto
El código inicial de Kaska se desarrolló como un único crate monolítico donde `src/lib.rs` y `src/main.rs` duplicaban la declaración de módulos. Esto ocasionaba:
1. Compilación redundante de tests (los 11 tests unitarios se ejecutaban dos veces).
2. Acoplamiento entre el código del motor HTTP y el toolkit Slint.
3. Imposibilidad de reutilizar el motor HTTP en modo headless o CLI sin arrastrar la dependencia de la interfaz gráfica.

## Decisión
Migrar la estructura del proyecto a un **Virtual Cargo Workspace**:
- `crates/kaska-http`: Biblioteca autónoma que contiene los modelos HTTP, el parser streaming RFC 9112, el proxy local, el control de alcance loopback y el servidor de pruebas. Cero dependencias de Slint.
- `crates/kaska-desktop`: Aplicación ejecutable que depende de `kaska-http` y `slint`, encapsulando las plantillas `.slint`, el controlador de UI y el punto de entrada.
- `crates/kaska-core`: Se pospone su creación hasta que surjan conceptos transversales compartidos reales entre futuros módulos de seguridad (evitando crates vacíos o abstracciones sin consumidores).

## Consecuencias
- **Positivas:**
  - El motor HTTP es testeable y reusable de forma 100% headless.
  - Se elimina la doble compilación de tests: los 28 tests se ejecutan una única vez.
  - Tiempos de compilación incremental más rápidos.
- **Negativas:**
  - Requiere mantener múltiples manifests `Cargo.toml`.
