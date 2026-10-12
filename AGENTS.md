# AGENTS.md — Directivas Operativas para Agentes Automatizados e IA en Kaska

Este documento establece las directivas obligatorias para cualquier agente de inteligencia artificial (o desarrollador automatizado) que opere en el repositorio de **Kaska**.

---

## 1. Principios y Jerarquía de Prioridades

Todo agente debe adherirse estrictamente a la siguiente jerarquía de decisiones:
```
Preservación del Código > Seguridad Operativa > Correctitud Técnica > Mantenibilidad > Rendimiento > Conveniencia
```

1. **No Destrucción:** Queda terminantemente prohibido ejecutar comandos destructivos (`git clean`, `git reset --hard`, `git stash drop`, force-pushes, borrados recursivos `rm -rf` o `Remove-Item -Recurse` no autorizados).
2. **Preservación de Archivos Untracked e Ignored:** No asumir que archivos sin seguimiento o ignorados son prescindibles. Directorios como `.agents/` o capturas de laboratorio deben preservarse.
3. **Un Solo Agente:** No invocar subagentes ni coordinar ejecuciones paralelas a menos que el usuario lo autorice expresamente.
4. **Cero Wrappers Externos:** Kaska implementa capacidades de seguridad nativas en Rust. No construir wrappers que invoquen binarios de terceros (Burp, Nmap, ffuf, etc.).

---

## 2. Reglas de Git y Control de Versiones

1. **GitFlow Local:**
   - `main`: Reservada exclusivamente para releases estables y verificadas.
   - `develop`: Rama principal de integración continua.
   - `feature/*`, `fix/*`, `refactor/*`, `docs/*`: Ramas de trabajo aisladas.
2. **Uso de Worktrees Aislados:** Las tareas de refactorización estructural o cambios de gran impacto deben desarrollarse en worktrees independientes (ej. `Kaska-cargo-workspace`), manteniendo intacto el checkout principal.
3. **Commits Convencionales (Conventional Commits):**
   - Formato: `<tipo>(<alcance>): <descripción corta en imperativo>`
   - Tipos válidos: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `perf`.
4. **Prohibición de Operaciones Remotas:**
   - No ejecutar `git push`, no configurar remotos no autorizados y no interactuar con APIs externas de GitHub sin aprobación explícita y previa del usuario.
5. **Detención antes del Commit:** Antes de realizar mutaciones de historial (`git commit`), el agente debe preparar el staging, verificar la integridad mediante `git diff --cached --check` y solicitar aprobación explícita si el hito así lo requiere.

---

## 3. Convenciones Rust y Estándares de Ingeniería

1. **Concurrencia de Compilación Controlada:**
   - Limitar siempre los jobs de compilación para no saturar el host:
     - En PowerShell: `$env:CARGO_BUILD_JOBS = '2'` o pasando `--jobs 2` a `cargo`.
2. **Formato y Calidad de Código:**
   - `cargo fmt --all --check`: Cero diferencias de formato.
   - `cargo clippy --workspace --all-targets --jobs 2 -- -D warnings`: Cero advertencias permitidas.
   - Prohibido silenciar advertencias de Clippy con `#[allow(...)]` globales injustificados.
3. **Reglas de Dependencias:**
   - `crates/kaska-http`: Motor HTTP, parser, proxy y store. **No debe depender de Slint ni de conceptos de UI.**
   - `crates/kaska-desktop`: Aplicación desktop binaria. Depende de `kaska-http` y `slint`.
   - Prohibidas dependencias circulares y frameworks de inyección dinámica innecesarios.

---

## 4. Pruebas y Validación Obligatoria

Antes de dar por concluida cualquier intervención:
1. Ejecutar la suite completa: `cargo test --workspace --jobs 2 -- --test-threads=2`.
2. Verificar que los tests unitarios y de integración pasen al 100%.
3. Ejecutar la verificación headless: `.\target\release\kaska-desktop.exe --headless-test`.
4. Verificar liberación de puertos: ningún socket listener debe quedar en estado `LISTENING` tras la ejecución de pruebas.

---

## 5. Seguridad del Sistema Operativo Host

1. Prohibido modificar configuraciones globales del sistema operativo (adaptadores de red, proxy del sistema de Windows, DNS, firewall, registro, controladores de audio o drivers).
2. Todas las pruebas de red deben utilizar servidores de prueba locales controlados sobre el rango loopback (`127.0.0.1`, `::1`) con puertos efímeros o dinámicos.
3. Prohibido escanear o enviar tráfico a redes o hosts externos no autorizados.
