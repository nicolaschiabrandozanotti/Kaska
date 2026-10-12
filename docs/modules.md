# Contratos y Módulos del Sistema — Kaska

Este documento describe las responsabilidades actuales de los crates y módulos que componen el workspace de **Kaska**, así como la estrategia de ampliación incremental hacia hitos futuros.

---

## 1. Crate: `kaska-http`

Biblioteca central que encapsula el protocolo HTTP, proxy de captura, servidor de pruebas y almacenamiento en memoria.

### Módulos:

| Módulo | Tipo | Responsabilidad y Contrato |
|---|---|---|
| `models` | Dominio | Estructuras de datos inmutables y serializables: `HttpRequest`, `HttpResponse`, `HttpHeader`, `HttpMethod`, `HttpTransaction` y `TransactionState`. |
| `parser` | Protocolo | Parser HTTP/1.1 cero-dependencias. Implementa `HttpParser` y la máquina de estados streaming `ChunkedTransferDecoder` conforme a RFC 9112 (soporta extensiones, trailers y fragmentación TCP). |
| `scope` | Seguridad | Contrato de control de alcance `AuditScope`. Valida nombres de host antes de resolverlos y filtra direcciones IP post-resolución restringiéndolas estrictamente a loopback (`127.0.0.0/8`, `::1`). |
| `proxy` | Red | Motor de interceptación y captura `NativeProxyServer`. Gestiona listeners no bloqueantes, resolución dual-stack, streaming incremental hacia el cliente, límite de 2 MB de inspección e inyección de `Connection: close`. |
| `store` | Estado | Cola en memoria thread-safe `TrafficStore` y `SharedTrafficStore` (`Arc<Mutex<TrafficStore>>`) con capacidad máxima acotada para evitar fugas de memoria. |
| `test_server` | Testing | Servidor HTTP controlado `ControlledTestServer` para validación y pruebas de integración locales sin dependencias de red externa. |

---

## 2. Crate: `kaska-desktop`

Aplicación ejecutable de escritorio que combina la interfaz gráfica Slint con el motor de red.

### Módulos:

| Módulo | Tipo | Responsabilidad y Contrato |
|---|---|---|
| `main` | Binario | Punto de entrada de la aplicación. Procesa argumentos de línea de comandos (e.g. `--headless-test`) e inicializa la ventana de Slint. |
| `controller` | Bridge | `AppController` conecta los eventos y modelos de datos de Slint con las llamadas asíncronas de `kaska-http`. Gestiona el ciclo de vida de los listeners del proxy y el servidor de pruebas. |
| `platform` | Sistema | Detección de sistema operativo (`PlatformInfo`) para presentar información contextual en la barra de estado. |
| `ui/*` | Vista | Componentes declarativos en Slint: vistas divididas para Network Inspector, panel de Scope, compositor preliminar de Repeater, configuraciones y barra de estado. |

---

## 3. Estrategia Futura de Ampliación

Kaska planea incorporar nuevas capacidades de seguridad en hitos posteriores (descubrimiento de redes, port scanning, fuzzing de rutas y compositor interactivo).

### Principio de diseño:
- **Modularidad sin sobre-ingeniería:** Las nuevas capacidades se incorporarán como nuevos crates especializados (ej. `crates/kaska-scanner`, `crates/kaska-fuzzer`) o como sub-módulos dentro de crates existentes cuando compartan dominio.
- **Sin plugins dinámicos prematuros:** No se introducirán sistemas complejos de carga dinámica de librerías (`dlopen`), IPCs innecesarios ni microservicios locales hasta que los módulos nativos se encuentren estabilizados y justifiquen dicha abstracción.
- **Contratos explícitos:** Cada nuevo módulo expondrá estructuras Rust bien tipadas, eventos a través de canales estándar (`std::sync::mpsc` o crossbeam si se justifica) y APIs no bloqueantes.
