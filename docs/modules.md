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
| `repeater` | Cliente / Motor | `crates/kaska-http/src/repeater.rs`. Motor cliente de emisión directa `HttpRepeaterEngine`. Gestiona solicitudes HTTP/1.1 punto a punto hacia endpoints loopback autorizados (`127.0.0.1`, `localhost`, `[::1]`) sin transitar por el proxy. Implementa validación estricta de especificación (`RepeaterRequestSpec`), límites de seguridad para cabeceras (64 KiB), cuerpo saliente (1 MiB) y respuesta entrante (2 MiB), timeouts configurables, decodificación por máquina de estados de chunked transfer conforme a RFC 9112 y soporte para cancelación cooperativa vía `AtomicBool`. |
| `test_server` | Testing | Servidor HTTP controlado `ControlledTestServer` para validación y pruebas de integración locales sin dependencias de red externa. |

---

## 2. Crate: `kaska-desktop`

Aplicación ejecutable de escritorio que combina la interfaz gráfica Slint con el motor de red.

### Módulos:

| Módulo | Tipo | Responsabilidad y Contrato |
|---|---|---|
| `main` | Binario | Punto de entrada de la aplicación (`crates/kaska-desktop/src/main.rs`). Procesa argumentos de línea de comandos (e.g. `--headless-test`) e inicializa la ventana de Slint. |
| `controller` | Bridge / Orquestación | `crates/kaska-desktop/src/controller.rs`. `AppController` conecta los eventos y modelos de datos de Slint con los motores de red. Conecta el proxy y el Inspector con `SharedTrafficStore`, e integra `RepeaterTaskController` para coordinar el ciclo de vida de Repeater mediante los callbacks `on_send_repeater`, `on_cancel_repeater` y `on_reset_repeater_defaults`. |
| `repeater_adapter` | Adaptador / Tarea | `crates/kaska-desktop/src/repeater_adapter.rs`. Adaptador de UI y controlador de tareas Repeater (`RepeaterTaskController`, `RepeaterUiInput`, `RepeaterViewState`, `RepeaterLifecycle`, `RepeaterEvent`, `RepeaterAdapterError`). Gestiona la sanitización de inputs, control de ejecución single-flight (`AlreadyRunning`), cancelación cooperativa (`cancel_flag`), formateo seguro de previsualizaciones de respuesta (`format_response_body_preview`, límite defensivo de 64 KiB / 256 KiB, volcado hex/ASCII para cargas binarias) y publicación de eventos hacia el event loop de la UI. |
| `platform` | Sistema | Detección de sistema operativo (`crates/kaska-desktop/src/platform.rs`, `PlatformInfo`) para presentar información contextual en la barra de estado y ajustar cotas iniciales de ventana en Windows. |
| `ui/*` | Vista | Componentes declarativos en Slint (`crates/kaska-desktop/ui/*`): vistas para Network Inspector, panel de Scope, HTTP Repeater interactivo con editores de solicitud y visualizadores de respuesta, configuraciones y barra de estado. |

---

## 3. Concurrencia: Responsabilidades del Worker y Event Loop

- **Hilo Principal (Slint Event Loop):** El event loop de la interfaz de usuario se ejecuta exclusivamente en el hilo principal del sistema operativo. Es responsable del renderizado visual, el procesamiento de eventos de entrada y la gestión del foco por teclado. Ninguna operación de red, resolución DNS ni lectura/escritura de socket se ejecuta en este hilo.
- **Worker Threads de Red:**
  - **Proxy Server:** `NativeProxyServer` utiliza un hilo de escucha no bloqueante y despacha cada conexión entrante a un hilo de procesamiento independiente con timeouts estrictos (3000 ms).
  - **Repeater Worker:** `RepeaterTaskController` despacha cada solicitud hacia un hilo secundario nativo (`thread::Builder::spawn("kaska-repeater-worker")`). El worker ejecuta `HttpRepeaterEngine::execute()`, realizando la resolución DNS, conexión TCP y lectura de respuesta de forma totalmente aislada.
- **Sincronización hacia la UI:** Los resultados y eventos de ciclo de vida (`RepeaterEvent`) se comunican de vuelta al hilo de la UI de forma asíncrona y no bloqueante mediante callbacks thread-safe y `slint::invoke_from_event_loop`.

---

## 4. Aislamiento Funcional: Inspector vs. Repeater

Existe una separación estricta entre el tráfico capturado por el Inspector y las solicitudes emitidas por el Repeater:
- **Network Inspector (Captura pasiva del proxy):** Intercepta y analiza el tráfico HTTP/1.1 de clientes externos configurados para usar `NativeProxyServer`. Cada transacción procesada se almacena en `SharedTrafficStore` (`TrafficStore` circular en memoria), actualizando la lista virtual de transacciones para inspección histórica.
- **HTTP Repeater (Despacho activo directo):** Emite solicitudes HTTP/1.1 directas e independientes hacia endpoints loopback específicos mediante `HttpRepeaterEngine`. Estas solicitudes **no transitan por el proxy local ni se almacenan en `TrafficStore`**. Esto garantiza que las pruebas activas o repetidas no contaminen el historial de captura pasiva del Inspector.

---

## 5. Estrategia Futura de Ampliación

Kaska planea incorporar nuevas capacidades de seguridad en hitos posteriores (descubrimiento de redes, port scanning y fuzzing de rutas).

### Principio de diseño:
- **Modularidad sin sobre-ingeniería:** Las nuevas capacidades se incorporarán como nuevos crates especializados (ej. `crates/kaska-scanner`, `crates/kaska-fuzzer`) o como sub-módulos dentro de crates existentes cuando compartan dominio.
- **Sin plugins dinámicos prematuros:** No se introducirán sistemas complejos de carga dinámica de librerías (`dlopen`), IPCs innecesarios ni microservicios locales hasta que los módulos nativos se encuentren estabilizados y justifiquen dicha abstracción.
- **Contratos explícitos:** Cada nuevo módulo expondrá estructuras Rust bien tipadas, eventos a través de canales estándar (`std::sync::mpsc` o crossbeam si se justifica) y APIs no bloqueantes.
