# Arquitectura del Sistema — Kaska

## 1. Visión General del Sistema

**Kaska** es una plataforma de análisis de seguridad e inspección de red modular estructurada en **Rust** con interfaz nativa **Slint**. Está diseñada bajo el principio de separación estricta entre motores de red headless y la interfaz gráfica de usuario.

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                              kaska-desktop                              │
│  ┌─────────────────────────────┐       ┌─────────────────────────────┐  │
│  │       Slint UI Views        │       │        AppController        │  │
│  │(Inspector, Repeater, Scope) │◄──────┤       (UI/Task Bridge)      │  │
│  └─────────────────────────────┘       └──────────────┬──────────────┘  │
│                                                       │                 │
│                                        ┌──────────────▼──────────────┐  │
│                                        │   RepeaterTaskController    │  │
│                                        │ (Single-Flight/Preview/Task)│  │
│                                        └──────────────┬──────────────┘  │
└───────────────────────────────────────────────────────┼─────────────────┘
                                                        │ Depende de
┌───────────────────────────────────────────────────────▼─────────────────┐
│                               kaska-http                                │
│  ┌─────────────────────────────┐       ┌─────────────────────────────┐  │
│  │      NativeProxyServer      │──────►│        TrafficStore         │  │
│  │   (Proxy Capture/Streaming) │       │(In-Memory Circular / Ephem) │  │
│  └──────────────┬──────────────┘       └─────────────────────────────┘  │
│                 │                                                       │
│  ┌──────────────▼──────────────┐       ┌─────────────────────────────┐  │
│  │         HttpParser          │       │     HttpRepeaterEngine      │  │
│  │    (RFC 9112 / Chunked)     │       │  (Direct Loopback Dispatch) │  │
│  └─────────────────────────────┘       └──────────────┬──────────────┘  │
│                                                       │                 │
│                                        ┌──────────────▼──────────────┐  │
│                                        │         AuditScope          │  │
│                                        │    (Loopback IP Filter)     │  │
│                                        └─────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Dirección de Dependencias y Reglas de Modularización

1. **Aislamiento de `kaska-http`:**
   - Cero dependencias de GUI o Slint.
   - Es una biblioteca pura de networking y protocolo HTTP/1.1 que puede utilizarse en entornos headless, herramientas CLI o servidores independientes. Sus dependencias directas en runtime se limitan a utilidades estándar del ecosistema Rust (`thiserror` para modelado tipado de errores y `regex`), manteniendo cero dependencias de frameworks gráficos o de interfaz.
2. **`kaska-desktop` como orquestador:**
   - Contiene el punto de entrada binario (`main.rs`), la ventana principal de Slint y el controlador reactivo.
   - Consume `kaska-http` exclusivamente a través de sus contratos públicos (`NativeProxyServer`, `AuditScope`, `SharedTrafficStore`, `HttpTransaction`, `HttpRepeaterEngine`, `RepeaterConfig`, `RepeaterRequestSpec`, `RepeaterExecutionResult`, `RepeaterError`).
3. **Cero Dependencias Circulares:** Las dependencias fluyen estrictamente desde la UI hacia los motores.
4. **Validación Multiplataforma y CI:** El motor `kaska-http` es 100% independiente de plataforma y compila de forma idéntica en Windows y Linux. `kaska-desktop` incluye modo `--headless-test` ejecutable en pipelines de CI sin requerir servidor gráfico X11/Wayland.

---

## 3. Concurrencia y Flujo Slint ↔ Rust

- **Event Loop no bloqueante:** La interfaz de usuario Slint corre exclusivamente en el hilo principal del sistema operativo. Ninguna operación de E/S de red (conexiones TCP, resolución DNS, lectura o escritura de sockets) se ejecuta en el hilo de la UI.
- **Worker Threads del Proxy:**
  - `NativeProxyServer::start()` instancia un hilo de escucha con `TcpListener` en modo no bloqueante (`set_nonblocking(true)`).
  - Cada conexión de cliente aceptada se despacha a un hilo de procesamiento independiente (`thread::spawn`) con timeouts estrictos de lectura y escritura (3000 ms).
  - Las transacciones capturadas se almacenan en un `SharedTrafficStore` (`Arc<Mutex<TrafficStore>>`) y opcionalmente notifican a la UI mediante un callback thread-safe que programa actualizaciones vía `slint::invoke_from_event_loop`.
- **Worker Thread y Despacho del Repeater:**
  - Cada solicitud interactiva del Repeater se despacha a un hilo de trabajo dedicado (`thread::Builder::spawn`), garantizando aislamiento total del event loop.
  - **Single-Flight Execution:** `RepeaterTaskController` asegura que solo una petición esté en vuelo a la vez mediante control de concurrencia atómico. Solicitudes concurrentes son rechazadas inmediatamente con `RepeaterAdapterError::AlreadyRunning`.
  - **Cancelación Cooperativa:** `cancel_active` solicita la cancelación mediante una bandera atómica (`cancel_flag: Arc<AtomicBool>`) evaluada periódicamente entre operaciones de E/S. El intervalo base está determinado por `DEFAULT_IO_SLICE_TIMEOUT_MS = 50 ms` (valor predeterminado configurable), pero este no representa una garantía máxima de latencia total de cancelación: la confirmación terminal depende de la observación efectiva de la bandera por el worker en el siguiente slice de lectura/escritura o verificación de deadline, y la fase inicial de conexión TCP o la resolución pueden introducir demoras superiores a dicho intervalo. La cancelación no produce una interrupción instantánea del I/O: la solicitud pasa en la UI por el estado transitorio `Cancelling` y el socket se aborta cuando el worker comprueba la bandera, alcanzando la confirmación terminal `Cancelled`.
  - **Aislamiento de Store:** El tráfico emitido por el Repeater viaja directamente al endpoint loopback de destino; no transita por `NativeProxyServer` ni interactúa con `TrafficStore`, impidiendo la contaminación del historial de auditoría.

---

## 4. Gestión de Memoria y Prevención de OOM

- **Desacoplamiento de Transmisión vs. Inspección en el Proxy:**
  - En solicitudes y respuestas con streaming o payloads extensos en el proxy, los bytes leídos de upstream se transmiten incrementalmente al socket del cliente con `client.write_all()` y `client.flush()` a medida que van llegando.
  - *Condición de entrega:* La transmisión completa hacia el cliente depende de la integridad de la conexión TCP: si el cliente aborta, se desconecta anticipadamente o falla el upstream, la transmisión se interrumpe y se genera el error de E/S correspondiente, sin que pueda afirmarse una entrega íntegra del cuerpo bajo condiciones de fallo o desconexión del cliente.
  - El buffer de almacenamiento para inspección (`inspected_body`) tiene un tope de seguridad estricto de **2 MB** (`MAX_INSPECTION_BODY_SIZE`). Si una respuesta excede 2 MB, el streaming hacia el cliente continúa de forma transparente mientras el socket permanezca abierto, pero la memoria de inspección no satura la aplicación.
- **Almacenamiento Efímero en Memoria (`TrafficStore`):**
  - `TrafficStore` es exclusivamente una estructura en memoria circular (`VecDeque`), no persistente, protegida mediante `Arc<Mutex<TrafficStore>>`.
  - **No constituye almacenamiento persistente ni base de datos en disco:** todas las transacciones son volátiles y se destruyen al cerrar la aplicación o reiniciar el servicio.
  - Posee una capacidad máxima configurable (10.000 transacciones por defecto). Al alcanzar el tope, las transacciones más antiguas son desalojadas automáticamente de la memoria.
- **Límites de Previsualización en la UI (Repeater):**
  - Para evitar que cuerpos de respuesta extensos saturen la memoria del event loop de Slint, la capa de escritorio impone un presupuesto de preview de 64 KiB y un límite defensivo de 256 KiB (`MAX_PREVIEW_LIMIT_BYTES`), independiente del límite de 2 MB del motor HTTP.
  - Las cargas con bytes nulos o caracteres de control se formatean automáticamente como volcados hex/ASCII seguros. Se activan indicadores explícitos (`http-truncated`, `preview-truncated`) al alcanzar las cotas de motor o de UI.

---

## 5. Ciclo de Vida y Control de Estado

- **Ciclo de Vida del Proxy:**
  - **Arranque:** `proxy.start()` enlaza el socket `TcpListener` local en `127.0.0.1:port` y establece la bandera atómica `running = true` (`AtomicBool` con `Ordering::SeqCst`).
  - **Detención:** `proxy.stop()` establece `running = false`. El hilo de aceptación detecta el cambio en su siguiente ciclo no bloqueante (intervalos de 20 ms) y finaliza, liberando el socket y permitiendo re-enlazar el puerto inmediatamente sin bloqueos.
  - **Manejo de Errores HTTP:** Destinos fuera de alcance reciben `403 Forbidden`, dominios no resolubles reciben `502 Bad Gateway`, y peticiones `CONNECT` reciben `501 Not Implemented`.
- **Ciclo de Vida del Repeater:**
  - El motor coordina cinco fases de ciclo de vida tipadas en `RepeaterLifecycle` (`Idle`, `Running`, `Completed`, `Failed`, `Cancelled`).
  - La interfaz gráfica modela adicionalmente un estado transitorio `Cancelling` (`repeater_is_cancelling = true`) mientras espera la confirmación de detención por parte del worker cooperativo.
