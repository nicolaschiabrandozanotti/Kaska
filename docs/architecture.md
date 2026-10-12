# Arquitectura del Sistema — Kaska

## 1. Visión General del Sistema

**Kaska** es una plataforma de análisis de seguridad e inspección de red modular estructurada en **Rust** con interfaz nativa **Slint**. Está diseñada bajo el principio de separación estricta entre motores de red headless y la interfaz gráfica de usuario.

```text
┌─────────────────────────────────────────────────────────┐
│                     kaska-desktop                       │
│  ┌───────────────────────┐   ┌───────────────────────┐  │
│  │   Slint UI Views      │   │     AppController     │  │
│  │  (Inspector, Scope)   │◄──┤    (UI Bridge/Task)   │  │
│  └───────────────────────┘   └───────────┬───────────┘  │
└──────────────────────────────────────────┼──────────────┘
                                           │ Depende de
┌──────────────────────────────────────────▼──────────────┐
│                       kaska-http                        │
│  ┌───────────────────────┐   ┌───────────────────────┐  │
│  │   NativeProxyServer   │──►│     TrafficStore      │  │
│  │  (Streaming/Loopback) │   │ (In-Memory Circular)  │  │
│  └───────────┬───────────┘   └───────────────────────┘  │
│              │                                          │
│  ┌───────────▼───────────┐   ┌───────────────────────┐  │
│  │      HttpParser       │   │      AuditScope       │  │
│  │ (RFC 9112 / Chunked)  │   │  (Loopback IP Filter) │  │
│  └───────────────────────┘   └───────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

---

## 2. Dirección de Dependencias y Reglas de Modularización

1. **Aislamiento de `kaska-http`:**
   - Cero dependencias de GUI o Slint.
   - Es una biblioteca pura de networking y protocolo HTTP/1.1 que puede utilizarse en entornos headless, herramientas CLI o servidores independientes. Sus dependencias directas en runtime se limitan a utilidades estándar del ecosistema Rust (`thiserror` para modelado tipado de errores y `regex`), manteniendo cero dependencias de frameworks gráficos o de interfaz.
2. **`kaska-desktop` como orquestador:**
   - Contiene el punto de entrada binario (`main.rs`), la ventana principal de Slint y el controlador reactivo.
   - Consume `kaska-http` a través de sus contratos públicos (`NativeProxyServer`, `AuditScope`, `SharedTrafficStore`, `HttpTransaction`).
3. **Cero Dependencias Circulares:** Las dependencias fluyen estrictamente desde la UI hacia los motores.
4. **Validación Multiplataforma y CI:** El motor `kaska-http` es 100% independiente de plataforma y compila de forma idéntica en Windows y Linux. `kaska-desktop` incluye modo `--headless-test` ejecutable en pipelines de CI sin requerir servidor gráfico X11/Wayland.

---

## 3. Concurrencia y Flujo Slint ↔ Rust

- **Event Loop no bloqueante:** La interfaz de usuario Slint corre en el hilo principal del sistema operativo. Ninguna operación de E/S de red (conexiones TCP, resolución DNS, lectura de sockets) se ejecuta en el hilo de la UI.
- **Worker Threads del Proxy:**
  - `NativeProxyServer::start()` instancia un hilo de escucha con `TcpListener` en modo no bloqueante (`set_nonblocking(true)`).
  - Cada conexión de cliente aceptada se despacha a un hilo de procesamiento independiente (`thread::spawn`) con timeouts estrictos de lectura y escritura (3000 ms).
- **Comunicación hacia la UI:**
  - Las transacciones capturadas se almacenan en un `SharedTrafficStore` (`Arc<Mutex<TrafficStore>>`).
  - Opcionalmente, se invoca un callback thread-safe `OnTransactionCallback` (`Arc<dyn Fn(HttpTransaction) + Send + Sync>`) que encola eventos para actualizar el modelo de la UI de Slint mediante `slint::invoke_from_event_loop`.

---

## 4. Gestión de Memoria y Prevención de OOM

- **Desacoplamiento de Transmisión vs. Inspección:**
  - En solicitudes y respuestas con streaming o payloads extensos, los bytes leídos de upstream se transmiten **inmediatamente** al socket del cliente con `client.write_all()` y `client.flush()`.
  - El buffer de almacenamiento para inspección (`inspected_body`) tiene un tope de seguridad estricto de **2 MB** (`MAX_INSPECTION_BODY_SIZE`). Si una respuesta excede 2 MB, el cliente recibe el 100% del archivo sin cortes, pero la memoria interna no satura la aplicación.
- **Límite de Retención de Historial:**
  - `TrafficStore` implementa una cola circular basada en `VecDeque` con capacidad máxima configurable (10.000 transacciones por defecto). Al alcanzar el tope, las transacciones más antiguas se desalojan de la memoria automáticamente.

---

## 5. Ciclo de Vida del Proxy y Control de Estado

- **Arranque:** `proxy.start()` enlaza el socket `TcpListener` local en `127.0.0.1:port` y establece la bandera atómica `running = true` (`AtomicBool` con `Ordering::SeqCst`).
- **Detención:** `proxy.stop()` establece `running = false`. El hilo de aceptación detecta el cambio en su siguiente ciclo no bloqueante (intervalos de 20 ms) y finaliza, liberando el socket y permitiendo re-enlazar el puerto inmediatamente sin bloqueos.
- **Manejo de Errores HTTP:** Destinos fuera de alcance reciben `403 Forbidden`, dominios no resolubles reciben `502 Bad Gateway`, y peticiones `CONNECT` reciben `501 Not Implemented`.
