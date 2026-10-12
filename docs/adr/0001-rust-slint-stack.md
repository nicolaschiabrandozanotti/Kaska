# ADR 0001: Selección del Stack Tecnológico Rust + Slint

## Estado
Aceptado

## Contexto
Kaska es una plataforma de escritorio para ciberseguridad, inspección de tráfico y herramientas de red multiplataforma (Windows y Linux). Se evaluaron diferentes alternativas de implementación:
- Electron / Web technologies: Alto consumo de memoria RAM (200-500 MB en reposo), latencia de rendering y complejidad para programación de bajo nivel de red.
- C++ / Qt: Alto rendimiento pero propenso a vulnerabilidades de memoria (buffer overflows, use-after-free) en el procesamiento de protocolos binarios y paquetes.
- Rust + Slint: Rendimiento nativo, seguridad de memoria garantizada en tiempo de compilación, huella de memoria reducida (<30 MB) y un lenguaje declarativo moderno para la interfaz gráfica.

## Decisión
Adoptar **Rust** como lenguaje de sistemas principal y **Slint** como toolkit de interfaz gráfica nativa.
- Todo el motor de red y pentesting se programa en Rust puro sin wrappers externos.
- Slint se compila a código nativo en tiempo de build mediante `slint-build`, sin navegadores embebidos ni webviews.

## Consecuencias
- **Positivas:**
  - Consumo mínimo de recursos en reposo.
  - Seguridad de memoria estricta al parsear cabeceras y streams HTTP complejos.
  - Binarios nativos autocontenidos para Windows y Linux.
- **Negativas / Desafíos:**
  - Requiere dependencias de sistema gráfico en Linux (`fontconfig`, `freetype`, `x11`/`wayland`).
  - La compilación inicial de Slint requiere recursos de CPU (mitigado limitando jobs a 2).
