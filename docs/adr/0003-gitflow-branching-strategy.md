# ADR 0003: Estrategia de Ramificación GitFlow Simplificada

## Estado
Aceptado

## Contexto
Kaska es un proyecto open source concebido para recibir contribuciones futuras y mantener lanzamientos estables verificables. Trabajar directamente sobre la rama principal `master` o `main` sin aislamiento impedía congelar baselines estables y facilitaba regresiones accidentales.

## Decisión
Adoptar un modelo de ramas GitFlow simplificado con las siguientes directrices:
- `main`: Rama de releases estables. Cada merge en `main` debe corresponder a una versión etiquetada y validada en su totalidad.
- `develop`: Rama de integración activa y baseline para nuevas características.
- Ramas efímeras con prefijo:
  - `feature/*`: Nuevas capacidades funcionales.
  - `fix/*`: Correcciones de bugs.
  - `refactor/*`: Reestructuración y mejoras internas.
  - `docs/*`: Documentación y ADRs.
  - `hotfix/*`: Parches críticos hacia `main`.
- Toda integración hacia `develop` o `main` se realiza mediante Pull Requests con validación de CI previa.

## Consecuencias
- **Positivas:**
  - Separación clara entre código estable probado y desarrollo activo.
  - Trazabilidad y gobernanza transparentes para contribuyentes externos.
- **Negativas:**
  - Requiere disciplina para sincronizar `develop` con `main` y gestionar ramas efímeras.
