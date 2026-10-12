# Política de Seguridad de Kaska

## 1. Alcance y Uso Ético Autorizado

**Kaska** es una plataforma de análisis de seguridad, inspección de red y pentesting concebida exclusivamente para:

- Educación en ciberseguridad e investigación técnica.
- Laboratorios de pruebas propios y entornos locales controlados.
- Competencias CTF (Capture The Flag).
- Evaluaciones y auditorías de seguridad debidamente autorizadas por escrito.

Queda estrictamente prohibido utilizar Kaska contra sistemas, redes o infraestructura de terceros sin consentimiento explícito y autorización legal previa.

---

## 2. Reporte Responsable de Vulnerabilidades del Proyecto

Nos tomamos con máxima seriedad la seguridad del propio código de Kaska, su proxy de interceptación y sus motores nativos.

Si descubres una posible vulnerabilidad de seguridad en Kaska (por ejemplo, desincronización de requests HTTP, vulnerabilidad de bypass en el control de scope, fuga de descriptores o condiciones de carrera):

1. **No abras un Issue público en GitHub** con detalles del exploit o vulnerabilidad.
2. Utiliza la funcionalidad de **GitHub Security Advisories** del repositorio oficial (`https://github.com/nicolaschiabrandozanotti/Kaska/security/advisories`) para enviar un reporte privado.
3. Proporciona una descripción técnica detallada, pasos para reproducir el fallo y, si es posible, una prueba de concepto mínima en un entorno local.
4. El equipo revisará el reporte, evaluará el impacto y coordinará la corrección y publicación de un parche de forma responsable.

---

## 3. Versiones con Soporte de Seguridad

Actualmente, el proyecto se encuentra en fase de desarrollo activo pre-1.0. Se garantiza soporte y correcciones prioritarias de seguridad únicamente sobre el commit más reciente de la rama `main` y la última versión etiquetada.
