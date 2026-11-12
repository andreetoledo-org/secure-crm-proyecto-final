# Hito 2 · Pipeline y ataque

Copien esta carpeta a `docs/hito-2/` del repositorio de su aplicación.
El workflow vive en `.github/workflows/`, no aquí: partan de
[`plantilla-pipeline/devsecops.yml`](../../../plantilla-pipeline/devsecops.yml).

## Pipeline

- Workflow: `.github/workflows/devsecops.yml`
- Corrida de evidencia (enlace a GitHub Actions):
- Modo del gate: `reporte` o `bloqueo`
- Umbral y por qué ese umbral (lo justifican los cuatro; el Equipo azul participa):

| Control | Herramienta | Umbral | Qué hicieron con los hallazgos |
|---|---|---|---|
| SAST | Semgrep |  |  |
| SCA |  |  |  |
| SBOM | Syft, CycloneDX | El artefacto `sbom.cdx.json` se publica |  |
| DAST | ZAP baseline, o paso manual |  |  |

*Instrucción: si el DAST no corre dentro del pipeline, escriban aquí por qué y
dónde está el reporte manual. Ese job es el control automático del grupo. La
sesión de ZAP y Burp del Equipo rojo va en la sección siguiente, y las dos se
entregan.*

## PoC del Equipo rojo

*Instrucción: mismo método del laboratorio DAST, con el WAF en DetectionOnly y
el proxy apuntando a `http://localhost:8080`. Primero ZAP (explorar, escanear y
guardar el reporte). Después Burp Repeater (petición y respuesta de cada
hallazgo). Luego OWASP Top 10:2025, CWE y el vector CVSS v3.1 completo.
Postman repite el PoC ya confirmado, con la hora anotada, para el Equipo azul.
Al menos tres vulnerabilidades de la app.*

- Reporte de ZAP (archivo en esta carpeta):

| ID | Vulnerabilidad | Dónde (método y ruta por :8080) | OWASP Top 10:2025 | CWE | Vector CVSS v3.1 | Puntaje |
|---|---|---|---|---|---|---|
| PoC-01 |  |  |  |  |  |  |
| PoC-02 |  |  |  |  |  |  |
| PoC-03 |  |  |  |  |  |  |

### PoC-01

- Alerta de ZAP (nombre y URL del reporte):
- Captura de Burp Repeater (petición y respuesta):
- Cómo repetirlo en Postman:
- Resultado observado:
- Justificación del CVSS, métrica por métrica:

### PoC-02

- Alerta de ZAP (nombre y URL del reporte):
- Captura de Burp Repeater (petición y respuesta):
- Cómo repetirlo en Postman:
- Resultado observado:
- Justificación del CVSS, métrica por métrica:

### PoC-03

- Alerta de ZAP (nombre y URL del reporte):
- Captura de Burp Repeater (petición y respuesta):
- Cómo repetirlo en Postman:
- Resultado observado:
- Justificación del CVSS, métrica por métrica:

## Registro de ataques

*Instrucción: una fila por intento, no solo por vulnerabilidad. Sirve para la
línea de tiempo del informe. Usen solo cuentas de prueba. En Herramienta
escriban ZAP, Burp o Postman según el intento. Cada vulnerabilidad lleva una
fila de ZAP, una de Burp y otra de la repetición en Postman.*

| Fecha | Hora | Quién | Herramienta | Método y ruta | Payload | Respuesta |
|---|---|---|---|---|---|---|
|  |  |  |  |  |  |  |
