# Hito 2 · Pipeline DevSecOps y Ataque (Red Team & Todo el Grupo)

## 1. Pipeline DevSecOps (Todo el Grupo + Umbral del Equipo Azul)

- **Workflow en el repositorio:** [`.github/workflows/devsecops.yml`](../../.github/workflows/devsecops.yml)
- **Corridas de evidencia en GitHub Actions:**
  - Corrida #1 (Hito 0 / Línea base inicial): <https://github.com/andreetoledo-org/secure-crm-proyecto-final/actions/runs/43130971368> (`Success` — 4 jobs completados y 4 artefactos publicados: `semgrep`, `sca`, `sbom.cdx.json`, `zap`).
- **Modo inicial del Security Gate:** `SECURITY_GATE: "reporte"`

### Justificación de los Umbrales del Security Gate (Equipo Azul y Grupo)

El pipeline se ejecuta automáticamente en cada `push`, `pull_request` y `workflow_dispatch`, integrando los **4 controles automatizados del SSDLC** (`SAST`, `SCA`, `SBOM` y `DAST`).

1. **Por qué inicia en modo `reporte` (`SECURITY_GATE: "reporte"`):**
   - La rama `main` de **Secure CRM** es **intencionalmente vulnerable** durante los Hitos 1, 2 y 3 para permitir que el **Equipo Rojo** ejecute sus pruebas de penetración (ZAP, Burp Suite y Postman) a través del WAF y que el **Equipo Azul** construya y calibre las reglas de detección en Kibana.
   - Si el gate estuviera en modo `bloqueo` desde el inicio, los pasos de verificación fallarían en cada push debido a los hallazgos plantados en la aplicación base. Con `continue-on-error: ${{ env.SECURITY_GATE != 'bloqueo' }}`, el pipeline ejecuta las evaluaciones del gate, imprime el conteo exacto de violaciones en el log y publica siempre los 4 artefactos (`if: always()`), reservando el fallo del workflow para cuando una herramienta no pueda ejecutarse o cuando se active `SECURITY_GATE: "bloqueo"` tras la remediación.
2. **Justificación técnica de cada umbral definido en `.github/workflows/devsecops.yml`:**
   - **SAST (Semgrep) → Umbral: `0` hallazgos de severidad `ERROR` (`--severity ERROR --error`):**
     - Las reglas de severidad `ERROR` en los rulesets `p/default` y `p/owasp-top-ten` corresponden a vulnerabilidades explotables de alta confianza en el código fuente o infraestructura (como contenedores corriendo como `root` o uso de primitivas criptográficas rotas como `MD5` para contraseñas). Las advertencias informativas o de estilo (`INFO`/`WARNING`) se conservan en el reporte `semgrep.sarif` para revisión sin bloquear despliegues por falsos positivos menores.
   - **SCA (`pnpm audit`) → Umbral: `0` vulnerabilidades de severidad `high` o `critical` en dependencias de producción (`--prod`):**
     - El comando `pnpm audit` devuelve código de salida `1` ante cualquier aviso (incluso `low` o `moderate` en paquetes de desarrollo como `concurrently` o `tailwindcss` que no se empaquetan en el runtime productivo). Por ello, el gate filtra primero con `--prod` y evalúa con `jq '.metadata.vulnerabilities.high + .metadata.vulnerabilities.critical' pnpm-audit.json` que la suma de vulnerabilidades **Altas y Críticas sea exactamente `0`**.
   - **SBOM (`Syft` CycloneDX) → Umbral: Generación y publicación obligatoria del artefacto `sbom.cdx.json`:**
     - Un inventario completo de componentes en formato estándar **CycloneDX JSON** es requisito indispensable de trazabilidad para responder ante nuevos CVEs (*Zero-Days*) sin necesidad de re-escanear el código fuente.
   - **DAST (`OWASP ZAP Baseline`) → Umbral: `0` alertas de riesgo Alto (`riskcode == "3"`):**
     - En un escaneo automatizado sin autenticación dentro del runner de CI/CD contra `http://localhost:3000/login` y `http://localhost:4000/api/health`, cualquier alerta clasificada con `riskcode == "3"` (High) representa un fallo crítico expuesto directamente en la superficie pública. Las alertas de riesgo medio/bajo (como cabeceras HTTP faltantes `CSP` y `X-Frame-Options`) quedan registradas en `reporte-zap.html` y `reporte-zap.json` como artefacto y se mitigan en el Hito 4.

### Resumen de Controles del Pipeline y Hallazgos en la Línea Base

| Control | Herramienta en GitHub Actions | Umbral del Security Gate | Qué encontró en la línea base y qué hizo el grupo con los hallazgos |
|---|---|---|---|
| **SAST** | **Semgrep** (`semgrep/semgrep` con `--config p/default --config p/owasp-top-ten`) | `0` hallazgos con `--severity ERROR` | Publicó el artefacto **`semgrep` (`semgrep.sarif`)** con **6 hallazgos**:<br>1. `md5-used-as-password` en `apps/api/src/hash.ts:7` (CWE-327).<br>2. `dockerfile.security.missing-user` en `apps/api/Dockerfile:22` y `apps/web/Dockerfile:26` (CWE-250).<br>3. Tres hallazgos de endurecimiento de supply chain en `pnpm-workspace.yaml` (`pnpm-trust-policy`, `pnpm-block-exotic-sub-dependencies`, `pnpm-minimum-release-age`).<br>**Acción:** Se vincularon a los requisitos `RS-04` y `RS-08` (Hito 1) y a la matriz de trazabilidad para su remediación y re-verificación en el Hito 4. |
| **SCA** | **pnpm audit** (`pnpm audit --prod --json > pnpm-audit.json`) | `high + critical == 0` en dependencias de producción | Publicó el artefacto **`sca` (`pnpm-audit.json`)**, identificando vulnerabilidades en paquetes alcanzables en producción (`lodash` Prototype Pollution/Code Injection, `jsonwebtoken` CWE-287, `qs` DoS, `proxy-addr` IP Spoofing y `next`), diferenciándolos mediante `pnpm why` de las dependencias exclusivas de desarrollo (`shell-quote`, `braces`).<br>**Acción:** Documentadas bajo `RS-05` para actualizar versiones y aplicar `pnpm.overrides` en la fase de remediación. |
| **SBOM** | **Anchore Syft** (`anchore/sbom-action@v0`, formato `cyclonedx-json`) | El artefacto `sbom.cdx.json` se genera y publica sin errores | Publicó el artefacto **`sbom.cdx.json`** con el árbol completo de componentes y versiones exactas de `apps/api`, `apps/web` y `packages/shared`.<br>**Acción:** Respaldo de inventario de cadena de suministro para cruzar CVEs en el informe final. |
| **DAST** | **OWASP ZAP Baseline** (`ghcr.io/zaproxy/zaproxy:stable` contra `:3000/login` y `:4000/api/health`) | `0` alertas de riesgo alto (`riskcode == "3"`) | Levantó la aplicación con `docker compose up --build -d` dentro del runner y publicó el artefacto **`zap` (`reporte-zap.html` y `reporte-zap.json`)**, detectando alertas medias y bajas de cabeceras de seguridad ausentes (`CSP Header Not Set` [10038], `Missing Anti-clickjacking Header X-Frame-Options` [10020], `X-Content-Type-Options Missing` [10021] y `Server Leaks X-Powered-By` [10037]).<br>**Acción:** Complementado con la sesión de ataque profundo del **Equipo Rojo** (ZAP Desktop + Burp Suite Repeater + Postman) a través del WAF (`:8080`). |

---

## 2. PoC del Equipo Rojo (A través del WAF en `http://localhost:8080`)

> **Nota operativa para el Equipo Rojo (Fabiola y Majo):**
> Con el entorno levantado en modo observación (`MODSEC_RULE_ENGINE=DetectionOnly`), el proxy de **OWASP ZAP Desktop** y **Burp Suite** apunta a `http://localhost:8080`.
> - Guarden el reporte de ZAP de su sesión en esta carpeta como `docs/hito-2/reporte-zap-redteam.html`.
> - Guarden las capturas de **Burp Repeater** (petición y respuesta) y **Postman** en `docs/assets/img/red/` (`02-postman-poc-variables.png`, `03-poc-sqli.png`, `04-poc-xss.png`, `05-poc-idor.png`, `06-calculadora-cvss.png`).
> - Anoten la **fecha y hora exacta** de cada envío en la tabla **Registro de ataques** al final de este documento para que el **Equipo Azul** filtre esa misma ventana de tiempo en Kibana (Hito 3).

- **Reporte de ZAP (sesión del Equipo Rojo por `:8080`):** [`reporte-zap-redteam.html`](reporte-zap-redteam.html) *(adjuntar tras correr el escaneo por `:8080`)*

### Resumen Clasificado de Vulnerabilidades Explotadas (Etapa 6 de PASTA)

| ID | Vulnerabilidad Explotada | Dónde (Método y Ruta por `:8080`) | OWASP Top 10:2025 | CWE | Vector CVSS v3.1 | Puntaje |
|---|---|---|---|---|---|---|
| **PoC-01** | **Bypass de Autenticación y Extracción de Datos por Inyección SQL (SQLi)** | `POST http://localhost:8080/api/auth/login` y `GET http://localhost:8080/api/tickets?q=` | `A05:2025 Injection` | `CWE-89` | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | **9.8 (Crítico)** |
| **PoC-02** | **Cross-Site Scripting (XSS) Almacenado en Creación/Visualización de Tickets** | `POST http://localhost:8080/api/tickets` (renderizado en `/tickets/:id`) | `A05:2025 Injection` | `CWE-79` | `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N` | **5.4 (Medio)** |
| **PoC-03** | **Control de Acceso Roto: IDOR en Tickets y Eliminación No Autorizada (`DELETE`)** | `GET http://localhost:8080/api/tickets/:id` y `DELETE http://localhost:8080/api/tickets/:id` | `A01:2025 Broken Access Control` | `CWE-639` / `CWE-862` | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` | **8.1 (Alto)** |
| **PoC-04** | **Escalada de Privilegios a `admin` por JWT sin Verificación de Firma y Exposición de Hashes MD5** | `GET http://localhost:8080/api/users` (con JWT forjado) | `A07:2025 Authentication Failures` / `A04:2025` | `CWE-347` / `CWE-327` | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | **8.8 (Alto)** |

---

### PoC-01 · Inyección SQL (SQLi) en Login y Búsqueda de Tickets (`CWE-89`)

- **Alerta de ZAP / Evidencia de descubrimiento:** Detectada en pruebas activas sobre `POST http://localhost:8080/api/auth/login` y `GET http://localhost:8080/api/tickets?q=`.
- **Captura de Burp Repeater (petición y respuesta):** `../assets/img/red/03-poc-sqli.png`
- **Petición reproducida en Burp Repeater y Postman:**
  ```http
  POST /api/auth/login HTTP/1.1
  Host: localhost:8080
  Content-Type: application/json

  {
    "username": "admin' OR '1'='1' --",
    "password": "cualquier_password"
  }
  ```
  *Variante en búsqueda de tickets:*
  ```http
  GET /api/tickets?q=test'%20OR%20'1'='1 HTTP/1.1
  Host: localhost:8080
  Authorization: Bearer <token>
  ```
- **Cómo repetirlo en Postman (Carpeta 2 · Ataques / PoC del Red Team):**
  - En el environment `SecureCRM-WAF`, configurar:
    - `poc_sqli_login_user` = `admin' OR '1'='1' --`
    - `poc_sqli_query` = `test' OR '1'='1`
  - Ejecutar los requests **PoC SQLi — Login bypass** y **PoC SQLi — Búsqueda de tickets** hacia `{{base_url}}` (`http://localhost:8080`).
- **Resultado observado (con WAF en `DetectionOnly`):**
  - El servidor responde `HTTP/1.1 200 OK` devolviendo un token JWT válido del usuario `admin` (`{"token": "eyJ...", "user": {"id": 1, "username": "admin", "role": "admin"}}`) y en `/api/tickets?q=` devuelve la totalidad de tickets de la base de datos. En Kibana se registra simultáneamente el evento `waf-audit` con `ruleId: 942100` (`SQL Injection Attack Detected via libinjection`).
- **Justificación del CVSS v3.1 (`9.8 Crítico` — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`), métrica por métrica:**
  - **Vector de Ataque (`AV:N` - Red):** El endpoint `/api/auth/login` es accesible remotamente por HTTP a través de la red sin requerir acceso local.
  - **Complejidad del Ataque (`AC:L` - Baja):** No existen condiciones especiales ni tokens anti-CSRF; la concatenación directa en `SELECT * FROM users WHERE username = '${username}'` se explota de forma determinista en un solo intento.
  - **Privilegios Requeridos (`PR:N` - Ninguno):** El ataque ocurre en la pantalla de inicio de sesión antes de estar autenticado.
  - **Interacción del Usuario (`UI:N` - Ninguna):** El atacante ejecuta el bypass de forma completamente autónoma sin intervención de ningún usuario legítimo.
  - **Alcance (`S:U` - Sin cambios):** La vulnerabilidad reside y compromete el mismo componente de aplicación y su base de datos SQLite subyacente.
  - **Confidencialidad (`C:H` - Alta):** Permite obtener acceso total como `admin`, leer todos los tickets confidenciales de clientes y consultar los hashes de todos los usuarios.
  - **Integridad (`I:H` - Alta):** Con la sesión de `admin` obtenida mediante el bypass, el atacante puede modificar o eliminar cualquier ticket y alterar roles o usuarios del sistema.
  - **Disponibilidad (`A:H` - Alta):** El acceso administrativo obtenido permite eliminar la totalidad de los tickets operativos del CRM.

---

### PoC-02 · Cross-Site Scripting (XSS) Almacenado en Tickets (`CWE-79`)

- **Alerta de ZAP / Evidencia de descubrimiento:** Identificada en las respuestas sin cabecera `Content-Security-Policy` (Alerta ZAP `10038`) y confirmada al inyectar HTML/JavaScript en la creación de tickets (`POST /api/tickets`) renderizado por `dangerouslySetInnerHTML` en `apps/web/app/tickets/[id]/page.tsx`.
- **Captura de Burp Repeater (petición y respuesta):** `../assets/img/red/04-poc-xss.png`
- **Petición reproducida en Burp Repeater y Postman:**
  ```http
  POST /api/tickets HTTP/1.1
  Host: localhost:8080
  Authorization: Bearer <token>
  Content-Type: application/json

  {
    "title": "Soporte urgente",
    "description": "<img src=x onerror=alert(document.cookie)>",
    "priority": "high",
    "customerEmail": "cliente@ejemplo.com"
  }
  ```
- **Cómo repetirlo en Postman:**
  - En el environment `SecureCRM-WAF`, configurar la variable `poc_xss_payload` = `<script>alert(document.cookie)</script>` (o `<img src=x onerror=alert(document.cookie)>`) y enviar **PoC XSS — Crear ticket con payload**.
- **Resultado observado (con WAF en `DetectionOnly`):**
  - La API responde `HTTP/1.1 201 Created` guardando el payload crudo en SQLite. Cuando cualquier agente o administrador abre el detalle del ticket en el navegador (`http://localhost:3000/tickets/<id>`), el código JavaScript se ejecuta automáticamente y accede a `document.cookie` (debido a que la cookie `session` no tiene el flag `HttpOnly`). En Kibana, ModSecurity registra las reglas de la familia `941*` (`941100` / `941110` / `941160` — `XSS Attack Detected`).
- **Justificación del CVSS v3.1 (`5.4 Medio` — `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N`), métrica por métrica:**
  - **Vector de Ataque (`AV:N` - Red):** El payload se envía por HTTP y se dispara a través del navegador web de la víctima.
  - **Complejidad del Ataque (`AC:L` - Baja):** No existe sanitización de entrada en la API ni escape de salida en el componente React que usa `dangerouslySetInnerHTML`.
  - **Privilegios Requeridos (`PR:L` - Bajos):** Se requiere una cuenta autenticada básica (por ejemplo `jperez`) para crear o editar un ticket en `/api/tickets`.
  - **Interacción del Usuario (`UI:R` - Requerida):** Requiere que otro usuario (como el administrador) navegue y abra la vista de detalle del ticket infectado.
  - **Alcance (`S:C` - Cambiado):** La vulnerabilidad está en el servidor web/API (que almacena y sirve el código sin sanitizar), pero el impacto de ejecución ocurre en el navegador del usuario víctima (DOM / cookies de sesión).
  - **Confidencialidad (`C:L` - Baja):** Permite leer datos del DOM y robar la cookie de sesión accesible por JavaScript en el navegador de la víctima.
  - **Integridad (`I:L` - Baja):** Permite alterar el contenido visualizado en la página del navegador de la víctima o ejecutar acciones en su nombre dentro de la sesión web.
  - **Disponibilidad (`A:N` - Ninguna):** No interrumpe la disponibilidad global del servidor backend.

---

### PoC-03 · Control de Acceso Roto: IDOR y Eliminación No Autorizada de Tickets (`CWE-639` / `CWE-862`)

- **Alerta de ZAP / Evidencia de descubrimiento:** Confirmada mediante prueba de autorización cruzada en Burp Suite Repeater utilizando un token de usuario con rol `viewer` (`viewer` / `viewer`) contra recursos de otros usuarios y operaciones destructivas (`DELETE`).
- **Captura de Burp Repeater (petición y respuesta):** `../assets/img/red/05-poc-idor.png`
- **Petición reproducida en Burp Repeater y Postman:**
  ```http
  GET /api/tickets/1 HTTP/1.1
  Host: localhost:8080
  Authorization: Bearer <token_viewer>
  ```
  *Y eliminación no autorizada (que además dispara la regla CRS `911100` en el WAF):*
  ```http
  DELETE /api/tickets/2 HTTP/1.1
  Host: localhost:8080
  Authorization: Bearer <token_viewer>
  ```
- **Cómo repetirlo en Postman:**
  - En el environment `SecureCRM-WAF`, configurar `poc_idor_ticket_id` = `1` (o ejecutar el request **DELETE Ticket** en la colección de Postman).
- **Resultado observado (con WAF en `DetectionOnly`):**
  - El usuario con rol `viewer` (solo lectura) logra leer el detalle completo de cualquier ticket por su ID secuencial (`200 OK`) e incluso eliminar tickets del sistema mediante `DELETE /api/tickets/:id` (`200 OK` / `204 No Content`), ya que el backend solo verifica que el usuario tenga sesión (`requireAuth`) pero no comprueba su rol ni la propiedad del recurso. En Kibana, la petición `DELETE` queda registrada por la regla `911100` (`Method is not allowed by policy`, cubierta por `DET-03`).
- **Justificación del CVSS v3.1 (`8.1 Alto` — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`), métrica por métrica:**
  - **Vector de Ataque (`AV:N` - Red):** Explotable directamente mediante peticiones HTTP REST a la API.
  - **Complejidad del Ataque (`AC:L` - Baja):** Los identificadores `:id` son enteros secuenciales predecibles (`1, 2, 3...`) sin validación de control de acceso.
  - **Privilegios Requeridos (`PR:L` - Bajos):** Requiere únicamente una sesión de nivel mínimo (`viewer`).
  - **Interacción del Usuario (`UI:N` - Ninguna):** No requiere ninguna acción por parte del propietario legítimo del ticket.
  - **Alcance (`S:U` - Sin cambios):** Afecta directamente los recursos gestionados por la misma API y base de datos SQLite.
  - **Confidencialidad (`C:H` - Alta):** Permite enumerar y extraer la totalidad de los tickets confidenciales del sistema.
  - **Integridad (`I:H` - Alta):** Un usuario de solo lectura (`viewer`) puede modificar o eliminar registros de tickets de cualquier cliente o agente.
  - **Disponibilidad (`A:N` - Ninguna):** Aunque permite borrar registros individuales (impacto en integridad de datos), no tumba el proceso del servidor API.

---

### PoC-04 (Adicional) · Falsificación de Token JWT sin Verificar Firma (`CWE-347`) y Exposición de Hashes MD5 (`CWE-327`)

- **Petición reproducida en Burp Repeater:**
  - Tomando un token JWT de `viewer`, se modifica el JSON del payload a `{"id": 1, "username": "admin", "role": "admin"}` en Base64URL conservando una firma inválida, y se envía a:
  ```http
  GET /api/users HTTP/1.1
  Host: localhost:8080
  Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwidXNlcm5hbWUiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.firma_invalida
  ```
- **Resultado observado:**
  - Debido a que `apps/api/src/middleware/auth.ts` utiliza `jwt.decode(token)` sin verificar la firma con `jwt.verify()`, el backend acepta el token falsificado y `GET /api/users` devuelve `HTTP 200 OK` exponiendo todos los usuarios junto con su campo `password_hash` en formato **MD5 sin salt** (`e3afed0047b08059d0fada10f400c1e5`, etc.).
- **Justificación del CVSS v3.1 (`8.8 Alto` — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`):**
  - `AV:N` (explotable por red HTTP), `AC:L` (basta codificar en Base64URL el payload deseado), `PR:L` (partiendo de un usuario básico o conociendo la estructura del token), `UI:N` (sin interacción de terceros), `S:U` (mismo componente backend), `C:H` / `I:H` / `A:H` (compromiso administrativo total del CRM y exposición de todos los hashes de contraseñas).

---

## 3. Registro de Ataques (Línea de Tiempo para Correlación con el SIEM en Hito 3)

> **Instrucción para el Equipo Rojo (Fabiola y Majo):** Al ejecutar cada prueba por `http://localhost:8080` con el WAF en `DetectionOnly`, confirmen o actualicen la hora exacta en esta tabla para que el Equipo Azul tome las capturas de `DET-01`, `DET-02` y `DET-03` en Kibana con esa misma marca de tiempo.

| Fecha | Hora (Local / UTC) | Quién (Red Team) | Herramienta | Método y Ruta (por `:8080`) | Payload Enviado | Respuesta HTTP (`DetectionOnly`) | Regla CRS Disparada en SIEM |
|---|---|---|---|---|---|---|---|
| 2026-11-11 | `19:21` (Local) / `01:21 UTC` | Equipo Rojo / Verificación inicial | `curl` / Postman | `POST /api/auth/login` | `{"username":"jperez","password":"Password1"}` | `200 OK` (Login legítimo de control) | Tráfico normal (`access.log`) |
| 2026-11-11 | `19:21` (Local) / `01:21 UTC` | Equipo Rojo (`@Fabiola-cc` / `@Maria-Villafuerte`) | Burp Repeater / Postman | `DELETE /api/tickets/999` | Petición `DELETE` fuera de `ALLOWED_METHODS` | `200 OK` / `204` (Pasa en `DetectionOnly`) | `911100` (`DET-03 Método`) |
| 2026-11-11 | `19:23` (Local) / `01:23 UTC` | Equipo Rojo (`@Fabiola-cc` / `@Maria-Villafuerte`) | Burp Repeater / Postman | `POST /api/auth/login` | `{"username":"admin' OR '1'='1' --","password":"x"}` | `200 OK` (Bypass SQLi exitoso, devuelve JWT admin) | `942100` (`DET-01 SQLi`) |
| 2026-11-11 | `19:23` (Local) / `01:23 UTC` | Equipo Rojo (`@Fabiola-cc` / `@Maria-Villafuerte`) | OWASP ZAP / Postman | `GET /api/tickets?q=<script>alert(1)</script>` | `?q=%3Cscript%3Ealert(1)%3C/script%3E` | `200 OK` (Reflejado/procesado en `DetectionOnly`) | `941100`, `941160` (`DET-02 XSS`) |
| *(Completar en sesión Red Team)* | *(Hora ZAP)* | `@Fabiola-cc` / `@Maria-Villafuerte` | OWASP ZAP Desktop | `http://localhost:8080/api/*` | Spider + Active Scan por `:8080` | `200 OK` (Reporte `reporte-zap-redteam.html`) | Múltiples `941*`, `942*`, `911100` |
| *(Completar en sesión Red Team)* | *(Hora Burp)* | `@Fabiola-cc` / `@Maria-Villafuerte` | Burp Suite Repeater | `POST /api/tickets` | `{"title":"PoC","description":"<img src=x onerror=alert(1)>"}` | `201 Created` (XSS almacenado confirmado) | `941100`, `941110` (`DET-02 XSS`) |
| *(Completar en sesión Red Team)* | *(Hora Postman)* | `@Fabiola-cc` / `@Maria-Villafuerte` | Postman (`SecureCRM-WAF`) | `GET /api/tickets/1` y `POST /api/auth/login` | Repetición con variables `poc_*` para el Blue Team | `200 OK` (Capturado en Kibana Discover) | `942*`, `941*`, `911100` |
