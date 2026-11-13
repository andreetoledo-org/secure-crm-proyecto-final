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
     - **Por qué `pnpm audit` y no `npm audit`:** Secure CRM es un monorepo gestionado con **pnpm** (`pnpm-workspace.yaml`, `pnpm-lock.yaml`, `packageManager: pnpm@10.12.1`). El árbol de dependencias real está descrito por el `pnpm-lock.yaml`; `npm audit` requeriría un `package-lock.json` que este proyecto no genera y resolvería un árbol distinto. Usar `pnpm audit` garantiza que la auditoría coincide con las versiones que pnpm instala en los tres paquetes del workspace (`apps/api`, `apps/web`, `packages/shared`).
   - **SBOM (`Syft` CycloneDX) → Umbral: Generación y publicación obligatoria del artefacto `sbom.cdx.json`:**
     - Un inventario completo de componentes en formato estándar **CycloneDX JSON** es requisito indispensable de trazabilidad para responder ante nuevos CVEs (*Zero-Days*) sin necesidad de re-escanear el código fuente.
   - **DAST (`OWASP ZAP Baseline`) → Umbral: `0` alertas de riesgo Alto (`riskcode == "3"`):**
     - El job solo pasa `-t "$APP_URL"` a ZAP, es decir, **escanea `http://localhost:3000/login`**; `http://localhost:4000/api/health` se usa únicamente como comprobación de que la API respondió antes de lanzar el escaneo, no se escanea (ver [`.github/workflows/devsecops.yml:133`](../../.github/workflows/devsecops.yml#L133)). En este escaneo automatizado sin autenticación dentro del runner de CI/CD, cualquier alerta clasificada con `riskcode == "3"` (High) representa un fallo crítico expuesto directamente en la superficie pública. Las alertas de riesgo medio/bajo (como cabeceras HTTP faltantes `CSP` y `X-Frame-Options`) quedan registradas en `reporte-zap.html` y `reporte-zap.json` como artefacto y se mitigan en el Hito 4.

### Resumen de Controles del Pipeline y Hallazgos en la Línea Base

| Control | Herramienta en GitHub Actions | Umbral del Security Gate | Qué encontró en la línea base y qué hizo el grupo con los hallazgos |
|---|---|---|---|
| **SAST** | **Semgrep** (`semgrep/semgrep` con `--config p/default --config p/owasp-top-ten`) | `0` hallazgos con `--severity ERROR` | Publicó el artefacto **`semgrep` (`semgrep.sarif`)** con **6 hallazgos**:<br>1. `md5-used-as-password` en `apps/api/src/hash.ts:7` (CWE-327).<br>2. `dockerfile.security.missing-user` en `apps/api/Dockerfile:22` y `apps/web/Dockerfile:26` (CWE-250).<br>3. Tres hallazgos de endurecimiento de supply chain en `pnpm-workspace.yaml` (`pnpm-trust-policy`, `pnpm-block-exotic-sub-dependencies`, `pnpm-minimum-release-age`).<br>**Acción:** Se vincularon a los requisitos `RS-04` y `RS-08` (Hito 1) y a la matriz de trazabilidad para su remediación y re-verificación en el Hito 4. |
| **SCA** | **pnpm audit** (`pnpm audit --prod --json > pnpm-audit.json`) | `high + critical == 0` en dependencias de producción | Publicó el artefacto **`sca` (`pnpm-audit.json`)**, identificando vulnerabilidades en paquetes alcanzables en producción (`lodash` Prototype Pollution/Code Injection, `jsonwebtoken` CWE-287, `qs` DoS, `proxy-addr` IP Spoofing y `next`), diferenciándolos mediante `pnpm why` de las dependencias exclusivas de desarrollo (`shell-quote`, `braces`).<br>**Acción:** Documentadas bajo `RS-05` para actualizar versiones y aplicar `pnpm.overrides` en la fase de remediación. |
| **SBOM** | **Anchore Syft** (`anchore/sbom-action@v0`, formato `cyclonedx-json`) | El artefacto `sbom.cdx.json` se genera y publica sin errores | Publicó el artefacto **`sbom.cdx.json`** con el árbol completo de componentes y versiones exactas de `apps/api`, `apps/web` y `packages/shared`.<br>**Acción:** Respaldo de inventario de cadena de suministro para cruzar CVEs en el informe final. |
| **DAST** | **OWASP ZAP Baseline** (`ghcr.io/zaproxy/zaproxy:stable` contra `:3000/login`; `:4000/api/health` solo como health check previo) | `0` alertas de riesgo alto (`riskcode == "3"`) | Levantó la aplicación con `docker compose up --build -d` dentro del runner y publicó el artefacto **`zap` (`reporte-zap.html` y `reporte-zap.json`)**, detectando alertas medias y bajas de cabeceras de seguridad ausentes (`CSP Header Not Set` [10038], `Missing Anti-clickjacking Header X-Frame-Options` [10020], `X-Content-Type-Options Missing` [10021] y `Server Leaks X-Powered-By` [10037]).<br>**Acción:** Complementado con la sesión de ataque profundo del **Equipo Rojo** (ZAP Desktop + Burp Suite Repeater + Postman) a través del WAF (`:8080`). |

---

## 2. PoC del Equipo Rojo (A través del WAF en `http://localhost:8080`)

> **Nota operativa para el Equipo Rojo (Fabiola y Majo):**
> Con el entorno levantado en modo observación (`MODSEC_RULE_ENGINE=DetectionOnly`), el proxy de **OWASP ZAP Desktop** y **Burp Suite** apunta a `http://localhost:8080`.
> - Guarden el reporte de ZAP de su sesión en esta carpeta como `docs/hito-2/reporte-zap-redteam.html`.
> - Guarden las capturas de **Burp Repeater** (petición y respuesta) como `docs/assets/img/red/burp-poc-01.png` … `burp-poc-04.png` (una por PoC).
> - Las imágenes `03-poc-sqli.png`, `04-poc-xss.png` y `05-poc-idor.png` corresponden a la **repetición en Postman** (no a Burp); `02-postman-poc-variables.png` muestra las variables del environment y `06-calculadora-cvss.png`, el cálculo del CVSS.
> - Anoten la **fecha y hora exacta** de cada envío en la tabla **Registro de ataques** al final de este documento para que el **Equipo Azul** filtre esa misma ventana de tiempo en Kibana (Hito 3).

**Evidencia de contexto (entorno y herramientas):**

- Bypass del WAF: la API responde directo en `:4000` sin pasar por el WAF (CA-05 / V-10).

  ![Bypass del WAF — GET http://localhost:4000/api/health responde 200](../assets/img/red/bypass-4000.png)

- Variables del environment `SecureCRM-WAF` en Postman (tokens y payloads de las PoC):

  ![Postman — variables del environment SecureCRM-WAF](../assets/img/red/02-postman-poc-variables.png)

- Cálculo del CVSS v3.1 en la calculadora oficial:

  ![Calculadora CVSS v3.1](../assets/img/red/06-calculadora-cvss.png)

- **Reporte de ZAP (sesión del Equipo Rojo por `:8080`):** [`reporte-zap-redteam.html`](reporte-zap-redteam.html) — generado el **2026-11-12 a las 11:30:00** con **ZAP 2.17.0**, sitio escaneado `http://localhost:8080`. Resumen: **0 Alto · 1 Medio · 4 Bajo · 3 Informativo** (8 alertas).
  - **Medio:** `Inyección SQL` en `POST /api/auth/login` (respalda PoC-01); `CSP: Failure to Define Directive with No Fallback`.
  - **Bajo:** `Cookie sin flag HttpOnly`, `Cookie sin atributo SameSite`, `El servidor divulga información (X-Powered-By)`, `Falta encabezado X-Content-Type-Options`.
  - *Nota:* el escaneo ZAP es del 2026-11-12; las PoC manuales de Burp/Postman son del 2026-11-13 (sesiones distintas, no se mezclan). ZAP no levantó una alerta propia de XSS reflejado; PoC-02 se respalda con la alerta `CSP` y la evidencia de Burp.

### Resumen Clasificado de Vulnerabilidades Explotadas (Etapa 6 de PASTA)

| ID | Vulnerabilidad Explotada | Dónde (Método y Ruta por `:8080`) | OWASP Top 10:2025 | CWE | Vector CVSS v3.1 | Puntaje |
|---|---|---|---|---|---|---|
| **PoC-01** | **Bypass de Autenticación por Inyección SQL (SQLi) en el Login** | `POST http://localhost:8080/api/auth/login` | `A05:2025 Injection` | `CWE-89` | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | **9.8 (Crítico)** |
| **PoC-02** | **Cross-Site Scripting (XSS) Reflejado en la Búsqueda de Tickets** (variante almacenada en la descripción) | `GET http://localhost:8080/api/tickets?q=` (reflejado en `/tickets`) | `A05:2025 Injection` | `CWE-79` | `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N` | **5.4 (Medio)** |
| **PoC-03** | **Control de Acceso Roto: IDOR en Tickets y Eliminación No Autorizada (`DELETE`)** | `GET http://localhost:8080/api/tickets/:id` y `DELETE http://localhost:8080/api/tickets/:id` | `A01:2025 Broken Access Control` | `CWE-639` / `CWE-862` | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` | **8.1 (Alto)** |
| **PoC-04** | **JWT Aceptado sin Verificar la Firma + Exposición de Hashes MD5** (`GET /api/users` sin control de rol) | `GET http://localhost:8080/api/users` (con JWT forjado) | `A07:2025 Authentication Failures` / `A04:2025` | `CWE-347` / `CWE-327` | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | **6.5 (Medio)** |

---

### PoC-01 · Inyección SQL (SQLi) en el Login (`CWE-89`)

- **Dónde vive:** `POST http://localhost:8080/api/auth/login`. Causa raíz verificada en [`apps/api/src/auth.ts:30`](../../apps/api/src/auth.ts#L30) — la consulta se construye por concatenación de strings (`SELECT * FROM users WHERE username = '${username}' AND password_hash = '${hashed}'`).
- **Herramienta:** OWASP ZAP (descubrimiento) + Burp Suite Repeater (explotación manual) + Postman (repetición para el SIEM).
- **Alerta de ZAP / Evidencia de descubrimiento:** ZAP (2026-11-12) levantó la alerta **`Inyección SQL` (riesgo Medio)** sobre `POST http://localhost:8080/api/auth/login` — ver `reporte-zap-redteam.html`.
- **Captura de Burp Repeater (petición y respuesta):**

  ![PoC-01 · SQLi en el login — Burp Repeater](../assets/img/red/burp-poc-01.png)
- **Captura de repetición en Postman:**

  ![PoC-01 · SQLi en el login — Postman](../assets/img/red/03-poc-sqli.png)
- **Petición reproducida (Burp Repeater y Postman):**
  ```http
  POST /api/auth/login HTTP/1.1
  Host: localhost:8080
  Content-Type: application/json

  {
    "username": "admin' OR '1'='1' --",
    "password": "x"
  }
  ```
- **Cómo repetirlo en Postman (Carpeta `2. Ataques` → request `SQLi en el login`):**
  - En el environment `SecureCRM-WAF`, la variable `poc_sqli_login` ya trae `admin' OR '1'='1' --`.
  - Enviar el request **`SQLi en el login`** hacia `{{base_url}}` (`http://localhost:8080/api/auth/login`).
- **Resultado observado (con WAF en `DetectionOnly`, 2026-11-13 15:40:26 hora local / 21:40:26 GMT):**
  - La API respondió **`HTTP/1.1 200 OK`** y devolvió un token JWT del usuario administrador: `{"token":"eyJ...","user":{"id":1,"username":"admin","email":"admin@secure-crm.local","fullName":"Ada Administradora","role":"admin","createdAt":"2026-11-13 20:42:23"}}`. El payload `admin' OR '1'='1' --` autenticó como `admin` sin contraseña válida (se envió `"password":"x"`). Evidencia: `../assets/img/red/burp-poc-01.png`. En Kibana el evento `waf-audit` queda con `ruleId: 942100` (`SQL Injection Attack Detected via libinjection`).
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

### PoC-02 · Cross-Site Scripting (XSS) Reflejado en la Búsqueda de Tickets (`CWE-79`)

> **Nota sobre la clasificación (CWE-79 vs CWE-89):** El parámetro `?q=` es un doble vector. En el backend se concatena en SQL ([`tickets.ts:40`](../../apps/api/src/routes/tickets.ts#L40) — CWE-89, mismo tipo de fallo que PoC-01). En el frontend, el término buscado se refleja **sin escapar** mediante `dangerouslySetInnerHTML` en [`apps/web/app/tickets/page.tsx:69`](../../apps/web/app/tickets/page.tsx#L69), lo que ejecuta HTML/JS en el navegador → **XSS reflejado (CWE-79)**. Esta ficha se centra en el XSS reflejado (impacto en el navegador de la víctima); el componente SQLi de `?q=` queda cubierto por la causa raíz de PoC-01. Existe además un **XSS almacenado** en la descripción del ticket, renderizada sin escape en [`apps/web/app/tickets/[id]/page.tsx:93`](../../apps/web/app/tickets/[id]/page.tsx#L93); se trata como variante al final de la ficha.

- **Dónde vive:** `GET http://localhost:8080/api/tickets?q=<payload>`, reflejado en la vista `http://localhost:3000/tickets`.
- **Herramienta:** OWASP ZAP (descubrimiento) + Burp Suite Repeater + Postman.
- **Alerta de ZAP / Evidencia de descubrimiento:** ZAP (2026-11-12) no generó una alerta propia de XSS reflejado, pero sí marcó **`CSP: Failure to Define Directive with No Fallback` (riesgo Medio)** — la ausencia de `Content-Security-Policy` es lo que permite que el script reflejado se ejecute. El XSS reflejado se confirma manualmente con Burp (`burp-poc-02.png`).
- **Captura de Burp Repeater (petición y respuesta):**

  ![PoC-02 · XSS reflejado en la búsqueda — Burp Repeater](../assets/img/red/burp-poc-02.png)
- **Captura de repetición en Postman:**

  ![PoC-02 · XSS reflejado en la búsqueda — Postman](../assets/img/red/04-poc-xss.png)
- **Petición reproducida (Burp Repeater y Postman):**
  ```http
  GET /api/tickets?q=<script>alert(1)</script> HTTP/1.1
  Host: localhost:8080
  Authorization: Bearer <token>
  ```
- **Cómo repetirlo en Postman (Carpeta `2. Ataques` → request `SQLi / XSS en la busqueda de tickets`):**
  - La variable `poc_busqueda` del environment ya trae `<script>alert(1)</script>`.
  - Primero ejecutar el login de la Carpeta `1. Trafico legitimo` (guarda `{{token}}`), luego enviar el request **`SQLi / XSS en la busqueda de tickets`**.
- **Resultado observado (con WAF en `DetectionOnly`, 2026-11-13 15:45:55 hora local / 21:45:55 GMT):**
  - La API respondió **`HTTP/1.1 200 OK`** devolviendo el término **sin sanitizar** en el campo `query`: `{"query":"<script>alert(1)</script>","tickets":[...]}`. Ese valor es el que la vista `http://localhost:3000/tickets` renderiza con `dangerouslySetInnerHTML`, ejecutando el script en el navegador. Evidencia: `../assets/img/red/burp-poc-02.png`. En Kibana, ModSecurity registra la familia `941*` (`941100` / `941110` / `941160` — `XSS Attack Detected`).
  - *Variante XSS almacenado:* `POST /api/tickets` con `description` = `<img src=x onerror=alert(document.cookie)>` se guarda crudo en SQLite y se ejecuta al abrir `/tickets/<id>`. La cookie `session` es accesible por JS porque carece de `HttpOnly` ([`auth.ts:48`](../../apps/api/src/auth.ts#L48)).
- **Justificación del CVSS v3.1 (`5.4 Medio` — `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N`), métrica por métrica:**
  - **Vector de Ataque (`AV:N` - Red):** El payload viaja por HTTP y se dispara en el navegador de la víctima.
  - **Complejidad del Ataque (`AC:L` - Baja):** No hay escape de salida en el componente React (`dangerouslySetInnerHTML`); el reflejo es determinista.
  - **Privilegios Requeridos (`PR:L` - Bajos):** La ruta `/api/tickets` exige una sesión autenticada (cualquier rol, incluido `viewer`), por lo que para probar el reflejo se necesita un token válido.
  - **Interacción del Usuario (`UI:R` - Requerida):** La víctima debe abrir la URL de búsqueda con el término malicioso (reflejado) o el ticket infectado (almacenado).
  - **Alcance (`S:C` - Cambiado):** El fallo vive en el componente servidor (API/SSR que entrega el dato sin escapar), pero el impacto se materializa en otro contexto de seguridad: el navegador de la víctima (DOM y cookies).
  - **Confidencialidad (`C:L` - Baja):** Permite leer datos del DOM y la cookie de sesión accesible por JS.
  - **Integridad (`I:L` - Baja):** Permite alterar lo que ve la víctima o actuar en su sesión web.
  - **Disponibilidad (`A:N` - Ninguna):** No afecta la disponibilidad del backend.

---

### PoC-03 · Control de Acceso Roto: IDOR y Eliminación No Autorizada de Tickets (`CWE-639` / `CWE-862`)

- **Dónde vive:** `GET http://localhost:8080/api/tickets/:id` ([`tickets.ts:51`](../../apps/api/src/routes/tickets.ts#L51)) y `DELETE http://localhost:8080/api/tickets/:id` ([`tickets.ts:109`](../../apps/api/src/routes/tickets.ts#L109)). Ambas rutas solo pasan por `authenticate` ([`tickets.ts:6`](../../apps/api/src/routes/tickets.ts#L6)); **no existe ningún `requireRole` ni verificación de propiedad** en el backend. La falla es de la aplicación: aunque el WAF bloquee `DELETE` por método (regla `911100`), eso no corrige la ausencia de control de acceso.
- **Herramienta:** Burp Suite Repeater (autorización cruzada) + Postman.
- **Alerta de ZAP / Evidencia de descubrimiento:** ZAP baseline **no detecta IDOR ni fallas de control de acceso** (requieren conocer la lógica de autorización y comparar entre roles), por eso no aparece en el reporte. Se descubre y confirma manualmente con Burp usando un token de `viewer` (`burp-poc-03.png`).
- **Captura de Burp Repeater (petición y respuesta):**

  ![PoC-03 · IDOR y DELETE con token viewer — Burp Repeater](../assets/img/red/burp-poc-03.png)
- **Captura de repetición en Postman:**

  ![PoC-03 · IDOR y DELETE con token viewer — Postman](../assets/img/red/05-poc-idor.png)
- **Petición reproducida (con un token de `viewer`):**
  ```http
  GET /api/tickets/1 HTTP/1.1
  Host: localhost:8080
  Authorization: Bearer <token_viewer>
  ```
  *Y eliminación no autorizada. **Usar un id que exista** (hay 12 tickets sembrados, ids 1–12): `DELETE` de un id inexistente devuelve `404` ([`tickets.ts:110-111`](../../apps/api/src/routes/tickets.ts#L110-L111)) y no probaría nada.*
  ```http
  DELETE /api/tickets/1 HTTP/1.1
  Host: localhost:8080
  Authorization: Bearer <token_viewer>
  ```
- **Cómo repetirlo en Postman (Carpeta `2. Ataques`):**
  - Obtener primero el token de `viewer` con el request **`Login viewer (guarda token_viewer)`** (Carpeta `1. Trafico legitimo`).
  - Ejecutar **`PoC-03 IDOR · GET ticket ajeno`** (usa `{{poc_idor_ticket_id}}=1` y `{{token_viewer}}`) y **`PoC-03 DELETE como viewer`**.
- **Resultado observado (con WAF en `DetectionOnly`, 2026-11-13 hora local, token de `viewer` confirmado: `{"sub":4,"username":"viewer","role":"viewer"}`):**
  - `GET /api/tickets/1` → **`200 OK`** (15:53:32 local / 21:53:32 GMT): el `viewer` leyó el ticket ajeno completo (cliente "Comercial El Quetzal", asignado a Juan Pérez) — **IDOR**.
  - `DELETE /api/tickets/1` → **`200 OK`** con `{"ok":true}` (15:54:31 local / 21:54:31 GMT): el `viewer` **eliminó** ese ticket, pese a ser de solo lectura — **Broken Access Control**. Evidencia: `../assets/img/red/burp-poc-03.png`.
  - El backend no comprueba rol ni propiedad. En modo `On`, el `DELETE` recibiría `403` del WAF por la regla `911100` (`DET-03`), pero eso enmascara —no corrige— el fallo de control de acceso de la app.
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

- **Dónde vive:** `GET http://localhost:8080/api/users`. El middleware usa `jwt.decode()` en vez de `jwt.verify()` ([`middleware/auth.ts:21`](../../apps/api/src/middleware/auth.ts#L21)) y lee **`payload.sub`** ([`:26`](../../apps/api/src/middleware/auth.ts#L26)). El token legítimo también se emite con `{ sub, username, role }` ([`auth.ts:45`](../../apps/api/src/auth.ts#L45)).
- **Herramienta:** Burp Suite Repeater + Postman.
- **Nota de honestidad sobre el alcance:** `GET /api/users` **no comprueba el rol** del solicitante ([`users.ts:13`](../../apps/api/src/routes/users.ts#L13)): cualquier token aceptado —incluso uno de `viewer` sin modificar— lista los usuarios y sus hashes. Por eso este PoC demuestra con rigor la **aceptación de un token con firma inválida (CWE-347)**, no una escalada por RBAC roto (no hay RBAC que romper en esta ruta). Cambiar `"role":"admin"` sí importa en rutas que *sí* leen el rol (p. ej. las que solo deberían permitir a `admin`); aquí se incluye para mostrar que el payload forjado se acepta tal cual.
- **Captura de Burp Repeater (petición y respuesta):**

  ![PoC-04 · JWT con firma inválida — Burp Repeater](../assets/img/red/burp-poc-04.png)
- **Petición reproducida.** A partir de un token de `viewer`, se reemplaza el payload por `{"sub":1,"username":"admin","role":"admin"}` en Base64URL y se deja la firma inválida:
  ```http
  GET /api/users HTTP/1.1
  Host: localhost:8080
  Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEsInVzZXJuYW1lIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.firma_invalida
  ```
  *(payload decodificado: `{"sub":1,"username":"admin","role":"admin"}`; el tercer segmento `firma_invalida` es deliberadamente incorrecto.)*
- **Cómo repetirlo en Postman (Carpeta `2. Ataques` → `PoC-04 JWT forjado`):** usa `Authorization: Bearer {{poc_jwt_forjado}}`, variable ya cargada en el environment con el token de ejemplo de arriba.
- **Resultado observado (2026-11-13 16:01:13 hora local / 22:01:13 GMT):**
  - **`HTTP/1.1 200 OK`**. El servidor aceptó el token cuya firma es literalmente `firma_invalida` y `GET /api/users` devolvió la lista completa de usuarios con su `passwordHash` en **MD5 sin salt** ([`hash.ts:7`](../../apps/api/src/hash.ts#L7)). Evidencia: `../assets/img/red/burp-poc-04.png`. Hashes reales devueltos:
    - `admin` → `2637a5c30af69a7bad877fdb65fbd78b` (MD5 de la contraseña semilla `Admin123!`)
    - `jperez` → `2ac9cb7dc02b3c0083eb70898e549b63` (MD5 de `Password1`)
  - **Nota verificada en esta sesión:** la misma ruta devolvió `200 OK` también con un token **legítimo de `viewer`** (sin modificar), lo que confirma que `GET /api/users` **no comprueba el rol** — la fuga de hashes no depende de forjar el token. El token forjado prueba por separado que la firma inválida se acepta (CWE-347).
- **Justificación del CVSS v3.1 (`6.5 Medio` — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`), confirmada con la evidencia de esta sesión:**
  - Se acota a `I:N/A:N` porque **esta ruta concreta** (`GET /api/users`) solo divulga información; no modifica ni afecta disponibilidad por sí sola.
  - **`AV:N` (Red):** explotable por HTTP remoto.
  - **`AC:L` (Baja):** basta recodificar el payload en Base64URL; no hay condición especial.
  - **`PR:L` (Bajos):** se parte de un token de usuario autenticado (`viewer`) para tener la estructura; el defecto es que la firma alterada se acepta igual.
  - **`UI:N` (Ninguna):** sin interacción de terceros.
  - **`S:U` (Sin cambios):** afecta el mismo componente backend.
  - **`C:H` (Alta):** expone todos los usuarios y sus hashes de contraseña.
  - **`I:N` / `A:N`:** `GET /api/users` no escribe datos ni degrada el servicio. (Si en el futuro se documenta una escritura con token forjado en una ruta que sí lee el rol, como `PUT /api/users/:id/role`, el impacto de integridad subiría a `I:H` y habría que recalcular el puntaje.)

---

## 3. Registro de Ataques (Línea de Tiempo para Correlación con el SIEM en Hito 3)

> **Formato (guía del curso):** columnas exactas `Fecha y hora | Hallazgo | Herramienta | Destino | Resultado`, **una sola herramienta por fila** y **una fila por envío**. Las fechas/horas provienen de la cabecera `Date` del servidor en cada respuesta, para que el Equipo Azul filtre esa misma ventana en Kibana (Hito 3). El escaneo ZAP es del 2026-11-12 y las pruebas manuales (Burp/Postman) del 2026-11-13.

| Fecha y hora | Hallazgo | Herramienta | Destino (`localhost:8080` + ruta) | Resultado (código HTTP y qué ocurrió) |
|---|---|---|---|---|
| 2026-11-13 (hora local) | Bypass del WAF (puerto directo) | Navegador / Postman (carpeta 0) | `base_url_directo` → `http://localhost:4000/api/health` | **`200 OK`** `{"status":"ok","service":"secure-crm-api"}` — la API responde sin pasar por el WAF (CA-05 / V-10). Captura `bypass-4000.png` |
| 2026-11-12 11:30:00 | Descubrimiento general (SQLi, CSP, cabeceras, cookies) | OWASP ZAP 2.17.0 (por `:8080`) | `http://localhost:8080/` (scan) | Reporte `reporte-zap-redteam.html`: 0 Alto · 1 Medio · 4 Bajo · 3 Info (incluye alerta de Inyección SQL en el login) |
| 2026-11-12 11:30:00 | PoC-01 SQLi en login | OWASP ZAP 2.17.0 | `POST http://localhost:8080/api/auth/login` | Alerta `Inyección SQL` (Medio) en el reporte `reporte-zap-redteam.html` |
| 2026-11-13 15:40:26 (local) / 21:40:26 GMT | PoC-01 SQLi en login (`admin' OR '1'='1' --`) | Burp Repeater | `POST http://localhost:8080/api/auth/login` | `200 OK` — devolvió JWT de `admin` (bypass exitoso). Captura `burp-poc-01.png` |
| 2026-11-13 16:22 (local) | PoC-01 SQLi en login | Postman (`SQLi en el login`) | `POST http://localhost:8080/api/auth/login` | `200 OK` (repetición de la colección `SecureCRM-WAF`) |
| 2026-11-12 11:30:00 | PoC-02 (contexto) XSS reflejado | OWASP ZAP 2.17.0 | `http://localhost:8080` | Sin alerta propia de XSS; sí alerta `CSP` (Medio) que habilita la ejecución. XSS confirmado por Burp |
| 2026-11-13 15:45:55 (local) / 21:45:55 GMT | PoC-02 XSS reflejado en búsqueda (`<script>alert(1)</script>`) | Burp Repeater | `GET http://localhost:8080/api/tickets?q=` | `200 OK` — `query` reflejado sin sanitizar. Captura `burp-poc-02.png` |
| 2026-11-13 16:22 (local) | PoC-02 XSS reflejado en búsqueda | Postman (`SQLi / XSS en la busqueda de tickets`) | `GET http://localhost:8080/api/tickets?q=` | `200 OK` (término reflejado sin sanitizar) |
| 2026-11-13 15:53:32 / 15:54:31 (local) | PoC-03 IDOR + DELETE con token `viewer` sobre ticket id 1 | Burp Repeater | `GET` y `DELETE http://localhost:8080/api/tickets/1` | GET `200 OK` (leyó ticket ajeno) y DELETE `200 OK` `{"ok":true}` (lo borró). Captura `burp-poc-03.png` |
| 2026-11-13 16:22 (local) | PoC-03 IDOR + DELETE con token `viewer` sobre ticket 1 | Postman (`PoC-03 IDOR` / `PoC-03 DELETE como viewer`) | `GET` y `DELETE http://localhost:8080/api/tickets/1` | GET `200 OK` y DELETE `200 OK` `{"ok":true}` (base reseedada antes de correr) |
| 2026-11-13 16:01:13 (local) / 22:01:13 GMT | PoC-04 JWT con firma inválida + fuga de hashes MD5 | Burp Repeater | `GET http://localhost:8080/api/users` | `200 OK` — aceptó firma `firma_invalida` y listó usuarios con `passwordHash`. Captura `burp-poc-04.png` |
| 2026-11-13 16:22 (local) | PoC-04 JWT con firma inválida + fuga de hashes | Postman (`PoC-04 JWT forjado`) | `GET http://localhost:8080/api/users` | `200 OK` (listó usuarios con `passwordHash`) |

> **Filas retiradas por falta de evidencia.** Las siguientes filas existían en una versión previa de esta tabla y se retiran porque no tienen captura/respaldo que las sustente y/o contradicen el código de la aplicación. Se vuelven a incluir en la tabla de arriba solo cuando haya evidencia real:
> - `2026-11-11 19:21` — `POST /api/auth/login` login de control de `jperez` (`200 OK`): sin captura.
> - `2026-11-11 19:21` — `DELETE /api/tickets/999` marcado como `200 OK` / `204`: **incorrecto**, un `DELETE` sobre un id inexistente devuelve `404` ([`tickets.ts:110-111`](../../apps/api/src/routes/tickets.ts#L110-L111)). Para probar el borrado hay que usar un id que exista (1–12).
> - `2026-11-11 19:23` — `POST /api/auth/login` con `admin' OR '1'='1' --` (`200 OK`, JWT admin): sin captura que lo respalde.
> - `2026-11-11 19:23` — `GET /api/tickets?q=<script>alert(1)</script>` (`200 OK`): sin captura que lo respalde.
