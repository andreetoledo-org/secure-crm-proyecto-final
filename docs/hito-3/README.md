# Hito 3 · Detección en SIEM y Respuesta Activa en WAF (Equipo Azul)

- **Integrantes responsables (Equipo Azul):**
  - **Andree Toledo** ([@andreetoledo](https://github.com/andreetoledo))
  - **Sofía Velásquez** ([@Sofiamishel2003](https://github.com/Sofiamishel2003))
- **Exportación de Saved Objects de Kibana (Reglas `DET-*`, Data View y Dashboard):** [`waf-siem/kibana-export.ndjson`](../../waf-siem/kibana-export.ndjson)
- **Archivo de Exclusiones del WAF:** [`waf-siem/waf/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf`](../../waf-siem/waf/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf)

---

## 1. Conexión de la Aplicación al WAF y Análisis de Riesgo (Opción A vs. Opción B)

- **Modalidad configurada en el entorno de trabajo:** **Opción A** (`APP_BACKEND=http://host.docker.internal:4000` en `waf-siem/.env` y `NEXT_PUBLIC_API_URL=http://localhost:8080` en el frontend web).
- **Flujo de red verificado:**
  - El cliente web (`http://localhost:3000`), **Postman**, **OWASP ZAP** y **Burp Suite** envían todas las peticiones hacia el proxy inverso **WAF (`http://localhost:8080`)**, el cual inspecciona la transacción con **ModSecurity v3 + OWASP CRS v4**, escribe la bitácora en `/var/log/waf/modsec_audit.json` (recolectada por **Filebeat** hacia **Elasticsearch** `:9200` y **Kibana** `:5601`) y reenvía el tráfico hacia la API en `:4000`.
- **Riesgo aceptado y documentado en el laboratorio (Hallazgo de Bypass del WAF):**
  - En la **Opción A**, el contenedor `api` publica el puerto `4000:4000` en la interfaz local del host. Esto significa que una petición enviada directamente a `http://localhost:4000/api/health` responde `200 OK` saltándose por completo la inspección de ModSecurity y sin dejar rastro en el SIEM (`DF-9` en el DFD del Hito 1).
  - **Mitigación arquitectónica (Opción B):** En un despliegue productivo, el servicio `api` se incorpora dentro del mismo `docker-compose.yml` del WAF usando únicamente `expose: ["4000"]` (sin `ports:`) y `APP_BACKEND=http://api:4000`, de modo que el backend solo sea alcanzable desde la red virtual interna del contenedor `waf`.

---

## 2. Reglas de Detección en Kibana (`MODSEC_RULE_ENGINE=DetectionOnly`)

Con el WAF operando inicialmente en modo observación (`DetectionOnly`) y el Data View **`filebeat-*`** (campo temporal `@timestamp`) configurado en **Kibana Discover**, se crearon y guardaron las siguientes búsquedas (`Saved Searches`) que detectan los ataques reales ejecutados por el **Equipo Rojo** a través de `http://localhost:8080`:

| ID Regla | Nombre en Kibana | Consulta KQL / ES\|QL Guardada | Ataque del Red Team que Detecta | Evidencia Real Capturada en SIEM (`@timestamp`, `ruleId`, `uri` y `details.data`) | Captura |
|---|---|---|---|---|---|
| **DET-01** | `DET-01 SQLi` | `fields.fuente : "waf-audit" and modsec.transaction.messages.details.ruleId : 942*` | **PoC-01:** Bypass de autenticación en `POST /api/auth/login` y extracción de tickets en `GET /api/tickets?q=` mediante Inyección SQL (`CWE-89`). | **1)** `2026-11-12T01:51:53.480Z` · `POST /api/auth/login` · Regla **`942100`** (`SQL Injection Attack Detected via libinjection`) · `Matched Data: s&sos found within ARGS:json.username: admin' OR '1'='1' --`<br>**2)** `2026-11-12T01:51:53.484Z` · `GET /api/tickets?q=soporte' OR '1'='1` · Regla **`942100`** · `Matched Data: s&sos found within ARGS:q: soporte' OR '1'='1` | `../assets/img/blue/02-regla-det-01-sqli.png` |
| **DET-02** | `DET-02 XSS` | `fields.fuente : "waf-audit" and modsec.transaction.messages.details.ruleId : 941*` | **PoC-02:** Inyección de scripts maliciosos (**XSS Almacenado y Reflejado**, `CWE-79`) en `POST /api/tickets` y `GET /api/tickets?q=`. | **1)** `2026-11-12T01:51:57.498Z` · `POST /api/tickets` · Reglas **`941100`, `941120`, `941160`, `941180`, `941390`** · `Matched Data: XSS data found within ARGS:json.description: <img src=x onerror=alert(document.cookie)>`<br>**2)** `2026-11-12T01:51:55.486Z` · `GET /api/tickets?q=<script>alert(document.cookie)</script>` · Reglas **`941100`, `941110`, `941160`** · `Matched Data: <script> found within ARGS:q` | `../assets/img/blue/03-regla-det-02-xss.png` |
| **DET-03** | `DET-03 Metodo` | `fields.fuente : "waf-audit" and modsec.transaction.messages.details.ruleId : 911100` | **PoC-03:** Invocación de métodos HTTP destructivos o fuera de política (`DELETE /api/tickets/:id`, `CWE-862` / escaneo de métodos). | `2026-11-12T01:21:24.353Z` (y `01:51:58Z`) · `DELETE /api/tickets/999` · Regla **`911100`** (`Method is not allowed by policy`) · `Matched Data: DELETE found within REQUEST_METHOD: DELETE` | `../assets/img/blue/04-regla-det-03-metodos.png` |
| **DET-04** | `DET-04 Bloqueo por Umbral de Anomalia (949110)` | `fields.fuente : "waf-audit" and modsec.transaction.messages.details.ruleId : 949110` | Peticiones ofensivas cuyo puntaje acumulado de anomalía (*Inbound Anomaly Score*) supera el umbral del CRS (`>= 5`). | Se dispara en conjunto con `942100`, `941100` y `911100` (`Inbound Anomaly Score Exceeded (Total Score: 5 / 25)`), siendo la regla que ejecuta el `HTTP 403` en modo `On`. | Exportada en `kibana-export.ndjson` |

### Consulta ES|QL Complementaria para Detección de Ráfagas / Escaneo por IP (ZAP / Fuerza Bruta)

Para detectar ráfagas de escaneo automatizado (como el spider/active scan de OWASP ZAP o intentos de fuerza bruta contra `/api/auth/login`), se utiliza en Discover (modo **ES|QL**) la siguiente consulta con umbral justificado de **20 eventos de auditoría por minuto por IP**:

```esql
FROM filebeat-*
| WHERE fields.fuente == "waf-audit"
| STATS eventos = COUNT(*) BY ip = modsec.transaction.client_ip, minuto = BUCKET(@timestamp, 1 minute)
| WHERE eventos > 20
| SORT eventos DESC
```

> **Justificación del umbral (`> 20 eventos/minuto`):** Un operador humano legítimo interactuando con el CRM genera entre 0 y 2 falsos positivos eventuales por minuto; una ráfaga superior a 20 alertas `waf-audit` en 60 segundos desde la misma IP corresponde inequívocamente a un escáner automatizado (ZAP/Burp Intruder) o a un ataque de diccionario.

---

## 3. Dashboard en Kibana: `WAF - Blue Team`

- **Nombre del objeto guardado:** `WAF - Blue Team` (ID: `waf-blue-team-dashboard`, incluido en [`waf-siem/kibana-export.ndjson`](../../waf-siem/kibana-export.ndjson)).
- **Paneles configurados (los 4 ejes de monitoreo del SOC):**
  1. **Tiempo (`@timestamp`):** Evolución temporal y conteo de eventos `waf-audit` y detecciones `DET-01 SQLi` (`942*`).
  2. **Reglas (`modsec.transaction.messages.details.ruleId` / `message`):** Distribución y top de reglas del OWASP CRS disparadas (`942100`, `941100`, `941160`, `911100`, `949110`) y panel `DET-02 XSS`.
  3. **Rutas (`modsec.transaction.request.uri`):** Top de endpoints atacados (`/api/auth/login`, `/api/tickets`, `/api/tickets/999`) y panel `DET-03 Metodo`.
  4. **Origen (`modsec.transaction.client_ip`):** Top de direcciones IP de origen del tráfico inspeccionado y resumen de anomalías `DET-04`.
- **Captura del Dashboard:** `../assets/img/blue/05-dashboard-waf.png`

---

## 4. Respuesta Activa (`MODSEC_RULE_ENGINE=On`) y Ajuste de Falsos Positivos (Exclusiones)

Al cambiar `MODSEC_RULE_ENGINE=On` en `waf-siem/.env` y aplicar `docker compose up -d waf`:
- Los ataques del Equipo Rojo (**PoC-01 SQLi**, **PoC-02 XSS** y **PoC-03 DELETE no autorizado**) son **bloqueados inmediatamente por el WAF con `HTTP 403 Forbidden`** antes de llegar al backend de Express (`../assets/img/blue/06-waf-403-bloqueo.png`).

### Análisis y Ajuste Quirúrgico de Falsos Positivos Detectados en Flujos Legítimos

Al probar la aplicación como un usuario legítimo con el WAF en modo `On`, se identificaron y ajustaron los siguientes falsos positivos aplicando el principio de **exclusión mínima** (sin desactivar el OWASP CRS ni excluir la regla de umbral `949110`):

| Regla CRS Disparada | Ruta y Parámetro (`found within`) | Tipo y Qué se Excluyó | Por qué el Tráfico es Legítimo | Riesgo Aceptado por el Equipo Azul | Archivo donde se Configuró |
|---|---|---|---|---|---|
| **`920350`** *(El encabezado Host es una dirección IP numérica)* | Todas las rutas locales · `REQUEST_HEADERS:Host` (`127.0.0.1:8080`) | **Tipo 1 (Pre-CRS, `id:10001`):** `ctl:ruleRemoveTargetById=920350;REQUEST_HEADERS:Host` condicionada a `^127\.0\.0\.1(?::\d+)?$` | En el entorno local de pruebas, las herramientas y scripts de verificación invocan al WAF usando la IP de loopback `127.0.0.1:8080` en lugar de un dominio FQDN. | Las peticiones cuyo header `Host` sea `127.0.0.1` no suman puntos por la regla `920350`; cualquier otra IP en `Host` y todas las demás reglas del CRS siguen evaluándose. | `waf-siem/waf/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf` |
| **`942100`** *(SQL Injection Attack Detected via libinjection)* *(El bloqueo 403 lo dispara `949110`, que se mantiene activo)* | `/api/tickets` · `ARGS:json.description` | **Tipo 1 (Pre-CRS, `id:10010`):** `SecRule REQUEST_URI "@beginsWith /api/tickets"` con `ctl:ruleRemoveTargetById=942100;ARGS:json.description` | Los agentes de soporte crean y actualizan tickets en `/api/tickets` cuyo campo `description` es texto libre donde se documentan mensajes de error técnicos, comillas, guiones (`--`) o palabras clave en inglés (`select`, `from`, `or`) que `libinjection` clasifica erróneamente como SQLi. | En `/api/tickets`, el campo `ARGS:json.description` ya no es evaluado por la regla `942100` (además, en la API `description` se inserta como valor y no en una cláusula `WHERE` concatenada). **Verificación cruzada:** Un payload XSS en `ARGS:json.description` (`<img src=x onerror=...>`) **sigue dando `403`** por `941100`, y un payload SQLi en `ARGS:q` (`GET /api/tickets?q=`) o en `ARGS:json.username` (`POST /api/auth/login`) **sigue dando `403`** por `942100`. | `waf-siem/waf/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf` |
| **`911100`** *(Method is not allowed by policy)* | `/api/tickets/:id` y `/api/users/:id/role` · `REQUEST_METHOD` (`PUT`, `DELETE`) | **Tipo 4 (Variable de entorno CRS):** Se actualizó `ALLOWED_METHODS=GET HEAD POST OPTIONS PUT DELETE` en `waf-siem/.env` y se recreó el contenedor con `docker compose up -d waf`. | La API REST de **Secure CRM** utiliza legítimamente el método `PUT` para editar tickets (`PUT /api/tickets/:id`) y cambiar roles (`PUT /api/users/:id/role`), así como `DELETE` para dar de baja tickets (`DELETE /api/tickets/:id`). Por defecto el CRS solo permite `GET HEAD POST OPTIONS`. | El WAF permite el paso de verbos `PUT` y `DELETE` hacia la API (inspeccionando igualmente sus parámetros y cuerpo con todas las reglas `941*`, `942*`, etc.), mientras que la regla `911100` permanece activa para bloquear cualquier otro método HTTP no utilizado por la aplicación (`PATCH`, `TRACE`, `CONNECT`, `PROPFIND`). | `waf-siem/.env` (`ALLOWED_METHODS`) |

### Regla `id:10010` implementada en `REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf`

```apache
SecRule REQUEST_URI "@beginsWith /api/tickets" \
    "id:10010,phase:1,pass,nolog,\
    ctl:ruleRemoveTargetById=942100;ARGS:json.description"
```

---

## 5. Guion de la Demo en Vivo (Purple Team: Red Team + Blue Team)

- **PoC acordado para repetir en vivo:** **PoC-01 (Bypass de Login por Inyección SQL en `POST /api/auth/login`)** y **PoC-02 (XSS en `POST /api/tickets`)**.
- **Hora acordada / Ventana de filtro en Kibana:** Últimos 15 minutos (`Last 15 minutes` en Kibana Discover).
- **Secuencia paso a paso de la demostración (4 minutos):**
  1. **Paso 1 — Ataque y Detección en SIEM (`DetectionOnly`):**
     - El **Equipo Rojo** envía desde Postman (`SecureCRM-WAF`) el request `SQLi en el login` con `{"username": "admin' OR '1'='1' --", "password": "x"}` a `http://localhost:8080/api/auth/login` y muestra cómo la aplicación vulnerable responde `200 OK` entregando el token de `admin`.
     - El **Equipo Azul** abre en Kibana (`http://localhost:5601`) la regla guardada **`DET-01 SQLi`** y el dashboard **`WAF - Blue Team`**, expande el documento recién llegado y muestra en vivo los tres campos clave:
       - `modsec.transaction.request.uri`: `/api/auth/login`
       - `modsec.transaction.messages.details.ruleId`: `942100`
       - `modsec.transaction.messages.details.data`: `Matched Data: s&sos found within ARGS:json.username: admin' OR '1'='1' --`
  2. **Paso 2 — Bloqueo Activo en el WAF (`MODSEC_RULE_ENGINE=On`):**
     - El **Equipo Azul** activa `MODSEC_RULE_ENGINE=On` en `waf-siem/.env` y ejecuta `docker compose up -d waf`.
     - El **Equipo Rojo** repite exactamente el mismo envío en Postman y recibe **`HTTP 403 Forbidden`** de `nginx / ModSecurity`.
  3. **Paso 3 — Demostración de Tráfico Legítimo y Exclusión de Falso Positivo:**
     - Se envía desde Postman una petición legítima de login (`jperez` / `Password1`) y la creación/edición de un ticket con texto técnico en `description`, comprobando que responden **`200 OK` / `201 Created`** gracias a la exclusión quirúrgica `id:10010` y `ALLOWED_METHODS`, mientras el ataque SQLi en login y el XSS en `description` continúan bloqueados con **`403 Forbidden`**.
