# Hito 4 · Remediación con IA

Las correcciones viven en el código de la aplicación (commits en `main`), no solo en el WAF. Se corrigieron **las cuatro vulnerabilidades explotadas por el Equipo Rojo** en el [Hito 2](../hito-2/README.md) (PoC-01 a PoC-04).

## Uso de IA (guía de la UVG)

| Campo | Detalle |
|---|---|
| **Herramienta** | Claude Code (modelo Claude Opus 5.5, Anthropic), extensión de VS Code, con acceso de lectura y escritura al repositorio local |
| **Quién la usó** | Sofía Velásquez (Equipo Azul) |
| **Fecha** | 2026-11-19 / 2026-11-20 |
| **Commits generados con IA** | [`d10aee3`](https://github.com/andreetoledo-org/secure-crm-proyecto-final/commit/d10aee3) · [`9015244`](https://github.com/andreetoledo-org/secure-crm-proyecto-final/commit/9015244) · [`865d704`](https://github.com/andreetoledo-org/secure-crm-proyecto-final/commit/865d704). Los tres llevan la línea `Co-Authored-By: Claude Opus 5.5` |

### Prompts usados

Se usaron dos prompts en la misma conversación, después de que el asistente ya tenía el contexto del proyecto (Hitos 1 a 3):

```text
Prompt 1:
Bueno hagamos el hito 4 remediación, hagamos el 1 que es el de corregir al menos 2
vulnerabilidades, entonces quiero que corrijas todas las vulnerabilidades que el equipo
rojo explotó de nuestro proyecto. Remediación con IA: Corregir en el código de la
aplicación, con ayuda de un asistente de IA, y auditar lo generado antes de integrarlo.
Corregir al menos 2 vulnerabilidades: Elijan hallazgos que el Equipo rojo haya
explotado. La corrección vive en el código de la aplicación.
```

```text
Prompt 2:
Quiero hacer cómo los fix, en 2 o 3 commits, entonces corrige 1 y luego me das el
texto del commit y lo subo y así para completar los cambios de corregir las
vulnerabilidades.
```

### Cómo trabajó la IA (resumen de la respuesta)

1. **Leyó el código vulnerable** antes de proponer cambios: `apps/api/src/auth.ts`, `middleware/auth.ts`, `hash.ts`, `routes/tickets.ts`, `routes/users.ts`, `index.ts` y las páginas de tickets de la web. Para cada PoC identificó la causa raíz (ver las correcciones abajo).
2. **Revisó el Hito 1** para que la corrección cumpliera lo que el diseño ya había prometido: PBKDF2-SHA512 (RS-04), `jwt.verify` con HS256 y `401` ante un token alterado (CA-04), `403` por rol (CA-03) y CSP (RS-02).
3. **Propuso las correcciones agrupadas en 3 commits** y entregó, para cada uno, el mensaje de commit. El grupo hizo el `commit` y el `push`.
4. **Verificó que compilara:** `tsc` de la API y de `shared`, y `tsc --noEmit` de la web, sin errores en los tres commits. También comprobó manualmente que `verifyPassword` acepta la contraseña correcta y rechaza una incorrecta y un hash MD5 antiguo.
5. **No agregó dependencias nuevas.** PBKDF2, `timingSafeEqual` y `randomBytes` vienen del módulo nativo `crypto` de Node.

### Qué aceptó y qué descartó el grupo

| Propuesta de la IA | Decisión del grupo |
|---|---|
| Correcciones de PoC-01 a PoC-04 en el código | ✅ **Aceptadas** |
| Entregar todo en un único cambio grande | ❌ **Descartado.** El grupo revirtió ese primer intento y pidió dividirlo en 3 commits por tema (prompt 2) para que cada uno se pueda revisar y re-probar por separado |
| Pruebas de regresión automáticas (`sql-injection.test.mjs`, `access-control.test.mjs`) | ❌ **Descartadas en este paso.** La prueba de regresión y la re-prueba le corresponden al Equipo Rojo |
| Auditoría SAST local con Semgrep ejecutada por la IA | ❌ **Interrumpida por el grupo.** La auditoría la realiza el Equipo Rojo (ver más abajo) |
| `.env.example`: quitar `JWT_SECRET=secret123` | ✅ Aceptado. El grupo además quitó por su cuenta las variables del WAF (`WAF_PORT`, `MODSEC_RULE_ENGINE`) que estaban mal ubicadas en ese archivo |

---

## Corrección 1 · SQL Injection en el login y en la búsqueda (PoC-01)

- **Vulnerabilidad:** [PoC-01 · SQLi en `POST /api/auth/login`](../hito-2/README.md#poc-01--inyección-sql-sqli-en-el-login-cwe-89) (`A05:2025` / `CWE-89`, CVSS 9.8). Incluye el vector SQLi de `GET /api/tickets?q=` del PoC-02.
- **Commit:** `d10aee3`. *fix(hito-4): corregir inyeccion SQL en login y busqueda y XSS en tickets (PoC-01, PoC-02)*
- **Causa raíz:** el SQL se armaba concatenando la entrada del usuario.

```ts
// Antes — apps/api/src/auth.ts
const sql = `SELECT * FROM users WHERE username = '${username}' AND password_hash = '${hashed}'`;
row = db.prepare(sql).get();

// Después (commit d10aee3 + 865d704)
const row = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
const passwordOk = verifyPassword(password, row?.password_hash ?? DUMMY_HASH);
```

| Archivo | Cambio |
|---|---|
| `apps/api/src/auth.ts` | Consulta parametrizada (`?`). Valida que `username` y `password` sean texto. El error ya no devuelve el SQL ni el mensaje del motor (`CWE-209`) |
| `apps/api/src/routes/tickets.ts` | La búsqueda `?q=` usa un parámetro con nombre (`LIKE @like`) en lugar de interpolar el término |

**Resultado esperado:** `{"username": "admin' OR '1'='1' --", "password": "x"}` devuelve `401 Credenciales inválidas`, aunque el WAF esté en `DetectionOnly`.

---

## Corrección 2 · Cross-Site Scripting reflejado y almacenado (PoC-02)

- **Vulnerabilidad:** [PoC-02 · XSS en la búsqueda de tickets](../hito-2/README.md#poc-02--cross-site-scripting-xss-reflejado-en-la-búsqueda-de-tickets-cwe-79) (`A05:2025` / `CWE-79`, CVSS 5.4), más la variante almacenada en la descripción.
- **Commits:** `d10aee3` (código) y `865d704` (cabeceras de defensa en profundidad)
- **Causa raíz:** React mostraba datos del usuario como HTML crudo con `dangerouslySetInnerHTML`, y la cookie de sesión era legible desde JavaScript.

```tsx
// Antes — apps/web/app/tickets/[id]/page.tsx
<div className="text-sm text-ink" dangerouslySetInnerHTML={{ __html: t.description }} />

// Después: React escapa el contenido
<div className="whitespace-pre-wrap break-words text-sm text-ink">{t.description}</div>
```

| Archivo | Cambio |
|---|---|
| `apps/web/app/tickets/page.tsx` | El término buscado y el título del ticket se muestran como texto (2 `dangerouslySetInnerHTML` eliminados) |
| `apps/web/app/tickets/[id]/page.tsx` | La descripción se muestra como texto (1 `dangerouslySetInnerHTML` eliminado) |
| `apps/api/src/auth.ts` | Cookie `session` con `HttpOnly`, `SameSite=strict` y `Secure` en producción (`CWE-1004`) |
| `apps/web/next.config.mjs` | `Content-Security-Policy` (`object-src 'none'`, `frame-ancestors 'none'`, `base-uri 'self'`…), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, sin `X-Powered-By` (alertas ZAP 10038, 10020, 10021 y 10037 del Hito 2) |

**Resultado esperado:** `<script>alert(1)</script>` en `?q=` o `<img src=x onerror=…>` en la descripción se muestran como texto literal y no se ejecutan.

**Limitación conocida:** la CSP incluye `'unsafe-inline'` en `script-src`, necesario para los scripts de hidratación de Next.js sin nonce. La defensa principal es el escape de React. El token sigue guardado también en `localStorage` (`apps/web/lib/api.ts`), lo cual queda como **riesgo residual**.

---

## Corrección 3 · Control de acceso roto: IDOR y DELETE sin rol (PoC-03)

- **Vulnerabilidad:** [PoC-03 · IDOR y eliminación no autorizada](../hito-2/README.md) (`A01:2025` / `CWE-639`, `CWE-862`, CVSS 8.1)
- **Commit:** `9015244`. *fix(hito-4): verificar firma JWT y aplicar control de acceso por rol en tickets y usuarios (PoC-03, PoC-04)*
- **Causa raíz:** ninguna ruta validaba el rol ni la propiedad del recurso.

| Rol | Antes | Después |
|---|---|---|
| `viewer` | Leía, creaba, editaba y **eliminaba** cualquier ticket | Solo lee **sus propios** tickets. Un ticket ajeno responde `404`, para no confirmar que el id existe. Crear, editar o eliminar responde `403` |
| `agent` | Igual que admin | Lee, crea y edita. **No** elimina (`403`) |
| `admin` | — | Todo |

| Archivo | Cambio |
|---|---|
| `apps/api/src/middleware/auth.ts` | Nuevo middleware `requireRole(...roles)` que responde `403` |
| `apps/api/src/routes/tickets.ts` | `requireRole` en `POST`, `PUT` y `DELETE`. Filtro por `created_by_id` para el viewer. Lista blanca de campos y valores (`status`, `priority`, `assigneeId`) contra mass assignment (`CWE-915`) |
| `apps/api/src/routes/users.ts` | Crear usuarios y cambiar roles es solo para admin. El rol se valida contra lista blanca (antes cualquiera podía crearse una cuenta `admin`). `GET /api/users/:id` solo para admin o el propio usuario |

**Resultado esperado:** `DELETE /api/tickets/1` con el token de `viewer` responde `403` y el ticket sigue existiendo. `GET /api/tickets/1` con ese token responde `404`.

---

## Corrección 4 · JWT sin verificar firma y exposición de hashes MD5 (PoC-04)

- **Vulnerabilidad:** [PoC-04 · JWT forjado + fuga de hashes](../hito-2/README.md) (`A07:2025` / `CWE-347`, `CWE-327`, `CWE-256`, CVSS 6.5)
- **Commits:** `9015244` (JWT y `/api/users`) y `865d704` (PBKDF2)
- **Causa raíz:** `jwt.decode` ignora la firma; el secreto `secret123` estaba publicado en el repo; `/api/users` no exigía rol y devolvía `passwordHash` en MD5 sin salt.

```ts
// Antes — apps/api/src/middleware/auth.ts
const payload = jwt.decode(token) as any;   // la firma se ignora

// Después
const verified = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
// + el rol se lee de la tabla users, no del token
```

| Archivo | Cambio |
|---|---|
| `apps/api/src/middleware/auth.ts` | `jwt.verify` solo con HS256 (rechaza `alg: none` y firmas inválidas con `401`). El rol se consulta en la base de datos en cada petición, así que un cambio de rol aplica de inmediato |
| `apps/api/src/config.ts` *(nuevo)* | `JWT_SECRET` se toma del entorno. Si falta o tiene menos de 32 caracteres, se genera uno aleatorio en cada arranque. Se eliminó `secret123` (`CWE-798`) |
| `apps/api/src/auth.ts` | El token se firma con HS256 y expira en 8 h |
| `apps/api/src/routes/users.ts` | `GET /api/users` solo para admin y **sin `passwordHash`** |
| `apps/api/src/hash.ts` | MD5 sin salt reemplazado por **PBKDF2-SHA512**, con salt aleatorio de 16 bytes, 210 000 iteraciones y `timingSafeEqual` (`CWE-327`, `CWE-759`) |
| `apps/api/src/auth.ts` | Si el usuario no existe se verifica contra un hash de relleno, para que el tiempo de respuesta no revele qué usuarios existen |
| `docker-compose.yml`, `.env.example` | Sin secreto JWT fijo |
| `packages/shared/src/index.ts` | `passwordHash` eliminado del tipo `User` |

**Resultado esperado:** el request `PoC-04 JWT forjado` de Postman responde `401 Token inválido`. Con un token válido de `viewer` o `agent`, `GET /api/users` responde `403`.

---

## Cambios adicionales de endurecimiento (commit `865d704`)

- `apps/api/src/index.ts`: CORS limitado a `CORS_ORIGINS` (por defecto `http://localhost:3000`), cuando antes reflejaba cualquier origen con credenciales (`CWE-942`). Cabeceras `nosniff`, `X-Frame-Options` y CSP en la API. Sin `X-Powered-By`. El manejador de errores ya no devuelve `message` ni `stack` (`CWE-209`).
- `apps/web/lib/api.ts`: la web ya no muestra `Unexpected token '<'` cuando el WAF responde un 403 en HTML (falso positivo documentado en el [Hito 3](../hito-3/README.md)).

## Cambios de comportamiento para quien pruebe

- `docker compose up -d --build`: el seed vuelve a crear las contraseñas con PBKDF2. Las cuentas de prueba no cambian.
- Los tokens emitidos antes del cambio dejan de servir (otro secreto y otra verificación): hay que volver a hacer login.
- El viewer ya no ve tickets ajenos. Para editar o borrar desde la web hay que usar `jperez` (agent) o `admin`.
- Crear un usuario nuevo exige una contraseña de al menos 8 caracteres.

---

## Pendiente del Equipo Rojo

> Se completa después de la re-prueba. Repetir cada PoC con el WAF en **`DetectionOnly`**: el ataque tiene que fallar **por el código**, no por un 403 del WAF.

### Prueba de regresión

| PoC | Prueba (nombre y comando) | Falla antes de la corrección | Pasa después |
|---|---|---|---|
| PoC-01 | | | |
| PoC-02 | | | |
| PoC-03 | | | |
| PoC-04 | | | |

### Auditoría del código generado

- [ ] SAST del pipeline corrido sobre este código, sin excluirlo. Resultado:
- [ ] Revisión manual con la checklist de la Lectura 10. Hallazgos:
- [ ] Cada dependencia nueva existe en el repositorio oficial (no es slopsquatting). *Nota: estos commits no agregan dependencias a `package.json` ni a `pnpm-lock.yaml`; verificar.*
- [ ] No se introdujeron secretos. *Nota: se eliminó `secret123`; verificar que no haya otros.*

### Re-prueba del Equipo Rojo

| PoC | Modo del WAF | Fecha y hora | Resultado esperado | Resultado obtenido | Captura |
|---|---|---|---|---|---|
| PoC-01 SQLi login | DetectionOnly | | `401` | | |
| PoC-02 XSS búsqueda y descripción | DetectionOnly | | Se muestra como texto, no ejecuta | | |
| PoC-03 IDOR (GET como viewer) | DetectionOnly | | `404` | | |
| PoC-03 DELETE como viewer | DetectionOnly | | `403`, el ticket sigue existiendo | | |
| PoC-04 JWT forjado | DetectionOnly | | `401` | | |

- **¿El pipeline pasa?** (enlace a la corrida de GitHub Actions):
