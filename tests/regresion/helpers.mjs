// Utilidades compartidas por las pruebas de regresión del Hito 4.
//
// Las pruebas repiten los PoC del Hito 2 contra la instancia local, igual que
// el Equipo Rojo en Burp: por defecto pasan por el WAF (http://localhost:8080),
// que debe estar en DetectionOnly para que el resultado dependa del código.
// Se puede apuntar a otra URL con la variable de entorno BASE_URL.
//
// Solo usan módulos nativos de Node (node:test, fetch): no agregan dependencias.

export const BASE_URL = (process.env.BASE_URL || 'http://localhost:8080').replace(/\/$/, '');

// Cuentas semilla de apps/api/src/seed.ts (solo existen en la instancia local).
export const CUENTAS = {
  admin: { username: 'admin', password: 'Admin123!' },
  agent: { username: 'jperez', password: 'Password1' },
  viewer: { username: 'viewer', password: 'viewer' },
};

export async function api(path, { method = 'GET', token, body } = {}) {
  const headers = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (token) headers.Authorization = `Bearer ${token}`;

  const res = await fetch(`${BASE_URL}${path}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    json = undefined; // p. ej. una página HTML de nginx si el WAF bloquea
  }
  return { status: res.status, headers: res.headers, json, text };
}

export async function login(cuenta) {
  const res = await api('/api/auth/login', { method: 'POST', body: CUENTAS[cuenta] });
  if (res.status !== 200 || !res.json?.token) {
    throw new Error(
      `No se pudo iniciar sesión como ${CUENTAS[cuenta].username} (HTTP ${res.status}). ` +
        `¿La app está levantada y recién sembrada en ${BASE_URL}?`
    );
  }
  return res.json.token;
}

// Muestra el código y el cuerpo de la respuesta en el mensaje de error.
export function detalle(res) {
  return `HTTP ${res.status} · ${res.text.slice(0, 300)}`;
}
