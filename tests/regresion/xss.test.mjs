// Prueba de regresión · PoC-02 · Cross-Site Scripting (A05:2025 / CWE-79)
// y cookie de sesión legible desde JavaScript (CWE-1004).
// Corrección: commit d10aee3 (React escapa el contenido, sin
// dangerouslySetInnerHTML; cookie HttpOnly) y 865d704 (cabeceras de seguridad).
//
// Comando: node --test tests/regresion/xss.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, dirname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { api, CUENTAS, detalle } from './helpers.mjs';

const RAIZ = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const PAGINAS_WEB = join(RAIZ, 'apps', 'web', 'app');

function archivosTsx(dir) {
  return readdirSync(dir).flatMap((nombre) => {
    const ruta = join(dir, nombre);
    if (statSync(ruta).isDirectory()) return archivosTsx(ruta);
    return /\.(t|j)sx$/.test(nombre) ? [ruta] : [];
  });
}

test('PoC-02: las páginas de la web no renderizan datos como HTML crudo (dangerouslySetInnerHTML)', () => {
  // El XSS reflejado (término de búsqueda) y el almacenado (título y descripción)
  // ocurrían porque la web pintaba esos datos con dangerouslySetInnerHTML.
  const usos = [];
  for (const archivo of archivosTsx(PAGINAS_WEB)) {
    readFileSync(archivo, 'utf8')
      .split('\n')
      .forEach((linea, i) => {
        if (/dangerouslySetInnerHTML\s*=/.test(linea)) usos.push(`${relative(RAIZ, archivo)}:${i + 1}`);
      });
  }
  assert.deepEqual(usos, [], `Puntos de XSS encontrados:\n  ${usos.join('\n  ')}`);
});

test('PoC-02: la cookie de sesión es HttpOnly y SameSite=Strict', async () => {
  const res = await api('/api/auth/login', { method: 'POST', body: CUENTAS.agent });
  assert.equal(res.status, 200, detalle(res));
  const cookie = res.headers.get('set-cookie') || '';
  assert.match(cookie, /session=/, 'El login debe emitir la cookie session');
  assert.match(cookie, /;\s*HttpOnly/i, `La cookie se puede leer desde JavaScript: ${cookie.slice(-80)}`);
  assert.match(cookie, /;\s*SameSite=Strict/i, `La cookie viaja en peticiones de otros sitios: ${cookie.slice(-80)}`);
});

test('PoC-02: la API envía cabeceras de defensa (CSP, nosniff, X-Frame-Options) y no anuncia Express', async () => {
  const res = await api('/api/health');
  assert.equal(res.status, 200, detalle(res));
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff', 'Falta X-Content-Type-Options: nosniff');
  assert.equal(res.headers.get('x-frame-options'), 'DENY', 'Falta X-Frame-Options: DENY');
  assert.match(res.headers.get('content-security-policy') || '', /default-src 'none'/, 'Falta Content-Security-Policy');
  assert.equal(res.headers.get('x-powered-by'), null, `La API anuncia X-Powered-By: ${res.headers.get('x-powered-by')}`);
});
