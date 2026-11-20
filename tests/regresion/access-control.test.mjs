// Prueba de regresión · PoC-03 · IDOR y falta de autorización (A01:2025 / CWE-639, CWE-862)
// y PoC-04 · JWT sin verificar y fuga de hashes (A07:2025 / CWE-347, CWE-256).
// Corrección: commit 9015244 (jwt.verify con HS256, requireRole, filtro por
// propietario, /api/users solo admin y sin passwordHash) y 865d704 (PBKDF2).
//
// Comando: node --test tests/regresion/access-control.test.mjs
// Correr contra una instancia recién sembrada: el ticket 1 es del admin.

import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { api, login, detalle } from './helpers.mjs';

const b64url = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');
const PAYLOAD_ADMIN = { sub: 1, username: 'admin', role: 'admin' };

// Mismo token del PoC-04 del Hito 2: payload de admin y firma inválida.
const TOKEN_FIRMA_INVALIDA = `${b64url({ alg: 'HS256', typ: 'JWT' })}.${b64url(PAYLOAD_ADMIN)}.firma_invalida`;
// Variante sin firma (alg: none).
const TOKEN_ALG_NONE = `${b64url({ alg: 'none', typ: 'JWT' })}.${b64url(PAYLOAD_ADMIN)}.`;

describe('PoC-03 · control de acceso por rol y propiedad', () => {
  test('un viewer no puede leer un ticket ajeno (404)', async () => {
    const viewer = await login('viewer');
    const res = await api('/api/tickets/1', { token: viewer });
    assert.equal(res.status, 404, `El viewer leyó el ticket 1 del admin (IDOR): ${detalle(res)}`);
  });

  test('un viewer no puede eliminar un ticket (403) y el ticket sigue existiendo', async () => {
    const viewer = await login('viewer');
    const res = await api('/api/tickets/1', { method: 'DELETE', token: viewer });
    assert.equal(res.status, 403, `El viewer pudo eliminar el ticket 1: ${detalle(res)}`);

    const admin = await login('admin');
    const sigue = await api('/api/tickets/1', { token: admin });
    assert.equal(sigue.status, 200, `El ticket 1 ya no existe: ${detalle(sigue)}`);
  });

  test('un viewer no puede crear tickets (403)', async () => {
    const viewer = await login('viewer');
    const res = await api('/api/tickets', {
      method: 'POST',
      token: viewer,
      body: { title: 'regresion-viewer', description: 'no debería crearse' },
    });
    assert.equal(res.status, 403, `El viewer pudo crear un ticket: ${detalle(res)}`);
  });
});

describe('PoC-04 · verificación del JWT y exposición de hashes', () => {
  test('un token con firma inválida responde 401', async () => {
    const res = await api('/api/users', { token: TOKEN_FIRMA_INVALIDA });
    assert.equal(res.status, 401, `Se aceptó un token con firma inválida: ${detalle(res)}`);
  });

  test('un token sin firma (alg: none) responde 401', async () => {
    const res = await api('/api/users', { token: TOKEN_ALG_NONE });
    assert.equal(res.status, 401, `Se aceptó un token sin firma: ${detalle(res)}`);
  });

  test('un viewer no puede listar usuarios (403)', async () => {
    const viewer = await login('viewer');
    const res = await api('/api/users', { token: viewer });
    assert.equal(res.status, 403, `El viewer listó los usuarios: ${detalle(res)}`);
  });

  test('el admin lista usuarios sin passwordHash', async () => {
    const admin = await login('admin');
    const res = await api('/api/users', { token: admin });
    assert.equal(res.status, 200, detalle(res));
    const conHash = res.json.filter((u) => 'passwordHash' in u).map((u) => u.username);
    assert.deepEqual(conHash, [], `La API devuelve el hash de: ${conHash.join(', ')}`);
  });
});
