// Prueba de regresión · PoC-01 · SQL Injection (A05:2025 / CWE-89)
// Corrección: commit d10aee3 (consultas parametrizadas en el login y en la
// búsqueda) y 865d704 (la contraseña se verifica en código con PBKDF2).
//
// Comando: node --test tests/regresion/sql-injection.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { api, login, detalle } from './helpers.mjs';

test("PoC-01: el login con  admin' OR '1'='1' --  responde 401 y no entrega token", async () => {
  const res = await api('/api/auth/login', {
    method: 'POST',
    body: { username: "admin' OR '1'='1' --", password: 'x' },
  });
  assert.equal(res.status, 401, `El bypass del login sigue funcionando: ${detalle(res)}`);
  assert.equal(res.json?.token, undefined, 'La respuesta no debe incluir un token');
});

test('PoC-01: una comilla suelta no rompe la consulta ni filtra el SQL (CWE-209)', async () => {
  // Antes, la comilla cerraba el literal, SQLite fallaba y la API respondía 500
  // con los campos "sql" y "detail" (la consulta completa y el error del motor).
  const res = await api('/api/auth/login', { method: 'POST', body: { username: "'", password: 'x' } });
  assert.equal(res.status, 401, `La comilla alteró la consulta: ${detalle(res)}`);
  assert.equal(res.json?.sql, undefined, 'La respuesta no debe incluir el SQL');
  assert.equal(res.json?.detail, undefined, 'La respuesta no debe incluir el error del motor');
});

test('PoC-01/02: la búsqueda de tickets trata la inyección como texto literal', async () => {
  const token = await login('agent');
  // Antes:  WHERE t.title LIKE '%zzz' OR 1=1 --%' ...  devolvía todos los tickets.
  // Ahora el término viaja como parámetro y ningún ticket contiene ese texto.
  const payload = "zzz' OR 1=1 --";
  const res = await api(`/api/tickets?q=${encodeURIComponent(payload)}`, { token });
  assert.equal(res.status, 200, detalle(res));
  assert.equal(
    res.json.tickets.length,
    0,
    `La inyección en ?q= devolvió ${res.json.tickets.length} tickets (debía tratarse como texto)`
  );
});
