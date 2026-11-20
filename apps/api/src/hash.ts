import crypto from 'crypto';

// Hito 4 (PoC-04 / CWE-327, CWE-759): se reemplaza MD5 sin salt por
// PBKDF2-SHA512 con salt aleatorio por usuario (RS-04 del Hito 1).
// Usa solo el módulo nativo 'crypto' de Node: no agrega dependencias.
// Formato almacenado: pbkdf2-sha512$<iteraciones>$<salt hex>$<hash hex>
const ALGORITHM = 'pbkdf2-sha512';
const ITERATIONS = 210_000; // recomendación OWASP Password Storage Cheat Sheet para PBKDF2-HMAC-SHA512
const KEY_LENGTH = 64;
const SALT_BYTES = 16;

export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(SALT_BYTES);
  const hash = crypto.pbkdf2Sync(password, salt, ITERATIONS, KEY_LENGTH, 'sha512');
  return `${ALGORITHM}$${ITERATIONS}$${salt.toString('hex')}$${hash.toString('hex')}`;
}

export function verifyPassword(password: string, stored: string): boolean {
  const parts = String(stored ?? '').split('$');
  if (parts.length !== 4 || parts[0] !== ALGORITHM) return false;
  const iterations = Number(parts[1]);
  if (!Number.isInteger(iterations) || iterations < 1) return false;
  const salt = Buffer.from(parts[2], 'hex');
  const expected = Buffer.from(parts[3], 'hex');
  if (expected.length === 0) return false;
  const actual = crypto.pbkdf2Sync(password, salt, iterations, expected.length, 'sha512');
  return crypto.timingSafeEqual(expected, actual);
}

// Hash de relleno: se verifica contra él cuando el usuario no existe, para que
// el tiempo de respuesta no revele qué usuarios existen (enumeración).
export const DUMMY_HASH = hashPassword(crypto.randomBytes(16).toString('hex'));
