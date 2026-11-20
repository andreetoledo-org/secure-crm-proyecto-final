import crypto from 'crypto';

// Hito 4 (PoC-04 / CWE-798, CWE-521): el secreto JWT ya no tiene un valor por
// defecto conocido ('secret123' estaba publicado en el repositorio y permitía
// firmar tokens válidos). Se toma de la variable de entorno JWT_SECRET; si no
// existe o es corto, se genera uno aleatorio en cada arranque (los tokens
// emitidos antes del reinicio dejan de ser válidos, lo cual es seguro).
const MIN_SECRET_LENGTH = 32;

function loadJwtSecret(): string {
  const fromEnv = process.env.JWT_SECRET;
  if (fromEnv && fromEnv.length >= MIN_SECRET_LENGTH) return fromEnv;
  console.warn(
    `[seguridad] JWT_SECRET ausente o menor a ${MIN_SECRET_LENGTH} caracteres: ` +
      'se usa un secreto aleatorio para este arranque.'
  );
  return crypto.randomBytes(48).toString('hex');
}

export const JWT_SECRET = loadJwtSecret();
export const JWT_ALGORITHM = 'HS256' as const;
export const JWT_EXPIRES_IN = '8h';
