import { Router } from 'express';
import jwt from 'jsonwebtoken';
import { db } from './db';
import { weakHash } from './hash';
import { JWT_ALGORITHM, JWT_EXPIRES_IN, JWT_SECRET } from './config';

export const authRouter = Router();

function toUser(row: any) {
  return {
    id: row.id,
    username: row.username,
    email: row.email,
    fullName: row.full_name,
    role: row.role,
    createdAt: row.created_at,
  };
}

// POST /api/auth/login
// Sin rate limiting ni bloqueo de cuenta (A07 / CWE-307): permite fuerza bruta.
// Hito 4 (PoC-01 / CWE-89): la consulta usa parámetros (?) en lugar de
// concatenar los valores en el SQL. Un usuario como  admin' OR '1'='1' --
// se compara como texto literal, no existe y la respuesta es 401.
authRouter.post('/login', (req, res) => {
  const { username, password } = req.body ?? {};
  if (typeof username !== 'string' || typeof password !== 'string' || !username || !password) {
    return res.status(400).json({ error: 'Usuario y contraseña son obligatorios' });
  }

  const hashed = weakHash(password);
  const row = db
    .prepare('SELECT * FROM users WHERE username = ? AND password_hash = ?')
    .get(username, hashed) as any;

  if (!row) {
    return res.status(401).json({ error: 'Credenciales inválidas' });
  }

  const user = toUser(row);
  // Hito 4 (PoC-04): token firmado con el secreto de config.ts, algoritmo fijo
  // HS256 y expiración de 8 horas.
  const token = jwt.sign({ sub: user.id, username: user.username, role: user.role }, JWT_SECRET, {
    algorithm: JWT_ALGORITHM,
    expiresIn: JWT_EXPIRES_IN,
  });

  // Hito 4 (PoC-02 / CWE-1004): la cookie de sesión ya no es legible desde
  // JavaScript (HttpOnly), así un XSS no puede robarla, y no viaja en
  // peticiones de otros sitios (SameSite).
  res.cookie('session', token, {
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production',
  });

  res.json({ token, user });
});
