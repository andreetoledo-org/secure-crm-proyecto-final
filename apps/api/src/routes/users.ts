import { Router } from 'express';
import { db } from '../db';
import { weakHash } from '../hash';
import { authenticate, requireRole, AuthedRequest } from '../middleware/auth';

export const usersRouter = Router();
usersRouter.use(authenticate);

const ROLES = ['admin', 'agent', 'viewer'];
const MIN_PASSWORD_LENGTH = 8;

// Hito 4 (PoC-04 / CWE-256): el hash de la contraseña NUNCA sale de la API.
function toPublicUser(r: any) {
  return {
    id: r.id,
    username: r.username,
    email: r.email,
    fullName: r.full_name,
    role: r.role,
    createdAt: r.created_at,
  };
}

// GET /api/users  (Hito 4, PoC-04 / CWE-862: solo admin y sin hashes)
usersRouter.get('/', requireRole('admin'), (_req, res) => {
  const rows = db.prepare('SELECT * FROM users ORDER BY id').all() as any[];
  res.json(rows.map(toPublicUser));
});

// GET /api/users/:id  (Hito 4: solo admin o el propio usuario; antes IDOR)
usersRouter.get('/:id', (req: AuthedRequest, res) => {
  const id = Number(req.params.id);
  if (req.user!.role !== 'admin' && req.user!.sub !== id) {
    return res.status(403).json({ error: 'No autorizado para esta acción' });
  }
  const r = db.prepare('SELECT * FROM users WHERE id = ?').get(id) as any;
  if (!r) return res.status(404).json({ error: 'Usuario no encontrado' });
  res.json(toPublicUser(r));
});

// POST /api/users
// Hito 4 (CWE-915 / CWE-269): solo admin crea usuarios y el rol se valida contra
// una lista blanca; antes cualquiera podía crear una cuenta con "role":"admin".
usersRouter.post('/', requireRole('admin'), (req: AuthedRequest, res) => {
  const b = req.body ?? {};
  if (typeof b.username !== 'string' || !b.username.trim()) {
    return res.status(400).json({ error: 'El usuario es obligatorio' });
  }
  const role = b.role ?? 'viewer';
  if (!ROLES.includes(role)) {
    return res.status(400).json({ error: 'Rol inválido' });
  }
  if (typeof b.password !== 'string' || b.password.length < MIN_PASSWORD_LENGTH) {
    return res.status(400).json({ error: `La contraseña debe tener al menos ${MIN_PASSWORD_LENGTH} caracteres` });
  }
  try {
    const info = db
      .prepare(
        `INSERT INTO users (username, email, full_name, role, password_hash)
         VALUES (@username, @email, @full_name, @role, @password_hash)`
      )
      .run({
        username: b.username,
        email: typeof b.email === 'string' ? b.email : '',
        full_name: typeof b.fullName === 'string' && b.fullName ? b.fullName : b.username,
        role,
        password_hash: weakHash(b.password),
      });
    const r = db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid) as any;
    res.status(201).json(toPublicUser(r));
  } catch {
    // Sin detalle del motor de base de datos (CWE-209).
    res.status(400).json({ error: 'No se pudo crear el usuario (¿el usuario ya existe?)' });
  }
});

// PUT /api/users/:id/role  (Hito 4: solo admin y rol validado; antes A01)
usersRouter.put('/:id/role', requireRole('admin'), (req, res) => {
  const role = (req.body ?? {}).role;
  if (!ROLES.includes(role)) {
    return res.status(400).json({ error: 'Rol inválido' });
  }
  const info = db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, req.params.id);
  if (info.changes === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
  const r = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id) as any;
  res.json({ id: r.id, username: r.username, role: r.role });
});
