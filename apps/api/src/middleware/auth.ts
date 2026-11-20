import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import type { Role } from '@secure-crm/shared';
import { db } from '../db';
import { JWT_ALGORITHM, JWT_SECRET } from '../config';

export interface AuthedRequest extends Request {
  user?: { sub: number; username: string; role: Role };
}

// Hito 4 (PoC-04 / CWE-347): el token se VERIFICA con jwt.verify (firma HMAC
// HS256 con el secreto del servidor, solo ese algoritmo, y expiración). Antes
// se usaba jwt.decode, que ignora la firma y permitía forjar tokens de admin.
export function authenticate(req: AuthedRequest, res: Response, next: NextFunction) {
  const header = req.headers.authorization || '';
  const bearer = header.startsWith('Bearer ') ? header.slice(7) : null;
  const token = bearer || (req as any).cookies?.session;

  if (!token) {
    return res.status(401).json({ error: 'No autenticado' });
  }

  let payload: jwt.JwtPayload;
  try {
    const verified = jwt.verify(token, JWT_SECRET, { algorithms: [JWT_ALGORITHM] });
    if (typeof verified === 'string') throw new Error('payload inválido');
    payload = verified;
  } catch {
    return res.status(401).json({ error: 'Token inválido' });
  }

  // El rol se lee de la base de datos y no del token: si a un usuario le
  // quitan privilegios o lo eliminan, el cambio aplica de inmediato.
  const row = db
    .prepare('SELECT id, username, role FROM users WHERE id = ?')
    .get(Number(payload.sub)) as { id: number; username: string; role: Role } | undefined;
  if (!row) {
    return res.status(401).json({ error: 'Token inválido' });
  }

  req.user = { sub: row.id, username: row.username, role: row.role };
  next();
}

// Hito 4 (PoC-03 / CWE-862): control de acceso basado en roles (RBAC).
// Uso: router.delete('/:id', requireRole('admin'), handler)
export function requireRole(...roles: Role[]) {
  return (req: AuthedRequest, res: Response, next: NextFunction) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'No autorizado para esta acción' });
    }
    next();
  };
}
