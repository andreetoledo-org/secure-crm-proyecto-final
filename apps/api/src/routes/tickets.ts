import { Router, Response } from 'express';
import { db } from '../db';
import { authenticate, requireRole, AuthedRequest } from '../middleware/auth';

export const ticketsRouter = Router();
ticketsRouter.use(authenticate);

// Política de acceso (Hito 4, PoC-03 / CWE-639, CWE-862):
//   admin  -> lee, crea, edita y elimina cualquier ticket.
//   agent  -> lee, crea y edita tickets; NO elimina.
//   viewer -> solo lectura, y únicamente de los tickets que él creó.
const STATUSES = ['open', 'in_progress', 'closed'];
const PRIORITIES = ['low', 'medium', 'high', 'urgent'];

function mapTicket(row: any) {
  return {
    id: row.id,
    title: row.title,
    description: row.description,
    status: row.status,
    priority: row.priority,
    customerName: row.customer_name,
    customerEmail: row.customer_email,
    assigneeId: row.assignee_id,
    assigneeName: row.assignee_name,
    createdById: row.created_by_id,
    createdByName: row.created_by_name,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

const SELECT = `
  SELECT t.*, a.full_name AS assignee_name, c.full_name AS created_by_name
  FROM tickets t
  LEFT JOIN users a ON a.id = t.assignee_id
  LEFT JOIN users c ON c.id = t.created_by_id
`;

function canRead(user: NonNullable<AuthedRequest['user']>, row: any): boolean {
  return user.role !== 'viewer' || row.created_by_id === user.sub;
}

// Valida y normaliza el cuerpo de creación/edición: lista blanca de campos y
// valores (evita mass assignment, CWE-915). Devuelve null si ya respondió 400.
function readTicketBody(b: any, res: Response): Record<string, any> | null {
  const out: Record<string, any> = {};
  for (const [field, column] of [
    ['title', 'title'],
    ['description', 'description'],
    ['customerName', 'customer_name'],
    ['customerEmail', 'customer_email'],
  ] as const) {
    if (b[field] !== undefined) {
      if (typeof b[field] !== 'string') {
        res.status(400).json({ error: `El campo ${field} debe ser texto` });
        return null;
      }
      out[column] = b[field];
    }
  }
  if (b.status !== undefined) {
    if (!STATUSES.includes(b.status)) {
      res.status(400).json({ error: 'Estado inválido' });
      return null;
    }
    out.status = b.status;
  }
  if (b.priority !== undefined) {
    if (!PRIORITIES.includes(b.priority)) {
      res.status(400).json({ error: 'Prioridad inválida' });
      return null;
    }
    out.priority = b.priority;
  }
  if (b.assigneeId !== undefined) {
    if (b.assigneeId !== null && !Number.isInteger(b.assigneeId)) {
      res.status(400).json({ error: 'Asignado inválido' });
      return null;
    }
    out.assignee_id = b.assigneeId;
  }
  return out;
}

// GET /api/tickets?q=...
// Hito 4 (PoC-02, vector SQLi / CWE-89): el término de búsqueda viaja como
// parámetro (@like), nunca concatenado en el SQL. El valor 'query' se sigue
// devolviendo, pero el frontend ahora lo muestra como texto (sin XSS).
// Hito 4 (PoC-03): un viewer solo recibe los tickets que él creó.
ticketsRouter.get('/', (req: AuthedRequest, res) => {
  const q = typeof req.query.q === 'string' ? req.query.q : '';
  const conditions: string[] = [];
  const params: Record<string, unknown> = {};
  if (q) {
    conditions.push('(t.title LIKE @like OR t.description LIKE @like OR t.customer_name LIKE @like)');
    params.like = `%${q}%`;
  }
  if (req.user!.role === 'viewer') {
    conditions.push('t.created_by_id = @uid');
    params.uid = req.user!.sub;
  }
  const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
  const rows = db.prepare(`${SELECT} ${where} ORDER BY t.created_at DESC`).all(params);
  res.json({ query: q, tickets: rows.map(mapTicket) });
});

// GET /api/tickets/:id
// Hito 4 (PoC-03 IDOR / CWE-639): un viewer solo ve sus propios tickets. Si no
// puede leerlo se responde 404 (igual que si no existiera) para no confirmar ids.
ticketsRouter.get('/:id', (req: AuthedRequest, res) => {
  const row = db.prepare(`${SELECT} WHERE t.id = ?`).get(req.params.id) as any;
  if (!row || !canRead(req.user!, row)) return res.status(404).json({ error: 'Ticket no encontrado' });
  res.json(mapTicket(row));
});

// POST /api/tickets  (Hito 4: viewer es solo lectura -> 403; campos en lista blanca)
ticketsRouter.post('/', requireRole('admin', 'agent'), (req: AuthedRequest, res) => {
  const b = readTicketBody(req.body ?? {}, res);
  if (!b) return;
  if (typeof b.title !== 'string' || !b.title.trim()) {
    return res.status(400).json({ error: 'El título es obligatorio' });
  }
  const info = db
    .prepare(
      `INSERT INTO tickets (title, description, status, priority, customer_name, customer_email, assignee_id, created_by_id)
       VALUES (@title, @description, @status, @priority, @customer_name, @customer_email, @assignee_id, @created_by_id)`
    )
    .run({
      title: b.title,
      description: b.description ?? '',
      status: b.status ?? 'open',
      priority: b.priority ?? 'medium',
      customer_name: b.customer_name ?? '',
      customer_email: b.customer_email ?? '',
      assignee_id: b.assignee_id ?? null,
      created_by_id: req.user!.sub,
    });
  const row = db.prepare(`${SELECT} WHERE t.id = ?`).get(info.lastInsertRowid);
  res.status(201).json(mapTicket(row));
});

// PUT /api/tickets/:id  (Hito 4, PoC-03: solo admin y agent -> viewer recibe 403)
ticketsRouter.put('/:id', requireRole('admin', 'agent'), (req, res) => {
  const existing = db.prepare('SELECT * FROM tickets WHERE id = ?').get(req.params.id) as any;
  if (!existing) return res.status(404).json({ error: 'Ticket no encontrado' });
  const b = readTicketBody(req.body ?? {}, res);
  if (!b) return;
  db.prepare(
    `UPDATE tickets SET
       title = @title, description = @description, status = @status, priority = @priority,
       customer_name = @customer_name, customer_email = @customer_email,
       assignee_id = @assignee_id, updated_at = datetime('now')
     WHERE id = @id`
  ).run({
    id: req.params.id,
    title: b.title ?? existing.title,
    description: b.description ?? existing.description,
    status: b.status ?? existing.status,
    priority: b.priority ?? existing.priority,
    customer_name: b.customer_name ?? existing.customer_name,
    customer_email: b.customer_email ?? existing.customer_email,
    assignee_id: b.assignee_id !== undefined ? b.assignee_id : existing.assignee_id,
  });
  const row = db.prepare(`${SELECT} WHERE t.id = ?`).get(req.params.id);
  res.json(mapTicket(row));
});

// DELETE /api/tickets/:id  (Hito 4, PoC-03 / CWE-862: solo admin)
ticketsRouter.delete('/:id', requireRole('admin'), (req, res) => {
  const info = db.prepare('DELETE FROM tickets WHERE id = ?').run(req.params.id);
  if (info.changes === 0) return res.status(404).json({ error: 'Ticket no encontrado' });
  res.json({ ok: true });
});
