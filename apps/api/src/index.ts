import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { initSchema } from './db';
import { authRouter } from './auth';
import { ticketsRouter } from './routes/tickets';
import { usersRouter } from './routes/users';
import { dashboardRouter } from './routes/dashboard';

initSchema();

const app = express();
const PORT = Number(process.env.API_PORT || 4000);

// Hito 4: no anunciar el framework en X-Powered-By (fingerprinting).
app.disable('x-powered-by');

// Hito 4 (CWE-942): CORS restringido a los orígenes de la web. Antes reflejaba
// cualquier Origin con credenciales. Configurable con CORS_ORIGINS (coma).
const allowedOrigins = (process.env.CORS_ORIGINS || 'http://localhost:3000')
  .split(',')
  .map((o) => o.trim())
  .filter(Boolean);
app.use(
  cors({
    origin: (origin, cb) => cb(null, !origin || allowedOrigins.includes(origin)),
    credentials: true,
  })
);

// Hito 4 (CWE-693): cabeceras de seguridad en las respuestas de la API (JSON).
app.use((_req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
  next();
});

app.use(express.json());
app.use(cookieParser());

app.get('/api/health', (_req, res) => res.json({ status: 'ok', service: 'secure-crm-api' }));

app.use('/api/auth', authRouter);
app.use('/api/tickets', ticketsRouter);
app.use('/api/users', usersRouter);
app.use('/api/dashboard', dashboardRouter);

// Hito 4 (CWE-209): manejador de errores genérico. El detalle queda en el log
// del servidor, no en la respuesta (antes devolvía message y stack al cliente).
app.use((err: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error(err);
  const status = err?.type === 'entity.parse.failed' ? 400 : 500;
  res.status(status).json({ error: status === 400 ? 'Petición inválida' : 'Error interno del servidor' });
});

app.listen(PORT, () => {
  console.log(`API secure-crm escuchando en http://localhost:${PORT}`);
});
