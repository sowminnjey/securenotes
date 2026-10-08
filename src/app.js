import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import cookieParser from 'cookie-parser';
import authRoutes from './routes/auth.js';
import notesRoutes from './routes/notes.js';

if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
  throw new Error('JWT_SECRET manquant ou trop court (32 caractères minimum)');
}

const app = express();
app.set('trust proxy', 1); // derrière le proxy de l'hébergeur

app.use(helmet());
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());

app.use('/api', rateLimit({ windowMs: 15 * 60 * 1000, limit: 300 }));
app.use('/api/auth', rateLimit({ windowMs: 15 * 60 * 1000, limit: 20 }));

// Défense CSRF supplémentaire : en-tête personnalisé obligatoire sur les requêtes qui modifient des données
app.use((req, res, next) => {
  const modifies = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method);
  if (modifies && req.get('X-Requested-With') !== 'fetch') {
    return res.status(403).json({ error: 'Requête refusée' });
  }
  next();
});

app.use('/api/auth', authRoutes);
app.use('/api/notes', notesRoutes);
app.use(express.static('public'));

app.use((req, res) => res.status(404).json({ error: 'Introuvable' }));
app.use((err, req, res, next) => {
  console.error(err); // détail dans les logs, jamais envoyé au client
  res.status(500).json({ error: 'Erreur serveur' });
});

export default app;