import { Router } from 'express';
import { z } from 'zod';
import db from '../db.js';
import { requireAuth } from '../middleware/auth.js';

const router = Router();
router.use(requireAuth);

const noteSchema = z.object({
  title: z.string().trim().min(1).max(100),
  content: z.string().trim().min(1).max(5000),
});
const idSchema = z.coerce.number().int().positive();

router.get('/', (req, res) => {
  const notes = db
    .prepare('SELECT id, title, content, created_at FROM notes WHERE user_id = ? ORDER BY id DESC')
    .all(req.userId);
  res.json(notes);
});

router.post('/', (req, res) => {
  const parsed = noteSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Données invalides' });
  const { title, content } = parsed.data;
  const info = db
    .prepare('INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)')
    .run(req.userId, title, content);
  res.status(201).json({ id: Number(info.lastInsertRowid), title, content });
});

router.put('/:id', (req, res) => {
  const id = idSchema.safeParse(req.params.id);
  const parsed = noteSchema.safeParse(req.body);
  if (!id.success || !parsed.success) return res.status(400).json({ error: 'Données invalides' });
  const { title, content } = parsed.data;
  const info = db
    .prepare('UPDATE notes SET title = ?, content = ? WHERE id = ? AND user_id = ?')
    .run(title, content, id.data, req.userId);
  if (info.changes === 0) return res.status(404).json({ error: 'Note introuvable' });
  res.json({ id: id.data, title, content });
});

router.delete('/:id', (req, res) => {
  const id = idSchema.safeParse(req.params.id);
  if (!id.success) return res.status(400).json({ error: 'Identifiant invalide' });
  const info = db.prepare('DELETE FROM notes WHERE id = ? AND user_id = ?').run(id.data, req.userId);
  if (info.changes === 0) return res.status(404).json({ error: 'Note introuvable' });
  res.status(204).end();
});

export default router;