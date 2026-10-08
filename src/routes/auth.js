import { Router } from 'express';
import argon2 from 'argon2';
import jwt from 'jsonwebtoken';
import { z } from 'zod';
import db from '../db.js';
import { requireAuth } from '../middleware/auth.js';

const router = Router();

const credentials = z.object({
  email: z.string().email().max(254).toLowerCase(),
  password: z.string().min(10).max(128),
});

const baseCookie = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict',
};

// Faux hash : on vérifie toujours un mot de passe, même si l'email est inconnu
const DUMMY_HASH = await argon2.hash('mot-de-passe-factice');

function startSession(res, userId) {
  const token = jwt.sign({ sub: String(userId) }, process.env.JWT_SECRET, {
    algorithm: 'HS256',
    expiresIn: '1h',
  });
  res.cookie('token', token, { ...baseCookie, maxAge: 60 * 60 * 1000 });
}

router.post('/register', async (req, res, next) => {
  try {
    const parsed = credentials.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Email invalide ou mot de passe trop court (10 caractères minimum)' });
    }
    const { email, password } = parsed.data;
    const hash = await argon2.hash(password);
    try {
      const info = db.prepare('INSERT INTO users (email, password_hash) VALUES (?, ?)').run(email, hash);
      startSession(res, info.lastInsertRowid);
      return res.status(201).json({ id: Number(info.lastInsertRowid), email });
    } catch (e) {
      if (e.code === 'SQLITE_CONSTRAINT_UNIQUE') {
        return res.status(409).json({ error: 'Inscription impossible' });
      }
      throw e;
    }
  } catch (e) {
    next(e);
  }
});

router.post('/login', async (req, res, next) => {
  try {
    const parsed = credentials.safeParse(req.body);
    if (!parsed.success) return res.status(401).json({ error: 'Identifiants incorrects' });
    const { email, password } = parsed.data;
    const user = db.prepare('SELECT id, password_hash FROM users WHERE email = ?').get(email);
    const ok = await argon2.verify(user ? user.password_hash : DUMMY_HASH, password);
    if (!user || !ok) return res.status(401).json({ error: 'Identifiants incorrects' });
    startSession(res, user.id);
    res.json({ id: user.id, email });
  } catch (e) {
    next(e);
  }
});

router.post('/logout', (req, res) => {
  res.clearCookie('token', baseCookie);
  res.status(204).end();
});

router.get('/me', requireAuth, (req, res) => {
  const user = db.prepare('SELECT id, email FROM users WHERE id = ?').get(req.userId);
  if (!user) return res.status(401).json({ error: 'Session invalide' });
  res.json(user);
});

export default router;