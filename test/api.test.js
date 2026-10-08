import test from 'node:test';
import assert from 'node:assert';

process.env.DB_PATH = ':memory:';
process.env.JWT_SECRET = 'x'.repeat(48);

const { default: app } = await import('../src/app.js');
const { default: request } = await import('supertest');
const H = { 'X-Requested-With': 'fetch' };

test('refuse l\'accès sans connexion', async () => {
  await request(app).get('/api/notes').expect(401);
});

test('refuse une requête POST sans en-tête anti-CSRF', async () => {
  await request(app)
    .post('/api/auth/login')
    .send({ email: 'a@test.com', password: 'motdepasse-long-1' })
    .expect(403);
});

test('un utilisateur ne peut pas toucher les notes d\'un autre (IDOR)', async () => {
  const a = request.agent(app);
  const b = request.agent(app);
  await a.post('/api/auth/register').set(H).send({ email: 'a@test.com', password: 'motdepasse-long-1' }).expect(201);
  await b.post('/api/auth/register').set(H).send({ email: 'b@test.com', password: 'motdepasse-long-2' }).expect(201);

  const created = await a.post('/api/notes').set(H).send({ title: 'secret', content: 'privé' }).expect(201);

  await b.delete('/api/notes/' + created.body.id).set(H).expect(404);
  const list = await b.get('/api/notes').expect(200);
  assert.deepStrictEqual(list.body, []);
});

test('rejette un mot de passe trop court', async () => {
  await request(app)
    .post('/api/auth/register')
    .set(H)
    .send({ email: 'c@test.com', password: 'court' })
    .expect(400);
});