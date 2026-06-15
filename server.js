// this file is part AI
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import Database from 'better-sqlite3';

const app = express();
const db = new Database('data.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    data TEXT,
    updated_at DATETIME
  )
`);

app.use(cors());
app.use(express.json());

const getStorageLimit = (isVerified) => (isVerified ? 50 : 10);

async function verifyIdentity(token) {
  const response = await fetch('https://auth.hackclub.com/api/v1/me', {
    headers: { 'Authorization': `Bearer ${token}` }
  });
  if (!response.ok) throw new Error('Unauthorized');
  return await response.json();
}

const authenticate = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const userData = await verifyIdentity(authHeader.split(' ')[1]);
    req.user = userData;
    next();
  } catch (e) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

app.post('/api/auth', async (req, res) => {
  const { code, code_verifier, redirect_uri } = req.body;
  try {
    const tokenResponse = await fetch('https://auth.hackclub.com/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: process.env.CLIENT_ID,
        client_secret: process.env.CLIENT_SECRET,
        code, redirect_uri, code_verifier
      })
    });
    if (!tokenResponse.ok) throw new Error('Token exchange failed');
    const tokenData = await tokenResponse.json();
    const userData = await verifyIdentity(tokenData.access_token);
    db.prepare('INSERT OR IGNORE INTO users (id, data, updated_at) VALUES (?, ?, ?)').run(
      userData.identity.id, JSON.stringify({}), new Date().toISOString()
    );
    res.json({ success: true, token: tokenData.access_token, user: userData });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/save-state', authenticate, (req, res) => {
  const { data } = req.body;
  const isVerified = req.user.identity?.verification_status === 'verified';
  const limit = getStorageLimit(isVerified);
  const sizeInMB = Buffer.byteLength(JSON.stringify(data)) / (1024 * 1024);
  if (sizeInMB > limit) {
    return res.status(413).json({ error: `Quota exceeded: ${limit}MB limit` });
  }
  db.prepare('UPDATE users SET data = ?, updated_at = ? WHERE id = ?').run(
    JSON.stringify(data), new Date().toISOString(), req.user.identity.id
  );
  res.json({ success: true });
});

app.get('/api/load-state', authenticate, (req, res) => {
  const row = db.prepare('SELECT data FROM users WHERE id = ?').get(req.user.identity.id);
  res.json({ success: true, data: row ? JSON.parse(row.data) : {} });
});

app.listen(process.env.PORT, () => console.log(`Server running on port ${process.env.PORT}`));
