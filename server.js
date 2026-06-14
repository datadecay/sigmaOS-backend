// this file is part AI
import express from 'express';
import cors from 'cors';
import fs from 'fs/promises';
import path from 'path';

const app = express();
const PORT = 8094;
const DB_FILE = path.resolve('./database.json');

const CLIENT_ID = '119dd61812e3d0a0c5c36112de508783';
const CLIENT_SECRET = 'c801f9ee336ecb58e2ae22ad5214cb123acea74a6bcbea98ea43b93d554778ba';
const REDIRECT_URI = 'https://friendly-barnacle-r4445jp9gw4ghpwg4-8000.app.github.dev/authenticate.html';

app.use(cors());
app.use(express.json());

async function readDatabase() {
    try {
        const data = await fs.readFile(DB_FILE, 'utf-8');
        return JSON.parse(data);
    } catch (err) { return {}; }
}

async function writeDatabase(data) {
    await fs.writeFile(DB_FILE, JSON.stringify(data, null, 2), 'utf-8');
}

async function getUserIdFromToken(authHeader) {
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        throw new Error('Missing or malformed Authorization header');
    }
    const token = authHeader.split(' ')[1];

    const userResponse = await fetch('https://auth.hackclub.com/api/v1/me', {
        headers: { 'Authorization': `Bearer ${token}` }
    });

    if (!userResponse.ok) {
        throw new Error('Invalid or expired token');
    }

    const userData = await userResponse.json();
    return userData.identity.id;
}

app.post('/api/auth', async (req, res) => {
    const { code, code_verifier } = req.body;

    try {
        const tokenResponse = await fetch('https://auth.hackclub.com/oauth/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                grant_type: 'authorization_code',
                client_id: CLIENT_ID,
                client_secret: CLIENT_SECRET,
                code: code,
                redirect_uri: REDIRECT_URI,
                code_verifier: code_verifier
            })
        });

        if (!tokenResponse.ok) {
            const errorBody = await tokenResponse.text();
            throw new Error(`OAuth token exchange failed: ${errorBody}`);
        }

        const tokenData = await tokenResponse.json();

        const userResponse = await fetch('https://auth.hackclub.com/api/v1/me', {
            headers: { 'Authorization': `Bearer ${tokenData.access_token}` }
        });

        if (!userResponse.ok) throw new Error('Failed to fetch user');
        const userData = await userResponse.json();

        const isVerified = userData.identity?.verification_status === 'verified';
        const assignedTier = isVerified ? 'verified' : 'standard';
        const storageLimitMB = isVerified ? 50 : 10;

        const db = await readDatabase();
        
        if (!db[userData.slack_id]) {
            db[userData.slack_id] = { data: {} };
        }
        
        db[userData.slack_id].tier = assignedTier;
        db[userData.slack_id].storageLimitMB = storageLimitMB;
        
        await writeDatabase(db);

        res.json({
            success: true,
            token: tokenData.access_token,
            user: userData,
            data: db[userData.slack_id].data
        });

    } catch (err) {
        console.error('Auth handler error:', err.message);
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/save-state', async (req, res) => {
    try {
        const userId = await getUserIdFromToken(req.headers.authorization);
        const { data } = req.body;

        if (data === undefined) {
            return res.status(400).json({ error: 'Missing "data" field in request body' });
        }

        const payloadString = JSON.stringify(data);
        const sizeInBytes = Buffer.byteLength(payloadString, 'utf8');
        const sizeInMB = sizeInBytes / (1024 * 1024);

        const db = await readDatabase();
        const userRecord = db[userId];

        const maxAllowedStorage = userRecord?.storageLimitMB || 10; 

        if (sizeInMB > maxAllowedStorage) {
            console.warn(`[Quota Block] User ${userId}. Attempted: ${sizeInMB.toFixed(2)}MB, Allowed: ${maxAllowedStorage}MB`);
            return res.status(413).json({
                error: `Quota exceeded. Your save data limit is ${maxAllowedStorage}MB. Current upload size: ${sizeInMB.toFixed(2)}MB.`
            });
        }

        db[userId] = {
            ...db[userId],
            data: data, 
            updated_at: new Date().toISOString()
        };
        await writeDatabase(db);

        res.json({ success: true });
    } catch (err) {
        res.status(err.message.includes('token') || err.message.includes('Authorization') ? 401 : 500)
           .json({ error: err.message });
    }
});


app.get('/api/load-state', async (req, res) => {
    try {
        const userId = await getUserIdFromToken(req.headers.authorization);
        
        const db = await readDatabase();
        const userRecord = db[userId] || { data: {} };

        res.json({ 
            success: true, 
            data: userRecord.data 
        });
    } catch (err) {
        res.status(err.message.includes('token') || err.message.includes('Authorization') ? 401 : 500)
           .json({ error: err.message });
    }
});

app.listen(PORT, () => console.log(`Backend running on http://localhost:${PORT}`));
