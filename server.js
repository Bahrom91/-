import 'dotenv/config';
import express from 'express';
import session from 'express-session';
import pgSession from 'connect-pg-simple';
import helmet from 'helmet';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { Pool } from 'pg';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} from '@simplewebauthn/server';

const app = express();
const port = Number(process.env.PORT || 3000);
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const RP_NAME = process.env.RP_NAME || 'Private Vault';
const RP_ID = process.env.RP_ID || 'localhost';
const ORIGIN = process.env.ORIGIN || `http://localhost:${port}`;

app.use(helmet({
  contentSecurityPolicy: false
}));
app.use(express.json({ limit: '100kb' }));
app.use(express.static('public'));

const PgStore = pgSession(session);

app.use(session({
  store: new PgStore({ pool, tableName: 'user_sessions', createTableIfMissing: true }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 1000 * 60 * 30
  }
}));

function requireLogin(req, res, next) {
  if (!req.session.userId || !req.session.twoFactorOk || !req.session.passkeyOk) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

function randomId() {
  return crypto.randomBytes(16).toString('hex');
}

async function db(query, params = []) {
  return pool.query(query, params);
}

async function bootstrap() {
  if (!process.env.SESSION_SECRET) {
    throw new Error('SESSION_SECRET is required');
  }
  await db(`CREATE TABLE IF NOT EXISTS user_sessions (
    sid varchar NOT NULL PRIMARY KEY,
    sess json NOT NULL,
    expire timestamp(6) NOT NULL
  )`);
  await db(`CREATE INDEX IF NOT EXISTS "IDX_user_sessions_expire" ON user_sessions (expire)`);

  const count = await db('SELECT COUNT(*)::int AS count FROM users');
  if (count.rows[0].count === 0) {
    const initialPin = process.env.INITIAL_PIN;
    const initialPassword = process.env.INITIAL_PASSWORD;
    if (!initialPin || !initialPassword) {
      throw new Error('Set INITIAL_PIN and INITIAL_PASSWORD for first setup.');
    }
    if (!/^\\d+$/.test(initialPin)) {
      throw new Error('INITIAL_PIN must contain digits only.');
    }
    if (!/^[A-Za-z]+$/.test(initialPassword)) {
      throw new Error('INITIAL_PASSWORD must contain letters only.');
    }

    const id = randomId();
    const pinHash = await bcrypt.hash(initialPin, 12);
    const passwordHash = await bcrypt.hash(initialPassword, 12);
    const salt = crypto.randomBytes(16).toString('base64url');

    await db(
      'INSERT INTO users (id, pin_hash, password_hash, vault_salt) VALUES ($1,$2,$3,$4)',
      [id, pinHash, passwordHash, salt]
    );

    const empty = { version: 1, accounts: [], numbers: [] };
    await db(
      'INSERT INTO vaults (user_id, ciphertext, iv) VALUES ($1,$2,$3)',
      [id, '', '']
    );
    console.log('Initial vault created. Register your first passkey from the setup page.');
  }
}

app.get('/api/status', async (req, res) => {
  const r = await db('SELECT id, vault_salt FROM users LIMIT 1');
  res.json({
    initialized: r.rowCount > 0,
    loggedIn: !!(req.session.userId && req.session.twoFactorOk && req.session.passkeyOk),
    passkeyRequired: true,
    vaultSalt: r.rows[0]?.vault_salt || null
  });
});

app.post('/api/login/step1', async (req, res) => {
  const { pin, password } = req.body || {};
  if (typeof pin !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Invalid credentials' });
  }

  const r = await db('SELECT * FROM users LIMIT 1');
  if (!r.rowCount) return res.status(500).json({ error: 'Vault is not initialized' });

  const user = r.rows[0];
  const pinOk = await bcrypt.compare(pin, user.pin_hash);
  const passOk = await bcrypt.compare(password, user.password_hash);

  if (!pinOk || !passOk) {
    return res.status(401).json({ error: 'PIN yoki harfli parol noto‘g‘ri.' });
  }

  req.session.userId = user.id;
  req.session.twoFactorOk = true;
  req.session.passkeyOk = false;

  res.json({ ok: true, needsPasskey: true });
});

app.get('/api/passkey/options', async (req, res) => {
  if (!req.session.userId || !req.session.twoFactorOk) {
    return res.status(401).json({ error: 'Complete PIN and password first.' });
  }

  const r = await db('SELECT id, public_key, counter, transports FROM passkeys WHERE user_id=$1', [req.session.userId]);
  const allowCredentials = r.rows.map(k => ({
    id: k.id,
    transports: k.transports || undefined
  }));

  const options = await generateAuthenticationOptions({
    rpID: RP_ID,
    allowCredentials,
    userVerification: 'required'
  });

  await db(
    `INSERT INTO auth_challenges(user_id, challenge, expires_at)
     VALUES($1,$2,NOW()+INTERVAL '5 minutes')
     ON CONFLICT(user_id) DO UPDATE SET challenge=EXCLUDED.challenge, expires_at=EXCLUDED.expires_at`,
    [req.session.userId, options.challenge]
  );

  res.json(options);
});

app.post('/api/passkey/verify', async (req, res) => {
  if (!req.session.userId || !req.session.twoFactorOk) {
    return res.status(401).json({ error: 'Complete PIN and password first.' });
  }

  const c = await db(
    'SELECT challenge FROM auth_challenges WHERE user_id=$1 AND expires_at>NOW()',
    [req.session.userId]
  );
  if (!c.rowCount) return res.status(400).json({ error: 'Authentication challenge expired.' });

  const r = await db(
    'SELECT * FROM passkeys WHERE user_id=$1 AND id=$2',
    [req.session.userId, req.body.id]
  );
  if (!r.rowCount) return res.status(401).json({ error: 'Passkey not registered.' });

  const key = r.rows[0];

  try {
    const verification = await verifyAuthenticationResponse({
      response: req.body,
      expectedChallenge: c.rows[0].challenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      credential: {
        id: key.id,
        publicKey: new Uint8Array(key.public_key),
        counter: Number(key.counter),
        transports: key.transports || undefined
      },
      requireUserVerification: true
    });

    if (!verification.verified) {
      return res.status(401).json({ error: 'Biometric verification failed.' });
    }

    await db('UPDATE passkeys SET counter=$1 WHERE id=$2', [
      verification.authenticationInfo.newCounter,
      key.id
    ]);
    await db('DELETE FROM auth_challenges WHERE user_id=$1', [req.session.userId]);

    req.session.passkeyOk = true;
    res.json({ ok: true });
  } catch {
    res.status(401).json({ error: 'Biometric verification failed.' });
  }
});

app.get('/api/passkey/register/options', async (req, res) => {
  if (!req.session.userId || !req.session.twoFactorOk) {
    return res.status(401).json({ error: 'Login with the first two factors first.' });
  }

  const user = await db('SELECT id FROM users WHERE id=$1', [req.session.userId]);
  const keys = await db('SELECT id, transports FROM passkeys WHERE user_id=$1', [req.session.userId]);

  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: RP_ID,
    userName: 'vault-owner',
    userDisplayName: 'Vault Owner',
    attestationType: 'none',
    excludeCredentials: keys.rows.map(k => ({
      id: k.id,
      transports: k.transports || undefined
    })),
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'required',
      authenticatorAttachment: 'platform'
    }
  });

  await db(
    `INSERT INTO auth_challenges(user_id, challenge, expires_at)
     VALUES($1,$2,NOW()+INTERVAL '5 minutes')
     ON CONFLICT(user_id) DO UPDATE SET challenge=EXCLUDED.challenge, expires_at=EXCLUDED.expires_at`,
    [req.session.userId, options.challenge]
  );

  res.json(options);
});

app.post('/api/passkey/register/verify', async (req, res) => {
  if (!req.session.userId || !req.session.twoFactorOk) {
    return res.status(401).json({ error: 'Login with the first two factors first.' });
  }

  const c = await db(
    'SELECT challenge FROM auth_challenges WHERE user_id=$1 AND expires_at>NOW()',
    [req.session.userId]
  );
  if (!c.rowCount) return res.status(400).json({ error: 'Registration challenge expired.' });

  try {
    const verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge: c.rows[0].challenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      requireUserVerification: true
    });

    if (!verification.verified || !verification.registrationInfo) {
      return res.status(400).json({ error: 'Passkey registration failed.' });
    }

    const { credential } = verification.registrationInfo;
    const id = credential.id;
    const publicKey = Buffer.from(credential.publicKey);
    const counter = credential.counter;

    await db(
      `INSERT INTO passkeys(id,user_id,public_key,counter,transports)
       VALUES($1,$2,$3,$4,$5)
       ON CONFLICT(id) DO NOTHING`,
      [id, req.session.userId, publicKey, counter, JSON.stringify(req.body.response?.transports || [])]
    );

    await db('DELETE FROM auth_challenges WHERE user_id=$1', [req.session.userId]);

    req.session.passkeyOk = true;
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(400).json({ error: 'Passkey registration failed.' });
  }
});

app.get('/api/vault', requireLogin, async (req, res) => {
  const r = await db('SELECT ciphertext, iv FROM vaults WHERE user_id=$1', [req.session.userId]);
  if (!r.rowCount) return res.status(404).json({ error: 'Vault not found' });
  res.json(r.rows[0]);
});

app.put('/api/vault', requireLogin, async (req, res) => {
  const { ciphertext, iv } = req.body || {};
  if (typeof ciphertext !== 'string' || typeof iv !== 'string') {
    return res.status(400).json({ error: 'Invalid vault payload' });
  }
  await db(
    `UPDATE vaults SET ciphertext=$1, iv=$2, updated_at=NOW() WHERE user_id=$3`,
    [ciphertext, iv, req.session.userId]
  );
  res.json({ ok: true });
});

app.post('/api/security/change', requireLogin, async (req, res) => {
  const { oldPin, oldPassword, newPin, newPassword } = req.body || {};
  if (!/^\d+$/.test(newPin || '') || !/^[A-Za-z]+$/.test(newPassword || '')) {
    return res.status(400).json({ error: 'PIN must be digits only and password letters only.' });
  }

  const r = await db('SELECT * FROM users WHERE id=$1', [req.session.userId]);
  const user = r.rows[0];

  const okPin = await bcrypt.compare(oldPin || '', user.pin_hash);
  const okPassword = await bcrypt.compare(oldPassword || '', user.password_hash);

  if (!okPin || !okPassword) {
    return res.status(401).json({ error: 'Current credentials are incorrect.' });
  }

  const pinHash = await bcrypt.hash(newPin, 12);
  const passwordHash = await bcrypt.hash(newPassword, 12);

  await db(
    'UPDATE users SET pin_hash=$1,password_hash=$2,updated_at=NOW() WHERE id=$3',
    [pinHash, passwordHash, user.id]
  );

  res.json({ ok: true });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('*', (req, res) => {
  res.sendFile('index.html', { root: 'public' });
});

bootstrap()
  .then(() => app.listen(port, () => {
    console.log(`Private Vault running on ${ORIGIN}`);
  }))
  .catch(err => {
    console.error(err);
    process.exit(1);
  });
