const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const Database = require('better-sqlite3');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const cors = require('cors');
const nodeCron = require('node-cron');
const nodemailer = require('nodemailer');
const twilio = require('twilio');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

dotenv.config();
const app = express();
app.use(bodyParser.json());
app.use(cors());

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';
const DB_FILE = process.env.DATABASE_FILE || './futureself.db';

const db = new Database(DB_FILE);
initialize();

function initialize(){
  // create tables
  db.prepare(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE,
    password_hash TEXT,
    email TEXT,
    phone TEXT,
    created_at TEXT,
    unlock_time TEXT,
    recover_food_hash TEXT,
    recover_celebrity_hash TEXT,
    recover_sweet_hash TEXT,
    remind_email INTEGER DEFAULT 0,
    remind_sms INTEGER DEFAULT 0,
    notified INTEGER DEFAULT 0
  )`).run();

  db.prepare(`CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    encrypted_message TEXT,
    salt TEXT,
    years INTEGER,
    created_at TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  )`).run();
}

// helper: send email
async function sendEmail(to, subject, text){
  if(!process.env.SMTP_HOST) return false;
  try{
    let transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT || 587),
      secure: false,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    });
    await transporter.sendMail({
      from: process.env.FROM_EMAIL || process.env.SMTP_USER,
      to, subject, text
    });
    return true;
  }catch(err){
    console.error('Email send error', err);
    return false;
  }
}

// helper: send SMS via Twilio
async function sendSMS(to, body){
  if(!process.env.TWILIO_ACCOUNT_SID) return false;
  try{
    const client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
    await client.messages.create({body, from: process.env.TWILIO_FROM, to});
    return true;
  }catch(err){
    console.error('SMS error', err);
    return false;
  }
}

// Register endpoint
app.post('/api/register', async (req, res) => {
  try{
    const { username, password, email, phone, years, encryptedMessage, salt, q_food, q_celebrity, q_sweet } = req.body;
    if(!username || !password || !years || !encryptedMessage) return res.status(400).json({ error:'missing fields' });
    const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
    if(existing) return res.status(400).json({ error:'username taken' });
    const id = uuidv4();
    const pwHash = await bcrypt.hash(password, 10);
    const foodHash = q_food ? await bcrypt.hash(q_food.toLowerCase(), 10) : null;
    const celebHash = q_celebrity ? await bcrypt.hash(q_celebrity.toLowerCase(), 10) : null;
    const sweetHash = q_sweet ? await bcrypt.hash(q_sweet.toLowerCase(), 10) : null;
    const created = new Date().toISOString();
    const unlockDate = new Date();
    unlockDate.setFullYear(unlockDate.getFullYear() + parseInt(years));
    db.prepare(`INSERT INTO users (id, username, password_hash, email, phone, created_at, unlock_time, recover_food_hash, recover_celebrity_hash, recover_sweet_hash)
      VALUES (?,?,?,?,?,?,?,?,?,?)`).run(id, username, pwHash, email||null, phone||null, created, unlockDate.toISOString(), foodHash, celebHash, sweetHash);
    const mid = uuidv4();
    db.prepare(`INSERT INTO messages (id, user_id, encrypted_message, salt, years, created_at) VALUES (?,?,?,?,?,?)`)
      .run(mid, id, encryptedMessage, salt, parseInt(years), created);
    return res.json({ ok:true });
  }catch(err){
    console.error(err);
    return res.status(500).json({ error:'server error' });
  }
});

// Login — returns JWT only if now >= unlock_time
app.post('/api/login', async (req, res) => {
  try{
    const { username, password } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if(!user) return res.status(400).json({ error:'invalid credentials' });
    const ok = await bcrypt.compare(password, user.password_hash);
    if(!ok) return res.status(400).json({ error:'invalid credentials' });
    const now = new Date();
    const unlock = new Date(user.unlock_time);
    if(now < unlock){
      return res.status(403).json({ error:'too early', unlock_time: user.unlock_time });
    }
    const token = jwt.sign({ uid: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    return res.json({ token });
  }catch(err){
    console.error(err);
    return res.status(500).json({ error:'server error' });
  }
});

// Get encrypted message (requires token)
app.get('/api/message', (req, res) => {
  try{
    const auth = req.headers.authorization;
    if(!auth) return res.status(401).json({ error:'no auth' });
    const token = auth.split(' ')[1];
    const data = jwt.verify(token, JWT_SECRET);
    const row = db.prepare('SELECT encrypted_message, salt, created_at, years FROM messages WHERE user_id = ?').get(data.uid);
    if(!row) return res.status(404).json({ error:'no message' });
    return res.json({ encryptedMessage: row.encrypted_message, salt: row.salt, created_at: row.created_at, years: row.years });
  }catch(err){
    console.error(err);
    return res.status(401).json({ error:'invalid token' });
  }
});

// Forgot / recover - check recovery answers and allow password reset (note: resetting password WILL NOT re-encrypt stored message; user must keep original password to decrypt)
app.post('/api/recover', async (req, res) => {
  try{
    const { username, q_food, q_celebrity, q_sweet, new_password } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if(!user) return res.status(400).json({ error:'no such user' });
    let ok = false;
    if(q_food && user.recover_food_hash){
      ok = ok || await bcrypt.compare(q_food.toLowerCase(), user.recover_food_hash);
    }
    if(q_celebrity && user.recover_celebrity_hash){
      ok = ok || await bcrypt.compare(q_celebrity.toLowerCase(), user.recover_celebrity_hash);
    }
    if(q_sweet && user.recover_sweet_hash){
      ok = ok || await bcrypt.compare(q_sweet.toLowerCase(), user.recover_sweet_hash);
    }
    if(!ok) return res.status(400).json({ error:'answers did not match' });
    if(!new_password) return res.status(400).json({ error:'provide new_password' });
    const newHash = await bcrypt.hash(new_password, 10);
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(newHash, user.id);
    return res.json({ ok:true, warning:'Password reset will not re-encrypt existing messages. If you cannot decrypt, contact support.' });
  }catch(err){
    console.error(err);
    return res.status(500).json({ error:'server error' });
  }
});

// Settings: toggle reminders
app.post('/api/settings', (req, res) => {
  try{
    const { token, remind_email, remind_sms } = req.body;
    if(!token) return res.status(401).json({ error:'no token' });
    const data = jwt.verify(token, JWT_SECRET);
    db.prepare('UPDATE users SET remind_email = ?, remind_sms = ? WHERE id = ?').run(remind_email?1:0, remind_sms?1:0, data.uid);
    return res.json({ ok:true });
  }catch(err){
    console.error(err);
    return res.status(401).json({ error:'invalid token' });
  }
});

// Static frontend serving (optional) - serve built frontend if desired
app.use(express.static(path.join(__dirname, '../frontend')));

// Reminder cron job - runs daily at 09:00 by default or uses REMINDER_CRON
const cronExpr = (process.env.REMINDER_CRON || '0 9 * * *').replace(/'/g,'');
nodeCron.schedule(cronExpr, async () => {
  console.log('Running reminders check...');
  const now = new Date();
  const nextDay = new Date(now.getTime() + (24*60*60*1000));
  const rows = db.prepare('SELECT id, username, email, phone, unlock_time, notified, remind_email, remind_sms FROM users WHERE (remind_email=1 OR remind_sms=1) AND notified=0').all();
  for(const r of rows){
    const unlock = new Date(r.unlock_time);
    if(unlock <= nextDay && unlock >= now){
      // send reminder
      const when = unlock.toDateString();
      if(r.remind_email && r.email){
        await sendEmail(r.email, 'FutureSelf reminder: your message unlocks soon', `Hi ${r.username}, your FutureSelf message will unlock on ${unlock.toISOString()}.`);
      }
      if(r.remind_sms && r.phone){
        await sendSMS(r.phone, `FutureSelf: your message unlocks on ${when}.`);
      }
      db.prepare('UPDATE users SET notified = 1 WHERE id = ?').run(r.id);
    }
  }
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log('Server running on port', PORT);
});
