const express = require('express');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

const app = express();
const SECRET = process.env.JWT_SECRET || 'isko-badal-dena-zaroor';
const DB_FILE = path.join(__dirname, 'db.json');
const UPLOAD_DIR = path.join(__dirname, 'uploads');

if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);
if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, JSON.stringify({ users: [], apps: [] }));

const readDB = () => JSON.parse(fs.readFileSync(DB_FILE));
const writeDB = (d) => fs.writeFileSync(DB_FILE, JSON.stringify(d, null, 2));

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const storage = multer.diskStorage({
  destination: UPLOAD_DIR,
  filename: (req, file, cb) => cb(null, Date.now() + '-' + Math.round(Math.random() * 1e6) + '.apk')
});
const upload = multer({
  storage,
  limits: { fileSize: 200 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (!file.originalname.toLowerCase().endsWith('.apk')) return cb(new Error('सिर्फ़ APK फ़ाइल चलेगी'));
    cb(null, true);
  }
});

function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  try { req.user = jwt.verify(token, SECRET); next(); }
  catch { res.status(401).json({ error: 'पहले लॉगिन कीजिए' }); }
}

app.post('/api/signup', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password || password.length < 6)
    return res.status(400).json({ error: 'यूज़रनेम और कम से कम 6 अक्षर का पासवर्ड दीजिए' });
  const db = readDB();
  if (db.users.find(u => u.username === username))
    return res.status(400).json({ error: 'यह यूज़रनेम पहले से है' });
  const user = { id: Date.now(), username, hash: await bcrypt.hash(password, 10) };
  db.users.push(user);
  writeDB(db);
  res.json({ token: jwt.sign({ id: user.id, username }, SECRET, { expiresIn: '7d' }), username });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = readDB().users.find(u => u.username === username);
  if (!user || !(await bcrypt.compare(password, user.hash)))
    return res.status(400).json({ error: 'यूज़रनेम या पासवर्ड गलत है' });
  res.json({ token: jwt.sign({ id: user.id, username }, SECRET, { expiresIn: '7d' }), username });
});

app.get('/api/apps', (req, res) => {
  const q = (req.query.q || '').toLowerCase();
  const list = readDB().apps
    .filter(a => a.name.toLowerCase().includes(q))
    .map(({ file, ...rest }) => rest)
    .reverse();
  res.json(list);
});

app.post('/api/upload', auth, (req, res) => {
  upload.single('apk')(req, res, (err) => {
    if (err) return res.status(400).json({ error: err.message });
    if (!req.file) return res.status(400).json({ error: 'फ़ाइल चुनिए' });
    const db = readDB();
    const entry = {
      id: Date.now(),
      name: (req.body.name || req.file.originalname).slice(0, 80),
      description: (req.body.description || '').slice(0, 500),
      uploader: req.user.username,
      size: req.file.size,
      downloads: 0,
      file: req.file.filename,
      date: new Date().toISOString()
    };
    db.apps.push(entry);
    writeDB(db);
    res.json({ ok: true });
  });
});

app.get('/download/:id', (req, res) => {
  const db = readDB();
  const a = db.apps.find(x => x.id == req.params.id);
  if (!a) return res.status(404).send('फ़ाइल नहीं मिली');
  a.downloads++;
  writeDB(db);
  res.download(path.join(UPLOAD_DIR, a.file), a.name.replace(/[^\w\-. ]/g, '_') + '.apk');
});

app.listen(3000, () => console.log('चालू है: http://localhost:3000'));
