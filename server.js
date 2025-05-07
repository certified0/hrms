const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');

const app = express();
const PORT = 3000;

app.use(bodyParser.json());
app.use(cors({
  origin: 'http://localhost:3001', // change if frontend origin differs
  credentials: true
}));
app.use(session({
  secret: 'supersecretkey123',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 3600000 },
}));

// Initialize SQLite DB
const db = new sqlite3.Database('./hrms.db', err => {
  if (err) {
    console.error('DB open error:', err);
    process.exit(1);
  }
  console.log('SQLite DB connected');
});

// Setup tables
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password_hash TEXT,
    role TEXT DEFAULT 'admin'
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS employees (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    role TEXT NOT NULL
  )`);
  db.get(`SELECT count(*) AS cnt FROM users`, (err, row) => {
    if (err) throw err;
    if(row.cnt === 0){
      // Create default admin user password 'admin'
      bcrypt.hash('admin', 10).then(hash => {
        db.run(`INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)`, ['admin', hash, 'admin']);
        console.log('Admin user created: admin/admin');
      });
    }
  });
});

// Auth middleware
function isAuthenticated(req, res, next) {
  if(req.session.user) return next();
  res.status(401).json({ error: 'Unauthorized' });
}

// Admin role middleware
function isAdmin(req, res, next){
  if(req.session.user && req.session.user.role === 'admin') return next();
  res.status(403).json({ error: 'Forbidden' });
}

// Login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if(!username || !password) return res.status(400).json({ error: 'Username and password required' });

  db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    bcrypt.compare(password, user.password_hash).then(match => {
      if(match){
        req.session.user = { id: user.id, username: user.username, role: user.role };
        res.json({ message: 'Login successful', user: req.session.user });
      } else {
        res.status(401).json({ error: 'Invalid credentials' });
      }
    }).catch(() => res.status(500).json({ error: 'Internal error' }));
  });
});

// Logout
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ message: 'Logged out' }));
});

// Session check
app.get('/api/session', (req, res) => {
  if(req.session.user) res.json({ user: req.session.user });
  else res.status(401).json({ error: 'Not authenticated' });
});

// Get employees (admin only)
app.get('/api/employees', isAuthenticated, isAdmin, (req, res) => {
  db.all(`SELECT id, name, email, role FROM employees ORDER BY name ASC`, [], (err, rows) => {
    if(err) return res.status(500).json({ error: 'DB error' });
    res.json(rows);
  });
});

// Add employee
app.post('/api/employees', isAuthenticated, isAdmin, (req, res) => {
  const { name, email, role } = req.body;
  if(!name || !email || !role) return res.status(400).json({ error: 'Missing fields' });
  const sql = `INSERT INTO employees (name, email, role) VALUES (?, ?, ?)`;
  db.run(sql, [name, email, role], function(err){
    if(err){
      if(err.message.includes('UNIQUE')) return res.status(400).json({ error: 'Email already exists' });
      return res.status(500).json({ error: 'DB error' });
    }
    res.json({ id: this.lastID, name, email, role });
  });
});

// Update employee
app.put('/api/employees/:id', isAuthenticated, isAdmin, (req, res) => {
  const id = req.params.id;
  const { name, email, role } = req.body;
  if(!name || !email || !role) return res.status(400).json({ error: 'Missing fields' });
  const sql = `UPDATE employees SET name=?, email=?, role=? WHERE id=?`;
  db.run(sql, [name, email, role, id], function(err){
    if(err) return res.status(500).json({ error: 'DB error' });
    if(this.changes === 0) return res.status(404).json({ error: 'Employee not found' });
    res.json({ id, name, email, role });
  });
});

// Delete employee
app.delete('/api/employees/:id', isAuthenticated, isAdmin, (req, res) => {
  const id = req.params.id;
  db.run(`DELETE FROM employees WHERE id=?`, [id], function(err){
    if(err) return res.status(500).json({ error: 'DB error' });
    if(this.changes === 0) return res.status(404).json({ error: 'Employee not found' });
    res.json({ message: 'Deleted' });
  });
});

app.listen(PORT, () => console.log(`HRMS server running at http://localhost:${PORT}`));