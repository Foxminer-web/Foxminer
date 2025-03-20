const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3');
const cookieParser = require('cookie-parser');
const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', 'https://foxminer-web.github.io');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Methods', 'GET, POST');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  console.log('Request Headers:', req.headers);
  next();
});

// SQLite DB
const db = new sqlite3.Database('./users.db', (err) => {
  if (err) console.error('DB Connection Error:', err);
  else console.log('Connected to SQLite DB');
});
db.run(
  'CREATE TABLE IF NOT EXISTS users (email TEXT PRIMARY KEY, password TEXT, wallet TEXT)',
  (err) => {
    if (err) console.error('Table Creation Error:', err);
    else console.log('Users table ready');
  }
);

// Root route
app.get('/', (req, res) => {
  res.send('Foxminer server is alive');
});

// Signup route
app.post('/signup', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).send('Missing email or password');
    const hash = await bcrypt.hash(password, 10);
    db.run('INSERT INTO users (email, password, wallet) VALUES (?, ?, ?)', [email, hash, ''], (err) => {
      if (err) {
        console.error('Signup DB Error:', err);
        return res.status(400).send('Email exists');
      }
      console.log('User signed up:', email); // Log success
      const token = jwt.sign({ email }, 'secret', { expiresIn: '1h' });
      console.log('Signup Token Set:', token);
      res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'none' });
      console.log('Signup Response Headers:', res.getHeaders());
      res.redirect('https://foxminer-web.github.io/Foxminer/dashboard.html');
    });
  } catch (err) {
    console.error('Signup Error:', err);
    res.status(500).send('Server error');
  }
});

// Signin route
app.post('/signin', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).send('Missing email or password');
    db.get('SELECT email, password FROM users WHERE email = ?', [email], async (err, user) => {
      if (err) {
        console.error('Signin DB Error:', err);
        return res.status(500).send('Database error');
      }
      if (!user) return res.status(400).send('User not found');
      const match = await bcrypt.compare(password, user.password);
      if (!match) return res.status(400).send('Invalid password');
      const token = jwt.sign({ email }, 'secret', { expiresIn: '1h' });
      console.log('Signin Token Set:', token);
      res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'none' });
      console.log('Signin Response Headers:', res.getHeaders());
      res.redirect('https://foxminer-web.github.io/Foxminer/dashboard.html');
    });
  } catch (err) {
    console.error('Signin Error:', err);
    res.status(500).send('Server error');
  }
});

// Check session route
app.get('/check-session', (req, res) => {
  try {
    const token = req.cookies.token;
    console.log('Check-Session Token Received:', token || 'None');
    if (!token) {
      console.log('No token, returning signedIn: false');
      return res.json({ signedIn: false });
    }
    jwt.verify(token, 'secret', (err, decoded) => {
      if (err) {
        console.error('JWT Verify Error:', err);
        return res.json({ signedIn: false });
      }
      db.get('SELECT email, wallet FROM users WHERE email = ?', [decoded.email], (err, user) => {
        if (err) {
          console.error('DB Query Error:', err);
          return res.status(500).send('Database error');
        }
        if (!user) {
          console.log('User not found for email:', decoded.email);
          return res.json({ signedIn: false });
        }
        console.log('Session valid for:', user.email);
        res.json({ signedIn: true, email: user.email, wallet: user.wallet });
      });
    });
  } catch (err) {
    console.error('Check-Session Error:', err);
    res.status(500).send('Server error');
  }
});

// Logout route
app.post('/logout', (req, res) => {
  res.clearCookie('token', { httpOnly: true, secure: true, sameSite: 'none' });
  console.log('Logout: Cookie cleared');
  res.json({ success: true });
});

// Set wallet route
app.post('/set-wallet', (req, res) => {
  try {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: 'Not signed in' });
    jwt.verify(token, 'secret', (err, decoded) => {
      if (err) return res.status(401).json({ error: 'Invalid token' });
      const { wallet } = req.body;
      db.run('UPDATE users SET wallet = ? WHERE email = ?', [wallet, decoded.email], (err) => {
        if (err) {
          console.error('Set Wallet DB Error:', err);
          return res.status(500).json({ error: 'Database error' });
        }
        res.json({ success: true });
      });
    });
  } catch (err) {
    console.error('Set Wallet Error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Users route (Secured with key)
app.get('/users', (req, res) => {
  const secretKey = 'fox123'; // Change this to your own secret
  if (req.query.key !== secretKey) {
    console.log('Unauthorized /users access attempt');
    return res.status(403).send('Unauthorized');
  }
  db.all('SELECT email, wallet FROM users', (err, rows) => {
    if (err) {
      console.error('Users DB Error:', err);
      return res.status(500).send('DB error');
    }
    console.log('Users fetched:', rows);
    res.json(rows);
  });
});

// Error handling
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
