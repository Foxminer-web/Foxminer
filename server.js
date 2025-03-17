const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3');
const cookieParser = require('cookie-parser');
const fetch = require('node-fetch');
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true })); // Add to parse JotForm POST
app.use(cookieParser());
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', 'https://foxminer.glitch.me');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Methods', 'GET,POST');
    next();
});

const db = new sqlite3.Database('users.db');
db.run('CREATE TABLE IF NOT EXISTS users (email TEXT PRIMARY KEY, password TEXT, wallet TEXT)');

app.post('/signup', async (req, res) => {
    const { email, password } = req.body; // JotForm might send q1_email, q2_password—check below
    const hash = await bcrypt.hash(password, 10);
    db.run('INSERT INTO users (email, password) VALUES (?, ?)', [email, hash], (err) => {
        if (err) {
            console.error('Signup error:', err);
            return res.status(400).json({ error: 'Email exists' });
        }
        const token = jwt.sign({ email }, 'secret');
        res.cookie('token', token, { httpOnly: true });
        res.redirect('https://foxminer.glitch.me/dashboard.html'); // Redirect to Glitch
    });
});

app.post('/login', (req, res) => {
    const { email, password } = req.body;
    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const token = jwt.sign({ email }, 'secret');
        res.cookie('token', token, { httpOnly: true });
        res.redirect('https://foxminer.glitch.me/dashboard.html'); // Redirect to Glitch
    });
});

app.post('/set-wallet', authenticate, (req, res) => {
    const { wallet } = req.body;
    db.run('UPDATE users SET wallet = ? WHERE email = ?', [wallet, req.user.email], (err) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json({ success: true });
    });
});

app.get('/check-session', (req, res) => {
    const token = req.cookies.token;
    if (!token) return res.json({ signedIn: false });
    jwt.verify(token, 'secret', (err, decoded) => {
        if (err) return res.json({ signedIn: false });
        db.get('SELECT email, wallet FROM users WHERE email = ?', [decoded.email], (err, user) => {
            if (err || !user) return res.json({ signedIn: false });
            res.json({ signedIn: true, email: user.email, wallet: user.wallet });
        });
    });
});

app.get('/get-stats', authenticate, async (req, res) => {
    db.get('SELECT wallet FROM users WHERE email = ?', [req.user.email], async (err, user) => {
        if (err || !user?.wallet) return res.json({ error: 'No wallet' });
        const stats = await fetch(`https://api.moneroocean.stream/miner/${user.wallet}/stats`)
            .then(res => res.json())
            .catch(err => {
                console.error('Monero Ocean fetch failed:', err);
                return { hash2: 0, hash: 0, amtDue: 0 };
            });
        res.json({
            hashRate: stats.hash2 || 0, // Hashes per second
            totalHashes: stats.hash || 0, // Total hashes
            amtDue: stats.amtDue || 0 // Pending XMR in piconero
        });
    });
});

app.post('/logout', (req, res) => {
    res.clearCookie('token').json({ success: true });
});

function authenticate(req, res, next) {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: 'Not signed in' });
    jwt.verify(token, 'secret', (err, decoded) => {
        if (err) return res.status(401).json({ error: 'Invalid token' });
        req.user = decoded;
        next();
    });
}

app.listen(3000, () => console.log('Server running'));
