const express = require('express');
const session = require('express-session');
const axios = require('axios');
require('dotenv').config();

const app = express();

app.set('view engine', 'ejs');
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}));

const AUTH_API_URL = process.env.AUTH_API_URL;

const oidc = require('./oidc');

app.set('trust proxy', true);

app.use('/oidc', oidc.callback);

app.get('/', (req, res) => {
  res.redirect('/login');
});

app.post('/login', async (req, res) => {
  const { nik, pass } = req.body;

  try {
    const response = await axios.post(
      process.env.AUTH_API_URL,
      { user: { nik, pass } },
      {
        headers: { 'Content-Type': 'application/json' }
      }
    );

    const result = response.data.LoginESS_V2Result; // get API response result

    if (result === 'Sukses') {
      req.session.loggedIn = true;
      req.session.username = nik;
      return res.redirect('/dashboard'); // change to redirect to publisher/Qlik
    } else {
      // console.log(result); // delete
      req.session.loginError = result;
      return res.redirect('/login');
    }

    req.session.loginError = 'Login gagal. Mohon coba lagi.';
    return res.redirect('/login');

  } catch (err) {
    console.error('Auth API error:', err.message);
    req.session.loginError = 'Authentication service is unavailable. Try again later.';
    return res.redirect('/login');
  }
});

app.get('/login', (req, res) => {
  console.log('Session on GET /login:', req.session); // delete
  const error = req.session.loginError || null;
  req.session.loginError = null; // clear after showing once
  res.render('login', { error });
});

app.get('/dashboard', (req, res) => {
  if (!req.session.loggedIn) {
    return res.redirect('/login');
  }
  res.render('dashboard', { nik: req.session.nik });
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

const PORT = 3000;
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));