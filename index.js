require('dotenv').config();

const express = require('express');
const session = require('express-session');
const axios = require('axios');

const oidc = require('./oidc');
const { consoleLog } = require('@ngrok/ngrok');

const app = express();

app.set('trust proxy', true); 

app.set('view engine', 'ejs');
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}));

app.use('/oidc', oidc.callback());

app.get('/', (req, res) => {
  res.redirect('/login');
});

app.post('/login', async (req, res) => {
  const { nik, pass } = req.body;

  try {
    const response = await axios.post(
      process.env.AUTH_API_URL,
      { user: { nik, pass } },
      { headers: { 'Content-Type': 'application/json' } }
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

// --------------- OIDC interaction routes -----------------------------------------------------
app.get('/interaction/:uid', async (req, res) => {
  try {
    await oidc.interactionDetails(req, res);
    res.render('login', { error: null, uid: req.params.uid });
  } catch (err) {
    console.error('Interaction error:', err);
    res.status(400).send('Invalid or expored login session');
  }
});

app.post('/interaction/:iud/login', async (req, res) => {
  const { nik, pass } = req.body;

  try {
    const response = await axios.post(
      process.env.AUTH_API_URL,
      { user: { nik, pass } },
      { headers: { 'Content-Type': 'application/json' } }
    );

    const result = response.data.LoginESS_V2Result; // get API response result

    if (result === 'Sukses') {
      const loginResult = { login: { accountId: username } };
      return await oidc.interactionFinished(req, res, loginResult, { mergeWithLastSubmission: false });
    } else {
      // console.log(result); // delete
      req.session.loginError = result;
      return res.redirect('/interaction/${interaction.uid}');
    }

    req.session.loginError = 'Login gagal. Mohon coba lagi.';
    return res.redirect('/interaction/${interaction.uid}');

  } catch (err) {
    console.error('Auth API error:', err.message);
    req.session.loginError = 'Authentication service is unavailable. Try again later.';
    return res.redirect('/interaction/${interaction.uid}');
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));