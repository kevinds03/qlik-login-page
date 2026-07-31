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

app.get('/', (req, res) => {
  res.redirect('/login');
});

app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const response = await axios.post(
      process.env.AUTH_API_URL,
      { username, password },
      {
        headers: { 'Content-Type': 'application/json' }
      }
    );

    console.log('Raw API response:', JSON.stringify(response.data, null, 2)); // ADD THIS TEMPORARILY

    const result = response.data.LoginESS_V2Result; // get API response result

    if (result === 'Sukses') {
      req.session.loggedIn = true;
      req.session.username = username;
      return res.redirect('/dashboard'); // redirect
    }

    // Handle "try again (n/3)" pattern
    if (result.startsWith('Username / password tidak sesuai')) {
      const insideParens = result.split('('[1]?.replace(')', ''));
      const [attempt, max] = insideParens.split('/').map(Number);

      if (attempt >= max) {
        const word = "menunggu";
        const regex = new RegExp('${word}\\s+(\\w+)', i);
        const minutesLocked = result.match(regex);

        return res.render('login', {
          error: 'Account locked after too many failed attempts. Please try again in {minutesLocked}.'
        });
      }

      return res.render('login', {
        error: `Incorrect credentials. Attempt ${attempt} of ${max}.`
      });
    }

    // Fallback for any unexpected response string
    return res.render('login', { error: 'Login failed. Please try again.' });

  } catch (err) {
    console.error('Auth API error:', err.message);
    res.render('login', { error: 'Authentication service is unavailable. Try again later.' });
  }
});

app.get('/dashboard', (req, res) => {
  if (!req.session.loggedIn) {
    return res.redirect('/login');
  }
  res.render('dashboard', { username: req.session.username });
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

const PORT = 3000;
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));