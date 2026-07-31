const express = require('express');
const session = require('express-session');
const axios = require('axios');

const app = express();

app.set('view engine', 'ejs');
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: 'replace-this-with-a-real-secret',
  resave: false,
  saveUninitialized: false
}));

const AUTH_API_URL = 'https://your-api-endpoint.com/authenticate'; // replace with your real API

app.get('/', (req, res) => {
  res.redirect('/login');
});

app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const response = await axios.post(AUTH_API_URL, {
      username,
      password
    });

    // Adjust this based on your API's actual response shape.
    // Examples: response.data === true, response.data.authenticated === 1, etc.
    const isAuthenticated = response.data === true || response.data.authenticated === true;

    if (isAuthenticated) {
      req.session.loggedIn = true;
      req.session.username = username;
      res.redirect('/dashboard');
    } else {
      res.render('login', { error: 'Invalid username or password' });
    }
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