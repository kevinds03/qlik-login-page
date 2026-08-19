require('dotenv').config();

const express = require('express');
const session = require('express-session');
const axios = require('axios');
const crypto = require('node:crypto');

const oidc = require('./oidc');
// const { consoleLog } = require('@ngrok/ngrok');
const { getUserWithAccess, updateSessionId } = require('./db');

const app = express();

app.set('trust proxy', true); 

app.set('view engine', 'ejs');
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));

// app.use(session({
//   secret: process.env.SESSION_SECRET,
//   resave: false,
//   saveUninitialized: false
// }));

app.use('/oidc', oidc.callback());

// app.get('/', (req, res) => {
//   res.redirect('/login');
// });

// app.post('/login', async (req, res) => {
//   const { nik, pass } = req.body;

//   try {
//     const response = await axios.post(
//       process.env.AUTH_API_URL,
//       { user: { nik, pass } },
//       { headers: { 'Content-Type': 'application/json' } }
//     );

//     const result = response.data.LoginESS_V2Result; // get API response result

//     if (result === 'Sukses') {
//       req.session.loggedIn = true;
//       req.session.username = nik;

//       return res.redirect('/dashboard'); // change to redirect to publisher/Qlik
//     } else {
//       // console.log(result); // delete
//       req.session.loginError = result;
//       return res.redirect('/login');
//     }

//     req.session.loginError = 'Login gagal. Mohon coba lagi.';
//     return res.redirect('/login');

//   } catch (err) {
//     console.error('Auth API error:', err.message);
//     req.session.loginError = 'Authentication service is unavailable. Try again later.';
//     return res.redirect('/login');
//   }
// });

// app.get('/login', (req, res) => {
//   console.log('Session on GET /login:', req.session); // delete
//   const error = req.session.loginError || null;
//   req.session.loginError = null; // clear after showing once
//   res.render('login', { error });
// });

// app.get('/dashboard', (req, res) => {
//   if (!req.session.loggedIn) {
//     return res.redirect('/login');
//   }
//   res.render('dashboard', { nik: req.session.nik });
// });

// app.get('/logout', (req, res) => {
//   req.session.destroy(() => res.redirect('/login'));
// });

// --------------- OIDC interaction routes -----------------------------------------------------
app.get('/interaction/:uid', async (req, res) => {
  try {
    await oidc.interactionDetails(req, res);
    res.render('login', { error: null, uid: req.params.uid });
  } catch (err) {
    console.error('Interaction error:', err);
    res.status(400).send('Invalid or expired login session');
  }
});

app.post('/interaction/:uid/login', async (req, res) => {
  const { nik, pass } = req.body;

  let response;
  try {
    const details = await oidc.interactionDetails(req, res);
    const { params } = details;

    response = await axios.post(
      process.env.AUTH_API_URL,
      { user: { nik, pass } },
      { headers: { 'Content-Type': 'application/json' } }
    );

    const result = response.data.LoginESS_V2Result != 'gagal' ? response.data.LoginESS_V2Result : null; // get API response result

    if (result === 'Sukses') {
      // Check if user exists in DB (function in db.js)
      const dbUser = await getUserWithAccess(nik);
      if(!dbUser) {
        return res.render('login', {
          error: 'Akun belum terdaftar, silahkan hubungi administrator.',
          uid: details.uid
        });
      }

      // Generate Session ID untuk SAS
      const newSessionId = crypto.randomUUID();
      await updateSessionId(nik, newSessionId);

      // Auto Grant Consent & Finish Interaction
      let grant;
      if (details.grantId) {
        grant = await oidc.Grant.find(details.grantId);
      } else {
        grant = new oidc.Grant({
          clientId: params.client_id,
          accountId: nik,
        });
      }

      if (params.scope) {
        grant.addOIDCScope(params.scope);
      }

      const grantId = await grant.save();
      
      const loginResult = { login: { accountId: nik }, consent: { grantId } };
      await oidc.interactionFinished(req, res, loginResult, { mergeWithLastSubmission: false });
      return;
    }
    const error = result ? result : 'Gagal autentikasi. NIK tidak terdaftar';

    return res.render('login', { error, uid: req.params.uid });

  } catch (err) {
    console.error('Auth API error:', err.message);
    return res.render('login', {
      error: 'Authentication service is unavailable. Try again later.',
      uid: req.params.uid
    });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));