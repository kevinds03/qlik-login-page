require('dotenv').config();

const express = require('express');
const session = require('express-session');
const axios = require('axios');
const crypto = require('node:crypto');
const helmet = require('helmet');
const app = express();
const path = require('path');

const oidc = require('./oidc');
app.use('/oidc', oidc.callback());

app.set('view engine', 'ejs');

app.set('trust proxy', 1);

// KONFIGURASI KEY CLOUDFLARE TURNSTILE
const TURNSTILE_SITE_KEY = process.env.TURNSTILE_SITE_KEY;   
const TURNSTILE_SECRET_KEY = process.env.TURNSTILE_SECRET_KEY;

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use('/public', express.static(path.join(__dirname, 'public')));

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", "https://challenges.cloudflare.com"],
        frameSrc: ["'self'", "https://challenges.cloudflare.com"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:", "blob:"],
        formAction: ["'self'", "http:", "https:"],
      },
    },
    crossOriginEmbedderPolicy: false,
  })
);

// --------------- OIDC interaction routes -----------------------------------------------------

app.get('/interaction/:uid', async (req, res) => {
  try {
    await oidc.interactionDetails(req, res);
    res.render('login', { error: null, uid: req.params.uid, TURNSTILE_SITE_KEY: TURNSTILE_SITE_KEY });
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
          uid: details.uid,
          TURNSTILE_SITE_KEY: TURNSTILE_SITE_KEY
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

    return res.render('login', { error, uid: req.params.uid, TURNSTILE_SITE_KEY: TURNSTILE_SITE_KEY });

  } catch (err) {
    console.error('Auth API error:', err.message);
    return res.render('login', {
      error: 'Authentication service is unavailable. Try again later.',
      uid: req.params.uid,
      TURNSTILE_SITE_KEY: TURNSTILE_SITE_KEY
    });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));