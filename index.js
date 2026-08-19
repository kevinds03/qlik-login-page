require('dotenv').config();

const { getUserWithAccess, updateSessionId, logoutUser } = require('./db');

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
  const { user_id, pass } = req.body;

  let response;
  try {
    let result;
    const details = await oidc.interactionDetails(req, res);
    const { params } = details;

    let cleanId = user_id.trim().includes('\\') ? user_id.trim().split('\\')[1] : user_id.trim();
    const isNIK = /^\d{10}$/.test(cleanId);

    console.log('cleanID: ', cleanId);
    console.log('isNik? ', isNIK);

    if (isNIK) {
      response = await axios.post(
        process.env.AUTH_API_URL,
        { user: { nik: user_id, pass } },
        { headers: { 'Content-Type': 'application/json' } }
      );
      result = response.data.LoginESS_V2Result != 'gagal' ? response.data.LoginESS_V2Result : null; // get API response result
    } else {
      result = 'Bukan NIK';
    }

    if (result === 'Sukses' || result === 'Bukan NIK') {
      // Check if user exists in DB (function in db.js)
      const dbUser = await getUserWithAccess(user_id.toLowerCase());
      if(!dbUser) {
        return res.render('login', {
          error: 'Akun belum terdaftar, silahkan hubungi administrator.',
          uid: details.uid,
          TURNSTILE_SITE_KEY: TURNSTILE_SITE_KEY
        });
      }
      console.log('[findAccount] user found:', JSON.stringify(dbUser, null, 2));

      // Generate Session ID untuk SAS
      const newSessionId = crypto.randomUUID();
      await updateSessionId(user_id.toLowerCase(), newSessionId);

      // Auto Grant Consent & Finish Interaction
      let grant;
      if (details.grantId) {
        grant = await oidc.Grant.find(details.grantId);
      } else {
        grant = new oidc.Grant({
          clientId: params.client_id,
          accountId: user_id,
        });
      }

      if (params.scope) {
        grant.addOIDCScope(params.scope);
      }

      const grantId = await grant.save();
      
      const loginResult = { login: { accountId: user_id }, consent: { grantId } };
      await oidc.interactionFinished(req, res, loginResult, { mergeWithLastSubmission: false });
      return;
    }

    return res.render('login', { error, uid: req.params.uid, TURNSTILE_SITE_KEY: TURNSTILE_SITE_KEY });

  } catch (err) {
    console.error('Auth API error:', err.message);
    return res.render('login', {
      error: /*err*/ 'Terjadi kesalahan pada sistem. Mohon tunggu.',
      uid: req.params.uid,
      TURNSTILE_SITE_KEY: TURNSTILE_SITE_KEY
    });
  }
});

// ------------------------- Log out ---------------------------------
// app.get('/interaction/:uid/logout', async (req, res) => {
//   const targetUserId = req.body.userid || req.body.userId || req.body.sub || req.body.user_id;

//   if (!targetUserId) {
//     return res.status(400).json({ status: 'error', message: 'ID or NIK not found' });
//   }

//   try {
//     await logoutUser(targetUserId);
//     return res.json({ status: 'ok', message: 'Session cleared' });
//   } catch (err) {
//     console.error('[logout] error:', err);
//     return res.status(500).json({ status: 'error', message: 'Failed to clear session' });
//   }
// });

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));