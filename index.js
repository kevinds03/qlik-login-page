require('dotenv').config();

const { getNIK, /*getCredentials,*/ getUserWithAccess, updateSessionId, logoutUser } = require('./db');

const express = require('express');
const session = require('express-session');
const axios = require('axios');
const crypto = require('node:crypto');
const helmet = require('helmet');
const app = express();
const path = require('path');

const oidc = require('./oidc');
const { error } = require('node:console');
app.use('/oidc', oidc.callback());

app.set('view engine', 'ejs');

app.set('trust proxy', 1);

// KONFIGURASI KEY CLOUDFLARE TURNSTILE
const TURNSTILE_SITE_KEY = process.env.TURNSTILE_SITE_KEY;   
const TURNSTILE_SECRET_KEY = process.env.TURNSTILE_SECRET_KEY;

// FUNCTION TO CHECK CLOUDFLARE TURNSTILE
async function verfivyTurnstile(token, remoteIp) {
  if (!token) return false;

  try {
    const params = new URLSearchParams();
    params.append('secret', TURNSTILE_SECRET_KEY);
    params.append('response', token);
    params.append('remoteip', remoteIp);

    const response = await axios.post('https://challenges.cloudflare.com/turnstile/v0/siteverify', params);
    return response.data && response.data.success === true;
  } catch (err) {
    console.error('Turnstile Verivication Error: ', err);
    return false;
  }
}

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

// PASSWORD DECRYPTOR
// const SECRET_KEY = process.env.APP_SECRET_KEY;
// function  decryptPass(hexVal, ivHex) {
//   try {
//     const key = Buffer.from(SECRET_KEY, 'utf8');
//     const iv = Buffer.from(ivHex, 'hex');
//     const encryptedText = Buffer.from(hexVal, 'hex');

//     const algo = key.length === 32 ? 'aes-256-cbc' : 'aes-128-cbc';

//     const decipher = crypto.createDecipheriv(algo, key, iv);
//     let decrypted = decipher.update(encryptedText, undefined, 'utf8');
//     decrypted += decipher.final('utf8');

//     return decrypted
//   } catch (err) {
//     console.error('Failed to decrypt password: ', err.message);
//     return null;
//   }
// }

// IN-MEMORY RATE LIMITER UNTUK USERNAME NON-10 DIGIT
// const noOfAttempts = new Map();

// Helper XSS Encoding
function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// Helper Parser Nama Perangkat & Browser dari User-Agent
function parseUserAgent (userAgent) {
  let browser = 'Browser';
  let os = 'OS';

  if (!userAgent) return 'Perangkat tidak diketahui';
  if (userAgentString.includes('Chrome')) browser = 'Google Chrome';
  else if (userAgentString.includes('Safari')) browser = 'Safari';
  else if (userAgentString.includes('Firefox')) browser = 'Mozilla Firefox';
  else if (userAgentString.includes('Edg')) browser = 'Microsoft Edge';

  if (userAgentString.includes('Windows')) os = 'Windows PC';
  else if (userAgentString.includes('Macintosh')) os = 'Mac OS';
  else if (userAgentString.includes('Android')) os = 'Android Device';
  else if (userAgentString.includes('iPhone') || userAgentString.includes('iPad')) os = 'iOS Device';
  else if (userAgentString.includes('Linux')) os = 'Linux';

  return `${browser} on ${os}`;
}

// GET PENDING FOR CONFIRMATION
const pendingConfirmations = new Map();
const PENDING_TTL_MS = 2 * 60 * 1000;

function setPending(uid, nik) {
  pendingConfirmations.set(uid, { nik, expiresAt: Date.now() + PENDING_TTL_MS });
}
function getPending(uid) {
  const entry = pendingConfirmations.get(uid);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) {
    pendingConfirmations.delete(uid);
    return null;
  }
  return entry;
}
function clearPending(uid) {
  pendingConfirmations.delete(uid);
}


// --------------- OIDC interaction routes -----------------------------------------------------

app.get('/interaction/:uid', async (req, res) => {
  try {
    await oidc.interactionDetails(req, res);
    if (res.headersSent) return;
    res.render('login', { error: null, uid: req.params.uid, TURNSTILE_SITE_KEY: TURNSTILE_SITE_KEY });
  } catch (err) {
    console.error('Interaction error:', err);
    res.status(400).send('Invalid or expired login session');
  }
});

app.post('/interaction/:uid/login', async (req, res) => {
  const { user_id, pass, force_login } = req.body;
  const turnstileToken = req.body['cf-turnstile-response'];
  const clientIp = req.ip || req.headers['x-forwarded-for'];
  const userAgent = req.headers['user-agent'] || '';

  let response;

  try {
    // VERIFIKASI CLOUDFLARE
    if (force_login !== 'true') {
      if (!turnstileToken) {
        if (res.headersSent) return;
        return res.render('login', {
          error: 'Silakan centang verifikasi Cloudflare Turnstile terlebih dahulu.',
          uid: req.params.uid,
          TURNSTILE_SITE_KEY: TURNSTILE_SITE_KEY
        });
      }
      const isHuman = await verfivyTurnstile(turnstileToken, clientIp);
      if (!isHuman) {
        if (res.headersSent) return;
        return res.render('login', {
          error: 'Verifikasi keamanan Turnstile gagal / kedaluwarsa. Silakan coba lagi.',
          uid: req.params.uid,
          TURNSTILE_SITE_KEY: TURNSTILE_SITE_KEY       
        });
      }
    }
    
    let result;
    const details = await oidc.interactionDetails(req, res);
    const { params } = details;

    let cleanId = user_id.trim().includes('\\') ? user_id.trim().split('\\')[1] : user_id.trim();
    const isNIK = /^\d{10}$/.test(cleanId);

    console.log('cleanID: ', cleanId);
    console.log('isNik? ', isNIK);

    let isAuthValid = false;
    // GET NIK -- IF USER INPUT ID THEN GET NIK FROM QUERY
    let nik = isNIK ? user_id : await getNIK(cleanId);
    nik = String(nik);
    if (!nik) {
        if (res.headersSent) return;
        return res.render('login', {
        error: 'Username tidak terdaftar!',
        uid: req.params.uid,
        TURNSTILE_SITE_KEY: TURNSTILE_SITE_KEY
      });
    }

    // LOGIN USING API ()
    response = await axios.post(
      process.env.AUTH_API_URL,
      { user: { nik, pass } },
      { headers: { 'Content-Type': 'application/json' } }
    );

    isAuthValid = response.data.LoginESS_V2Result === 'Sukses';
    console.log(`User ${nik} is logged in: ${isAuthValid}`);

    // LOGIN USER ID -- uncomment if used
    // const now = Date.now();
    // let record = noOfAttempts.get(key) || { failedCount: 0, lockoutUntil: 0 };
    // console.log(key);

    // if (record.noOfAttempts > 0 && now >= record.lockoutUntil) {
    //   record.failedCount = 0;
    //   record.lockoutUntil = 0;
    //   noOfAttempts.delete(key.nik);
    //   console.log('Reset counter & timer');
    // }

    // if (now < record.lockoutUntil) {
    //   const remainingMs = record.lockoutUntil - now;
    //   const remainingMins = Math.ceil(remainingMs / 60000);
    //   console.log('Time remaining: ', remainingMins);
    // }

    // // AUTHENTICATION NIK
    // if (isNIK) {
    //   response = await axios.post(
    //     process.env.AUTH_API_URL,
    //     { user: { nik: user_id, pass } },
    //     { headers: { 'Content-Type': 'application/json' } }
    //   );

    //   result = response.data.LoginESS_V2Result != 'gagal' ? response.data.LoginESS_V2Result : null; // get API response result
    //   console.log(response.data.LoginESS_V2Result);

    //   isAuthValid = result === "Sukses" ? true : false;
    // } else {
    //   // AUTHENTICATION USER ID
    //   const dbCredentials = await getCredentials(cleanId);
    //   if (dbCredentials.password && dbCredentials.iv) {
    //     const decryptedPass = decryptPass(dbCredentials.password, dbCredentials.iv);
    //     if (decryptedPass && pass === decryptedPass) isAuthValid = true;
    //   }

    //   if (!isAuthValid && key) {
    //     // MAKE THE COUNTER FOR NIK AND ID THE SAME
    //     response = await axios.post(
    //       process.env.AUTH_API_URL,
    //       { user: { nik: key, pass: '' } },
    //       { headers: { 'Content-Type': 'application/json' } }
    //     );
    //   }
    // }

    // if (!isAuthValid) {
    //   record.failedCount += 1;
    //   let errMsg = '';
    //   if (record.failedCount === 1) 
    //       errMsg = 'Username / password tidak sesuai (1/3).';
    //   else if (record.failedCount === 2)
    //       errMsg = 'Username / password tidak sesuai (2/3). Bila sekali lagi tidak berhasil, anda harus menunggu 15 menit untuk dapat login kembali!';
    //   else {
    //     record.failedCount = 3;
    //     if (!record.lockoutUntil) record.lockoutUntil = now + (15 * 60000);
    //     const remainingMs = record.lockoutUntil - now;
    //     const remainingMins = Math.ceil(remainingMs / 60000);
    //     errMsg = `Username / password tidak sesuai (3/3). Mohon menunggu ${remainingMins} menit untuk dapat mencoba login kembali.`;
    //   }

    //   noOfAttempts.set(key.nik, record);
    //   return res.render('login', { error: errMsg, uid: details.uid, TURNSTILE_SITE_KEY: TURNSTILE_SITE_KEY });
    // }
    // noOfAttempts.delete(key.nik);

    let dbUser;
    if (isAuthValid) {
      // Check if user exists in DB (function in db.js)
      dbUser = await getUserWithAccess(user_id.toLowerCase());
      // if(!dbUser) {
      //   return res.render('login', {
      //     error: 'Akun belum terdaftar, silahkan hubungi administrator.',
      //     uid: details.uid,
      //     TURNSTILE_SITE_KEY: TURNSTILE_SITE_KEY
      //   });
      // }
      console.log('[findAccount] user found:', JSON.stringify(dbUser, null, 2));

      // CEK CURRENT LOGIN
      if (dbUser.current_session_id && force_login !== 'true') {
        setPending(req.params.uid, nik);
        return res.render('confirm-session', {
          uid: details.uid,
          device: escapeHtml(dbUser.lastdevicename) || '(Perangkat tidak diketahui)',
          loginAt: escapeHtml(dbUser.lastlogin) || '(Waktu login tidak diketahui)'
        });
      }

      return await finishLogin({ req, res, nik, details, params })
    }

    if (res.headersSent) return;
    return res.render('login', { error: response.data.LoginESS_V2Result, uid: req.params.uid, TURNSTILE_SITE_KEY: TURNSTILE_SITE_KEY });

  } catch (err) {
    console.error('Auth API error:', err.message);
    if (res.headersSent) return;
    return res.render('login', {
      error: err /*'Terjadi kesalahan pada sistem. Mohon tunggu.'*/,
      uid: req.params.uid,
      TURNSTILE_SITE_KEY: TURNSTILE_SITE_KEY
    });
  }
});

app.post('/interaction/:uid/login/confirm', async (req, res) => {
  const uid = req.params.uid;
 
  try {
    const pending = getPending(uid);
    if (!pending) {
      if (res.headersSent) return;
      return res.status(400).render('login', {
        error: 'Sesi konfirmasi telah kedaluwarsa. Silakan login kembali.',
        uid,
        TURNSTILE_SITE_KEY
      });
    }
 
    const details = await oidc.interactionDetails(req, res);
    const { params } = details;
 
    // const dbUser = await getUserWithAccess(pending.nik);
    // if (!dbUser) {
    //   clearPending(uid);
    //   return res.render('login', {
    //     error: 'Akun belum terdaftar, silahkan hubungi administrator.',
    //     uid,
    //     TURNSTILE_SITE_KEY
    //   });
    // }
 
    clearPending(uid);
    return await finishLogin({ req, res, nik: pending.nik, details, params });
 
  } catch (err) {
    console.error('Confirm login error:', err);
    clearPending(uid);
    if (res.headersSent) return;
    return res.render('login', {
      error: 'Authentication service is unavailable. Try again later.',
      uid,
      TURNSTILE_SITE_KEY
    });
  }
});

async function finishLogin({ req, res, nik, details, params }) {
  console.log('[finishLogin] starting with nik:', nik);
  
  const newSessionId = crypto.randomUUID();
  const currDeviceName = req.headers['user-agent'] || '(tidak diketahui)';
  
  console.log('[finishLogin] calling updateSessionId with:', { nik, newSessionId, currDeviceName });
  await updateSessionId(nik, newSessionId, currDeviceName);
  console.log('[finishLogin] updateSessionId completed');

  let grant;
  if (details.grantId) {
    console.log('[finishLogin] using existing grantId:', details.grantId);
    grant = await oidc.Grant.find(details.grantId);
  } else {
    console.log('[finishLogin] creating new grant for accountId:', nik);
    grant = new oidc.Grant({
      clientId: params.client_id,
      accountId: nik,
    });
  }

  if (params.scope) {
    grant.addOIDCScope(params.scope);
  }

  console.log('[finishLogin] calling grant.save()');
  const grantId = await grant.save();
  console.log('[finishLogin] grant saved, grantId:', grantId);

  const loginResult = { login: { accountId: nik }, consent: { grantId } };
  console.log('[finishLogin] calling interactionFinished with:', loginResult);
  try {
    await oidc.interactionFinished(req, res, loginResult, { mergeWithLastSubmission: false });
    console.log('[finishLogin] interactionFinished completed (should have redirected)');
  } catch (err) {
    console.error('[finishLogin] ERROR in interactionFinished:', err);
    console.error('[finishLogin] ERROR stack:', err.stack);
    throw err;
  }
}

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