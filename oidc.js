const { Provider } = require('oidc-provider');

const { getUserWithAccess, getActiveSession, logoutUser } = require('./db');

const configuration = {
    clients: [
        {
            client_id: process.env.QLIKSENSE_CLIENT_ID || 'qliksense',
            client_secret: process.env.QLIKSENSE_SECRET,
            redirect_uris: process.env.QLIKSENSE_REDIRECT_URI.split(',').map(uri => uri.trim()),
            post_logout_redirect_uris: process.env.QLIKSENSE_LOGOUT_REDIRECT_URI.split(',').map(uri => uri.trim()),
            // frontchannel_logout_uri: QLIKSENSE_FRONTCHANNEL_LOGOUT_URI, // if QlikSense supports it
            grant_types: ['authorization_code'],
            response_types:['code'], 
        },
        {
            client_id: process.env.QLIKCLOUD_CLIENT_ID || 'qlikcloud',
            client_secret: process.env.QLIKCLOUD_SECRET,
            redirect_uris: process.env.QLIKCLOUD_REDIRECT_URI.split(',').map(uri => uri.trim()),
            post_logout_redirect_uris: process.env.QLIKCLOUD_LOGOUT_REDIRECT_URI.split(',').map(uri => uri.trim()),
            // frontchannel_logout_uri: QLIKCLOUD_FRONTCHANNEL_LOGOUT_URI, // if QlikCloud supports it
            grant_types: ['authorization_code'],
            response_types:['code'],
        },
        {
            client_id: process.env.USERMANAGE_CLIENT_ID || 'usermanage',
            client_secret: process.env.USERMANAGE_SECRET,
            redirect_uris: process.env.USERMANAGE_REDIRECT_URI.split(',').map(uri => uri.trim()),
            post_logout_redirect_uris: process.env.USERMANAGE_LOGOUT_REDIRECT_URI.split(',').map(uri => uri.trim()),
            // frontchannel_logout_uri: USERMANAGE_FRONTCHANNEL_LOGOUT_URI, // if QlikCloud supports it
            grant_types: ['authorization_code'],
            response_types:['code'], 
        },
        {
            client_id: process.env.PUBLISHER_CLIENT_ID || 'publisher',
            client_secret: process.env.PUBLISHER_SECRET,
            redirect_uris: process.env.PUBLISHER_REDIRECT_URI.split(',').map(uri => uri.trim()),
            post_logout_redirect_uris: process.env.PUBLISHER_LOGOUT_REDIRECT_URI.split(',').map(uri => uri.trim()),
            // frontchannel_logout_uri: PUBLISHER_FRONTCHANNEL_LOGOUT_URI, // if QlikCloud supports it
            grant_types: ['authorization_code'],
            response_types:['code'], 
        }
    ],
    pkce: {
        required: () => false
    },
    claims: {
        openid: ['sub'],
        profile: ['userid', 'is_admin', 'role'],
        email: ['email'],
        qlik_access: ['streams', 'groups'],
    },
    findAccount: async(ctx, sub) => {
        console.log('[findAccount] looking up sub:', sub);

        const user = await getUserWithAccess(sub);
        if (!user) { 
            console.log('[findAccount] no matching user found for sub:', sub);
            return undefined;
        }

        const activeSession = await getActiveSession(sub);
        if (!activeSession) {
            await logoutUser;
            return undefined;
        }

        return {
            accountId: sub,
            async claims(use, scope) {
                return { 
                    sub,
                    nik: user.nik,
                    userid: user.userid,
                    email: user.email,
                    is_admin: user.is_admin,
                    role: user.role,
                    streams: user.streams,
                    groups: user.groups,
                    current_session_id: user.current_session_id,
                    lastlogin: user.lastlogin ? new Date(user.lastlogin).toLocaleString('id-ID') : 'No last login detected',
                    lastdevicename: user.lastdevicename || 'Device not recognized'
                };
            }
        };
    },
    features: {
        backchannelLogout: { enabled: true },
        rpInitiatedLogout: { enabled: true },
        devInteractions: { enabled: false }
    },
    interactions: {
        url(ctx, interaction) {
            return `/interaction/${interaction.uid}`;
        }
    },
    cookies: {
        keys: [process.env.SESSION_SECRET]
    },
    jwks: JSON.parse(process.env.OIDC_JWKS)
};

const oidc = new Provider(process.env.OIDC_ISSUER_URL, configuration);

console.log('OIDC provider constructed OK:', typeof oidc.callback);

// This fires automatically when /oidc/session/end completes (RP-initiated logout)
oidc.on('end_session.success', async (ctx) => {
  try {
    const accountId = ctx.oidc?.session?.accountId;
    if (!accountId) {
      console.log('[end_session.success] no accountId found, skipping DB logout');
      return;
    }

    console.log('[end_session.success] clearing session for:', accountId);
    await logoutUser(accountId);
    console.log('[end_session.success] session cleared successfully');
  } catch (err) {
    console.error('[end_session.success] failed to clear session:', err);
    // Don't throw — logout already succeeded at the OIDC level,
    // DB cleanup failure shouldn't break the user's experience
  }
});

oidc.proxy = true;

module.exports = oidc;