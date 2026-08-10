const { Provider } = require('oidc-provider');

const { getUserWithAccess } = require('./db');

const configuration = {
    clients: [
        {
            client_id: process.env.QLIKSENSE_CLIENT_ID || 'qliksense',
            client_secret: process.env.QLIKSENSE_SECRET,
            redirect_uris: [process.env.QLIKSENSE_REDIRECT_URI.split(',').map(uri => uri.trim())],
            post_logout_redirect_uris: [process.env.QLIKSENSE_LOGOUT_REDIRECT_URI.split(',').map(uri => uri.trim())],
            // frontchannel_logout_uri: QLIKSENSE_FRONTCHANNEL_LOGOUT_URI, // if QlikSense supports it
            grant_types: ['authorization_code'],
            response_types:['code'], 
        },
        {
            client_id: process.env.QLIKCLOUD_CLIENT_ID || 'qlikcloud',
            client_secret: process.env.QLIKCLOUD_SECRET,
            redirect_uris: [process.env.QLIKCLOUD_REDIRECT_URI.split(',').map(uri => uri.trim())],
            post_logout_redirect_uris: [process.env.QLIKCLOUD_LOGOUT_REDIRECT_URI.split(',').map(uri => uri.trim())],
            // frontchannel_logout_uri: QLIKCLOUD_FRONTCHANNEL_LOGOUT_URI, // if QlikCloud supports it
            grant_types: ['authorization_code'],
            response_types:['code'],
        },
        {
            client_id: process.env.USERMANAGE_CLIENT_ID || 'usermanage',
            client_secret: process.env.USERMANAGE_SECRET,
            redirect_uris: [process.env.USERMANAGE_REDIRECT_URI.split(',').map(uri => uri.trim())],
            post_logout_redirect_uris: [process.env.USERMANAGE_LOGOUT_REDIRECT_URI.split(',').map(uri => uri.trim())],
            // frontchannel_logout_uri: USERMANAGE_FRONTCHANNEL_LOGOUT_URI, // if QlikCloud supports it
            grant_types: ['authorization_code'],
            response_types:['code'], 
        },
        {
            client_id: process.env.PUBLISHER_CLIENT_ID || 'publisher',
            client_secret: process.env.PUBLISHER_SECRET,
            redirect_uris: [process.env.PUBLISHER_REDIRECT_URI.split(',').map(uri => uri.trim())],
            post_logout_redirect_uris: [process.env.PUBLISHER_LOGOUT_REDIRECT_URI.split(',').map(uri => uri.trim())],
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
        profile: ['username'],
        email: ['email'],
        qlik_acess: ['streams', 'groups'],
    },
    findAccount: async(ctx, sub) => {
        const user = await getUserWithAccess(sub);
        if (!user) return undefined;

        return {
            accountID: sub,
            async claims(use, scope) {
                return { 
                    sub,
                    userid: user.userid,
                    email: user.email,
                    is_admin: user.is_admin,
                    role: user.role,
                    streams: user.streams,
                    groups: user.groups
                };
            }
        };
    },
    features: {
        backchannelLogout: { enabled: true },
        rpInitiatedLogout: { enabled: true }
    },
    cookies: {
        keys: [process.env.SESSION_SECRET]
    },
    jwks: JSON.parse(process.env.OIDC_JWKS)
};

const oidc = new Provider(process.env.OIDC_ISSUER_URL, configuration);

oidc.proxy = true;

module.exports = oidc;