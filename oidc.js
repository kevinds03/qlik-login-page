const { Provider } = require('oidc-provider');

const { getUserWithAccess } = require('./db');

const configuration = {
    clients: [
        {
            client_id: 'qliksense',
            client_secret: process.env.QLIKSENSE_SECRET,
            redirect_uris: ['https://qliksense/'],
            post_logout_redirect_uris: ['https://yourtenant.us.qlikcloud.com/logged-out'],
            frontchannel_logout_uri: 'https://yourtenant.us.qlikcloud.com/oidc-logout', // if QlikCloud supports it
            grant_types: ['authorization_code'],
            response_types:['code'], 
        },
        {
            client_id: 'qlikcloud',
            client_secret: process.env.QLIKCLOUD_SECRET,
            redirect_uris: ['https://qlikcloud/'],
            post_logout_redirect_uris: ['https://yourtenant.us.qlikcloud.com/logged-out'],
            frontchannel_logout_uri: 'https://yourtenant.us.qlikcloud.com/oidc-logout', // if QlikCloud supports it
            grant_types: ['authorization_code'],
            response_types:['code'],
        },
        {
            client_id: 'usermanage',
            client_secret: process.env.USERMANAGE_SECRET,
            redirect_uris: ['https://usermgt/'], // seusaikan link
            post_logout_redirect_uris: ['https://yourtenant.us.qlikcloud.com/logged-out'],
            frontchannel_logout_uri: 'https://yourtenant.us.qlikcloud.com/oidc-logout', // if QlikCloud supports it
            grant_types: ['authorization_code'],
            response_types:['code'], 
        },
        {
            client_id: 'publisher',
            client_secret: process.env.PUBLISHER_SECRET,
            redirect_uris: ['https://publisher/'], // seusaikan link
            post_logout_redirect_uris: ['https://yourtenant.us.qlikcloud.com/logged-out'],
            frontchannel_logout_uri: 'https://yourtenant.us.qlikcloud.com/oidc-logout', // if QlikCloud supports it
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
        stream: ['stream'],
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
    }
};

const oidc = new Provider(process.env.OIDC_ISSUER_URL, configuration);

module.exports = oidc;