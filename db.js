const { Pool } = require('pg');
 
const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT || 5432,
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  // ssl: { rejectUnauthorized: false } // uncomment if your Postgres requires SSL (e.g. managed cloud DB)
});

pool.on('error', (err) => {
    console.error('Unexpected PostgreSQL pool error:', err);
});

async function getNIK(id) {
    try {
        const res = await pool.query(
            'select nik from public.master_users where lower(userid) = lower($1);',
            [id]
        );

        if (res.rows.length === 0) return null;

        const user = res.rows[0];
        return user.nik;
    } catch {
        console.error('[db] getNIK error: ', err);
        throw err;
    }
}

// async function getCredentials(id) {
//     try {
//         const res = await pool.query(
//             'select password, iv from public.master_users where lower(userid) = lower($1);',
//             [id]
//         );

//         if (res.rows.length === 0) return null;
        
//         const user = res.rows[0];
//         return {
//             password: user.password,
//             iv: user.iv
//         };
//     } catch (err) {
//         console.error('[db] getCredentials error: ', err);
//         throw err;
//     }
// }

async function getUserWithAccess(id) {
    try {
        const userResult = await pool.query(
            'select nik, userid, is_admin, email, '+ // for login purposes
            'name, current_session_id, lastlogin, lastdevicename '+ // for user profile
            'from public.master_users '+
            'where nik::text = $1 or lower(userid::text) = $1;',
            [id]
        );
        // console.log('[db] master_users rows:', JSON.stringify(userResult.rows, null, 2));

        if (userResult.rows.length === 0) return null;

        const user = userResult.rows[0];

        const roleResult = await pool.query(
            'select value as "role" from qlik_user_attributes '+
            'where userid = $1 and "type" = $2;',
            [user.userid, 'qlik_role']
        );
        const role = roleResult.rows[0]?.role || null;
        // console.log('[db] master_role rows:', JSON.stringify(roleResult.rows, null, 2));

        const streamsResult = await pool.query(
            'select value as "stream_name" from qlik_user_attributes '+
            'where userid = $1 and "type" = $2;',
            [user.userid, 'stream_access']
        );
        // console.log('[db] master_streams rows:', JSON.stringify(streamsResult.rows, null, 2));

        const groupsResult = await pool.query(
            'select value as "group_name" from qlik_user_attributes '+
            'where userid = $1 and "type" = $2;',
            [user.userid, 'Group']
        );
        // console.log('[db] master_groups rows:', JSON.stringify(groupsResult.rows, null, 2));

        const result = {
            nik: user.nik,
            userid: user.userid,
            is_admin: user.is_admin,
            email: user.email,
            role: role,
            streams: streamsResult.rows.map(r => r.stream_name),
            groups: groupsResult.rows.map(r => r.group_name),
            current_session_id: user.current_session_id,
            lastlogin: user.lastlogin,
            lastdevicename: user.lastdevicename
        };
        
        // console.log('[db] getUserWithAccess result:', JSON.stringify(result, null, 2));
        
        return result;
    } catch (err) {
        console.error('[db] getUserWithAccess ERROR:', err);
        throw err;
    }
}

async function updateSessionId(id, sessionId, currDeviceName) {
    try {
        await pool.query(
            'update master_users set current_session_id = $1, lastlogin = NOW(), lastdevicename = $2'+
            'where nik::text = $3 or lower(userid::text) = $3',
            [sessionId, currDeviceName, id]
        );
        console.log('[db] updateSessionId: session ID updated to ', sessionId);
        console.log('[db] Device name updated to: ', currDeviceName);
    } catch (err) {
        console.error('[db] updateSessionId ERROR:', err);
        throw err;
    }
}

async function logoutUser(id) {
    try {
        await pool.query(
            'update master_users set current_session_id = NULL'+
            'where lower(userid::text) = lower($1)'+
            'or lower(nik::text) = lower($1)',
            [id]
        );
    } catch (err) {
      console.error('Logout failed: ', err.message);
      throw err;
    }
}

module.exports = { getNIK, /*getCredentials,*/ getUserWithAccess, updateSessionId, logoutUser };