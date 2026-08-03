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

async function getUserWithAccess(nik) {
    const UserResult = await pool.query(
        'select "userid", "is_admin", "email" from public.master_users '+
        'where mu.nik = $1;'
        [nik]
    );

    if (UserResult.rows.length === 0) return null;

    const user = UserResult.rows[0];

    const roleResult = await pool.query(
        'select value as "role" from qlik_user_attributes '+
        'where userid = $1 and "type" = "qlik_role";',
        [user.userid]
    );
    const role = roleResult.rows[0];

    const streamsResult = await pool.query(
        'select value as "stream_name" from qlik_user_attributes '+
        'where userid = $1 and "type" = "stream_access"; ',
        [user.userid]
    );

    const groupsResult = await pool.query(
        'select value as "group_name" from qlik_user_attributes '+
        'where userid = $1 and "type" = "Group";',
        [user.userid]
    );

    return {
        userid: user.userid,
        email: user.email,
        is_admin: user.is_admin,
        role: role.role,
        streams: streamsResult.rows.map(r => r.stream_name),
        groups: groupsResult.rows.map(r => r.group_name)
    };  
}

module.exports = { getUserWithAccess, pool };