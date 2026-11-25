import pool from "./pg.js";

export async function getUserDataByEmail(email) {
  const client = await pool.connect();
  const user = await client.query(
    `SELECT user_id, email, password FROM users WHERE email = $1`,
    [email],
  );
  client.release();
  return user.rows[0];
}
