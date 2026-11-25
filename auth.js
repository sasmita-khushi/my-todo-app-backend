import { verifyJWT } from "./jwt.js";
import pool from "./pg.js";

export async function Auth(req, res, next) {
  const header = req.headers.authorization || "";
  const [scheme, token] = header.split(" ");

  if (scheme !== "Bearer" || !token) {
    return res.status(401).json({ error: "Access token missing" });
  }

  const payload = verifyJWT(token, process.env.ACCESS_TOKEN_KEY);
  if (!payload?.email) {
    return res.status(401).json({ error: "Invalid or expired access token" });
  }

  try {
    const result = await pool.query(
      `SELECT id, email, username FROM users WHERE email = $1`,
      [payload.email],
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Authenticated user not found" });
    }

    req.user = {
      id: result.rows[0].id,
      email: result.rows[0].email,
      username: result.rows[0].username,
    };
    return next();
  } catch (err) {
    console.error("Authentication error:", err.message);
    return res.status(500).json({ error: "Internal server error" });
  }
}
