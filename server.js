import express from "express";
import pool from "./pg.js";
import bcrypt from "bcrypt";
import cors from "cors";
import cookieParser from "cookie-parser";
import { createJWT, verifyJWT } from "./jwt.js";
import { Auth } from "./auth.js";

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(cookieParser());

app.use(
  cors({
    origin: "http://localhost:8081",
    credentials: true,
  }),
);

app.get("/", (req, res) => {
  res.json({ message: "Todo app backend is running" });
});

app.post("/signup", async (req, res) => {
  const { username, email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({
      error: "Email and password are required",
    });
  }

  try {
    const user = await pool.query(`SELECT email FROM users WHERE email = $1`, [
      email,
    ]);

    if (user.rows.length > 0) {
      return res.status(400).json({
        error: "User already exists",
      });
    }

    const hash = await bcrypt.hash(password, 10);
    await pool.query(
      `INSERT INTO users (username, email, password) VALUES ($1, $2, $3)`,
      [username, email, hash],
    );

    res.status(201).json({
      message: "User added successfully",
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({
      error: "Internal server error",
    });
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({
      error: "Email and password are required",
    });
  }
  try {
    const user = await pool.query(`SELECT * FROM users WHERE email=$1`, [
      email,
    ]);
    if (user.rows.length === 0) {
      return res.status(400).json({
        error: "User does not exist",
      });
    }
    const validPassword = await bcrypt.compare(password, user.rows[0].password);
    if (!validPassword) {
      return res.status(400).json({
        error: "Invalid password",
      });
    }
    let payload = {
      email: user.rows[0].email,
      username: user.rows[0].username,
    };

    let accessToken = createJWT(
      payload,
      process.env.ACCESS_TOKEN_KEY,
      process.env.ACCESS_TOKEN_EXPIRY,
    );
    let refreshToken = createJWT(
      payload,
      process.env.REFRESH_TOKEN_KEY,
      process.env.REFRESH_TOKEN_EXPIRY,
    );

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true, // Prevents JavaScript (XSS) from reading the cookie
      secure: process.env.NODE_ENV === "production", // true on HTTPS, false on localhost
      sameSite: "lax", // Protects against CSRF ("none" + secure: true if cross-domain in prod)
      maxAge: 2 * 60 * 1000, //2 minutes in milliseconds
    });

    return res.status(200).json({
      message: "Login success",
      accessToken,
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({
      error: "Internal server error",
    });
  }
});

app.post("/refresh", async (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) {
    return res.status(401).json({ error: "Refresh token not found" });
  }

  try {
    const payload = verifyJWT(refreshToken, process.env.REFRESH_TOKEN_KEY);
    const newAccessToken = createJWT(
      { email: payload.email, username: payload.username },
      process.env.ACCESS_TOKEN_KEY,
      process.env.ACCESS_TOKEN_EXPIRY,
    );

    const newRefreshToken = createJWT(
      { email: payload.email, username: payload.username },
      process.env.REFRESH_TOKEN_KEY,
      process.env.REFRESH_TOKEN_EXPIRY,
    );

    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 2 * 60 * 1000, // 2 minutes in milliseconds
    });

    return res.status(200).json({
      accessToken: newAccessToken,
    });
  } catch (err) {
    console.error(err.message);
    return res.status(403).json({ error: "Invalid refresh token" });
  }
});

const TODO_COLUMNS = "id, title, completed, created_at";

const parseId = (value) => {
  const id = Number(value);
  return Number.isInteger(id) && id > 0 ? id : null;
};

// GET /todo -> all todos of the logged-in user, newest first
app.get("/todo", Auth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT ${TODO_COLUMNS} FROM todos
       WHERE user_id = $1
       ORDER BY created_at DESC, id DESC`,
      [req.user.id],
    );
    res.json(rows);
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: "Could not load todos." });
  }
});

// POST /todo  body: { title }  (also accepts { text } from your current frontend)
app.post("/todo", Auth, async (req, res) => {
  const raw = req.body?.title ?? req.body?.text;
  const title = typeof raw === "string" ? raw.trim() : "";

  if (!title) {
    return res.status(400).json({ error: "Title is required." });
  }
  if (title.length > 500) {
    return res.status(400).json({ error: "Title is too long." });
  }

  try {
    const { rows } = await pool.query(
      `INSERT INTO todos (user_id, title)
       VALUES ($1, $2)
       RETURNING ${TODO_COLUMNS}`,
      [req.user.id, title],
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: "Could not add todo." });
  }
});

// PATCH /todo/:id  body: { title?, completed? }
app.patch("/todo/:id", Auth, async (req, res) => {
  const id = parseId(req.params.id);
  if (!id) return res.status(400).json({ error: "Invalid todo id." });

  const { title, completed } = req.body ?? {};

  let newTitle = null;
  if (title !== undefined) {
    if (typeof title !== "string" || !title.trim()) {
      return res.status(400).json({ error: "Title cannot be empty." });
    }
    newTitle = title.trim();
  }

  let newCompleted = null;
  if (completed !== undefined) {
    if (typeof completed !== "boolean") {
      return res.status(400).json({ error: "Completed must be a boolean." });
    }
    newCompleted = completed;
  }

  if (newTitle === null && newCompleted === null) {
    return res.status(400).json({ error: "Nothing to update." });
  }

  try {
    const { rows } = await pool.query(
      `UPDATE todos
       SET title     = COALESCE($1, title),
           completed = COALESCE($2, completed)
       WHERE id = $3 AND user_id = $4
       RETURNING ${TODO_COLUMNS}`,
      [newTitle, newCompleted, id, req.user.id],
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: "Todo not found." });
    }
    res.json(rows[0]);
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: "Could not update todo." });
  }
});

// DELETE /todo/:id
app.delete("/todo/:id", Auth, async (req, res) => {
  const id = parseId(req.params.id);
  if (!id) return res.status(400).json({ error: "Invalid todo id." });

  try {
    const result = await pool.query(
      `DELETE FROM todos WHERE id = $1 AND user_id = $2`,
      [id, req.user.id],
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: "Todo not found." });
    }
    res.status(204).send();
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: "Could not delete todo." });
  }
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
