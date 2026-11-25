import "dotenv/config";

import { Pool } from "pg";

const pool = new Pool({
  host: process.env.HOST,
  user: process.env._USER,
  database: process.env.DATABASE,
  password: process.env.PASSWORD,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
  maxLifetimeSeconds: 60,
  ssl: {
    rejectUnauthorized: false,
  },
});

export default pool;
