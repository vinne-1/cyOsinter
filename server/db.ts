import { Pool } from "pg";
import { drizzle } from "drizzle-orm/node-postgres";
import * as schema from "@shared/schema";
import { createLogger } from "./logger";

const dbLog = createLogger("db");

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL environment variable is required");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

pool.on("error", (err) => {
  dbLog.error({ err }, "Unexpected pool error");
});

export const db = drizzle(pool, { schema });
