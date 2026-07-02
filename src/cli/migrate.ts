import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";
import { config as loadDotenv } from "dotenv";
import { PostgresDb } from "../db.js";

loadDotenv();

const databaseUrl = process.env.DATABASE_URL?.trim();
if (!databaseUrl) {
  throw new Error("Missing required environment variable DATABASE_URL");
}

const db = new PostgresDb(databaseUrl);

await db.query(`
  CREATE TABLE IF NOT EXISTS schema_migrations (
    filename text PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT now()
  )
`);

const migrationsDir = resolve(process.cwd(), "migrations");
const files = readdirSync(migrationsDir)
  .filter((file) => file.endsWith(".sql"))
  .sort();

for (const file of files) {
  const existing = await db.query("SELECT 1 FROM schema_migrations WHERE filename = $1", [file]);
  if (existing.rowCount) {
    continue;
  }
  const sql = readFileSync(resolve(migrationsDir, file), "utf8");
  await db.transaction(async (tx) => {
    await tx.query(sql);
    await tx.query("INSERT INTO schema_migrations (filename) VALUES ($1)", [file]);
  });
  console.log(`Applied ${file}`);
}

await db.close();
