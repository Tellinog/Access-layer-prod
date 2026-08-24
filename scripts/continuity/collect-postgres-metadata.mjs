#!/usr/bin/env node
/** Collect PostgreSQL schema/migration metadata in a read-only transaction. */

import { createHash } from "node:crypto";
import process from "node:process";
import { pathToFileURL } from "node:url";
import pg from "pg";

const { Client } = pg;

async function queryRows(client, text) {
  return (await client.query(text)).rows;
}

export async function collectPostgresMetadata(connectionString) {
  if (!connectionString) throw new Error("DATABASE_URL is not present");
  const client = new Client({ connectionString, application_name: "access-layer-continuity-readonly" });
  await client.connect();
  try {
    await client.query("BEGIN READ ONLY");
    await client.query("SET LOCAL statement_timeout = '10s'");
    const identity = (await client.query("SELECT current_database() AS database_name, current_setting('server_version') AS server_version")).rows[0];
    const columns = await queryRows(client, `
      SELECT table_schema, table_name, column_name, ordinal_position, data_type, is_nullable, column_default
      FROM information_schema.columns
      WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
      ORDER BY table_schema, table_name, ordinal_position
    `);
    const constraints = await queryRows(client, `
      SELECT table_schema, table_name, constraint_name, constraint_type
      FROM information_schema.table_constraints
      WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
      ORDER BY table_schema, table_name, constraint_name
    `);
    const migrationTable = await client.query("SELECT to_regclass('public.schema_migrations') AS name");
    const appliedMigrations = migrationTable.rows[0]?.name
      ? (await client.query("SELECT filename FROM public.schema_migrations ORDER BY filename")).rows.map((row) => row.filename)
      : [];
    await client.query("COMMIT");
    const canonical = JSON.stringify({ columns, constraints });
    const missing = [];
    if (!migrationTable.rows[0]?.name) missing.push("schema_migrations");
    if (appliedMigrations.length === 0) missing.push("applied_migration_ids");
    return {
      status: missing.length === 0 ? "OBSERVED" : "NOT_READY",
      collected_at: new Date().toISOString(),
      server_version: identity.server_version,
      database_name: identity.database_name,
      schema_fingerprint_sha256: createHash("sha256").update(canonical).digest("hex"),
      migration_table_present: Boolean(migrationTable.rows[0]?.name),
      applied_migration_ids: appliedMigrations,
      metadata_counts: { columns: columns.length, constraints: constraints.length },
      row_contents_collected: false,
      missing,
    };
  } catch (error) {
    try { await client.query("ROLLBACK"); } catch { /* connection may already be closed */ }
    throw error;
  } finally {
    await client.end();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const report = await collectPostgresMetadata(process.env.DATABASE_URL);
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    process.exitCode = report.status === "OBSERVED" ? 0 : 2;
  } catch (error) {
    // Never echo driver messages: they may include connection details.
    const rawCode = error && typeof error === "object" && "code" in error ? String(error.code) : "";
    const code = /^[A-Z0-9]{5}$/.test(rawCode) ? rawCode : "UNOBSERVED";
    process.stderr.write(`PostgreSQL metadata observation failed (${code}). No connection details were printed.\n`);
    process.exitCode = 2;
  }
}
