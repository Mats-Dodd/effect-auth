/**
 * The three catalogs behind `TestDatabase`.
 *
 * `information_schema`, `pg_catalog`, `PRAGMA` and the three reset dialects
 * live here, and this is the only place a *test* reaches one: a test asks
 * `TestDatabase` for table, column and index names and never learns which
 * database answered. (`Migrations.forUserFields` introspects on its own account
 * — it runs in the library, on every boot — and `test/sql/Dialect.test.ts` is
 * the one file whose subject is a dialect's own facts.)
 *
 * Not part of the public API — `effect-auth/testing` re-exports `Database`, not
 * this module.
 *
 * @internal
 */
import { Effect } from "effect"
import type { SqlClient, SqlError } from "effect/unstable/sql"
import type { TestDatabaseService } from "../Database.js"

/** A one-column catalog answer. Drivers disagree on the JavaScript type. */
interface NameRow {
  readonly name: unknown
}

const names = (rows: ReadonlyArray<NameRow>): ReadonlyArray<string> => rows.map((row) => String(row.name))

/**
 * The migration bookkeeping tables, which `reset` leaves alone: this library's
 * `effect_auth_migrations` and every plugin's `effect_auth_<plugin>_migrations`.
 * Emptying them would make a migration test pass against a schema that was
 * never built.
 */
const isBookkeeping = (table: string): boolean => table.endsWith("_migrations")

/** The tables `reset` empties: everything the build holds but the bookkeeping. */
const resettable = (
  tables: Effect.Effect<ReadonlyArray<string>, SqlError.SqlError>
): Effect.Effect<ReadonlyArray<string>, SqlError.SqlError> =>
  Effect.map(tables, (all) => all.filter((table) => !isBookkeeping(table)))

/**
 * PostgreSQL, for the real driver and for PGlite alike: both answer
 * `current_schema()`, which is the per-build schema under PGlite and `public`
 * in a per-build database.
 *
 * @internal
 */
export const postgres = (sql: SqlClient.SqlClient): TestDatabaseService => {
  const tableNames = Effect.map(
    sql<NameRow>`SELECT table_name AS name FROM information_schema.tables
      WHERE table_schema = current_schema() AND table_type = 'BASE TABLE'
      ORDER BY table_name`,
    names
  )
  return {
    dialect: "pg",
    // One statement: `CASCADE` follows the foreign keys, so no order is needed
    // and no constraint is ever suspended.
    reset: Effect.flatMap(resettable(tableNames), (tables) =>
      tables.length === 0
        ? Effect.void
        : Effect.asVoid(sql`TRUNCATE TABLE ${sql.csv(tables.map((table) => sql`${sql(table)}`))} CASCADE`)
    ),
    tableNames,
    columnNames: (table) =>
      Effect.map(
        sql<NameRow>`SELECT column_name AS name FROM information_schema.columns
          WHERE table_schema = current_schema() AND table_name = ${table}
          ORDER BY ordinal_position`,
        names
      ),
    indexNames: (table) =>
      Effect.map(
        sql<NameRow>`SELECT index_class.relname AS name
          FROM pg_index
          JOIN pg_class AS table_class ON table_class.oid = pg_index.indrelid
          JOIN pg_class AS index_class ON index_class.oid = pg_index.indexrelid
          JOIN pg_namespace ON pg_namespace.oid = table_class.relnamespace
          WHERE pg_namespace.nspname = current_schema()
            AND table_class.relname = ${table}
            AND pg_index.indisprimary = false
          ORDER BY index_class.relname`,
        names
      )
  }
}

/**
 * SQLite, through the pragma table-valued functions so that a table name is a
 * bound parameter rather than something interpolated into the statement.
 *
 * @internal
 */
export const sqlite = (sql: SqlClient.SqlClient): TestDatabaseService => {
  const tableNames = Effect.map(
    sql<NameRow>`SELECT name FROM sqlite_master
      WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
      ORDER BY name`,
    names
  )
  return {
    dialect: "sqlite",
    // `defer_foreign_keys` is transaction-scoped and clears itself at COMMIT,
    // so — unlike `PRAGMA foreign_keys = OFF` — a reset cannot leave the
    // connection with enforcement switched off.
    reset: Effect.flatMap(resettable(tableNames), (tables) =>
      tables.length === 0
        ? Effect.void
        : sql.withTransaction(
            Effect.gen(function* () {
              yield* sql`PRAGMA defer_foreign_keys = ON`
              for (const table of tables) yield* sql`DELETE FROM ${sql(table)}`
            })
          )
    ),
    tableNames,
    columnNames: (table) => Effect.map(sql<NameRow>`SELECT name FROM pragma_table_info(${table}) ORDER BY cid`, names),
    indexNames: (table) =>
      Effect.map(sql<NameRow>`SELECT name FROM pragma_index_list(${table}) WHERE origin <> 'pk' ORDER BY name`, names)
  }
}

/**
 * MySQL. `DATABASE()` is the per-build database, so every answer is scoped to
 * this build without the schema name having to be threaded through.
 *
 * @internal
 */
export const mysql = (sql: SqlClient.SqlClient): TestDatabaseService => {
  const tableNames = Effect.map(
    sql<NameRow>`SELECT table_name AS name FROM information_schema.tables
      WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE'
      ORDER BY table_name`,
    names
  )
  return {
    dialect: "mysql",
    // `FOREIGN_KEY_CHECKS` is a session variable and the transaction holds one
    // connection for the duration, so the suspension cannot escape onto another
    // connection in the pool. It is restored on the way out.
    reset: Effect.flatMap(resettable(tableNames), (tables) =>
      tables.length === 0
        ? Effect.void
        : sql.withTransaction(
            Effect.gen(function* () {
              yield* sql`SET FOREIGN_KEY_CHECKS = 0`
              yield* Effect.ensuring(
                Effect.forEach(tables, (table) => sql`DELETE FROM ${sql(table)}`, { discard: true }),
                Effect.orDie(sql`SET FOREIGN_KEY_CHECKS = 1`)
              )
            })
          )
    ),
    tableNames,
    columnNames: (table) =>
      Effect.map(
        sql<NameRow>`SELECT column_name AS name FROM information_schema.columns
          WHERE table_schema = DATABASE() AND table_name = ${table}
          ORDER BY ordinal_position`,
        names
      ),
    indexNames: (table) =>
      Effect.map(
        sql<NameRow>`SELECT DISTINCT index_name AS name FROM information_schema.statistics
          WHERE table_schema = DATABASE() AND table_name = ${table} AND index_name <> 'PRIMARY'
          ORDER BY index_name`,
        names
      )
  }
}
