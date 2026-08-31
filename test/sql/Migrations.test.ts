import { PgliteClient } from "@effect/sql-pglite"
import { assert, describe, it } from "@effect/vitest"
import { Effect } from "effect"
import { SqlClient } from "effect/unstable/sql"
import * as Migrations from "../../src/sql/Migrations.js"

interface TableRow {
  readonly name: unknown
}

describe("sql/Migrations", () => {
  it.effect("applies every migration to an empty database", () =>
    Effect.gen(function*() {
      const applied = yield* Migrations.run

      assert.deepStrictEqual(applied.map(([id]) => id), [1, 2, 3, 4])
      assert.deepStrictEqual(applied.map(([, name]) => name), [
        "create_users",
        "create_sessions",
        "create_accounts",
        "create_verifications"
      ])

      const sql = yield* SqlClient.SqlClient
      const tables = yield* sql<TableRow>`SELECT table_name AS "name" FROM information_schema.tables
        WHERE table_schema = 'public' ORDER BY table_name`

      assert.deepStrictEqual(tables.map((row) => row.name), [
        "accounts",
        "effect_auth_migrations",
        "sessions",
        "users",
        "verifications"
      ])
    }).pipe(Effect.provide(PgliteClient.layer())))

  it.effect("is idempotent on a second run", () =>
    Effect.gen(function*() {
      yield* Migrations.run
      const second = yield* Migrations.run

      assert.deepStrictEqual(second, [])
    }).pipe(Effect.provide(PgliteClient.layer())))

  it.effect("creates the indexes the stores rely on", () =>
    Effect.gen(function*() {
      yield* Migrations.run

      const sql = yield* SqlClient.SqlClient
      const indexes = yield* sql<TableRow>`SELECT indexname AS "name" FROM pg_indexes
        WHERE schemaname = 'public' ORDER BY indexname`
      const names = indexes.map((row) => row.name)

      for (
        const expected of [
          "users_email_unique",
          "sessions_token_hash_unique",
          "sessions_user_id_idx",
          "accounts_issuer_account_id_unique",
          "accounts_user_id_idx",
          "verifications_identifier_idx"
        ]
      ) {
        assert.include(names as Array<string>, expected)
      }
    }).pipe(Effect.provide(PgliteClient.layer())))
})

describe("sql/Migrations.make", () => {
  const createLinks = Effect.flatMap(
    SqlClient.SqlClient,
    (sql) => sql`CREATE TABLE IF NOT EXISTS plugin_links (id text PRIMARY KEY)`
  )

  const plugin = Migrations.make({
    table: "effect_auth_plugin_migrations",
    migrations: { "0001_create_links": createLinks }
  })

  it.effect("records a plugin's migrations in a bookkeeping table of its own", () =>
    Effect.gen(function*() {
      // Sequenced, as a plugin whose tables reference this library's must be.
      yield* Migrations.run
      const applied = yield* plugin.run

      // Its numbering starts at 1 and is entirely its own business: this is
      // exactly what merging the two records would have made impossible.
      assert.deepStrictEqual(applied, [[1, "create_links"]])
      assert.deepStrictEqual(yield* plugin.run, [])

      const sql = yield* SqlClient.SqlClient
      const tables = yield* sql<TableRow>`SELECT table_name AS "name" FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name LIKE '%migrations' ORDER BY table_name`

      assert.deepStrictEqual(tables.map((row) => row.name), [
        "effect_auth_migrations",
        "effect_auth_plugin_migrations"
      ])
    }).pipe(Effect.provide(PgliteClient.layer())))
})
