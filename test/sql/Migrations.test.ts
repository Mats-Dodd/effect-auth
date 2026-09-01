import { PgliteClient } from "@effect/sql-pglite"
import { assert, layer } from "@effect/vitest"
import { Effect } from "effect"
import { SqlClient } from "effect/unstable/sql"
import * as Migrations from "../../src/sql/Migrations.js"

interface TableRow {
  readonly name: string
}

/**
 * A database per test, as each of these needs.
 *
 * "applies every migration to an empty database" and "is idempotent on a second
 * run" are both statements about a database whose whole history is the test's
 * own, so they cannot share one: a sibling that had already migrated would make
 * either of them pass for the wrong reason. `@effect/vitest` builds a block's
 * layer once and gives a sibling block a memo map of its own, so one block per
 * test is what keeps them isolated.
 */
const database = () => PgliteClient.layer()

layer(database())("sql/Migrations", (it) => {
  it.effect("applies every migration to an empty database", () =>
    Effect.gen(function* () {
      const applied = yield* Migrations.run

      assert.deepStrictEqual(
        applied.map(([id]) => id),
        [1, 2, 3, 4, 5]
      )
      assert.deepStrictEqual(
        applied.map(([, name]) => name),
        ["create_users", "create_sessions", "create_accounts", "create_verifications", "session_remember_me"]
      )

      const sql = yield* SqlClient.SqlClient
      const tables = yield* sql<TableRow>`SELECT table_name AS "name" FROM information_schema.tables
        WHERE table_schema = 'public' ORDER BY table_name`

      assert.deepStrictEqual(
        tables.map((row) => row.name),
        ["accounts", "effect_auth_migrations", "sessions", "users", "verifications"]
      )
    })
  )
})

layer(database())("sql/Migrations", (it) => {
  it.effect("is idempotent on a second run", () =>
    Effect.gen(function* () {
      yield* Migrations.run
      const second = yield* Migrations.run

      assert.deepStrictEqual(second, [])
    })
  )
})

layer(database())("sql/Migrations", (it) => {
  it.effect("adds the sessions.remember_me flag, defaulted so existing rows are remembered", () =>
    Effect.gen(function* () {
      yield* Migrations.run

      const sql = yield* SqlClient.SqlClient
      const columns = yield* sql<TableRow>`SELECT column_name AS "name" FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'sessions' ORDER BY column_name`

      assert.include(
        columns.map((row) => row.name),
        "remember_me"
      )

      // A row inserted without stating the flag inherits the DEFAULT, so a
      // deployment's pre-existing sessions read back as remembered rather than
      // as a NULL the model cannot decode.
      yield* sql`INSERT INTO users (id, name, email, email_verified, image, created_at, updated_at)
        VALUES ('u-remember', 'Ada', 'remember@example.com', false, NULL, '2024-01-01T00:00:00.000Z', '2024-01-01T00:00:00.000Z')`
      yield* sql`INSERT INTO sessions (id, token_hash, user_id, expires_at, ip_address, user_agent, created_at, updated_at)
        VALUES ('s-remember', 'hash-remember', 'u-remember', '2999-01-01T00:00:00.000Z', NULL, NULL, '2024-01-01T00:00:00.000Z', '2024-01-01T00:00:00.000Z')`

      const rows = yield* sql<{ readonly rememberMe: unknown }>`SELECT remember_me AS "rememberMe"
        FROM sessions WHERE id = 's-remember'`
      assert.strictEqual(rows[0]?.rememberMe, true)
    })
  )
})

layer(database())("sql/Migrations", (it) => {
  it.effect("creates the indexes the stores rely on", () =>
    Effect.gen(function* () {
      yield* Migrations.run

      const sql = yield* SqlClient.SqlClient
      const indexes = yield* sql<TableRow>`SELECT indexname AS "name" FROM pg_indexes
        WHERE schemaname = 'public' ORDER BY indexname`
      const names = indexes.map((row) => row.name)

      for (const expected of [
        "users_email_unique",
        "sessions_token_hash_unique",
        "sessions_user_id_idx",
        "accounts_issuer_account_id_unique",
        "accounts_user_id_idx",
        "verifications_identifier_idx"
      ]) {
        assert.include(names, expected)
      }
    })
  )
})

const createLinks = Effect.flatMap(
  SqlClient.SqlClient,
  (sql) => sql`CREATE TABLE IF NOT EXISTS plugin_links (id text PRIMARY KEY)`
)

const plugin = Migrations.make({
  table: "effect_auth_plugin_migrations",
  migrations: { "0001_create_links": createLinks }
})

layer(database())("sql/Migrations.make", (it) => {
  it.effect("records a plugin's migrations in a bookkeeping table of its own", () =>
    Effect.gen(function* () {
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

      assert.deepStrictEqual(
        tables.map((row) => row.name),
        ["effect_auth_migrations", "effect_auth_plugin_migrations"]
      )
    })
  )
})
