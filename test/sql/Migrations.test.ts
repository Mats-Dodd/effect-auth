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
        [1, 2, 3, 4, 5, 6]
      )
      assert.deepStrictEqual(
        applied.map(([, name]) => name),
        [
          "create_users",
          "create_sessions",
          "create_accounts",
          "create_verifications",
          "session_remember_me",
          "session_assurance"
        ]
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
      // `authenticated_at` has no DEFAULT on purpose — only the writer knows
      // when the person actually authenticated — so it is stated here, while
      // `remember_me`, `aal` and `methods` are the ones being left to theirs.
      yield* sql`INSERT INTO sessions (id, token_hash, user_id, expires_at, ip_address, user_agent, authenticated_at, created_at, updated_at)
        VALUES ('s-remember', 'hash-remember', 'u-remember', '2999-01-01T00:00:00.000Z', NULL, NULL, '2024-01-01T00:00:00.000Z', '2024-01-01T00:00:00.000Z', '2024-01-01T00:00:00.000Z')`

      const rows = yield* sql<{ readonly rememberMe: unknown }>`SELECT remember_me AS "rememberMe"
        FROM sessions WHERE id = 's-remember'`
      assert.strictEqual(rows[0]?.rememberMe, true)
    })
  )
})

layer(database())("sql/Migrations", (it) => {
  it.effect("backfills sessions.authenticated_at from created_at, and defaults the derived columns", () =>
    Effect.gen(function* () {
      const sql = yield* SqlClient.SqlClient

      // The `sessions` table as an existing deployment has it — every column
      // through `0005` and none of this migration's — with a row already in
      // it. What the migration does to *that* row is the whole point, and it is
      // unobservable if the row is written afterwards. The migrator's own
      // `CREATE TABLE IF NOT EXISTS` then finds this table and leaves it alone.
      yield* sql`CREATE TABLE users (
        id text PRIMARY KEY,
        name text NOT NULL,
        email text NOT NULL,
        email_verified boolean NOT NULL DEFAULT false,
        image text,
        created_at text NOT NULL,
        updated_at text NOT NULL
      )`
      yield* sql`CREATE TABLE sessions (
        id text PRIMARY KEY,
        token_hash text NOT NULL,
        user_id text NOT NULL REFERENCES users (id) ON DELETE CASCADE,
        expires_at text NOT NULL,
        ip_address text,
        user_agent text,
        remember_me boolean NOT NULL DEFAULT true,
        created_at text NOT NULL,
        updated_at text NOT NULL
      )`

      yield* sql`INSERT INTO users (id, name, email, email_verified, image, created_at, updated_at)
        VALUES ('u-assurance', 'Ada', 'assurance@example.com', false, NULL, '2024-01-01T00:00:00.000Z', '2024-01-01T00:00:00.000Z')`
      yield* sql`INSERT INTO sessions (id, token_hash, user_id, expires_at, ip_address, user_agent, created_at, updated_at)
        VALUES ('s-assurance', 'hash-assurance', 'u-assurance', '2999-01-01T00:00:00.000Z', NULL, NULL, '2024-03-04T05:06:07.000Z', '2024-03-04T05:06:07.000Z')`

      const applied = yield* Migrations.run
      assert.include(
        applied.map(([, name]) => name),
        "session_assurance"
      )

      const rows = yield* sql<{
        readonly authenticatedAt: unknown
        readonly aal: unknown
        readonly methods: unknown
      }>`SELECT authenticated_at AS "authenticatedAt", aal, methods FROM sessions WHERE id = 's-assurance'`

      // Before step-up existed, a session's creation *was* the moment its owner
      // authenticated, so that is what an existing row is worth — not "now",
      // which would silently re-freshen every session in the table.
      assert.strictEqual(rows[0]?.authenticatedAt, "2024-03-04T05:06:07.000Z")
      assert.strictEqual(rows[0]?.aal, "aal1")
      assert.strictEqual(rows[0]?.methods, "[]")
    })
  )
})

layer(database())("sql/Migrations", (it) => {
  it.effect("leaves sessions.authenticated_at NOT NULL", () =>
    Effect.gen(function* () {
      yield* Migrations.run

      const sql = yield* SqlClient.SqlClient
      const columns = yield* sql<{ readonly name: string; readonly nullable: string }>`SELECT column_name AS "name",
          is_nullable AS "nullable"
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'sessions' AND column_name IN ('authenticated_at', 'aal', 'methods')
        ORDER BY column_name`

      assert.deepStrictEqual(
        columns.map((row) => [row.name, row.nullable]),
        [
          ["aal", "NO"],
          ["authenticated_at", "NO"],
          ["methods", "NO"]
        ]
      )
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
