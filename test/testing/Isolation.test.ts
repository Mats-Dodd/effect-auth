/**
 * The standing proof that one `layer()` block never sees another's rows.
 *
 * **Details**
 *
 * `layer()` gives every top-level block a memo map of its own, so two
 * top-level blocks over the *same* layer value build the provider twice. This
 * file is that shape: the first block writes a row, the second insists it
 * cannot see it, and the third proves `TestDatabase.reset` empties the tables
 * without touching the migration bookkeeping.
 *
 * **Gotchas**
 *
 * Isolation here is *not* an ordering claim, and that is the measurement that
 * settled how `Database.pglite` is built. With `sequence.concurrent` on, two
 * top-level blocks in one file overlap in time: the second block's tests start
 * before the first block's have finished (measured 2026-09-02 — a bare vitest
 * probe with two `describe`s and a delay in the first showed `["a1-start",
 * "b1-start"]`). That rules out one PGlite per worker with a schema per build,
 * because the isolation would rest on a `search_path` carried by PGlite's one
 * connection and the second build would set it under the first block's running
 * tests. So `Database.pglite` is a pool of whole engines per worker: two blocks
 * that overlap hold two engines, and a block that starts after another finished
 * inherits that engine wiped — which is the case the second block below is most
 * likely to be exercising, and the one this file exists to keep honest. Only
 * `postgres` and `mysql` — where a build is a database on a shared server and
 * every connection is its own — keep a single engine per worker.
 */
import { assert, layer } from "@effect/vitest"
import { Effect } from "effect"
import { SqlClient } from "effect/unstable/sql"
import { TestDatabase } from "../../src/testing/Database.js"
import * as AuthTest from "../../src/testing/TestLayer.js"

interface CountRow {
  readonly count: unknown
}

const users = Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient
  const rows = yield* sql<CountRow>`SELECT COUNT(*) AS "count" FROM users`
  return Number(rows[0]?.count ?? 0)
})

const insert = (email: string) =>
  Effect.gen(function* () {
    const sql = yield* SqlClient.SqlClient
    // The one dialect fact this file cannot avoid: SQLite has no boolean, and
    // `node:sqlite` refuses to bind one. The stores go through the library's own
    // codec; a raw statement has to say it itself.
    const verified = sql.onDialectOrElse({ orElse: () => 0, pg: () => false, mysql: () => false })
    const now = "2026-09-02T00:00:00.000Z"
    yield* sql`INSERT INTO users (id, name, email, email_verified, created_at, updated_at)
      VALUES (${email}, ${"Ada"}, ${email}, ${verified}, ${now}, ${now})`
  })

layer(AuthTest.layerStores)("testing/Isolation — the first block", (it) => {
  it.effect("gets a migrated database of its own, and it is empty", () =>
    Effect.gen(function* () {
      const database = yield* TestDatabase
      const tables = yield* database.tableNames

      // A real, migrated database rather than an empty one: the four core
      // tables and the bookkeeping the migrator wrote.
      assert.include(tables, "users")
      assert.include(tables, "sessions")
      assert.include(tables, "effect_auth_migrations")
      assert.strictEqual(yield* users, 0)

      yield* insert("first@example.com")
      assert.strictEqual(yield* users, 1)
    })
  )
})

layer(AuthTest.layerStores)("testing/Isolation — the second block", (it) => {
  it.effect("cannot see the first block's row", () =>
    Effect.gen(function* () {
      // If both blocks landed in one schema this would be 1, and every suite in
      // this repository would be reading its siblings' rows.
      assert.strictEqual(yield* users, 0)
    })
  )
})

layer(AuthTest.layerStores)("testing/Isolation — TestDatabase.reset", (it) => {
  it.effect("empties the tables and keeps the migration bookkeeping", () =>
    Effect.gen(function* () {
      const database = yield* TestDatabase
      yield* insert("reset@example.com")
      assert.strictEqual(yield* users, 1)

      yield* database.reset

      assert.strictEqual(yield* users, 0)
      // Emptying this one would let a migration test pass against a schema
      // that was never built.
      const applied = yield* Effect.map(
        Effect.flatMap(
          SqlClient.SqlClient,
          (sql) => sql<CountRow>`SELECT COUNT(*) AS "count" FROM effect_auth_migrations`
        ),
        (rows) => Number(rows[0]?.count ?? 0)
      )
      assert.isAbove(applied, 0)
    })
  )
})
