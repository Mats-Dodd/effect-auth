/**
 * `effect-auth/testing/sqlite` — the SQLite backend for a test suite.
 *
 * **When to use**
 *
 * Through `EFFECT_AUTH_TEST_DATABASE=sqlite`, or by passing {@link memory} as
 * `AuthTest.Settings.database` when one suite should run on SQLite whatever the
 * variable says.
 *
 * **Gotchas**
 *
 * This subpath needs `@effect/sql-sqlite-node`, an optional peer dependency,
 * and therefore Node 22 or later — the driver is `node:sqlite`. Nothing under
 * `effect-auth`, `effect-auth/client` or `effect-auth/testing` imports it.
 *
 * @since 0.1.0
 */
import { SqliteClient } from "@effect/sql-sqlite-node"
import { Effect, Layer } from "effect"
import { Reactivity } from "effect/unstable/reactivity"
import { SqlClient } from "effect/unstable/sql"
import type { Provider } from "../Database.js"
import { TestDatabase } from "../Database.js"
import * as Catalog from "../internal/catalog.js"

/**
 * A `:memory:` database per build, with foreign keys switched on.
 *
 * **Details**
 *
 * There is nothing per worker to share: an in-memory SQLite database belongs to
 * its connection, so the build's client *is* the database and closing the scope
 * is the whole teardown. `PRAGMA foreign_keys = ON` is not optional — SQLite
 * parses foreign keys either way and enforces them only when asked, so without
 * it a cascade test would pass against a schema that never cascades.
 *
 * @category layers
 * @since 0.1.0
 */
export const memory: Provider = Layer.effect(TestDatabase, Effect.map(SqlClient.SqlClient, Catalog.sqlite)).pipe(
  Layer.provideMerge(
    Layer.effect(
      SqlClient.SqlClient,
      Effect.tap(
        Effect.provide(SqliteClient.make({ filename: ":memory:" }), Reactivity.layer),
        (sql) => sql`PRAGMA foreign_keys = ON`
      )
    )
  )
)
