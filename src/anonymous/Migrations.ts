/**
 * The anonymous plugin's own schema.
 *
 * One marker table, `effect_auth_anonymous`, recorded in a bookkeeping table of
 * the plugin's own and numbered from `0001`.
 *
 * **Details**
 *
 * A marker table and **never** an `is_anonymous` column on `users`: a plugin
 * that adds a column to a core table is a shared table wearing a hat, and the
 * row's absence is exactly what "this person is somebody now" means — adoption
 * is a `DELETE`, which no `UPDATE` on a core row can be rolled back around.
 *
 * `last_seen_at` is what the sweep measures idleness by. It starts equal to
 * `created_at`; `Anonymous.touch` moves it.
 *
 * The three columns are declared through `Dialect.columnType` — `id` for the
 * holder, `timestamp` for the two clocks — so each supported database gets the
 * type its indexes need without the statement being written three times.
 *
 * **Gotchas**
 *
 * Register this nowhere: the consumer composes it, sequenced after this
 * library's own so the foreign key onto `users` has something to point at.
 *
 * @since 0.2.0
 */
import { Effect } from "effect"
import { SqlClient } from "effect/unstable/sql"
import type { ColumnRole } from "../sql/Dialect.js"
import { columnType, dialectOf, identifier } from "../sql/Dialect.js"
import * as Migrations from "../sql/Migrations.js"

/** The marker table. */
const anonymous = "effect_auth_anonymous"

/** What the sweep scans by. */
const lastSeenIndex = "effect_auth_anonymous_last_seen_at_idx"

const createAnonymous = Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient
  const dialect = yield* dialectOf(sql)
  const type = (role: ColumnRole) => sql.literal(columnType(dialect, role))
  const anonymousTable = identifier(sql, anonymous)

  // The foreign key is a table constraint rather than a column one because
  // MySQL parses an inline `REFERENCES` clause and then ignores it — the
  // cascade, which is the whole of what "the marker goes with the person"
  // means, would silently not exist. PostgreSQL and SQLite read the two forms
  // identically. The holder is the primary key, so InnoDB has an index for the
  // foreign key already and adds none of its own.
  yield* sql`CREATE TABLE IF NOT EXISTS ${anonymousTable} (
    user_id ${type("id")} PRIMARY KEY,
    created_at ${type("timestamp")} NOT NULL,
    last_seen_at ${type("timestamp")} NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
  )`

  // The sweep's predicate. Timestamps are fixed-width ISO-8601, so the index is
  // usable for the range scan. MySQL has no `IF NOT EXISTS` on `CREATE INDEX`
  // and needs none: a migration runs exactly once.
  const ifNotExists = sql.literal(dialect === "mysql" ? "" : "IF NOT EXISTS ")
  yield* sql`CREATE INDEX ${ifNotExists}${identifier(sql, lastSeenIndex)} ON ${anonymousTable} (last_seen_at)`
})

/**
 * The name of the table this plugin records its own migrations in.
 *
 * @category constructors
 * @since 0.2.0
 */
export const table = "effect_auth_anonymous_migrations"

/**
 * The anonymous plugin's migrations, keyed `<id>_<name>`.
 *
 * @category models
 * @since 0.2.0
 */
export const migrations: Record<string, Effect.Effect<void, unknown, SqlClient.SqlClient>> = {
  "0001_create_anonymous": createAnonymous
}

const set = Migrations.make({ table, migrations })

/**
 * Runs the anonymous plugin's migrations, answering with the ones that were
 * applied.
 *
 * @category constructors
 * @since 0.2.0
 */
export const run: Migrations.MigrationSet["run"] = set.run

/**
 * The `Migrator` loader for {@link migrations}.
 *
 * @category models
 * @since 0.2.0
 */
export const loader: Migrations.MigrationSet["loader"] = set.loader

/**
 * A layer that applies the anonymous plugin's migrations while it is built.
 *
 * @category layers
 * @since 0.2.0
 */
export const layer: Migrations.MigrationSet["layer"] = set.layer
