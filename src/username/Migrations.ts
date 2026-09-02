/**
 * The username plugin's own schema.
 *
 * One table, `effect_auth_usernames`, recorded in a bookkeeping table of the
 * plugin's own and numbered from `0001` — see `Migrations.make` for why a
 * plugin never merges its statements into this library's record.
 *
 * **Details**
 *
 * Two forms per PRECIS (RFC 8265). `username_key` is the `UsernameCaseMapped`
 * form — the primary key, and therefore the uniqueness rule — and `username` is
 * what the person typed and what a profile shows. `user_id` is unique as well:
 * a person holds at most one username, and changing it rewrites the row rather
 * than adding one.
 *
 * Every column is declared through `Dialect.columnType`, so the three supported
 * databases each get the type their own indexes need: `text` on PostgreSQL and
 * SQLite, and on MySQL a bounded `varchar` in a binary collation — `identity`
 * for the two name forms, `id` for the holder, `timestamp` for `created_at`.
 *
 * **Gotchas**
 *
 * Register this nowhere: the consumer composes it, sequenced after this
 * library's own so that the foreign key onto `users` has something to point at.
 *
 * ```ts skip-type-checking
 * import { Layer } from "effect"
 * import { Migrations } from "effect-auth"
 * import { UsernameMigrations } from "effect-auth"
 *
 * const Schema = UsernameMigrations.layer.pipe(Layer.provide(Migrations.layer))
 * ```
 *
 * @since 0.2.0
 */
import { Effect } from "effect"
import { SqlClient } from "effect/unstable/sql"
import type { ColumnRole } from "../sql/Dialect.js"
import { columnType, dialectOf, identifier } from "../sql/Dialect.js"
import * as Migrations from "../sql/Migrations.js"

/** The table the plugin's rows live in. */
const usernames = "effect_auth_usernames"

/** One person, one name — the unique index, and the conflict target `claim` upserts on. */
const holderIndex = "effect_auth_usernames_user_id_unique"

const createUsernames = Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient
  const dialect = yield* dialectOf(sql)
  const type = (role: ColumnRole) => sql.literal(columnType(dialect, role))
  const usernamesTable = identifier(sql, usernames)

  // InnoDB gives a foreign key an index of its own whenever the `CREATE TABLE`
  // that declares it leaves the column without one, so on MySQL the holder's
  // unique index is declared inside the table: the standalone statement below
  // would otherwise leave `user_id` carrying two indexes, the first of them
  // named by the server. PostgreSQL and SQLite run the statement they always
  // have, and keep the index name they always had.
  const holderUnique =
    dialect === "mysql" ? sql`, CONSTRAINT ${identifier(sql, holderIndex)} UNIQUE (user_id)` : sql.literal("")

  // The foreign key is a table constraint rather than a column one because
  // MySQL parses an inline `REFERENCES` clause and then ignores it — the
  // cascade would silently not exist. PostgreSQL and SQLite read the two forms
  // identically, down to the constraint name PostgreSQL derives.
  yield* sql`CREATE TABLE IF NOT EXISTS ${usernamesTable} (
    username_key ${type("identity")} PRIMARY KEY,
    username ${type("identity")} NOT NULL,
    user_id ${type("id")} NOT NULL,
    created_at ${type("timestamp")} NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE${holderUnique}
  )`

  if (dialect !== "mysql") {
    yield* sql`CREATE UNIQUE INDEX IF NOT EXISTS ${identifier(sql, holderIndex)} ON ${usernamesTable} (user_id)`
  }
})

/**
 * The name of the table this plugin records its own migrations in.
 *
 * @category constructors
 * @since 0.2.0
 */
export const table = "effect_auth_username_migrations"

/**
 * The username plugin's migrations, keyed `<id>_<name>`.
 *
 * @category models
 * @since 0.2.0
 */
export const migrations: Record<string, Effect.Effect<void, unknown, SqlClient.SqlClient>> = {
  "0001_create_usernames": createUsernames
}

const set = Migrations.make({ table, migrations })

/**
 * Runs the username plugin's migrations, answering with the ones that were
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
 * A layer that applies the username plugin's migrations while it is built.
 *
 * **Gotchas**
 *
 * Sequence it after this library's own — `Layer.provide(Migrations.layer)` —
 * or the foreign key onto `users` races the table it points at.
 *
 * @category layers
 * @since 0.2.0
 */
export const layer: Migrations.MigrationSet["layer"] = set.layer
