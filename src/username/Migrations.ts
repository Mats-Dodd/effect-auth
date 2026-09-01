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
 * Ids and names are bounded `varchar` so the `db-expansion.md` MySQL port stays
 * mechanical: MySQL cannot index an unbounded `text` column.
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
import { Migrator, SqlClient } from "effect/unstable/sql"
import * as Migrations from "../sql/Migrations.js"

const unsupportedDialect = Effect.fail(
  new Migrator.MigrationError({
    kind: "Failed",
    message: `effect-auth username migrations only support the "pg" and "sqlite" dialects`
  })
)

const createUsernames = Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient

  // The statement is the same on both dialects, and the branch is still here:
  // it is what turns an unsupported dialect into a stated refusal rather than
  // into whatever that driver makes of `varchar`.
  yield* sql.onDialectOrElse({
    pg: () =>
      sql`CREATE TABLE IF NOT EXISTS effect_auth_usernames (
        username_key varchar(64) PRIMARY KEY,
        username varchar(64) NOT NULL,
        user_id varchar(36) NOT NULL REFERENCES users (id) ON DELETE CASCADE,
        created_at text NOT NULL
      )`,
    sqlite: () =>
      sql`CREATE TABLE IF NOT EXISTS effect_auth_usernames (
        username_key varchar(64) PRIMARY KEY,
        username varchar(64) NOT NULL,
        user_id varchar(36) NOT NULL REFERENCES users (id) ON DELETE CASCADE,
        created_at text NOT NULL
      )`,
    orElse: () => unsupportedDialect
  })

  // One username per person, and the conflict target `set` upserts on.
  yield* sql`CREATE UNIQUE INDEX IF NOT EXISTS effect_auth_usernames_user_id_unique ON effect_auth_usernames (user_id)`
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
