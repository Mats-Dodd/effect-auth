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
 * **Gotchas**
 *
 * Register this nowhere: the consumer composes it, sequenced after this
 * library's own so the foreign key onto `users` has something to point at.
 *
 * @since 0.2.0
 */
import { Effect } from "effect"
import { Migrator, SqlClient } from "effect/unstable/sql"
import * as Migrations from "../sql/Migrations.js"

const unsupportedDialect = Effect.fail(
  new Migrator.MigrationError({
    kind: "Failed",
    message: `effect-auth anonymous migrations only support the "pg" and "sqlite" dialects`
  })
)

const createAnonymous = Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient

  // The statement is the same on both dialects, and the branch is still here:
  // it is what turns an unsupported dialect into a stated refusal rather than
  // into whatever that driver makes of `varchar`.
  yield* sql.onDialectOrElse({
    pg: () =>
      sql`CREATE TABLE IF NOT EXISTS effect_auth_anonymous (
        user_id varchar(36) PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
        created_at text NOT NULL,
        last_seen_at text NOT NULL
      )`,
    sqlite: () =>
      sql`CREATE TABLE IF NOT EXISTS effect_auth_anonymous (
        user_id varchar(36) PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
        created_at text NOT NULL,
        last_seen_at text NOT NULL
      )`,
    orElse: () => unsupportedDialect
  })

  // The sweep's predicate. Timestamps are fixed-width ISO-8601, so the index is
  // usable for the range scan.
  yield* sql`CREATE INDEX IF NOT EXISTS effect_auth_anonymous_last_seen_at_idx ON effect_auth_anonymous (last_seen_at)`
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
