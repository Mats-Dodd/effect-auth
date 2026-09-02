/**
 * The one table the phone plugin owns.
 *
 * **Details**
 *
 * A set of its own, recorded in `effect_auth_phone_migrations`, numbered from
 * `0001` and never merged into this library's — see `Migrations.make`, whose
 * header explains why a plugin that shares a bookkeeping table is one
 * renumbering away from a migration that silently never runs.
 *
 * The table is not registered anywhere global. A deployment composes it, and
 * sequences it after the core set because `user_id` references `users`:
 *
 * ```ts skip-type-checking
 * const MigrationsLive = Phone.Migrations.layer.pipe(Layer.provide(Migrations.layer))
 * ```
 *
 * **Gotchas**
 *
 * Bounded `varchar` for the number and the user id, so the `db-expansion.md`
 * MySQL port stays mechanical — MySQL cannot index an unbounded `text` column.
 * `phone_e164` is 16 characters because E.164 caps a number at fifteen digits
 * and the `+` makes sixteen; anything longer is not a number this plugin can
 * have stored, since `E164.normalize` is the only thing that writes here.
 *
 * @since 0.2.0
 */
import type { Layer } from "effect"
import { Effect } from "effect"
import { Migrator, SqlClient, type SqlError } from "effect/unstable/sql"
import { make as makeMigrations, type MigrationSet } from "../sql/Migrations.js"

/**
 * The table a verified phone number lives in.
 *
 * @category constructors
 * @since 0.2.0
 */
export const phoneNumbersTable = "effect_auth_phone_numbers"

/**
 * The table this set records itself in.
 *
 * @category constructors
 * @since 0.2.0
 */
export const table = "effect_auth_phone_migrations"

const unsupportedDialect = Effect.fail(
  new Migrator.MigrationError({
    kind: "Failed",
    message: `effect-auth phone migrations only support the "pg" and "sqlite" dialects`
  })
)

/**
 * `0001_create_phone_numbers`.
 *
 * One row per number and — through the unique constraint on `user_id` — at most
 * one number per person. The number itself is the primary key, so two people
 * can never hold the same handset: the second `INSERT` is refused by the
 * database rather than by a check somebody could forget to write.
 *
 * `verified_at` is nullable and is what every read filters on. A row with a
 * null there is a claim, not a proof.
 */
const createPhoneNumbers = Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient

  yield* sql.onDialectOrElse({
    pg: () =>
      sql`CREATE TABLE IF NOT EXISTS effect_auth_phone_numbers (
        phone_e164 varchar(16) PRIMARY KEY,
        user_id varchar(36) NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
        verified_at text,
        created_at text NOT NULL
      )`,
    sqlite: () =>
      // SQLite reports a conflict on a declared PRIMARY KEY as
      // SQLITE_CONSTRAINT_PRIMARYKEY (1555) and only a conflict on a UNIQUE
      // index as SQLITE_CONSTRAINT_UNIQUE (2067), which is the only one
      // `persistenceFailureKind` classifies as a lost race — so the number is a
      // NOT NULL UNIQUE column here rather than the primary key it is on the
      // other dialects. The constraint is the same; the reported error is not.
      sql`CREATE TABLE IF NOT EXISTS effect_auth_phone_numbers (
        phone_e164 text NOT NULL UNIQUE,
        user_id text NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
        verified_at text,
        created_at text NOT NULL
      )`,
    orElse: () => unsupportedDialect
  })
})

/**
 * The plugin's migrations, keyed `<id>_<name>` as `Migrator.fromRecord` expects.
 *
 * @category models
 * @since 0.2.0
 */
export const migrations: Record<string, Effect.Effect<void, unknown, SqlClient.SqlClient>> = {
  "0001_create_phone_numbers": createPhoneNumbers
}

/** {@link migrations}, and everything derived from them. */
const set: MigrationSet = makeMigrations({ table, migrations })

/**
 * The `Migrator` loader for {@link migrations}.
 *
 * @category models
 * @since 0.2.0
 */
export const loader: Migrator.Loader = set.loader

/**
 * Runs the phone plugin's migrations against the ambient `SqlClient`.
 *
 * @category constructors
 * @since 0.2.0
 */
export const run: Effect.Effect<
  ReadonlyArray<readonly [id: number, name: string]>,
  Migrator.MigrationError | SqlError.SqlError,
  SqlClient.SqlClient
> = set.run

/**
 * A layer that applies the phone plugin's migrations while it is built.
 *
 * **Gotchas**
 *
 * Sequence it after this library's own — the foreign key names `users` — with
 * `Phone.Migrations.layer.pipe(Layer.provide(Migrations.layer))`. Two sets built
 * over one `SqlClient` with no ordering between them run concurrently.
 *
 * @category layers
 * @since 0.2.0
 */
export const layer: Layer.Layer<never, Migrator.MigrationError | SqlError.SqlError, SqlClient.SqlClient> = set.layer
