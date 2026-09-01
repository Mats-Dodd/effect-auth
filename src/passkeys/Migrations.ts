/**
 * The two tables the passkeys plugin owns, as a {@link Migrations.MigrationSet}
 * of its own.
 *
 * **Details**
 *
 * Recorded in `effect_auth_passkey_migrations`, numbered from `0001`, and never
 * merged into this library's own record: `Migrator` orders and records by a
 * global numeric id, so a plugin sharing a bookkeeping table with core would be
 * one renumbering away from a migration that silently never runs. See
 * `Migrations.make`.
 *
 * **When to use**
 *
 * Nothing registers this globally — the consumer composes it, and must sequence
 * it *after* the core set, because both tables carry a foreign key to `users`:
 *
 * ```ts skip-type-checking
 * import { Layer } from "effect"
 * import { Migrations } from "effect-auth"
 * import { PasskeyMigrations } from "effect-auth/passkeys"
 *
 * const MigrationsLive = PasskeyMigrations.layer.pipe(Layer.provide(Migrations.layer))
 * ```
 *
 * **Gotchas**
 *
 * `ON DELETE CASCADE` is only enforced by SQLite when the connection has
 * `PRAGMA foreign_keys = ON` — the same caveat the core migrations carry.
 *
 * @since 0.2.0
 */
import { Effect, type Layer } from "effect"
import { Migrator, SqlClient, type SqlError } from "effect/unstable/sql"
import { make, type MigrationSet } from "../sql/Migrations.js"

const migrationError = (message: string) => new Migrator.MigrationError({ kind: "Failed", message })

const unsupportedDialect = Effect.fail(
  migrationError(`the effect-auth passkeys migrations only support the "pg" and "sqlite" dialects`)
)

/**
 * The credential table.
 *
 * `credential_id` is unique across the whole table rather than per user: a
 * credential id identifies an authenticator's key, and the same key registered
 * to two accounts would make a discoverable sign-in ambiguous — which of them
 * did the person mean? Better-auth indexes it without a unique constraint and
 * has that ambiguity.
 */
const createPasskeys = Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient

  yield* sql.onDialectOrElse({
    pg: () =>
      sql`CREATE TABLE IF NOT EXISTS effect_auth_passkeys (
        id varchar(36) PRIMARY KEY,
        user_id varchar(36) NOT NULL REFERENCES users (id) ON DELETE CASCADE,
        credential_id varchar(1024) NOT NULL,
        public_key text NOT NULL,
        sign_count bigint NOT NULL DEFAULT 0,
        transports text NOT NULL DEFAULT '[]',
        aaguid varchar(36) NOT NULL,
        backup_eligible boolean NOT NULL DEFAULT false,
        backed_up boolean NOT NULL DEFAULT false,
        uv_initialised boolean NOT NULL DEFAULT false,
        name varchar(64),
        created_at text NOT NULL,
        last_used_at text
      )`,
    sqlite: () =>
      sql`CREATE TABLE IF NOT EXISTS effect_auth_passkeys (
        id varchar(36) PRIMARY KEY,
        user_id varchar(36) NOT NULL REFERENCES users (id) ON DELETE CASCADE,
        credential_id varchar(1024) NOT NULL,
        public_key text NOT NULL,
        sign_count bigint NOT NULL DEFAULT 0,
        transports text NOT NULL DEFAULT '[]',
        aaguid varchar(36) NOT NULL,
        backup_eligible integer NOT NULL DEFAULT 0,
        backed_up integer NOT NULL DEFAULT 0,
        uv_initialised integer NOT NULL DEFAULT 0,
        name varchar(64),
        created_at text NOT NULL,
        last_used_at text
      )`,
    orElse: () => unsupportedDialect
  })

  yield* sql`CREATE UNIQUE INDEX IF NOT EXISTS effect_auth_passkeys_credential_id_unique
    ON effect_auth_passkeys (credential_id)`
  yield* sql`CREATE INDEX IF NOT EXISTS effect_auth_passkeys_user_id_idx ON effect_auth_passkeys (user_id)`
})

/**
 * The handle table: one row per user who has ever been offered a passkey.
 *
 * The handle is unique as well as the key, so that a `userHandle` coming back
 * from a discoverable sign-in names at most one account whatever else went
 * wrong.
 */
const createPasskeyUsers = Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient

  yield* sql`CREATE TABLE IF NOT EXISTS effect_auth_passkey_users (
    user_id varchar(36) PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    handle varchar(86) NOT NULL
  )`

  yield* sql`CREATE UNIQUE INDEX IF NOT EXISTS effect_auth_passkey_users_handle_unique
    ON effect_auth_passkey_users (handle)`
})

/**
 * The name of the table this plugin records its own migrations in.
 *
 * @category constructors
 * @since 0.2.0
 */
export const table = "effect_auth_passkey_migrations"

/**
 * Every migration this plugin ships, keyed `<id>_<name>` as `Migrator.fromRecord`
 * expects, numbered from `0001` in its own namespace.
 *
 * @category models
 * @since 0.2.0
 */
export const migrations: Record<string, Effect.Effect<void, unknown, SqlClient.SqlClient>> = {
  "0001_create_passkeys": createPasskeys,
  "0002_create_passkey_users": createPasskeyUsers
}

const set: MigrationSet = make({ table, migrations })

/**
 * The `Migrator` loader for {@link migrations}.
 *
 * @category models
 * @since 0.2.0
 */
export const loader: Migrator.Loader = set.loader

/**
 * Runs this plugin's migrations against the ambient `SqlClient`, answering with
 * the ones that were applied.
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
 * A layer that applies this plugin's migrations while it is being built.
 *
 * **Gotchas**
 *
 * Sequence it after the core set — `Layer.provide(Migrations.layer)` — or the
 * foreign keys to `users` have nothing to point at. Two sets built over one
 * `SqlClient` with no ordering between them run concurrently.
 *
 * @category layers
 * @since 0.2.0
 */
export const layer: Layer.Layer<never, Migrator.MigrationError | SqlError.SqlError, SqlClient.SqlClient> = set.layer
