/**
 * The two-factor plugin's own tables.
 *
 * Three of them, and none of them a column on a core table: a TOTP enrolment
 * per user, one row per recovery code, and one row per remembered browser. They
 * are versioned in a bookkeeping table of this plugin's own
 * (`effect_auth_two_factor_migrations`) and numbered from `0001`, so this set's
 * numbering is nobody else's business — see `Migrations.make`.
 *
 * **When to use**
 *
 * The consumer composes it; nothing registers it globally. Sequence it under
 * the library's own, because every table here has a foreign key to `users`:
 *
 * ```ts skip-type-checking
 * import { Layer } from "effect"
 * import { Migrations } from "effect-auth"
 * import { TwoFactorMigrations } from "effect-auth"
 *
 * const Schema = TwoFactorMigrations.layer.pipe(Layer.provide(Migrations.layer))
 * ```
 *
 * **Gotchas**
 *
 * Ids and hashes are bounded `varchar`, so the MySQL port stays mechanical: a
 * `text` primary key or a `text` unique index is a length-limit error there.
 * Timestamps are `text` holding ISO-8601 UTC, exactly as the core tables' are,
 * which is what makes `expires_at > $now` a correct comparison on both
 * dialects.
 *
 * The `ON DELETE CASCADE` foreign keys are only enforced by SQLite when the
 * connection has `PRAGMA foreign_keys = ON` — the same caveat the core
 * migrations carry.
 *
 * @since 0.2.0
 */
import { Effect } from "effect"
import type { Layer } from "effect"
import { Migrator, SqlClient, type SqlError } from "effect/unstable/sql"
import * as Migrations from "../sql/Migrations.js"

const migrationError = (message: string) => new Migrator.MigrationError({ kind: "Failed", message })

const unsupportedDialect = Effect.fail(
  migrationError(`effect-auth migrations only support the "pg" and "sqlite" dialects`)
)

/**
 * `0001_create_two_factor`: the TOTP enrolment, the recovery codes and the
 * trusted devices.
 *
 * **Details**
 *
 * `effect_auth_totp.user_id` is the primary key: a person has one authenticator
 * app enrolment, and `ON CONFLICT (user_id)` is what makes "abandoning a
 * pending enrolment regenerates it" one statement rather than a read and a
 * write.
 *
 * `last_used_step` is the replay guard's column — the TOTP step the enrolment
 * last authenticated with. `bigint` rather than `integer` because a 32-bit
 * step count runs out, and the comparison that guards it is numeric.
 *
 * Both `code_hash` and `token_hash` are keyed digests (`Hmac`), never fast
 * hashes, and both are globally unique: a code or a device token names exactly
 * one row whoever presents it.
 */
const createTwoFactor = Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient

  yield* sql.onDialectOrElse({
    pg: () =>
      sql`CREATE TABLE IF NOT EXISTS effect_auth_totp (
        user_id varchar(36) PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
        secret_ciphertext text NOT NULL,
        verified_at text,
        last_used_step bigint,
        created_at text NOT NULL
      )`,
    sqlite: () =>
      sql`CREATE TABLE IF NOT EXISTS effect_auth_totp (
        user_id varchar(36) PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
        secret_ciphertext text NOT NULL,
        verified_at text,
        last_used_step bigint,
        created_at text NOT NULL
      )`,
    orElse: () => unsupportedDialect
  })

  yield* sql.onDialectOrElse({
    pg: () =>
      sql`CREATE TABLE IF NOT EXISTS effect_auth_recovery_codes (
        id varchar(36) PRIMARY KEY,
        user_id varchar(36) NOT NULL REFERENCES users (id) ON DELETE CASCADE,
        code_hash varchar(64) NOT NULL,
        used_at text,
        created_at text NOT NULL
      )`,
    sqlite: () =>
      sql`CREATE TABLE IF NOT EXISTS effect_auth_recovery_codes (
        id varchar(36) PRIMARY KEY,
        user_id varchar(36) NOT NULL REFERENCES users (id) ON DELETE CASCADE,
        code_hash varchar(64) NOT NULL,
        used_at text,
        created_at text NOT NULL
      )`,
    orElse: () => unsupportedDialect
  })

  yield* sql`CREATE UNIQUE INDEX IF NOT EXISTS effect_auth_recovery_codes_code_hash_unique ON effect_auth_recovery_codes (code_hash)`
  yield* sql`CREATE INDEX IF NOT EXISTS effect_auth_recovery_codes_user_id_idx ON effect_auth_recovery_codes (user_id)`

  yield* sql.onDialectOrElse({
    pg: () =>
      sql`CREATE TABLE IF NOT EXISTS effect_auth_trusted_devices (
        id varchar(36) PRIMARY KEY,
        user_id varchar(36) NOT NULL REFERENCES users (id) ON DELETE CASCADE,
        token_hash varchar(64) NOT NULL,
        expires_at text NOT NULL,
        last_used_at text NOT NULL,
        user_agent text,
        ip_address text,
        label varchar(64),
        created_at text NOT NULL
      )`,
    sqlite: () =>
      sql`CREATE TABLE IF NOT EXISTS effect_auth_trusted_devices (
        id varchar(36) PRIMARY KEY,
        user_id varchar(36) NOT NULL REFERENCES users (id) ON DELETE CASCADE,
        token_hash varchar(64) NOT NULL,
        expires_at text NOT NULL,
        last_used_at text NOT NULL,
        user_agent text,
        ip_address text,
        label varchar(64),
        created_at text NOT NULL
      )`,
    orElse: () => unsupportedDialect
  })

  yield* sql`CREATE UNIQUE INDEX IF NOT EXISTS effect_auth_trusted_devices_token_hash_unique ON effect_auth_trusted_devices (token_hash)`
  yield* sql`CREATE INDEX IF NOT EXISTS effect_auth_trusted_devices_user_id_idx ON effect_auth_trusted_devices (user_id)`
})

/**
 * The table this plugin records its own migrations in.
 *
 * @category constructors
 * @since 0.2.0
 */
export const table = "effect_auth_two_factor_migrations"

/**
 * Every migration this plugin owns, keyed `<id>_<name>`.
 *
 * @category models
 * @since 0.2.0
 */
export const migrations: Record<string, Effect.Effect<void, unknown, SqlClient.SqlClient>> = {
  "0001_create_two_factor": createTwoFactor
}

const set = Migrations.make({ table, migrations })

/**
 * The `Migrator` loader for {@link migrations}.
 *
 * @category models
 * @since 0.2.0
 */
export const loader: Migrator.Loader = set.loader

/**
 * Runs this plugin's migrations against the ambient `SqlClient`.
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
 * Sequence it *under* the library's own — `Layer.provide(Migrations.layer)` —
 * or the foreign keys have no `users` table to point at. Two migration sets
 * built over one `SqlClient` with no ordering between them run concurrently.
 *
 * @category layers
 * @since 0.2.0
 */
export const layer: Layer.Layer<never, Migrator.MigrationError | SqlError.SqlError, SqlClient.SqlClient> = set.layer
