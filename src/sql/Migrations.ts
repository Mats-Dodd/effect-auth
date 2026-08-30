/**
 * The database schema of `effect-auth`, as a `Migrator`-compatible record.
 *
 * Four tables — `users`, `sessions`, `accounts`, `verifications` — plus the
 * indexes the stores rely on. Every statement is written for both PostgreSQL and
 * SQLite; the single place the two dialects genuinely differ is the boolean
 * column `users.email_verified`, which is a real `boolean` on PostgreSQL and an
 * `integer` flag on SQLite. {@link SqlStores.layer} adapts to that difference on
 * the way in and out, so the models see a `boolean` either way.
 *
 * **Details**
 *
 * All timestamps are `text` columns holding ISO-8601 UTC strings
 * (`2024-01-01T00:00:00.000Z`). That is the encoded form of the domain models'
 * `DateTime` fields, it behaves identically on both dialects, and — because the
 * format is fixed width — it orders and compares lexicographically, which is
 * what the expiry predicates in `SessionStore` and `VerificationStore` depend
 * on.
 *
 * **Gotchas**
 *
 * The `ON DELETE CASCADE` foreign keys are only enforced by SQLite when the
 * connection has `PRAGMA foreign_keys = ON`.
 *
 * @since 1.0.0
 */
import { Effect, Layer } from "effect"
import { Migrator, SqlClient, SqlError } from "effect/unstable/sql"

// -----------------------------------------------------------------------------
// Migrations
// -----------------------------------------------------------------------------

const unsupportedDialect = Effect.fail(
  new Migrator.MigrationError({
    kind: "Failed",
    message: `effect-auth migrations only support the "pg" and "sqlite" dialects`
  })
)

const createUsers = Effect.gen(function*() {
  const sql = yield* SqlClient.SqlClient

  yield* sql.onDialectOrElse({
    pg: () =>
      sql`CREATE TABLE IF NOT EXISTS users (
        id text PRIMARY KEY,
        name text NOT NULL,
        email text NOT NULL,
        email_verified boolean NOT NULL DEFAULT false,
        image text,
        created_at text NOT NULL,
        updated_at text NOT NULL
      )`,
    sqlite: () =>
      sql`CREATE TABLE IF NOT EXISTS users (
        id text PRIMARY KEY,
        name text NOT NULL,
        email text NOT NULL,
        email_verified integer NOT NULL DEFAULT 0,
        image text,
        created_at text NOT NULL,
        updated_at text NOT NULL
      )`,
    orElse: () => unsupportedDialect
  })

  yield* sql`CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique ON users (email)`
})

const createSessions = Effect.gen(function*() {
  const sql = yield* SqlClient.SqlClient

  yield* sql`CREATE TABLE IF NOT EXISTS sessions (
    id text PRIMARY KEY,
    token_hash text NOT NULL,
    user_id text NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    expires_at text NOT NULL,
    ip_address text,
    user_agent text,
    created_at text NOT NULL,
    updated_at text NOT NULL
  )`

  yield* sql`CREATE UNIQUE INDEX IF NOT EXISTS sessions_token_hash_unique ON sessions (token_hash)`
  yield* sql`CREATE INDEX IF NOT EXISTS sessions_user_id_idx ON sessions (user_id)`
})

const createAccounts = Effect.gen(function*() {
  const sql = yield* SqlClient.SqlClient

  yield* sql`CREATE TABLE IF NOT EXISTS accounts (
    id text PRIMARY KEY,
    issuer text NOT NULL,
    account_id text NOT NULL,
    provider_id text NOT NULL,
    user_id text NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    access_token text,
    refresh_token text,
    id_token text,
    access_token_expires_at text,
    refresh_token_expires_at text,
    scope text,
    password_hash text,
    created_at text NOT NULL,
    updated_at text NOT NULL
  )`

  yield* sql`CREATE UNIQUE INDEX IF NOT EXISTS accounts_issuer_account_id_unique ON accounts (issuer, account_id)`
  yield* sql`CREATE INDEX IF NOT EXISTS accounts_user_id_idx ON accounts (user_id)`
})

const createVerifications = Effect.gen(function*() {
  const sql = yield* SqlClient.SqlClient

  yield* sql`CREATE TABLE IF NOT EXISTS verifications (
    id text PRIMARY KEY,
    identifier text NOT NULL,
    value_hash text NOT NULL,
    payload text,
    expires_at text NOT NULL,
    created_at text NOT NULL,
    updated_at text NOT NULL
  )`

  yield* sql`CREATE INDEX IF NOT EXISTS verifications_identifier_idx ON verifications (identifier)`
})

/**
 * Every `effect-auth` migration, keyed by `<id>_<name>` as
 * `Migrator.fromRecord` expects.
 *
 * **When to use**
 *
 * Merge these entries into your own migration record when the application owns
 * the migrator, so that the auth tables are versioned alongside the rest of your
 * schema:
 *
 * ```ts skip-type-checking
 * const loader = Migrator.fromRecord({
 *   ...Migrations.migrations,
 *   "0100_create_todos": createTodos
 * })
 * ```
 *
 * **Gotchas**
 *
 * The numeric prefixes are part of the contract: `Migrator` orders and records
 * migrations by that id, so renumbering them in a deployed application replays
 * or skips migrations. Number your own migrations above `0004`.
 *
 * @category models
 * @since 1.0.0
 */
export const migrations: Record<string, Effect.Effect<void, unknown, SqlClient.SqlClient>> = {
  "0001_create_users": createUsers,
  "0002_create_sessions": createSessions,
  "0003_create_accounts": createAccounts,
  "0004_create_verifications": createVerifications
}

/**
 * The `Migrator` loader for {@link migrations}.
 *
 * @category models
 * @since 1.0.0
 */
export const loader: Migrator.Loader = Migrator.fromRecord(migrations)

/**
 * Runs the `effect-auth` migrations against the ambient `SqlClient`, returning
 * the migrations that were applied.
 *
 * @category constructors
 * @since 1.0.0
 */
export const run: Effect.Effect<
  ReadonlyArray<readonly [id: number, name: string]>,
  Migrator.MigrationError | SqlError.SqlError,
  SqlClient.SqlClient
> = Migrator.make({})({ loader, table: "effect_auth_migrations" })

/**
 * A layer that applies the `effect-auth` migrations while it is being built.
 *
 * **When to use**
 *
 * A quickstart and development convenience: provide it above your `SqlClient`
 * layer and the auth tables exist before the first request. Production
 * deployments usually run migrations as a separate step instead, in which case
 * merge {@link migrations} into the application's own `Migrator` record rather
 * than using this layer.
 *
 * **Gotchas**
 *
 * Migrations are recorded in a dedicated `effect_auth_migrations` table so that
 * they cannot collide with the application's own migration ids.
 *
 * @category layers
 * @since 1.0.0
 */
export const layer: Layer.Layer<never, Migrator.MigrationError | SqlError.SqlError, SqlClient.SqlClient> = Layer
  .effectDiscard(run)
