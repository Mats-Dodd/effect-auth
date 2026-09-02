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
 * Every column is declared through {@link Dialect.columnType} from the role it
 * plays rather than from a type written out per dialect, so PostgreSQL and
 * SQLite keep unbounded `text` and MySQL gets the bounded, binary-collated
 * `varchar` an index there requires. `credential_id` and `handle` are the
 * `credential` role — `varchar(1024) … ascii_bin` on MySQL, which is what both
 * of this plugin's unique indexes are built on and is well inside InnoDB's
 * 3072-byte key limit.
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
import type { Migrator, SqlError, Statement } from "effect/unstable/sql"
import { SqlClient } from "effect/unstable/sql"
import type { ColumnRole, Dialect } from "../sql/Dialect.js"
import { booleanLiteral, columnType, dialectOf } from "../sql/Dialect.js"
import { make, type MigrationSet } from "../sql/Migrations.js"

// -----------------------------------------------------------------------------
// DDL vocabulary
// -----------------------------------------------------------------------------

/**
 * The four things this plugin's DDL has to spell per dialect.
 *
 * Everything else — the table and column names, the constraints, the foreign
 * keys — is written once and is the same text on all three.
 */
interface Ddl {
  /** The type a column role is declared as here. */
  readonly type: (role: ColumnRole) => Statement.Fragment
  /** A flag, as a `DEFAULT` clause takes it. */
  readonly flag: (value: boolean) => Statement.Fragment
  /**
   * `IF NOT EXISTS `, on the dialects whose `CREATE INDEX` takes it.
   *
   * MySQL's does not, and needs none: a migration runs exactly once, and the
   * clause is belt-and-braces on the other two rather than load-bearing.
   */
  readonly indexIfNotExists: Statement.Fragment
  /**
   * A JSON document as a `DEFAULT`.
   *
   * MySQL refuses a literal default on a `text` column (`ER_BLOB_CANT_HAVE_DEFAULT`)
   * and takes a parenthesised expression instead, from 8.0.13.
   */
  readonly jsonDefault: (value: string) => Statement.Fragment
  /**
   * How a *natural* key — one whose value comes from the domain rather than
   * from `Crypto` — is declared.
   *
   * SQLite reports a conflict on a declared `PRIMARY KEY` as
   * `SQLITE_CONSTRAINT_PRIMARYKEY` (1555) and only a conflict on a UNIQUE index
   * as `SQLITE_CONSTRAINT_UNIQUE` (2067), which is the only one
   * `persistenceFailureKind` classifies as a lost race — and
   * `PasskeyStore.createHandle` is documented to fail with a `UniqueViolation`
   * so that `Passkeys` can resolve the race by reading again. So the column is
   * `NOT NULL UNIQUE` there and the primary key on the other two. The
   * constraint is the same; the reported error is not.
   */
  readonly naturalKey: Statement.Fragment
}

const ddlFor = (sql: SqlClient.SqlClient, dialect: Dialect): Ddl => ({
  type: (role) => sql.literal(columnType(dialect, role)),
  flag: (value) => sql.literal(booleanLiteral(dialect, value)),
  indexIfNotExists: sql.literal(dialect === "mysql" ? "" : "IF NOT EXISTS "),
  jsonDefault: (value) => sql.literal(dialect === "mysql" ? `('${value}')` : `'${value}'`),
  naturalKey: sql.literal(dialect === "sqlite" ? "NOT NULL UNIQUE" : "PRIMARY KEY")
})

// -----------------------------------------------------------------------------
// Migrations
// -----------------------------------------------------------------------------

/**
 * The credential table.
 *
 * `credential_id` is unique across the whole table rather than per user: a
 * credential id identifies an authenticator's key, and the same key registered
 * to two accounts would make a discoverable sign-in ambiguous — which of them
 * did the person mean? Better-auth indexes it without a unique constraint and
 * has that ambiguity.
 *
 * **Gotchas**
 *
 * The foreign key is a *table* constraint rather than a column one. MySQL's own
 * documentation says an inline `REFERENCES` on a column definition is parsed and
 * ignored — the server this wave tests against does honour it, which is exactly
 * why the library must not depend on that, because the failure mode is a cascade
 * that silently does not run and orphans a credential whose owner was deleted.
 * The table form is honoured by every version and reads identically on
 * PostgreSQL and SQLite. InnoDB creates an index of its own for it and then
 * drops that one in favour of `effect_auth_passkeys_user_id_idx` below, so the
 * column ends up indexed exactly once (verified against MySQL 9.7).
 */
const createPasskeys = Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient
  const dialect = yield* dialectOf(sql)
  const ddl = ddlFor(sql, dialect)

  yield* sql`CREATE TABLE IF NOT EXISTS effect_auth_passkeys (
    id ${ddl.type("id")} PRIMARY KEY,
    user_id ${ddl.type("id")} NOT NULL,
    credential_id ${ddl.type("credential")} NOT NULL,
    public_key ${ddl.type("text")} NOT NULL,
    sign_count ${ddl.type("bigint")} NOT NULL DEFAULT 0,
    transports ${ddl.type("text")} NOT NULL DEFAULT ${ddl.jsonDefault("[]")},
    aaguid ${ddl.type("identity")} NOT NULL,
    backup_eligible ${ddl.type("boolean")} NOT NULL DEFAULT ${ddl.flag(false)},
    backed_up ${ddl.type("boolean")} NOT NULL DEFAULT ${ddl.flag(false)},
    uv_initialised ${ddl.type("boolean")} NOT NULL DEFAULT ${ddl.flag(false)},
    name ${ddl.type("text")},
    created_at ${ddl.type("timestamp")} NOT NULL,
    last_used_at ${ddl.type("timestamp")},
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
  )`

  yield* sql`CREATE UNIQUE INDEX ${ddl.indexIfNotExists}effect_auth_passkeys_credential_id_unique
    ON effect_auth_passkeys (credential_id)`
  yield* sql`CREATE INDEX ${ddl.indexIfNotExists}effect_auth_passkeys_user_id_idx
    ON effect_auth_passkeys (user_id)`
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
  const dialect = yield* dialectOf(sql)
  const ddl = ddlFor(sql, dialect)

  yield* sql`CREATE TABLE IF NOT EXISTS effect_auth_passkey_users (
    user_id ${ddl.type("id")} ${ddl.naturalKey},
    handle ${ddl.type("credential")} NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
  )`

  yield* sql`CREATE UNIQUE INDEX ${ddl.indexIfNotExists}effect_auth_passkey_users_handle_unique
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
