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
 * Every column is declared through {@link Dialect.columnType} from the role it
 * plays: ids and digests are unbounded `text` on PostgreSQL and SQLite and
 * bounded, binary-collated `varchar` on MySQL, which is what an index there
 * requires. `last_used_step` is the one column of the `bigint` role in this
 * library.
 *
 * Timestamps are the `timestamp` role — ISO-8601 UTC in a string column,
 * exactly as the core tables' are, which is what makes `expires_at > $now` a
 * correct comparison on all three dialects.
 *
 * The `ON DELETE CASCADE` foreign keys are only enforced by SQLite when the
 * connection has `PRAGMA foreign_keys = ON` — the same caveat the core
 * migrations carry.
 *
 * @since 0.2.0
 */
import { Effect } from "effect"
import type { Layer } from "effect"
import type { Migrator, SqlError, Statement } from "effect/unstable/sql"
import { SqlClient } from "effect/unstable/sql"
import type { ColumnRole, Dialect } from "../sql/Dialect.js"
import { columnType, dialectOf } from "../sql/Dialect.js"
import * as Migrations from "../sql/Migrations.js"

// -----------------------------------------------------------------------------
// DDL vocabulary
// -----------------------------------------------------------------------------

/**
 * The two things this plugin's DDL has to spell per dialect. Everything else —
 * the names, the constraints, the foreign keys — is the same text on all three.
 */
interface Ddl {
  /** The type a column role is declared as here. */
  readonly type: (role: ColumnRole) => Statement.Fragment
  /**
   * `IF NOT EXISTS `, on the dialects whose `CREATE INDEX` takes it.
   *
   * MySQL's does not, and needs none: a migration runs exactly once, and the
   * clause is belt-and-braces on the other two rather than load-bearing.
   */
  readonly indexIfNotExists: Statement.Fragment
}

const ddlFor = (sql: SqlClient.SqlClient, dialect: Dialect): Ddl => ({
  type: (role) => sql.literal(columnType(dialect, role)),
  indexIfNotExists: sql.literal(dialect === "mysql" ? "" : "IF NOT EXISTS ")
})

// -----------------------------------------------------------------------------
// Migrations
// -----------------------------------------------------------------------------

/**
 * `0001_create_two_factor`: the TOTP enrolment, the recovery codes and the
 * trusted devices.
 *
 * **Details**
 *
 * `effect_auth_totp.user_id` is the primary key: a person has one authenticator
 * app enrolment, and the conditional upsert on it is what makes "abandoning a
 * pending enrolment regenerates it" one statement rather than a read and a
 * write. It stays a declared `PRIMARY KEY` on SQLite — unlike the natural keys
 * that a store reaches by inserting and catching the loser — because no caller
 * ever sees a conflict on it: every write goes through
 * `Mutations.upsertAndRead`, which resolves the collision inside the statement
 * rather than failing.
 *
 * `last_used_step` is the replay guard's column — the TOTP step the enrolment
 * last authenticated with. The `bigint` role rather than an integer one because
 * a 32-bit step count runs out, and the comparison that guards it is numeric.
 *
 * Both `code_hash` and `token_hash` are keyed digests (`Hmac`), never fast
 * hashes, and both are globally unique: a code or a device token names exactly
 * one row whoever presents it. They carry the `hash` role, so on MySQL they are
 * `varchar(64) … ascii_bin` and their unique indexes are inside InnoDB's
 * 3072-byte key limit.
 *
 * **Gotchas**
 *
 * Every foreign key is a *table* constraint rather than a column one. MySQL's
 * own documentation says an inline `REFERENCES` on a column definition is
 * parsed and ignored — the server this wave tests against does honour it, which
 * is exactly why the library must not depend on that, because the failure mode
 * is a cascade that silently does not run and orphans a recovery code whose
 * owner was deleted. The table form is honoured by every version and reads
 * identically on PostgreSQL and SQLite. InnoDB creates an index of its own for
 * each of them and then drops it in favour of the `_user_id_idx` created below,
 * so a column ends up indexed exactly once (verified against MySQL 9.7).
 */
const createTwoFactor = Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient
  const dialect = yield* dialectOf(sql)
  const ddl = ddlFor(sql, dialect)

  yield* sql`CREATE TABLE IF NOT EXISTS effect_auth_totp (
    user_id ${ddl.type("id")} PRIMARY KEY,
    secret_ciphertext ${ddl.type("text")} NOT NULL,
    verified_at ${ddl.type("timestamp")},
    last_used_step ${ddl.type("bigint")},
    created_at ${ddl.type("timestamp")} NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
  )`

  yield* sql`CREATE TABLE IF NOT EXISTS effect_auth_recovery_codes (
    id ${ddl.type("id")} PRIMARY KEY,
    user_id ${ddl.type("id")} NOT NULL,
    code_hash ${ddl.type("hash")} NOT NULL,
    used_at ${ddl.type("timestamp")},
    created_at ${ddl.type("timestamp")} NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
  )`

  yield* sql`CREATE UNIQUE INDEX ${ddl.indexIfNotExists}effect_auth_recovery_codes_code_hash_unique
    ON effect_auth_recovery_codes (code_hash)`
  yield* sql`CREATE INDEX ${ddl.indexIfNotExists}effect_auth_recovery_codes_user_id_idx
    ON effect_auth_recovery_codes (user_id)`

  yield* sql`CREATE TABLE IF NOT EXISTS effect_auth_trusted_devices (
    id ${ddl.type("id")} PRIMARY KEY,
    user_id ${ddl.type("id")} NOT NULL,
    token_hash ${ddl.type("hash")} NOT NULL,
    expires_at ${ddl.type("timestamp")} NOT NULL,
    last_used_at ${ddl.type("timestamp")} NOT NULL,
    user_agent ${ddl.type("text")},
    ip_address ${ddl.type("text")},
    label ${ddl.type("text")},
    created_at ${ddl.type("timestamp")} NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
  )`

  yield* sql`CREATE UNIQUE INDEX ${ddl.indexIfNotExists}effect_auth_trusted_devices_token_hash_unique
    ON effect_auth_trusted_devices (token_hash)`
  yield* sql`CREATE INDEX ${ddl.indexIfNotExists}effect_auth_trusted_devices_user_id_idx
    ON effect_auth_trusted_devices (user_id)`
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
