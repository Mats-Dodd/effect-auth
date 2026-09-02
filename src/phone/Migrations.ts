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
 * Every column is declared through `Dialect.columnType` — `identity` for the
 * number, `id` for the holder, `timestamp` for the two clocks — so PostgreSQL
 * and SQLite get `text` and MySQL, which cannot index an unbounded `text`
 * column, gets a bounded `varchar` in a binary collation. The number takes a
 * bound of its own, sixteen: E.164 caps a number at fifteen digits and the `+`
 * makes sixteen, and `E164.normalize` is the only thing that writes here.
 *
 * @since 0.2.0
 */
import type { Layer } from "effect"
import { Effect } from "effect"
import { type Migrator, SqlClient, type SqlError } from "effect/unstable/sql"
import type { ColumnRole } from "../sql/Dialect.js"
import { columnType, dialectOf, identifier } from "../sql/Dialect.js"
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

/**
 * What a number can be at its longest: E.164 caps one at fifteen digits and the
 * `+` makes sixteen.
 *
 * It overrides the `identity` role's MySQL bound rather than taking it, because
 * `E164.normalize` is the only thing that ever writes this column and it cannot
 * produce a longer string — so the tighter bound is a fact about the data rather
 * than a guess, and it keeps the key narrow.
 */
const e164Length = 16

/**
 * `0001_create_phone_numbers`.
 *
 * One row per number and — through the unique constraint on `user_id` — at most
 * one number per person. The number itself is the key, so two people can never
 * hold the same handset: the second `INSERT` is refused by the database rather
 * than by a check somebody could forget to write.
 *
 * `verified_at` is nullable and is what every read filters on. A row with a
 * null there is a claim, not a proof.
 */
const createPhoneNumbers = Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient
  const dialect = yield* dialectOf(sql)
  const type = (role: ColumnRole, length?: number) => sql.literal(columnType(dialect, role, { length }))

  // SQLite reports a conflict on a declared PRIMARY KEY as
  // SQLITE_CONSTRAINT_PRIMARYKEY (1555) and only a conflict on a UNIQUE index
  // as SQLITE_CONSTRAINT_UNIQUE (2067), which is the only one
  // `persistenceFailureKind` classifies as a lost race — so the number is a
  // NOT NULL UNIQUE column there rather than the primary key it is on the other
  // two. The constraint is the same; the reported error is not. MySQL reports
  // ER_DUP_ENTRY (1062) for either, so it keeps the primary key.
  const numberKey = sql.literal(dialect === "sqlite" ? "NOT NULL UNIQUE" : "PRIMARY KEY")

  // The foreign key is a table constraint rather than a column one because
  // MySQL parses an inline `REFERENCES` clause and then ignores it — the
  // cascade would silently not exist. PostgreSQL and SQLite read the two forms
  // identically. `user_id` is unique, so InnoDB has an index for the foreign
  // key already and adds none of its own.
  yield* sql`CREATE TABLE IF NOT EXISTS ${identifier(sql, phoneNumbersTable)} (
    phone_e164 ${type("identity", e164Length)} ${numberKey},
    user_id ${type("id")} NOT NULL UNIQUE,
    verified_at ${type("timestamp")},
    created_at ${type("timestamp")} NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
  )`
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
