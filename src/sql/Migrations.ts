/**
 * The database schema of `effect-auth`, as a `Migrator`-compatible record.
 *
 * Four tables — `users`, `sessions`, `accounts`, `verifications` — plus the
 * indexes the stores rely on, written once and rendered for PostgreSQL, SQLite
 * and MySQL. Every column is declared by its *role* rather than by a type:
 * `Dialect.columnType` turns a role into `text` on PostgreSQL and SQLite and
 * into a bounded, binary-collated `varchar` on MySQL, which is the only database
 * of the three that cannot index unbounded text or compare an opaque identity
 * without being told which collation to use. The role table is
 * `db-expansion-plan.md` §"Column roles and MySQL lengths".
 *
 * **Details**
 *
 * All timestamps are text columns holding ISO-8601 UTC strings
 * (`2024-01-01T00:00:00.000Z`). That is the encoded form of the domain models'
 * `DateTime` fields, it behaves identically on all three dialects, and — because
 * the format is fixed width — it orders and compares lexicographically, which is
 * what the expiry predicates in `SessionStore` and `VerificationStore` depend
 * on.
 *
 * Flags are the one column shape the dialects genuinely disagree about: a real
 * `boolean` on PostgreSQL and MySQL, an `integer` on SQLite. {@link SqlStores}
 * adapts on the way in and out through `Dialect.booleanCodec`, so the models see
 * a `boolean` either way, and a `DEFAULT` here is written with
 * `Dialect.booleanLiteral` for the same reason.
 *
 * A deployment that added user fields of its own needs a column for each of
 * them. {@link forUserFields} derives those statements from the model — the
 * column name, its type and its default all come off the field's schema — and
 * {@link layerFor} is the four tables plus that.
 *
 * **Gotchas**
 *
 * The `ON DELETE CASCADE` foreign keys are only enforced by SQLite when the
 * connection has `PRAGMA foreign_keys = ON`.
 *
 * On MySQL every statement here is DDL, and DDL commits implicitly: the
 * transaction `Migrator` opens around a run is closed by the first
 * `CREATE TABLE`, so a run that fails half-way leaves the statements that
 * already succeeded in place. `CREATE TABLE IF NOT EXISTS` and the recorded
 * migration ids are what make the retry safe.
 *
 * @since 0.1.0
 */
import { Effect, Layer, Option, Predicate, SchemaAST } from "effect"
import type { Schema } from "effect"
import { Migrator, SqlClient, type SqlError, type Statement } from "effect/unstable/sql"
import type { UserFields, UserModel } from "../domain/Schema.js"
import { camelToSnake } from "../internal/records.js"
import type { ColumnRole, Dialect } from "./Dialect.js"
import { booleanLiteral, columnType, identifier } from "./Dialect.js"

// -----------------------------------------------------------------------------
// The dialect a migration is written for
// -----------------------------------------------------------------------------

const migrationError = (message: string) => new Migrator.MigrationError({ kind: "Failed", message })

const unsupportedDialect = Effect.fail(
  migrationError(`effect-auth migrations only support the "pg", "sqlite" and "mysql" dialects`)
)

/**
 * The dialect these migrations are written for, or the failure that says there
 * is none.
 *
 * Deliberately not `Dialect.dialectOf`, which *dies*. A migration's failures
 * belong to the migrator: `Migrator` wraps one in a `MigrationError` naming the
 * migration that raised it, and {@link forUserFields} declares the same error in
 * its own channel. `dialectOf` is for a store, where an unsupported database is
 * a layer that must not build at all.
 */
const dialectFor = (sql: SqlClient.SqlClient): Effect.Effect<Dialect, Migrator.MigrationError> =>
  sql.onDialectOrElse({
    orElse: () => unsupportedDialect,
    pg: () => Effect.succeed<Dialect>("pg"),
    sqlite: () => Effect.succeed<Dialect>("sqlite"),
    mysql: () => Effect.succeed<Dialect>("mysql")
  })

/**
 * Everything about this library's DDL that one of the three dialects spells
 * differently, as fragments a statement interpolates.
 *
 * There is one of these per migration and it is the only place a migration
 * branches: the statements themselves are written once.
 */
interface Ddl {
  readonly sql: SqlClient.SqlClient
  readonly dialect: Dialect
  /** The DDL type of a column role — `text` here, a bounded `varchar` on MySQL. */
  readonly type: (role: ColumnRole, options?: { readonly length?: number | undefined }) => Statement.Fragment
  /** A flag as a `DEFAULT` literal: `true`/`false` on PostgreSQL, `1`/`0` elsewhere. */
  readonly flag: (value: boolean) => Statement.Fragment
  /**
   * A `DEFAULT` for a column of the `text` role.
   *
   * MySQL refuses a literal default on a `TEXT` column outright (error 1101) and
   * takes an *expression* default instead — parenthesised, as it has since
   * 8.0.13. PostgreSQL and SQLite take the bare literal, which is what they were
   * given before this file knew about MySQL.
   */
  readonly textDefault: (value: string) => Statement.Fragment
  /**
   * `IF NOT EXISTS `, for `CREATE INDEX`.
   *
   * PostgreSQL and SQLite need it: `CREATE TABLE IF NOT EXISTS` may have found a
   * table an older release of this library created, in which case its indexes
   * are there too. MySQL has no such clause on `CREATE INDEX` and needs none —
   * this library has never created a MySQL table, so there is no older schema
   * for one of these statements to arrive late at.
   */
  readonly ifNotExists: Statement.Fragment
  /** `ADD COLUMN`, with the idempotence PostgreSQL is the only one to offer. */
  readonly addColumn: Statement.Fragment
  /**
   * The cascade to `users`, as part of the column definition.
   *
   * Empty on MySQL: InnoDB parses an inline `REFERENCES` and then ignores it, so
   * a foreign key that was declared that way would never cascade. There the
   * constraint is {@link Ddl.usersForeignKey} instead.
   */
  readonly referencesUsers: Statement.Fragment
  /** The cascade to `users` as a table-level constraint, which is MySQL's only working form. */
  readonly usersForeignKey: Statement.Fragment
}

/** The DDL vocabulary of the ambient client's dialect. */
const ddl: Effect.Effect<Ddl, Migrator.MigrationError, SqlClient.SqlClient> = Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient
  const dialect = yield* dialectFor(sql)
  const mysql = dialect === "mysql"
  return {
    sql,
    dialect,
    type: (role, options) => sql.literal(columnType(dialect, role, options)),
    flag: (value) => sql.literal(booleanLiteral(dialect, value)),
    textDefault: (value) => sql.literal(mysql ? `('${value}')` : `'${value}'`),
    ifNotExists: sql.literal(mysql ? "" : "IF NOT EXISTS "),
    addColumn: sql.literal(dialect === "pg" ? "ADD COLUMN IF NOT EXISTS" : "ADD COLUMN"),
    referencesUsers: sql.literal(mysql ? "" : " REFERENCES users (id) ON DELETE CASCADE"),
    usersForeignKey: sql.literal(mysql ? ",\n    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE" : "")
  }
})

// -----------------------------------------------------------------------------
// Migrations
// -----------------------------------------------------------------------------

const createUsers = Effect.gen(function* () {
  const { flag, ifNotExists, sql, type } = yield* ddl

  yield* sql`CREATE TABLE IF NOT EXISTS users (
    id ${type("id")} PRIMARY KEY,
    name ${type("text")} NOT NULL,
    email ${type("email")} NOT NULL,
    email_verified ${type("boolean")} NOT NULL DEFAULT ${flag(false)},
    image ${type("text")},
    created_at ${type("timestamp")} NOT NULL,
    updated_at ${type("timestamp")} NOT NULL
  )`

  yield* sql`CREATE UNIQUE INDEX ${ifNotExists}users_email_unique ON users (email)`
})

const createSessions = Effect.gen(function* () {
  const { ifNotExists, referencesUsers, sql, type, usersForeignKey } = yield* ddl

  yield* sql`CREATE TABLE IF NOT EXISTS sessions (
    id ${type("id")} PRIMARY KEY,
    token_hash ${type("hash")} NOT NULL,
    user_id ${type("id")} NOT NULL${referencesUsers},
    expires_at ${type("timestamp")} NOT NULL,
    ip_address ${type("text")},
    user_agent ${type("text")},
    created_at ${type("timestamp")} NOT NULL,
    updated_at ${type("timestamp")} NOT NULL${usersForeignKey}
  )`

  yield* sql`CREATE UNIQUE INDEX ${ifNotExists}sessions_token_hash_unique ON sessions (token_hash)`
  yield* sql`CREATE INDEX ${ifNotExists}sessions_user_id_idx ON sessions (user_id)`
})

const createAccounts = Effect.gen(function* () {
  const { ifNotExists, referencesUsers, sql, type, usersForeignKey } = yield* ddl

  yield* sql`CREATE TABLE IF NOT EXISTS accounts (
    id ${type("id")} PRIMARY KEY,
    issuer ${type("identity")} NOT NULL,
    account_id ${type("identity")} NOT NULL,
    provider_id ${type("identity")} NOT NULL,
    user_id ${type("id")} NOT NULL${referencesUsers},
    access_token ${type("text")},
    refresh_token ${type("text")},
    id_token ${type("text")},
    access_token_expires_at ${type("timestamp")},
    refresh_token_expires_at ${type("timestamp")},
    scope ${type("text")},
    password_hash ${type("text")},
    created_at ${type("timestamp")} NOT NULL,
    updated_at ${type("timestamp")} NOT NULL${usersForeignKey}
  )`

  yield* sql`CREATE UNIQUE INDEX ${ifNotExists}accounts_issuer_account_id_unique ON accounts (issuer, account_id)`
  yield* sql`CREATE INDEX ${ifNotExists}accounts_user_id_idx ON accounts (user_id)`
})

const createVerifications = Effect.gen(function* () {
  const { ifNotExists, sql, type } = yield* ddl

  yield* sql`CREATE TABLE IF NOT EXISTS verifications (
    id ${type("id")} PRIMARY KEY,
    identifier ${type("identifier")} NOT NULL,
    value_hash ${type("hash")} NOT NULL,
    payload ${type("text")},
    expires_at ${type("timestamp")} NOT NULL,
    created_at ${type("timestamp")} NOT NULL,
    updated_at ${type("timestamp")} NOT NULL
  )`

  yield* sql`CREATE INDEX ${ifNotExists}verifications_identifier_idx ON verifications (identifier)`
})

const addSessionRememberMe = Effect.gen(function* () {
  const { addColumn, flag, sql, type } = yield* ddl

  // A `boolean` on PostgreSQL and MySQL, an integer flag on SQLite — the same
  // divergence as `users.email_verified`. `NOT NULL DEFAULT true`/`1` reflects
  // the behaviour sessions had before the column existed (a full-length
  // "remembered" session) and backfills any row already in the table.
  yield* sql`ALTER TABLE sessions ${addColumn} remember_me ${type("boolean")} NOT NULL DEFAULT ${flag(true)}`
})

const addSessionAssurance = Effect.gen(function* () {
  const { addColumn, dialect, sql, textDefault, type } = yield* ddl

  // Three text columns on every dialect — the levels are literal strings and the
  // log is a JSON array, so nothing here diverges the way a boolean would. They
  // are added separately because SQLite has no multi-column `ADD COLUMN`.
  //
  // `authenticated_at` is backfilled from `created_at`: before step-up existed,
  // a session's creation *was* the moment its owner authenticated, so that is
  // the honest value, and it keeps every existing session exactly as fresh as
  // it was rather than silently re-freshening the table.
  //
  // It has no `DEFAULT`, because only the writer knows when a person actually
  // authenticated and any constant here would be a lie. That is also why it is
  // added nullable and backfilled before the constraint goes on: a `NOT NULL`
  // column with no default cannot be added to a table that has rows.
  yield* sql`ALTER TABLE sessions ${addColumn} authenticated_at ${type("timestamp")}`
  yield* sql`UPDATE sessions SET authenticated_at = created_at WHERE authenticated_at IS NULL`

  // SQLite cannot tighten a column afterwards, so there the `NOT NULL` is the
  // model's to enforce — the backfill still leaves no NULL behind, and
  // `Session.insert` always states the value. The other two can, and do, each in
  // its own spelling.
  if (dialect === "pg") {
    yield* sql`ALTER TABLE sessions ALTER COLUMN authenticated_at SET NOT NULL`
  } else if (dialect === "mysql") {
    yield* sql`ALTER TABLE sessions MODIFY COLUMN authenticated_at ${type("timestamp")} NOT NULL`
  }

  yield* sql`ALTER TABLE sessions ${addColumn} aal ${type("identity")} NOT NULL DEFAULT 'aal1'`
  yield* sql`ALTER TABLE sessions ${addColumn} methods ${type("text")} NOT NULL DEFAULT ${textDefault("[]")}`
})

// -----------------------------------------------------------------------------
// Custom user fields
// -----------------------------------------------------------------------------

/**
 * The shape of a column, as far as any of the three dialects is concerned.
 *
 * Each of these is also a {@link ColumnRole}, so a kind is the role its column
 * is declared with.
 */
type ColumnKind = Extract<ColumnRole, "text" | "boolean" | "number">

/**
 * The bound a custom string field's column gets on MySQL.
 *
 * MySQL cannot index unbounded text, and a deployment may well want an index on
 * a field of its own, so a custom string column is a `varchar` rather than a
 * `text`. Per-field storage metadata — a length, a collation, a large-text
 * intent — is roadmap work; until it exists this is the one bound, and it is
 * documented in the README beside the field API. PostgreSQL and SQLite ignore
 * it: they index `text` happily.
 */
const customStringLength = 255

/**
 * Only names this library derives from a model's own field names are ever
 * interpolated into a statement, but a table name comes from a caller. Both go
 * through {@link identifier} and are therefore escaped; anything that is not a
 * plain identifier is refused as well, because a name that needs escaping to be
 * safe is a mistake worth naming rather than a name worth quoting.
 */
const plainIdentifier = /^[A-Za-z_][A-Za-z0-9_]*$/

/** A one-column catalog answer; the three drivers disagree on the JavaScript type. */
interface NameRow {
  readonly name: unknown
}

const toNames = (rows: ReadonlyArray<NameRow>): ReadonlySet<string> =>
  new Set(rows.map((row) => row.name).filter(Predicate.isString))

/**
 * The columns a table already has, on the dialects that have to be asked.
 *
 * PostgreSQL is not asked at all: it has `ADD COLUMN IF NOT EXISTS`, so the
 * idempotence is the statement's. SQLite is read through `pragma_table_info`,
 * the table-valued form of `PRAGMA table_info`, so that the table name is a
 * bound parameter rather than something interpolated. MySQL has neither, and is
 * read through `information_schema`, scoped to the database the connection is
 * actually pointed at.
 */
const existingColumns = (
  sql: SqlClient.SqlClient,
  dialect: Dialect,
  table: string
): Effect.Effect<ReadonlySet<string>, SqlError.SqlError> => {
  switch (dialect) {
    case "pg":
      return Effect.succeed(new Set<string>())
    case "sqlite":
      return Effect.map(sql<NameRow>`SELECT name FROM pragma_table_info(${table})`, toNames)
    case "mysql":
      return Effect.map(
        sql<NameRow>`SELECT column_name AS name FROM information_schema.columns
          WHERE table_schema = DATABASE() AND table_name = ${table}`,
        toNames
      )
  }
}

/**
 * The column kind a field is stored as, read off its *encoded* schema.
 *
 * **Details**
 *
 * `Schema.Literals(["free", "pro"])` is a union of string literals and stores as
 * text; `Schema.DateTimeUtcFromString` decodes to a `DateTime` and stores as
 * text; a branded string is a string. A union is resolved by dropping its `null`
 * member and requiring the rest to agree, which is what makes
 * `Schema.NullOr(…)` work and a genuinely mixed union fail.
 */
const columnKind = (ast: SchemaAST.AST): Option.Option<ColumnKind> => {
  const encoded = SchemaAST.toEncoded(ast)
  if (SchemaAST.isString(encoded) || SchemaAST.isTemplateLiteral(encoded)) return Option.some("text")
  if (SchemaAST.isBoolean(encoded)) return Option.some("boolean")
  if (SchemaAST.isNumber(encoded)) return Option.some("number")
  if (SchemaAST.isLiteral(encoded)) {
    const { literal } = encoded
    if (Predicate.isString(literal)) return Option.some("text")
    if (Predicate.isBoolean(literal)) return Option.some("boolean")
    if (Predicate.isNumber(literal)) return Option.some("number")
    return Option.none()
  }
  if (SchemaAST.isUnion(encoded)) {
    const kinds = encoded.types.filter((member) => !SchemaAST.isNull(member)).map(columnKind)
    const first = kinds[0]
    if (kinds.length === 0 || first === undefined || Option.isNone(first)) return Option.none()
    return kinds.every((kind) => Option.isSome(kind) && kind.value === first.value) ? first : Option.none()
  }
  return Option.none()
}

/** Whether a field accepts `null`, and therefore whether its column may. */
const isNullable = (ast: SchemaAST.AST): boolean => {
  const encoded = SchemaAST.toEncoded(ast)
  return (
    SchemaAST.isNull(encoded) ||
    (SchemaAST.isUnion(encoded) && encoded.types.some((member) => SchemaAST.isNull(member)))
  )
}

/** A default value, as the literal a `DEFAULT` clause takes. */
const defaultLiteral = (value: unknown, dialect: Dialect): Option.Option<string> => {
  if (Predicate.isString(value)) return Option.some(`'${value.replace(/'/g, "''")}'`)
  if (Predicate.isBoolean(value)) return Option.some(booleanLiteral(dialect, value))
  if (Predicate.isNumber(value) && Number.isFinite(value)) return Option.some(String(value))
  return Option.none()
}

/** A field's column name, refused rather than escaped when it is not an identifier. */
const columnFor = (field: string): Effect.Effect<string, Migrator.MigrationError> => {
  const column = camelToSnake(field)
  return plainIdentifier.test(column)
    ? Effect.succeed(column)
    : Effect.fail(migrationError(`effect-auth: the user field ${field} is not a valid column name`))
}

/** The column kind a field stores as, or the failure that names the field. */
const columnKindFor = (field: string, ast: SchemaAST.AST): Effect.Effect<ColumnKind, Migrator.MigrationError> =>
  Option.match(columnKind(ast), {
    onNone: () =>
      Effect.fail(
        migrationError(
          `effect-auth: the user field ${field} has no column type — a custom field must store as a string, a boolean or a number, so declare it over Schema.String, Schema.Literals, Schema.Boolean, Schema.Number or a DateTime, or add its column by hand`
        )
      ),
    onSome: Effect.succeed
  })

/**
 * Adds a column to the `users` table for every custom field a model declares.
 *
 * **Details**
 *
 * The column name is the field name in `snake_case`, its type comes from the
 * field's encoded schema, and its `DEFAULT` is the field's own declared default,
 * encoded — which is what lets the statement run against a table that already
 * has rows in it. A field whose schema stores as something no column can hold
 * fails with a `MigrationError` naming it, at migration time rather than at the
 * first insert.
 *
 * It is idempotent on all three dialects: PostgreSQL is asked for
 * `ADD COLUMN IF NOT EXISTS`, and SQLite and MySQL — which have no such clause —
 * are read first, through `pragma_table_info` and `information_schema.columns`
 * respectively.
 *
 * **When to use**
 *
 * Number it into your own migration record, above this library's own ids:
 *
 * ```ts skip-type-checking
 * const loader = Migrator.fromRecord({
 *   ...Migrations.migrations,
 *   "0005_user_fields": Migrations.forUserFields(model)
 * })
 * ```
 *
 * **Gotchas**
 *
 * `Migrator` runs each id exactly once, so *adding another field later* needs
 * another id (`"0006_user_fields"`) — the recorded `0005` will not run again. Its
 * statements are idempotent precisely so that re-listing it under a new id is
 * the whole of what adding a field costs. {@link layerFor} sidesteps this by
 * running it outside the migrator on every boot.
 *
 * A custom string field is `text` on PostgreSQL and SQLite and `varchar(255)` on
 * MySQL, because MySQL cannot index unbounded text. A field that needs more room
 * than that on MySQL wants a column added by hand.
 *
 * @category constructors
 * @since 0.1.0
 */
export const forUserFields = <F extends UserFields>(
  model: UserModel<F>,
  options?: { readonly table?: string | undefined }
): Effect.Effect<void, Migrator.MigrationError | SqlError.SqlError, SqlClient.SqlClient> => {
  // Neither guard needs the client, so both are decided before the generator is
  // entered.
  if (model.extraKeys.length === 0) return Effect.void

  const table = options?.table ?? "users"
  if (!plainIdentifier.test(table)) {
    return Effect.fail(migrationError(`effect-auth: ${table} is not a valid table name`))
  }

  return Effect.gen(function* () {
    const { addColumn, dialect, sql, type } = yield* ddl

    const defaults = yield* model.extraDefaults
    const existing = yield* existingColumns(sql, dialect, table)

    for (const field of model.extraKeys) {
      const schema: Schema.Top | undefined = model.selectFields[field]
      if (schema === undefined) continue

      const column = yield* columnFor(field)
      if (existing.has(column)) continue

      const kind = yield* columnKindFor(field, schema.ast)

      const value = defaultLiteral(defaults[field], dialect)
      const nullable = isNullable(schema.ast)
      const constraints = `${nullable ? "" : " NOT NULL"}${Option.isSome(value) ? ` DEFAULT ${value.value}` : ""}`

      yield* sql`ALTER TABLE ${identifier(sql, table)} ${addColumn} ${identifier(sql, column)} ${type(kind, {
        length: customStringLength
      })}${sql.literal(constraints)}`
    }
  })
}

// -----------------------------------------------------------------------------
// Migration sets
// -----------------------------------------------------------------------------

/**
 * A migration record together with everything derived from it: the loader, the
 * effect that runs it, and the layer that runs it while it is built.
 *
 * @category models
 * @since 0.1.0
 */
export interface MigrationSet {
  /** The migrations themselves, keyed `<id>_<name>`. */
  readonly migrations: Record<string, Effect.Effect<void, unknown, SqlClient.SqlClient>>
  /** {@link MigrationSet.migrations} as a `Migrator` loader. */
  readonly loader: Migrator.Loader
  /** Runs them, answering with the ones that were applied. */
  readonly run: Effect.Effect<
    ReadonlyArray<readonly [id: number, name: string]>,
    Migrator.MigrationError | SqlError.SqlError,
    SqlClient.SqlClient
  >
  /** {@link MigrationSet.run}, as a layer that applies them while it is built. */
  readonly layer: Layer.Layer<never, Migrator.MigrationError | SqlError.SqlError, SqlClient.SqlClient>
}

/**
 * Gathers a plugin's migrations into a {@link MigrationSet} with a bookkeeping
 * table of its own.
 *
 * **When to use**
 *
 * In every plugin that owns tables. `Migrator.fromRecord` orders and records
 * migrations by a *global* numeric id, so a plugin that merged its statements
 * into this library's record — or into the application's — would be one
 * renumbering away from a migration that never runs: an id lower than one
 * already recorded is silently skipped. A table per plugin is what keeps each
 * set's numbering its own business, and it is why every set starts at `0001`.
 *
 * **Example**
 *
 * ```ts
 * import { Effect } from "effect"
 * import { SqlClient } from "effect/unstable/sql"
 * import { Migrations } from "effect-auth"
 *
 * const createInvites = Effect.flatMap(
 *   SqlClient.SqlClient,
 *   (sql) => sql`CREATE TABLE IF NOT EXISTS invites (id varchar(64) NOT NULL PRIMARY KEY)`
 * )
 *
 * export const Migrations$ = Migrations.make({
 *   table: "effect_auth_invites_migrations",
 *   migrations: { "0001_create_invites": createInvites }
 * })
 * ```
 *
 * **Gotchas**
 *
 * Sequence the layers where one set's tables reference another's:
 * `Plugin.Migrations.layer.pipe(Layer.provide(Migrations.layer))`. Two sets built
 * over the same `SqlClient` with no ordering between them run concurrently.
 *
 * Write the DDL for all three supported dialects, as this library's own does: a
 * key is a bounded `varchar` rather than a `text`, because MySQL cannot index
 * unbounded text at all.
 *
 * @category constructors
 * @since 0.1.0
 */
export const make = (options: {
  readonly table: string
  readonly migrations: Record<string, Effect.Effect<void, unknown, SqlClient.SqlClient>>
}): MigrationSet => {
  const loader = Migrator.fromRecord(options.migrations)
  const run = Migrator.make({})({ loader, table: options.table })
  return { migrations: options.migrations, loader, run, layer: Layer.effectDiscard(run) }
}

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
 * or skips migrations. Number your own migrations above `0006`.
 *
 * @category models
 * @since 0.1.0
 */
export const migrations: Record<string, Effect.Effect<void, unknown, SqlClient.SqlClient>> = {
  "0001_create_users": createUsers,
  "0002_create_sessions": createSessions,
  "0003_create_accounts": createAccounts,
  "0004_create_verifications": createVerifications,
  "0005_session_remember_me": addSessionRememberMe,
  "0006_session_assurance": addSessionAssurance
}

/**
 * The name of the table this library records its own migrations in.
 *
 * @category constructors
 * @since 0.1.0
 */
export const table = "effect_auth_migrations"

/** {@link migrations}, and everything derived from them. */
const core = make({ table, migrations })

/**
 * The `Migrator` loader for {@link migrations}.
 *
 * @category models
 * @since 0.1.0
 */
export const loader: Migrator.Loader = core.loader

/**
 * Runs the `effect-auth` migrations against the ambient `SqlClient`, returning
 * the migrations that were applied.
 *
 * @category constructors
 * @since 0.1.0
 */
export const run: Effect.Effect<
  ReadonlyArray<readonly [id: number, name: string]>,
  Migrator.MigrationError | SqlError.SqlError,
  SqlClient.SqlClient
> = core.run

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
 * @since 0.1.0
 */
export const layer: Layer.Layer<never, Migrator.MigrationError | SqlError.SqlError, SqlClient.SqlClient> = core.layer

/**
 * {@link layer}, plus the columns a model's custom user fields need.
 *
 * **Details**
 *
 * The four table migrations run through `Migrator` as always; the custom columns
 * are then synchronised by {@link forUserFields}, *outside* the migrator and on
 * every build. That is deliberate: the statements are idempotent, and a recorded
 * migration would silently skip a field added after the first deployment — which
 * is exactly the mistake this convenience layer exists to spare a quickstart.
 *
 * **When to use**
 *
 * As a quickstart and in tests. A production deployment that owns its migrator
 * numbers {@link forUserFields} into its own record instead, and takes on the
 * bookkeeping that comes with that.
 *
 * @category layers
 * @since 0.1.0
 */
export const layerFor = <F extends UserFields>(
  model: UserModel<F>
): Layer.Layer<never, Migrator.MigrationError | SqlError.SqlError, SqlClient.SqlClient> =>
  Layer.effectDiscard(Effect.flatMap(run, () => forUserFields(model)))
