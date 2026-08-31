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
 * @since 1.0.0
 */
import { Effect, Layer, Option, Predicate, SchemaAST } from "effect"
import type { Schema } from "effect"
import { Migrator, SqlClient, SqlError } from "effect/unstable/sql"
import type { UserFields, UserModel } from "../domain/Schema.js"
import { camelToSnake } from "../internal/records.js"

// -----------------------------------------------------------------------------
// Migrations
// -----------------------------------------------------------------------------

const migrationError = (message: string) => new Migrator.MigrationError({ kind: "Failed", message })

const unsupportedDialect = Effect.fail(
  migrationError(`effect-auth migrations only support the "pg" and "sqlite" dialects`)
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

// -----------------------------------------------------------------------------
// Custom user fields
// -----------------------------------------------------------------------------

/**
 * The shape of a column, as far as either dialect is concerned.
 */
type ColumnKind = "text" | "boolean" | "number"

/** The SQL type and the boolean literals each dialect spells differently. */
interface Dialect {
  readonly type: (kind: ColumnKind) => string
  readonly boolean: (value: boolean) => string
  readonly addColumn: (table: string, definition: string) => string
  readonly existingColumns: Effect.Effect<ReadonlySet<string>, SqlError.SqlError, SqlClient.SqlClient>
}

/**
 * Only names this library derives from a model's own field names are ever
 * interpolated into a statement, but a table name comes from a caller, and the
 * two go into the same string. Anything that is not a plain identifier is
 * refused rather than escaped.
 */
const identifier = /^[A-Za-z_][A-Za-z0-9_]*$/

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
  return SchemaAST.isNull(encoded) ||
    (SchemaAST.isUnion(encoded) && encoded.types.some((member) => SchemaAST.isNull(member)))
}

/** A default value, as the literal a `DEFAULT` clause takes. */
const defaultLiteral = (value: unknown, dialect: Dialect): Option.Option<string> => {
  if (Predicate.isString(value)) return Option.some(`'${value.replace(/'/g, "''")}'`)
  if (Predicate.isBoolean(value)) return Option.some(dialect.boolean(value))
  if (Predicate.isNumber(value) && Number.isFinite(value)) return Option.some(String(value))
  return Option.none()
}

const dialectOf = (
  sql: SqlClient.SqlClient,
  table: string
): Option.Option<Dialect> =>
  sql.onDialectOrElse({
    orElse: (): Option.Option<Dialect> => Option.none(),
    pg: () =>
      Option.some({
        type: (kind) => kind === "text" ? "text" : kind === "boolean" ? "boolean" : "double precision",
        boolean: (value) => value ? "true" : "false",
        // PostgreSQL has the idempotence built in; SQLite has to be asked.
        addColumn: (table, definition) => `ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS ${definition}`,
        existingColumns: Effect.succeed(new Set<string>())
      }),
    sqlite: () =>
      Option.some({
        type: (kind) => kind === "text" ? "text" : kind === "boolean" ? "integer" : "real",
        boolean: (value) => value ? "1" : "0",
        addColumn: (table, definition) => `ALTER TABLE ${table} ADD COLUMN ${definition}`,
        existingColumns: Effect.map(
          sql.unsafe<{ readonly name: unknown }>(`PRAGMA table_info(${table})`),
          (rows) => new Set(rows.map((row) => row.name).filter(Predicate.isString))
        )
      })
  })

/**
 * Adds a column to the `users` table for every custom field a model declares.
 *
 * **Details**
 *
 * The column name is the field name in `snake_case`, its type comes from the
 * field's encoded schema, and its `DEFAULT` is the field's own declared default,
 * encoded — which is what lets the statement run against a table that already
 * has rows in it. A field whose schema stores as something neither dialect has a
 * column for fails with a `MigrationError` naming it, at migration time rather
 * than at the first insert.
 *
 * It is idempotent on both dialects: PostgreSQL is asked for
 * `ADD COLUMN IF NOT EXISTS`, and SQLite — which has no such clause — is read
 * with `PRAGMA table_info` first.
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
 * @category constructors
 * @since 1.0.0
 */
export const forUserFields = <F extends UserFields>(
  model: UserModel<F>,
  options?: { readonly table?: string | undefined }
): Effect.Effect<void, Migrator.MigrationError | SqlError.SqlError, SqlClient.SqlClient> =>
  Effect.gen(function*() {
    if (model.extraKeys.length === 0) return

    const table = options?.table ?? "users"
    if (!identifier.test(table)) {
      return yield* Effect.fail(migrationError(`effect-auth: ${table} is not a valid table name`))
    }

    const sql = yield* SqlClient.SqlClient
    const dialect = dialectOf(sql, table)
    if (Option.isNone(dialect)) return yield* unsupportedDialect

    const defaults = yield* model.extraDefaults
    const existing = yield* dialect.value.existingColumns

    for (const field of model.extraKeys) {
      const schema: Schema.Top | undefined = model.selectFields[field]
      if (schema === undefined) continue

      const column = camelToSnake(field)
      if (!identifier.test(column)) {
        return yield* Effect.fail(migrationError(`effect-auth: the user field ${field} is not a valid column name`))
      }
      if (existing.has(column)) continue

      const kind = columnKind(schema.ast)
      if (Option.isNone(kind)) {
        return yield* Effect.fail(
          migrationError(
            `effect-auth: the user field ${field} has no column type — a custom field must store as a string, a boolean or a number, so declare it over Schema.String, Schema.Literals, Schema.Boolean, Schema.Number or a DateTime, or add its column by hand`
          )
        )
      }

      const value = defaultLiteral(defaults[field], dialect.value)
      const nullable = isNullable(schema.ast)
      const definition = `${column} ${dialect.value.type(kind.value)}${nullable ? "" : " NOT NULL"}${
        Option.isSome(value) ? ` DEFAULT ${value.value}` : ""
      }`
      yield* sql.unsafe(dialect.value.addColumn(table, definition))
    }
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
 * @since 1.0.0
 */
export const layerFor = <F extends UserFields>(
  model: UserModel<F>
): Layer.Layer<never, Migrator.MigrationError | SqlError.SqlError, SqlClient.SqlClient> =>
  Layer.effectDiscard(Effect.flatMap(run, () => forUserFields(model)))
