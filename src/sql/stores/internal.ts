/**
 * The machinery the four SQL store implementations share: the user model's
 * column map and the projections derived from it, the dialect's boolean codec,
 * the raw row shapes a statement hands back, and the wrapper that turns any
 * failure into a `PersistenceError`.
 *
 * Not exported from the package: nothing here is part of the public API. The
 * one symbol that is — `decodeSqliteBoolean` — is re-exported by
 * `src/sql/SqlStores.ts`, which is where its documentation lives.
 *
 * @internal
 */
import { Effect, Predicate, type Schema, SchemaAST } from "effect"
import type { SqlClient } from "effect/unstable/sql"
import { camelToSnake } from "../../internal/records.js"
import { PersistenceError, persistenceFailureKind } from "../../domain/Stores.js"
import type { UserRow } from "../../domain/Schema.js"

// -----------------------------------------------------------------------------
// User columns, derived from the model
// -----------------------------------------------------------------------------

/**
 * One stored column of the user model.
 *
 * **Details**
 *
 * `field` is what the model calls it, `column` is what the database calls it,
 * and `boolean` is whether the stored value is one — the single dialect-sensitive
 * property a column has here, and the reason it is read off the schema rather
 * than off a hard-coded list of names.
 *
 * @internal
 */
export interface UserColumn {
  readonly field: string
  readonly column: string
  readonly boolean: boolean
}

/**
 * Whether a field's *stored* form is a boolean.
 *
 * **Gotchas**
 *
 * The encoded side is what matters: `Schema.DateTimeUtcFromString` decodes to a
 * `DateTime` and stores a string, and a `Schema.Literals` of strings stores one
 * too. A nullable boolean is a union, so its members are looked at as well.
 */
const storesBoolean = (schema: Schema.Top): boolean => {
  const ast = SchemaAST.toEncoded(schema.ast)
  return SchemaAST.isBoolean(ast) || (SchemaAST.isUnion(ast) && ast.types.some((member) => SchemaAST.isBoolean(member)))
}

/** @internal */
export const userColumnsOf = (fields: { readonly [key: string]: Schema.Top }): ReadonlyArray<UserColumn> =>
  Object.entries(fields).map(([field, schema]) => ({
    field,
    column: camelToSnake(field),
    boolean: storesBoolean(schema)
  }))

/**
 * `id, email_verified AS "emailVerified", …` — the projection of a plain read.
 *
 * @internal
 */
export const projectionOf = (columns: ReadonlyArray<UserColumn>): string =>
  columns.map(({ column, field }) => (column === field ? column : `${column} AS "${field}"`)).join(", ")

/**
 * `u.email_verified AS "u_emailVerified", …` — the projection of the joined read.
 *
 * @internal
 */
export const joinedProjectionOf = (columns: ReadonlyArray<UserColumn>, alias: string, prefix: string): string =>
  columns.map(({ column, field }) => `${alias}.${column} AS "${prefix}${field}"`).join(", ")

// -----------------------------------------------------------------------------
// Raw rows
// -----------------------------------------------------------------------------

/** @internal */
export interface RawCountRow {
  readonly count: unknown
}

/** @internal */
export interface RawIdRow {
  readonly id: unknown
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

const fail = (operation: string) => (cause: unknown) =>
  PersistenceError.make({ operation, kind: persistenceFailureKind(cause), cause })

/** @internal */
export const persist =
  (operation: string) =>
  <A, E, R>(effect: Effect.Effect<A, E, R>): Effect.Effect<A, PersistenceError, R> =>
    Effect.mapError(effect, fail(operation))

/**
 * Reads SQLite's integer flag back as a boolean, leaving an absent value
 * absent. Public as `SqlStores.decodeSqliteBoolean`, where the reasoning for
 * leaving `null` and `undefined` alone is written down.
 *
 * @internal
 */
export const decodeSqliteBoolean = (value: unknown): unknown =>
  value === null || value === undefined ? value : value === 1 || value === true

/**
 * SQLite has no boolean type: `users.email_verified` is an integer flag there
 * and a real boolean on PostgreSQL. These two adapters are the only dialect
 * divergence in the store implementations.
 *
 * @internal
 */
export const booleanCodec = (sql: SqlClient.SqlClient) => ({
  encode: sql.onDialectOrElse({
    orElse:
      () =>
      (value: boolean): boolean | number =>
        value,
    sqlite:
      () =>
      (value: boolean): boolean | number =>
        value ? 1 : 0
  }),
  decode: sql.onDialectOrElse({
    orElse:
      () =>
      (value: unknown): unknown =>
        value,
    sqlite: () => decodeSqliteBoolean
  })
})

/**
 * Reads the user half out of a result row: the columns the model declares,
 * un-prefixed, with the boolean ones brought back from whatever the dialect
 * stores them as.
 *
 * @internal
 */
export const userReaderOf =
  (columns: ReadonlyArray<UserColumn>, decodeBoolean: (value: unknown) => unknown) =>
  (row: UserRow, prefix: string): UserRow => {
    const user: Record<string, unknown> = Object.create(null)
    for (const { boolean, field } of columns) {
      const value = row[`${prefix}${field}`]
      user[field] = boolean ? decodeBoolean(value) : value
    }
    return user
  }

/**
 * Turns an encoded model row into the columns a statement writes: `camelCase`
 * becomes `snake_case`, and a boolean becomes whatever this dialect stores one
 * as.
 *
 * @internal
 */
export const columnWriterOf = (
  columns: ReadonlyArray<UserColumn>,
  encodeBoolean: (value: boolean) => boolean | number
) => {
  const byField = new Map(columns.map((column) => [column.field, column]))
  return (row: UserRow): Record<string, unknown> => {
    const record: Record<string, unknown> = Object.create(null)
    for (const [field, value] of Object.entries(row)) {
      const column = byField.get(field)
      record[column?.column ?? camelToSnake(field)] =
        column?.boolean === true && Predicate.isBoolean(value) ? encodeBoolean(value) : value
    }
    return record
  }
}
