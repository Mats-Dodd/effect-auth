/**
 * The three dialects this library supports, and the four things they disagree
 * about.
 *
 * `effect-auth` runs on PostgreSQL, SQLite and MySQL. Everything else about the
 * SQL it writes is portable; these four are not, and every one of them is
 * decided here rather than at a statement:
 *
 * - **How a flag is stored.** {@link booleanCodec}. PostgreSQL has a `boolean`;
 *   SQLite has an integer and MySQL a `tinyint(1)`, so a flag goes in as `1`/`0`
 *   and comes back as whichever of the two the driver felt like.
 * - **How a row is locked.** {@link lockClause}. PostgreSQL and MySQL take
 *   `FOR UPDATE`; SQLite has no such clause and needs none, because
 *   `@effect/sql-sqlite-node` opens a writable transaction with `BEGIN
 *   IMMEDIATE` and therefore serialises writers already.
 * - **What a column is declared as.** {@link columnType} and
 *   {@link booleanLiteral}. PostgreSQL and SQLite index unbounded `text`; MySQL
 *   cannot, so every indexed column is a bounded `varchar` with a stated
 *   collation. The roles are the table in `db-expansion-plan.md` §"Column roles".
 * - **How a name is escaped.** {@link identifier}, which is the only way a table
 *   or column name reaches a statement.
 *
 * **Details**
 *
 * {@link dialectOf} is the single place the ambient client's dialect is read. It
 * narrows Effect SQL's five-member `Statement.Dialect` to the three this library
 * supports and *dies* on the other two, so a store or a migration set never has
 * an `orElse` branch that quietly inherits PostgreSQL's spelling on a database
 * that does not share it. Everything downstream branches on the narrowed
 * {@link Dialect} value, which is a total `switch` rather than a lookup with a
 * fallback.
 *
 * **Gotchas**
 *
 * {@link identifier} escapes — `"users"` on PostgreSQL and SQLite, `` `users` ``
 * on MySQL — where the `sql.literal(name)` it replaces did not. The two are
 * equivalent for every name this library uses (all lower-case, none reserved),
 * and the escaped form is the one that stays correct when a deployment names a
 * custom user field after a keyword.
 *
 * Not exported from the package: nothing here is part of the public API.
 *
 * @internal
 */
import { Effect } from "effect"
import type { SqlClient, Statement } from "effect/unstable/sql"

// -----------------------------------------------------------------------------
// The dialect
// -----------------------------------------------------------------------------

/**
 * The three dialects this library supports. Never `"mssql"`, never
 * `"clickhouse"`.
 *
 * @internal
 */
export type Dialect = "pg" | "sqlite" | "mysql"

/**
 * The dialect the ambient client reports, narrowed to the three that are
 * supported.
 *
 * **Details**
 *
 * Read once, where a store or a migration set is built, and passed to every
 * helper below as a value. The die is the whole point: Effect SQL's dialect
 * union has five members, and the two this library has never been run against
 * would otherwise take the `orElse` branch of every `onDialectOrElse` in the
 * tree and be served PostgreSQL's SQL.
 *
 * A layer that builds a store therefore fails to build at all on an unsupported
 * database, with the dialect the driver reported in the message, rather than at
 * the first statement that happens to differ.
 *
 * @internal
 */
export const dialectOf = (sql: SqlClient.SqlClient): Effect.Effect<Dialect> => {
  const reported: Statement.Dialect | "unknown" = sql.onDialectOrElse({
    orElse: () => "unknown" as const,
    pg: () => "pg" as const,
    sqlite: () => "sqlite" as const,
    mysql: () => "mysql" as const,
    mssql: () => "mssql" as const,
    clickhouse: () => "clickhouse" as const
  })
  return reported === "pg" || reported === "sqlite" || reported === "mysql"
    ? Effect.succeed(reported)
    : Effect.die(
        new Error(`effect-auth does not support the ${reported} SQL dialect: it supports pg, sqlite and mysql`)
      )
}

// -----------------------------------------------------------------------------
// Identifiers
// -----------------------------------------------------------------------------

/**
 * A table or column name, escaped by the dialect's own compiler.
 *
 * **When to use**
 *
 * Every time a name is not written out in the template: a plugin's table name,
 * a custom user field's column, the key columns a mutation helper re-addresses a
 * row by. It is the replacement for `sql.literal(name)` and for every
 * `sql.unsafe` that interpolated one.
 *
 * **Gotchas**
 *
 * A *projection* — `token_hash AS "tokenHash", …` — is not an identifier; it is
 * a list of them with aliases. The ones whose names this library writes out are
 * a `sql.literal` fragment built once when the store is constructed; the ones
 * over a deployment's own columns are built from this, in
 * `src/sql/stores/internal.ts`, because a custom field may be called `order`.
 *
 * @internal
 */
export const identifier = (sql: SqlClient.SqlClient, name: string): Statement.Identifier => sql(name)

// -----------------------------------------------------------------------------
// Booleans
// -----------------------------------------------------------------------------

/**
 * The two directions a flag travels, for one dialect.
 *
 * @internal
 */
export interface BooleanCodec {
  /** A `boolean`, as this dialect stores one. */
  readonly encode: (value: boolean) => boolean | number
  /** Whatever the driver handed back, as a `boolean`. */
  readonly decode: (value: unknown) => boolean
  /**
   * {@link BooleanCodec.decode}, leaving an absent value absent.
   *
   * `null` and `undefined` pass through untouched. A custom user field may be
   * `NullOr(Schema.Boolean)` — a nullable flag whose column is nullable on every
   * dialect — and turning its `null` into `false` would be a silent rewrite of
   * "not asked yet" into "declined" on every read, which the model would accept
   * because `false` decodes just as well.
   */
  readonly decodeNullable: (value: unknown) => boolean | null | undefined
}

/** `1`/`0` on the dialects with no boolean type. */
const encodeFlag = (value: boolean): boolean | number => (value ? 1 : 0)

/** The dialect that has one stores a `boolean`. */
const passThrough = (value: boolean): boolean | number => value

/**
 * A stored flag, whichever of the three forms a driver hands it back in.
 *
 * PostgreSQL returns `true`/`false`, SQLite the integer it was given, and
 * mysql2 the `tinyint(1)` as `1`/`0` — so one reader covers all three, and it is
 * total rather than a pass-through, because a column that is not one of those
 * five values is a schema that has drifted, not a flag.
 */
const decodeFlag = (value: unknown): boolean => value === true || value === 1

/**
 * The single boolean codec in this library.
 *
 * **Details**
 *
 * `encode` is the only half that varies: PostgreSQL is handed a `boolean` and
 * SQLite and MySQL are handed `1`/`0`. `decode` is deliberately the same
 * function on all three — every driver's stored form reads back the same way,
 * and a reader that branched would be a second place to keep in step with the
 * migrations.
 *
 * **When to use**
 *
 * At the two edges of a store: on the way into a statement, and on the way out
 * of a row, before the model's schema sees it. Never in the domain — above the
 * store seam a flag is a `boolean` and nothing else.
 *
 * @internal
 */
export const booleanCodec = (dialect: Dialect): BooleanCodec => ({
  encode: dialect === "pg" ? passThrough : encodeFlag,
  decode: decodeFlag,
  decodeNullable: (value) => (value === null || value === undefined ? value : decodeFlag(value))
})

/**
 * A flag as a DDL literal, for a `DEFAULT` clause.
 *
 * @internal
 */
export const booleanLiteral = (dialect: Dialect, value: boolean): string =>
  dialect === "pg" ? (value ? "true" : "false") : value ? "1" : "0"

// -----------------------------------------------------------------------------
// Row locks
// -----------------------------------------------------------------------------

/**
 * ` FOR UPDATE`, on the dialects that have it.
 *
 * **Gotchas**
 *
 * Empty on SQLite, which has no such clause and needs none: its driver opens a
 * writable transaction with `BEGIN IMMEDIATE`, so writers are serialised from
 * the first statement rather than upgrading a read lock half-way through. The
 * fragment carries its own leading space, so a call site appends it to the
 * statement with no separator — `… WHERE id = ${id}${lockClause(sql, dialect)}`
 * — and SQLite's empty fragment leaves no trailing whitespace behind.
 *
 * @internal
 */
export const lockClause = (sql: SqlClient.SqlClient, dialect: Dialect): Statement.Fragment =>
  sql.literal(dialect === "sqlite" ? "" : " FOR UPDATE")

// -----------------------------------------------------------------------------
// Column types
// -----------------------------------------------------------------------------

/**
 * What a column is *for*, which is what decides its type on each dialect.
 *
 * **Details**
 *
 * PostgreSQL and SQLite index unbounded `text` happily, so every string role is
 * `text` there and the role only matters on MySQL, where an indexed column has
 * to be a bounded `varchar` and an opaque identity must not inherit the server's
 * (usually case-insensitive) default collation. The bounds are in
 * `db-expansion-plan.md` §"Column roles"; each of them keeps its unique index
 * inside InnoDB's 3072-byte key limit.
 *
 * @internal
 */
export type ColumnRole =
  /** Primary keys and foreign keys. */
  | "id"
  /** `token_hash`, `value_hash`, `code_hash` — anything that is a digest. */
  | "hash"
  /** WebAuthn credential ids and passkey user handles. */
  | "credential"
  /** `users.email`, stored already normalised by the domain. */
  | "email"
  /** `issuer`, `account_id`, `provider_id`, `username`, `phone_e164`, `aaguid`, `aal`. */
  | "identity"
  /** `verifications.identifier` — `<purpose>:<subject>`, where the subject may be an address. */
  | "identifier"
  /** Every `*_at` column: ISO-8601 UTC, fixed width, ordered lexicographically. */
  | "timestamp"
  /** Every flag. */
  | "boolean"
  /** Custom number fields. */
  | "number"
  /** `last_used_step`. */
  | "bigint"
  /** Names, URLs, user agents, IPs, JSON, ciphertexts, password hashes, public keys. */
  | "text"

/** A MySQL string column: a bound, or `text`, and the character set it is compared in. */
interface MysqlString {
  readonly length: number | undefined
  readonly charset: MysqlCharset
}

/** The two character sets this library declares a column in. */
type MysqlCharset = "ascii" | "utf8mb4"

/**
 * The binary collation of each character set — the whole point of naming a
 * character set at all.
 *
 * **Gotchas**
 *
 * `utf8mb4_0900_bin` rather than `utf8mb4_bin`, because `utf8mb4_bin` is a *PAD
 * SPACE* collation: MySQL ignores trailing spaces in every comparison made in
 * it, so `"sub"` and `"sub "` are one value in an equality test and one row in a
 * unique index — while PostgreSQL and SQLite compare the bytes and see two. That
 * reaches `accounts.account_id`, which holds an identity provider's `sub`
 * verbatim, and every custom string user field. `utf8mb4_0900_bin` is *NO PAD*
 * and compares exactly, and it has been available since MySQL 8.0.17, inside
 * this library's 8.0.19 floor.
 *
 * `ascii_bin` is PAD SPACE too and has no NO PAD sibling; the roles it carries —
 * ids, digests, ISO-8601 timestamps, base64url credential ids — have alphabets
 * this library generates and none of them contains a space, let alone a trailing
 * one.
 */
const collations: Record<MysqlCharset, string> = {
  ascii: "ascii_bin",
  utf8mb4: "utf8mb4_0900_bin"
}

interface RoleType {
  readonly pg: string
  readonly sqlite: string
  readonly mysql: string | MysqlString
}

/**
 * The column-role table of `db-expansion-plan.md`, as the one value that
 * decides a DDL type.
 */
const roleTypes: Record<ColumnRole, RoleType> = {
  id: { pg: "text", sqlite: "text", mysql: { length: 64, charset: "ascii" } },
  hash: { pg: "text", sqlite: "text", mysql: { length: 64, charset: "ascii" } },
  // WebAuthn allows a raw credential id of up to 1023 bytes, and what this
  // library stores is its base64url spelling — 1364 characters at that size, not
  // the 1023 the specification states. The bound is that plus a little, and it
  // is ascii, so the unique index over it is 1368 bytes and well inside InnoDB's
  // 3072-byte key limit.
  credential: { pg: "text", sqlite: "text", mysql: { length: 1368, charset: "ascii" } },
  email: { pg: "text", sqlite: "text", mysql: { length: 320, charset: "utf8mb4" } },
  identity: { pg: "text", sqlite: "text", mysql: { length: 255, charset: "utf8mb4" } },
  identifier: { pg: "text", sqlite: "text", mysql: { length: 400, charset: "utf8mb4" } },
  timestamp: { pg: "text", sqlite: "text", mysql: { length: 32, charset: "ascii" } },
  text: { pg: "text", sqlite: "text", mysql: { length: undefined, charset: "utf8mb4" } },
  boolean: { pg: "boolean", sqlite: "integer", mysql: "boolean" },
  number: { pg: "double precision", sqlite: "real", mysql: "double" },
  bigint: { pg: "bigint", sqlite: "integer", mysql: "bigint" }
}

/**
 * The DDL type a column role is declared as on this dialect.
 *
 * **Details**
 *
 * On MySQL *every* string role carries its character set and a binary
 * collation — the unbounded `text` role as much as the bounded `varchar` ones —
 * so that an id, a digest, an OAuth identity or a display name compares exactly
 * the way it does on PostgreSQL and SQLite rather than however the server was
 * installed. `ascii_bin` is for the roles whose alphabet this library controls
 * (ids, digests, ISO timestamps, base64url credential ids);
 * `utf8mb4_0900_bin` is for the roles that hold something a person typed.
 *
 * A bare `text` would inherit the *database's* default character set rather than
 * the column's role, and a database created `CHARACTER SET latin1` — which a
 * legacy server's configuration still does — refuses a name with an emoji in it
 * with error 1366. Stating the character set on the column is what makes this
 * schema independent of how the database was created.
 *
 * **When to use**
 *
 * In migrations, as the type of every column this library creates.
 * `options.length` overrides the MySQL bound, which is what a custom string user
 * field needs — those are `varchar(255)` rather than `text`, because a
 * deployment may index one.
 *
 * **Gotchas**
 *
 * `options.length` is read on MySQL only, and only for the string roles: the
 * boolean, number and bigint roles have no width to override and ignore it.
 *
 * @internal
 */
export const columnType = (
  dialect: Dialect,
  role: ColumnRole,
  options?: { readonly length?: number | undefined }
): string => {
  const type = roleTypes[role]
  if (dialect === "pg") return type.pg
  if (dialect === "sqlite") return type.sqlite
  if (typeof type.mysql === "string") return type.mysql
  const length = options?.length ?? type.mysql.length
  const charset = type.mysql.charset
  const collated = `CHARACTER SET ${charset} COLLATE ${collations[charset]}`
  return length === undefined ? `text ${collated}` : `varchar(${length}) ${collated}`
}
