/**
 * The six mutations a store cannot write portably, each written once.
 *
 * PostgreSQL and SQLite answer a write with the row it wrote: `INSERT …
 * RETURNING`, `UPDATE … RETURNING`, `DELETE … RETURNING`. MySQL has no general
 * `RETURNING`, so every one of those becomes two or three statements that have
 * to run on one connection, under one lock, or they are not the same operation
 * at all. That difference is the whole of this module, and it is the only place
 * in the library where it exists.
 *
 * Each helper takes the ambient `sql` client and the {@link Dialect.Dialect}
 * {@link Dialect.dialectOf} narrowed it to, and answers the same thing on every
 * dialect: the rows the mutation produced, undecoded, in the projection the
 * caller asked for. That shape is deliberate — it is exactly what
 * `SqlSchema.findOne`, `SqlSchema.findOneOption` and `SqlSchema.findAll` take as
 * their `execute`, so a store that was written around them keeps its decoders,
 * its request schemas and its error mapping untouched and swaps only the
 * statement.
 *
 * **Details — how the MySQL branches are built**
 *
 * Every multi-statement branch runs inside {@link atomically}, which reserves one
 * connection, propagates it, commits on success and rolls back on failure or
 * interruption — and which, for a caller already inside `WithAuthTransaction`,
 * is the caller's own transaction and nothing else. It deliberately does *not*
 * open a savepoint there: a MySQL deadlock rolls the whole transaction back, and
 * a savepoint taken inside it stops existing at that moment, so the
 * `ROLLBACK TO SAVEPOINT` that would follow is a defect over a statement that
 * had a perfectly good typed failure of its own. See {@link atomically}.
 *
 * A write that has to be read back never re-runs the caller's predicate. It
 * takes the row's key under `SELECT … FOR UPDATE` first, and then mutates and
 * reads by that key:
 *
 * ```text
 * SELECT <key> FROM <table> WHERE <predicate> FOR UPDATE   -- 0 rows → None
 * UPDATE <table> SET … WHERE <key>                          -- or DELETE
 * SELECT <columns> FROM <table> WHERE <key>
 * ```
 *
 * Two things fall out of that order, and both are why it is not "update, then
 * select":
 *
 * - A guarded update — `WHERE verified_at IS NULL`, `WHERE used_at IS NULL` —
 *   stops holding the moment the update lands. Selecting by the predicate
 *   afterwards would find nothing; selecting by the key alone would hand back a
 *   row the guard had refused. Evaluating the guard once, under the lock, is the
 *   only reading that matches `UPDATE … RETURNING`.
 * - `ROW_COUNT()` cannot stand in for it. MySQL counts rows *changed*, not rows
 *   matched, so an update that writes the values a row already held reports `0`
 *   — and `SessionStore.touch` under a frozen test clock does exactly that.
 *   `ROW_COUNT()` is used for one thing only, {@link deleteAndCount}, where
 *   "deleted" and "changed" are the same number.
 *
 * Because the row is locked by our own transaction from before the mutation
 * until after the read-back, no other connection can change it in between: the
 * row a MySQL write-then-read returns is the row that write produced.
 *
 * **Details — the two conditional upserts, worked**
 *
 * {@link upsertAndRead} exists for exactly two call sites. `src/username/Store.ts`
 * claims a name, rewriting the row only while the claimant already owns it:
 *
 * ```ts skip-type-checking
 * yield* Mutations.upsertAndRead({
 *   sql,
 *   dialect,
 *   table: "effect_auth_usernames",
 *   record: { username_key: key, username, user_id: userId, created_at: now },
 *   conflict: ["username_key"],
 *   update: ["username"],
 *   condition: (current, incoming) => sql`${current("user_id")} = ${incoming("user_id")}`,
 *   columns: cols,
 *   readBack: sql`username_key = ${key} AND user_id = ${userId}`
 * })
 * ```
 *
 * which is, on PostgreSQL and SQLite,
 *
 * ```sql
 * INSERT INTO "effect_auth_usernames" (…) VALUES (…)
 * ON CONFLICT ("username_key") DO UPDATE SET "username" = excluded."username"
 * WHERE "effect_auth_usernames"."user_id" = excluded."user_id"
 * RETURNING …
 * ```
 *
 * and on MySQL
 *
 * ```sql
 * INSERT INTO `effect_auth_usernames` (…) VALUES (…) AS new
 * ON DUPLICATE KEY UPDATE
 *   `username` = IF(`effect_auth_usernames`.`user_id` = new.`user_id`,
 *                   new.`username`,
 *                   `effect_auth_usernames`.`username`);
 * SELECT … FROM `effect_auth_usernames` WHERE username_key = ? AND user_id = ?
 * ```
 *
 * The read-back is the caller's, and it is what turns "the update did nothing"
 * into `None`: the row comes back only while the claimant owns it, which on
 * PostgreSQL is what the empty `RETURNING` says.
 *
 * `src/two-factor/Store.ts` writes a *pending* TOTP enrolment, replacing a
 * pending one and refusing to touch an active one:
 *
 * ```ts skip-type-checking
 * yield* Mutations.upsertAndRead({
 *   sql,
 *   dialect,
 *   table: "effect_auth_totp",
 *   record: {
 *     user_id: userId,
 *     secret_ciphertext: secret,
 *     created_at: now,
 *     last_used_step: null,
 *     verified_at: null
 *   },
 *   conflict: ["user_id"],
 *   update: ["secret_ciphertext", "created_at", "last_used_step", "verified_at"],
 *   condition: (current) => sql`${current("verified_at")} IS NULL`,
 *   columns: totpCols,
 *   readBack: sql`user_id = ${userId} AND verified_at IS NULL`
 * })
 * ```
 *
 * **Gotchas**
 *
 * Three things about MySQL's `ON DUPLICATE KEY UPDATE` that the two call sites
 * above are written around, and that a third one has to be written around too:
 *
 * 1. It fires on *any* unique key the insert collides with, not on the one named
 *    in `conflict` — which MySQL has no way to name. Both tables above are safe
 *    because a collision on their other unique key can only be the same row.
 * 2. Its assignments are evaluated left to right, and a later one sees what an
 *    earlier one wrote. So **list any column the condition reads last** in
 *    `update`: the TOTP example ends with `verified_at` for that reason, and
 *    every `IF` in it therefore tests the value the row had before the statement.
 * 3. `AS new` is MySQL 8.0.19 and later. The deprecated `VALUES()` form is not
 *    used.
 *
 * Not exported from the package: nothing here is part of the public API.
 *
 * @internal
 */
import { Effect, Option, Predicate, Schema } from "effect"
import type { SqlClient, SqlConnection, Statement } from "effect/unstable/sql"
import { SqlError, SqlSchema } from "effect/unstable/sql"
import type { Dialect } from "./Dialect.js"
import { identifier, lockClause } from "./Dialect.js"

// -----------------------------------------------------------------------------
// Shared pieces
// -----------------------------------------------------------------------------

/** What every helper takes: a client, the dialect it reported, and one table. */
interface Target {
  readonly sql: SqlClient.SqlClient
  readonly dialect: Dialect
  /** The table, escaped as an identifier — never interpolated as text. */
  readonly table: string
}

/** A helper that has to be able to name one row again after it has changed it. */
interface Keyed extends Target {
  /**
   * The columns that name a row uniquely, in the database's own spelling.
   *
   * On PostgreSQL and SQLite it is only what `RETURNING` projects when the
   * caller wants a count. On MySQL it is how the helper re-addresses the row it
   * locked, so it has to be a real unique key of the table — a primary key, or
   * the columns of a unique index.
   */
  readonly key: ReadonlyArray<string>
}

/**
 * One connection, one atomic sequence — and on MySQL, never a savepoint inside a
 * transaction somebody else opened.
 *
 * **Details**
 *
 * Outside a transaction this is `sql.withTransaction`: `BEGIN`, the statements,
 * `COMMIT`, on one reserved connection. That is what makes a MySQL
 * write-then-read one operation rather than two.
 *
 * Inside one — which is where most store calls happen, because the domain wraps
 * its multi-store workflows in `WithAuthTransaction` — the connection and the
 * transaction are already the caller's, and on MySQL this adds nothing to them.
 *
 * **Gotchas**
 *
 * `sql.withTransaction` nested is a *savepoint*, and on MySQL a savepoint does
 * not survive the thing it would be needed for. InnoDB answers a deadlock by
 * rolling back the entire transaction, not the statement, and every savepoint in
 * it goes with it — so the `ROLLBACK TO SAVEPOINT` Effect issues on the way out
 * fails, and because that rollback is `orDie`, a deadlock a caller could have
 * seen as a `DeadlockError` arrives as a defect with a second, misleading
 * message about a savepoint. Not opening one is the fix: the deadlock stays the
 * typed `SqlError` the store maps to a `PersistenceError`, and the caller's
 * transaction — which InnoDB has already rolled back — fails on the way out
 * instead of committing.
 *
 * PostgreSQL and SQLite keep the savepoint: `ROLLBACK TO SAVEPOINT` after a
 * serialization failure is valid on PostgreSQL, and SQLite serialises writers
 * rather than deadlocking them. Only MySQL's implicit rollback is the problem,
 * so only MySQL's branch differs.
 *
 * @internal
 */
export const atomically = <A, E, R>(
  sql: SqlClient.SqlClient,
  dialect: Dialect,
  effect: Effect.Effect<A, E, R>
): Effect.Effect<A, E | SqlError.SqlError, R> =>
  dialect === "mysql"
    ? Effect.flatMap(
        Effect.serviceOption(sql.transactionService),
        Option.match({ onNone: () => sql.withTransaction(effect), onSome: () => effect })
      )
    : sql.withTransaction(effect)

/**
 * Whether a driver failure is InnoDB breaking a deadlock.
 *
 * The single definition in this library: MySQL is the only supported dialect
 * that reports one, and every call site that retries reads it from here.
 *
 * @internal
 */
export const isDeadlock = (error: unknown): boolean =>
  SqlError.isSqlError(error) && Predicate.isTagged(error.reason, "DeadlockError")

/** Three attempts after the first is enough for a lock cycle to have cleared. */
const deadlockRetries = 3

/**
 * Runs an *idempotent* statement again when MySQL breaks a deadlock on it — but
 * only while it is the outermost transaction.
 *
 * **Details**
 *
 * A range delete over a hot index is the case: InnoDB takes next-key locks over
 * the range it scans, so two of them racing an insert into the same range can
 * form a cycle, and the loser is told to try again. Trying again is exactly
 * right for a delete, which has the same effect however many times it runs.
 *
 * **Gotchas**
 *
 * Only outermost. A deadlock rolls back the *whole* MySQL transaction, so a
 * retry inside one would run in autocommit against a transaction that no longer
 * exists — it would appear to succeed and commit on its own, which is worse than
 * the failure it was hiding. Inside a transaction the failure is reported, the
 * caller's transaction fails with it, and the retry belongs to whoever opened
 * that transaction. `src/sql/stores/Transaction.ts` proves the transaction is
 * still there before it commits, so a swallowed one cannot slip through either.
 *
 * @internal
 */
export const retryDeadlocks = <A, R>(
  sql: SqlClient.SqlClient,
  dialect: Dialect,
  effect: Effect.Effect<A, SqlError.SqlError, R>
): Effect.Effect<A, SqlError.SqlError, R> =>
  dialect !== "mysql"
    ? effect
    : Effect.flatMap(
        Effect.serviceOption(sql.transactionService),
        Option.match({
          onNone: () => Effect.retry(effect, { while: isDeadlock, times: deadlockRetries }),
          onSome: () => effect
        })
      )

/**
 * A key of no columns is `1=1`, which on the MySQL branches would delete or
 * rewrite the table. It is a defect in the caller and never a database's answer,
 * so it dies before it reaches a statement.
 */
const emptyKey = Effect.die(new Error("effect-auth: a mutation helper needs at least one key column"))

/** `<column> = <value>`, with the column escaped and the value bound. */
const equals = (sql: SqlClient.SqlClient, column: string, value: unknown): Statement.Fragment =>
  sql`${identifier(sql, column)} = ${value}`

/** The predicate that names one row, read out of a row the database handed back. */
const keyOf = (sql: SqlClient.SqlClient, key: ReadonlyArray<string>, row: SqlConnection.Row): Statement.Fragment =>
  sql.and(key.map((column) => equals(sql, column, row[column])))

/** The predicate that names every row of `rows`. */
const keysOf = (
  sql: SqlClient.SqlClient,
  key: ReadonlyArray<string>,
  rows: ReadonlyArray<SqlConnection.Row>
): Statement.Fragment => sql.or(rows.map((row) => keyOf(sql, key, row)))

/** One escaped name, as a fragment `sql.csv` and `sql.and` can take. */
const column = (sql: SqlClient.SqlClient, name: string): Statement.Fragment => sql`${identifier(sql, name)}`

/** `<a>,<b>` — the key columns, as a projection. */
const keyColumns = (sql: SqlClient.SqlClient, key: ReadonlyArray<string>): Statement.Fragment =>
  sql.csv(key.map((name) => column(sql, name)))

/**
 * The predicate that names the row an `INSERT` is about to write, taken from the
 * record itself.
 *
 * Ids in this library are generated by the application before the insert, so the
 * key is always known and MySQL never needs `LAST_INSERT_ID()`. A key column the
 * record does not carry is a defect in the caller, not something a database can
 * answer, so it dies rather than selecting on `NULL` and reporting "no row".
 */
const insertedKey = (
  sql: SqlClient.SqlClient,
  key: ReadonlyArray<string>,
  record: Record<string, unknown>
): Effect.Effect<Statement.Fragment> => {
  const missing = key.filter((name) => !Object.hasOwn(record, name))
  return missing.length === 0
    ? Effect.succeed(keyOf(sql, key, record))
    : Effect.die(new Error(`effect-auth: the key column(s) ${missing.join(", ")} are not in the row being written`))
}

/** `ROW_COUNT()`, as a number, whether the driver hands it over as one or as a string. */
const RowCount = Schema.Struct({ count: Schema.Union([Schema.Finite, Schema.FiniteFromString]) })

/**
 * How many rows the statement before this one touched, decoded through
 * `SqlSchema` rather than read off a driver result header.
 *
 * **Gotchas**
 *
 * Deliberately `unprepared`. `ROW_COUNT()` reports on the *previous statement*
 * on the connection, and a prepared read would put a `COM_STMT_PREPARE` between
 * the delete and the count on the first call of the process — one that a warm
 * statement cache would then skip, which is worse than either. A single
 * `COM_QUERY` has nothing in between, every time.
 */
const rowCount = (sql: SqlClient.SqlClient): Effect.Effect<number, SqlError.SqlError> => {
  const read = SqlSchema.findOne({
    Request: Schema.Struct({}),
    Result: RowCount,
    execute: () => sql`SELECT ROW_COUNT() AS "count"`.unprepared
  })
  return Effect.map(
    // A `ROW_COUNT()` that is not a number, or a `SELECT` of a constant that
    // returned nothing, is this library's bug rather than a failure a caller
    // could act on.
    Effect.catchTags(read({}), { SchemaError: Effect.die, NoSuchElementError: Effect.die }),
    (row) => row.count
  )
}

// -----------------------------------------------------------------------------
// Insert
// -----------------------------------------------------------------------------

/**
 * What {@link insertAndRead} writes.
 *
 * @internal
 */
export interface InsertAndRead extends Keyed {
  /** The row, in database column names, with every value already dialect-encoded. */
  readonly record: Record<string, unknown>
  /** The projection to answer with. */
  readonly columns: Statement.Fragment
}

/**
 * Inserts one row and answers with it.
 *
 * PostgreSQL and SQLite do it in one statement. MySQL inserts and then reads the
 * row back by `key`, on the transaction's connection — deterministic, because
 * the key was in the row this library just wrote.
 *
 * @internal
 */
export const insertAndRead = <A extends object = SqlConnection.Row>(
  options: InsertAndRead
): Effect.Effect<ReadonlyArray<A>, SqlError.SqlError> => {
  const { columns, dialect, record, sql } = options
  if (options.key.length === 0) return emptyKey
  const table = identifier(sql, options.table)
  if (dialect !== "mysql") {
    return sql<A>`INSERT INTO ${table} ${sql.insert(record)} RETURNING ${columns}`
  }
  return atomically(
    sql,
    dialect,
    Effect.gen(function* () {
      const where = yield* insertedKey(sql, options.key, record)
      yield* sql`INSERT INTO ${table} ${sql.insert(record)}`
      return yield* sql<A>`SELECT ${columns} FROM ${table} WHERE ${where}`
    })
  )
}

// -----------------------------------------------------------------------------
// Update
// -----------------------------------------------------------------------------

/**
 * What {@link updateAndRead} writes.
 *
 * @internal
 */
export interface UpdateAndRead extends Keyed {
  /** The assignments, in database column names, already dialect-encoded. */
  readonly set: Record<string, unknown>
  /** Which rows to write, and under what guard. */
  readonly where: Statement.Fragment
  /** The projection to answer with. */
  readonly columns: Statement.Fragment
}

/**
 * Updates the rows matching `where` and answers with them as they now are — no
 * rows when the predicate matched nothing, which every caller reads as "no such
 * row" or "the guard refused".
 *
 * **Gotchas**
 *
 * On MySQL the answer is ordered by the read-back rather than by the update.
 * Every call site in this library updates a single row addressed by its key, so
 * there is no order to preserve; a future multi-row caller that cares has to say
 * so in its own `ORDER BY`.
 *
 * @internal
 */
export const updateAndRead = <A extends object = SqlConnection.Row>(
  options: UpdateAndRead
): Effect.Effect<ReadonlyArray<A>, SqlError.SqlError> => {
  const { columns, dialect, key, set, sql, where } = options
  if (key.length === 0) return emptyKey
  const table = identifier(sql, options.table)
  if (dialect !== "mysql") {
    return sql<A>`UPDATE ${table} SET ${sql.update(set)} WHERE ${where} RETURNING ${columns}`
  }
  const lock = lockClause(sql, dialect)
  const empty: ReadonlyArray<A> = []
  return atomically(
    sql,
    dialect,
    Effect.gen(function* () {
      const locked = yield* sql`SELECT ${keyColumns(sql, key)} FROM ${table} WHERE ${where}${lock}`
      if (locked.length === 0) return empty
      const by = keysOf(sql, key, locked)
      yield* sql`UPDATE ${table} SET ${sql.update(set)} WHERE ${by}`
      return yield* sql<A>`SELECT ${columns} FROM ${table} WHERE ${by}`
    })
  )
}

// -----------------------------------------------------------------------------
// Delete
// -----------------------------------------------------------------------------

/**
 * What {@link deleteAndCount} deletes.
 *
 * @internal
 */
export interface DeleteAndCount extends Keyed {
  /** Which rows to delete. */
  readonly where: Statement.Fragment
}

/**
 * Deletes the rows matching `where` and answers how many went.
 *
 * PostgreSQL and SQLite count the ids `RETURNING` handed back. MySQL asks the
 * connection, in the same transaction: `ROW_COUNT()` after a `DELETE` is the
 * number of rows deleted, and it is decoded through `SqlSchema` so that no
 * driver-shaped value reaches a caller.
 *
 * **When to use**
 *
 * For a delete whose answer is a count *or* a boolean — `count > 0` is the same
 * statement, and a second helper for it would be a second thing to keep in step.
 *
 * @internal
 */
export const deleteAndCount = (options: DeleteAndCount): Effect.Effect<number, SqlError.SqlError> => {
  const { dialect, key, sql, where } = options
  if (key.length === 0) return emptyKey
  const table = identifier(sql, options.table)
  if (dialect !== "mysql") {
    return Effect.map(sql`DELETE FROM ${table} WHERE ${where} RETURNING ${keyColumns(sql, key)}`, (rows) => rows.length)
  }
  return atomically(
    sql,
    dialect,
    Effect.gen(function* () {
      yield* sql`DELETE FROM ${table} WHERE ${where}`
      return yield* rowCount(sql)
    })
  )
}

/**
 * What {@link deleteAndRead} and {@link consumeOne} delete.
 *
 * @internal
 */
export interface DeleteAndRead extends Keyed {
  /** Which rows to delete. */
  readonly where: Statement.Fragment
  /** The projection to answer with, read while the rows are still there. */
  readonly columns: Statement.Fragment
}

/**
 * Deletes the rows matching `where` and answers with them as they were.
 *
 * On MySQL: lock the matching rows, read them, delete them by their own key.
 *
 * **Gotchas**
 *
 * The locking read is a range scan under the caller's predicate, so on MySQL it
 * takes a next-key lock over whatever index serves that predicate. That is the
 * gap lock InnoDB is famous for, and two of these racing an `INSERT` into the
 * same range can deadlock. {@link consumeOne} — the one call site where that
 * race is the normal case rather than the exception — is written differently
 * for exactly that reason, and its documentation says how. A future caller of
 * this helper on a hot, contended range should read that note before using it.
 *
 * @internal
 */
export const deleteAndRead = <A extends object = SqlConnection.Row>(
  options: DeleteAndRead
): Effect.Effect<ReadonlyArray<A>, SqlError.SqlError> => {
  const { columns, dialect, key, sql, where } = options
  if (key.length === 0) return emptyKey
  const table = identifier(sql, options.table)
  if (dialect !== "mysql") {
    return sql<A>`DELETE FROM ${table} WHERE ${where} RETURNING ${columns}`
  }
  const lock = lockClause(sql, dialect)
  const empty: ReadonlyArray<A> = []
  return atomically(
    sql,
    dialect,
    Effect.gen(function* () {
      const locked = yield* sql`SELECT ${keyColumns(sql, key)} FROM ${table} WHERE ${where}${lock}`
      if (locked.length === 0) return empty
      const by = keysOf(sql, key, locked)
      const rows = yield* sql<A>`SELECT ${columns} FROM ${table} WHERE ${by}`
      yield* sql`DELETE FROM ${table} WHERE ${by}`
      return rows
    })
  )
}

/**
 * Claims one row: deletes it and answers with it, or answers with nothing and
 * deletes nothing.
 *
 * **Details**
 *
 * This is the exactly-once primitive, and `VerificationStore.consume` — the
 * statement behind every password-reset token, e-mail verification link and
 * OAuth state — is written on it. Two callers presenting the same value must not
 * both be handed the row.
 *
 * On PostgreSQL and SQLite that is one guarded `DELETE … RETURNING`: the winner
 * is decided by the storage engine and the loser sees nothing.
 *
 * MySQL takes three statements in one transaction, and the order of them is the
 * whole design:
 *
 * ```text
 * SELECT <key> FROM <table> WHERE <predicate> LIMIT 1          -- which row, if any
 * SELECT <columns> FROM <table> WHERE <key> AND <predicate> FOR UPDATE
 * DELETE FROM <table> WHERE <key>
 * ```
 *
 * The first read is *plain*: under `REPEATABLE READ` it is a consistent
 * non-locking read, so it takes no record lock and — the point — no gap lock on
 * the index range it scanned. The claim is decided by the second statement,
 * which is a locking read of a single row by its primary key: an exact match on
 * a unique index takes a record lock and never a gap, and being a locking read
 * it sees the row as it is now rather than as the snapshot had it. The loser of
 * a race blocks there, and when the winner commits it re-reads the guard and
 * finds the row gone, so it answers with nothing and deletes nothing.
 *
 * **Gotchas**
 *
 * Why not the obvious `SELECT … WHERE <predicate> LIMIT 1 FOR UPDATE`: that is a
 * *range* scan, and on MySQL a locking range scan takes a next-key lock over the
 * gap it scanned — including when it matches nothing. Two consumers of one
 * identifier racing an insert under the same identifier then deadlock, which is
 * not theoretical: it reproduced within three runs of a twelve-way storm against
 * MySQL 8 before this was written, as `ER_LOCK_DEADLOCK` on that very statement.
 * The plain read cannot deadlock because it takes nothing, and the locking read
 * that follows it holds exactly one primary-key record lock.
 *
 * The price is the snapshot the first read sees. A caller already inside a
 * `WithAuthTransaction` that has *already read something* is on that outer
 * transaction's snapshot, so a row another connection committed since then is
 * invisible to the first statement and the claim answers `None`. Every real
 * caller presents a value it was handed by an earlier, committed request, so the
 * window needs a token consumed before it was issued; and the failure is closed
 * — a claim that is not made — rather than a row handed out twice.
 *
 * `LIMIT 1` makes MySQL claim exactly one row where PostgreSQL and SQLite would
 * delete every row the predicate matched. The predicates this is used with carry
 * a high-entropy digest, so a second matching row is a hash collision rather
 * than a case; the singular reading is the one the contract is stated in.
 *
 * @internal
 */
export const consumeOne = <A extends object = SqlConnection.Row>(
  options: DeleteAndRead
): Effect.Effect<ReadonlyArray<A>, SqlError.SqlError> => {
  const { columns, dialect, key, sql, where } = options
  if (key.length === 0) return emptyKey
  const table = identifier(sql, options.table)
  if (dialect !== "mysql") {
    return sql<A>`DELETE FROM ${table} WHERE ${where} RETURNING ${columns}`
  }
  const lock = lockClause(sql, dialect)
  const empty: ReadonlyArray<A> = []
  return atomically(
    sql,
    dialect,
    Effect.gen(function* () {
      const candidate = yield* sql`SELECT ${keyColumns(sql, key)} FROM ${table} WHERE ${where} LIMIT 1`
      const first = candidate[0]
      if (first === undefined) return empty
      // The guard is re-stated under the lock, parenthesised because it is the
      // caller's and may be a disjunction: the row this claims has to be one
      // that still satisfies it now, not one the snapshot liked.
      const by = sql.and([keyOf(sql, key, first), sql`(${where})`])
      const rows = yield* sql<A>`SELECT ${columns} FROM ${table} WHERE ${by}${lock}`
      if (rows.length === 0) return empty
      yield* sql`DELETE FROM ${table} WHERE ${keyOf(sql, key, first)}`
      return rows
    })
  )
}

// -----------------------------------------------------------------------------
// Conditional upsert
// -----------------------------------------------------------------------------

/**
 * A condition on a conflicting row, written once for both spellings.
 *
 * `current(column)` is the row that is already stored; `incoming(column)` is the
 * row that was offered — `excluded` on PostgreSQL and SQLite, the `AS new` row
 * alias on MySQL.
 *
 * @internal
 */
export type UpsertCondition = (
  current: (column: string) => Statement.Fragment,
  incoming: (column: string) => Statement.Fragment
) => Statement.Fragment

/**
 * What {@link upsertAndRead} writes.
 *
 * @internal
 */
export interface UpsertAndRead extends Target {
  /** The row to insert, in database column names, already dialect-encoded. */
  readonly record: Record<string, unknown>
  /** The unique key the insert is expected to collide on. PostgreSQL and SQLite only. */
  readonly conflict: ReadonlyArray<string>
  /**
   * The columns a conflicting row is rewritten with, from the row that was
   * offered.
   *
   * On MySQL the assignments are evaluated in this order and each sees what the
   * one before it wrote, so a column the condition reads goes last.
   */
  readonly update: ReadonlyArray<string>
  /** When a conflicting row may be rewritten. */
  readonly condition: UpsertCondition
  /** The projection to answer with. */
  readonly columns: Statement.Fragment
  /**
   * MySQL only: the predicate that reads back the row the caller now owns.
   *
   * MySQL cannot say whether its conditional assignment changed anything, so the
   * caller states what "it worked" looks like — `username_key = ? AND user_id =
   * ?`, `user_id = ? AND verified_at IS NULL` — and no row means the condition
   * held for somebody else, which is what an empty `RETURNING` means on the other
   * two dialects.
   */
  readonly readBack: Statement.Fragment
}

/**
 * Inserts a row, or rewrites the row it collides with while a condition holds,
 * and answers with the caller's row — or with nothing, when the condition did
 * not hold.
 *
 * The two call sites it exists for, and the MySQL hazards it is written around,
 * are worked through in this module's own documentation.
 *
 * @internal
 */
export const upsertAndRead = <A extends object = SqlConnection.Row>(
  options: UpsertAndRead
): Effect.Effect<ReadonlyArray<A>, SqlError.SqlError> => {
  const { columns, condition, dialect, record, sql, update } = options
  const table = identifier(sql, options.table)
  const current = (column: string): Statement.Fragment => sql`${table}.${identifier(sql, column)}`

  if (dialect !== "mysql") {
    const excluded = (column: string): Statement.Fragment => sql`excluded.${identifier(sql, column)}`
    const assignments = sql.csv(update.map((column) => sql`${identifier(sql, column)} = ${excluded(column)}`))
    return sql<A>`INSERT INTO ${table} ${sql.insert(record)}
      ON CONFLICT (${keyColumns(sql, options.conflict)}) DO UPDATE SET ${assignments}
      WHERE ${condition(current, excluded)}
      RETURNING ${columns}`
  }

  const incoming = (column: string): Statement.Fragment => sql`new.${identifier(sql, column)}`
  const guard = condition(current, incoming)
  const assignments = sql.csv(
    update.map((column) => sql`${identifier(sql, column)} = IF(${guard}, ${incoming(column)}, ${current(column)})`)
  )
  return atomically(
    sql,
    dialect,
    Effect.gen(function* () {
      yield* sql`INSERT INTO ${table} ${sql.insert(record)} AS new
        ON DUPLICATE KEY UPDATE ${assignments}`
      return yield* sql<A>`SELECT ${columns} FROM ${table} WHERE ${options.readBack}`
    })
  )
}
