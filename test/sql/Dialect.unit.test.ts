import { MysqlClient } from "@effect/sql-mysql2"
import { PgliteClient } from "@effect/sql-pglite"
import { assert, describe, it as vitestIt, layer } from "@effect/vitest"
import { Effect, Exit, Stream } from "effect"
import { Reactivity } from "effect/unstable/reactivity"
import type { SqlConnection } from "effect/unstable/sql"
import { SqlClient, SqlError, Statement } from "effect/unstable/sql"
import * as Dialect from "../../src/sql/Dialect.js"
import * as Mutations from "../../src/sql/Mutations.js"
import * as Database from "../../src/testing/Database.js"

// -----------------------------------------------------------------------------
// A client that records rather than connects
// -----------------------------------------------------------------------------

/**
 * The three real compilers, so that what this file asserts is the text the
 * drivers themselves would send — not a hand-rolled approximation of it. MySQL
 * is not otherwise exercised on this machine: Wave B runs the mysql branches
 * against a real server, and these tests are what make them readable before then.
 */
const compilers = {
  pg: PgliteClient.makeCompiler(),
  sqlite: Statement.makeCompilerSqlite(),
  mysql: MysqlClient.makeCompiler()
} satisfies Record<Dialect.Dialect, Statement.Compiler>

const mssqlCompiler = Statement.makeCompiler({
  dialect: "mssql",
  placeholder: (index) => `@p${index}`,
  onIdentifier: Statement.defaultEscape(`"`),
  onCustom: (): readonly [string, ReadonlyArray<unknown>] => ["", []],
  onRecordUpdate: (): readonly [string, ReadonlyArray<unknown>] => ["", []]
})

/**
 * What a fake connection answers with: a plausible key row for every read, and a
 * count for the one statement that asks for one. It is enough for every
 * multi-statement branch to take its non-empty path and render the statements
 * that follow.
 */
const respond = (statement: string): ReadonlyArray<SqlConnection.Row> =>
  statement.includes("ROW_COUNT") ? [{ count: 2 }] : [{ id: "widget-1", user_id: "user-1", username_key: "ada" }]

const recorder = (
  compiler: Statement.Compiler
): Effect.Effect<
  { readonly sql: SqlClient.SqlClient; readonly statements: () => ReadonlyArray<string> },
  never,
  Reactivity.Reactivity
> =>
  Effect.gen(function* () {
    const log: Array<string> = []
    const run = (statement: string) =>
      Effect.sync(() => {
        log.push(statement.replace(/\s+/g, " ").trim())
        return respond(statement)
      })
    const connection: SqlConnection.Connection = {
      execute: (statement) => run(statement),
      executeRaw: (statement) => run(statement),
      executeUnprepared: (statement) => run(statement),
      executeStream: (statement) => Stream.unwrap(Effect.map(run(statement), Stream.fromIterable)),
      executeValues: (statement) => Effect.map(run(statement), (rows) => rows.map((row) => Object.values(row))),
      executeValuesUnprepared: (statement) =>
        Effect.map(run(statement), (rows) => rows.map((row) => Object.values(row)))
    }
    const sql = yield* SqlClient.make({
      acquirer: Effect.succeed(connection),
      compiler,
      spanAttributes: []
    })
    return { sql, statements: () => log }
  })

/** Runs `use` against a recording client of `dialect` and hands back what it sent. */
const rendered = (
  dialect: Dialect.Dialect,
  use: (sql: SqlClient.SqlClient, dialect: Dialect.Dialect) => Effect.Effect<unknown, SqlError.SqlError>
): Promise<ReadonlyArray<string>> =>
  Effect.gen(function* () {
    const { sql, statements } = yield* recorder(compilers[dialect])
    yield* Effect.orDie(use(sql, dialect))
    return statements()
  }).pipe(Effect.provide(Reactivity.layer), Effect.runPromise)

/**
 * The same, with the caller already inside a transaction — which is where a
 * store helper is called from most of the time, because the domain wraps its
 * multi-store workflows in `WithAuthTransaction`.
 */
const renderedNested = (
  dialect: Dialect.Dialect,
  use: (sql: SqlClient.SqlClient, dialect: Dialect.Dialect) => Effect.Effect<unknown, SqlError.SqlError>
): Promise<ReadonlyArray<string>> =>
  Effect.gen(function* () {
    const { sql, statements } = yield* recorder(compilers[dialect])
    yield* Effect.orDie(sql.withTransaction(use(sql, dialect)))
    return statements()
  }).pipe(Effect.provide(Reactivity.layer), Effect.runPromise)

const widgets = {
  table: "widgets",
  key: ["id"],
  columns: (sql: SqlClient.SqlClient) => sql.literal(`id, owner_id AS "ownerId", label`)
}

// -----------------------------------------------------------------------------
// The dialect itself
// -----------------------------------------------------------------------------

describe("sql/Dialect", () => {
  vitestIt.effect("narrows the client's dialect to the three that are supported", () =>
    Effect.gen(function* () {
      for (const dialect of ["pg", "sqlite", "mysql"] as const) {
        const { sql } = yield* recorder(compilers[dialect])
        assert.strictEqual(yield* Dialect.dialectOf(sql), dialect)
      }
    }).pipe(Effect.provide(Reactivity.layer))
  )

  vitestIt.effect("dies on a dialect it has never been run against, naming it", () =>
    Effect.gen(function* () {
      const { sql } = yield* recorder(mssqlCompiler)
      const exit = yield* Effect.exit(Dialect.dialectOf(sql))
      assert.isTrue(Exit.isFailure(exit))
      assert.include(String(exit), "mssql")
    }).pipe(Effect.provide(Reactivity.layer))
  )

  vitestIt.effect("escapes an identifier the way the dialect's own compiler does", () =>
    Effect.gen(function* () {
      const escaped: Record<string, string> = {}
      for (const dialect of ["pg", "sqlite", "mysql"] as const) {
        const { sql } = yield* recorder(compilers[dialect])
        escaped[dialect] = sql`SELECT 1 FROM ${Dialect.identifier(sql, "effect_auth_usernames")}`.compile()[0]
      }
      assert.strictEqual(escaped["pg"], `SELECT 1 FROM "effect_auth_usernames"`)
      assert.strictEqual(escaped["sqlite"], `SELECT 1 FROM "effect_auth_usernames"`)
      assert.strictEqual(escaped["mysql"], "SELECT 1 FROM `effect_auth_usernames`")
    }).pipe(Effect.provide(Reactivity.layer))
  )

  vitestIt.effect("locks a row where the dialect has a clause for it, and nowhere else", () =>
    Effect.gen(function* () {
      const clauses: Record<string, string> = {}
      for (const dialect of ["pg", "sqlite", "mysql"] as const) {
        const { sql } = yield* recorder(compilers[dialect])
        clauses[dialect] = sql`SELECT id FROM users${Dialect.lockClause(sql, dialect)}`.compile()[0]
      }
      assert.strictEqual(clauses["pg"], "SELECT id FROM users FOR UPDATE")
      assert.strictEqual(clauses["mysql"], "SELECT id FROM users FOR UPDATE")
      assert.strictEqual(clauses["sqlite"], "SELECT id FROM users")
    }).pipe(Effect.provide(Reactivity.layer))
  )

  vitestIt("stores a flag as the dialect stores one, and reads every stored form back", () => {
    assert.strictEqual(Dialect.booleanCodec("pg").encode(true), true)
    assert.strictEqual(Dialect.booleanCodec("pg").encode(false), false)
    assert.strictEqual(Dialect.booleanCodec("sqlite").encode(true), 1)
    assert.strictEqual(Dialect.booleanCodec("sqlite").encode(false), 0)
    assert.strictEqual(Dialect.booleanCodec("mysql").encode(true), 1)
    assert.strictEqual(Dialect.booleanCodec("mysql").encode(false), 0)

    for (const dialect of ["pg", "sqlite", "mysql"] as const) {
      const codec = Dialect.booleanCodec(dialect)
      assert.strictEqual(codec.decode(true), true)
      assert.strictEqual(codec.decode(1), true)
      assert.strictEqual(codec.decode(false), false)
      assert.strictEqual(codec.decode(0), false)
      assert.strictEqual(codec.decodeNullable(1), true)
      assert.strictEqual(codec.decodeNullable(0), false)
      // "not asked yet" is not "declined": a nullable flag keeps its absence.
      assert.strictEqual(codec.decodeNullable(null), null)
      assert.strictEqual(codec.decodeNullable(undefined), undefined)
    }
  })

  vitestIt("spells a DEFAULT flag the way the dialect's DDL takes one", () => {
    assert.strictEqual(Dialect.booleanLiteral("pg", true), "true")
    assert.strictEqual(Dialect.booleanLiteral("pg", false), "false")
    assert.strictEqual(Dialect.booleanLiteral("sqlite", true), "1")
    assert.strictEqual(Dialect.booleanLiteral("sqlite", false), "0")
    assert.strictEqual(Dialect.booleanLiteral("mysql", true), "1")
    assert.strictEqual(Dialect.booleanLiteral("mysql", false), "0")
  })

  vitestIt("gives every column role the type its dialect indexes", () => {
    // PostgreSQL and SQLite index unbounded text, so a string role is `text`
    // there and only the scalar roles differ.
    for (const role of ["id", "hash", "credential", "email", "identity", "identifier", "timestamp", "text"] as const) {
      assert.strictEqual(Dialect.columnType("pg", role), "text")
      assert.strictEqual(Dialect.columnType("sqlite", role), "text")
    }
    assert.strictEqual(Dialect.columnType("pg", "boolean"), "boolean")
    assert.strictEqual(Dialect.columnType("sqlite", "boolean"), "integer")
    assert.strictEqual(Dialect.columnType("pg", "number"), "double precision")
    assert.strictEqual(Dialect.columnType("sqlite", "number"), "real")
    assert.strictEqual(Dialect.columnType("pg", "bigint"), "bigint")
    assert.strictEqual(Dialect.columnType("sqlite", "bigint"), "integer")

    // MySQL: bounded, and never on the server's own character set or collation.
    assert.strictEqual(Dialect.columnType("mysql", "id"), "varchar(64) CHARACTER SET ascii COLLATE ascii_bin")
    assert.strictEqual(Dialect.columnType("mysql", "hash"), "varchar(64) CHARACTER SET ascii COLLATE ascii_bin")
    // 1023 raw bytes is WebAuthn's maximum credential id, which is 1364
    // base64url characters — the form this library stores. A bound of 1024
    // would refuse a long authenticator's key on MySQL and nowhere else.
    assert.strictEqual(Dialect.columnType("mysql", "credential"), "varchar(1368) CHARACTER SET ascii COLLATE ascii_bin")
    assert.strictEqual(Dialect.columnType("mysql", "timestamp"), "varchar(32) CHARACTER SET ascii COLLATE ascii_bin")
    // `utf8mb4_0900_bin`, never `utf8mb4_bin`: the latter is PAD SPACE, so a
    // trailing space would be invisible to both an equality test and a unique
    // index on MySQL alone.
    assert.strictEqual(
      Dialect.columnType("mysql", "email"),
      "varchar(320) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin"
    )
    assert.strictEqual(
      Dialect.columnType("mysql", "identity"),
      "varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin"
    )
    assert.strictEqual(
      Dialect.columnType("mysql", "identifier"),
      "varchar(400) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin"
    )
    assert.strictEqual(Dialect.columnType("mysql", "boolean"), "boolean")
    assert.strictEqual(Dialect.columnType("mysql", "number"), "double")
    assert.strictEqual(Dialect.columnType("mysql", "bigint"), "bigint")

    // `text` is unbounded until somebody says otherwise, which is what a custom
    // string user field does — but it still states its character set, because a
    // bare `text` inherits the database's and a `latin1` database would refuse
    // an emoji in a display name.
    assert.strictEqual(Dialect.columnType("mysql", "text"), "text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin")
    assert.strictEqual(
      Dialect.columnType("mysql", "text", { length: 255 }),
      "varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin"
    )
    assert.strictEqual(
      Dialect.columnType("mysql", "id", { length: 36 }),
      "varchar(36) CHARACTER SET ascii COLLATE ascii_bin"
    )
    // A length is a MySQL bound and nothing else.
    assert.strictEqual(Dialect.columnType("pg", "text", { length: 255 }), "text")
    assert.strictEqual(Dialect.columnType("mysql", "bigint", { length: 8 }), "bigint")
  })
})

// -----------------------------------------------------------------------------
// The statements the mutation helpers render
// -----------------------------------------------------------------------------

const insert = (sql: SqlClient.SqlClient, dialect: Dialect.Dialect) =>
  Mutations.insertAndRead({
    sql,
    dialect,
    table: widgets.table,
    key: widgets.key,
    record: { id: "widget-1", owner_id: "user-1", label: "spanner" },
    columns: widgets.columns(sql)
  })

const update = (sql: SqlClient.SqlClient, dialect: Dialect.Dialect) =>
  Mutations.updateAndRead({
    sql,
    dialect,
    table: widgets.table,
    key: widgets.key,
    set: { label: "wrench" },
    where: sql`id = ${"widget-1"} AND label IS NOT NULL`,
    columns: widgets.columns(sql)
  })

const count = (sql: SqlClient.SqlClient, dialect: Dialect.Dialect) =>
  Mutations.deleteAndCount({
    sql,
    dialect,
    table: widgets.table,
    key: widgets.key,
    where: sql`owner_id = ${"user-1"}`
  })

const consume = (sql: SqlClient.SqlClient, dialect: Dialect.Dialect) =>
  Mutations.consumeOne({
    sql,
    dialect,
    table: widgets.table,
    key: widgets.key,
    where: sql`label = ${"spanner"}`,
    columns: widgets.columns(sql)
  })

const remove = (sql: SqlClient.SqlClient, dialect: Dialect.Dialect) =>
  Mutations.deleteAndRead({
    sql,
    dialect,
    table: widgets.table,
    key: widgets.key,
    where: sql`owner_id = ${"user-1"}`,
    columns: widgets.columns(sql)
  })

/** The username claim, which is the call site `upsertAndRead` was shaped for. */
const claim = (sql: SqlClient.SqlClient, dialect: Dialect.Dialect) =>
  Mutations.upsertAndRead({
    sql,
    dialect,
    table: "effect_auth_usernames",
    record: { username_key: "ada", username: "Ada", user_id: "user-1", created_at: "2026-01-01T00:00:00.000Z" },
    conflict: ["username_key"],
    update: ["username"],
    condition: (current, incoming) => sql`${current("user_id")} = ${incoming("user_id")}`,
    columns: sql.literal(`username_key AS "usernameKey", username`),
    readBack: sql`username_key = ${"ada"} AND user_id = ${"user-1"}`
  })

describe("sql/Mutations — rendered statements", () => {
  vitestIt("writes one statement per mutation on PostgreSQL and SQLite", async () => {
    for (const dialect of ["pg", "sqlite"] as const) {
      const p = dialect === "pg"
      assert.deepStrictEqual(await rendered(dialect, insert), [
        `INSERT INTO "widgets" ("id","owner_id","label") VALUES (${p ? "$1,$2,$3" : "?,?,?"}) RETURNING id, owner_id AS "ownerId", label`
      ])
      assert.deepStrictEqual(await rendered(dialect, update), [
        `UPDATE "widgets" SET "label" = ${p ? "$1" : "?"} WHERE id = ${p ? "$2" : "?"} AND label IS NOT NULL RETURNING id, owner_id AS "ownerId", label`
      ])
      assert.deepStrictEqual(await rendered(dialect, count), [
        `DELETE FROM "widgets" WHERE owner_id = ${p ? "$1" : "?"} RETURNING "id"`
      ])
      assert.deepStrictEqual(await rendered(dialect, consume), [
        `DELETE FROM "widgets" WHERE label = ${p ? "$1" : "?"} RETURNING id, owner_id AS "ownerId", label`
      ])
      assert.deepStrictEqual(await rendered(dialect, remove), [
        `DELETE FROM "widgets" WHERE owner_id = ${p ? "$1" : "?"} RETURNING id, owner_id AS "ownerId", label`
      ])
      assert.deepStrictEqual(await rendered(dialect, claim), [
        `INSERT INTO "effect_auth_usernames" ("username_key","username","user_id","created_at") VALUES (${
          p ? "$1,$2,$3,$4" : "?,?,?,?"
        }) ON CONFLICT ("username_key") DO UPDATE SET "username" = excluded."username" WHERE "effect_auth_usernames"."user_id" = excluded."user_id" RETURNING username_key AS "usernameKey", username`
      ])
    }
  })

  vitestIt("writes MySQL's replacement for RETURNING, inside a transaction", async () => {
    assert.deepStrictEqual(await rendered("mysql", insert), [
      "BEGIN",
      "INSERT INTO `widgets` (`id`,`owner_id`,`label`) VALUES (?,?,?)",
      'SELECT id, owner_id AS "ownerId", label FROM `widgets` WHERE `id` = ?',
      "COMMIT"
    ])

    // The guard is evaluated once, under the lock, and the write and the
    // read-back both address the row it selected.
    assert.deepStrictEqual(await rendered("mysql", update), [
      "BEGIN",
      "SELECT `id` FROM `widgets` WHERE id = ? AND label IS NOT NULL FOR UPDATE",
      "UPDATE `widgets` SET `label` = ? WHERE `id` = ?",
      'SELECT id, owner_id AS "ownerId", label FROM `widgets` WHERE `id` = ?',
      "COMMIT"
    ])

    assert.deepStrictEqual(await rendered("mysql", count), [
      "BEGIN",
      "DELETE FROM `widgets` WHERE owner_id = ?",
      'SELECT ROW_COUNT() AS "count"',
      "COMMIT"
    ])

    // The exactly-once claim, and the one place the first read is deliberately
    // *not* a locking one: a `LIMIT 1 … FOR UPDATE` over the predicate would
    // take an InnoDB next-key lock on the range it scanned and deadlock against
    // a concurrent insert into the same range (reproduced on MySQL 8; see
    // `consumeOne`'s documentation). So the plain read picks the row, the
    // locking read by primary key re-states the guard and decides the claim,
    // and the delete addresses the key rather than the predicate.
    assert.deepStrictEqual(await rendered("mysql", consume), [
      "BEGIN",
      "SELECT `id` FROM `widgets` WHERE label = ? LIMIT 1",
      'SELECT id, owner_id AS "ownerId", label FROM `widgets` WHERE (`id` = ? AND (label = ?)) FOR UPDATE',
      "DELETE FROM `widgets` WHERE `id` = ?",
      "COMMIT"
    ])

    assert.deepStrictEqual(await rendered("mysql", remove), [
      "BEGIN",
      "SELECT `id` FROM `widgets` WHERE owner_id = ? FOR UPDATE",
      'SELECT id, owner_id AS "ownerId", label FROM `widgets` WHERE `id` = ?',
      "DELETE FROM `widgets` WHERE `id` = ?",
      "COMMIT"
    ])

    assert.deepStrictEqual(await rendered("mysql", claim), [
      "BEGIN",
      "INSERT INTO `effect_auth_usernames` (`username_key`,`username`,`user_id`,`created_at`) VALUES (?,?,?,?) AS new " +
        "ON DUPLICATE KEY UPDATE `username` = IF(`effect_auth_usernames`.`user_id` = new.`user_id`, new.`username`, `effect_auth_usernames`.`username`)",
      'SELECT username_key AS "usernameKey", username FROM `effect_auth_usernames` WHERE username_key = ? AND user_id = ?',
      "COMMIT"
    ])
  })

  vitestIt("takes no savepoint inside a transaction MySQL has already opened", async () => {
    // What `sql.withTransaction` does when it is nested, and what every MySQL
    // branch used to do: a savepoint, rolled back on the way out.
    assert.deepStrictEqual(await renderedNested("mysql", (sql) => sql.withTransaction(sql`SELECT 1`)), [
      "BEGIN",
      "SAVEPOINT effect_sql_1",
      "SELECT 1",
      "COMMIT"
    ])

    // A savepoint is worse than useless on MySQL: InnoDB answers a deadlock by
    // rolling back the whole transaction, savepoints and all, so the
    // `ROLLBACK TO SAVEPOINT` that follows fails — and Effect issues that
    // rollback with `orDie`, which turns a `DeadlockError` a store would have
    // reported as a `PersistenceError` into a defect about a savepoint. The
    // helpers therefore run on the caller's transaction and open nothing.
    assert.deepStrictEqual(await renderedNested("mysql", insert), [
      "BEGIN",
      "INSERT INTO `widgets` (`id`,`owner_id`,`label`) VALUES (?,?,?)",
      'SELECT id, owner_id AS "ownerId", label FROM `widgets` WHERE `id` = ?',
      "COMMIT"
    ])
    assert.deepStrictEqual(await renderedNested("mysql", consume), [
      "BEGIN",
      "SELECT `id` FROM `widgets` WHERE label = ? LIMIT 1",
      'SELECT id, owner_id AS "ownerId", label FROM `widgets` WHERE (`id` = ? AND (label = ?)) FOR UPDATE',
      "DELETE FROM `widgets` WHERE `id` = ?",
      "COMMIT"
    ])

    // PostgreSQL and SQLite write one statement either way, and where one of
    // them does open a nested transaction its savepoint is valid: `ROLLBACK TO
    // SAVEPOINT` after a serialization failure is what PostgreSQL is for.
    assert.deepStrictEqual(await renderedNested("pg", insert), [
      "BEGIN",
      `INSERT INTO "widgets" ("id","owner_id","label") VALUES ($1,$2,$3) RETURNING id, owner_id AS "ownerId", label`,
      "COMMIT"
    ])
  })

  vitestIt.effect("retries an idempotent statement through a deadlock, and only outside a transaction", () =>
    Effect.gen(function* () {
      const deadlock = SqlError.SqlError.make({
        reason: SqlError.DeadlockError.make({ cause: undefined, message: "Deadlock found", operation: "execute" })
      })
      assert.isTrue(Mutations.isDeadlock(deadlock))
      assert.isFalse(Mutations.isDeadlock(new Error("not a driver failure")))

      /** Fails with a deadlock on the first two attempts, then succeeds. */
      const flaky = () => {
        let attempts = 0
        return {
          attempts: () => attempts,
          effect: Effect.suspend(() => {
            attempts += 1
            return attempts > 2 ? Effect.succeed(attempts) : Effect.fail(deadlock)
          })
        }
      }

      const { sql } = yield* recorder(compilers.mysql)

      // Outermost: the delete runs again, and the caller never sees the
      // deadlock.
      const outer = flaky()
      assert.strictEqual(yield* Mutations.retryDeadlocks(sql, "mysql", outer.effect), 3)
      assert.strictEqual(outer.attempts(), 3)

      // Inside a transaction: reported once. InnoDB has rolled that transaction
      // back, so a second attempt would run in autocommit and commit itself.
      const nested = flaky()
      const inside = yield* Effect.exit(sql.withTransaction(Mutations.retryDeadlocks(sql, "mysql", nested.effect)))
      assert.isTrue(Exit.isFailure(inside))
      assert.strictEqual(nested.attempts(), 1)

      // PostgreSQL and SQLite do not report deadlocks on the statements this
      // guards, and their nested transactions recover through a savepoint, so
      // the helper is the identity there.
      const pg = flaky()
      assert.isTrue(Exit.isFailure(yield* Effect.exit(Mutations.retryDeadlocks(sql, "pg", pg.effect))))
      assert.strictEqual(pg.attempts(), 1)
    }).pipe(Effect.provide(Reactivity.layer))
  )

  vitestIt.effect("refuses a key that would name every row, and one the row does not carry", () =>
    Effect.gen(function* () {
      const { sql } = yield* recorder(compilers.mysql)

      // No key columns at all is `1=1`, which on the MySQL branches would
      // rewrite the table.
      const noKey = yield* Effect.exit(
        Mutations.deleteAndCount({
          sql,
          dialect: "mysql",
          table: widgets.table,
          key: [],
          where: sql`owner_id = ${"user-1"}`
        })
      )
      assert.isTrue(Exit.isFailure(noKey))
      assert.include(String(noKey), "key column")

      // A key the row being written does not carry would read back `NULL` and
      // report "no row" for a row that is in fact there.
      const absent = yield* Effect.exit(
        Mutations.insertAndRead({
          sql,
          dialect: "mysql",
          table: widgets.table,
          key: ["id"],
          record: { owner_id: "user-1" },
          columns: widgets.columns(sql)
        })
      )
      assert.isTrue(Exit.isFailure(absent))
      assert.include(String(absent), "id")
    }).pipe(Effect.provide(Reactivity.layer))
  )
})

// -----------------------------------------------------------------------------
// What the helpers do to a real PostgreSQL
// -----------------------------------------------------------------------------

const createWidgets = Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient
  yield* sql`CREATE TABLE IF NOT EXISTS widgets (
    id text PRIMARY KEY,
    owner_id text NOT NULL,
    label text,
    flag boolean NOT NULL DEFAULT false
  )`
})

interface Widget {
  readonly id: string
  readonly ownerId: string
  readonly label: string | null
}

/**
 * The pg branches, run for real.
 *
 * `Database.pglite` rather than `PgliteClient.layer()`: every `layer()` block in
 * this tree goes through the `Database.Provider` seam, so the block gets a
 * private schema and a `TestDatabase` beside its client exactly as every other
 * one does. It is deliberately *not* `Database.fromConfig` — these cases are
 * about the SQL PostgreSQL and SQLite render, and the MySQL branches are
 * asserted as text above and exercised against a real server by `Dialect.test.ts`
 * and the store contracts.
 */
layer(Database.pglite)("sql/Mutations (pg)", (it) => {
  const setUp = Effect.gen(function* () {
    const sql = yield* SqlClient.SqlClient
    yield* createWidgets
    return { sql, dialect: yield* Dialect.dialectOf(sql) }
  })

  const widget = (id: string, ownerId: string, label: string | null) => ({
    id,
    owner_id: ownerId,
    label
  })

  it.effect("inserts a row and answers with it", () =>
    Effect.gen(function* () {
      const { dialect, sql } = yield* setUp
      const rows = yield* Mutations.insertAndRead<Widget>({
        sql,
        dialect,
        table: widgets.table,
        key: widgets.key,
        record: widget("insert-1", "user-1", "spanner"),
        columns: widgets.columns(sql)
      })
      assert.deepStrictEqual(rows, [{ id: "insert-1", ownerId: "user-1", label: "spanner" }])
    })
  )

  it.effect("updates under a guard, and answers with nothing when the guard refuses", () =>
    Effect.gen(function* () {
      const { dialect, sql } = yield* setUp
      yield* Mutations.insertAndRead({
        sql,
        dialect,
        table: widgets.table,
        key: widgets.key,
        record: widget("update-1", "user-1", null),
        columns: widgets.columns(sql)
      })

      // The guard holds: an unlabelled widget may be labelled.
      const first = yield* Mutations.updateAndRead<Widget>({
        sql,
        dialect,
        table: widgets.table,
        key: widgets.key,
        set: { label: "wrench" },
        where: sql`id = ${"update-1"} AND label IS NULL`,
        columns: widgets.columns(sql)
      })
      assert.deepStrictEqual(first, [{ id: "update-1", ownerId: "user-1", label: "wrench" }])

      // It no longer does, and the answer is no row rather than the row.
      const second = yield* Mutations.updateAndRead<Widget>({
        sql,
        dialect,
        table: widgets.table,
        key: widgets.key,
        set: { label: "hammer" },
        where: sql`id = ${"update-1"} AND label IS NULL`,
        columns: widgets.columns(sql)
      })
      assert.deepStrictEqual(second, [])
    })
  )

  it.effect("counts the rows a delete removed", () =>
    Effect.gen(function* () {
      const { dialect, sql } = yield* setUp
      for (const id of ["count-1", "count-2", "count-3"]) {
        yield* Mutations.insertAndRead({
          sql,
          dialect,
          table: widgets.table,
          key: widgets.key,
          record: widget(id, "counted", null),
          columns: widgets.columns(sql)
        })
      }

      assert.strictEqual(
        yield* Mutations.deleteAndCount({
          sql,
          dialect,
          table: widgets.table,
          key: widgets.key,
          where: sql`owner_id = ${"counted"}`
        }),
        3
      )
      assert.strictEqual(
        yield* Mutations.deleteAndCount({
          sql,
          dialect,
          table: widgets.table,
          key: widgets.key,
          where: sql`owner_id = ${"counted"}`
        }),
        0
      )
    })
  )

  it.effect("hands the deleted rows back as they were", () =>
    Effect.gen(function* () {
      const { dialect, sql } = yield* setUp
      yield* Mutations.insertAndRead({
        sql,
        dialect,
        table: widgets.table,
        key: widgets.key,
        record: widget("delete-1", "deleted", "spanner"),
        columns: widgets.columns(sql)
      })

      const gone = yield* Mutations.deleteAndRead<Widget>({
        sql,
        dialect,
        table: widgets.table,
        key: widgets.key,
        where: sql`owner_id = ${"deleted"}`,
        columns: widgets.columns(sql)
      })
      assert.deepStrictEqual(gone, [{ id: "delete-1", ownerId: "deleted", label: "spanner" }])
      assert.deepStrictEqual(yield* sql`SELECT id FROM widgets WHERE owner_id = ${"deleted"}`, [])
    })
  )

  it.effect("claims a row exactly once", () =>
    Effect.gen(function* () {
      const { dialect, sql } = yield* setUp
      yield* Mutations.insertAndRead({
        sql,
        dialect,
        table: widgets.table,
        key: widgets.key,
        record: widget("consume-1", "user-1", "single-use"),
        columns: widgets.columns(sql)
      })

      const claimOnce = Mutations.consumeOne<Widget>({
        sql,
        dialect,
        table: widgets.table,
        key: widgets.key,
        where: sql`label = ${"single-use"}`,
        columns: widgets.columns(sql)
      })

      assert.deepStrictEqual(yield* claimOnce, [{ id: "consume-1", ownerId: "user-1", label: "single-use" }])
      assert.deepStrictEqual(yield* claimOnce, [])
    })
  )

  it.effect("rewrites the conflicting row only while the condition holds", () =>
    Effect.gen(function* () {
      const sql = yield* SqlClient.SqlClient
      const dialect = yield* Dialect.dialectOf(sql)
      yield* sql`CREATE TABLE IF NOT EXISTS names (
        username_key text PRIMARY KEY,
        username text NOT NULL,
        user_id text NOT NULL
      )`

      const cols = sql.literal(`username_key AS "usernameKey", username, user_id AS "userId"`)
      const claimFor = (userId: string, username: string) =>
        Mutations.upsertAndRead<{ readonly usernameKey: string; readonly username: string; readonly userId: string }>({
          sql,
          dialect,
          table: "names",
          record: { username_key: "ada", username, user_id: userId },
          conflict: ["username_key"],
          update: ["username"],
          condition: (current, incoming) => sql`${current("user_id")} = ${incoming("user_id")}`,
          columns: cols,
          readBack: sql`username_key = ${"ada"} AND user_id = ${userId}`
        })

      // Nobody holds it: the insert lands.
      assert.deepStrictEqual(yield* claimFor("user-1", "Ada"), [
        { usernameKey: "ada", username: "Ada", userId: "user-1" }
      ])

      // The holder restates it in another casing: the conditional update runs.
      assert.deepStrictEqual(yield* claimFor("user-1", "ADA"), [
        { usernameKey: "ada", username: "ADA", userId: "user-1" }
      ])

      // Somebody else asks for it: no row, and the stored row is untouched.
      assert.deepStrictEqual(yield* claimFor("user-2", "Ada L"), [])
      assert.deepStrictEqual(
        yield* sql`SELECT username, user_id AS "userId" FROM names WHERE username_key = ${"ada"}`,
        [{ username: "ADA", userId: "user-1" }]
      )
    })
  )

  it.effect("round-trips a flag through the dialect's own storage", () =>
    Effect.gen(function* () {
      const { dialect, sql } = yield* setUp
      const codec = Dialect.booleanCodec(dialect)
      yield* Mutations.insertAndRead({
        sql,
        dialect,
        table: widgets.table,
        key: widgets.key,
        record: { ...widget("flag-1", "user-1", null), flag: codec.encode(true) },
        columns: sql.literal("id")
      })

      const rows = yield* sql<{ readonly flag: unknown }>`SELECT flag FROM widgets WHERE id = ${"flag-1"}`
      assert.strictEqual(codec.decode(rows[0]?.flag), true)
    })
  )
})
