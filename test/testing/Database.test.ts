/**
 * The `TestDatabase` contract, on whichever backend the run is against.
 *
 * **Details**
 *
 * `reset`, `tableNames`, `columnNames` and `indexNames` are the four things a
 * test may ask a database beyond SQL, and the whole point of them is that the
 * answer does not depend on which database answered. This file is what holds
 * that: it builds two tables and an index with DDL all four backends accept,
 * and then asserts the same four answers on all four. Run it with
 * `EFFECT_AUTH_TEST_DATABASE` set to each of `pglite`, `sqlite`, `pg` and
 * `mysql`.
 *
 * It deliberately does not use `effect-auth`'s own migrations: the contract has
 * to be provable on a backend whose migrations are not ported yet, and a
 * failure here should say "the catalog is wrong", not "the schema is".
 */
import { assert, layer } from "@effect/vitest"
import { Effect, Layer } from "effect"
import { SqlClient } from "effect/unstable/sql"
import * as Database from "../../src/testing/Database.js"

/**
 * Two tables, a foreign key, a named index, and a bookkeeping table `reset`
 * must leave alone. `varchar(64)` is the one type all four accept as a key.
 */
const schema = Layer.effectDiscard(
  Effect.gen(function* () {
    const sql = yield* SqlClient.SqlClient
    yield* sql`CREATE TABLE parents (id varchar(64) PRIMARY KEY)`
    yield* sql`CREATE TABLE kids (
    id varchar(64) PRIMARY KEY,
    parent_id varchar(64) NOT NULL,
    CONSTRAINT kids_parent_fk FOREIGN KEY (parent_id) REFERENCES parents (id)
  )`
    yield* sql`CREATE INDEX kids_parent_idx ON kids (parent_id)`
    yield* sql`CREATE TABLE probe_migrations (id varchar(64) PRIMARY KEY)`
  })
).pipe(Layer.provideMerge(Database.fromConfig), Layer.orDie)

const rows = (table: string) =>
  Effect.gen(function* () {
    const sql = yield* SqlClient.SqlClient
    const result = yield* sql<{ readonly count: unknown }>`SELECT COUNT(*) AS "count" FROM ${sql(table)}`
    return Number(result[0]?.count ?? 0)
  })

const seed = Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient
  yield* sql`INSERT INTO parents (id) VALUES (${"p1"})`
  yield* sql`INSERT INTO kids (id, parent_id) VALUES (${"k1"}, ${"p1"})`
  yield* sql`INSERT INTO probe_migrations (id) VALUES (${"m1"})`
})

layer(schema)("testing/Database — the TestDatabase contract", (it) => {
  it.effect("names every table in this build, and nothing from another", () =>
    Effect.gen(function* () {
      const database = yield* Database.TestDatabase
      assert.deepStrictEqual(yield* database.tableNames, ["kids", "parents", "probe_migrations"])
    })
  )

  it.effect("names a table's columns in definition order", () =>
    Effect.gen(function* () {
      const database = yield* Database.TestDatabase
      assert.deepStrictEqual(yield* database.columnNames("kids"), ["id", "parent_id"])
    })
  )

  it.effect("names a table's indexes and leaves the primary key out", () =>
    Effect.gen(function* () {
      const database = yield* Database.TestDatabase
      // Every dialect indexes a primary key, under a name of its own choosing;
      // reporting it would make an index assertion unwritable.
      assert.deepStrictEqual(yield* database.indexNames("parents"), [])
      assert.deepStrictEqual(yield* database.indexNames("kids"), ["kids_parent_idx"])
    })
  )

  it.effect("empties the tables through a foreign key and keeps the bookkeeping", () =>
    Effect.gen(function* () {
      const database = yield* Database.TestDatabase
      yield* seed
      assert.strictEqual(yield* rows("kids"), 1)

      yield* database.reset

      // The child row goes even though the parent is deleted too: pg truncates
      // with CASCADE, SQLite defers its checks, MySQL suspends them.
      assert.strictEqual(yield* rows("parents"), 0)
      assert.strictEqual(yield* rows("kids"), 0)
      // Emptying this one would let a migration test pass against a schema that
      // was never built.
      assert.strictEqual(yield* rows("probe_migrations"), 1)
    })
  )

  it.effect("reports the dialect it is", () =>
    Effect.gen(function* () {
      const reported = yield* Database.dialect
      assert.include(["pg", "sqlite", "mysql"], reported)
    })
  )
})
