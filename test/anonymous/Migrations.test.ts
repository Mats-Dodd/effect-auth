/**
 * The anonymous plugin's schema, on whichever database
 * `EFFECT_AUTH_TEST_DATABASE` names.
 *
 * **Details**
 *
 * Table, column and index names come from {@link Database.TestDatabase}; no
 * catalog is read here. The `is_nullable` and `character_maximum_length`
 * assertions this file used to make are restated as behaviour — a `NULL` the
 * database refuses, and a table MySQL would not have created had its key been
 * unbounded.
 */
import { assert, describe, layer } from "@effect/vitest"
import { Effect } from "effect"
import { SqlClient } from "effect/unstable/sql"
import { migrations, table } from "../../src/anonymous/Migrations.js"
import { User } from "../../src/domain/Schema.js"
import { UserStore } from "../../src/domain/Stores.js"
import * as AnonymousTest from "../../src/testing/AnonymousTest.js"
import * as Database from "../../src/testing/Database.js"
import { testName, uniqueEmail } from "../fixtures.js"

const anonymous = "effect_auth_anonymous"

const now = "2026-01-01T00:00:00.000Z"

/** A visitor for the marker to point at, written through the store. */
const createUser = Effect.fnUntraced(function* (label: string) {
  const users = yield* UserStore
  return yield* users.create(
    yield* User.insert.makeEffect({ name: testName, email: uniqueEmail(label), emailVerified: false, image: null })
  )
})

/** Whether the database refused the marker — the behavioural form of `is_nullable`. */
const refuses = Effect.fnUntraced(function* (row: Record<string, unknown>) {
  const sql = yield* SqlClient.SqlClient
  const outcome = yield* Effect.result(sql`INSERT INTO ${sql(anonymous)} ${sql.insert(row)}`)
  return outcome._tag === "Failure"
})

describe.sequential("anonymous/Migrations", () => {
  layer(AnonymousTest.layer())("the plugin's own table", (it) => {
    it("numbers its migrations from 0001 in a bookkeeping table of its own", () => {
      assert.strictEqual(table, "effect_auth_anonymous_migrations")
      assert.deepStrictEqual(Object.keys(migrations), ["0001_create_anonymous"])
    })

    it.effect("creates effect_auth_anonymous as a marker keyed by the person", () =>
      Effect.gen(function* () {
        const database = yield* Database.TestDatabase

        // That the table exists at all is the bound on `user_id`: MySQL refuses
        // a key on an unbounded column, so an unbounded primary key here would
        // have failed the migration rather than produced a wider column.
        assert.include(yield* database.tableNames, anonymous)
        assert.deepStrictEqual([...(yield* database.columnNames(anonymous))].sort(), [
          "created_at",
          "last_seen_at",
          "user_id"
        ])
      })
    )

    it.effect("refuses a marker with either timestamp missing", () =>
      Effect.gen(function* () {
        const dialect = yield* Database.dialect
        const user = yield* createUser("anonymous-null")

        // Nothing here may be absent: the row's *existence* is the whole of the
        // fact it records, and the sweep reads both timestamps.
        for (const column of ["created_at", "last_seen_at"]) {
          assert.isTrue(
            yield* refuses({ user_id: user.id, created_at: now, last_seen_at: now, [column]: null }),
            column
          )
        }

        // SQLite — alone among the three — lets a NULL into a `PRIMARY KEY`
        // column that is not also declared `NOT NULL`.
        if (dialect !== "sqlite") {
          assert.isTrue(yield* refuses({ user_id: null, created_at: now, last_seen_at: now }))
        }
      })
    )

    it.effect("indexes what the sweep scans by", () =>
      Effect.gen(function* () {
        const database = yield* Database.TestDatabase
        // Timestamps are fixed-width ISO-8601, so the index is usable for the
        // range scan the sweep's predicate is. Asserted by name, per table: an
        // index a dialect quietly failed to create is a full table scan.
        assert.include(yield* database.indexNames(anonymous), "effect_auth_anonymous_last_seen_at_idx")
      })
    )

    it.effect("takes the marker with the person, so a deleted visitor is not still anonymous", () =>
      Effect.gen(function* () {
        const sql = yield* SqlClient.SqlClient
        const users = yield* UserStore
        const user = yield* createUser("anonymous-cascade")
        yield* sql`INSERT INTO ${sql(anonymous)} ${sql.insert({
          user_id: user.id,
          created_at: now,
          last_seen_at: now
        })}`

        assert.isTrue(yield* users.delete(user.id))

        // ON DELETE CASCADE — and on SQLite that only means anything with
        // `PRAGMA foreign_keys = ON`, so this is also where a provider that
        // forgot it would be caught.
        const left = yield* sql<{ readonly user_id: string }>`
          SELECT user_id FROM ${sql(anonymous)} WHERE user_id = ${user.id}`
        assert.strictEqual(left.length, 0)
      })
    )

    it.effect("adds no is_anonymous column to any core table", () =>
      Effect.gen(function* () {
        const database = yield* Database.TestDatabase
        // The decision phase 1 locked: a marker table, never a column on
        // `users`. Adoption is a DELETE, which no UPDATE on a shared row can be
        // rolled back around.
        for (const core of ["users", "sessions", "accounts", "verifications"]) {
          const names = yield* database.columnNames(core)
          assert.isFalse(
            names.some((name) => name.includes("anonymous")),
            `${core} has no anonymous column`
          )
          assert.isFalse(names.includes("is_anonymous"), `${core} has no is_anonymous column`)
        }
      })
    )
  })
})
