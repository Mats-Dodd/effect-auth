/**
 * The username plugin's schema, on whichever database `EFFECT_AUTH_TEST_DATABASE`
 * names.
 *
 * **Details**
 *
 * Nothing here reads a catalog: table, column and index names come from
 * {@link Database.TestDatabase}, which is where the `information_schema`,
 * `pg_catalog` and `PRAGMA` behind those answers live. The assertions that used to
 * read `is_nullable` and `character_maximum_length` are restated as behaviour —
 * a `NULL` the database refuses, a name too long for a bounded column — because
 * those are the same facts and they are true on all three dialects.
 */
import { assert, describe, layer } from "@effect/vitest"
import { Effect } from "effect"
import { SqlClient } from "effect/unstable/sql"
import { User } from "../../src/domain/Schema.js"
import { UserStore } from "../../src/domain/Stores.js"
import * as Database from "../../src/testing/Database.js"
import * as UsernameTest from "../../src/testing/UsernameTest.js"
import { migrations, table } from "../../src/username/Migrations.js"
import { testName, uniqueEmail } from "../fixtures.js"

const usernames = "effect_auth_usernames"

const now = "2026-01-01T00:00:00.000Z"

/** A person for the row to point at, written through the store. */
const createUser = Effect.fnUntraced(function* (label: string) {
  const users = yield* UserStore
  return yield* users.create(
    yield* User.insert.makeEffect({ name: testName, email: uniqueEmail(label), emailVerified: false, image: null })
  )
})

/**
 * Whether the database refused the row — the behavioural form of every
 * `is_nullable` and `character_maximum_length` assertion this file used to make.
 */
const refuses = Effect.fnUntraced(function* (row: Record<string, unknown>) {
  const sql = yield* SqlClient.SqlClient
  const outcome = yield* Effect.result(sql`INSERT INTO ${sql(usernames)} ${sql.insert(row)}`)
  return outcome._tag === "Failure"
})

let counter = 0
const uniqueName = (): string => `ada${(counter += 1)}`

describe.sequential("username/Migrations", () => {
  layer(UsernameTest.layer())("the plugin's own table", (it) => {
    it("numbers its migrations from 0001 in a bookkeeping table of its own", () => {
      // A plugin that merged into this library's record would be one
      // renumbering away from a migration that silently never runs.
      assert.strictEqual(table, "effect_auth_username_migrations")
      assert.deepStrictEqual(Object.keys(migrations), ["0001_create_usernames"])
    })

    it.effect("creates effect_auth_usernames with both PRECIS forms", () =>
      Effect.gen(function* () {
        const database = yield* Database.TestDatabase
        assert.deepStrictEqual([...(yield* database.columnNames(usernames))].sort(), [
          "created_at",
          "user_id",
          "username",
          "username_key"
        ])
      })
    )

    it.effect("refuses a row with no name, no holder and no timestamp", () =>
      Effect.gen(function* () {
        const dialect = yield* Database.dialect
        const user = yield* createUser("username-null")
        const complete = { username_key: uniqueName(), username: "Ada", user_id: user.id, created_at: now }

        // A username is never absent from its own row: the key is the identity,
        // and the display form is what the key was folded from.
        for (const column of ["username", "user_id", "created_at"]) {
          assert.isTrue(yield* refuses({ ...complete, username_key: uniqueName(), [column]: null }), column)
        }

        // The key column is the primary key, and SQLite — alone among the
        // three — lets a NULL into a `PRIMARY KEY` column that is not also
        // declared `NOT NULL`. Where the dialect can say it, it is said.
        if (dialect !== "sqlite") {
          assert.isTrue(yield* refuses({ ...complete, username_key: null }))
        }
      })
    )

    it.effect("bounds the key and the name, so MySQL can index them", () =>
      Effect.gen(function* () {
        const database = yield* Database.TestDatabase
        const dialect = yield* Database.dialect

        // An index is the proof MySQL cares about: `CREATE INDEX` on an
        // unbounded column is refused there outright, so the index existing is
        // the bound existing.
        assert.include(yield* database.indexNames(usernames), "effect_auth_usernames_user_id_unique")

        // And on MySQL the bound is a real one. Only MySQL has it: `columnType`
        // gives PostgreSQL and SQLite the unbounded `text` they have always had,
        // because neither needs a length to index a column. The length itself is
        // deliberately not asserted — this says the column is bounded, not by how
        // much; the numbers live in the README beside the PRECIS constraint that
        // guarantees them.
        if (dialect === "mysql") {
          const user = yield* createUser("username-long")
          const long = "x".repeat(1024)
          assert.isTrue(yield* refuses({ username_key: long, username: long, user_id: user.id, created_at: now }))
        }
      })
    )

    it.effect("makes the key the identity and the holder unique", () =>
      Effect.gen(function* () {
        const first = yield* createUser("username-key-first")
        const second = yield* createUser("username-key-second")
        const key = uniqueName()

        assert.isFalse(yield* refuses({ username_key: key, username: "Ada", user_id: first.id, created_at: now }))
        // One name, one holder…
        assert.isTrue(yield* refuses({ username_key: key, username: "Ada", user_id: second.id, created_at: now }))
        // …and one holder, one name — the conflict target `set` upserts on.
        assert.isTrue(
          yield* refuses({ username_key: uniqueName(), username: "Ada", user_id: first.id, created_at: now })
        )
      })
    )

    it.effect("takes the row with the person, so a deleted user leaves no name behind", () =>
      Effect.gen(function* () {
        const sql = yield* SqlClient.SqlClient
        const users = yield* UserStore
        const user = yield* createUser("username-cascade")
        const key = uniqueName()
        yield* sql`INSERT INTO ${sql(usernames)} ${sql.insert({
          username_key: key,
          username: "Ada",
          user_id: user.id,
          created_at: now
        })}`

        assert.isTrue(yield* users.delete(user.id))

        // ON DELETE CASCADE, not a dangling row a later claim would collide
        // with: the name is free again the moment the person is gone. On SQLite
        // that is only true with `PRAGMA foreign_keys = ON`, so this is also
        // where a provider that forgot it would be caught.
        const left = yield* sql<{ readonly username_key: string }>`
          SELECT username_key FROM ${sql(usernames)} WHERE username_key = ${key}`
        assert.strictEqual(left.length, 0)
      })
    )

    it.effect("adds no column to any core table", () =>
      Effect.gen(function* () {
        const database = yield* Database.TestDatabase
        // The one rule a plugin may not break.
        for (const core of ["users", "sessions", "accounts", "verifications"]) {
          const names = yield* database.columnNames(core)
          assert.isFalse(
            names.some((name) => name.includes("username")),
            `${core} has no username column`
          )
        }
      })
    )
  })
})
