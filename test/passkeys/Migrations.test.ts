/**
 * The passkey plugin's schema, on whichever database `EFFECT_AUTH_TEST_DATABASE`
 * names.
 *
 * **Details**
 *
 * Table, column and index names come from {@link Database.TestDatabase}; no
 * catalog is read here. The `is_nullable` assertions this file used to make are
 * restated as behaviour — the two columns a credential may leave out, and the
 * eleven it may not — because that is the same fact on all three dialects, and
 * because it also proves the DEFAULTs do not quietly swallow an explicit NULL.
 */
import { assert, describe, layer } from "@effect/vitest"
import { Effect } from "effect"
import { SqlClient } from "effect/unstable/sql"
import { User } from "../../src/domain/Schema.js"
import { UserStore } from "../../src/domain/Stores.js"
import { migrations, table } from "../../src/passkeys/Migrations.js"
import { booleanCodec } from "../../src/sql/Dialect.js"
import * as Database from "../../src/testing/Database.js"
import * as PasskeysTest from "../../src/testing/PasskeysTest.js"
import { testName, uniqueEmail } from "../fixtures.js"

const passkeys = "effect_auth_passkeys"
const passkeyUsers = "effect_auth_passkey_users"

const now = "2026-01-01T00:00:00.000Z"

let counter = 0
const unique = (label: string): string => `${label}-${(counter += 1)}`

/** A person for the credential to belong to, written through the store. */
const createUser = Effect.fnUntraced(function* (label: string) {
  const users = yield* UserStore
  return yield* users.create(
    yield* User.insert.makeEffect({ name: testName, email: uniqueEmail(label), emailVerified: false, image: null })
  )
})

/** Whether the database refused the row — the behavioural form of `is_nullable`. */
const refuses = Effect.fnUntraced(function* (into: string, row: Record<string, unknown>) {
  const sql = yield* SqlClient.SqlClient
  const outcome = yield* Effect.result(sql`INSERT INTO ${sql(into)} ${sql.insert(row)}`)
  return outcome._tag === "Failure"
})

/** Every column of a credential, filled — the row the NULL cases spoil one field of. */
const credential = Effect.fnUntraced(function* (userId: string) {
  const dialect = yield* Database.dialect
  const flag = booleanCodec(dialect).encode(false)
  return {
    id: unique("pk"),
    user_id: userId,
    credential_id: unique("cred"),
    public_key: "cHVibGlj",
    sign_count: 0,
    transports: "[]",
    aaguid: "00000000-0000-0000-0000-000000000000",
    backup_eligible: flag,
    backed_up: flag,
    uv_initialised: flag,
    name: "laptop",
    created_at: now,
    last_used_at: now
  }
})

describe.sequential("passkeys/Migrations", () => {
  layer(PasskeysTest.layer())("the plugin's own tables", (it) => {
    it("numbers its migrations from 0001 in a bookkeeping table of its own", () => {
      // A plugin that merged into this library's record would be one
      // renumbering away from a migration that silently never runs.
      assert.strictEqual(table, "effect_auth_passkey_migrations")
      assert.deepStrictEqual(Object.keys(migrations), ["0001_create_passkeys", "0002_create_passkey_users"])
    })

    it.effect("creates effect_auth_passkeys with every column the model reads", () =>
      Effect.gen(function* () {
        const database = yield* Database.TestDatabase
        assert.deepStrictEqual([...(yield* database.columnNames(passkeys))].sort(), [
          "aaguid",
          "backed_up",
          "backup_eligible",
          "created_at",
          "credential_id",
          "id",
          "last_used_at",
          "name",
          "public_key",
          "sign_count",
          "transports",
          "user_id",
          "uv_initialised"
        ])
      })
    )

    it.effect("lets a credential leave out its name and its last use, and nothing else", () =>
      Effect.gen(function* () {
        const dialect = yield* Database.dialect
        const user = yield* createUser("passkey-null")
        const complete = yield* credential(user.id)

        // Exactly two things a credential may not have: a name, and a last use.
        for (const column of ["name", "last_used_at"]) {
          const row = { ...(yield* credential(user.id)), [column]: null }
          assert.isFalse(yield* refuses(passkeys, row), column)
        }

        // The other ten are required — including the four that carry a DEFAULT,
        // which is only reached by a column left out, never by an explicit NULL.
        const required = Object.keys(complete).filter(
          (column) => column !== "name" && column !== "last_used_at" && column !== "id"
        )
        for (const column of required) {
          const row = { ...(yield* credential(user.id)), [column]: null }
          assert.isTrue(yield* refuses(passkeys, row), column)
        }

        // `id` is the primary key, and SQLite — alone among the three — lets a
        // NULL into a `PRIMARY KEY` column not also declared `NOT NULL`.
        if (dialect !== "sqlite") {
          assert.isTrue(yield* refuses(passkeys, { ...(yield* credential(user.id)), id: null }))
        }
      })
    )

    it.effect("creates effect_auth_passkey_users, whose whole purpose is the handle", () =>
      Effect.gen(function* () {
        const database = yield* Database.TestDatabase
        const user = yield* createUser("passkey-handle")
        assert.deepStrictEqual([...(yield* database.columnNames(passkeyUsers))].sort(), ["handle", "user_id"])

        // Neither half is optional: a row with no handle is a row that answers
        // no discoverable sign-in.
        assert.isTrue(yield* refuses(passkeyUsers, { user_id: user.id, handle: null }))
        assert.isFalse(yield* refuses(passkeyUsers, { user_id: user.id, handle: unique("handle") }))
      })
    )

    it.effect("makes a credential id unique across the whole table, not per user", () =>
      Effect.gen(function* () {
        const database = yield* Database.TestDatabase
        const first = yield* createUser("passkey-shared-first")
        const second = yield* createUser("passkey-shared-second")

        // By name — an index a dialect quietly failed to create is a full table
        // scan on the sign-in hot path, and on MySQL it is also the proof that
        // `credential_id` is bounded, since a key on an unbounded column is
        // refused there outright.
        const present = yield* database.indexNames(passkeys)
        for (const name of ["effect_auth_passkeys_credential_id_unique", "effect_auth_passkeys_user_id_idx"]) {
          assert.include(present, name)
        }
        assert.include(yield* database.indexNames(passkeyUsers), "effect_auth_passkey_users_handle_unique")

        // And the rule the unique index carries: the same key registered to two
        // accounts would make a discoverable sign-in ambiguous.
        const shared = unique("cred-shared")
        const mine = { ...(yield* credential(first.id)), credential_id: shared }
        assert.isFalse(yield* refuses(passkeys, mine))
        assert.isTrue(yield* refuses(passkeys, { ...(yield* credential(second.id)), credential_id: shared }))
      })
    )

    it.effect("takes both rows with the person", () =>
      Effect.gen(function* () {
        const sql = yield* SqlClient.SqlClient
        const users = yield* UserStore
        const user = yield* createUser("passkey-cascade")
        yield* sql`INSERT INTO ${sql(passkeys)} ${sql.insert(yield* credential(user.id))}`
        yield* sql`INSERT INTO ${sql(passkeyUsers)} ${sql.insert({ user_id: user.id, handle: unique("handle") })}`

        assert.isTrue(yield* users.delete(user.id))

        // ON DELETE CASCADE — and on SQLite that only means anything with
        // `PRAGMA foreign_keys = ON`.
        const left = yield* sql<{ readonly id: string }>`
          SELECT id FROM ${sql(passkeys)} WHERE user_id = ${user.id}`
        const handles = yield* sql<{ readonly handle: string }>`
          SELECT handle FROM ${sql(passkeyUsers)} WHERE user_id = ${user.id}`
        assert.strictEqual(left.length, 0)
        assert.strictEqual(handles.length, 0)
      })
    )

    it.effect("adds no column to any core table", () =>
      Effect.gen(function* () {
        const database = yield* Database.TestDatabase
        // The one rule a plugin may not break. `users`, `sessions`, `accounts`
        // and `verifications` are this library's, and a passkey lives in
        // neither of them.
        for (const core of ["users", "sessions", "accounts", "verifications"]) {
          const names = yield* database.columnNames(core)
          assert.isFalse(
            names.some((name) => name.includes("passkey")),
            `${core} has no passkey column`
          )
          assert.isFalse(
            names.some((name) => name.includes("credential_id")),
            `${core} has no credential column`
          )
        }
      })
    )
  })
})
