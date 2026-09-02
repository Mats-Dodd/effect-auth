/**
 * The phone plugin's store and the table under it, on whichever database
 * `EFFECT_AUTH_TEST_DATABASE` names.
 *
 * **Details**
 *
 * One `layer()` block, so one database build: the schema cases and the
 * behaviour cases are statements about the same migrated table and have no
 * reason to each pay for one. Table, column and index names come from
 * {@link Database.TestDatabase}; the `is_nullable` and
 * `character_maximum_length` reads that used to be here are restated as
 * behaviour — a `NULL` the database refuses, a number too long for a bounded
 * column.
 */
import { assert, describe, it as plainIt, layer } from "@effect/vitest"
import { Effect, Layer, Option } from "effect"
import { SqlClient } from "effect/unstable/sql"
import { User } from "../../src/domain/Schema.js"
import { isUniqueViolation, UserStore } from "../../src/domain/Stores.js"
import { table as phoneMigrationsTable, phoneNumbersTable } from "../../src/phone/Migrations.js"
import * as PhoneBarrel from "../../src/phone/index.js"
import { PhoneStore } from "../../src/phone/Store.js"
import * as Database from "../../src/testing/Database.js"
import * as PhoneTest from "../../src/testing/PhoneTest.js"
import * as AuthTest from "../../src/testing/TestLayer.js"
import { testName, uniqueEmail } from "../fixtures.js"

/** The stores, plus the plugin's own table over the same database. */
const layerStores = PhoneTest.layerStore.pipe(Layer.provideMerge(AuthTest.layerStores))

let counter = 0
const uniqueNumber = (): string => `+1555${String(4000000 + counter++)}`

const createUser = Effect.fnUntraced(function* (label: string) {
  const users = yield* UserStore
  const row = yield* User.insert.makeEffect({
    name: testName,
    email: uniqueEmail(label),
    emailVerified: false,
    image: null
  })
  return yield* users.create(row)
})

/**
 * Whether the database refused the row — the behavioural form of every
 * `is_nullable` and `character_maximum_length` assertion this file used to make.
 */
const refuses = Effect.fnUntraced(function* (row: Record<string, unknown>) {
  const sql = yield* SqlClient.SqlClient
  const outcome = yield* Effect.result(sql`INSERT INTO ${sql(phoneNumbersTable)} ${sql.insert(row)}`)
  return outcome._tag === "Failure"
})

describe.sequential("phone/Store", () => {
  layer(layerStores)("phone/Store", (it) => {
    describe("the table the plugin owns", () => {
      it.effect("has exactly the four columns, and only the proof is optional", () =>
        Effect.gen(function* () {
          const database = yield* Database.TestDatabase
          const user = yield* createUser("store-columns")
          assert.deepStrictEqual([...(yield* database.columnNames(phoneNumbersTable))].sort(), [
            "created_at",
            "phone_e164",
            "user_id",
            "verified_at"
          ])

          // A row with a null there is a claim, not a proof — which is what
          // every read filters on, so it has to be allowed to be absent.
          const complete = {
            phone_e164: uniqueNumber(),
            user_id: user.id,
            verified_at: null,
            created_at: "2026-01-01T00:00:00.000Z"
          }
          assert.isFalse(yield* refuses(complete))

          // The other three are the row itself.
          for (const column of ["phone_e164", "user_id", "created_at"]) {
            const row = { ...complete, phone_e164: uniqueNumber(), user_id: user.id, [column]: null }
            assert.isTrue(yield* refuses(row), column)
          }
        })
      )

      it.effect("bounds the number and the holder, so MySQL can key them", () =>
        Effect.gen(function* () {
          const dialect = yield* Database.dialect
          // `phone_e164` is the key on pg and mysql and a unique column on
          // sqlite, and `user_id` is unique everywhere: MySQL refuses a key on
          // an unbounded column, so the table existing there at all is the
          // bound existing.
          assert.include(yield* (yield* Database.TestDatabase).tableNames, phoneNumbersTable)

          // And on MySQL the bound is a real one. Only MySQL has it:
          // `columnType` gives PostgreSQL and SQLite the unbounded `text` they
          // have always had. The length itself is not asserted — this says the
          // column is bounded, not by how much; the number lives in the README
          // beside the E.164 constraint that guarantees it.
          if (dialect === "mysql") {
            const user = yield* createUser("store-bounded")
            const row = {
              phone_e164: `+1${"5".repeat(64)}`,
              user_id: user.id,
              verified_at: null,
              created_at: "2026-01-01T00:00:00.000Z"
            }
            assert.isTrue(yield* refuses(row))
          }
        })
      )

      it.effect("records its migrations in a bookkeeping table of its own", () =>
        Effect.gen(function* () {
          const database = yield* Database.TestDatabase
          const names = yield* database.tableNames

          assert.include(names, phoneMigrationsTable)
          assert.include(names, "effect_auth_migrations")
          assert.notStrictEqual(phoneMigrationsTable, "effect_auth_migrations")
        })
      )

      it.effect("adds no column to any core table", () =>
        Effect.gen(function* () {
          const database = yield* Database.TestDatabase

          for (const table of ["users", "sessions", "accounts", "verifications"]) {
            const names = yield* database.columnNames(table)
            assert.isFalse(
              names.some((name) => name.includes("phone")),
              `${table} should carry no phone column`
            )
          }
        })
      )
    })

    describe("the two constraints that carry the rules", () => {
      it.effect("one account holds one number: a second claim replaces the first", () =>
        Effect.gen(function* () {
          const store = yield* PhoneStore
          const user = yield* createUser("store-replace")
          const first = uniqueNumber()
          const second = uniqueNumber()

          yield* store.claim({ phoneE164: first, userId: user.id })
          yield* store.claim({ phoneE164: second, userId: user.id })

          assert.isTrue(Option.isNone(yield* store.findByPhone(first)))
          const held = yield* store.findByUserId(user.id)
          assert.strictEqual(Option.getOrNull(held)?.phoneE164, second)
        })
      )

      it.effect("one number belongs to one account: the second claim is refused by the database", () =>
        Effect.gen(function* () {
          const store = yield* PhoneStore
          const owner = yield* createUser("store-owner")
          const other = yield* createUser("store-other")
          const number = uniqueNumber()

          yield* store.claim({ phoneE164: number, userId: owner.id })
          const outcome = yield* Effect.result(store.claim({ phoneE164: number, userId: other.id }))

          assert.strictEqual(outcome._tag, "Failure")
          if (outcome._tag !== "Failure") return
          assert.isTrue(isUniqueViolation(outcome.failure))
          // And the loser's own row was not left behind by the transaction.
          assert.isTrue(Option.isNone(yield* store.findByUserId(other.id)))
          assert.strictEqual(Option.getOrNull(yield* store.findByPhone(number))?.userId, owner.id)
        })
      )

      it.effect("a claim is verified the moment it is written", () =>
        Effect.gen(function* () {
          const store = yield* PhoneStore
          const user = yield* createUser("store-verified")
          const row = yield* store.claim({ phoneE164: uniqueNumber(), userId: user.id })
          assert.isNotNull(row.verifiedAt)
        })
      )

      it.effect("deleting the user takes the number with it", () =>
        Effect.gen(function* () {
          const store = yield* PhoneStore
          const users = yield* UserStore
          const user = yield* createUser("store-cascade")
          const number = uniqueNumber()

          yield* store.claim({ phoneE164: number, userId: user.id })
          assert.isTrue(yield* users.delete(user.id))
          assert.isTrue(Option.isNone(yield* store.findByPhone(number)))
        })
      )

      it.effect("deleteForUser answers how many rows went, and is safe twice", () =>
        Effect.gen(function* () {
          const store = yield* PhoneStore
          const user = yield* createUser("store-delete")
          yield* store.claim({ phoneE164: uniqueNumber(), userId: user.id })

          assert.strictEqual(yield* store.deleteForUser(user.id), 1)
          assert.strictEqual(yield* store.deleteForUser(user.id), 0)
        })
      )

      it.effect("a number nobody claimed is nobody's", () =>
        Effect.gen(function* () {
          const store = yield* PhoneStore
          const stranger = yield* createUser("store-stranger")
          assert.isTrue(Option.isNone(yield* store.findByPhone(uniqueNumber())))
          assert.isTrue(Option.isNone(yield* store.findByUserId(stranger.id)))
        })
      )
    })
  })

  // The barrel is the plugin's public surface, and a consumer reaches every one
  // of these through it. The two sub-modules are namespaced rather than flat
  // because `table` and `make` are names three modules here would each want.
  describe("the barrel", () => {
    plainIt("carries the two sub-modules under their own namespaces", () => {
      assert.strictEqual(PhoneBarrel.Store.PhoneStore, PhoneStore)
      assert.strictEqual(PhoneBarrel.Migrations.table, phoneMigrationsTable)
      assert.strictEqual(PhoneBarrel.Migrations.phoneNumbersTable, phoneNumbersTable)
      assert.isFunction(PhoneBarrel.E164.normalize)
    })

    plainIt("carries the service, the group and the seams flat", () => {
      for (const name of ["Phone", "SmsSender", "PhoneApiGroup", "handlers", "layer", "authenticators", "makeConfig"]) {
        assert.isTrue(name in PhoneBarrel, `${name} is not reachable from the phone barrel`)
      }
    })
  })
})
