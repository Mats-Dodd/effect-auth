import { assert, describe, it as plainIt, layer } from "@effect/vitest"
import { Effect, Layer, Option, Schema } from "effect"
import { SqlClient, SqlSchema } from "effect/unstable/sql"
import { User } from "../../src/domain/Schema.js"
import { isUniqueViolation, UserStore } from "../../src/domain/Stores.js"
import { table as phoneMigrationsTable, phoneNumbersTable } from "../../src/phone/Migrations.js"
import * as PhoneBarrel from "../../src/phone/index.js"
import { PhoneStore } from "../../src/phone/Store.js"
import * as PhoneTest from "../../src/testing/PhoneTest.js"
import * as AuthTest from "../../src/testing/TestLayer.js"
import { testName, uniqueEmail } from "../fixtures.js"

/** The stores, plus the plugin's own table over the same database. */
const layerStores = PhoneTest.layerStore.pipe(Layer.provideMerge(AuthTest.layerStores))

let counter = 0
const uniqueNumber = (): string => `+1555${String(4000000 + counter++)}`

const Column = Schema.Struct({
  column_name: Schema.String,
  data_type: Schema.String,
  is_nullable: Schema.String,
  character_maximum_length: Schema.NullOr(Schema.Finite)
})

const Name = Schema.Struct({ name: Schema.String })

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

describe.sequential("phone/Store", () => {
  layer(layerStores)("the table the plugin owns", (it) => {
    it.effect("has exactly the four columns, bounded where they are keys", () =>
      Effect.gen(function* () {
        const sql = yield* SqlClient.SqlClient
        const columns = yield* SqlSchema.findAll({
          Request: Schema.String,
          Result: Column,
          execute: (table) =>
            sql`SELECT column_name, data_type, is_nullable, character_maximum_length
              FROM information_schema.columns WHERE table_name = ${table} ORDER BY column_name`
        })(phoneNumbersTable)

        assert.deepStrictEqual(
          columns.map((column) => column.column_name),
          ["created_at", "phone_e164", "user_id", "verified_at"]
        )
        const byName = new Map(columns.map((column) => [column.column_name, column]))
        // Bounded varchar for the two keys, so the MySQL port stays mechanical.
        assert.strictEqual(byName.get("phone_e164")?.character_maximum_length, 16)
        assert.strictEqual(byName.get("user_id")?.character_maximum_length, 36)
        // The proof is nullable and everything else is not.
        assert.strictEqual(byName.get("verified_at")?.is_nullable, "YES")
        assert.strictEqual(byName.get("phone_e164")?.is_nullable, "NO")
        assert.strictEqual(byName.get("user_id")?.is_nullable, "NO")
        assert.strictEqual(byName.get("created_at")?.is_nullable, "NO")
      })
    )

    it.effect("records its migrations in a bookkeeping table of its own", () =>
      Effect.gen(function* () {
        const sql = yield* SqlClient.SqlClient
        const tables = yield* SqlSchema.findAll({
          Request: Schema.Void,
          Result: Schema.Struct({ table_name: Schema.String }),
          execute: () =>
            sql`SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name`
        })(undefined)
        const names = tables.map((row) => row.table_name)

        assert.include(names, phoneMigrationsTable)
        assert.include(names, "effect_auth_migrations")
        assert.notStrictEqual(phoneMigrationsTable, "effect_auth_migrations")
      })
    )

    it.effect("adds no column to any core table", () =>
      Effect.gen(function* () {
        const sql = yield* SqlClient.SqlClient
        const read = SqlSchema.findAll({
          Request: Schema.String,
          Result: Name,
          execute: (table) =>
            sql`SELECT column_name AS "name" FROM information_schema.columns WHERE table_name = ${table}`
        })

        for (const table of ["users", "sessions", "accounts", "verifications"]) {
          const names = (yield* read(table)).map((row) => row.name)
          assert.isFalse(
            names.some((name) => name.includes("phone")),
            `${table} should carry no phone column`
          )
        }
      })
    )
  })

  layer(layerStores)("the two constraints that carry the rules", (it) => {
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
