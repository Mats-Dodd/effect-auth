/**
 * The username plugin's store, on whichever database `EFFECT_AUTH_TEST_DATABASE`
 * names.
 *
 * **Details**
 *
 * A claim is two writes in one transaction and it is the plugin's only
 * concurrent path, so this file is about what happens when several people reach
 * it at once — including the case a first deployment starts in, an empty table.
 * On MySQL that case is the one that used to deadlock: a claim that releases
 * nothing matches nothing, and a predicate that matches nothing takes a gap
 * lock every other claimant then wants to insert into.
 */
import { assert, describe, layer } from "@effect/vitest"
import { Effect, Layer, Option } from "effect"
import { User } from "../../src/domain/Schema.js"
import { UserStore } from "../../src/domain/Stores.js"
import * as Database from "../../src/testing/Database.js"
import * as AuthTest from "../../src/testing/TestLayer.js"
import * as UsernameMigrations from "../../src/username/Migrations.js"
import { layerUsernameStore, UsernameStore } from "../../src/username/Store.js"
import { testName, uniqueEmail } from "../fixtures.js"

/** The plugin's table and store over the same deployment the users live in. */
const testLayer = layerUsernameStore.pipe(
  Layer.provide(Layer.orDie(UsernameMigrations.layer)),
  Layer.provideMerge(AuthTest.layerStores)
)

let counter = 0
const uniqueKey = (): string => `ada${(counter += 1)}`

const createUser = Effect.fnUntraced(function* (label: string) {
  const users = yield* UserStore
  return yield* users.create(
    yield* User.insert.makeEffect({ name: testName, email: uniqueEmail(label), emailVerified: false, image: null })
  )
})

layer(testLayer)("username/Store", (it) => {
  // `describe.sequential` because one case resets the database and the block's
  // cases otherwise run concurrently — a reset would empty the table a sibling
  // was still filling.
  describe.sequential("claim, concurrently", () => {
    it.effect("lets twelve people take twelve names at once on a table that has never held one", () =>
      Effect.gen(function* () {
        const database = yield* Database.TestDatabase
        const store = yield* UsernameStore
        // The empty table is the case, so the block's other rows go first.
        yield* database.reset
        const users = yield* Effect.forEach(
          Array.from({ length: 12 }, (_, index) => index),
          (index) => createUser(`claim-storm-${index}`),
          { concurrency: "unbounded" }
        )
        const names = users.map(() => uniqueKey())
        const claimed = yield* Effect.forEach(
          users,
          (user, index) => store.claim({ usernameKey: names[index]!, username: names[index]!, userId: user.id }),
          { concurrency: "unbounded" }
        )
        assert.deepStrictEqual(claimed.map((row) => row.usernameKey).sort(), [...names].sort())
        for (const [index, user] of users.entries()) {
          const held = yield* store.findByUserId(user.id)
          assert.deepStrictEqual(
            Option.map(held, (row) => row.usernameKey),
            Option.some(names[index]!)
          )
        }
      })
    )

    it.effect("hands one name to exactly one of two people asking for it together", () =>
      Effect.gen(function* () {
        const store = yield* UsernameStore
        const first = yield* createUser("claim-race-a")
        const second = yield* createUser("claim-race-b")
        const name = uniqueKey()
        const outcomes = yield* Effect.forEach(
          [first, second],
          (user) => Effect.result(store.claim({ usernameKey: name, username: name, userId: user.id })),
          { concurrency: "unbounded" }
        )
        assert.strictEqual(outcomes.filter((outcome) => outcome._tag === "Success").length, 1)
        const refusals = outcomes.flatMap((outcome) => (outcome._tag === "Failure" ? [outcome.failure._tag] : []))
        assert.deepStrictEqual(refusals, ["UsernameTaken"])
      })
    )

    it.effect("leaves one person holding one name when they rename themselves twice at once", () =>
      Effect.gen(function* () {
        const store = yield* UsernameStore
        const user = yield* createUser("claim-rename")
        const first = uniqueKey()
        yield* store.claim({ usernameKey: first, username: first, userId: user.id })
        const [second, third] = [uniqueKey(), uniqueKey()]
        yield* Effect.forEach(
          [second, third],
          (name) => Effect.ignore(store.claim({ usernameKey: name, username: name, userId: user.id })),
          { concurrency: "unbounded" }
        )
        // Whichever landed last, the unique index on the holder is the promise:
        // one person, one name.
        const held = yield* store.findByUserId(user.id)
        assert.isTrue(Option.isSome(held))
        const remaining = yield* Effect.forEach([first, second, third], (name) => store.findByKey(name))
        assert.strictEqual(remaining.filter(Option.isSome).length, 1)
      })
    )
  })
})
