/**
 * A deployment's own user columns, through the SQL store.
 *
 * **Details**
 *
 * The store never sees the field map: its projection, its `INSERT` and its
 * `UPDATE` are derived from the model when the layer is built. What these tests
 * pin down is that the derivation is complete in both directions — a custom
 * column is written, read back, patched, carried through the session join — and
 * that the two rules the kernel promises hold at the storage boundary: a
 * `hidden` field never reaches a JSON encoding, and a row built by a caller that
 * knows nothing about the custom fields is still storable.
 */
import { assert, describe, it, layer } from "@effect/vitest"
import { DateTime, Duration, Effect, Option, Random, Schema } from "effect"
import { Session, User } from "../../src/domain/Schema.js"
import { sessionStoreOf, UserStore, userStoreOf } from "../../src/domain/Stores.js"
import { expectSome, testName, uniqueEmail } from "../fixtures.js"
import { layerStores, model } from "./model.js"

const users = userStoreOf(model)
const sessionStore = sessionStoreOf(model)

layer(layerStores)("fields/Store", (it) => {
  it.effect("round-trips a custom column", () =>
    Effect.gen(function* () {
      const store = yield* users
      const email = uniqueEmail("plan")
      const row = yield* model.makeInsert({
        name: testName,
        email,
        emailVerified: false,
        image: null,
        plan: "pro",
        apiSecret: "s3cret"
      })
      const created = yield* store.create(row)

      assert.strictEqual(created.plan, "pro")
      assert.strictEqual(created.apiSecret, "s3cret")
      assert.strictEqual(created.role, "user")
      assert.strictEqual(created.emailVerified, false)

      const found = yield* expectSome(yield* store.findByEmail(email), "the user was not found")
      assert.strictEqual(found.plan, "pro")
      assert.strictEqual(found.apiSecret, "s3cret")
    })
  )

  it.effect("fills a custom column in for a caller that builds the base row", () =>
    Effect.gen(function* () {
      // `UserStore` — the base-typed key — is what the OAuth flow and any plugin
      // holds. The row it can build has base fields and nothing else.
      const base = yield* UserStore
      const email = uniqueEmail("provisioned")
      const row = yield* User.insert.makeEffect({
        name: testName,
        email,
        emailVerified: true,
        image: null
      })
      yield* base.create(row)

      const store = yield* users
      const found = yield* expectSome(yield* store.findByEmail(email), "the user was not found")
      assert.strictEqual(found.plan, "free")
      assert.strictEqual(found.role, "user")
      assert.strictEqual(found.apiSecret, null)
    })
  )

  it.effect("patches one custom column and leaves the rest alone", () =>
    Effect.gen(function* () {
      const store = yield* users
      const email = uniqueEmail("patch")
      const created = yield* store.create(
        yield* model.makeInsert({
          name: testName,
          email,
          emailVerified: false,
          image: null,
          apiSecret: "keep-me"
        })
      )
      assert.strictEqual(created.plan, "free")

      const updated = yield* expectSome(yield* store.update(created.id, { plan: "pro" }), "the update matched no row")
      assert.strictEqual(updated.plan, "pro")
      assert.strictEqual(updated.apiSecret, "keep-me")
      assert.strictEqual(updated.name, testName)
      assert.isTrue(DateTime.isGreaterThanOrEqualTo(updated.updatedAt, created.updatedAt))
    })
  )

  it.effect("keeps a hidden field out of every JSON encoding", () =>
    Effect.gen(function* () {
      const store = yield* users
      const created = yield* store.create(
        yield* model.makeInsert({
          name: testName,
          email: uniqueEmail("hidden"),
          emailVerified: false,
          image: null,
          apiSecret: "never-on-the-wire"
        })
      )

      const encoded = yield* Schema.encodeEffect(model.json)(created)
      assert.notProperty(encoded, "apiSecret")
      assert.propertyVal(encoded, "plan", "free")
      assert.propertyVal(encoded, "role", "user")
      // The same projection as a string — what a response body would carry.
      const text = yield* Schema.encodeEffect(Schema.fromJsonString(model.json))(created)
      assert.notInclude(text, "never-on-the-wire")
    })
  )

  it.effect("carries the custom columns through the session join", () =>
    Effect.gen(function* () {
      const store = yield* users
      const sessions = yield* sessionStore
      const created = yield* store.create(
        yield* model.makeInsert({
          name: testName,
          email: uniqueEmail("join"),
          emailVerified: true,
          image: null,
          plan: "pro"
        })
      )

      const now = yield* DateTime.now
      const tokenHash = `hash-${(yield* Random.nextIntBetween(0, Number.MAX_SAFE_INTEGER)).toString(36)}`
      yield* sessions.create(
        yield* Session.insert.makeEffect({
          tokenHash,
          userId: created.id,
          expiresAt: DateTime.addDuration(now, Duration.days(1)),
          ipAddress: null,
          userAgent: null
        })
      )

      const found = yield* sessions.findByTokenHash(tokenHash)
      assert.isTrue(Option.isSome(found))
      const joined = yield* expectSome(found, "the session was not found")
      assert.strictEqual(joined.user.id, created.id)
      assert.strictEqual(joined.user.plan, "pro")
      assert.strictEqual(joined.user.emailVerified, true)
      assert.strictEqual(joined.user.apiSecret, null)
    })
  )

  it.effect("drops a value a client tries to put in a read-only field", () =>
    Effect.gen(function* () {
      const store = yield* users
      // `role` is not part of `jsonCreate`, so an excess key in a payload is
      // ignored on the way in and the model's default is written instead.
      const payload = yield* Schema.decodeUnknownEffect(model.jsonCreate)({
        name: testName,
        email: uniqueEmail("readonly"),
        image: null,
        plan: "pro",
        role: "admin"
      })
      assert.notProperty(payload, "role")

      const created = yield* store.create(yield* model.makeInsert({ ...payload, emailVerified: false }))
      assert.strictEqual(created.role, "user")
      assert.strictEqual(created.plan, "pro")
    })
  )
})

describe("fields/Store (model)", () => {
  it("names its custom columns and nothing else", () => {
    assert.deepStrictEqual(model.extraKeys, ["plan", "apiSecret", "role"])
  })

  it.effect("reports the custom fields' defaults, encoded", () =>
    Effect.map(model.extraDefaults, (defaults) => {
      assert.deepStrictEqual(defaults, { plan: "free", apiSecret: null, role: "user" })
    })
  )
})
