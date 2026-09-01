/**
 * The authenticator seam: how two contributors compose, what a deployment that
 * installed none answers, and what a plugin that appends to one it cannot see
 * gets.
 *
 * **Details**
 *
 * Everything here is an ordinary value over an ordinary `Context.Reference`,
 * so none of it needs a deployment. What is asserted is that `combine` is a
 * lawful monoid with `{}` as its identity — identity on both sides,
 * associativity, `list` concatenating in order and `revokeAll` summing — because
 * that is the whole contract a factor plugin writes against, and because the two
 * core decisions built on it (would `unlink` leave zero ways in; did reclaim
 * revoke every way in) are wrong in a security-relevant direction if a
 * contributor is ever silently dropped.
 *
 * The `Layer.updateService` checkpoint at the end is the same one
 * `test/domain/Hooks.test.ts` keeps: `append` is built on reading a reference
 * from the context a layer is being built in, and if that ever stopped resolving
 * the reference's default, appending to a deployment that installed nothing
 * would silently do nothing.
 */
import { assert, describe, it } from "@effect/vitest"
import { Context, DateTime, Effect, Layer } from "effect"
import type { AuthenticatorSummary, AuthenticatorsService } from "../../src/domain/Authenticators.js"
import {
  append,
  Authenticators,
  combine,
  layer as authenticatorsLayer,
  list,
  revokeAll
} from "../../src/domain/Authenticators.js"
import { UserId } from "../../src/domain/Schema.js"
import { PersistenceError } from "../../src/domain/Stores.js"

/** The set a layer built under a given composition actually ended up with. */
class Captured extends Context.Service<Captured, AuthenticatorsService>()(
  "effect-auth/test/domain/Authenticators.test/Captured"
) {}

const userId = UserId.make("0193f6f0-0000-7000-8000-000000000001")
const otherUserId = UserId.make("0193f6f0-0000-7000-8000-000000000002")

/** One summary of a kind, named after the contributor that answered it. */
const summary = (type: string, id: string): AuthenticatorSummary => ({
  type,
  id,
  name: null,
  verifiedAt: DateTime.makeUnsafe(0),
  lastUsedAt: null,
  signIn: true,
  secondFactor: true,
  restricted: false
})

/**
 * A contributor that answers `count` authenticators of its own kind and revokes
 * them, recording the order in which it was called.
 */
const contributor = (type: string, count: number, trace: Array<string> = []): AuthenticatorsService => ({
  list: (id) =>
    Effect.sync(() => {
      trace.push(`list:${type}:${id}`)
      return Array.from({ length: count }, (_, index) => summary(type, `${type}-${index}`))
    }),
  revokeAll: (id) =>
    Effect.sync(() => {
      trace.push(`revoke:${type}:${id}`)
      return count
    })
})

/** The types a contributor's `list` answered, in order. */
const typesOf = (rows: ReadonlyArray<AuthenticatorSummary>): ReadonlyArray<string> => rows.map((row) => row.type)

describe("domain/Authenticators", () => {
  describe("the reference", () => {
    it.effect("defaults to a set that contributes nothing", () =>
      Effect.gen(function* () {
        const installed = yield* Authenticators

        assert.deepStrictEqual(installed, {})
        // The default has neither member, and the two readers answer the empty
        // aggregate rather than requiring every call site to branch.
        assert.deepStrictEqual(yield* list(installed, userId), [])
        assert.strictEqual(yield* revokeAll(installed, userId), 0)
      })
    )
  })

  describe("combine", () => {
    it.effect("concatenates lists left to right", () =>
      Effect.gen(function* () {
        const trace: Array<string> = []
        const both = combine(contributor("passkey", 2, trace), contributor("totp", 1, trace))

        assert.deepStrictEqual(typesOf(yield* list(both, userId)), ["passkey", "passkey", "totp"])
        // Sequential and in order: `revokeAll` runs inside the caller's
        // transaction, so two contributors racing inside it is not something
        // either of them should have to think about.
        assert.deepStrictEqual(trace, [`list:passkey:${userId}`, `list:totp:${userId}`])
      })
    )

    it.effect("sums what each contributor revoked", () =>
      Effect.gen(function* () {
        const trace: Array<string> = []
        const both = combine(contributor("passkey", 2, trace), contributor("totp", 3, trace))

        assert.strictEqual(yield* revokeAll(both, userId), 5)
        assert.deepStrictEqual(trace, [`revoke:passkey:${userId}`, `revoke:totp:${userId}`])
      })
    )

    it.effect("passes the user through to every contributor", () =>
      Effect.gen(function* () {
        const trace: Array<string> = []
        const both = combine(contributor("passkey", 1, trace), contributor("totp", 1, trace))

        yield* list(both, otherUserId)

        assert.deepStrictEqual(trace, [`list:passkey:${otherUserId}`, `list:totp:${otherUserId}`])
      })
    )

    it("declares only the members at least one side had", () => {
      const listOnly: AuthenticatorsService = { list: () => Effect.succeed([]) }
      const revokeOnly: AuthenticatorsService = { revokeAll: () => Effect.succeed(1) }

      // "No revoke here" must not become "a revoke that removes nothing": a
      // caller that branches on absence can tell the two apart.
      assert.deepStrictEqual(Object.keys(combine(listOnly, {})), ["list"])
      assert.deepStrictEqual(Object.keys(combine({}, revokeOnly)), ["revokeAll"])
      assert.deepStrictEqual(Object.keys(combine(listOnly, revokeOnly)).sort(), ["list", "revokeAll"])
      assert.deepStrictEqual(Object.keys(combine({}, {})), [])
    })

    it.effect("has the empty set as its identity, on both sides", () =>
      Effect.gen(function* () {
        const one = contributor("passkey", 2)

        for (const composed of [combine({}, one), combine(one, {})]) {
          assert.deepStrictEqual(typesOf(yield* list(composed, userId)), ["passkey", "passkey"])
          assert.strictEqual(yield* revokeAll(composed, userId), 2)
        }
      })
    )

    it.effect("is associative", () =>
      Effect.gen(function* () {
        const a = contributor("passkey", 2)
        const b = contributor("totp", 1)
        const c = contributor("recovery-code", 4)

        const left = combine(combine(a, b), c)
        const right = combine(a, combine(b, c))

        assert.deepStrictEqual(typesOf(yield* list(left, userId)), typesOf(yield* list(right, userId)))
        assert.deepStrictEqual(typesOf(yield* list(left, userId)), [
          "passkey",
          "passkey",
          "totp",
          "recovery-code",
          "recovery-code",
          "recovery-code",
          "recovery-code"
        ])
        assert.strictEqual(yield* revokeAll(left, userId), yield* revokeAll(right, userId))
        assert.strictEqual(yield* revokeAll(left, userId), 7)
      })
    )

    it.effect("fails the whole aggregate when one contributor fails", () =>
      Effect.gen(function* () {
        const failing: AuthenticatorsService = {
          revokeAll: () => Effect.fail(PersistenceError.make({ operation: "PasskeyStore.deleteByUserId" }))
        }
        const both = combine(contributor("totp", 1), failing)

        const result = yield* Effect.result(revokeAll(both, userId))

        // A sweep that half-ran is a reclaim that reported success while
        // leaving a way in: the caller's transaction must see the failure.
        assert.isTrue(result._tag === "Failure")
      })
    )
  })

  describe("layers", () => {
    it.effect("layer installs a set, replacing whatever was there", () =>
      Effect.gen(function* () {
        const installed = yield* Effect.provide(
          Effect.flatMap(Authenticators, (service) => list(service, userId)),
          authenticatorsLayer(contributor("passkey", 1))
        )

        assert.deepStrictEqual(typesOf(installed), ["passkey"])
      })
    )

    it.effect("append adds to a deployment that installed nothing", () =>
      Effect.gen(function* () {
        const rows = yield* Effect.provide(
          Effect.flatMap(Authenticators, (service) => list(service, userId)),
          append(contributor("passkey", 1))
        )

        // The whole point of `append` resolving the reference's default: a
        // plugin cannot require the deployment to install an empty set first.
        assert.deepStrictEqual(typesOf(rows), ["passkey"])
      })
    )

    it.effect("append runs after whatever was already installed", () =>
      Effect.gen(function* () {
        const stack = append(contributor("totp", 1)).pipe(
          Layer.provideMerge(append(contributor("passkey", 1))),
          Layer.provideMerge(authenticatorsLayer(contributor("account", 1)))
        )

        const rows = yield* Effect.provide(
          Effect.flatMap(Authenticators, (service) => list(service, userId)),
          stack
        )

        assert.deepStrictEqual(typesOf(rows), ["account", "passkey", "totp"])
      })
    )

    it.effect("reads the reference when the consuming layer is built", () =>
      Effect.gen(function* () {
        // A checkpoint on `effect`, not on this library: `append` is
        // `Layer.effect` over a reference read, and a deployment that never
        // installed one has to resolve the default for that read to mean
        // anything.
        const captured = yield* Effect.provide(
          Captured,
          Layer.effect(
            Captured,
            Effect.map(Authenticators, (service) => service)
          ).pipe(Layer.provide(append(contributor("passkey", 1))))
        )

        assert.deepStrictEqual(typesOf(yield* list(captured, userId)), ["passkey"])
      })
    )
  })
})
