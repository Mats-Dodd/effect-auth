/**
 * The hook kernel: how two hook sets compose, how a plugin adds to a set it
 * cannot see, and what `Users.provision` does with whatever it is handed.
 *
 * **Details**
 *
 * Most of this file needs no deployment at all — `combine`, `layer` and
 * `append` are ordinary values over an ordinary `Context.Reference`, and the
 * composition rules they encode (chain left to right, first refusal wins, an
 * appended set never shadows the one already installed) are the whole contract
 * a plugin author writes against.
 *
 * The `Layer.updateService` block below is a *checkpoint* rather than a
 * behavioural test: `append` is built on reading a reference from the context a
 * layer is being built in, and if that did not resolve the reference's default
 * when nothing provided one, appending to a deployment with no hooks would
 * silently do nothing. It is asserted here so that a change in `effect` breaks a
 * test rather than a deployment.
 */
import { assert, describe, it, layer } from "@effect/vitest"
import { Context, Effect, Layer, Option } from "effect"
import type { AuthHooksService, ProvisionSource } from "../../src/domain/Hooks.js"
import { append, AuthHooks, combine, hooksOf, layer as hooksLayer, PolicyRefused } from "../../src/domain/Hooks.js"
import type { UserInsertOf } from "../../src/domain/Schema.js"
import { baseUserModel } from "../../src/domain/Schema.js"
import { UserStore } from "../../src/domain/Stores.js"
import { Users } from "../../src/domain/Users.js"
import { AuthTest } from "../../src/testing/index.js"
import { expectSome, testName, uniqueEmail } from "../fixtures.js"

/** The source every test here provisions with, unless it is testing the source. */
const testSource: ProvisionSource = { _tag: "Plugin", plugin: "test" }

/** A candidate row, built the way every provisioning flow builds one. */
const candidateFor = (email: string): Effect.Effect<UserInsertOf<{}>> =>
  baseUserModel.makeInsert({ name: testName, email, emailVerified: false, image: null })

/**
 * A hook set that appends `label` to `trace` and lets the operation through.
 *
 * `beforeUserCreate` also rewrites the name, so a chain's *order* is readable
 * off the row it produced and not only off the trace it left.
 */
const recording = (trace: Array<string>, label: string): AuthHooksService => ({
  beforeUserCreate: ({ candidate }) =>
    Effect.sync(() => {
      trace.push(`before:${label}`)
      return { ...candidate, name: `${candidate.name}/${label}` }
    }),
  afterUserCreate: () => Effect.sync(() => void trace.push(`after:${label}`)),
  beforeUserDelete: () => Effect.sync(() => void trace.push(`delete:${label}`))
})

/** A hook set that refuses everything, naming itself in the code. */
const refusing = (trace: Array<string>, label: string): AuthHooksService => ({
  beforeUserCreate: () =>
    Effect.suspend(() => {
      trace.push(`before:${label}`)
      return Effect.fail(new PolicyRefused({ code: label }))
    }),
  beforeUserDelete: () =>
    Effect.suspend(() => {
      trace.push(`delete:${label}`)
      return Effect.fail(new PolicyRefused({ code: label }))
    })
})

/** The hooks a layer built under a given composition actually ends up with. */
class Installed extends Context.Service<Installed, AuthHooksService>()("test/InstalledHooks") {}

/**
 * A layer that copies whatever `AuthHooks` resolves to at *build* time — which
 * is exactly how the domain services read it.
 */
const installed: Layer.Layer<Installed> = Layer.effect(Installed, AuthHooks)

/** Builds `composition` and answers the hook set it left in the reference. */
const resolve = (composition: Layer.Layer<never>): Effect.Effect<AuthHooksService> =>
  Effect.provide(Effect.map(Installed, (hooks): AuthHooksService => hooks), installed.pipe(Layer.provide(composition)))

/** Unwraps an optional hook member, failing the test when the composition dropped it. */
const declared = <A>(member: A | undefined, name: string): Effect.Effect<A> =>
  member === undefined ? Effect.sync(() => assert.fail(`the composed set should declare ${name}`)) : Effect.succeed(member)

/** The `beforeUserCreate` of a composed set, which the composition must have declared. */
const beforeCreateOf = (hooks: AuthHooksService) => declared(hooks.beforeUserCreate, "beforeUserCreate")

describe("domain/Hooks", () => {
  // ---------------------------------------------------------------------------
  // combine
  // ---------------------------------------------------------------------------

  it("leaves a member absent when neither side declared it", () => {
    assert.deepStrictEqual(combine({}, {}), {})
    // `{}` is the reference's default, so it has to be a true identity: a
    // combined set that answered with six no-op functions would turn "nobody
    // installed a hook" into "somebody installed a hook that does nothing".
    const only: AuthHooksService = { beforeUserDelete: () => Effect.void }
    assert.strictEqual(combine(only, {}).beforeUserDelete, only.beforeUserDelete)
    assert.strictEqual(combine({}, only).beforeUserDelete, only.beforeUserDelete)
    assert.isUndefined(combine(only, {}).beforeUserCreate)
  })

  it.effect("chains beforeUserCreate left to right, each seeing the previous rewrite", () =>
    Effect.gen(function*() {
      const trace: Array<string> = []
      const combined = combine(recording(trace, "one"), recording(trace, "two"))
      const candidate = yield* candidateFor("chain@example.com")

      const beforeCreate = yield* beforeCreateOf(combined)
      const rewritten = yield* beforeCreate({ candidate, source: testSource })

      assert.deepStrictEqual(trace, ["before:one", "before:two"])
      // The second hook was handed what the first answered with, not the
      // original: the suffixes are in the order the hooks ran.
      assert.strictEqual(rewritten.name, `${testName}/one/two`)
    }))

  it.effect("sequences afterUserCreate and the veto members in the same order", () =>
    Effect.gen(function*() {
      const trace: Array<string> = []
      const combined = combine(recording(trace, "one"), recording(trace, "two"))
      const user = yield* baseUserModel.decodeRow({
        id: "0193f6f0-0000-7000-8000-0000000000aa",
        name: testName,
        email: "sequence@example.com",
        emailVerified: false,
        image: null,
        createdAt: "2024-01-01T00:00:00.000Z",
        updatedAt: "2024-01-01T00:00:00.000Z"
      })

      const after = yield* declared(combined.afterUserCreate, "afterUserCreate")
      const beforeDelete = yield* declared(combined.beforeUserDelete, "beforeUserDelete")
      yield* after({ user, source: testSource })
      yield* beforeDelete({ user })

      assert.deepStrictEqual(trace, ["after:one", "after:two", "delete:one", "delete:two"])
    }))

  it.effect("stops at the first refusal, whichever side it came from", () =>
    Effect.gen(function*() {
      const trace: Array<string> = []
      const candidate = yield* candidateFor("refused@example.com")

      const firstRefuses = yield* beforeCreateOf(combine(refusing(trace, "one"), recording(trace, "two")))
      const refused = yield* Effect.flip(firstRefuses({ candidate, source: testSource }))
      assert.strictEqual(refused._tag, "PolicyRefused")
      assert.strictEqual(refused.code, "one")
      // The second hook never ran: a refusal is the end of the chain, so a
      // policy after a refusing one cannot undo it or observe the attempt.
      assert.deepStrictEqual(trace, ["before:one"])

      trace.length = 0
      const secondRefuses = yield* beforeCreateOf(combine(recording(trace, "one"), refusing(trace, "two")))
      const later = yield* Effect.flip(secondRefuses({ candidate, source: testSource }))
      assert.strictEqual(later.code, "two")
      assert.deepStrictEqual(trace, ["before:one", "before:two"])
    }))

  // ---------------------------------------------------------------------------
  // layer / append — the checkpoint
  // ---------------------------------------------------------------------------

  it.effect("resolves to no hooks at all when nothing provided any", () =>
    Effect.gen(function*() {
      assert.deepStrictEqual(yield* resolve(Layer.empty), {})
    }))

  it.effect("applies Layer.updateService over the reference's own default", () =>
    Effect.gen(function*() {
      // The checkpoint `hooks.md` calls for. `append` is `updateService`'s own
      // definition written out, so what is asserted here is the property both
      // depend on: the function is handed the *default* when nothing in the
      // context provided the reference, rather than being skipped entirely.
      const trace: Array<string> = []
      const updated = Layer.updateService(installed, AuthHooks, (hooks) => combine(hooks, recording(trace, "only")))
      const hooks = yield* Effect.provide(Effect.map(Installed, (h): AuthHooksService => h), updated)

      const beforeCreate = yield* beforeCreateOf(hooks)
      const rewritten = yield* beforeCreate({ candidate: yield* candidateFor("default@example.com"), source: testSource })
      assert.strictEqual(rewritten.name, `${testName}/only`)
      assert.deepStrictEqual(trace, ["before:only"])
    }))

  it.effect("appends over the default, so a plugin needs no consumer set to exist", () =>
    Effect.gen(function*() {
      const trace: Array<string> = []
      const beforeCreate = yield* beforeCreateOf(yield* resolve(append(recording(trace, "plugin"))))

      const rewritten = yield* beforeCreate({
        candidate: yield* candidateFor("append-default@example.com"),
        source: testSource
      })
      assert.strictEqual(rewritten.name, `${testName}/plugin`)
      assert.deepStrictEqual(trace, ["before:plugin"])
    }))

  it.effect("appends after a consumer's set rather than shadowing it", () =>
    Effect.gen(function*() {
      const trace: Array<string> = []
      // The composition a deployment writes: the application's set is provided
      // underneath the plugin's, so the plugin reads it and adds to it.
      const hooks = yield* resolve(
        append(recording(trace, "plugin")).pipe(Layer.provide(hooksLayer(recording(trace, "app"))))
      )

      const beforeCreate = yield* beforeCreateOf(hooks)
      const rewritten = yield* beforeCreate({
        candidate: yield* candidateFor("append-over@example.com"),
        source: testSource
      })
      assert.strictEqual(rewritten.name, `${testName}/app/plugin`)
      assert.deepStrictEqual(trace, ["before:app", "before:plugin"])
    }))

  it.effect("lets the application's refusal short-circuit an appended plugin", () =>
    Effect.gen(function*() {
      const trace: Array<string> = []
      const hooks = yield* resolve(
        append(recording(trace, "plugin")).pipe(Layer.provide(hooksLayer(refusing(trace, "app"))))
      )

      const beforeCreate = yield* beforeCreateOf(hooks)
      const refused = yield* Effect.flip(
        beforeCreate({ candidate: yield* candidateFor("append-refused@example.com"), source: testSource })
      )
      assert.strictEqual(refused.code, "app")
      assert.deepStrictEqual(trace, ["before:app"])
    }))

  it.effect("gives the typed view the same slot as the base reference", () =>
    Effect.gen(function*() {
      // A typed view is the same key with a narrower shape, so a set installed
      // through it is the set core reads back through the base one.
      const typed = hooksOf(baseUserModel)
      const hooks = yield* resolve(Layer.succeed(typed)({ beforeUserDelete: () => Effect.void }))
      assert.isDefined(hooks.beforeUserDelete)
    }))
})

// -----------------------------------------------------------------------------
// The choke point
// -----------------------------------------------------------------------------

/** A hook set that refuses the addresses a test marked, and rewrites the rest. */
const provisionHooks: AuthHooksService = {
  beforeUserCreate: ({ candidate, source }) =>
    candidate.email.includes("refused")
      ? Effect.fail(new PolicyRefused({ code: "not_welcome", detail: source._tag }))
      : Effect.succeed({ ...candidate, name: "Rewritten", emailVerified: true })
}

layer(AuthTest.layer())("domain/Hooks — provision", (it) => {
  it.effect("writes the candidate through unchanged when no hook is installed", () =>
    Effect.gen(function*() {
      const users = yield* Users
      const email = uniqueEmail("provision-plain")
      const candidate = yield* candidateFor(email)

      const user = yield* users.provision({ candidate, source: testSource })

      assert.strictEqual(user.email, email)
      assert.strictEqual(user.name, testName)
      // The id is the caller's: it was generated before this was called, so the
      // flow that is about to write related rows already knows it.
      assert.strictEqual(user.id, candidate.id)
    }))

  it.layer(AuthTest.layer({ hooks: provisionHooks }))("with beforeUserCreate installed", (it) => {
    it.effect("stores what the hook rewrote, re-validated by the model", () =>
      Effect.gen(function*() {
        const users = yield* Users
        const store = yield* UserStore
        const email = uniqueEmail("provision-rewrite")

        const user = yield* users.provision({ candidate: yield* candidateFor(email), source: testSource })

        assert.strictEqual(user.name, "Rewritten")
        assert.isTrue(user.emailVerified)
        // The row that was written, not the value the hook answered with.
        const stored = yield* expectSome(yield* store.findById(user.id), "the provisioned row")
        assert.strictEqual(stored.name, "Rewritten")
      }))

    it.effect("refuses, and writes no row", () =>
      Effect.gen(function*() {
        const users = yield* Users
        const store = yield* UserStore
        const email = uniqueEmail("provision-refused")

        const refused = yield* Effect.flip(
          users.provision({ candidate: yield* candidateFor(email), source: testSource })
        )
        assert.strictEqual(refused._tag, "PolicyRefused")
        if (refused._tag === "PolicyRefused") {
          assert.strictEqual(refused.code, "not_welcome")
          // The source reaches the hook, which is what lets one policy cover
          // every flow that provisions a person.
          assert.strictEqual(refused.detail, "Plugin")
        }

        assert.isTrue(Option.isNone(yield* store.findByEmail(email)))
      }))
  })
})
