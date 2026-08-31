/**
 * A deployment's own policy, over a deployment's own user columns.
 *
 * **Details**
 *
 * `hooksOf(model)` is a typed view: the same context key with a narrower shape,
 * exactly as `userStoreOf` and `currentUserOf` are. What that buys is the whole
 * point of these tests — a hook installed through it reads and writes the
 * deployment's *own* fields with no cast and no `any`, while core, which knows
 * nothing about them, goes on reading the base-typed key and re-validating
 * whatever the hook answered with through the model itself.
 *
 * So the claims here are:
 *
 * - a set installed through the view lands in the slot core reads (it fires at
 *   all — the key string is what makes that true);
 * - it *reads* a custom field, including the one the model defaulted;
 * - it *writes* one, including a `readOnly` field no client may state and a
 *   `hidden` one that never leaves the server, and the row that is stored says
 *   what the hook said;
 * - and a refusal keyed off a custom field leaves no row behind.
 */
import { assert, layer } from "@effect/vitest"
import { Effect, Layer, Option } from "effect"
import type { AuthHooksOf } from "../../src/domain/Hooks.js"
import { hooksOf, PolicyRefused } from "../../src/domain/Hooks.js"
import { passwordsOf } from "../../src/domain/Passwords.js"
import { userStoreOf } from "../../src/domain/Stores.js"
import { AuthTest } from "../../src/testing/index.js"
import { expectSome, testName, testPassword, uniqueEmail } from "../fixtures.js"
import type { Fields } from "./model.js"
import { model } from "./model.js"

const passwords = passwordsOf(model)
const users = userStoreOf(model)

/**
 * The deployment's policy, typed by the deployment's model.
 *
 * **Details**
 *
 * Every field named below is one the compiler knows about: `candidate.plan` is
 * `"free" | "pro"`, and `role` and `apiSecret` are settable here and nowhere a
 * client can reach. Rewriting the two of them is the shape of the real thing —
 * a deployment deriving a role, or minting a per-account secret, at the one
 * moment every provisioning flow passes through.
 */
const planHooks: AuthHooksOf<Fields> = {
  beforeUserCreate: ({ candidate }) =>
    candidate.email.startsWith("banned-plan-")
      ? Effect.fail(new PolicyRefused({ code: "plan_not_available", detail: candidate.plan }))
      : Effect.succeed({
        ...candidate,
        // Read off the fields the model resolved before the hook was consulted,
        // written onto ones no payload may carry. The witness goes into the row
        // rather than into an array beside it: the tests in a `layer()` block
        // share a deployment and run beside each other, so what a hook saw has
        // to be recoverable from the row it produced.
        role: candidate.plan === "pro" ? ("admin" as const) : ("user" as const),
        apiSecret: `saw:${candidate.plan}/${candidate.role}`
      })
}

/**
 * The deployment, with the typed set underneath it.
 *
 * `Layer.succeed(hooksOf(model))` rather than `AuthTest.layer({ hooks })`: the
 * seam takes the base-typed set, and what is under test is the view — that a
 * set installed through the model's own key is the set the base-typed domain
 * services read back.
 */
const deployment = AuthTest.layer({ user: { model } }).pipe(
  Layer.provide(Layer.succeed(hooksOf(model))(planHooks))
)

layer(deployment)("fields/Hooks", (it) => {
  it.effect("reads the field the model defaulted and writes the ones no client may state", () =>
    Effect.gen(function*() {
      const store = yield* users
      const email = uniqueEmail("hooks-fields-default")

      const { user } = yield* (yield* passwords).signUp({ name: testName, email, password: testPassword })

      // The candidate reached the hook already carrying the model's own
      // defaults for `plan` and `role`, so a policy reads a complete row rather
      // than a half-built one.
      assert.strictEqual(user.apiSecret, "saw:free/user")
      assert.strictEqual(user.plan, "free")
      assert.strictEqual(user.role, "user")

      // And what was stored is what the hook answered with, re-validated
      // through the model on its way in.
      const stored = yield* expectSome(yield* store.findByEmail(email), "the provisioned row")
      assert.strictEqual(stored.role, "user")
      assert.strictEqual(stored.apiSecret, "saw:free/user")
    }))

  it.effect("sees what the sign-up stated, and derives the read-only field from it", () =>
    Effect.gen(function*() {
      const store = yield* users
      const email = uniqueEmail("hooks-fields-pro")

      // `plan` is the one custom field a client may state; `role` is not, which
      // is exactly why deriving it here rather than trusting a payload is what a
      // deployment wants.
      const { user } = yield* (yield* passwords).signUp({
        name: testName,
        email,
        password: testPassword,
        plan: "pro"
      })

      // The hook was handed the plan the payload stated, and the model's own
      // default for the field the payload could not.
      assert.strictEqual(user.apiSecret, "saw:pro/user")
      assert.strictEqual(user.plan, "pro")
      assert.strictEqual(user.role, "admin")
      const stored = yield* expectSome(yield* store.findByEmail(email), "the provisioned row")
      assert.strictEqual(stored.role, "admin")
      assert.strictEqual(stored.apiSecret, "saw:pro/user")
    }))

  it.effect("refuses on a custom field, and leaves no row", () =>
    Effect.gen(function*() {
      const store = yield* users
      const email = `banned-plan-${uniqueEmail("hooks-fields")}`

      const refused = yield* Effect.flip(
        (yield* passwords).signUp({ name: testName, email, password: testPassword, plan: "pro" })
      )

      assert.strictEqual(refused._tag, "PolicyRefused")
      if (refused._tag === "PolicyRefused") {
        assert.strictEqual(refused.code, "plan_not_available")
        // The custom field the policy refused over, read off the candidate.
        assert.strictEqual(refused.detail, "pro")
      }
      assert.isTrue(Option.isNone(yield* store.findByEmail(email)))
    }))
})
