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
 * - a refusal keyed off a custom field leaves no row behind;
 * - and the candidate carries those fields on **every** source, not only on the
 *   one whose caller happens to build its row through the model — see the
 *   `every source` block at the bottom of this file.
 */
import { assert, describe, layer } from "@effect/vitest"
import { Cause, Effect, Layer, Option, Random } from "effect"
import type { OAuthIdentity } from "../../src/domain/Accounts.js"
import { Accounts } from "../../src/domain/Accounts.js"
import type { AuthHooksOf, AuthHooksService } from "../../src/domain/Hooks.js"
import { hooksOf, PolicyRefused } from "../../src/domain/Hooks.js"
import { passwordsOf } from "../../src/domain/Passwords.js"
import { oauthIssuer } from "../../src/domain/Schema.js"
import { userStoreOf } from "../../src/domain/Stores.js"
import { MagicLink } from "../../src/magic-link/MagicLink.js"
import { AuthTest, MagicLinkTest } from "../../src/testing/index.js"
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
      ? Effect.fail(PolicyRefused.make({ code: "plan_not_available", detail: candidate.plan }))
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
const deployment = AuthTest.layer({ user: { model } }).pipe(Layer.provide(Layer.succeed(hooksOf(model))(planHooks)))

layer(deployment)("fields/Hooks", (it) => {
  it.effect("reads the field the model defaulted and writes the ones no client may state", () =>
    Effect.gen(function* () {
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
    })
  )

  it.effect("sees what the sign-up stated, and derives the read-only field from it", () =>
    Effect.gen(function* () {
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
    })
  )

  it.effect("refuses on a custom field, and leaves no row", () =>
    Effect.gen(function* () {
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
    })
  )
})

// -----------------------------------------------------------------------------
// Every source, not just the one that builds its row through the model
// -----------------------------------------------------------------------------

/**
 * The deployment above, with the two sources whose callers are base-typed.
 *
 * **Details**
 *
 * A sign-up builds its candidate with `model.makeInsert`, so the custom columns
 * are on it before any hook is consulted. The OAuth flow and the magic-link
 * plugin cannot: `Accounts` is base-typed on purpose (a provider identity
 * carries base fields and nothing else) and a plugin never knows what a
 * deployment declared. Completing the candidate from the model's own defaults
 * before `beforeUserCreate` is asked is what makes one policy read the same row
 * whichever door the person came through — without it {@link planHooks} would
 * read `undefined` for `plan` and `role` here and store `saw:undefined/undefined`
 * on two sources out of three.
 *
 * The set is provided once, underneath the whole composition, so the plugin
 * layered over the deployment and the deployment itself resolve the very same
 * one.
 */
const everySource = MagicLinkTest.layerMagicLink().pipe(
  Layer.provideMerge(AuthTest.layer({ user: { model }, trustedProviders: ["github"] })),
  Layer.provide(Layer.succeed(hooksOf(model))(planHooks))
)

/**
 * What a provider hands back, with a subject no other test will claim.
 *
 * The subject is drawn from Effect's `Random` — injected randomness rather than
 * the global `crypto` — which is why this is an effect and not a plain value.
 */
const identityFor = (email: string): Effect.Effect<OAuthIdentity> =>
  Effect.map(Random.nextIntBetween(0, Number.MAX_SAFE_INTEGER), (draw) => ({
    providerId: "github",
    issuer: oauthIssuer("github"),
    accountId: `gh-${draw.toString(36)}`,
    email,
    emailVerified: true,
    name: testName
  }))

// One deployment, one policy: the tests below assert the *same* row against the
// two sources that do not build it through the model.
describe.sequential("fields/Hooks — every source", () => {
  layer(everySource)((it) => {
    it.effect("hands a first OAuth sign-in a candidate carrying the model's own columns", () =>
      Effect.gen(function* () {
        const store = yield* users
        const email = uniqueEmail("hooks-fields-oauth")

        const linked = yield* (yield* Accounts).linkOAuth(yield* identityFor(email))

        assert.isTrue(linked.userCreated)
        // The very row the password source produces for a defaulted plan — the
        // claim `hooksOf` makes, held against the source that knows nothing
        // about the deployment's fields.
        const stored = yield* expectSome(yield* store.findByEmail(email), "the provisioned row")
        assert.strictEqual(stored.plan, "free")
        assert.strictEqual(stored.role, "user")
        assert.strictEqual(stored.apiSecret, "saw:free/user")
      })
    )

    it.effect("hands a magic link's first sign-in the same candidate", () =>
      Effect.gen(function* () {
        const store = yield* users
        const magic = yield* MagicLink
        const emails = yield* AuthTest.TestEmails
        const email = uniqueEmail("hooks-fields-magic")

        yield* magic.request({ email, name: testName })
        const verified = yield* magic.verify({
          token: yield* emails.tokenFor(MagicLinkTest.magicLinkKind, email)
        })

        assert.strictEqual(verified.user.email, email)
        const stored = yield* expectSome(yield* store.findByEmail(email), "the provisioned row")
        assert.strictEqual(stored.plan, "free")
        assert.strictEqual(stored.role, "user")
        assert.strictEqual(stored.apiSecret, "saw:free/user")
      })
    )
  })
})

// -----------------------------------------------------------------------------
// A rewrite the deployment's own schema rejects
// -----------------------------------------------------------------------------

/**
 * A base-typed policy answering with a value the model does not allow.
 *
 * **Details**
 *
 * `plan` is `"free" | "pro"`; `"enterprise"` is what a hook that copied a raw
 * provider claim, or a plugin that guessed, would produce. The set is
 * *base*-typed on purpose — that is the position a plugin writes from, and the
 * one where the compiler cannot help — so the schema has to be what refuses it.
 *
 * `Object.assign` rather than an object literal for the same reason: a
 * base-typed candidate has no `plan` key to state.
 */
const smugglingHooks: AuthHooksService = {
  beforeUserCreate: ({ candidate }) => Effect.succeed(Object.assign({ ...candidate }, { plan: "enterprise" }))
}

layer(AuthTest.layer({ user: { model }, hooks: smugglingHooks, trustedProviders: ["github"] }))(
  "fields/Hooks — a rewrite the schema rejects",
  (it) => {
    /**
     * Both sources refuse it, and neither stores a row: a rewrite is put back
     * through the *deployment's* `insert` variant — the only schema that knows
     * what `plan` may say — before anything is written, so a value outside the
     * union is a defect (a broken policy is a `500`, per `Hooks.ts`) rather than
     * a row.
     *
     * **Gotchas**
     *
     * The shipped SQL store would refuse this one too, at its own encoder, so
     * what these two assert is the *parity* rather than the layer that catches
     * it. The layer still matters: `UserStore` is a documented seam and an
     * implementation of somebody's own is under no obligation to validate, so
     * the OAuth path validating only the base half — which is what it used to
     * do, copying the deployment's columns across by name — made the store the
     * last line of defence on one source out of three.
     */
    it.effect("refuses it on the password source, storing nothing", () =>
      Effect.gen(function* () {
        const store = yield* users
        const email = uniqueEmail("hooks-fields-smuggle-password")

        const exit = yield* Effect.exit((yield* passwords).signUp({ name: testName, email, password: testPassword }))

        assert.strictEqual(exit._tag, "Failure")
        assert.isTrue(exit._tag === "Failure" && Cause.hasDies(exit.cause))
        assert.isTrue(Option.isNone(yield* store.findByEmail(email)))
      })
    )

    it.effect("refuses it on the OAuth source too, storing nothing", () =>
      Effect.gen(function* () {
        const store = yield* users
        const email = uniqueEmail("hooks-fields-smuggle-oauth")

        const exit = yield* Effect.exit((yield* Accounts).linkOAuth(yield* identityFor(email)))

        assert.strictEqual(exit._tag, "Failure")
        assert.isTrue(exit._tag === "Failure" && Cause.hasDies(exit.cause))
        assert.isTrue(Option.isNone(yield* store.findByEmail(email)))
      })
    )
  }
)
