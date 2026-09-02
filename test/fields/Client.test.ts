/**
 * The browser client of a deployment that declared its own user fields.
 *
 * **Details**
 *
 * `AuthClient.make({ api, model })` is the only place the model is stated on the
 * client side, and it has to do two things: type the atoms the application reads
 * (`session.user.plan` is a `"free" | "pro"`, and `apiSecret` is not a key at
 * all) and decode a real response through the model's own schemas. The stub
 * transport is what makes the second one a *test* rather than an assertion about
 * types — a field the declaration were missing would fail the decode, and the
 * atom would hold a defect instead of a user.
 *
 * The type-level half of the same claim lives in `Fields.types.ts`.
 */
import { assert, describe, it } from "@effect/vitest"
import { Effect } from "effect"
import { Atom, AtomRegistry } from "effect/unstable/reactivity"
import { AuthClient } from "../../src/client/index.js"
import * as Stub from "../client/stub.js"
import { testName, testPassword } from "../fixtures.js"
import { FieldsApi, model } from "./model.js"

/** The encoded user this deployment's `json` variant produces. */
const userJson = {
  ...Stub.userJson,
  plan: "pro",
  role: "admin",
  order: "desc"
}

const registry = Effect.acquireRelease(
  Effect.sync(() => AtomRegistry.make()),
  (_) => Effect.sync(() => _.dispose())
)

const harness = (options?: { readonly signedIn?: boolean | undefined }) =>
  Effect.gen(function* () {
    const stub = Stub.make({ signedIn: options?.signedIn, user: userJson })
    const client = AuthClient.make({ api: FieldsApi, model, httpClient: stub.layer })
    const reg = yield* registry
    return { stub, client, reg } as const
  })

describe("fields/AuthClient", () => {
  it.effect("decodes the custom fields of the session's user", () =>
    Effect.gen(function* () {
      const { client, reg } = yield* harness({ signedIn: true })

      const session = yield* Atom.getResult(client.session).pipe(Effect.provideService(AtomRegistry.AtomRegistry, reg))

      // Typed, not merely present: `plan` is the literal union the model
      // declared, so this comparison would not compile against the base client.
      const plan: "free" | "pro" = session.user.plan
      assert.strictEqual(plan, "pro")
      assert.strictEqual(session.user.role, "admin")
      // Hidden fields are absent from the `json` variant, so there is no key to
      // read and nothing for a devtools panel to show.
      assert.isFalse(Object.hasOwn(session.user, "apiSecret"))
    })
  )

  it.effect("sends a custom field in the sign-up payload", () =>
    Effect.gen(function* () {
      const { client, reg, stub } = yield* harness()

      const registered = yield* AuthClient.run(client.signUp, {
        name: testName,
        email: "ada@example.com",
        password: testPassword,
        plan: "pro"
      }).pipe(Effect.provideService(AtomRegistry.AtomRegistry, reg))

      assert.strictEqual(registered.user.plan, "pro")
      assert.strictEqual(registered.session?.userId, registered.user.id)
      assert.deepStrictEqual(stub.calls, ["POST /auth/sign-up/email"])
    })
  )

  it.effect("carries the custom fields through sign-in", () =>
    Effect.gen(function* () {
      const { client, reg } = yield* harness()

      const signedIn = yield* AuthClient.run(client.signIn, {
        email: "ada@example.com",
        password: testPassword
      }).pipe(Effect.provideService(AtomRegistry.AtomRegistry, reg))

      // Sign-in answers a union: a session, or the 202 a factor plugin owes a
      // second factor with. This deployment installs none.
      assert.isFalse("_tag" in signedIn)
      if ("_tag" in signedIn) return
      assert.strictEqual(signedIn.user.plan, "pro")
    })
  )
})
