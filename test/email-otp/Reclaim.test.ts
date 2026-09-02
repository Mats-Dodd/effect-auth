import { assert, describe, layer } from "@effect/vitest"
import { Effect, Layer, Redacted, Result } from "effect"
import type { AuthenticatorsService } from "../../src/domain/Authenticators.js"
import { layer as authenticatorsLayer } from "../../src/domain/Authenticators.js"
import { AccountStore } from "../../src/domain/Stores.js"
import { EmailOtp } from "../../src/email-otp/EmailOtp.js"
import * as EmailOtpTest from "../../src/testing/EmailOtpTest.js"
import * as AuthTest from "../../src/testing/TestLayer.js"
import { forUser, signUpUser, uniqueEmail } from "../fixtures.js"

/**
 * A factor plugin's contribution, counted rather than mocked: what the takeover
 * defence must do is *ask* it, inside the transaction that destroys everything
 * else, and this records that it was asked and for whom.
 */
const swept: Array<string> = []

const contributor: AuthenticatorsService = {
  revokeAll: (userId) =>
    Effect.sync(() => {
      swept.push(userId)
      return 2
    })
}

/** Asks for a code and reads it out of the outbox, as its recipient does. */
const codeFor = Effect.fnUntraced(function* (email: string, nth = 1) {
  const otp = yield* EmailOtp
  const issued = yield* otp.send({ email, purpose: "signIn" })
  return { handle: issued.handle, code: yield* EmailOtpTest.awaitCode(email, nth) }
})

/**
 * The plugin sits above `AuthTest.layer`'s own composition, so the reference has
 * to be provided over the *whole* deployment as well as inside it — which is
 * exactly what a consumer does with one `Layer.provide` over their composed
 * stack. Passing it in the settings alone would reach core and not the plugin.
 */
const deployment = EmailOtpTest.layer({ authenticators: contributor }).pipe(
  Layer.provide(authenticatorsLayer(contributor))
)

describe.sequential("email-otp/reclaim", () => {
  layer(deployment)("with a factor plugin installed alongside the takeover defence", (it) => {
    it.effect("revokes the pre-registrant's factors as well as their accounts", () =>
      Effect.gen(function* () {
        // Somebody registers an address they do not own, and enrols a passkey
        // on it. Destroying the `accounts` rows alone would leave that passkey
        // working — the defence would announce a takeover it had not prevented.
        const email = uniqueEmail("squatted-with-a-factor")
        const registered = yield* signUpUser(email)
        assert.isFalse(registered.user.emailVerified)
        swept.length = 0

        const otp = yield* EmailOtp
        const { code, handle } = yield* codeFor(email)
        const { events, result } = yield* AuthTest.recordingEvents(otp.verify({ handle, code }))

        assert.strictEqual(result._tag, "SignedIn")
        if (result._tag !== "SignedIn") return
        assert.strictEqual(result.user.id, registered.user.id)
        // The contributor was asked, exactly once, for exactly this user.
        assert.deepStrictEqual(swept, [registered.user.id])
        const accounts = yield* AccountStore
        assert.deepStrictEqual(yield* accounts.listByUserId(registered.user.id), [])

        // And what it swept is reported beside what core swept.
        const plugin = forUser(events, result.user.id).find((event) => event._tag === "PluginEvent")
        if (plugin === undefined || plugin._tag !== "PluginEvent") {
          return assert.fail("expected the takeover defence to publish its PluginEvent")
        }
        assert.strictEqual(plugin.plugin, "email-otp")
        assert.strictEqual(plugin.event, "UnprovenAccountRevoked")
        assert.strictEqual(plugin.data["authenticators"], 2)
        assert.strictEqual(plugin.data["accounts"], 1)
      })
    )

    it.effect("does not touch the factors of an account whose address was already proved", () =>
      Effect.gen(function* () {
        const email = uniqueEmail("proven")
        const registered = yield* signUpUser(email)
        const otp = yield* EmailOtp
        // Prove the address first, so the second code is an ordinary sign-in.
        const first = yield* codeFor(email)
        yield* otp.verify({ handle: first.handle, code: first.code })
        swept.length = 0

        const second = yield* codeFor(email, 2)
        const result = yield* otp.verify({ handle: second.handle, code: second.code })

        assert.strictEqual(result._tag, "SignedIn")
        if (result._tag !== "SignedIn") return
        assert.strictEqual(result.user.id, registered.user.id)
        // A sign-in is not a takeover: nothing of theirs is destroyed.
        assert.deepStrictEqual(swept, [])
        assert.notStrictEqual(Redacted.value(result.token).length, 0)
      })
    )

    it.effect("the link path runs the same defence", () =>
      Effect.gen(function* () {
        const email = uniqueEmail("squatted-link")
        const registered = yield* signUpUser(email)
        swept.length = 0

        const otp = yield* EmailOtp
        yield* otp.send({ email, purpose: "signIn" })
        const token = yield* EmailOtpTest.awaitLinkToken(email)
        const outcome = yield* otp.follow({ token: Redacted.make(token) })

        assert.isTrue(Result.isSuccess(outcome))
        if (!Result.isSuccess(outcome)) return
        assert.strictEqual(outcome.success._tag, "SignedIn")
        assert.deepStrictEqual(swept, [registered.user.id])
      })
    )

    it.effect("proving an address by a reset code re-secures it too", () =>
      Effect.gen(function* () {
        const email = uniqueEmail("squatted-reset")
        const registered = yield* signUpUser(email)
        swept.length = 0

        const otp = yield* EmailOtp
        const issued = yield* otp.send({ email, purpose: "resetPassword" })
        const code = yield* EmailOtpTest.awaitCode(email)
        const result = yield* otp.verify({ handle: issued.handle, code })

        assert.strictEqual(result._tag, "PasswordReset")
        assert.deepStrictEqual(swept, [registered.user.id])
      })
    )
  })
})
