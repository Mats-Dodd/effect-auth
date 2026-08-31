import { assert, layer } from "@effect/vitest"
import { Duration, Effect, Redacted, Schema } from "effect"
import { TestClock } from "effect/testing"
import { identifierOf, purpose, Verifications } from "../../src/domain/Verifications.js"
import { AuthTest } from "../../src/testing/index.js"
import { uniqueEmail } from "../fixtures.js"

/** A purpose that carries something, as a plugin's would. */
const invite = purpose("test-invite", Schema.Struct({ callbackURL: Schema.NullOr(Schema.String) }))

/** A purpose that carries nothing, as the two core ones do. */
const ping = purpose("test-ping")

layer(AuthTest.layer())("domain/Verifications", (it) => {
  it.effect("names its rows `<purpose>:<subject>`", () => {
    assert.strictEqual(identifierOf(invite, "ada@example.com"), "test-invite:ada@example.com")
    assert.strictEqual(identifierOf(ping, "ada@example.com"), "test-ping:ada@example.com")
    return Effect.void
  })

  it.effect("hands a payload back to whoever claims the token", () =>
    Effect.gen(function*() {
      const verifications = yield* Verifications
      const subject = uniqueEmail("invite")

      const issued = yield* verifications.issue({
        purpose: invite,
        subject,
        ttl: Duration.minutes(10),
        payload: { callbackURL: "/welcome" }
      })
      assert.strictEqual(issued.identifier, `test-invite:${subject}`)

      const claimed = yield* verifications.claim(invite, issued.token)
      assert.strictEqual(claimed.subject, subject)
      assert.strictEqual(claimed.payload.callbackURL, "/welcome")
      assert.strictEqual(claimed.verification.identifier, issued.identifier)

      // Single use: the row went with the claim.
      const replayed = yield* Effect.flip(verifications.claim(invite, issued.token))
      assert.strictEqual(replayed._tag, "InvalidToken")
    }))

  it.effect("answers `null` for a purpose that declares no payload", () =>
    Effect.gen(function*() {
      const verifications = yield* Verifications
      const subject = uniqueEmail("ping")

      const issued = yield* verifications.issue({
        purpose: ping,
        subject,
        ttl: Duration.minutes(10),
        payload: null
      })
      const claimed = yield* verifications.claim(ping, issued.token)
      assert.strictEqual(claimed.payload, null)
    }))

  it.effect("refuses a token of another purpose, and nonsense", () =>
    Effect.gen(function*() {
      const verifications = yield* Verifications
      const subject = uniqueEmail("crossed")

      const issued = yield* verifications.issue({
        purpose: ping,
        subject,
        ttl: Duration.minutes(10),
        payload: null
      })

      // The secret is genuine; the identifier it names belongs to the other
      // purpose, so the claim finds nothing.
      const crossed = yield* Effect.flip(verifications.claim(invite, issued.token))
      assert.strictEqual(crossed._tag, "InvalidToken")

      const nonsense = yield* Effect.flip(verifications.claim(ping, Redacted.make("not-a-subject-token")))
      assert.strictEqual(nonsense._tag, "InvalidToken")
    }))

  it.effect("retires the siblings of a claim, and expires on time", () =>
    AuthTest.freshClock(Effect.gen(function*() {
      const verifications = yield* Verifications
      const subject = uniqueEmail("siblings")

      const first = yield* verifications.issue({
        purpose: ping,
        subject,
        ttl: Duration.minutes(10),
        payload: null
      })
      const second = yield* verifications.issue({
        purpose: ping,
        subject,
        ttl: Duration.minutes(10),
        payload: null
      })

      // Two outstanding links for one subject; retiring takes both.
      assert.strictEqual(yield* verifications.retire(ping, subject), 2)
      assert.strictEqual((yield* Effect.flip(verifications.claim(ping, first.token)))._tag, "InvalidToken")
      assert.strictEqual((yield* Effect.flip(verifications.claim(ping, second.token)))._tag, "InvalidToken")

      const third = yield* verifications.issue({
        purpose: ping,
        subject,
        ttl: Duration.minutes(10),
        payload: null
      })
      yield* TestClock.adjust(Duration.minutes(11))
      assert.strictEqual((yield* Effect.flip(verifications.claim(ping, third.token)))._tag, "InvalidToken")
    })))
})
