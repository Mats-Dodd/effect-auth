import { PgliteClient } from "@effect/sql-pglite"
import { assert, describe, it } from "@effect/vitest"
import { Duration, Effect, Layer, Redacted } from "effect"
import { TestClock } from "effect/testing"
import { layer as authConfigLayer } from "../../src/config/AuthConfig.js"
import { Token, layer as tokenLayer } from "../../src/crypto/Token.js"
import { UserId } from "../../src/domain/Schema.js"
import { VerificationStore } from "../../src/domain/Stores.js"
import { codeChallengeMethod, consume, issue } from "../../src/oauth/State.js"
import * as Migrations from "../../src/sql/Migrations.js"
import * as SqlStores from "../../src/sql/SqlStores.js"

/**
 * State needs three things and nothing else: configuration for the TTL, the
 * token service, and somewhere to put the row. Each test gets its own database
 * so it also gets its own `TestClock`.
 */
const stateLayer = (oauthStateTtl?: Duration.Duration) => {
  const database = PgliteClient.layer()
  const storage = SqlStores.layer.pipe(
    Layer.provide(Migrations.layer.pipe(Layer.provideMerge(database)))
  )
  return Layer.mergeAll(
    storage,
    tokenLayer,
    authConfigLayer({
      baseUrl: "https://app.example.com",
      secret: Redacted.make("test-secret-not-for-production"),
      tokens: oauthStateTtl === undefined ? undefined : { oauthStateTtl }
    })
  )
}

const testTimeout = 30_000

describe("oauth/State", () => {
  it.effect("sends S256 and nothing else", () => Effect.sync(() => {
    assert.strictEqual(codeChallengeMethod, "S256")
  }))

  it.effect(
    "round-trips a request: what was minted is what the callback reads back",
    () =>
      Effect.gen(function*() {
        const issued = yield* issue({
          providerId: "github",
          callbackURL: "https://app.example.com/welcome",
          errorURL: "https://app.example.com/oops",
          linkUserId: UserId.make("0193f6f0-0000-7000-8000-000000000001"),
          rememberMe: false,
          withNonce: true
        })

        const payload = yield* consume("github", issued.state)
        assert.strictEqual(payload.providerId, "github")
        assert.strictEqual(payload.callbackURL, "https://app.example.com/welcome")
        assert.strictEqual(payload.errorURL, "https://app.example.com/oops")
        assert.strictEqual(payload.codeVerifier, Redacted.value(issued.codeVerifier))
        assert.strictEqual(payload.nonce, issued.nonce)
        assert.strictEqual(payload.linkUserId, "0193f6f0-0000-7000-8000-000000000001")
        assert.isFalse(payload.rememberMe)
      }).pipe(Effect.provide(stateLayer())),
    testTimeout
  )

  it.effect(
    "derives the challenge as the S256 transformation of the verifier",
    () =>
      Effect.gen(function*() {
        const tokens = yield* Token
        const issued = yield* issue({ providerId: "google", withNonce: true })
        const expected = yield* tokens.hashToken(issued.codeVerifier)
        assert.strictEqual(issued.codeChallenge, expected)
        // The challenge is not the verifier, and the state is neither.
        assert.notStrictEqual(issued.codeChallenge, Redacted.value(issued.codeVerifier))
        assert.notStrictEqual(issued.codeChallenge, Redacted.value(issued.state))
      }).pipe(Effect.provide(stateLayer())),
    testTimeout
  )

  it.effect(
    "mints a nonce only when one was asked for",
    () =>
      Effect.gen(function*() {
        const withNonce = yield* issue({ providerId: "google", withNonce: true })
        assert.isNotNull(withNonce.nonce)

        const without = yield* issue({ providerId: "github", withNonce: false })
        assert.isNull(without.nonce)
        const payload = yield* consume("github", without.state)
        assert.isNull(payload.nonce)
      }).pipe(Effect.provide(stateLayer())),
    testTimeout
  )

  it.effect(
    "stores the state hashed: the raw value never reaches the row",
    () =>
      Effect.gen(function*() {
        const tokens = yield* Token
        const store = yield* VerificationStore
        const issued = yield* issue({ providerId: "github", withNonce: false })
        const stateHash = yield* tokens.hashToken(issued.state)

        // The row is named by the digest, so this is the only lookup that
        // finds it — a lookup by the raw value cannot.
        const byRaw = yield* store.consume(
          `oauth-state:${Redacted.value(issued.state)}`,
          Redacted.value(issued.state)
        )
        assert.isTrue(byRaw._tag === "None")

        const byHash = yield* store.consume(`oauth-state:${stateHash}`, stateHash)
        assert.isTrue(byHash._tag === "Some")
      }).pipe(Effect.provide(stateLayer())),
    testTimeout
  )

  it.effect(
    "is single-use: a replayed callback finds nothing",
    () =>
      Effect.gen(function*() {
        const issued = yield* issue({ providerId: "github", withNonce: false })
        yield* consume("github", issued.state)

        const replay = yield* Effect.result(consume("github", issued.state))
        assert.strictEqual(replay._tag, "Failure")
        if (replay._tag === "Failure") {
          assert.strictEqual(replay.failure._tag, "OAuthStateMismatch")
        }
      }).pipe(Effect.provide(stateLayer())),
    testTimeout
  )

  it.effect(
    "refuses a state redeemed at another provider's callback",
    () =>
      Effect.gen(function*() {
        const issued = yield* issue({ providerId: "github", withNonce: false })

        const wrong = yield* Effect.result(consume("google", issued.state))
        assert.strictEqual(wrong._tag, "Failure")

        // And the row was still consumed, so the right provider cannot pick it
        // up afterwards either.
        const after = yield* Effect.result(consume("github", issued.state))
        assert.strictEqual(after._tag, "Failure")
      }).pipe(Effect.provide(stateLayer())),
    testTimeout
  )

  it.effect(
    "refuses a state nobody issued",
    () =>
      Effect.gen(function*() {
        const result = yield* Effect.result(consume("github", Redacted.make("not-a-state-anybody-minted")))
        assert.strictEqual(result._tag, "Failure")
      }).pipe(Effect.provide(stateLayer())),
    testTimeout
  )

  it.effect(
    "expires ten minutes after it was minted",
    () =>
      Effect.gen(function*() {
        const issued = yield* issue({ providerId: "github", withNonce: false })

        yield* TestClock.adjust(Duration.minutes(10).pipe(Duration.subtract(Duration.millis(1))))
        const justInTime = yield* Effect.result(consume("github", issued.state))
        assert.strictEqual(justInTime._tag, "Success")

        const second = yield* issue({ providerId: "github", withNonce: false })
        yield* TestClock.adjust(Duration.minutes(10))
        const tooLate = yield* Effect.result(consume("github", second.state))
        assert.strictEqual(tooLate._tag, "Failure")
      }).pipe(Effect.provide(stateLayer())),
    testTimeout
  )
})
