import { assert, describe, layer } from "@effect/vitest"
import { DateTime, Duration, Effect, Redacted } from "effect"
import { TestClock } from "effect/testing"
import type { JWTPayload } from "jose"
import { isRedirectResponse, verify } from "../../src/oauth/IdToken.js"
import { AuthTest, MockProvider } from "../../src/testing/index.js"

/**
 * The issuer and audience {@link MockProvider.IdTokenSigner} mints for by
 * default — the provider a token has to have come from for `verify` to admit it.
 */
const issuer = MockProvider.providerOrigin
const audience = "mock-client-id"

/** The one hour after the (test) epoch that every token below expires at. */
const expiresAt = 3600

const sign = (
  signer: MockProvider.IdTokenSignerService,
  payload: JWTPayload,
  options?: MockProvider.SignOptions
): Effect.Effect<Redacted.Redacted<string>> =>
  Effect.promise(async () => Redacted.make(await signer.sign(payload, options)))

const verifying = (
  token: Redacted.Redacted<string>,
  keys: MockProvider.IdTokenSignerService["jwks"],
  overrides?: {
    readonly issuer?: string
    readonly audience?: string
    readonly nonce?: string | null
  }
) =>
  Effect.result(verify({
    providerId: "google",
    token,
    issuer: overrides?.issuer ?? issuer,
    audience: overrides?.audience ?? audience,
    keys,
    nonce: overrides?.nonce ?? null,
    algorithms: ["RS256"]
  }))

/**
 * One key pair for the whole file: verification is network-free because
 * `createLocalJWKSet` answers from the key set in memory, which is the whole
 * point of `verify` taking a `KeyResolver` rather than a URL — and generating
 * that pair costs tens of milliseconds, so the block builds it once.
 */
layer(MockProvider.IdTokenSigner.layer)("oauth/IdToken", (it) => {
  describe("verify", () => {
    it.effect("accepts a well-formed token and projects its claims", () =>
      Effect.gen(function*() {
        const signer = yield* MockProvider.IdTokenSigner
        const token = yield* sign(signer, {
          sub: "provider-subject",
          email: "ada@example.com",
          email_verified: true,
          name: "Ada Lovelace",
          picture: "https://cdn.test/ada.png",
          nonce: "the-nonce"
        }, { expiresAt })

        const result = yield* verifying(token, signer.jwks, { nonce: "the-nonce" })
        assert.strictEqual(result._tag, "Success")
        if (result._tag !== "Success") return
        const claims = result.success
        assert.strictEqual(claims.subject, "provider-subject")
        assert.strictEqual(claims.issuer, issuer)
        assert.deepStrictEqual([...claims.audience], [audience])
        assert.strictEqual(claims.email, "ada@example.com")
        assert.isTrue(claims.emailVerified)
        assert.strictEqual(claims.name, "Ada Lovelace")
        assert.strictEqual(claims.picture, "https://cdn.test/ada.png")
        assert.strictEqual(claims.nonce, "the-nonce")
        assert.strictEqual(DateTime.toEpochMillis(claims.expiresAt), expiresAt * 1000)
      }))

    it.effect("reads the string spelling of email_verified, and defaults it to false", () =>
      Effect.gen(function*() {
        const signer = yield* MockProvider.IdTokenSigner
        const asString = yield* sign(signer, { sub: "s", email_verified: "true" }, { expiresAt })
        const stringy = yield* verifying(asString, signer.jwks)
        assert.strictEqual(stringy._tag, "Success")
        if (stringy._tag === "Success") assert.isTrue(stringy.success.emailVerified)

        const absent = yield* sign(signer, { sub: "s" }, { expiresAt })
        const missing = yield* verifying(absent, signer.jwks)
        assert.strictEqual(missing._tag, "Success")
        if (missing._tag === "Success") {
          assert.isFalse(missing.success.emailVerified)
          assert.isNull(missing.success.email)
        }
      }))

    it.effect("refuses a token signed by a key the provider does not publish", () =>
      Effect.gen(function*() {
        const signer = yield* MockProvider.IdTokenSigner
        // The one place a second key pair is worth its cost: a forgery is a
        // token that verifies perfectly against the wrong key set.
        const forger = yield* MockProvider.makeIdTokenSigner()
        const forged = yield* sign(forger, { sub: "s" }, { expiresAt })

        const result = yield* verifying(forged, signer.jwks)
        assert.strictEqual(result._tag, "Failure")
        if (result._tag === "Failure") {
          assert.strictEqual(result.failure._tag, "OAuthProviderError")
          assert.strictEqual(result.failure.reason, "IdTokenInvalid")
          assert.strictEqual(result.failure.providerId, "google")
        }
      }))

    it.effect("refuses another issuer's token", () =>
      Effect.gen(function*() {
        const signer = yield* MockProvider.IdTokenSigner
        const token = yield* sign(signer, { sub: "s" }, { issuer: "https://evil.test", expiresAt })
        const result = yield* verifying(token, signer.jwks)
        assert.strictEqual(result._tag, "Failure")
      }))

    it.effect("refuses a token minted for another audience", () =>
      Effect.gen(function*() {
        const signer = yield* MockProvider.IdTokenSigner
        const token = yield* sign(signer, { sub: "s" }, { audience: "someone-elses-client", expiresAt })
        const result = yield* verifying(token, signer.jwks)
        assert.strictEqual(result._tag, "Failure")
      }))

    it.effect("refuses a token with no sub", () =>
      Effect.gen(function*() {
        const signer = yield* MockProvider.IdTokenSigner
        const token = yield* sign(signer, { email: "ada@example.com" }, { expiresAt })
        const result = yield* verifying(token, signer.jwks)
        assert.strictEqual(result._tag, "Failure")
      }))

    it.effect("refuses a token with no exp, however well signed", () =>
      Effect.gen(function*() {
        const signer = yield* MockProvider.IdTokenSigner
        const token = yield* sign(signer, { sub: "s" }, { expiresAt: null })
        const result = yield* verifying(token, signer.jwks)
        assert.strictEqual(result._tag, "Failure")
      }))

    it.effect("refuses a token whose nonce is absent or wrong when one was minted", () =>
      Effect.gen(function*() {
        const signer = yield* MockProvider.IdTokenSigner

        const withoutNonce = yield* sign(signer, { sub: "s" }, { expiresAt })
        const absent = yield* verifying(withoutNonce, signer.jwks, { nonce: "the-nonce" })
        assert.strictEqual(absent._tag, "Failure")

        const otherNonce = yield* sign(signer, { sub: "s", nonce: "somebody-elses" }, { expiresAt })
        const wrong = yield* verifying(otherNonce, signer.jwks, { nonce: "the-nonce" })
        assert.strictEqual(wrong._tag, "Failure")
      }))

    it.effect("expires by the Effect clock", () =>
      // The block's `TestClock` is shared: this test moves one of its own, so
      // that the hour it burns is not also burnt by its siblings.
      AuthTest.freshClock(Effect.gen(function*() {
        const signer = yield* MockProvider.IdTokenSigner
        const token = yield* sign(signer, { sub: "s" }, { expiresAt })

        const fresh = yield* verifying(token, signer.jwks)
        assert.strictEqual(fresh._tag, "Success")

        yield* TestClock.adjust(Duration.seconds(expiresAt + 1))
        const stale = yield* verifying(token, signer.jwks)
        assert.strictEqual(stale._tag, "Failure")
      })))
  })

  describe("isRedirectResponse", () => {
    it("catches the redirect in every shape a runtime reports it", () => {
      for (const status of [301, 302, 303, 307, 308]) {
        assert.isTrue(isRedirectResponse({ status }), `${status}`)
      }
      // Spec-compliant runtimes hand back an opaque filtered response instead.
      assert.isTrue(isRedirectResponse({ status: 0, type: "opaqueredirect" }))
      assert.isTrue(isRedirectResponse({ status: 0 }))

      assert.isFalse(isRedirectResponse({ status: 200, type: "basic" }))
      assert.isFalse(isRedirectResponse({ status: 404 }))
    })
  })
})
