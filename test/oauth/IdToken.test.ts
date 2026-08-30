import { assert, describe, it } from "@effect/vitest"
import { DateTime, Duration, Effect, Redacted } from "effect"
import { TestClock } from "effect/testing"
import type { JWTPayload, KeyObject } from "jose"
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } from "jose"
import { isRedirectResponse, verify } from "../../src/oauth/IdToken.js"

const issuer = "https://issuer.test"
const audience = "client-id"

/**
 * A key pair and the local JWKS that admits it. Verification is therefore
 * network-free: `createLocalJWKSet` answers from the key set in memory, which
 * is the whole point of `verify` taking a `KeyResolver` rather than a URL.
 */
const keys = Effect.promise(async () => {
  const pair = await generateKeyPair("RS256", { extractable: true })
  const jwk = await exportJWK(pair.publicKey)
  const resolver = createLocalJWKSet({ keys: [{ ...jwk, kid: "k1", alg: "RS256" }] })
  return { privateKey: pair.privateKey, resolver }
})

const sign = (
  privateKey: CryptoKey | KeyObject,
  payload: JWTPayload,
  options?: { readonly issuer?: string; readonly audience?: string; readonly exp?: number }
) =>
  Effect.promise(async () => {
    let jwt = new SignJWT(payload).setProtectedHeader({ alg: "RS256", kid: "k1" })
      .setIssuer(options?.issuer ?? issuer)
      .setAudience(options?.audience ?? audience)
    if (options?.exp !== undefined) jwt = jwt.setExpirationTime(options.exp)
    return Redacted.make(await jwt.sign(privateKey))
  })

const verifying = (
  token: Redacted.Redacted<string>,
  resolver: ReturnType<typeof createLocalJWKSet>,
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
    keys: resolver,
    nonce: overrides?.nonce ?? null,
    algorithms: ["RS256"]
  }))

/** The one hour after the (test) epoch that every token below expires at. */
const expiresAt = 3600

describe("oauth/IdToken", () => {
  describe("verify", () => {
    it.effect("accepts a well-formed token and projects its claims", () =>
      Effect.gen(function*() {
        const { privateKey, resolver } = yield* keys
        const token = yield* sign(privateKey, {
          sub: "provider-subject",
          email: "ada@example.com",
          email_verified: true,
          name: "Ada Lovelace",
          picture: "https://cdn.test/ada.png",
          nonce: "the-nonce"
        }, { exp: expiresAt })

        const result = yield* verifying(token, resolver, { nonce: "the-nonce" })
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
        const { privateKey, resolver } = yield* keys
        const asString = yield* sign(privateKey, { sub: "s", email_verified: "true" }, { exp: expiresAt })
        const stringy = yield* verifying(asString, resolver)
        assert.strictEqual(stringy._tag, "Success")
        if (stringy._tag === "Success") assert.isTrue(stringy.success.emailVerified)

        const absent = yield* sign(privateKey, { sub: "s" }, { exp: expiresAt })
        const missing = yield* verifying(absent, resolver)
        assert.strictEqual(missing._tag, "Success")
        if (missing._tag === "Success") {
          assert.isFalse(missing.success.emailVerified)
          assert.isNull(missing.success.email)
        }
      }))

    it.effect("refuses a token signed by a key the provider does not publish", () =>
      Effect.gen(function*() {
        const { resolver } = yield* keys
        const other = yield* keys
        const forged = yield* sign(other.privateKey, { sub: "s" }, { exp: expiresAt })

        const result = yield* verifying(forged, resolver)
        assert.strictEqual(result._tag, "Failure")
        if (result._tag === "Failure") {
          assert.strictEqual(result.failure._tag, "OAuthProviderError")
          assert.strictEqual(result.failure.reason, "IdTokenInvalid")
          assert.strictEqual(result.failure.providerId, "google")
        }
      }))

    it.effect("refuses another issuer's token", () =>
      Effect.gen(function*() {
        const { privateKey, resolver } = yield* keys
        const token = yield* sign(privateKey, { sub: "s" }, { issuer: "https://evil.test", exp: expiresAt })
        const result = yield* verifying(token, resolver)
        assert.strictEqual(result._tag, "Failure")
      }))

    it.effect("refuses a token minted for another audience", () =>
      Effect.gen(function*() {
        const { privateKey, resolver } = yield* keys
        const token = yield* sign(privateKey, { sub: "s" }, { audience: "someone-elses-client", exp: expiresAt })
        const result = yield* verifying(token, resolver)
        assert.strictEqual(result._tag, "Failure")
      }))

    it.effect("refuses a token with no sub", () =>
      Effect.gen(function*() {
        const { privateKey, resolver } = yield* keys
        const token = yield* sign(privateKey, { email: "ada@example.com" }, { exp: expiresAt })
        const result = yield* verifying(token, resolver)
        assert.strictEqual(result._tag, "Failure")
      }))

    it.effect("refuses a token with no exp, however well signed", () =>
      Effect.gen(function*() {
        const { privateKey, resolver } = yield* keys
        const token = yield* sign(privateKey, { sub: "s" })
        const result = yield* verifying(token, resolver)
        assert.strictEqual(result._tag, "Failure")
      }))

    it.effect("refuses a token whose nonce is absent or wrong when one was minted", () =>
      Effect.gen(function*() {
        const { privateKey, resolver } = yield* keys

        const withoutNonce = yield* sign(privateKey, { sub: "s" }, { exp: expiresAt })
        const absent = yield* verifying(withoutNonce, resolver, { nonce: "the-nonce" })
        assert.strictEqual(absent._tag, "Failure")

        const otherNonce = yield* sign(privateKey, { sub: "s", nonce: "somebody-elses" }, { exp: expiresAt })
        const wrong = yield* verifying(otherNonce, resolver, { nonce: "the-nonce" })
        assert.strictEqual(wrong._tag, "Failure")
      }))

    it.effect("expires by the Effect clock", () =>
      Effect.gen(function*() {
        const { privateKey, resolver } = yield* keys
        const token = yield* sign(privateKey, { sub: "s" }, { exp: expiresAt })

        const fresh = yield* verifying(token, resolver)
        assert.strictEqual(fresh._tag, "Success")

        yield* TestClock.adjust(Duration.seconds(expiresAt + 1))
        const stale = yield* verifying(token, resolver)
        assert.strictEqual(stale._tag, "Failure")
      }))
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
