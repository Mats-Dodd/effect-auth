import { assert, describe, layer } from "@effect/vitest"
import { DateTime, Duration, Effect, Layer, Redacted } from "effect"
import { TestClock } from "effect/testing"
import type { JWTPayload } from "jose"
import { exportJWK, generateKeyPair, SignJWT } from "jose"
import { isRedirectResponse, Jwks, layerJwks, verify } from "../../src/oauth/IdToken.js"
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
): Effect.Effect<Redacted.Redacted> =>
  Effect.map(
    // The signer is `jose`, so the promise is the boundary; the redaction is
    // this side of it.
    Effect.promise(() => signer.sign(payload, options)),
    (token) => Redacted.make(token)
  )

const verifying = (
  token: Redacted.Redacted,
  keys: MockProvider.IdTokenSignerService["jwks"],
  overrides?: {
    readonly issuer?: string
    readonly audience?: string
    readonly nonce?: string | null
  }
) =>
  Effect.result(
    verify({
      providerId: "google",
      token,
      issuer: overrides?.issuer ?? issuer,
      audience: overrides?.audience ?? audience,
      keys,
      nonce: overrides?.nonce ?? null,
      algorithms: ["RS256"]
    })
  )

/**
 * One key pair for the whole file: verification is network-free because
 * `createLocalJWKSet` answers from the key set in memory, which is the whole
 * point of `verify` taking a `KeyResolver` rather than a URL — and generating
 * that pair costs tens of milliseconds, so the block builds it once.
 */
layer(MockProvider.IdTokenSigner.layer)("oauth/IdToken", (it) => {
  describe("verify", () => {
    it.effect("accepts a well-formed token and projects its claims", () =>
      Effect.gen(function* () {
        const signer = yield* MockProvider.IdTokenSigner
        const token = yield* sign(
          signer,
          {
            sub: "provider-subject",
            email: "ada@example.com",
            email_verified: true,
            name: "Ada Lovelace",
            picture: "https://cdn.test/ada.png",
            nonce: "the-nonce"
          },
          { expiresAt }
        )

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
      })
    )

    it.effect("reads the string spelling of email_verified, and defaults it to false", () =>
      Effect.gen(function* () {
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
      })
    )

    it.effect("refuses a token signed by a key the provider does not publish", () =>
      Effect.gen(function* () {
        const signer = yield* MockProvider.IdTokenSigner
        // The one place a second key pair is worth its cost: a forgery is a
        // token that verifies perfectly against the wrong key set.
        const forger = yield* MockProvider.makeIdTokenSigner
        const forged = yield* sign(forger, { sub: "s" }, { expiresAt })

        const result = yield* verifying(forged, signer.jwks)
        assert.strictEqual(result._tag, "Failure")
        if (result._tag === "Failure") {
          assert.strictEqual(result.failure._tag, "OAuthProviderError")
          assert.strictEqual(result.failure.reason, "IdTokenInvalid")
          assert.strictEqual(result.failure.providerId, "google")
        }
      })
    )

    it.effect("refuses another issuer's token", () =>
      Effect.gen(function* () {
        const signer = yield* MockProvider.IdTokenSigner
        const token = yield* sign(signer, { sub: "s" }, { issuer: "https://evil.test", expiresAt })
        const result = yield* verifying(token, signer.jwks)
        assert.strictEqual(result._tag, "Failure")
      })
    )

    it.effect("refuses a token minted for another audience", () =>
      Effect.gen(function* () {
        const signer = yield* MockProvider.IdTokenSigner
        const token = yield* sign(signer, { sub: "s" }, { audience: "someone-elses-client", expiresAt })
        const result = yield* verifying(token, signer.jwks)
        assert.strictEqual(result._tag, "Failure")
      })
    )

    it.effect("refuses a token with no sub", () =>
      Effect.gen(function* () {
        const signer = yield* MockProvider.IdTokenSigner
        const token = yield* sign(signer, { email: "ada@example.com" }, { expiresAt })
        const result = yield* verifying(token, signer.jwks)
        assert.strictEqual(result._tag, "Failure")
      })
    )

    it.effect("refuses a token with no exp, however well signed", () =>
      Effect.gen(function* () {
        const signer = yield* MockProvider.IdTokenSigner
        const token = yield* sign(signer, { sub: "s" }, { expiresAt: null })
        const result = yield* verifying(token, signer.jwks)
        assert.strictEqual(result._tag, "Failure")
      })
    )

    it.effect("refuses a token whose nonce is absent or wrong when one was minted", () =>
      Effect.gen(function* () {
        const signer = yield* MockProvider.IdTokenSigner

        const withoutNonce = yield* sign(signer, { sub: "s" }, { expiresAt })
        const absent = yield* verifying(withoutNonce, signer.jwks, { nonce: "the-nonce" })
        assert.strictEqual(absent._tag, "Failure")

        const otherNonce = yield* sign(signer, { sub: "s", nonce: "somebody-elses" }, { expiresAt })
        const wrong = yield* verifying(otherNonce, signer.jwks, { nonce: "the-nonce" })
        assert.strictEqual(wrong._tag, "Failure")
      })
    )

    it.effect("expires by the Effect clock", () =>
      // The block's `TestClock` is shared: this test moves one of its own, so
      // that the hour it burns is not also burnt by its siblings.
      AuthTest.freshClock(
        Effect.gen(function* () {
          const signer = yield* MockProvider.IdTokenSigner
          const token = yield* sign(signer, { sub: "s" }, { expiresAt })

          const fresh = yield* verifying(token, signer.jwks)
          assert.strictEqual(fresh._tag, "Success")

          yield* TestClock.adjust(Duration.seconds(expiresAt + 1))
          const stale = yield* verifying(token, signer.jwks)
          assert.strictEqual(stale._tag, "Failure")
        })
      )
    )
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

  describe("Jwks", () => {
    const jwksUrl = `${MockProvider.providerOrigin}/jwks`

    /**
     * A key pair, the JWKS a provider would publish it in, and a token signed
     * with it. Separate from the block's signer on purpose: the point here is
     * the *fetch*, so the keys have to arrive over the stubbed transport rather
     * than be handed in as a resolver.
     */
    const published = Effect.gen(function* () {
      const pair = yield* Effect.promise(() => generateKeyPair("RS256", { extractable: true }))
      const jwk = yield* Effect.promise(() => exportJWK(pair.publicKey))
      const token = yield* Effect.promise(() =>
        new SignJWT({ sub: "remote-subject" })
          .setProtectedHeader({ alg: "RS256", kid: "remote-k1" })
          .setIssuer(issuer)
          .setAudience(audience)
          .setExpirationTime(expiresAt)
          .sign(pair.privateKey)
      )
      return {
        body: { keys: [{ ...jwk, kid: "remote-k1", alg: "RS256", use: "sig" }] },
        token: Redacted.make(token)
      }
    })

    /** The service over a stubbed transport, wrapped exactly as the flow wraps it. */
    const over = (fetch: typeof globalThis.fetch) => layerJwks.pipe(Layer.provide(MockProvider.safeHttpLayer(fetch)))

    // `Jwks` is a cache and every test below counts the fetches that reached
    // the endpoint, so each gets a block — and a stubbed endpoint — of its own.
    const onceServer = MockProvider.mockServer()
    it.layer(over(onceServer.fetch))((it) => {
      it.effect("fetches the key set over the HttpClient, and fetches it once", () =>
        Effect.gen(function* () {
          const { body, token } = yield* published
          onceServer.on(jwksUrl, () => MockProvider.json(body))

          const jwks = yield* Jwks
          const keys = yield* jwks.keys(jwksUrl)
          const result = yield* Effect.result(
            verify({
              providerId: "remote",
              token,
              issuer,
              audience,
              keys,
              nonce: null,
              algorithms: ["RS256"]
            })
          )
          assert.strictEqual(result._tag, "Success")
          if (result._tag === "Success") assert.strictEqual(result.success.subject, "remote-subject")

          // The second provider callback of the day reuses the cached key set.
          yield* jwks.keys(jwksUrl)
          assert.strictEqual(onceServer.to(jwksUrl).length, 1)
          // And it went out with redirects refused, like every other OAuth call.
          assert.strictEqual(onceServer.to(jwksUrl)[0]?.redirect, "manual")
        })
      )
    })

    const rotationServer = MockProvider.mockServer()
    it.layer(over(rotationServer.fetch))((it) => {
      it.effect("refetches a rotated key set when a token names an unknown kid", () =>
        Effect.gen(function* () {
          const { body: oldBody } = yield* published
          // The provider's next key: not in the published set the cache warmed
          // up on, exactly what an emergency rotation looks like.
          const rotatedPair = yield* Effect.promise(() => generateKeyPair("RS256", { extractable: true }))
          const rotatedJwk = yield* Effect.promise(() => exportJWK(rotatedPair.publicKey))
          const rotatedToken = yield* Effect.promise(() =>
            new SignJWT({ sub: "rotated-subject" })
              .setProtectedHeader({ alg: "RS256", kid: "rotated-k2" })
              .setIssuer(issuer)
              .setAudience(audience)
              .setExpirationTime(expiresAt)
              .sign(rotatedPair.privateKey)
          )
          const rotated = {
            body: { keys: [{ ...rotatedJwk, kid: "rotated-k2", alg: "RS256", use: "sig" }] },
            token: Redacted.make(rotatedToken)
          }

          // Warm the cache on the pre-rotation set...
          rotationServer.on(jwksUrl, () => MockProvider.json(oldBody))
          const jwks = yield* Jwks
          const keys = yield* jwks.keys(jwksUrl)

          // ...then rotate: the endpoint now serves the new set, and the token
          // is signed with a kid the cached resolver has never seen.
          rotationServer.on(jwksUrl, () => MockProvider.json(rotated.body))
          const claims = yield* verify({
            providerId: "remote",
            token: rotated.token,
            issuer,
            audience,
            keys,
            nonce: null,
            algorithms: ["RS256"],
            freshKeys: Effect.orDie(jwks.refresh(jwksUrl))
          })
          assert.strictEqual(claims.subject, "rotated-subject")
          assert.strictEqual(rotationServer.to(jwksUrl).length, 2)

          // Inside the cooldown a second refresh is served the same fresh set —
          // an invented kid cannot turn callbacks into a fetch storm.
          yield* jwks.refresh(jwksUrl)
          assert.strictEqual(rotationServer.to(jwksUrl).length, 2)
        })
      )
    })

    const redirectServer = MockProvider.mockServer()
    it.layer(over(redirectServer.fetch))((it) => {
      it.effect("refuses a JWKS endpoint that answers with a redirect", () => {
        redirectServer.on(jwksUrl, () => MockProvider.redirect("http://169.254.169.254/latest/meta-data/"))
        return Effect.gen(function* () {
          const jwks = yield* Jwks
          const result = yield* Effect.result(jwks.keys(jwksUrl))
          assert.strictEqual(result._tag, "Failure")
          if (result._tag === "Failure") assert.strictEqual(result.failure._tag, "JwksUnavailable")
          // The hop was never taken.
          assert.isUndefined(
            redirectServer.requests.find((request) => request.url.startsWith("http://169.254.169.254"))
          )
        })
      })
    })

    const recoveryServer = MockProvider.mockServer()
    it.layer(over(recoveryServer.fetch))((it) => {
      it.effect("caches a key set but never a failure", () => {
        recoveryServer.on(jwksUrl, () => MockProvider.json({ message: "no" }, 503))
        return Effect.gen(function* () {
          const { body } = yield* published
          const jwks = yield* Jwks

          const down = yield* Effect.result(jwks.keys(jwksUrl))
          assert.strictEqual(down._tag, "Failure")

          // A provider that was unreachable once is asked again on the next
          // callback rather than refused for the whole cache lifetime.
          recoveryServer.on(jwksUrl, () => MockProvider.json(body))
          const recovered = yield* Effect.result(jwks.keys(jwksUrl))
          assert.strictEqual(recovered._tag, "Success")
          assert.strictEqual(recoveryServer.to(jwksUrl).length, 2)
        })
      })
    })

    const malformedServer = MockProvider.mockServer()
    it.layer(over(malformedServer.fetch))((it) => {
      it.effect("refuses a body that is not a key set", () => {
        malformedServer.on(jwksUrl, () => MockProvider.json({ keys: "not a list" }))
        return Effect.gen(function* () {
          const jwks = yield* Jwks
          const result = yield* Effect.result(jwks.keys(jwksUrl))
          assert.strictEqual(result._tag, "Failure")
        })
      })
    })
  })
})
