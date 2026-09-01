import { assert, describe, layer } from "@effect/vitest"
import { Duration, Effect, Layer, Redacted, type Result } from "effect"
import { TestClock } from "effect/testing"
import type { JWTPayload } from "jose"
import { OAuthFlow } from "../../src/oauth/Flow.js"
import { AuthTest, MockProvider } from "../../src/testing/index.js"
import { testName, uniqueEmail } from "../fixtures.js"

/**
 * One stubbed provider for the whole block, which is why the block is
 * sequential: every test replaces the token endpoint, because the `id_token` it
 * mints has to echo the nonce that its own `start` generated.
 */
const server = MockProvider.mockServer()

/**
 * The deployment: one OIDC provider, whose key set is the block's signer.
 *
 * There is no second, keyless provider here any more. "Declares an issuer but
 * publishes no keys" used to be a configuration this file had to prove failed
 * closed at runtime; `oidc.keys` is now a required union, so it is a
 * configuration that cannot be written down — the guarantee moved from a test
 * to the type, and the runtime arm that enforced it is gone with it.
 *
 * `Layer.unwrap` because the provider list is data and the key set is a
 * service — the signer has to exist before the providers can be described, and
 * generating its key pair is the one expensive thing in this file.
 */
const oidcLayer = Layer.unwrap(
  Effect.gen(function* () {
    const signer = yield* MockProvider.IdTokenSigner
    return AuthTest.layerFlow({
      providers: [MockProvider.oidcProvider(signer.jwks)],
      fetch: server.fetch,
      baseUrl: "https://app.example.com"
    })
  })
).pipe(Layer.provideMerge(MockProvider.IdTokenSigner.layer))

/**
 * Every test here follows the same shape: start the flow, read the nonce out of
 * the authorization URL, mint an `id_token` for it, and see what the callback
 * makes of it. `claims` and `sign` are what each test bends.
 */
const runOidc = Effect.fnUntraced(function* (options?: {
  readonly providerId?: string | undefined
  readonly claims?: ((nonce: string | null, email: string) => JWTPayload) | undefined
  readonly sign?: MockProvider.SignOptions | undefined
  readonly omitIdToken?: boolean | undefined
}) {
  const signer = yield* MockProvider.IdTokenSigner
  const flow = yield* OAuthFlow
  const providerId = options?.providerId ?? "oidc"
  // The block shares one database: every identity it provisions is its own.
  const email = uniqueEmail("oidc")

  yield* Effect.sync(() => {
    server.clear()
    server.on(MockProvider.userInfoUrl, () => MockProvider.json({ sub: "unused" }))
  })

  const started = yield* flow.start({ providerId })
  const nonce = MockProvider.paramsOf(started.url).get("nonce")

  yield* Effect.sync(() =>
    server.on(MockProvider.tokenUrl, async () => {
      const claims = options?.claims?.(nonce, email) ?? {
        sub: email,
        email,
        email_verified: true,
        name: testName,
        nonce
      }
      const idToken = await signer.sign(claims, options?.sign)
      return MockProvider.json({
        access_token: "provider-access-token",
        token_type: "bearer",
        expires_in: 3600,
        ...(options?.omitIdToken === true ? {} : { id_token: idToken })
      })
    })
  )

  return {
    nonce,
    email,
    result: yield* Effect.result(
      flow.callback({
        providerId,
        code: "authorization-code",
        state: Redacted.value(started.state)
      })
    )
  }
})

/**
 * The callback refused the token, and said so as an `OAuthProviderError`.
 *
 * The parameter is a `Result` over any failure that carries a tag and a reason,
 * so the narrowing is the `Result` union's own rather than a cast.
 */
const assertIdTokenInvalid = (
  result: Result.Result<unknown, { readonly _tag: string; readonly reason?: string | undefined }>
) => {
  assert.strictEqual(result._tag, "Failure")
  if (result._tag !== "Failure") return
  assert.strictEqual(result.failure._tag, "OAuthProviderError")
  assert.strictEqual(result.failure.reason, "IdTokenInvalid")
}

describe.sequential("oauth/Flow (OIDC)", () => {
  layer(oidcLayer)((it) => {
    it.effect("mints a nonce, verifies the id_token and takes the identity from its claims", () =>
      Effect.gen(function* () {
        const { email, nonce, result } = yield* runOidc()
        assert.isNotNull(nonce)
        assert.strictEqual(result._tag, "Success")
        if (result._tag !== "Success") return
        const done = result.success
        assert.strictEqual(done.user.email, email)
        assert.isTrue(done.user.emailVerified)
        // An OIDC provider's accounts are stored under its real issuer, not the
        // synthetic `local:oauth:` one a plain OAuth2 provider gets.
        assert.strictEqual(done.account.issuer, MockProvider.providerOrigin)
        assert.strictEqual(done.account.accountId, email)
        assert.isNotNull(done.token)
      })
    )

    it.effect("refuses a provider that returned no id_token at all", () =>
      Effect.gen(function* () {
        const { result } = yield* runOidc({ omitIdToken: true })
        assertIdTokenInvalid(result)
      })
    )

    it.effect("refuses a token from another issuer", () =>
      Effect.gen(function* () {
        const { result } = yield* runOidc({ sign: { issuer: "https://evil.test" } })
        assertIdTokenInvalid(result)
      })
    )

    it.effect("refuses a token minted for another audience", () =>
      Effect.gen(function* () {
        const { result } = yield* runOidc({ sign: { audience: "somebody-elses-client" } })
        assertIdTokenInvalid(result)
      })
    )

    it.effect("refuses a token that has expired by the Effect clock", () =>
      // A clock of this test's own: the `exp` below is an absolute instant, so
      // it must be read against a clock nothing else in the block has moved.
      // The state row is unaffected — `Flow` issues and consumes it under the
      // context its layer was built with, which is the block's clock.
      AuthTest.freshClock(
        Effect.gen(function* () {
          yield* TestClock.adjust(Duration.seconds(61))
          const { result } = yield* runOidc({ sign: { expiresAt: 60 } })
          assertIdTokenInvalid(result)
        })
      )
    )

    it.effect("refuses a token whose nonce is somebody else's", () =>
      Effect.gen(function* () {
        const { result } = yield* runOidc({
          claims: (_nonce, email) => ({ sub: email, email, nonce: "a-nonce-from-another-session" })
        })
        assertIdTokenInvalid(result)
      })
    )

    it.effect("refuses a token that carries no nonce, which is what a replay looks like", () =>
      Effect.gen(function* () {
        const { result } = yield* runOidc({
          claims: (_nonce, email) => ({ sub: email, email })
        })
        assertIdTokenInvalid(result)
      })
    )

    it.effect("refuses a token with no subject", () =>
      Effect.gen(function* () {
        const { result } = yield* runOidc({
          claims: (nonce, email) => ({ email, nonce })
        })
        assertIdTokenInvalid(result)
      })
    )
  })
})
