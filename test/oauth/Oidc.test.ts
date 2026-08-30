import { assert, describe, it } from "@effect/vitest"
import { Duration, Effect, Redacted } from "effect"
import { TestClock } from "effect/testing"
import type { JWTPayload } from "jose"
import { OAuthFlow } from "../../src/oauth/Flow.js"
import type { OAuthProviderConfig } from "../../src/oauth/Provider.js"
import {
  flowLayer,
  idTokenSigner,
  json,
  mockServer,
  oidcProvider,
  paramsOf,
  providerOrigin,
  testTimeout,
  tokenUrl,
  userInfoUrl
} from "./harness.js"

/**
 * Every test here follows the same shape: start the flow, read the nonce out of
 * the authorization URL, mint an `id_token` for it, and see what the callback
 * makes of it. `claims` and `options` are what each test bends.
 */
const runOidc = (options?: {
  readonly provider?: (keys: OAuthProviderConfig["jwks"]) => OAuthProviderConfig
  readonly claims?: (nonce: string | null) => JWTPayload
  readonly sign?: {
    readonly issuer?: string | undefined
    readonly audience?: string | undefined
    readonly expiresAt?: number | undefined
  } | undefined
  readonly omitIdToken?: boolean | undefined
  readonly advance?: Duration.Duration | undefined
}) =>
  Effect.gen(function*() {
    const signer = yield* idTokenSigner
    const server = mockServer()
    server.on(userInfoUrl, () => json({ sub: "unused" }))
    const provider = (options?.provider ?? ((keys) => oidcProvider(keys)))(signer.jwks)

    const program = Effect.gen(function*() {
      const flow = yield* OAuthFlow
      const started = yield* flow.start({ providerId: provider.id })
      const nonce = paramsOf(started.url).get("nonce")

      server.on(tokenUrl, async () => {
        const claims = options?.claims?.(nonce) ??
          {
            sub: "google-subject-1",
            email: "ada@example.com",
            email_verified: true,
            name: "Ada Lovelace",
            nonce
          }
        const idToken = await signer.sign(claims, options?.sign)
        return json({
          access_token: "provider-access-token",
          token_type: "bearer",
          expires_in: 3600,
          ...(options?.omitIdToken === true ? {} : { id_token: idToken })
        })
      })

      if (options?.advance !== undefined) yield* TestClock.adjust(options.advance)

      return {
        nonce,
        result: yield* Effect.result(flow.callback({
          providerId: provider.id,
          code: "authorization-code",
          state: Redacted.value(started.state)
        }))
      }
    })

    return yield* Effect.provide(
      program,
      flowLayer({ providers: [provider], fetch: server.fetch })
    )
  })

const assertIdTokenInvalid = (result: { readonly _tag: string; readonly failure?: unknown }) => {
  assert.strictEqual(result._tag, "Failure")
  const failure = result.failure as { _tag?: string; reason?: string } | undefined
  assert.strictEqual(failure?._tag, "OAuthProviderError")
  assert.strictEqual(failure?.reason, "IdTokenInvalid")
}

describe("oauth/Flow (OIDC)", () => {
  it.effect(
    "mints a nonce, verifies the id_token and takes the identity from its claims",
    () =>
      Effect.gen(function*() {
        const { nonce, result } = yield* runOidc()
        assert.isNotNull(nonce)
        assert.strictEqual(result._tag, "Success")
        if (result._tag !== "Success") return
        const done = result.success
        assert.strictEqual(done.user.email, "ada@example.com")
        assert.isTrue(done.user.emailVerified)
        // An OIDC provider's accounts are stored under its real issuer, not the
        // synthetic `local:oauth:` one a plain OAuth2 provider gets.
        assert.strictEqual(done.account.issuer, providerOrigin)
        assert.strictEqual(done.account.accountId, "google-subject-1")
        assert.isNotNull(done.token)
      }),
    testTimeout
  )

  it.effect(
    "refuses a provider that returned no id_token at all",
    () =>
      Effect.gen(function*() {
        const { result } = yield* runOidc({ omitIdToken: true })
        assertIdTokenInvalid(result)
      }),
    testTimeout
  )

  it.effect(
    "refuses a token from another issuer",
    () =>
      Effect.gen(function*() {
        const { result } = yield* runOidc({ sign: { issuer: "https://evil.test" } })
        assertIdTokenInvalid(result)
      }),
    testTimeout
  )

  it.effect(
    "refuses a token minted for another audience",
    () =>
      Effect.gen(function*() {
        const { result } = yield* runOidc({ sign: { audience: "somebody-elses-client" } })
        assertIdTokenInvalid(result)
      }),
    testTimeout
  )

  it.effect(
    "refuses a token that has expired by the Effect clock",
    () =>
      Effect.gen(function*() {
        const { result } = yield* runOidc({
          sign: { expiresAt: 60 },
          advance: Duration.seconds(61)
        })
        assertIdTokenInvalid(result)
      }),
    testTimeout
  )

  it.effect(
    "refuses a token whose nonce is somebody else's",
    () =>
      Effect.gen(function*() {
        const { result } = yield* runOidc({
          claims: () => ({ sub: "s", email: "ada@example.com", nonce: "a-nonce-from-another-session" })
        })
        assertIdTokenInvalid(result)
      }),
    testTimeout
  )

  it.effect(
    "refuses a token that carries no nonce, which is what a replay looks like",
    () =>
      Effect.gen(function*() {
        const { result } = yield* runOidc({
          claims: () => ({ sub: "s", email: "ada@example.com" })
        })
        assertIdTokenInvalid(result)
      }),
    testTimeout
  )

  it.effect(
    "refuses a token with no subject",
    () =>
      Effect.gen(function*() {
        const { result } = yield* runOidc({
          claims: (nonce) => ({ email: "ada@example.com", nonce })
        })
        assertIdTokenInvalid(result)
      }),
    testTimeout
  )

  it.effect(
    "fails closed when the provider declares an issuer but publishes no keys",
    () =>
      Effect.gen(function*() {
        const { result } = yield* runOidc({
          provider: () => {
            const { jwks: _jwks, ...rest } = oidcProvider(undefined)
            return { ...rest, id: "oidc" } satisfies OAuthProviderConfig
          }
        })
        assertIdTokenInvalid(result)
      }),
    testTimeout
  )
})
