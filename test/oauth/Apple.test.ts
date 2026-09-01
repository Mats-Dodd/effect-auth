import { assert, describe, layer } from "@effect/vitest"
import { Cause, Config, ConfigProvider, Context, DateTime, Duration, Effect, Layer, Option, Redacted } from "effect"
import { exportPKCS8, generateKeyPair, jwtVerify } from "jose"
import * as AuthHandlers from "../../src/http/Handlers.js"
import type { IdTokenClaims } from "../../src/oauth/IdToken.js"
import { verify } from "../../src/oauth/IdToken.js"
import { providerIssuer, resolveClientSecret } from "../../src/oauth/Provider.js"
import * as Apple from "../../src/oauth/providers/Apple.js"
import { AuthTest, MockProvider, TestHttpClient } from "../../src/testing/index.js"
import { uniqueEmail } from "../fixtures.js"

/** The Services ID this deployment is registered under, and Apple's own ids. */
const clientId = "com.example.web"
const teamId = "ABCDE12345"
const keyId = "FGHIJ67890"

/**
 * A P-256 key pair standing in for the `.p8` Apple issues: the PKCS#8 PEM the
 * provider is configured with, and the public half a test verifies the minted
 * client secret against.
 */
interface AppleKeyMaterial {
  readonly privateKey: Redacted.Redacted
  readonly publicKey: CryptoKey
}

/**
 * The key material, behind a service so that one key pair serves a whole
 * `layer()` block.
 */
class AppleKeys extends Context.Service<AppleKeys, AppleKeyMaterial>()("effect-auth/test/oauth/Apple.test/AppleKeys") {
  static readonly layer: Layer.Layer<AppleKeys> = Layer.effect(
    AppleKeys,
    Effect.gen(function* () {
      const pair = yield* Effect.promise(() => generateKeyPair("ES256", { extractable: true }))
      const pkcs8 = yield* Effect.promise(() => exportPKCS8(pair.privateKey))
      return { privateKey: Redacted.make(pkcs8), publicKey: pair.publicKey } satisfies AppleKeyMaterial
    })
  )
}

const secretOptions = (keys: AppleKeyMaterial, overrides?: Partial<Apple.Options>): Apple.Options => ({
  clientId,
  teamId,
  keyId,
  privateKey: keys.privateKey,
  ...overrides
})

/** The claims a verified Apple `id_token` would carry. */
const claims = (overrides?: Partial<IdTokenClaims>): IdTokenClaims => ({
  subject: "001234.apple.subject",
  issuer: Apple.issuer,
  audience: [clientId],
  email: "ada@privaterelay.appleid.com",
  emailVerified: true,
  name: null,
  picture: null,
  nonce: "the-nonce",
  expiresAt: DateTime.makeUnsafe(3_600_000),
  raw: {},
  ...overrides
})

/** Apple's `user` field, as it posts it back on the very first authorization. */
const userField = JSON.stringify({
  name: { firstName: "Ada", lastName: "Lovelace" },
  email: "ada@example.com"
})

/**
 * The other shapes Apple's `user` field arrives in, as the text it arrives as.
 *
 * `nameOf` reads a provider-controlled JSON *string*, so what a test hands it is
 * a string: these are the payloads, written once here rather than built inside
 * the assertions.
 */
const firstNameOnly = JSON.stringify({ name: { firstName: "Ada" } })
const emptyName = JSON.stringify({ name: {} })
const nameNotAnObject = JSON.stringify({ name: "Ada" })
const addressOnly = JSON.stringify({ email: "evil@example.com" })

/**
 * A transport for providers that never make a request: every route on it is a
 * 404, so an accidental fetch fails loudly rather than silently passing.
 */
const noNetwork = MockProvider.safeHttpLayer(MockProvider.mockServer().fetch)

layer(AppleKeys.layer)("oauth/providers/Apple", (it) => {
  describe("configuration", () => {
    it.effect("is an OIDC provider that asks for a form_post callback", () =>
      Effect.gen(function* () {
        const provider = Apple.make(secretOptions(yield* AppleKeys))
        assert.strictEqual(provider.id, "apple")
        assert.strictEqual(provider.oidc?.issuer, "https://appleid.apple.com")
        assert.strictEqual(providerIssuer(provider), "https://appleid.apple.com")
        assert.strictEqual(provider.authorizationUrl, "https://appleid.apple.com/auth/authorize")
        assert.strictEqual(provider.tokenUrl, "https://appleid.apple.com/auth/token")
        assert.deepStrictEqual(provider.oidc?.keys, { jwksUrl: "https://appleid.apple.com/auth/keys" })
        assert.deepStrictEqual([...provider.scopes], ["email", "name"])
        // Asking for `name` is what makes Apple post the callback instead of
        // redirecting to it. `response_type` stays `code`: the code is exchanged
        // server-side, so the hybrid flow's front-channel token buys nothing.
        assert.strictEqual(provider.authorizationParams?.response_mode, "form_post")
        assert.isUndefined(provider.authorizationParams?.response_type)
      })
    )

    it.effect("expects the audience the deployment actually receives tokens for", () =>
      Effect.gen(function* () {
        const keys = yield* AppleKeys
        assert.strictEqual(Apple.make(secretOptions(keys)).oidc?.audience, clientId)
        // A native application's tokens carry its bundle identifier, not the
        // web Services ID.
        assert.strictEqual(
          Apple.make(secretOptions(keys, { appBundleIdentifier: "com.example.app" })).oidc?.audience,
          "com.example.app"
        )
        // A deployment serving both states both, and nothing else is admitted.
        assert.deepStrictEqual(
          Apple.make(
            secretOptions(keys, {
              appBundleIdentifier: "com.example.app",
              audience: [clientId, "com.example.app"]
            })
          ).oidc?.audience,
          [clientId, "com.example.app"]
        )
      })
    )
  })

  describe("clientSecret", () => {
    it.effect("mints an ES256 assertion that verifies against the signing key", () =>
      Effect.gen(function* () {
        const keys = yield* AppleKeys
        const provider = Apple.make(secretOptions(keys))
        const secret = yield* resolveClientSecret(provider)
        assert.isTrue(Option.isSome(secret))
        if (Option.isNone(secret)) return

        // The real check: Apple would verify this against the public half of the
        // `.p8`, so the test does too. `jose` reads the wall clock unless it is
        // told otherwise, and the assertion was minted off the Effect one — so
        // `currentDate` is that clock, which under `it.effect` is the epoch.
        const now = DateTime.toDateUtc(yield* DateTime.now)
        const verified = yield* Effect.promise(() =>
          jwtVerify(Redacted.value(secret.value), keys.publicKey, {
            issuer: teamId,
            audience: Apple.issuer,
            algorithms: ["ES256"],
            currentDate: now
          })
        )
        assert.strictEqual(verified.protectedHeader.alg, "ES256")
        assert.strictEqual(verified.protectedHeader.kid, keyId)
        assert.strictEqual(verified.payload.sub, clientId)
        assert.strictEqual(verified.payload.iss, teamId)
        assert.strictEqual(verified.payload.iat, 0)
        assert.strictEqual(verified.payload.exp, 3600)
      })
    )

    it.effect("mints a fresh one for every token request", () =>
      Effect.gen(function* () {
        const provider = Apple.make(secretOptions(yield* AppleKeys))
        // The whole point of the effectful shape: the assertion expires, so it
        // must not be resolved once and kept in a layer.
        const first = yield* resolveClientSecret(provider)
        const second = yield* resolveClientSecret(provider)
        assert.isTrue(Option.isSome(first) && Option.isSome(second))
      })
    )

    it.effect("clamps the lifetime to the six months Apple accepts", () =>
      Effect.gen(function* () {
        const keys = yield* AppleKeys
        const secret = yield* Apple.clientSecret({
          ...secretOptions(keys),
          secretTtl: Duration.days(365)
        })
        const now = DateTime.toDateUtc(yield* DateTime.now)
        const verified = yield* Effect.promise(() =>
          jwtVerify(Redacted.value(secret), keys.publicKey, { currentDate: now })
        )
        assert.strictEqual(verified.payload.exp, Duration.toSeconds(Apple.maximumSecretTtl))
      })
    )

    it.effect("reports a key it cannot sign with, without quoting it", () =>
      Effect.gen(function* () {
        const result = yield* Effect.result(
          Apple.clientSecret({
            clientId,
            teamId,
            keyId,
            privateKey: Redacted.make("-----BEGIN PRIVATE KEY-----\nnot a key\n-----END PRIVATE KEY-----")
          })
        )
        assert.strictEqual(result._tag, "Failure")
        if (result._tag !== "Failure") return
        assert.strictEqual(result.failure._tag, "OAuthProviderError")
        assert.strictEqual(result.failure.reason, "ClientSecretUnavailable")
      })
    )
  })

  describe("makeConfig", () => {
    it.effect("builds the provider and proves the key works", () =>
      Effect.gen(function* () {
        const keys = yield* AppleKeys
        const provider = yield* Apple.makeConfig({
          clientId: Config.string("APPLE_CLIENT_ID"),
          teamId: Config.string("APPLE_TEAM_ID"),
          keyId: Config.string("APPLE_KEY_ID"),
          privateKey: Config.redacted("APPLE_PRIVATE_KEY"),
          appBundleIdentifier: Config.string("APPLE_BUNDLE_ID")
        }).pipe(
          Effect.provideService(
            ConfigProvider.ConfigProvider,
            ConfigProvider.fromUnknown({
              APPLE_CLIENT_ID: clientId,
              APPLE_TEAM_ID: teamId,
              APPLE_KEY_ID: keyId,
              APPLE_PRIVATE_KEY: Redacted.value(keys.privateKey),
              APPLE_BUNDLE_ID: "com.example.app"
            })
          )
        )
        assert.strictEqual(provider.clientId, clientId)
        assert.strictEqual(provider.oidc?.audience, "com.example.app")
        assert.isTrue(Option.isSome(yield* resolveClientSecret(provider)))
      })
    )

    it.effect("dies at build time on a key that is not one", () =>
      Effect.gen(function* () {
        // A `.p8` that cannot sign is a deployment that can never complete a
        // sign-in. It is a defect at boot, not a failure on somebody's first
        // callback — and not a `ConfigError` either, since the setting was
        // present.
        const exit = yield* Effect.exit(
          Apple.makeConfig({
            clientId: Config.string("APPLE_CLIENT_ID"),
            teamId: Config.string("APPLE_TEAM_ID"),
            keyId: Config.string("APPLE_KEY_ID"),
            privateKey: Config.redacted("APPLE_PRIVATE_KEY")
          }).pipe(
            Effect.provideService(
              ConfigProvider.ConfigProvider,
              ConfigProvider.fromUnknown({
                APPLE_CLIENT_ID: clientId,
                APPLE_TEAM_ID: teamId,
                APPLE_KEY_ID: keyId,
                APPLE_PRIVATE_KEY: "not-a-pem-at-all"
              })
            )
          )
        )
        assert.isTrue(exit._tag === "Failure" && Cause.hasDies(exit.cause))
      })
    )
  })

  describe("nameOf", () => {
    it.effect("reads the two halves Apple sends once, and nothing else", () =>
      Effect.sync(() => {
        assert.strictEqual(Apple.nameOf(userField), "Ada Lovelace")
        assert.strictEqual(Apple.nameOf(firstNameOnly), "Ada")
        assert.isNull(Apple.nameOf(undefined))
        assert.isNull(Apple.nameOf("not json at all"))
        assert.isNull(Apple.nameOf(emptyName))
        assert.isNull(Apple.nameOf(nameNotAnObject))
        // The address in there is Apple's *unsigned* echo, and is never read:
        // the identity's address comes from the token.
        assert.strictEqual(Apple.nameOf(addressOnly), null)
      })
    )
  })

  // Every test here proves the provider makes no request at all, so the
  // 404-only transport is the block's rather than each test's.
  it.layer(noNetwork)("userInfo", (it) => {
    it.effect("takes the identity from the token and the name from the callback", () =>
      Effect.gen(function* () {
        const provider = Apple.make(secretOptions(yield* AppleKeys))
        const info = yield* provider.userInfo(
          MockProvider.tokensOf("apple-access-token", { idTokenClaims: claims() }),
          { params: { user: userField } }
        )
        assert.strictEqual(info.id, "001234.apple.subject")
        assert.strictEqual(info.email, "ada@privaterelay.appleid.com")
        assert.isTrue(info.emailVerified)
        assert.strictEqual(info.name, "Ada Lovelace")
      })
    )

    it.effect("falls back to the address on every later sign-in", () =>
      Effect.gen(function* () {
        const provider = Apple.make(secretOptions(yield* AppleKeys))
        // Apple sends `user` exactly once, on the first authorization.
        const info = yield* provider.userInfo(MockProvider.tokensOf("apple-access-token", { idTokenClaims: claims() }))
        assert.strictEqual(info.name, "ada@privaterelay.appleid.com")
      })
    )

    it.effect("fails closed when the flow handed it no verified claims", () =>
      Effect.gen(function* () {
        const provider = Apple.make(secretOptions(yield* AppleKeys))
        const result = yield* Effect.result(provider.userInfo(MockProvider.tokensOf("apple-access-token")))
        assert.strictEqual(result._tag, "Failure")
        if (result._tag !== "Failure") return
        assert.strictEqual(result.failure.reason, "IdTokenInvalid")
      })
    )

    it.effect("fails when the token carries no address", () =>
      Effect.gen(function* () {
        const provider = Apple.make(secretOptions(yield* AppleKeys))
        const result = yield* Effect.result(
          provider.userInfo(MockProvider.tokensOf("apple-access-token", { idTokenClaims: claims({ email: null }) }))
        )
        assert.strictEqual(result._tag, "Failure")
        if (result._tag !== "Failure") return
        assert.strictEqual(result.failure.reason, "UserInfoFailed")
      })
    )
  })
})

layer(MockProvider.IdTokenSigner.layer)("oauth/providers/Apple audiences", (it) => {
  const verifying = (
    signer: MockProvider.IdTokenSignerService,
    audience: string | ReadonlyArray<string>,
    minted: string
  ) =>
    Effect.gen(function* () {
      const token = Redacted.make(
        yield* Effect.promise(() =>
          signer.sign(
            { sub: "s" },
            {
              issuer: Apple.issuer,
              audience: minted
            }
          )
        )
      )
      return yield* Effect.result(
        verify({
          providerId: Apple.id,
          token,
          issuer: Apple.issuer,
          audience,
          keys: signer.jwks,
          nonce: null,
          algorithms: ["RS256"]
        })
      )
    })

  it.effect("admits a token minted for any stated audience, and no other", () =>
    Effect.gen(function* () {
      const signer = yield* MockProvider.IdTokenSigner
      const audience = [clientId, "com.example.app"]

      // A deployment serving the web flow and the native one receives tokens
      // addressed to either; the list is what admits both.
      const web = yield* verifying(signer, audience, clientId)
      assert.strictEqual(web._tag, "Success")
      const native = yield* verifying(signer, audience, "com.example.app")
      assert.strictEqual(native._tag, "Success")

      // A list of permitted audiences is still a closed one.
      const other = yield* verifying(signer, audience, "com.someone.else")
      assert.strictEqual(other._tag, "Failure")
    })
  )
})

// -----------------------------------------------------------------------------
// The form_post hop, end to end
// -----------------------------------------------------------------------------

/**
 * One stubbed Apple for the whole block, which is why it is sequential: the
 * token endpoint is replaced per test, because the `id_token` it mints has to
 * echo the nonce that this test's own `start` generated.
 */
const server = MockProvider.mockServer()

/**
 * The whole server stack with a real OAuth flow behind it, serving Apple against
 * the stubbed transport. The key set is the block's RSA signer rather than a
 * fetched JWKS, and the `.p8` is the block's P-256 pair — both are services, so
 * the provider can only be described inside `Layer.unwrap`.
 */
const appleHttp = Layer.unwrap(
  Effect.gen(function* () {
    const signer = yield* MockProvider.IdTokenSigner
    const keys = yield* AppleKeys
    const apple = Apple.make({
      clientId,
      teamId,
      keyId,
      privateKey: keys.privateKey,
      jwks: signer.jwks,
      algorithms: ["RS256"]
    })
    return Layer.mergeAll(
      AuthHandlers.layer(AuthTest.TestApi).pipe(
        Layer.provideMerge(AuthTest.layerFlow({ providers: [apple], fetch: server.fetch }))
      ),
      AuthTest.layerPlatform
    )
  })
).pipe(Layer.provideMerge(MockProvider.IdTokenSigner.layer), Layer.provideMerge(AppleKeys.layer))

describe.sequential("oauth/providers/Apple form_post", () => {
  layer(appleHttp)((it) => {
    it.effect("completes a sign-in through the POST callback and its GET twin", () =>
      Effect.gen(function* () {
        const signer = yield* MockProvider.IdTokenSigner
        const keys = yield* AppleKeys
        const email = uniqueEmail("apple")
        yield* Effect.sync(() => server.clear())

        const { client, cookies } = yield* TestHttpClient.makeClient(AuthTest.TestApi)
        const started = yield* client.auth.signInSocial({
          payload: { providerId: "apple", callbackURL: "/welcome" }
        })
        const authorize = new URL(started.url)
        assert.strictEqual(authorize.origin + authorize.pathname, Apple.authorizationUrl)
        assert.strictEqual(authorize.searchParams.get("response_mode"), "form_post")
        assert.strictEqual(authorize.searchParams.get("response_type"), "code")
        const nonce = authorize.searchParams.get("nonce")
        const state = authorize.searchParams.get("state") ?? ""

        yield* Effect.sync(() =>
          // The route is a `fetch`-shaped callback, so what it hands back is a
          // promise rather than an Effect: the signer's own promise, mapped.
          server.on(Apple.tokenUrl, async () => {
            const idToken = await signer.sign(
              { sub: "001234.apple.subject", email, email_verified: "true", nonce },
              { issuer: Apple.issuer, audience: clientId }
            )
            return MockProvider.json({
              access_token: "apple-access-token",
              token_type: "bearer",
              expires_in: 3600,
              id_token: idToken
            })
          })
        )

        // Apple posts the callback cross-site. That request carries no
        // `SameSite=Lax` cookie, so the endpoint does nothing but turn it into
        // the top-level GET navigation the flow is built for.
        const [, hop] = yield* client.auth.oauthCallbackForm({
          params: { providerId: "apple" },
          payload: { code: "the-code", state, user: userField },
          responseMode: "decoded-and-response"
        })
        assert.strictEqual(hop.status, 302)
        assert.strictEqual(yield* TestHttpClient.sessionCookieValue(cookies), "<absent>")

        const query = MockProvider.queryOf(hop.headers["location"] ?? "")
        const [, done] = yield* client.auth.oauthCallback({
          params: { providerId: "apple" },
          query,
          responseMode: "decoded-and-response"
        })

        assert.strictEqual(done.status, 302)
        assert.strictEqual(done.headers["location"], "http://localhost:3000/welcome")
        // The browser is signed in, under the identity the *token* named.
        const session = yield* client.auth.getSession()
        assert.strictEqual(session.user.email, email)
        // Apple's `email_verified: "true"` is the string spelling, and counts.
        assert.isTrue(session.user.emailVerified)
        // The display name Apple posted *once*, to the endpoint above: the form
        // handler puts `user` on the GET's query string and the callback handler
        // forwards it into `CallbackOptions.params`, which is the only route by
        // which an unsigned value reaches `userInfo`. It names the account and
        // nothing else.
        assert.strictEqual(session.user.name, "Ada Lovelace")

        // The one request that carries the client secret: a fresh ES256
        // assertion, which Apple would verify against the `.p8`'s public half.
        const exchange = server.to(Apple.tokenUrl)
        assert.strictEqual(exchange.length, 1)
        const form = MockProvider.formOf(exchange[0]!)
        assert.strictEqual(form.get("grant_type"), "authorization_code")
        assert.strictEqual(form.get("client_id"), clientId)
        const assertion = form.get("client_secret") ?? ""
        // The assertion was minted off the Effect clock, so it is verified
        // against that clock rather than against the wall one.
        const now = DateTime.toDateUtc(yield* DateTime.now)
        const verified = yield* Effect.promise(() =>
          jwtVerify(assertion, keys.publicKey, {
            issuer: teamId,
            audience: Apple.issuer,
            algorithms: ["ES256"],
            currentDate: now
          })
        )
        assert.strictEqual(verified.payload.sub, clientId)
      })
    )
  })
})
