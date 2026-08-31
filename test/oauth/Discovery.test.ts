import { assert, describe, it, layer } from "@effect/vitest"
import { DateTime, Effect, Layer, Redacted } from "effect"
import type { DiscoveryError } from "../../src/domain/Errors.js"
import * as OidcDiscovery from "../../src/oauth/Discovery.js"
import { OAuthFlow } from "../../src/oauth/Flow.js"
import { AuthTest, MockProvider } from "../../src/testing/index.js"
import { testName, uniqueEmail } from "../fixtures.js"

const clientId = "mock-client-id"

/**
 * Runs discovery against a stubbed `.well-known`, exactly as a boot would: the
 * transport is the redirect-refusing one every outbound OAuth request uses.
 */
const discover = (
  handler: MockProvider.RouteHandler,
  options?: Partial<OidcDiscovery.Options>,
  routes?: (server: MockProvider.MockServer) => void
) => {
  const server = MockProvider.mockServer()
  server.on(MockProvider.discoveryUrl, handler)
  routes?.(server)
  return {
    server,
    run: Effect.result(OidcDiscovery.make({
      id: "acme",
      issuer: MockProvider.providerOrigin,
      clientId,
      clientSecret: Redacted.make("mock-client-secret"),
      ...options
    })).pipe(Effect.provide(MockProvider.safeHttpLayer(server.fetch)))
  }
}

const serving = (document: unknown): MockProvider.RouteHandler => () => MockProvider.json(document)

/** The reason a discovery failed, or `"Success"` — one assertion per case. */
const reasonOf = (
  result: { readonly _tag: string; readonly failure?: unknown }
): string => {
  if (result._tag !== "Failure") return "Success"
  const failure = result.failure as DiscoveryError
  assert.strictEqual(failure._tag, "DiscoveryError")
  assert.strictEqual(failure.id, "acme")
  return failure.reason
}

describe("oauth/Discovery", () => {
  describe("discoveryUrlOf", () => {
    it("appends the well-known path to the issuer, path and all", () => {
      // Keycloak and Zitadel serve under the issuer's own path, so the path is
      // appended rather than rooted.
      assert.strictEqual(
        OidcDiscovery.discoveryUrlOf("https://id.acme.test/realms/acme"),
        "https://id.acme.test/realms/acme/.well-known/openid-configuration"
      )
      assert.strictEqual(
        OidcDiscovery.discoveryUrlOf("https://id.acme.test//"),
        "https://id.acme.test/.well-known/openid-configuration"
      )
    })
  })

  describe("asymmetricAlgorithms", () => {
    it("keeps the asymmetric families and drops everything else", () => {
      // A provider advertising `HS256` is advertising an algorithm whose key is
      // the client secret, and a discovered list is the provider's say-so.
      assert.deepStrictEqual(
        OidcDiscovery.asymmetricAlgorithms(["RS256", "HS256", "none", "ES384", "PS256", "EdDSA"]),
        ["RS256", "ES384", "PS256", "EdDSA"]
      )
      // Nothing usable is stated at all, rather than an empty allow-list, which
      // would refuse every token.
      assert.isUndefined(OidcDiscovery.asymmetricAlgorithms(["HS256"]))
      assert.isUndefined(OidcDiscovery.asymmetricAlgorithms(undefined))
    })
  })

  describe("failures", () => {
    it.effect("reports an endpoint that is not there", () =>
      Effect.gen(function*() {
        const { run } = discover(() => MockProvider.json({ message: "no such realm" }, 404))
        assert.strictEqual(reasonOf(yield* run), "Unreachable")
      }))

    it.effect("reports an endpoint that is down", () =>
      Effect.gen(function*() {
        const { run } = discover(() => MockProvider.json({}, 503))
        assert.strictEqual(reasonOf(yield* run), "Unreachable")
      }))

    it.effect("refuses a discovery endpoint that answers with a redirect", () =>
      Effect.gen(function*() {
        const { run, server } = discover(() => MockProvider.redirect("http://169.254.169.254/latest/meta-data/"))
        assert.strictEqual(reasonOf(yield* run), "Unreachable")
        // The hop was never taken: a `.well-known` cannot become an SSRF
        // primitive by answering `302`.
        assert.isUndefined(server.requests.find((request) => request.url.startsWith("http://169.254.169.254")))
      }))

    it.effect("reports a body that is not a document", () =>
      Effect.gen(function*() {
        const notJson = discover(() => new Response("<html>nope</html>", { status: 200 }))
        assert.strictEqual(reasonOf(yield* notJson.run), "Malformed")

        const notAnObject = discover(serving(["a", "list"]))
        assert.strictEqual(reasonOf(yield* notAnObject.run), "Malformed")
      }))

    it.effect("tells a document with no issuer from one with the wrong issuer", () =>
      Effect.gen(function*() {
        const missing = discover(serving(MockProvider.discoveryDocument({ issuer: null })))
        assert.strictEqual(reasonOf(yield* missing.run), "IssuerMissing")

        // A document is evidence about the issuer it names and no other, and a
        // mismatch is what a hijacked discovery endpoint looks like.
        const mismatched = discover(serving(MockProvider.discoveryDocument({ issuer: "https://evil.test" })))
        assert.strictEqual(reasonOf(yield* mismatched.run), "IssuerMismatch")

        // Byte for byte: a trailing slash is a different issuer.
        const nearly = discover(
          serving(MockProvider.discoveryDocument({ issuer: `${MockProvider.providerOrigin}/` }))
        )
        assert.strictEqual(reasonOf(yield* nearly.run), "IssuerMismatch")
      }))

    it.effect("reports a document missing either endpoint", () =>
      Effect.gen(function*() {
        const noAuthorize = discover(serving(MockProvider.discoveryDocument({ authorization_endpoint: null })))
        assert.strictEqual(reasonOf(yield* noAuthorize.run), "EndpointsMissing")

        const noToken = discover(serving(MockProvider.discoveryDocument({ token_endpoint: null })))
        assert.strictEqual(reasonOf(yield* noToken.run), "EndpointsMissing")
      }))

    it.effect("fails closed when there are no keys to verify a token with", () =>
      Effect.gen(function*() {
        // "No keys" is not "skip the signature check".
        const keyless = discover(serving(MockProvider.discoveryDocument({ jwks_uri: null })))
        assert.strictEqual(reasonOf(yield* keyless.run), "KeysMissing")
      }))
  })

  describe("success", () => {
    it.effect("builds a provider out of the document", () =>
      Effect.gen(function*() {
        const { run, server } = discover(serving(MockProvider.discoveryDocument()))
        const result = yield* run
        assert.strictEqual(result._tag, "Success")
        if (result._tag !== "Success") return
        const provider = result.success

        assert.strictEqual(provider.id, "acme")
        assert.strictEqual(provider.oidc?.issuer, MockProvider.providerOrigin)
        assert.strictEqual(provider.authorizationUrl, MockProvider.authorizeUrl)
        assert.strictEqual(provider.tokenUrl, MockProvider.tokenUrl)
        assert.deepStrictEqual(provider.oidc?.keys, { jwksUrl: MockProvider.jwksUrl })
        assert.deepStrictEqual([...provider.scopes], ["openid", "email", "profile"])
        assert.deepStrictEqual(
          provider.oidc?.algorithms === undefined ? [] : [...provider.oidc.algorithms],
          ["RS256"]
        )
        // The document was read once, over the redirect-refusing transport.
        assert.strictEqual(server.requests.length, 1)
        assert.strictEqual(server.requests[0]?.redirect, "manual")
      }))

    it.effect("lets an explicit setting win over the document", () =>
      Effect.gen(function*() {
        const { run } = discover(serving(MockProvider.discoveryDocument()), {
          tokenUrl: "https://gateway.acme.test/token",
          scopes: ["openid", "groups"],
          algorithms: ["ES256"],
          audience: ["mock-client-id", "com.example.app"]
        })
        const result = yield* run
        assert.strictEqual(result._tag, "Success")
        if (result._tag !== "Success") return
        assert.strictEqual(result.success.tokenUrl, "https://gateway.acme.test/token")
        // A gateway rewriting one endpoint does not cost discovery the other four.
        assert.strictEqual(result.success.authorizationUrl, MockProvider.authorizeUrl)
        assert.deepStrictEqual([...result.success.scopes], ["openid", "groups"])
        assert.deepStrictEqual(
          result.success.oidc?.algorithms === undefined ? [] : [...result.success.oidc.algorithms],
          ["ES256"]
        )
        assert.deepStrictEqual(result.success.oidc?.audience, ["mock-client-id", "com.example.app"])
      }))

    it.effect("reads the document from a stated URL, and accepts a pinned key set", () =>
      Effect.gen(function*() {
        const elsewhere = `${MockProvider.providerOrigin}/oidc/config`
        const server = MockProvider.mockServer()
        server.on(elsewhere, () => MockProvider.json(MockProvider.discoveryDocument({ jwks_uri: null })))
        const result = yield* Effect.result(OidcDiscovery.make({
          id: "acme",
          issuer: MockProvider.providerOrigin,
          discoveryUrl: elsewhere,
          clientId,
          // Pinned keys are the one way to have no `jwks_uri` and still be
          // verifiable.
          jwks: () => Promise.reject(new Error("unused"))
        })).pipe(Effect.provide(MockProvider.safeHttpLayer(server.fetch)))

        assert.strictEqual(result._tag, "Success")
        if (result._tag !== "Success") return
        // The key source is a union, so a pinned key set does not leave an
        // unused URL behind — the built provider carries the resolver and
        // nothing else, and "issuer but no keys" is unwritable rather than
        // merely refused.
        const keys = result.success.oidc?.keys
        assert.isDefined(keys)
        assert.isTrue(keys !== undefined && "jwks" in keys)
        // A public PKCE client sends no secret at all.
        assert.isUndefined(result.success.clientSecret)
      }))
  })

  describe("the default userInfo", () => {
    const provider = (document?: Readonly<Record<string, unknown>>) =>
      Effect.gen(function*() {
        const { run } = discover(serving(MockProvider.discoveryDocument(document)))
        const result = yield* run
        if (result._tag !== "Success") return yield* Effect.die("discovery failed")
        return result.success
      })

    const claims = {
      subject: "the-subject",
      issuer: MockProvider.providerOrigin,
      audience: [clientId],
      email: "ada@example.com",
      emailVerified: true,
      name: "Ada Lovelace",
      picture: "https://cdn.test/ada.png",
      nonce: null,
      expiresAt: DateTime.makeUnsafe(3_600_000),
      raw: {}
    }

    it.effect("takes the identity from the verified token, with no request at all", () => {
      const server = MockProvider.mockServer()
      return Effect.gen(function*() {
        const acme = yield* provider()
        const info = yield* acme.userInfo(
          MockProvider.tokensOf("access-token", { idTokenClaims: { ...claims } })
        ).pipe(Effect.provide(MockProvider.safeHttpLayer(server.fetch)))
        assert.strictEqual(info.id, "the-subject")
        assert.strictEqual(info.email, "ada@example.com")
        assert.strictEqual(server.to(MockProvider.userInfoUrl).length, 0)
      })
    })

    it.effect("consults the discovered userinfo endpoint when the token carries no address", () => {
      const server = MockProvider.mockServer()
      server.on(MockProvider.userInfoUrl, () =>
        MockProvider.json({ sub: "somebody-else", email: "ada@example.com", email_verified: true }))
      return Effect.gen(function*() {
        const acme = yield* provider()
        const info = yield* acme.userInfo(
          MockProvider.tokensOf("access-token", { idTokenClaims: { ...claims, email: null, name: null } })
        ).pipe(Effect.provide(MockProvider.safeHttpLayer(server.fetch)))
        // The address may come from the bearer-authenticated body; the subject
        // never does — it stays the one the signature covered.
        assert.strictEqual(info.id, "the-subject")
        assert.strictEqual(info.email, "ada@example.com")
        assert.isTrue(info.emailVerified)
      })
    })

    it.effect("fails when there is no address and no endpoint to ask", () => {
      const server = MockProvider.mockServer()
      return Effect.gen(function*() {
        const acme = yield* provider({ userinfo_endpoint: null })
        const result = yield* Effect.result(
          acme.userInfo(MockProvider.tokensOf("access-token", { idTokenClaims: { ...claims, email: null } }))
        ).pipe(Effect.provide(MockProvider.safeHttpLayer(server.fetch)))
        assert.strictEqual(result._tag, "Failure")
        if (result._tag !== "Failure") return
        assert.strictEqual(result.failure.reason, "UserInfoFailed")
      })
    })

    it.effect("fails closed when the flow handed it no verified claims", () => {
      const server = MockProvider.mockServer()
      return Effect.gen(function*() {
        const acme = yield* provider()
        const result = yield* Effect.result(acme.userInfo(MockProvider.tokensOf("access-token")))
          .pipe(Effect.provide(MockProvider.safeHttpLayer(server.fetch)))
        assert.strictEqual(result._tag, "Failure")
        if (result._tag !== "Failure") return
        assert.strictEqual(result.failure.reason, "IdTokenInvalid")
      })
    })
  })
})

// -----------------------------------------------------------------------------
// A discovered provider, signing somebody in
// -----------------------------------------------------------------------------

/**
 * One stubbed provider for the whole block, which is why it is sequential: the
 * token endpoint is replaced per test so that the `id_token` echoes the nonce
 * that this test's own `start` generated.
 */
const server = MockProvider.mockServer()

/**
 * The deployment: a provider nobody wrote an endpoint of down. Discovery reads
 * the document and the published key set over the same stubbed transport the
 * flow then runs on, so this is the whole path — `.well-known`, `jwks_uri`,
 * authorization URL, token exchange, `id_token` verification, account creation.
 *
 * `Layer.unwrap` because the provider is *resolved* rather than written: the key
 * set has to exist before the document can name it, and discovery is an effect.
 */
const discoveredLayer = Layer.unwrap(Effect.gen(function*() {
  const signer = yield* MockProvider.IdTokenSigner
  yield* Effect.sync(() => {
    server.on(MockProvider.discoveryUrl, () => MockProvider.json(MockProvider.discoveryDocument()))
    server.on(MockProvider.jwksUrl, () => MockProvider.json(signer.keySet))
  })
  const provider = yield* OidcDiscovery.make({
    id: "discovered",
    issuer: MockProvider.providerOrigin,
    clientId,
    clientSecret: Redacted.make("mock-client-secret")
  }).pipe(Effect.provide(MockProvider.safeHttpLayer(server.fetch)), Effect.orDie)

  return AuthTest.layerFlow({
    providers: [provider],
    fetch: server.fetch,
    baseUrl: "https://app.example.com"
  })
})).pipe(Layer.provideMerge(MockProvider.IdTokenSigner.layer))

describe.sequential("oauth/Discovery (end to end)", () => {
  layer(discoveredLayer)((it) => {
    it.effect("signs somebody in through a provider that was never written down", () =>
      Effect.gen(function*() {
        const signer = yield* MockProvider.IdTokenSigner
        const flow = yield* OAuthFlow
        const email = uniqueEmail("discovered")
        yield* Effect.sync(() => server.clear())

        const started = yield* flow.start({ providerId: "discovered" })
        assert.isTrue(started.url.startsWith(MockProvider.authorizeUrl))
        const nonce = MockProvider.paramsOf(started.url).get("nonce")

        yield* Effect.sync(() =>
          server.on(MockProvider.tokenUrl, async () => {
            const idToken = await signer.sign({
              sub: email,
              email,
              email_verified: true,
              name: testName,
              nonce
            })
            return MockProvider.json({
              access_token: "provider-access-token",
              token_type: "bearer",
              expires_in: 3600,
              id_token: idToken
            })
          })
        )

        const done = yield* flow.callback({
          providerId: "discovered",
          code: "authorization-code",
          state: Redacted.value(started.state)
        })

        assert.strictEqual(done.user.email, email)
        assert.isTrue(done.user.emailVerified)
        // The account is stored under the issuer the document declared and the
        // token claimed — not under the synthetic `local:oauth:` one.
        assert.strictEqual(done.account.issuer, MockProvider.providerOrigin)
        assert.isNotNull(done.token)
        // The keys came from the discovered `jwks_uri`, over the same transport.
        assert.strictEqual(server.to(MockProvider.jwksUrl).length, 1)
      }))
  })
})
