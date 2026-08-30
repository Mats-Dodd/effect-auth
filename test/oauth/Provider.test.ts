import { assert, describe, it } from "@effect/vitest"
import { Effect, Option, Redacted } from "effect"
import {
  fetchJson,
  isOidc,
  layer as providersLayer,
  layerEmpty,
  layerMerge,
  makeRegistry,
  OAuthProviders,
  providerIssuer,
  reservedAuthorizationParams,
  revealToken
} from "../../src/oauth/Provider.js"
import * as Github from "../../src/oauth/providers/Github.js"
import * as Google from "../../src/oauth/providers/Google.js"
import { json, mockProvider, mockServer, redirect, safeHttpLayer } from "./harness.js"

const github = Github.make({ clientId: "id", clientSecret: Redacted.make("secret") })
const google = Google.make({ clientId: "id", clientSecret: Redacted.make("secret") })

describe("oauth/Provider", () => {
  describe("registry", () => {
    it("resolves a registered id and refuses everything else", () => {
      const registry = makeRegistry([github, google])
      assert.deepStrictEqual([...registry.ids], ["github", "google"])
      assert.isTrue(Option.isSome(registry.find("github")))
      assert.isTrue(Option.isNone(registry.find("gitlab")))
    })

    it.effect("answers UnknownProvider rather than returning nothing", () =>
      Effect.gen(function*() {
        const registry = makeRegistry([github])
        const result = yield* Effect.result(registry.get("gitlab"))
        assert.strictEqual(result._tag, "Failure")
        if (result._tag !== "Failure") return
        assert.strictEqual(result.failure._tag, "OAuthProviderError")
        assert.strictEqual(result.failure.reason, "UnknownProvider")
        assert.strictEqual(result.failure.providerId, "gitlab")
      }))

    it.effect("cannot be walked into the prototype by a request path", () =>
      Effect.gen(function*() {
        // `providerId` reaches the registry straight out of a URL path. On an
        // ordinary object `registry.find("__proto__")` or `"constructor"` would
        // hand back something truthy, and `toString` would be a function.
        const registry = makeRegistry([github])
        for (const hostile of ["__proto__", "constructor", "toString", "hasOwnProperty"]) {
          assert.isTrue(Option.isNone(registry.find(hostile)), hostile)
          const result = yield* Effect.result(registry.get(hostile))
          assert.strictEqual(result._tag, "Failure", hostile)
        }
      }))

    it("lets the last registration of an id win, and lists it once", () => {
      const other = { ...github, clientId: "second" }
      const registry = makeRegistry([github, other])
      assert.deepStrictEqual([...registry.ids], ["github"])
      const found = registry.find("github")
      assert.strictEqual(Option.isSome(found) ? found.value.clientId : "", "second")
    })

    it.effect("is empty, not absent, when a deployment configures no providers", () =>
      Effect.gen(function*() {
        const registry = yield* OAuthProviders
        assert.deepStrictEqual([...registry.ids], [])
        const result = yield* Effect.result(registry.get("github"))
        assert.strictEqual(result._tag, "Failure")
      }).pipe(Effect.provide(layerEmpty)))

    it.effect("merges one-provider layers into a single registry", () =>
      Effect.gen(function*() {
        const registry = yield* OAuthProviders
        assert.deepStrictEqual([...registry.ids], ["github", "google"])
      }).pipe(Effect.provide(layerMerge([Github.layer({
        clientId: "id",
        clientSecret: Redacted.make("secret")
      }), Google.layer({ clientId: "id", clientSecret: Redacted.make("secret") })]))))

    it.effect("keeps a single-provider layer usable on its own", () =>
      Effect.gen(function*() {
        const registry = yield* OAuthProviders
        assert.deepStrictEqual([...registry.ids], ["mock"])
      }).pipe(Effect.provide(providersLayer([mockProvider()]))))
  })

  describe("issuers", () => {
    it("distinguishes an OIDC provider from a plain OAuth2 one", () => {
      assert.isTrue(isOidc(google))
      assert.isFalse(isOidc(github))
      assert.strictEqual(providerIssuer(google), "https://accounts.google.com")
      assert.strictEqual(providerIssuer(github), "local:oauth:github")
    })
  })

  describe("reserved parameters", () => {
    it("covers everything the flow sets itself", () => {
      for (
        const key of [
          "response_type",
          "client_id",
          "redirect_uri",
          "scope",
          "state",
          "code_challenge",
          "code_challenge_method",
          "nonce"
        ]
      ) {
        assert.isTrue(reservedAuthorizationParams.has(key), key)
      }
    })
  })

  describe("revealToken", () => {
    it("unwraps a credential only where one exists", () => {
      assert.strictEqual(revealToken(Redacted.make("a-token")), "a-token")
      assert.isNull(revealToken(null))
    })
  })

  describe("fetchJson", () => {
    const call = (url: string) =>
      Effect.result(fetchJson({
        providerId: "mock",
        url,
        accessToken: Redacted.make("an-access-token")
      }))

    it.effect("reports a refusal as a status rather than an error", () => {
      const server = mockServer()
      server.on("https://provider.test/userinfo", () => json({ message: "no" }, 403))
      return Effect.gen(function*() {
        const result = yield* call("https://provider.test/userinfo")
        assert.strictEqual(result._tag, "Success")
        if (result._tag !== "Success") return
        assert.strictEqual(result.success.status, 403)
        assert.isNull(result.success.body)
      }).pipe(Effect.provide(safeHttpLayer(server.fetch)))
    })

    it.effect("reads a body that is not JSON as no body at all", () => {
      const server = mockServer()
      server.on("https://provider.test/userinfo", () => new Response("<html>nope</html>", { status: 200 }))
      return Effect.gen(function*() {
        const result = yield* call("https://provider.test/userinfo")
        assert.strictEqual(result._tag, "Success")
        if (result._tag !== "Success") return
        assert.isNull(result.success.body)
      }).pipe(Effect.provide(safeHttpLayer(server.fetch)))
    })

    it.effect("refuses a redirect, and reports it as ProviderUnavailable", () => {
      const server = mockServer()
      server.on("https://provider.test/userinfo", () => redirect("http://169.254.169.254/"))
      return Effect.gen(function*() {
        const result = yield* call("https://provider.test/userinfo")
        assert.strictEqual(result._tag, "Failure")
        if (result._tag !== "Failure") return
        assert.strictEqual(result.failure.reason, "ProviderUnavailable")
        assert.strictEqual(server.requests.length, 1)
      }).pipe(Effect.provide(safeHttpLayer(server.fetch)))
    })
  })
})
