import { assert, describe, it } from "@effect/vitest"
import { Context, type Schema } from "effect"
import { HttpApi, OpenApi } from "effect/unstable/httpapi"
import { AuthApi } from "../../src/http/AuthApi.js"
import { Authenticated, AuthoritativeSession, RequireAssurance } from "../../src/http/Middleware.js"
import { OneTapApi, OneTapApiGroup } from "../../src/one-tap/index.js"

/**
 * The plugin's contract, transcribed from the design.
 *
 * Two endpoints and no more: One Tap is a second road to the sign-in this
 * library already has, not a verification path of its own. Neither is
 * authenticated — a person using them has no session yet, which is the point —
 * so neither carries `AuthoritativeSession` or an assurance policy, and the
 * callback checks a present origin itself.
 */
const contract = [
  {
    identifier: "nonce",
    method: "GET",
    path: "/auth/one-tap/nonce",
    errors: ["effect-auth/RateLimited"]
  },
  {
    identifier: "callback",
    method: "POST",
    path: "/auth/one-tap/callback",
    errors: [
      "effect-auth/one-tap/OneTapRejected",
      "effect-auth/OAuthProviderError",
      "effect-auth/AccountAlreadyLinked",
      "effect-auth/UserNotFound",
      "effect-auth/PolicyRefused",
      "effect-auth/OriginNotAllowed",
      "effect-auth/RateLimited"
    ]
  }
] as const

/**
 * What these tests read off an endpoint. See `test/phone/Api.test.ts` for why
 * `HttpApiEndpoint.Top` cannot be the value type here.
 */
interface EndpointFacts {
  readonly method: string
  readonly path: string
  readonly error: ReadonlySet<Schema.Top>
  readonly middlewares: ReadonlySet<unknown>
  readonly annotations: Context.Context<never>
}

const endpoints: Readonly<Record<string, EndpointFacts>> = OneTapApiGroup.endpoints

const endpointOf = (identifier: string): EndpointFacts => {
  const endpoint = Object.hasOwn(endpoints, identifier) ? endpoints[identifier] : undefined
  if (endpoint === undefined) throw new Error(`no endpoint "${identifier}" in the oneTap group`)
  return endpoint
}

const errorTags = (endpoint: EndpointFacts): ReadonlyArray<string> =>
  Array.from(endpoint.error, (schema) => {
    const identifier = schema.ast.annotations?.["identifier"] ?? schema.ast.annotations?.["title"]
    return typeof identifier === "string" ? identifier : "<anonymous>"
  })

describe("one-tap/Api", () => {
  it("declares exactly the two endpoints in the design", () => {
    assert.deepStrictEqual(
      Object.keys(endpoints),
      contract.map((entry) => entry.identifier)
    )
  })

  it("serves each endpoint at its specified method and path", () => {
    for (const entry of contract) {
      const endpoint = endpointOf(entry.identifier)
      assert.strictEqual(endpoint.method, entry.method, entry.identifier)
      assert.strictEqual(endpoint.path, entry.path, entry.identifier)
    }
  })

  it("declares the specified error union on each endpoint", () => {
    for (const entry of contract) {
      assert.deepStrictEqual(errorTags(endpointOf(entry.identifier)), [...entry.errors], entry.identifier)
    }
  })

  it("authenticates neither, and so annotates neither", () => {
    for (const entry of contract) {
      assert.isFalse(endpointOf(entry.identifier).middlewares.has(Authenticated), entry.identifier)
      assert.isFalse(Context.get(endpointOf(entry.identifier).annotations, AuthoritativeSession), entry.identifier)
      assert.strictEqual(
        Context.get(endpointOf(entry.identifier).annotations, RequireAssurance),
        undefined,
        entry.identifier
      )
    }
  })

  it("checks a present origin on the endpoint that mints a session", () => {
    // Unauthenticated and it signs somebody in, so the cookie-shaped defence in
    // `Authenticated` never sees it.
    assert.include(errorTags(endpointOf("callback")), "effect-auth/OriginNotAllowed")
  })

  describe("composition", () => {
    it("merges into an application HttpApi beside the auth group", () => {
      const api = HttpApi.make("app").addHttpApi(AuthApi).add(OneTapApiGroup)
      assert.deepStrictEqual(Object.keys(api.groups), ["auth", "oneTap"])
    })

    it("generates an OpenAPI document with the plugin's two paths", () => {
      const spec = OpenApi.fromApi(HttpApi.make("app").addHttpApi(AuthApi).add(OneTapApiGroup))
      const paths = Object.keys(spec.paths).filter((path) => path.startsWith("/auth/one-tap"))
      assert.deepStrictEqual(paths, ["/auth/one-tap/nonce", "/auth/one-tap/callback"])
    })

    it("answers the callback on two statuses", () => {
      const spec = OpenApi.fromApi(OneTapApi)
      const responses = Object.keys(
        Object(Object(Object(spec.paths)["/auth/one-tap/callback"])["post"]).responses
      ).sort()
      assert.isTrue(responses.includes("200"))
      assert.isTrue(responses.includes("202"))
    })

    it("keeps the stored digests out of the plugin's document", () => {
      const json = JSON.stringify(OpenApi.fromApi(OneTapApi))
      assert.isFalse(json.includes("tokenHash"))
      assert.isFalse(json.includes("passwordHash"))
      assert.isFalse(json.includes("valueHash"))
      assert.isFalse(json.includes("secretCiphertext"))
    })
  })
})
