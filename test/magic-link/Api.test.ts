import { assert, describe, it } from "@effect/vitest"
import type { Schema } from "effect"
import { HttpApi, OpenApi } from "effect/unstable/httpapi"
import { AuthApi } from "../../src/http/AuthApi.js"
import { Authenticated } from "../../src/http/Middleware.js"
import { MagicLinkApi, MagicLinkApiGroup } from "../../src/magic-link/Api.js"

/**
 * The plugin's contract, transcribed from the design. `errors` holds the
 * identifiers the error schemas were declared with, which is what the OpenAPI
 * component names are derived from.
 */
const contract = [
  {
    identifier: "signIn",
    method: "POST",
    path: "/auth/magic-link/sign-in",
    errors: ["effect-auth/RateLimited"]
  },
  {
    identifier: "verify",
    method: "GET",
    path: "/auth/magic-link/verify",
    errors: ["effect-auth/RateLimited"]
  },
  {
    identifier: "exchange",
    method: "POST",
    path: "/auth/magic-link/exchange",
    errors: [
      "effect-auth/InvalidToken",
      "effect-auth/magic-link/SignUpDisabled",
      // A deployment's own hook declining the account or the session. The
      // browser endpoint beside it declares no such thing: it reports one as a
      // redirect, because a person who followed a link has to land on a page.
      "effect-auth/PolicyRefused",
      "effect-auth/RateLimited"
    ]
  }
] as const

/**
 * What these tests read off an endpoint.
 *
 * `HttpApiEndpoint.Top` is not usable as the value type here: the interface is
 * invariant in its middleware parameter and computes `~Request` off `this`, so
 * a concrete endpoint is not assignable to it. Naming the four members that are
 * actually asserted about keeps the group's own value flowing in unrestated.
 */
interface EndpointFacts {
  readonly method: string
  readonly path: string
  readonly error: ReadonlySet<Schema.Top>
  readonly middlewares: ReadonlySet<unknown>
}

const endpoints: Readonly<Record<string, EndpointFacts>> = MagicLinkApiGroup.endpoints

const endpointOf = (identifier: string): EndpointFacts => {
  const endpoint = Object.hasOwn(endpoints, identifier) ? endpoints[identifier] : undefined
  if (endpoint === undefined) throw new Error(`no endpoint "${identifier}" in the magicLink group`)
  return endpoint
}

const errorTags = (endpoint: EndpointFacts): ReadonlyArray<string> =>
  Array.from(endpoint.error, (schema) => {
    const identifier = schema.ast.annotations?.["identifier"] ?? schema.ast.annotations?.["title"]
    return typeof identifier === "string" ? identifier : "<anonymous>"
  })

describe("magic-link/Api", () => {
  it("declares exactly the three endpoints in the design", () => {
    assert.deepStrictEqual(
      Object.keys(endpoints),
      contract.map((entry) => entry.identifier)
    )
  })

  it("serves every endpoint at its specified method and path", () => {
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

  it("carries the Authenticated middleware nowhere", () => {
    // A magic link *is* the credential. Requiring a session to spend one would
    // defeat the flow, and asking for one has to be reachable by somebody who
    // cannot sign in at all.
    const authenticated = Object.keys(endpoints).filter((identifier) =>
      endpointOf(identifier).middlewares.has(Authenticated)
    )
    assert.deepStrictEqual(authenticated, [])
  })

  describe("composition", () => {
    it("merges into an application HttpApi beside the auth group", () => {
      const api = HttpApi.make("app").addHttpApi(AuthApi).add(MagicLinkApiGroup)
      assert.deepStrictEqual(Object.keys(api.groups), ["auth", "magicLink"])
    })

    it("generates an OpenAPI document with the plugin's three paths", () => {
      const spec = OpenApi.fromApi(HttpApi.make("app").addHttpApi(AuthApi).add(MagicLinkApiGroup))
      const paths = Object.keys(spec.paths).filter((path) => path.startsWith("/auth/magic-link"))

      assert.deepStrictEqual(paths, [
        "/auth/magic-link/sign-in",
        "/auth/magic-link/verify",
        "/auth/magic-link/exchange"
      ])
    })

    it("keeps the stored digests out of the plugin's document", () => {
      const json = JSON.stringify(OpenApi.fromApi(MagicLinkApi))
      assert.isFalse(json.includes("tokenHash"))
      assert.isFalse(json.includes("passwordHash"))
      assert.isFalse(json.includes("valueHash"))
    })
  })
})
