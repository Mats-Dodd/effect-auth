import { assert, describe, it } from "@effect/vitest"
import { Context, type Schema } from "effect"
import { HttpApi, OpenApi } from "effect/unstable/httpapi"
import { AuthApi } from "../../src/http/AuthApi.js"
import { Authenticated, AuthoritativeSession, RequireAssurance } from "../../src/http/Middleware.js"
import { PhoneApi, PhoneApiGroup } from "../../src/phone/index.js"

/**
 * The plugin's contract, transcribed from the design. `errors` holds the
 * identifiers the error schemas were declared with, which is what the OpenAPI
 * component names are derived from.
 *
 * The two flags either side of `authenticated` are the fail-closed invariant
 * written down: every endpoint that rewrites the row the request authenticated
 * with is `authoritative`, and every one that *enrols or manages a factor*
 * costs a recent authentication. The step-up pair is the deliberate exception —
 * an endpoint somebody reaches precisely because they do not meet a policy yet
 * cannot itself demand that policy.
 */
const contract = [
  {
    identifier: "sendVerification",
    method: "POST",
    path: "/auth/phone/send-verification",
    authenticated: true,
    authoritative: true,
    assurance: true,
    errors: [
      "effect-auth/phone/InvalidPhoneNumber",
      "effect-auth/phone/PhoneCountryNotAllowed",
      "effect-auth/phone/RestrictedFactorNotAllowed",
      "effect-auth/RateLimited"
    ]
  },
  {
    identifier: "verify",
    method: "POST",
    path: "/auth/phone/verify",
    authenticated: true,
    authoritative: true,
    assurance: true,
    errors: [
      "effect-auth/InvalidCode",
      "effect-auth/phone/PhoneAlreadyInUse",
      "effect-auth/phone/RestrictedFactorNotAllowed",
      "effect-auth/RateLimited"
    ]
  },
  {
    identifier: "remove",
    method: "POST",
    path: "/auth/phone/remove",
    authenticated: true,
    authoritative: true,
    assurance: true,
    errors: ["effect-auth/RateLimited"]
  },
  {
    identifier: "signInSend",
    method: "POST",
    path: "/auth/phone/sign-in/send",
    authenticated: false,
    authoritative: false,
    assurance: false,
    errors: [
      "effect-auth/phone/InvalidPhoneNumber",
      "effect-auth/phone/PhoneCountryNotAllowed",
      "effect-auth/OriginNotAllowed",
      "effect-auth/RateLimited"
    ]
  },
  {
    identifier: "signInVerify",
    method: "POST",
    path: "/auth/phone/sign-in/verify",
    authenticated: false,
    authoritative: false,
    assurance: false,
    // Unauthenticated and it mints a session, so it checks a present Origin for
    // the same reason the send beside it does — a site holding a code of its
    // own must not be able to sign a visitor's browser into its account.
    errors: [
      "effect-auth/InvalidCode",
      "effect-auth/OriginNotAllowed",
      "effect-auth/PolicyRefused",
      "effect-auth/RateLimited"
    ]
  },
  {
    identifier: "stepUpSend",
    method: "POST",
    path: "/auth/phone/step-up/send",
    authenticated: true,
    authoritative: true,
    assurance: false,
    errors: ["effect-auth/phone/PhoneNotVerified", "effect-auth/RateLimited"]
  },
  {
    identifier: "stepUpVerify",
    method: "POST",
    path: "/auth/phone/step-up/verify",
    authenticated: true,
    authoritative: true,
    assurance: false,
    errors: ["effect-auth/InvalidCode", "effect-auth/RateLimited"]
  }
] as const

/**
 * What these tests read off an endpoint.
 *
 * `HttpApiEndpoint.Top` is not usable as the value type here: the interface is
 * invariant in its middleware parameter and computes `~Request` off `this`, so
 * a concrete endpoint is not assignable to it. Naming the members that are
 * actually asserted about keeps the group's own value flowing in unrestated.
 */
interface EndpointFacts {
  readonly method: string
  readonly path: string
  readonly error: ReadonlySet<Schema.Top>
  readonly middlewares: ReadonlySet<unknown>
  readonly annotations: Context.Context<never>
}

const endpoints: Readonly<Record<string, EndpointFacts>> = PhoneApiGroup.endpoints

const endpointOf = (identifier: string): EndpointFacts => {
  const endpoint = Object.hasOwn(endpoints, identifier) ? endpoints[identifier] : undefined
  if (endpoint === undefined) throw new Error(`no endpoint "${identifier}" in the phone group`)
  return endpoint
}

const errorTags = (endpoint: EndpointFacts): ReadonlyArray<string> =>
  Array.from(endpoint.error, (schema) => {
    const identifier = schema.ast.annotations?.["identifier"] ?? schema.ast.annotations?.["title"]
    return typeof identifier === "string" ? identifier : "<anonymous>"
  })

/** Whether an endpoint carries `AuthoritativeSession`. */
const isAuthoritative = (identifier: string): boolean =>
  Context.get(endpointOf(identifier).annotations, AuthoritativeSession)

/** Whether an endpoint states an assurance policy of its own. */
const requiresAssurance = (identifier: string): boolean =>
  Context.get(endpointOf(identifier).annotations, RequireAssurance) !== undefined

describe("phone/Api", () => {
  it("declares exactly the seven endpoints in the design", () => {
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

  it("carries the Authenticated middleware on exactly the five endpoints that need a caller", () => {
    // A code is the credential on the sign-in pair, so requiring a session
    // there would defeat the flow it exists for.
    const authenticated = Object.keys(endpoints).filter((identifier) =>
      endpointOf(identifier).middlewares.has(Authenticated)
    )
    assert.deepStrictEqual(
      authenticated,
      contract.filter((entry) => entry.authenticated).map((entry) => entry.identifier)
    )
  })

  it("marks every authenticated endpoint authoritative", () => {
    // Each of the five reads or rewrites the row the request authenticated
    // with, so none may be decided from a cookie-cache snapshot.
    for (const entry of contract) {
      assert.strictEqual(isAuthoritative(entry.identifier), entry.authoritative, entry.identifier)
    }
  })

  it("requires assurance on factor management and never on the step-up pair", () => {
    for (const entry of contract) {
      assert.strictEqual(requiresAssurance(entry.identifier), entry.assurance, entry.identifier)
    }
  })

  it("checks a present origin on both unauthenticated endpoints", () => {
    // The cookie-shaped defence in `Authenticated` never sees a request that
    // carries no cookie, so these two carry the check themselves.
    for (const entry of contract.filter((entry) => !entry.authenticated)) {
      assert.include(entry.errors, "effect-auth/OriginNotAllowed", entry.identifier)
    }
  })

  describe("composition", () => {
    it("merges into an application HttpApi beside the auth group", () => {
      const api = HttpApi.make("app").addHttpApi(AuthApi).add(PhoneApiGroup)
      assert.deepStrictEqual(Object.keys(api.groups), ["auth", "phone"])
    })

    it("generates an OpenAPI document with the plugin's seven paths", () => {
      const spec = OpenApi.fromApi(HttpApi.make("app").addHttpApi(AuthApi).add(PhoneApiGroup))
      const paths = Object.keys(spec.paths).filter((path) => path.startsWith("/auth/phone"))

      assert.deepStrictEqual(paths, [
        "/auth/phone/send-verification",
        "/auth/phone/verify",
        "/auth/phone/remove",
        "/auth/phone/sign-in/send",
        "/auth/phone/sign-in/verify",
        "/auth/phone/step-up/send",
        "/auth/phone/step-up/verify"
      ])
    })

    it("answers the sign-in verify on two statuses", () => {
      const spec = OpenApi.fromApi(PhoneApi)
      const responses = Object.keys(
        Object(Object(Object(spec.paths)["/auth/phone/sign-in/verify"])["post"]).responses
      ).sort()
      assert.isTrue(responses.includes("200"))
      assert.isTrue(responses.includes("202"))
    })

    it("keeps the stored digests and the handle out of the plugin's document", () => {
      const json = JSON.stringify(OpenApi.fromApi(PhoneApi))
      assert.isFalse(json.includes("tokenHash"))
      assert.isFalse(json.includes("passwordHash"))
      assert.isFalse(json.includes("valueHash"))
      // This plugin stores no secret of its own: the code's peppered digest and
      // its attempt budget live in the challenge row.
      assert.isFalse(json.includes("codeHash"))
      assert.isFalse(json.includes("attemptsLeft"))
      // The handle is named in the prose — it has to be, a consumer needs to
      // know where it lives — but it is never a field: it rides in a `__Host-`
      // cookie, so no request or response schema on this document carries it.
      const schemas = JSON.stringify(Object(OpenApi.fromApi(PhoneApi))["components"])
      assert.isFalse(schemas.includes("handle"))
    })
  })
})
