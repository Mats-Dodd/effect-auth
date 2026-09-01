import { assert, describe, it } from "@effect/vitest"
import { Context, type Schema } from "effect"
import { HttpApi, OpenApi } from "effect/unstable/httpapi"
import { EmailOtpApi, EmailOtpApiGroup } from "../../src/email-otp/Api.js"
import { AuthApi } from "../../src/http/AuthApi.js"
import { Authenticated, AuthoritativeSession, RequireAssurance } from "../../src/http/Middleware.js"

/**
 * The plugin's contract, transcribed from the design. `errors` holds the
 * identifiers the error schemas were declared with, which is what the OpenAPI
 * component names are derived from.
 */
const contract = [
  {
    identifier: "send",
    method: "POST",
    path: "/auth/email-otp/send",
    authenticated: false,
    authoritative: false,
    assurance: false,
    errors: ["effect-auth/RateLimited", "effect-auth/OriginNotAllowed"]
  },
  {
    identifier: "verify",
    method: "POST",
    path: "/auth/email-otp/verify",
    authenticated: false,
    authoritative: false,
    assurance: false,
    errors: [
      "effect-auth/InvalidCode",
      "effect-auth/email-otp/SignUpDisabled",
      // A deployment's own hook declining the account or the session. The
      // browser endpoint beside it declares no such thing: it reports one as a
      // redirect, because a person who followed a link has to land on a page.
      "effect-auth/PolicyRefused",
      "effect-auth/RateLimited",
      // An unauthenticated POST that mints a session. The handle cookie is
      // `SameSite` capped away from `Strict`, so it is not what stops a
      // cross-site form post from signing a visitor into somebody else's
      // account — this is.
      "effect-auth/OriginNotAllowed"
    ]
  },
  {
    identifier: "link",
    method: "GET",
    path: "/auth/email-otp/link",
    authenticated: false,
    authoritative: false,
    assurance: false,
    errors: ["effect-auth/RateLimited"]
  },
  {
    identifier: "stepUpSend",
    method: "POST",
    path: "/auth/email-otp/step-up/send",
    authenticated: true,
    authoritative: true,
    // The endpoint that *satisfies* an assurance requirement cannot carry one:
    // a person steps up precisely because they do not meet it yet.
    assurance: false,
    errors: ["effect-auth/RateLimited"]
  },
  {
    identifier: "stepUpVerify",
    method: "POST",
    path: "/auth/email-otp/step-up/verify",
    authenticated: true,
    authoritative: true,
    assurance: false,
    errors: ["effect-auth/InvalidCode", "effect-auth/RateLimited"]
  },
  {
    identifier: "changeEmailSend",
    method: "POST",
    path: "/auth/email-otp/change-email/send",
    authenticated: true,
    authoritative: true,
    assurance: true,
    errors: ["effect-auth/EmailUnchanged", "effect-auth/RateLimited"]
  },
  {
    identifier: "changeEmailVerify",
    method: "POST",
    path: "/auth/email-otp/change-email/verify",
    authenticated: true,
    authoritative: true,
    assurance: true,
    errors: ["effect-auth/InvalidCode", "effect-auth/UserAlreadyExists", "effect-auth/RateLimited"]
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

const endpoints: Readonly<Record<string, EndpointFacts>> = EmailOtpApiGroup.endpoints

const endpointOf = (identifier: string): EndpointFacts => {
  const endpoint = Object.hasOwn(endpoints, identifier) ? endpoints[identifier] : undefined
  if (endpoint === undefined) throw new Error(`no endpoint "${identifier}" in the emailOtp group`)
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

describe("email-otp/Api", () => {
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

  it("carries the Authenticated middleware on exactly the two authenticated pairs", () => {
    // A code *is* the credential on the other three. Requiring a session to
    // spend one would defeat the flow, and asking for one has to be reachable
    // by somebody who cannot sign in at all.
    const authenticated = Object.keys(endpoints).filter((identifier) =>
      endpointOf(identifier).middlewares.has(Authenticated)
    )
    assert.deepStrictEqual(
      authenticated,
      contract.filter((entry) => entry.authenticated).map((entry) => entry.identifier)
    )
  })

  it("marks every authenticated endpoint authoritative", () => {
    // Each of the four rewrites the row the request authenticated with, so
    // none of them may be decided from a cookie-cache snapshot.
    for (const entry of contract) {
      assert.strictEqual(isAuthoritative(entry.identifier), entry.authoritative, entry.identifier)
    }
  })

  it("requires assurance on the change-of-address pair and nowhere else", () => {
    for (const entry of contract) {
      assert.strictEqual(requiresAssurance(entry.identifier), entry.assurance, entry.identifier)
    }
  })

  describe("composition", () => {
    it("merges into an application HttpApi beside the auth group", () => {
      const api = HttpApi.make("app").addHttpApi(AuthApi).add(EmailOtpApiGroup)
      assert.deepStrictEqual(Object.keys(api.groups), ["auth", "emailOtp"])
    })

    it("generates an OpenAPI document with the plugin's seven paths", () => {
      const spec = OpenApi.fromApi(HttpApi.make("app").addHttpApi(AuthApi).add(EmailOtpApiGroup))
      const paths = Object.keys(spec.paths).filter((path) => path.startsWith("/auth/email-otp"))

      assert.deepStrictEqual(paths, [
        "/auth/email-otp/send",
        "/auth/email-otp/verify",
        "/auth/email-otp/link",
        "/auth/email-otp/step-up/send",
        "/auth/email-otp/step-up/verify",
        "/auth/email-otp/change-email/send",
        "/auth/email-otp/change-email/verify"
      ])
    })

    it("answers the sign-in verify on two statuses", () => {
      const spec = OpenApi.fromApi(EmailOtpApi)
      const responses = Object.keys(
        Object(Object(Object(spec.paths)["/auth/email-otp/verify"])["post"]).responses
      ).sort()
      assert.isTrue(responses.includes("200"))
      assert.isTrue(responses.includes("202"))
    })

    it("keeps the stored digests out of the plugin's document", () => {
      const json = JSON.stringify(OpenApi.fromApi(EmailOtpApi))
      assert.isFalse(json.includes("tokenHash"))
      assert.isFalse(json.includes("passwordHash"))
      assert.isFalse(json.includes("valueHash"))
      // The plugin's own stored secrets are not on the wire either: the code's
      // peppered digest and its attempt budget live in the challenge row, and
      // the handle travels in a cookie rather than in any schema.
      assert.isFalse(json.includes("codeHash"))
      assert.isFalse(json.includes("attemptsLeft"))
      assert.isFalse(json.includes("secretCiphertext"))
    })
  })
})
