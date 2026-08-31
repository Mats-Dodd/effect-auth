import { assert, describe, expect, it } from "@effect/vitest"
import { Context, Effect, Redacted, Schema } from "effect"
import type { HttpApiEndpoint } from "effect/unstable/httpapi"
import { HttpApi, OpenApi } from "effect/unstable/httpapi"
import { AuthApi, AuthApiGroup, SignInEmailPayload } from "../../src/http/AuthApi.js"
import { Authenticated, AuthoritativeSession } from "../../src/http/Middleware.js"
import { testPasswordText } from "../fixtures.js"

/**
 * The contract from SPEC.md, transcribed. `authenticated` records which
 * endpoints carry the `Authenticated` middleware, and `errors` the tags of the
 * declared error union — the middleware's own `Unauthorized` is added
 * separately by the builder and is asserted for below.
 */
const contract = [
  {
    identifier: "signUpEmail",
    method: "POST",
    path: "/auth/sign-up/email",
    authenticated: false,
    errors: ["effect-auth/UserAlreadyExists", "effect-auth/PasswordPolicyViolation", "effect-auth/RateLimited"]
  },
  {
    identifier: "signInEmail",
    method: "POST",
    path: "/auth/sign-in/email",
    authenticated: false,
    errors: ["effect-auth/InvalidCredentials", "effect-auth/EmailNotVerified", "effect-auth/RateLimited"]
  },
  { identifier: "signOut", method: "POST", path: "/auth/sign-out", authenticated: true, errors: [] },
  { identifier: "getSession", method: "GET", path: "/auth/session", authenticated: true, errors: [] },
  { identifier: "listSessions", method: "GET", path: "/auth/sessions", authenticated: true, errors: [] },
  {
    identifier: "revokeSession",
    method: "POST",
    path: "/auth/revoke-session",
    authenticated: true,
    errors: ["effect/HttpApiError/NotFound"]
  },
  { identifier: "revokeSessions", method: "POST", path: "/auth/revoke-sessions", authenticated: true, errors: [] },
  {
    identifier: "revokeOtherSessions",
    method: "POST",
    path: "/auth/revoke-other-sessions",
    authenticated: true,
    errors: []
  },
  {
    identifier: "requestPasswordReset",
    method: "POST",
    path: "/auth/request-password-reset",
    authenticated: false,
    errors: ["effect-auth/RateLimited"]
  },
  {
    identifier: "resetPassword",
    method: "POST",
    path: "/auth/reset-password",
    authenticated: false,
    errors: ["effect-auth/InvalidToken", "effect-auth/PasswordPolicyViolation"]
  },
  {
    identifier: "changePassword",
    method: "POST",
    path: "/auth/change-password",
    authenticated: true,
    errors: ["effect-auth/InvalidCredentials", "effect-auth/SessionNotFresh", "effect-auth/PasswordPolicyViolation"]
  },
  {
    identifier: "sendVerificationEmail",
    method: "POST",
    path: "/auth/send-verification-email",
    authenticated: false,
    errors: ["effect-auth/RateLimited"]
  },
  {
    identifier: "verifyEmail",
    method: "GET",
    path: "/auth/verify-email",
    authenticated: false,
    errors: ["effect-auth/InvalidToken"]
  },
  {
    identifier: "signInSocial",
    method: "POST",
    path: "/auth/sign-in/social",
    authenticated: false,
    // Beyond the SPEC table: the endpoint is unauthenticated and writes a state
    // row per call, so it carries the credential endpoints' limit — see the
    // amendment note in SPEC.md.
    errors: ["effect-auth/OAuthProviderError", "effect-auth/RateLimited"]
  },
  {
    identifier: "oauthCallback",
    method: "GET",
    path: "/auth/callback/:providerId",
    authenticated: false,
    errors: ["effect-auth/OAuthStateMismatch", "effect-auth/OAuthProviderError"]
  },
  { identifier: "listAccounts", method: "GET", path: "/auth/accounts", authenticated: true, errors: [] },
  {
    identifier: "linkSocial",
    method: "POST",
    path: "/auth/link-social",
    authenticated: true,
    errors: ["effect-auth/OAuthProviderError"]
  },
  {
    identifier: "unlinkAccount",
    method: "POST",
    path: "/auth/unlink-account",
    authenticated: true,
    errors: ["effect-auth/CannotUnlinkLastAccount", "effect/HttpApiError/NotFound", "effect-auth/SessionNotFresh"]
  },
  {
    identifier: "updateUser",
    method: "POST",
    path: "/auth/update-user",
    authenticated: true,
    errors: ["effect-auth/UserNotFound"]
  },
  {
    identifier: "changeEmail",
    method: "POST",
    path: "/auth/change-email",
    authenticated: true,
    errors: ["effect-auth/EmailUnchanged", "effect-auth/SessionNotFresh", "effect-auth/RateLimited"]
  },
  {
    identifier: "confirmEmailChange",
    method: "GET",
    path: "/auth/change-email/confirm",
    authenticated: false,
    errors: ["effect-auth/InvalidToken"]
  },
  {
    identifier: "verifyEmailChange",
    method: "GET",
    path: "/auth/change-email/verify",
    authenticated: false,
    errors: ["effect-auth/InvalidToken", "effect-auth/UserAlreadyExists"]
  },
  {
    identifier: "deleteUser",
    method: "POST",
    path: "/auth/delete-user",
    authenticated: true,
    errors: ["effect-auth/InvalidCredentials", "effect-auth/SessionNotFresh", "effect-auth/RateLimited"]
  },
  {
    identifier: "deleteUserCallback",
    method: "GET",
    path: "/auth/delete-user/callback",
    authenticated: true,
    errors: ["effect-auth/InvalidToken"]
  },
  {
    identifier: "setPassword",
    method: "POST",
    path: "/auth/set-password",
    authenticated: true,
    errors: [
      "effect-auth/PasswordAlreadySet",
      "effect-auth/PasswordPolicyViolation",
      "effect-auth/SessionNotFresh",
      "effect-auth/RateLimited"
    ]
  },
  {
    identifier: "getAccessToken",
    method: "POST",
    path: "/auth/get-access-token",
    authenticated: true,
    errors: ["effect/HttpApiError/NotFound", "effect-auth/TokenRefreshFailed"]
  },
  {
    identifier: "refreshToken",
    method: "POST",
    path: "/auth/refresh-token",
    authenticated: true,
    errors: ["effect/HttpApiError/NotFound", "effect-auth/TokenRefreshFailed"]
  },
  {
    identifier: "oauthCallbackForm",
    method: "POST",
    path: "/auth/callback/:providerId",
    authenticated: false,
    errors: []
  }
] as const

/**
 * The endpoints that must see the session as the database has it, rather than as
 * a cookie-cache snapshot remembers it. Every one of them either reads a
 * credential, changes one, or changes the identity behind it.
 */
const authoritative = [
  "changePassword",
  "unlinkAccount",
  "changeEmail",
  "deleteUser",
  "deleteUserCallback",
  "setPassword"
] as const

const endpoints = AuthApiGroup.endpoints as unknown as Readonly<Record<string, HttpApiEndpoint.Top>>

const endpointOf = (identifier: string): HttpApiEndpoint.Top => {
  const endpoint = Object.hasOwn(endpoints, identifier) ? endpoints[identifier] : undefined
  if (endpoint === undefined) throw new Error(`no endpoint "${identifier}" in the auth group`)
  return endpoint
}

// Error schemas are identified by the `Schema.TaggedError` identifier they were
// declared with, which is what the OpenAPI component names are derived from.
const errorTags = (endpoint: HttpApiEndpoint.Top): ReadonlyArray<string> =>
  Array.from(endpoint.error, (schema) => {
    const identifier = (schema.ast.annotations?.["identifier"] ?? schema.ast.annotations?.["title"]) as
      | string
      | undefined
    return identifier ?? "<anonymous>"
  })

describe("http/AuthApi", () => {
  it("declares exactly the endpoints in the specification", () => {
    assert.deepStrictEqual(
      Object.keys(endpoints),
      contract.map((entry) => entry.identifier)
    )
    assert.strictEqual(contract.length, 28)
  })

  it("serves every endpoint at its specified method and path", () => {
    for (const entry of contract) {
      const endpoint = endpointOf(entry.identifier)
      assert.strictEqual(endpoint.method, entry.method, entry.identifier)
      assert.strictEqual(endpoint.path, entry.path, entry.identifier)
    }
  })

  it("applies Authenticated to exactly the session-bound endpoints", () => {
    const expected = contract.filter((entry) => entry.authenticated).map((entry) => entry.identifier)
    const actual = Object.keys(endpoints).filter((identifier) =>
      endpointOf(identifier).middlewares.has(Authenticated as never)
    )
    assert.deepStrictEqual(actual, expected)
    assert.strictEqual(expected.length, 17)
  })

  it("marks exactly the credential- and identity-changing endpoints authoritative", () => {
    // The cookie cache is bypassed for these, in both directions. A new endpoint
    // that reads or changes a credential and forgets the annotation would be
    // served from a snapshot up to `cookieCache.maxAge` old — which is why the
    // list is pinned here rather than left to review.
    const actual = Object.keys(endpoints).filter((identifier) =>
      Context.get(endpointOf(identifier).annotations, AuthoritativeSession)
    )
    assert.deepStrictEqual(actual, [...authoritative])
  })

  it("declares the specified error union on each endpoint", () => {
    for (const entry of contract) {
      assert.deepStrictEqual(errorTags(endpointOf(entry.identifier)), [...entry.errors], entry.identifier)
    }
  })

  it("keeps the stored digests out of the whole document", () => {
    // The `.json` model variants drop every `Model.Sensitive` field. Assert on
    // the whole generated document so no endpoint can reintroduce one.
    const json = JSON.stringify(OpenApi.fromApi(AuthApi))
    assert.isFalse(json.includes("tokenHash"))
    assert.isFalse(json.includes("passwordHash"))
    assert.isFalse(json.includes("valueHash"))
  })

  it("keeps provider tokens out of every schema but the two that exist to serve them", () => {
    // `get-access-token` and `refresh-token` hand a provider credential to the
    // account's own owner, on purpose; the `Account`, `Session` and `User`
    // projections every other endpoint answers with must carry none. The two
    // paths are removed and the rest of the document asserted against, so a
    // token field reintroduced anywhere else — a `listAccounts` that started
    // returning `accessToken`, say — fails here.
    const spec = OpenApi.fromApi(AuthApi) as unknown as {
      readonly paths: Record<string, unknown>
      readonly components: unknown
    }
    const elsewhere = Object.fromEntries(
      Object.entries(spec.paths).filter(([path]) =>
        path !== "/auth/get-access-token" && path !== "/auth/refresh-token"
      )
    )
    const json = JSON.stringify({ paths: elsewhere, components: spec.components })
    assert.isFalse(json.includes(`"accessToken"`))
    assert.isFalse(json.includes(`"refreshToken"`))
    assert.isFalse(json.includes(`"idToken"`))
  })

  describe("composition", () => {
    it("merges into an application HttpApi via addHttpApi", () => {
      const api = HttpApi.make("app").addHttpApi(AuthApi)
      assert.deepStrictEqual(Object.keys(api.groups), ["auth"])
      const group = api.groups.auth as unknown as { readonly endpoints: Record<string, unknown> }
      assert.strictEqual(Object.keys(group.endpoints).length, 28)
    })

    it("generates an OpenAPI document without throwing", () => {
      const api = HttpApi.make("app").addHttpApi(AuthApi)
      const spec = OpenApi.fromApi(api)

      assert.strictEqual(spec.openapi, "3.1.0")
      assert.deepStrictEqual(Object.keys(spec.paths), [
        "/auth/sign-up/email",
        "/auth/sign-in/email",
        "/auth/sign-out",
        "/auth/session",
        "/auth/sessions",
        "/auth/revoke-session",
        "/auth/revoke-sessions",
        "/auth/revoke-other-sessions",
        "/auth/request-password-reset",
        "/auth/reset-password",
        "/auth/change-password",
        "/auth/send-verification-email",
        "/auth/verify-email",
        "/auth/sign-in/social",
        // Both the GET a provider redirects to and the POST a `form_post`
        // provider submits to live here, so the path appears once.
        "/auth/callback/{providerId}",
        "/auth/accounts",
        "/auth/link-social",
        "/auth/unlink-account",
        "/auth/update-user",
        "/auth/change-email",
        "/auth/change-email/confirm",
        "/auth/change-email/verify",
        "/auth/delete-user",
        "/auth/delete-user/callback",
        "/auth/set-password",
        "/auth/get-access-token",
        "/auth/refresh-token"
      ])
    })

    it("serves the form_post callback beside the redirect callback on one path", () => {
      const spec = OpenApi.fromApi(HttpApi.make("app").addHttpApi(AuthApi))
      const operations = (spec.paths as Record<string, Record<string, unknown>>)["/auth/callback/{providerId}"]

      assert.isDefined(operations)
      assert.deepStrictEqual(Object.keys(operations ?? {}).sort(), ["get", "post"])
    })

    it("matches the committed OpenAPI snapshot", async () => {
      // The Definition of done asks for a snapshot, and it earns its keep next
      // to the targeted assertions above: those pin the paths, the errors and
      // the absence of sensitive fields, while this catches drift anywhere else
      // in the document — a renamed schema, a changed status code, a payload
      // field that quietly became optional. Regenerate with `vitest -u` and
      // read the diff before accepting it.
      const spec = OpenApi.fromApi(AuthApi)
      await expect(JSON.stringify(spec, null, 2)).toMatchFileSnapshot(
        "./__snapshots__/openapi.json"
      )
    })

    it("documents the cookie and bearer security schemes", () => {
      const spec = OpenApi.fromApi(HttpApi.make("app").addHttpApi(AuthApi))

      assert.deepStrictEqual(spec.components.securitySchemes, {
        secureSessionCookie: {
          type: "apiKey",
          name: "__Secure-effect_auth.session",
          in: "cookie"
        },
        sessionCookie: {
          type: "apiKey",
          name: "effect_auth.session",
          in: "cookie"
        },
        bearer: {
          type: "http",
          scheme: "Bearer"
        }
      })
    })

    it("requires a credential on the session-bound operations only", () => {
      const spec = OpenApi.fromApi(HttpApi.make("app").addHttpApi(AuthApi))
      const paths = spec.paths as Record<string, Record<string, { security?: ReadonlyArray<unknown> }>>

      const securityOf = (path: string, method: string): ReadonlyArray<unknown> => {
        const operations = Object.hasOwn(paths, path) ? paths[path] : undefined
        if (operations === undefined || !Object.hasOwn(operations, method)) {
          throw new Error(`no ${method} ${path} operation`)
        }
        return operations[method]?.security ?? []
      }

      for (const entry of contract) {
        const path = entry.path.replace(":providerId", "{providerId}")
        const security = securityOf(path, entry.method.toLowerCase())
        if (entry.authenticated) {
          assert.deepStrictEqual(
            security,
            [{ secureSessionCookie: [] }, { sessionCookie: [] }, { bearer: [] }],
            entry.identifier
          )
        } else {
          assert.deepStrictEqual(security, [], entry.identifier)
        }
      }
    })

    it("answers 401 on the session-bound operations", () => {
      const spec = OpenApi.fromApi(HttpApi.make("app").addHttpApi(AuthApi))
      const paths = spec.paths as Record<string, Record<string, { responses: Record<string, unknown> }>>

      for (const entry of contract.filter((entry) => entry.authenticated)) {
        const operations = paths[entry.path]
        const operation = operations?.[entry.method.toLowerCase()]
        assert.isTrue(
          operation !== undefined && Object.hasOwn(operation.responses, "401"),
          entry.identifier
        )
      }
    })

    it("answers 302 with a Location header on the OAuth callback", () => {
      const spec = OpenApi.fromApi(HttpApi.make("app").addHttpApi(AuthApi))
      const paths = spec.paths as Record<
        string,
        Record<string, { responses: Record<string, { headers?: Record<string, unknown> }> }>
      >
      const response = paths["/auth/callback/{providerId}"]?.get?.responses?.["302"]

      assert.isDefined(response)
      assert.isTrue(response !== undefined && Object.hasOwn(response.headers ?? {}, "location"))
    })
  })

  describe("payloads", () => {
    it.effect("decodes a password into a Redacted that renders as <redacted>", () =>
      Effect.gen(function*() {
        const payload = yield* Schema.decodeUnknownEffect(Schema.toCodecJson(SignInEmailPayload))({
          email: "ada@example.com",
          password: testPasswordText
        })

        assert.strictEqual(Redacted.value(payload.password), testPasswordText)
        assert.strictEqual(String(payload.password), "<redacted>")
        assert.isFalse(JSON.stringify(payload).includes(testPasswordText))
      }))
  })
})
