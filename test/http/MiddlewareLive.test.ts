import { assert, describe, it } from "@effect/vitest"
import { Effect, Option, Redacted } from "effect"
import {
  makeClient,
  responseCookie,
  sessionCookie,
  sessionCookieValue,
  signedUp,
  testLayer,
  testTimeout
} from "./harness.js"

describe("http/MiddlewareLive", () => {
  it.effect(
    "refuses a request that presents nothing at all",
    () =>
      Effect.gen(function*() {
        const { client } = yield* makeClient()

        const session = yield* Effect.flip(client.auth.getSession())
        const sessions = yield* Effect.flip(client.auth.listSessions())
        const out = yield* Effect.flip(client.auth.signOut())

        assert.strictEqual(session._tag, "Unauthorized")
        assert.strictEqual(sessions._tag, "Unauthorized")
        assert.strictEqual(out._tag, "Unauthorized")
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "refuses a cookie that names no session",
    () =>
      Effect.gen(function*() {
        const { cookies } = yield* signedUp()
        const stolen = yield* sessionCookieValue(cookies)

        // Same shape, one character different: an attacker guessing.
        const forged = `${stolen.slice(0, -1)}${stolen.endsWith("A") ? "B" : "A"}`
        const impostor = yield* makeClient({ bearerToken: () => forged })

        const error = yield* Effect.flip(impostor.client.auth.getSession())
        assert.strictEqual(error._tag, "Unauthorized")
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "accepts the same opaque token as a bearer, for clients with no cookie jar",
    () =>
      Effect.gen(function*() {
        const browser = yield* signedUp()
        const token = yield* sessionCookieValue(browser.cookies)

        const api = yield* makeClient({ bearerToken: () => token })
        const current = yield* api.client.auth.getSession()

        assert.strictEqual(current.user.id, browser.user.id)
        // Nothing was sent as a cookie: the third declared scheme was reached
        // only because both cookie schemes failed on the empty credential.
        assert.isTrue(Option.isNone(yield* sessionCookie(api.cookies)))

        // And it is the same session the browser holds.
        const fromCookie = yield* browser.client.auth.getSession()
        assert.strictEqual(current.session.id, fromCookie.session.id)
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "refuses a cookie-authenticated mutation from an untrusted origin",
    () =>
      Effect.gen(function*() {
        const browser = yield* signedUp()
        // The same browser, the same jar — but the request was initiated by
        // somebody else's page.
        const crossSite = yield* makeClient({
          cookies: browser.cookies,
          headers: { origin: "https://evil.test" }
        })

        const error = yield* Effect.flip(crossSite.client.auth.revokeSessions())
        assert.strictEqual(error._tag, "Unauthorized")

        // Nothing happened: the session is still there.
        yield* browser.client.auth.getSession()
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "allows a mutation from the deployment's own origin, and from a configured one",
    () =>
      Effect.gen(function*() {
        const browser = yield* signedUp()

        const own = yield* makeClient({
          cookies: browser.cookies,
          headers: { origin: "http://localhost:3000" }
        })
        yield* own.client.auth.revokeOtherSessions()

        const trusted = yield* makeClient({
          cookies: browser.cookies,
          headers: { origin: "https://trusted.example.com" }
        })
        yield* trusted.client.auth.revokeOtherSessions()
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "does not apply the origin check to reads, nor to bearer clients",
    () =>
      Effect.gen(function*() {
        const browser = yield* signedUp()
        const token = yield* sessionCookieValue(browser.cookies)

        // A read is not a state change: `SameSite` and the origin check are
        // about mutations.
        const reading = yield* makeClient({
          cookies: browser.cookies,
          headers: { origin: "https://evil.test" }
        })
        yield* reading.client.auth.getSession()

        // A bearer token is not attached by a browser, so demanding an origin
        // would reject every non-browser client and stop no attack.
        const api = yield* makeClient({
          bearerToken: () => token,
          headers: { origin: "https://evil.test" }
        })
        yield* api.client.auth.revokeOtherSessions()
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "writes the __Secure- prefixed cookie when the deployment is served over TLS",
    () =>
      Effect.gen(function*() {
        const { client } = yield* makeClient()
        const [, response] = yield* client.auth.signUpEmail({
          payload: {
            name: "Ada Lovelace",
            email: "ada@example.com",
            password: Redacted.make("correct horse battery staple")
          },
          responseMode: "decoded-and-response"
        })

        const cookie = responseCookie(response, "__Secure-effect_auth.session")
        assert.isTrue(Option.isSome(cookie), "the secure cookie name was not used")
        assert.strictEqual(cookie.pipe(Option.getOrThrow).options?.secure, true)
        // The un-prefixed name is not written as well: one cookie, one name.
        assert.isTrue(Option.isNone(responseCookie(response)))

        // The first declared security scheme now matches, and reading works.
        yield* client.auth.getSession()
      }).pipe(Effect.provide(testLayer({ cookie: { secure: true } }))),
    testTimeout
  )

  it.effect(
    "refuses the un-prefixed cookie on a TLS deployment, and the prefixed one elsewhere",
    () =>
      Effect.gen(function*() {
        const { client } = yield* makeClient()
        const [, response] = yield* client.auth.signUpEmail({
          payload: {
            name: "Ada Lovelace",
            email: "ada@example.com",
            password: Redacted.make("correct horse battery staple")
          },
          responseMode: "decoded-and-response"
        })
        const token = responseCookie(response, "__Secure-effect_auth.session").pipe(
          Option.getOrThrow
        ).value

        // The same, valid session token — under the name an attacker on a
        // plain-HTTP sibling origin is able to set. `__Secure-` exists to make
        // that name worthless here, so honouring it would hand back the
        // session-fixation attack the prefix prevents.
        const forged = yield* makeClient({
          bearerToken: () => undefined,
          headers: { cookie: `effect_auth.session=${token}` }
        })
        const refused = yield* Effect.flip(forged.client.auth.getSession())
        assert.strictEqual(refused._tag, "Unauthorized")

        // Under the name this deployment actually writes, it works.
        const honest = yield* makeClient({
          bearerToken: () => undefined,
          headers: { cookie: `__Secure-effect_auth.session=${token}` }
        })
        yield* honest.client.auth.getSession()
      }).pipe(Effect.provide(testLayer({ cookie: { secure: true } }))),
    testTimeout
  )

  it.effect(
    "refuses a __Secure- prefixed cookie on a plain-HTTP deployment",
    () =>
      Effect.gen(function*() {
        const browser = yield* signedUp()
        const token = yield* sessionCookieValue(browser.cookies)

        const prefixed = yield* makeClient({
          bearerToken: () => undefined,
          headers: { cookie: `__Secure-effect_auth.session=${token}` }
        })
        const refused = yield* Effect.flip(prefixed.client.auth.getSession())
        assert.strictEqual(refused._tag, "Unauthorized")
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "does not re-send the cookie on a request that changed nothing",
    () =>
      Effect.gen(function*() {
        const { client } = yield* signedUp()
        const [, response] = yield* client.auth.getSession({ responseMode: "decoded-and-response" })

        assert.isTrue(Option.isNone(responseCookie(response)))
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "answers 404 for the credential endpoints when they are switched off",
    () =>
      Effect.gen(function*() {
        const { client } = yield* makeClient()
        const response = yield* client.auth.signInEmail({
          payload: { email: "ada@example.com", password: Redacted.make("correct horse battery staple") },
          responseMode: "response-only"
        })

        assert.strictEqual(response.status, 404)
      }).pipe(Effect.provide(testLayer({ emailPassword: { enabled: false } }))),
    testTimeout
  )
})

describe("http/RateLimits over the wire", () => {
  const enabled = testLayer({ rateLimit: { enabled: true } })

  it.effect(
    "refuses the fourth sign-in attempt in a window, and says how long to wait",
    () =>
      Effect.gen(function*() {
        yield* signedUp()
        const attacker = yield* makeClient({ headers: { "x-forwarded-for": "203.0.113.7" } })

        const attempt = () =>
          Effect.flip(attacker.client.auth.signInEmail({
            payload: { email: "ada@example.com", password: Redacted.make("guess number one") }
          }))

        for (let i = 0; i < 3; i++) {
          assert.strictEqual((yield* attempt())._tag, "InvalidCredentials")
        }

        const limited = yield* attempt()
        assert.strictEqual(limited._tag, "RateLimited")
        if (limited._tag === "RateLimited") {
          assert.isAbove(limited.retryAfterSeconds, 0)
          assert.isAtMost(limited.retryAfterSeconds, 10)
        }

        // Another client is counted separately, and the correct password still
        // works for them.
        const innocent = yield* makeClient({ headers: { "x-forwarded-for": "198.51.100.4" } })
        yield* innocent.client.auth.signInEmail({
          payload: { email: "ada@example.com", password: Redacted.make("correct horse battery staple") }
        })
      }).pipe(Effect.provide(enabled)),
    testTimeout
  )

  it.effect(
    "counts callers it cannot identify as one caller",
    () =>
      Effect.gen(function*() {
        yield* signedUp()
        // No forwarding header and no remote address: the fail-closed bucket.
        const first = yield* makeClient()
        const second = yield* makeClient()

        const attempt = (client: typeof first) =>
          Effect.flip(client.client.auth.signInEmail({
            payload: { email: "ada@example.com", password: Redacted.make("guess number one") }
          }))

        assert.strictEqual((yield* attempt(first))._tag, "InvalidCredentials")
        assert.strictEqual((yield* attempt(second))._tag, "InvalidCredentials")
        assert.strictEqual((yield* attempt(first))._tag, "InvalidCredentials")
        // The fourth attempt across the two of them is refused: with no way to
        // tell them apart, they share one counter rather than getting one each.
        assert.strictEqual((yield* attempt(second))._tag, "RateLimited")
      }).pipe(Effect.provide(enabled)),
    testTimeout
  )

  it.effect(
    "counts each path separately, so signing up does not spend sign-in's attempts",
    () =>
      Effect.gen(function*() {
        const client = yield* makeClient({ headers: { "x-forwarded-for": "203.0.113.9" } })

        for (let i = 0; i < 3; i++) {
          yield* Effect.flip(client.client.auth.signUpEmail({
            payload: { name: "Ada", email: "ada@example.com", password: Redacted.make("short") }
          }))
        }
        const limited = yield* Effect.flip(client.client.auth.signUpEmail({
          payload: { name: "Ada", email: "ada@example.com", password: Redacted.make("short") }
        }))
        assert.strictEqual(limited._tag, "RateLimited")

        // Sign-in is a different path and therefore a different counter.
        const signIn = yield* Effect.flip(client.client.auth.signInEmail({
          payload: { email: "ada@example.com", password: Redacted.make("correct horse battery staple") }
        }))
        assert.strictEqual(signIn._tag, "InvalidCredentials")
      }).pipe(Effect.provide(enabled)),
    testTimeout
  )

  it.effect(
    "limits the mail endpoints without ever revealing whether the address exists",
    () =>
      Effect.gen(function*() {
        const client = yield* makeClient({ headers: { "x-forwarded-for": "203.0.113.11" } })

        for (let i = 0; i < 3; i++) {
          const ok = yield* client.client.auth.requestPasswordReset({
            payload: { email: "nobody@example.com" }
          })
          assert.strictEqual(ok.success, true)
        }
        const limited = yield* Effect.flip(client.client.auth.requestPasswordReset({
          payload: { email: "nobody@example.com" }
        }))
        assert.strictEqual(limited._tag, "RateLimited")
      }).pipe(Effect.provide(enabled)),
    testTimeout
  )
})
