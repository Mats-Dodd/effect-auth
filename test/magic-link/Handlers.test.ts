import { assert, describe, layer } from "@effect/vitest"
import { Duration, Effect, Layer, Option, Redacted } from "effect"
import { TestClock } from "effect/testing"
import { AuthTest, MagicLinkTest, TestEmails, TestHttpClient } from "../../src/testing/index.js"
import { testName, testPassword, testPasswordText, uniqueEmail } from "../fixtures.js"

/**
 * A deployment with a `TestClock` of its own, which a test may move.
 *
 * `AuthTest.freshClock` is the wrong tool over HTTP: `HttpApiBuilder` captures a
 * handler's services when the *layer* is built, so a clock provided inside a test
 * body governs the client and nothing behind the router.
 */
const layerMovingClock = (options?: MagicLinkTest.Options) =>
  MagicLinkTest.layerHttp(options).pipe(Layer.provideMerge(Layer.fresh(TestClock.layer())))

/** A browser addressing this block's deployment, with a jar the test can read. */
const makeClient = (options?: TestHttpClient.ClientOptions) =>
  TestHttpClient.makeClient(MagicLinkTest.TestApi, options)

/** The token out of the most recent link mailed to an address. */
const linkToken = (email: string) =>
  Effect.flatMap(
    TestEmails.TestEmails,
    (emails) => Effect.map(emails.tokenFor(MagicLinkTest.magicLinkKind, email), Redacted.value)
  )

/** The `Max-Age` a response's session cookie was written with, in seconds. */
const maxAgeSeconds = (
  response: Parameters<typeof TestHttpClient.responseCookie>[0]
): number | undefined => {
  const cookie = TestHttpClient.responseCookie(response)
  if (Option.isNone(cookie)) return undefined
  const maxAge = cookie.value.options?.maxAge
  return maxAge === undefined ? undefined : Duration.toSeconds(Duration.fromInputUnsafe(maxAge))
}

describe.sequential("magic-link/Handlers", () => {
  layer(MagicLinkTest.layerHttp())("the endpoints", (it) => {
    it.effect("answers a request for a link identically for a stranger and a member", () =>
      Effect.gen(function*() {
        const stranger = uniqueEmail("http-stranger")
        const member = uniqueEmail("http-member")
        const { client } = yield* makeClient()

        yield* client.auth.signUpEmail({ payload: { name: testName, email: member, password: testPassword } })

        const first = yield* client.magicLink.signIn({ payload: { email: stranger } })
        const second = yield* client.magicLink.signIn({ payload: { email: member } })

        assert.deepStrictEqual(first, { success: true })
        assert.deepStrictEqual(second, { success: true })
      }))

    it.effect("signs the browser in when the link is followed", () =>
      Effect.gen(function*() {
        const email = uniqueEmail("http-follow")
        const { client, cookies } = yield* makeClient()

        yield* client.magicLink.signIn({ payload: { email, name: "Ada", callbackURL: "/welcome" } })
        const token = yield* linkToken(email)

        const [, response] = yield* client.magicLink.verify({
          query: { token },
          responseMode: "decoded-and-response"
        })

        assert.strictEqual(response.status, 302)
        assert.strictEqual(response.headers["location"], `${AuthTest.testBaseUrl}/welcome`)
        assert.isTrue(Option.isSome(TestHttpClient.responseCookie(response)))

        // The cookie the redirect wrote is a working session.
        const session = yield* client.auth.getSession()
        assert.strictEqual(session.user.email, email)
        assert.isTrue(session.user.emailVerified)
        assert.isTrue(Option.isSome(yield* TestHttpClient.sessionCookie(cookies)))
      }))

    it.effect("writes a session cookie with the attributes the library always uses", () =>
      Effect.gen(function*() {
        const email = uniqueEmail("http-cookie")
        const { client } = yield* makeClient()

        yield* client.magicLink.signIn({ payload: { email } })
        const [, response] = yield* client.magicLink.verify({
          query: { token: yield* linkToken(email) },
          responseMode: "decoded-and-response"
        })

        const cookie = TestHttpClient.responseCookie(response)
        assert.isTrue(Option.isSome(cookie))
        if (Option.isNone(cookie)) return
        assert.isTrue(cookie.value.options?.httpOnly)
        assert.strictEqual(cookie.value.options?.sameSite, "lax")
        assert.strictEqual(cookie.value.options?.path, "/")
        // Seven days, the configured session lifetime.
        assert.strictEqual(maxAgeSeconds(response), Duration.toSeconds(Duration.days(7)))
      }))

    it.effect("honours rememberMe: false with a browser-session cookie", () =>
      Effect.gen(function*() {
        const email = uniqueEmail("http-forgetful")
        const { client } = yield* makeClient()

        // The choice travels in the token's payload, so it is made when the link
        // is *asked for* and honoured when it is followed.
        yield* client.magicLink.signIn({ payload: { email, rememberMe: false } })
        const [, response] = yield* client.magicLink.verify({
          query: { token: yield* linkToken(email) },
          responseMode: "decoded-and-response"
        })

        assert.strictEqual(response.status, 302)
        assert.strictEqual(maxAgeSeconds(response), undefined)
      }))

    it.effect("exchanges a link for a session body, and a cookie with it", () =>
      Effect.gen(function*() {
        const email = uniqueEmail("http-exchange")
        const { client, cookies } = yield* makeClient()

        yield* client.magicLink.signIn({ payload: { email, name: "Ada" } })
        const token = yield* linkToken(email)

        const result = yield* client.magicLink.exchange({ payload: { token: Redacted.make(token) } })

        assert.strictEqual(result.user.email, email)
        assert.strictEqual(result.session.userId, result.user.id)
        // The public projection, exactly as `GET /session` answers it.
        assert.isFalse(Object.hasOwn(result.session, "tokenHash"))
        assert.isTrue(Option.isSome(yield* TestHttpClient.sessionCookie(cookies)))

        const session = yield* client.auth.getSession()
        assert.strictEqual(session.user.id, result.user.id)
      }))

    it.effect("redirects a replayed link to baseUrl with a safe code", () =>
      Effect.gen(function*() {
        const email = uniqueEmail("http-replay")
        const { client } = yield* makeClient()

        yield* client.magicLink.signIn({ payload: { email, errorCallbackURL: "/oops" } })
        const token = yield* linkToken(email)
        yield* client.magicLink.verify({ query: { token } })

        const [, response] = yield* client.magicLink.verify({
          query: { token },
          responseMode: "decoded-and-response"
        })

        assert.strictEqual(response.status, 302)
        // Nothing was claimed the second time, so the link's own error page is
        // not available — and the code says nothing about who is registered.
        assert.strictEqual(
          response.headers["location"],
          `${AuthTest.testBaseUrl}/?error=invalid_token`
        )
      }))

    it.effect("reports a replayed link as InvalidToken on the JSON twin", () =>
      Effect.gen(function*() {
        const email = uniqueEmail("http-replay-json")
        const { client } = yield* makeClient()

        yield* client.magicLink.signIn({ payload: { email } })
        const token = Redacted.make(yield* linkToken(email))
        yield* client.magicLink.exchange({ payload: { token } })

        const error = yield* Effect.flip(client.magicLink.exchange({ payload: { token } }))
        assert.strictEqual(error._tag, "InvalidToken")
      }))

    it.effect("takes over an unproven account, over HTTP", () =>
      Effect.gen(function*() {
        const email = uniqueEmail("http-squatted")
        const squatter = yield* makeClient()
        yield* squatter.client.auth.signUpEmail({
          payload: { name: testName, email, password: testPassword }
        })

        const owner = yield* makeClient()
        yield* owner.client.magicLink.signIn({ payload: { email } })
        yield* owner.client.magicLink.verify({ query: { token: yield* linkToken(email) } })

        // The real owner is signed in…
        const session = yield* owner.client.auth.getSession()
        assert.strictEqual(session.user.email, email)
        assert.isTrue(session.user.emailVerified)

        // …and the squatter's session and password are both gone.
        const stale = yield* Effect.flip(squatter.client.auth.getSession())
        assert.strictEqual(stale._tag, "Unauthorized")
        const refused = yield* Effect.flip(
          squatter.client.auth.signInEmail({ payload: { email, password: testPassword } })
        )
        assert.strictEqual(refused._tag, "InvalidCredentials")
      }))
  })

  layer(layerMovingClock())("the clock", (it) => {
    it.effect("refuses a link whose five minutes are up", () =>
      Effect.gen(function*() {
        const email = uniqueEmail("http-expired")
        const { client } = yield* makeClient()

        yield* client.magicLink.signIn({ payload: { email } })
        const token = yield* linkToken(email)

        yield* TestClock.adjust(Duration.minutes(6))

        const [, response] = yield* client.magicLink.verify({
          query: { token },
          responseMode: "decoded-and-response"
        })
        assert.strictEqual(response.status, 302)
        assert.strictEqual(response.headers["location"], `${AuthTest.testBaseUrl}/?error=invalid_token`)

        // And nobody was signed in on the way past.
        const refused = yield* Effect.flip(client.auth.getSession())
        assert.strictEqual(refused._tag, "Unauthorized")
      }))

    it.effect("serves a link that is still inside its window", () =>
      Effect.gen(function*() {
        const email = uniqueEmail("http-in-time")
        const { client } = yield* makeClient()

        yield* client.magicLink.signIn({ payload: { email } })
        const token = yield* linkToken(email)

        yield* TestClock.adjust(Duration.minutes(4))

        const [, response] = yield* client.magicLink.verify({
          query: { token },
          responseMode: "decoded-and-response"
        })
        assert.strictEqual(response.status, 302)
        assert.strictEqual(response.headers["location"], AuthTest.testBaseUrl)
      }))
  })

  layer(MagicLinkTest.layerHttp({ rateLimit: { enabled: true } }))("the rate limits", (it) => {
    it.effect("counts the plugin's endpoints on buckets of their own", () =>
      Effect.gen(function*() {
        const email = uniqueEmail("http-limited")
        const { client } = yield* makeClient()

        // Three per minute on the mail bucket, keyed by path.
        for (let attempt = 0; attempt < 3; attempt++) {
          yield* client.magicLink.signIn({ payload: { email } })
        }
        const limited = yield* Effect.flip(client.magicLink.signIn({ payload: { email } }))
        assert.strictEqual(limited._tag, "RateLimited")

        // The library's own mail endpoint shares the *policy* and not the
        // counter: the key carries the request path.
        const elsewhere = yield* client.auth.requestPasswordReset({ payload: { email } })
        assert.deepStrictEqual(elsewhere, { success: true })
      }))

    it.effect("counts spending a link against the credential bucket", () =>
      Effect.gen(function*() {
        const email = uniqueEmail("http-limited-exchange")
        const { client } = yield* makeClient()
        yield* client.auth.signUpEmail({ payload: { name: testName, email, password: testPassword } })

        const token = Redacted.make("bm90aGluZw.not-a-token")
        for (let attempt = 0; attempt < 3; attempt++) {
          yield* Effect.flip(client.magicLink.exchange({ payload: { token } }))
        }
        const limited = yield* Effect.flip(client.magicLink.exchange({ payload: { token } }))
        assert.strictEqual(limited._tag, "RateLimited")

        // And the password endpoint, on the same policy and a different path, is
        // untouched by that run.
        const signedIn = yield* client.auth.signInEmail({
          payload: { email, password: Redacted.make(testPasswordText) }
        })
        assert.strictEqual(signedIn.user.email, email)
      }))
  })
})
