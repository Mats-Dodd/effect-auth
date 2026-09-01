import { assert, describe, layer } from "@effect/vitest"
import { DateTime, Duration, Effect, Option, Redacted } from "effect"
import { Cookies } from "effect/unstable/http"
import { AuthConfig } from "../../src/config/AuthConfig.js"
import type { SignInPipelineService } from "../../src/domain/SignIn.js"
import { proceed } from "../../src/domain/SignIn.js"
import { handleCookie } from "../../src/email-otp/Handlers.js"
import * as AuthHandlers from "../../src/http/Handlers.js"
import * as EmailOtpTest from "../../src/testing/EmailOtpTest.js"
import * as AuthTest from "../../src/testing/TestLayer.js"
import * as TestHttpClient from "../../src/testing/TestHttpClient.js"
import { testName, testPassword, uniqueEmail } from "../fixtures.js"

/** A browser addressing this block's deployment, with a jar the test can read. */
const makeClient = (options?: TestHttpClient.ClientOptions) => TestHttpClient.makeClient(EmailOtpTest.TestApi, options)

/** The handle cookie's name for this deployment. */
const handleCookieName = Effect.map(AuthConfig, (config) => handleCookie(config, Duration.zero).name)

/**
 * The `_tag` a request failed with.
 *
 * The endpoints declare their refusals, so the generated client decodes them
 * into the error itself rather than leaving a raw response — which is what
 * `TestHttpClient.refusedStatus` reads. The tag is the assertion that matters:
 * the status is fixed by the error's own annotation.
 */
const failureTag = <A, E, R>(request: Effect.Effect<A, E, R>): Effect.Effect<string, never, R> =>
  Effect.match(request, {
    onSuccess: () => "Success",
    onFailure: (error) =>
      typeof error === "object" && error !== null && "_tag" in error && typeof error._tag === "string"
        ? error._tag
        : "Unknown"
  })

/** The `Max-Age` a response wrote a named cookie with, in seconds. */
const maxAgeOf = (response: { readonly cookies: Cookies.Cookies }, name: string): number | undefined => {
  const cookie = Cookies.get(response.cookies, name)
  if (Option.isNone(cookie)) return undefined
  const maxAge = cookie.value.options?.maxAge
  return maxAge === undefined ? undefined : Duration.toSeconds(Duration.fromInputUnsafe(maxAge))
}

describe.sequential("email-otp/Handlers", () => {
  layer(EmailOtpTest.layerHttp())("the endpoints", (it) => {
    it.effect("answers a request for a code identically for a stranger and a member", () =>
      Effect.gen(function* () {
        const stranger = uniqueEmail("http-stranger")
        const member = uniqueEmail("http-member")
        const { client } = yield* makeClient()

        yield* client.auth.signUpEmail({ payload: { name: testName, email: member, password: testPassword } })

        const [first, firstResponse] = yield* client.emailOtp.send({
          payload: { email: stranger, purpose: "signIn" },
          responseMode: "decoded-and-response"
        })
        const [second, secondResponse] = yield* client.emailOtp.send({
          payload: { email: member, purpose: "signIn" },
          responseMode: "decoded-and-response"
        })

        // The same status, the same body…
        assert.strictEqual(firstResponse.status, secondResponse.status)
        assert.deepStrictEqual(first, { success: true })
        assert.deepStrictEqual(second, { success: true })
        // …and the same one cookie, differing only in the opaque handle.
        const name = yield* handleCookieName
        assert.deepStrictEqual(Object.keys(Cookies.toRecord(firstResponse.cookies)), [name])
        assert.deepStrictEqual(Object.keys(Cookies.toRecord(secondResponse.cookies)), [name])
      })
    )

    it.effect("sets the handle in an HttpOnly, host-scoped cookie and nowhere else", () =>
      Effect.gen(function* () {
        const email = uniqueEmail("http-cookie")
        const { client } = yield* makeClient()

        const [body, response] = yield* client.emailOtp.send({
          payload: { email, purpose: "signIn" },
          responseMode: "decoded-and-response"
        })

        const name = yield* handleCookieName
        const cookie = Option.getOrThrow(Cookies.get(response.cookies, name))
        assert.strictEqual(cookie.options?.httpOnly, true)
        // `__Host-` forbids `Domain` and forces `Path=/`, and the attributes are
        // fixed whether or not the prefix is on the name.
        assert.strictEqual(cookie.options?.path, "/")
        assert.isUndefined(cookie.options?.domain)
        assert.strictEqual(maxAgeOf(response, name), Duration.toSeconds(Duration.minutes(10)))

        // Not in the body: the handle is a credential.
        assert.deepStrictEqual(body, { success: true })
        assert.isFalse((yield* response.text).includes(cookie.value))
      })
    )

    it.effect("is __Host- prefixed on a TLS deployment and bare on plain HTTP", () =>
      Effect.gen(function* () {
        const config = yield* AuthConfig
        assert.strictEqual(
          handleCookie({ ...config, cookie: { ...config.cookie, secure: false } }, Duration.zero).name,
          "effect_auth.email_otp_handle"
        )
        assert.strictEqual(
          handleCookie({ ...config, cookie: { ...config.cookie, secure: true } }, Duration.zero).name,
          "__Host-effect_auth.email_otp_handle"
        )
      })
    )

    it.effect("signs the browser in when the code is answered", () =>
      Effect.gen(function* () {
        const email = uniqueEmail("http-verify")
        const { client, cookies } = yield* makeClient()

        yield* client.emailOtp.send({ payload: { email, purpose: "signIn", name: "Ada" } })
        const code = yield* EmailOtpTest.awaitCode(email)

        const [result, response] = yield* client.emailOtp.verify({
          payload: { code },
          responseMode: "decoded-and-response"
        })

        assert.strictEqual(response.status, 200)
        assert.strictEqual(result._tag, "SignedIn")
        if (result._tag !== "SignedIn") return
        assert.strictEqual(result.user.email, email)
        assert.isTrue(result.user.emailVerified)

        // The cookie the answer wrote is a working session…
        const session = yield* client.auth.getSession()
        assert.strictEqual(session.user.email, email)
        assert.isTrue(Option.isSome(yield* TestHttpClient.sessionCookie(cookies)))
        // …and the handle was expired on the same response.
        const name = yield* handleCookieName
        assert.strictEqual(Option.getOrThrow(Cookies.get(response.cookies, name)).value, "")
      })
    )

    it.effect("signs the browser in when the link is followed instead", () =>
      Effect.gen(function* () {
        const email = uniqueEmail("http-link")
        const { client, cookies } = yield* makeClient()

        yield* client.emailOtp.send({ payload: { email, purpose: "signIn", callbackURL: "/welcome" } })
        const token = yield* EmailOtpTest.awaitLinkToken(email)

        const [, response] = yield* client.emailOtp.link({
          query: { token },
          responseMode: "decoded-and-response"
        })

        assert.strictEqual(response.status, 302)
        assert.strictEqual(response.headers["location"], `${AuthTest.testBaseUrl}/welcome`)
        assert.isTrue(Option.isSome(TestHttpClient.responseCookie(response)))

        const session = yield* client.auth.getSession()
        assert.strictEqual(session.user.email, email)
        assert.isTrue(Option.isSome(yield* TestHttpClient.sessionCookie(cookies)))
      })
    )

    it.effect("redirects a spent link to its own error page", () =>
      Effect.gen(function* () {
        const email = uniqueEmail("http-link-spent")
        const { client } = yield* makeClient()

        yield* client.emailOtp.send({
          payload: { email, purpose: "signIn", errorCallbackURL: "/oops" }
        })
        const token = yield* EmailOtpTest.awaitLinkToken(email)
        yield* client.emailOtp.link({ query: { token } })

        const [, response] = yield* client.emailOtp.link({
          query: { token },
          responseMode: "decoded-and-response"
        })
        assert.strictEqual(response.status, 302)
        // No error URL is in hand for a token this deployment never minted, so
        // the site root is where a replay lands.
        assert.isTrue(response.headers["location"]?.includes("error=invalid_token"))
      })
    )

    it.effect("honours rememberMe: false with a browser-session cookie", () =>
      Effect.gen(function* () {
        const email = uniqueEmail("http-forgetful")
        const { client } = yield* makeClient()

        // The choice travels in the challenge's payload, so it is made when the
        // code is *asked for* and honoured when it is answered.
        yield* client.emailOtp.send({ payload: { email, purpose: "signIn", rememberMe: false } })
        const code = yield* EmailOtpTest.awaitCode(email)
        const [, response] = yield* client.emailOtp.verify({
          payload: { code },
          responseMode: "decoded-and-response"
        })

        assert.strictEqual(response.status, 200)
        assert.isUndefined(maxAgeOf(response, "effect_auth.session"))
      })
    )

    it.effect("refuses a request that claims an origin this deployment does not trust", () =>
      Effect.gen(function* () {
        const email = uniqueEmail("http-origin")
        const { client } = yield* makeClient({ headers: { origin: "https://evil.example" } })
        const refused = yield* failureTag(client.emailOtp.send({ payload: { email, purpose: "signIn" } }))
        assert.strictEqual(refused, "OriginNotAllowed")

        // And a caller that claims none — a server, `curl` — is let through.
        const { client: plain } = yield* makeClient()
        assert.deepStrictEqual(yield* plain.emailOtp.send({ payload: { email, purpose: "signIn" } }), {
          success: true
        })
      })
    )

    it.effect("answers a wrong code with InvalidCode, and a missing handle with the same", () =>
      Effect.gen(function* () {
        const email = uniqueEmail("http-wrong")
        const { client } = yield* makeClient()

        // No cookie at all.
        assert.strictEqual(
          yield* failureTag(client.emailOtp.verify({ payload: { code: Redacted.make("00000000") } })),
          "InvalidCode"
        )

        yield* client.emailOtp.send({ payload: { email, purpose: "signIn" } })
        assert.strictEqual(
          yield* failureTag(client.emailOtp.verify({ payload: { code: Redacted.make("00000000") } })),
          "InvalidCode"
        )
      })
    )

    it.effect("answers the verify-address purpose as Verified, with no session", () =>
      Effect.gen(function* () {
        const email = uniqueEmail("http-verify-address")
        const { client, cookies } = yield* makeClient()
        yield* client.auth.signUpEmail({ payload: { name: testName, email, password: testPassword } })
        yield* client.auth.signOut()

        yield* client.emailOtp.send({ payload: { email, purpose: "verifyEmail" } })
        const code = yield* EmailOtpTest.awaitCode(email)
        const [result, response] = yield* client.emailOtp.verify({
          payload: { code },
          responseMode: "decoded-and-response"
        })

        assert.strictEqual(response.status, 200)
        assert.deepStrictEqual(result, { _tag: "Verified" })
        // Proving an address is not signing in.
        assert.isTrue(Option.isNone(TestHttpClient.responseCookie(response)))
        assert.strictEqual(yield* TestHttpClient.sessionCookieValue(cookies), "")
      })
    )

    it.effect("answers the reset purpose with a continuation the core endpoint spends", () =>
      Effect.gen(function* () {
        const email = uniqueEmail("http-reset")
        const { client } = yield* makeClient()
        yield* client.auth.signUpEmail({ payload: { name: testName, email, password: testPassword } })
        yield* client.auth.signOut()

        yield* client.emailOtp.send({ payload: { email, purpose: "resetPassword" } })
        const code = yield* EmailOtpTest.awaitCode(email)
        const [result, response] = yield* client.emailOtp.verify({
          payload: { code },
          responseMode: "decoded-and-response"
        })

        assert.strictEqual(response.status, 200)
        assert.strictEqual(result._tag, "PasswordReset")
        if (result._tag !== "PasswordReset") return
        // No session came of it — the reset is what re-secures the account.
        assert.isTrue(Option.isNone(TestHttpClient.responseCookie(response)))

        yield* client.auth.resetPassword({
          payload: { token: result.token, newPassword: Redacted.make("a-much-longer-replacement-passphrase") }
        })
        const signedIn = yield* client.auth.signInEmail({
          payload: { email, password: Redacted.make("a-much-longer-replacement-passphrase") }
        })
        assert.isFalse("_tag" in signedIn)
      })
    )

    it.effect("raises the session's assurance through the step-up pair", () =>
      Effect.gen(function* () {
        const email = uniqueEmail("http-step-up")
        const { client } = yield* makeClient()
        yield* client.auth.signUpEmail({ payload: { name: testName, email, password: testPassword } })

        const before = yield* client.auth.getSession()
        assert.strictEqual(before.session.aal, "aal1")

        yield* client.emailOtp.stepUpSend()
        const code = yield* EmailOtpTest.awaitCode(email)
        const [elevated, response] = yield* client.emailOtp.stepUpVerify({
          payload: { code },
          responseMode: "decoded-and-response"
        })

        // The id survives, the level moves, and the cookie carries the rotated
        // token — a session cookie is written on this response.
        assert.strictEqual(elevated.session.id, before.session.id)
        assert.strictEqual(elevated.session.aal, "aal2")
        assert.isTrue(Option.isSome(TestHttpClient.responseCookie(response)))

        const after = yield* client.auth.getSession()
        assert.strictEqual(after.session.aal, "aal2")
        assert.deepStrictEqual(
          after.session.methods.map((entry) => entry.method),
          ["password", "emailOtp"]
        )
      })
    )

    it.effect("moves an account's address through the change-email pair", () =>
      Effect.gen(function* () {
        const email = uniqueEmail("http-mover")
        const destination = uniqueEmail("http-destination")
        const { client } = yield* makeClient()
        yield* client.auth.signUpEmail({ payload: { name: testName, email, password: testPassword } })

        yield* client.emailOtp.changeEmailSend({ payload: { newEmail: destination } })
        const code = yield* EmailOtpTest.awaitCode(destination)
        assert.deepStrictEqual(yield* client.emailOtp.changeEmailVerify({ payload: { code } }), { success: true })

        const after = yield* client.auth.getSession()
        assert.strictEqual(after.user.email, destination)
        assert.isTrue(after.user.emailVerified)
      })
    )

    it.effect("refuses the authenticated pairs to a signed-out browser", () =>
      Effect.gen(function* () {
        const { client } = yield* makeClient()
        assert.strictEqual(yield* failureTag(client.emailOtp.stepUpSend()), "Unauthorized")
        assert.strictEqual(
          yield* failureTag(client.emailOtp.stepUpVerify({ payload: { code: Redacted.make("1") } })),
          "Unauthorized"
        )
        assert.strictEqual(
          yield* failureTag(client.emailOtp.changeEmailSend({ payload: { newEmail: uniqueEmail("nope") } })),
          "Unauthorized"
        )
      })
    )
  })

  layer(
    EmailOtpTest.layerHttp({
      rateLimit: { enabled: true },
      emailOtp: { resendCooldown: Duration.seconds(60) }
    })
  )("with the resend cooldown on", (it) => {
    it.effect("counts a second code against the address, not the caller", () =>
      Effect.gen(function* () {
        const email = uniqueEmail("cooldown")
        const { client } = yield* makeClient()
        yield* client.emailOtp.send({ payload: { email, purpose: "signIn" } })

        // A second caller, at a different address of its own, is still refused:
        // the counter belongs to the mailbox.
        const { client: other } = yield* makeClient({ headers: { "x-forwarded-for": "203.0.113.9" } })
        assert.strictEqual(
          yield* failureTag(other.emailOtp.send({ payload: { email, purpose: "signIn" } })),
          "RateLimited"
        )

        // And another mailbox has its own allowance.
        assert.deepStrictEqual(
          yield* other.emailOtp.send({ payload: { email: uniqueEmail("cooldown-other"), purpose: "signIn" } }),
          { success: true }
        )
      })
    )
  })
})

/**
 * A factor plugin's decider, without the plugin: it owes a second factor to
 * anybody who signs in through this deployment.
 */
const challengeTtl = Duration.minutes(10)
const pendingToken = "pending-authentication-token-for-the-test"

const pipeline: SignInPipelineService = {
  decide: (options) =>
    options.source._tag === "Plugin"
      ? Effect.map(DateTime.now, (now) => ({
          _tag: "Challenge" as const,
          kind: "mfa",
          available: ["totp"],
          token: Redacted.make(pendingToken),
          expiresAt: DateTime.addDuration(now, challengeTtl)
        }))
      : Effect.succeed(proceed)
}

describe.sequential("email-otp/Handlers — a second factor is owed", () => {
  layer(EmailOtpTest.layerHttp({ signInPipeline: pipeline }))("with a challenging decider", (it) => {
    it.effect("answers 202 with the pending cookie and no session cookie", () =>
      Effect.gen(function* () {
        const email = uniqueEmail("http-mfa")
        const { client, cookies } = yield* makeClient()

        yield* client.emailOtp.send({ payload: { email, purpose: "signIn" } })
        const code = yield* EmailOtpTest.awaitCode(email)
        const [result, response] = yield* client.emailOtp.verify({
          payload: { code },
          responseMode: "decoded-and-response"
        })

        assert.strictEqual(response.status, 202)
        assert.strictEqual(result._tag, "MfaRequired")
        if (result._tag !== "MfaRequired") return
        assert.deepStrictEqual(result.available, ["totp"])

        // Neither the address nor the token is on the wire.
        const json = yield* response.text
        assert.isFalse(json.includes(email))
        assert.isFalse(json.includes(pendingToken))

        // One cookie name on this response — the pending one — plus the handle
        // being expired. No session cookie at all.
        const written = Object.keys(Cookies.toRecord(response.cookies)).sort()
        const handleName = yield* handleCookieName
        assert.deepStrictEqual(written, [AuthHandlers.pendingCookieBaseName, handleName].sort())
        assert.isTrue(Option.isNone(TestHttpClient.responseCookie(response)))

        const pending = Option.getOrThrow(Cookies.get(response.cookies, AuthHandlers.pendingCookieBaseName))
        assert.strictEqual(pending.value, pendingToken)
        assert.strictEqual(pending.options?.httpOnly, true)

        // And the browser is signed out.
        assert.strictEqual(yield* TestHttpClient.sessionCookieValue(cookies), "<absent>")
        assert.strictEqual(yield* failureTag(client.auth.getSession()), "Unauthorized")
      })
    )

    it.effect("redirects a challenged link with ?mfa=required and no session cookie", () =>
      Effect.gen(function* () {
        const email = uniqueEmail("http-mfa-link")
        const { client } = yield* makeClient()

        yield* client.emailOtp.send({ payload: { email, purpose: "signIn", callbackURL: "/welcome" } })
        const token = yield* EmailOtpTest.awaitLinkToken(email)
        const [, response] = yield* client.emailOtp.link({
          query: { token },
          responseMode: "decoded-and-response"
        })

        assert.strictEqual(response.status, 302)
        assert.strictEqual(response.headers["location"], `${AuthTest.testBaseUrl}/welcome?mfa=required`)
        assert.isTrue(Option.isNone(TestHttpClient.responseCookie(response)))
        assert.isTrue(Option.isSome(Cookies.get(response.cookies, AuthHandlers.pendingCookieBaseName)))
      })
    )
  })
})
