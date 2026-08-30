import { assert, describe, it } from "@effect/vitest"
import { DateTime, Duration, Effect, Option, Redacted } from "effect"
import { TestClock } from "effect/testing"
import {
  makeClient,
  responseCookie,
  sessionCookie,
  sessionCookieValue,
  signedUp,
  testLayer,
  testTimeout,
  TestEmails,
  tokenOf
} from "./harness.js"

describe("http/Handlers", () => {
  it.effect(
    "signs a person up, in, out, and refuses them afterwards",
    () =>
      Effect.gen(function*() {
        const { client, cookies } = yield* makeClient()

        // --- sign up ------------------------------------------------------
        const registered = yield* client.auth.signUpEmail({
          payload: {
            name: "Ada Lovelace",
            email: "Ada@Example.com",
            password: Redacted.make("correct horse battery staple")
          }
        })
        assert.strictEqual(registered.user.email, "ada@example.com")
        assert.isNotNull(registered.user.id)
        assert.isNotNull(registered.session)
        // The session projection is the JSON variant: the digest of the token
        // is not in it, and there is no field that could carry the token.
        assert.isFalse(Object.hasOwn(registered.session!, "tokenHash"))

        const afterSignUp = yield* sessionCookie(cookies)
        assert.isTrue(Option.isSome(afterSignUp))

        // --- sign out, so the sign-in below is the thing under test -------
        yield* client.auth.signOut()
        assert.strictEqual(yield* sessionCookieValue(cookies), "")

        // --- sign in ------------------------------------------------------
        const signedIn = yield* client.auth.signInEmail({
          payload: {
            email: "ada@example.com",
            password: Redacted.make("correct horse battery staple")
          }
        })
        assert.strictEqual(signedIn.user.id, registered.user.id)

        const cookie = yield* sessionCookie(cookies)
        assert.isTrue(Option.isSome(cookie))
        const session = cookie.pipe(Option.getOrThrow)
        // The raw token is 32 random bytes, base64url encoded.
        assert.strictEqual(session.value.length, 43)
        assert.strictEqual(session.options?.httpOnly, true)
        assert.strictEqual(session.options?.sameSite, "lax")
        assert.strictEqual(session.options?.path, "/")
        // Plain HTTP base URL: no `Secure`, and therefore no `__Secure-` name.
        assert.notStrictEqual(session.options?.secure, true)
        assert.strictEqual(session.name, "effect_auth.session")

        // --- read it back --------------------------------------------------
        const current = yield* client.auth.getSession()
        assert.strictEqual(current.user.id, registered.user.id)
        assert.strictEqual(current.session.id, signedIn.session.id)

        // --- change the password, which the fresh session permits ----------
        yield* client.auth.changePassword({
          payload: {
            currentPassword: Redacted.make("correct horse battery staple"),
            newPassword: Redacted.make("a different long password")
          }
        })
        // The caller's own session survives its own password change.
        yield* client.auth.getSession()

        // --- revoke the others ---------------------------------------------
        yield* client.auth.revokeOtherSessions()
        yield* client.auth.getSession()

        // --- sign out -------------------------------------------------------
        const done = yield* client.auth.signOut()
        assert.strictEqual(done.success, true)

        const cleared = yield* sessionCookie(cookies)
        assert.isTrue(Option.isSome(cleared))
        assert.strictEqual(cleared.pipe(Option.getOrThrow).value, "")
        assert.deepStrictEqual(cleared.pipe(Option.getOrThrow).options?.expires, new Date(0))

        const refused = yield* Effect.flip(client.auth.getSession())
        assert.strictEqual(refused._tag, "Unauthorized")
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "answers the same InvalidCredentials for a wrong password and an unknown address",
    () =>
      Effect.gen(function*() {
        const { client } = yield* signedUp()

        const wrongPassword = yield* Effect.flip(client.auth.signInEmail({
          payload: { email: "ada@example.com", password: Redacted.make("not the password") }
        }))
        const unknownAddress = yield* Effect.flip(client.auth.signInEmail({
          payload: { email: "nobody@example.com", password: Redacted.make("not the password") }
        }))

        assert.strictEqual(wrongPassword._tag, "InvalidCredentials")
        assert.deepStrictEqual(wrongPassword, unknownAddress)
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "reports UserAlreadyExists for a second sign-up, whatever the address's case",
    () =>
      Effect.gen(function*() {
        const { client } = yield* signedUp()
        const error = yield* Effect.flip(client.auth.signUpEmail({
          payload: {
            name: "Impostor",
            email: "ADA@example.com",
            password: Redacted.make("another long enough password")
          }
        }))
        assert.strictEqual(error._tag, "UserAlreadyExists")
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "enforces the password policy before creating anything",
    () =>
      Effect.gen(function*() {
        const { client } = yield* makeClient()
        const error = yield* Effect.flip(client.auth.signUpEmail({
          payload: { name: "Ada", email: "ada@example.com", password: Redacted.make("short") }
        }))
        assert.strictEqual(error._tag, "PasswordPolicyViolation")
        if (error._tag === "PasswordPolicyViolation") {
          assert.strictEqual(error.reason, "TooShort")
          assert.strictEqual(error.minLength, 8)
        }
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "withholds the session when the address must be verified first",
    () =>
      Effect.gen(function*() {
        const { client, cookies } = yield* makeClient()
        const registered = yield* client.auth.signUpEmail({
          payload: {
            name: "Ada Lovelace",
            email: "ada@example.com",
            password: Redacted.make("correct horse battery staple")
          }
        })

        assert.isNull(registered.session)
        assert.isTrue(Option.isNone(yield* sessionCookie(cookies)))

        const refused = yield* Effect.flip(client.auth.signInEmail({
          payload: {
            email: "ada@example.com",
            password: Redacted.make("correct horse battery staple")
          }
        }))
        assert.strictEqual(refused._tag, "EmailNotVerified")

        // The verification mail went out with the sign-up.
        const emails = yield* TestEmails
        const sent = yield* emails.last("verification")
        yield* client.auth.verifyEmail({ query: { token: tokenOf(sent) } })

        const signedIn = yield* client.auth.signInEmail({
          payload: {
            email: "ada@example.com",
            password: Redacted.make("correct horse battery staple")
          }
        })
        assert.strictEqual(signedIn.user.emailVerified, true)
        assert.isTrue(Option.isSome(yield* sessionCookie(cookies)))

        // The token was spent by the first use.
        const replayed = yield* Effect.flip(client.auth.verifyEmail({ query: { token: tokenOf(sent) } }))
        assert.strictEqual(replayed._tag, "InvalidToken")
      }).pipe(Effect.provide(testLayer({ emailPassword: { requireEmailVerification: true } }))),
    testTimeout
  )

  it.effect(
    "resets a forgotten password from another browser, and ends every session",
    () =>
      Effect.gen(function*() {
        const signedIn = yield* signedUp()
        const other = yield* makeClient()

        // Always acknowledged, whether or not the address is known.
        const unknown = yield* other.client.auth.requestPasswordReset({
          payload: { email: "nobody@example.com" }
        })
        assert.strictEqual(unknown.success, true)

        yield* other.client.auth.requestPasswordReset({ payload: { email: "ada@example.com" } })
        const emails = yield* TestEmails
        const sent = yield* emails.last("reset")
        assert.strictEqual(sent.user.email, "ada@example.com")

        yield* other.client.auth.resetPassword({
          payload: {
            token: Redacted.make(tokenOf(sent)),
            newPassword: Redacted.make("an entirely new password")
          }
        })

        // The browser that was signed in has been signed out.
        const refused = yield* Effect.flip(signedIn.client.auth.getSession())
        assert.strictEqual(refused._tag, "Unauthorized")

        // The old password no longer works; the new one does.
        const stale = yield* Effect.flip(other.client.auth.signInEmail({
          payload: { email: "ada@example.com", password: Redacted.make(signedIn.password) }
        }))
        assert.strictEqual(stale._tag, "InvalidCredentials")

        yield* other.client.auth.signInEmail({
          payload: { email: "ada@example.com", password: Redacted.make("an entirely new password") }
        })

        // Single use: the same link cannot be redeemed twice.
        const replayed = yield* Effect.flip(other.client.auth.resetPassword({
          payload: {
            token: Redacted.make(tokenOf(sent)),
            newPassword: Redacted.make("yet another password")
          }
        }))
        assert.strictEqual(replayed._tag, "InvalidToken")
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "requires a fresh session to change a password",
    () =>
      Effect.gen(function*() {
        const { client } = yield* signedUp()
        // Older than the default one-day freshAge, and still well inside the
        // seven-day expiry.
        yield* TestClock.adjust(Duration.days(2))

        const error = yield* Effect.flip(client.auth.changePassword({
          payload: {
            currentPassword: Redacted.make("correct horse battery staple"),
            newPassword: Redacted.make("a different long password")
          }
        }))

        assert.strictEqual(error._tag, "SessionNotFresh")
        if (error._tag === "SessionNotFresh") {
          assert.strictEqual(error.freshAgeSeconds, 86_400)
        }
        // The session itself is still perfectly good.
        yield* client.auth.getSession()
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "refuses a change of password that does not know the current one",
    () =>
      Effect.gen(function*() {
        const { client } = yield* signedUp()
        const error = yield* Effect.flip(client.auth.changePassword({
          payload: {
            currentPassword: Redacted.make("not the current password"),
            newPassword: Redacted.make("a different long password")
          }
        }))
        assert.strictEqual(error._tag, "InvalidCredentials")
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "revokes the other browsers and leaves this one signed in",
    () =>
      Effect.gen(function*() {
        const first = yield* signedUp()
        const second = yield* makeClient()
        yield* second.client.auth.signInEmail({
          payload: { email: first.email, password: Redacted.make(first.password) }
        })

        const listed = yield* second.client.auth.listSessions()
        assert.strictEqual(listed.length, 2)

        yield* second.client.auth.revokeOtherSessions()

        yield* second.client.auth.getSession()
        const refused = yield* Effect.flip(first.client.auth.getSession())
        assert.strictEqual(refused._tag, "Unauthorized")
        assert.strictEqual((yield* second.client.auth.listSessions()).length, 1)
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "revokes one session by id, and reports another user's as NotFound",
    () =>
      Effect.gen(function*() {
        const first = yield* signedUp()
        const second = yield* makeClient()
        const other = yield* second.client.auth.signInEmail({
          payload: { email: first.email, password: Redacted.make(first.password) }
        })

        yield* first.client.auth.revokeSession({ payload: { sessionId: other.session.id } })
        const refused = yield* Effect.flip(second.client.auth.getSession())
        assert.strictEqual(refused._tag, "Unauthorized")

        const stranger = yield* makeClient()
        yield* stranger.client.auth.signUpEmail({
          payload: {
            name: "Grace Hopper",
            email: "grace@example.com",
            password: Redacted.make("another perfectly fine password")
          }
        })
        const mine = yield* stranger.client.auth.getSession()

        const notFound = yield* Effect.flip(
          first.client.auth.revokeSession({ payload: { sessionId: mine.session.id } })
        )
        assert.strictEqual(notFound._tag, "NotFound")
        // And it really did not revoke it.
        yield* stranger.client.auth.getSession()
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "signs every browser out when all sessions are revoked",
    () =>
      Effect.gen(function*() {
        const first = yield* signedUp()
        const second = yield* makeClient()
        yield* second.client.auth.signInEmail({
          payload: { email: first.email, password: Redacted.make(first.password) }
        })

        yield* second.client.auth.revokeSessions()

        assert.strictEqual(yield* sessionCookieValue(second.cookies), "")
        const here = yield* Effect.flip(second.client.auth.getSession())
        const there = yield* Effect.flip(first.client.auth.getSession())
        assert.strictEqual(here._tag, "Unauthorized")
        assert.strictEqual(there._tag, "Unauthorized")
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "lists the sign-in methods without any secret on them",
    () =>
      Effect.gen(function*() {
        const { client } = yield* signedUp()
        const accounts = yield* client.auth.listAccounts()

        assert.strictEqual(accounts.length, 1)
        const account = accounts[0]!
        assert.strictEqual(account.providerId, "credential")
        assert.strictEqual(account.issuer, "local:credential")
        for (const field of ["passwordHash", "accessToken", "refreshToken", "idToken"]) {
          assert.isFalse(Object.hasOwn(account, field), `${field} must not reach a client`)
        }
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "refuses to unlink the only remaining sign-in method",
    () =>
      Effect.gen(function*() {
        const { client } = yield* signedUp()
        const accounts = yield* client.auth.listAccounts()

        const error = yield* Effect.flip(
          client.auth.unlinkAccount({ payload: { accountId: accounts[0]!.id } })
        )
        assert.strictEqual(error._tag, "CannotUnlinkLastAccount")
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "rolls the expiry forward and re-sends the cookie once updateAge has passed",
    () =>
      Effect.gen(function*() {
        const { client, cookies } = yield* signedUp()
        const before = yield* client.auth.getSession()
        const token = yield* sessionCookieValue(cookies)

        yield* TestClock.adjust(Duration.days(2))

        const [after, response] = yield* client.auth.getSession({ responseMode: "decoded-and-response" })

        assert.isAbove(
          DateTime.toEpochMillis(after.session.expiresAt),
          DateTime.toEpochMillis(before.session.expiresAt)
        )
        // Re-sent under the same name, carrying the same opaque token: a
        // refresh moves the expiry, it does not mint a new session.
        assert.isTrue(Option.isSome(responseCookie(response)))
        assert.strictEqual(yield* sessionCookieValue(cookies), token)

        // And it is not re-sent on a request that is not yet due.
        const [, second] = yield* client.auth.getSession({ responseMode: "decoded-and-response" })
        assert.isTrue(Option.isNone(responseCookie(second)))
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "reports an expired session as Unauthorized",
    () =>
      Effect.gen(function*() {
        const { client } = yield* signedUp()
        yield* TestClock.adjust(Duration.days(8))

        const error = yield* Effect.flip(client.auth.getSession())
        assert.strictEqual(error._tag, "Unauthorized")
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )
})

/**
 * What the cookie's `Max-Age` says.
 *
 * **Details**
 *
 * `rememberMe: false` is a promise about the *browser*, not only about the
 * session row: the cookie must carry no `Max-Age` at all, so that it dies when
 * the window does. Every other cookie this library writes — a plain sign-in,
 * and the one the rolling refresh re-sends — carries a `Max-Age` mirroring what
 * is left of the session, so the browser forgets it at the moment the server
 * does.
 */
describe("http/Handlers cookie persistence", () => {
  /** The `Max-Age` a response's session cookie was written with, in seconds. */
  const maxAgeSeconds = (
    response: Parameters<typeof responseCookie>[0]
  ): number | undefined => {
    const cookie = responseCookie(response)
    if (Option.isNone(cookie)) return undefined
    const maxAge = cookie.value.options?.maxAge
    return maxAge === undefined ? undefined : Duration.toSeconds(Duration.fromInputUnsafe(maxAge))
  }

  const sevenDays = Duration.toSeconds(Duration.days(7))
  const oneDay = Duration.toSeconds(Duration.days(1))

  it.effect(
    "omits Max-Age entirely when the caller declined to be remembered",
    () =>
      Effect.gen(function*() {
        const registered = yield* signedUp()

        const browser = yield* makeClient()
        const [, response] = yield* browser.client.auth.signInEmail({
          payload: {
            email: registered.email,
            password: Redacted.make(registered.password),
            rememberMe: false
          },
          responseMode: "decoded-and-response"
        })

        assert.isTrue(Option.isSome(responseCookie(response)), "no session cookie was written")
        assert.strictEqual(maxAgeSeconds(response), undefined)
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "gives an ordinary sign-in a Max-Age that mirrors the session's lifetime",
    () =>
      Effect.gen(function*() {
        const registered = yield* signedUp()

        const browser = yield* makeClient()
        const [, response] = yield* browser.client.auth.signInEmail({
          payload: { email: registered.email, password: Redacted.make(registered.password) },
          responseMode: "decoded-and-response"
        })

        assert.strictEqual(maxAgeSeconds(response), sevenDays)
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "shortens Max-Age with the session when rememberMe is off but the row still persists",
    () =>
      Effect.gen(function*() {
        const browser = yield* makeClient()
        const [, response] = yield* browser.client.auth.signUpEmail({
          payload: {
            name: "Ada Lovelace",
            email: "ada@example.com",
            password: Redacted.make("correct horse battery staple"),
            rememberMe: false
          },
          responseMode: "decoded-and-response"
        })

        // No `Max-Age` on the wire — but the session row itself is the shorter
        // `rememberMeDisabledExpiresIn` one, which is what the *server* forgets.
        assert.strictEqual(maxAgeSeconds(response), undefined)
        const current = yield* browser.client.auth.getSession()
        const now = yield* DateTime.now
        const remaining = Math.round(
          (DateTime.toEpochMillis(current.session.expiresAt) - DateTime.toEpochMillis(now)) / 1000
        )
        assert.strictEqual(remaining, oneDay)
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "re-sends a full Max-Age when the rolling refresh moves the expiry",
    () =>
      Effect.gen(function*() {
        const { client } = yield* signedUp()
        yield* TestClock.adjust(Duration.days(2))

        const [, response] = yield* client.auth.getSession({ responseMode: "decoded-and-response" })

        // The refresh rolls the expiry to `now + expiresIn`, and the cookie
        // says exactly that: a browser holding it stops sending it at the same
        // moment the row stops being accepted.
        assert.strictEqual(maxAgeSeconds(response), sevenDays)
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )
})
