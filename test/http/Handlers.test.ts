import { assert, describe, it, layer } from "@effect/vitest"
import { Cause, DateTime, Duration, Effect, Option, Redacted, Schema } from "effect"
import { TestClock } from "effect/testing"
import { PolicyRefused } from "../../src/domain/Hooks.js"
import * as AuthHandlers from "../../src/http/Handlers.js"
import { AuthTest, TestHttpClient } from "../../src/testing/index.js"
import { expectSome, testName, testPassword, uniqueEmail } from "../fixtures.js"
import { makeClient, maxAgeSeconds, signedUp } from "./helpers.js"

const sevenDays = Duration.toSeconds(Duration.days(7))
const oneDay = Duration.toSeconds(Duration.days(1))

layer(AuthTest.layerHttp())("http/Handlers", (it) => {
  it.effect("signs a person up, in, out, and refuses them afterwards", () =>
    Effect.gen(function*() {
      const email = uniqueEmail("lifecycle")
      const { client, cookies } = yield* makeClient()

      // --- sign up ------------------------------------------------------
      const registered = yield* client.auth.signUpEmail({
        payload: {
          // Shouted, to prove the address is normalised on the way in.
          name: testName,
          email: email.toUpperCase(),
          password: testPassword
        }
      })
      assert.strictEqual(registered.user.email, email)
      assert.isNotNull(registered.user.id)
      assert.isNotNull(registered.session)
      // The session projection is the JSON variant: the digest of the token
      // is not in it, and there is no field that could carry the token.
      assert.isFalse(Object.hasOwn(registered.session!, "tokenHash"))

      const afterSignUp = yield* TestHttpClient.sessionCookie(cookies)
      assert.isTrue(Option.isSome(afterSignUp))

      // --- sign out, so the sign-in below is the thing under test -------
      yield* client.auth.signOut()
      assert.strictEqual(yield* TestHttpClient.sessionCookieValue(cookies), "")

      // --- sign in ------------------------------------------------------
      const signedIn = yield* client.auth.signInEmail({
        payload: { email, password: testPassword }
      })
      assert.strictEqual(signedIn.user.id, registered.user.id)

      const cookie = yield* TestHttpClient.sessionCookie(cookies)
      const session = yield* expectSome(cookie, "signing in should set the session cookie")
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
          currentPassword: testPassword,
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

      const cleared = yield* expectSome(
        yield* TestHttpClient.sessionCookie(cookies),
        "signing out should write an expiring cookie"
      )
      assert.strictEqual(cleared.value, "")
      assert.deepStrictEqual(cleared.options?.expires, new Date(0))

      const refused = yield* Effect.flip(client.auth.getSession())
      assert.strictEqual(refused._tag, "Unauthorized")
    }))

  it.effect("answers the same InvalidCredentials for a wrong password and an unknown address", () =>
    Effect.gen(function*() {
      const email = uniqueEmail("credentials")
      const { client } = yield* signedUp(email)

      const wrongPassword = yield* Effect.flip(client.auth.signInEmail({
        payload: { email, password: Redacted.make("not the password") }
      }))
      const unknownAddress = yield* Effect.flip(client.auth.signInEmail({
        payload: { email: uniqueEmail("nobody"), password: Redacted.make("not the password") }
      }))

      assert.strictEqual(wrongPassword._tag, "InvalidCredentials")
      assert.deepStrictEqual(wrongPassword, unknownAddress)
    }))

  it.effect("reports UserAlreadyExists for a second sign-up, whatever the address's case", () =>
    Effect.gen(function*() {
      const email = uniqueEmail("duplicate")
      const { client } = yield* signedUp(email)
      const error = yield* Effect.flip(client.auth.signUpEmail({
        payload: {
          name: "Impostor",
          email: email.toUpperCase(),
          password: Redacted.make("another perfectly fine password")
        }
      }))
      assert.strictEqual(error._tag, "UserAlreadyExists")
    }))

  it.effect("enforces the password policy before creating anything", () =>
    Effect.gen(function*() {
      const { client } = yield* makeClient()
      const error = yield* Effect.flip(client.auth.signUpEmail({
        payload: { name: testName, email: uniqueEmail("policy"), password: Redacted.make("short") }
      }))
      assert.strictEqual(error._tag, "PasswordPolicyViolation")
      if (error._tag === "PasswordPolicyViolation") {
        assert.strictEqual(error.reason, "TooShort")
        assert.strictEqual(error.minLength, 8)
      }
    }))

  // A configuration variant: everything above the database is rebuilt for this
  // sub-block, and the database itself is inherited from the block above.
  it.layer(AuthTest.layerHttp({ emailPassword: { requireEmailVerification: true } }))(
    "when the address must be verified first",
    (it) => {
      it.effect("withholds the session until the e-mailed link is followed", () =>
        Effect.gen(function*() {
          const email = uniqueEmail("verify")
          const { client, cookies } = yield* makeClient()
          const registered = yield* client.auth.signUpEmail({
            payload: { name: testName, email, password: testPassword }
          })

          assert.isNull(registered.session)
          assert.isTrue(Option.isNone(yield* TestHttpClient.sessionCookie(cookies)))

          const refused = yield* Effect.flip(client.auth.signInEmail({
            payload: { email, password: testPassword }
          }))
          assert.strictEqual(refused._tag, "EmailNotVerified")

          // The verification mail went out with the sign-up.
          const emails = yield* AuthTest.TestEmails
          const sent = yield* expectSome(
            yield* emails.last("verification", email),
            "signing up should send a verification e-mail"
          )
          yield* client.auth.verifyEmail({ query: { token: TestHttpClient.tokenOf(sent) } })

          const signedIn = yield* client.auth.signInEmail({
            payload: { email, password: testPassword }
          })
          assert.strictEqual(signedIn.user.emailVerified, true)
          assert.isTrue(Option.isSome(yield* TestHttpClient.sessionCookie(cookies)))

          // The token was spent by the first use.
          const replayed = yield* Effect.flip(
            client.auth.verifyEmail({ query: { token: TestHttpClient.tokenOf(sent) } })
          )
          assert.strictEqual(replayed._tag, "InvalidToken")
        }))
    }
  )

  it.effect("resets a forgotten password from another browser, and ends every session", () =>
    Effect.gen(function*() {
      const email = uniqueEmail("reset")
      const signedIn = yield* signedUp(email)
      const other = yield* makeClient()
      const emails = yield* AuthTest.TestEmails

      // Always acknowledged, whether or not the address is known.
      const unknown = yield* other.client.auth.requestPasswordReset({
        payload: { email: uniqueEmail("nobody") }
      })
      assert.strictEqual(unknown.success, true)

      yield* other.client.auth.requestPasswordReset({ payload: { email } })
      const sent = yield* expectSome(
        yield* emails.last("reset", email),
        "a reset e-mail should have gone out"
      )
      assert.strictEqual(sent.to, email)

      yield* other.client.auth.resetPassword({
        payload: {
          token: Redacted.make(TestHttpClient.tokenOf(sent)),
          newPassword: Redacted.make("an entirely new password")
        }
      })

      // The browser that was signed in has been signed out.
      const refused = yield* Effect.flip(signedIn.client.auth.getSession())
      assert.strictEqual(refused._tag, "Unauthorized")

      // The old password no longer works; the new one does.
      const stale = yield* Effect.flip(other.client.auth.signInEmail({
        payload: { email, password: Redacted.make(signedIn.password) }
      }))
      assert.strictEqual(stale._tag, "InvalidCredentials")

      yield* other.client.auth.signInEmail({
        payload: { email, password: Redacted.make("an entirely new password") }
      })

      // Single use: the same link cannot be redeemed twice.
      const replayed = yield* Effect.flip(other.client.auth.resetPassword({
        payload: {
          token: Redacted.make(TestHttpClient.tokenOf(sent)),
          newPassword: Redacted.make("yet another password")
        }
      }))
      assert.strictEqual(replayed._tag, "InvalidToken")
    }))

  it.effect("refuses a change of password that does not know the current one", () =>
    Effect.gen(function*() {
      const { client } = yield* signedUp(uniqueEmail("wrong-current"))
      const error = yield* Effect.flip(client.auth.changePassword({
        payload: {
          currentPassword: Redacted.make("not the current password"),
          newPassword: Redacted.make("a different long password")
        }
      }))
      assert.strictEqual(error._tag, "InvalidCredentials")
    }))

  it.effect("revokes the other browsers and leaves this one signed in", () =>
    Effect.gen(function*() {
      const first = yield* signedUp(uniqueEmail("revoke-others"))
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
    }))

  it.effect("revokes one session by id, and reports another user's as NotFound", () =>
    Effect.gen(function*() {
      const first = yield* signedUp(uniqueEmail("revoke-one"))
      const second = yield* makeClient()
      const other = yield* second.client.auth.signInEmail({
        payload: { email: first.email, password: Redacted.make(first.password) }
      })

      yield* first.client.auth.revokeSession({ payload: { sessionId: other.session.id } })
      const refused = yield* Effect.flip(second.client.auth.getSession())
      assert.strictEqual(refused._tag, "Unauthorized")

      const stranger = yield* signedUp(uniqueEmail("stranger"))
      const mine = yield* stranger.client.auth.getSession()

      const notFound = yield* Effect.flip(
        first.client.auth.revokeSession({ payload: { sessionId: mine.session.id } })
      )
      assert.strictEqual(notFound._tag, "NotFound")
      // And it really did not revoke it.
      yield* stranger.client.auth.getSession()
    }))

  it.effect("clears this browser's cookies when it revokes its own session", () =>
    Effect.gen(function*() {
      const browser = yield* signedUp(uniqueEmail("revoke-self"))
      const mine = yield* browser.client.auth.getSession()

      yield* browser.client.auth.revokeSession({ payload: { sessionId: mine.session.id } })

      // The row is gone and the session cookie is expired on the same response,
      // so the cookie cache cannot keep this browser authenticated behind a
      // snapshot until it ages out.
      assert.strictEqual(yield* TestHttpClient.sessionCookieValue(browser.cookies), "")
      const after = yield* Effect.flip(browser.client.auth.getSession())
      assert.strictEqual(after._tag, "Unauthorized")
    }))

  it.effect("signs every browser out when all sessions are revoked", () =>
    Effect.gen(function*() {
      const first = yield* signedUp(uniqueEmail("revoke-all"))
      const second = yield* makeClient()
      yield* second.client.auth.signInEmail({
        payload: { email: first.email, password: Redacted.make(first.password) }
      })

      yield* second.client.auth.revokeSessions()

      assert.strictEqual(yield* TestHttpClient.sessionCookieValue(second.cookies), "")
      const here = yield* Effect.flip(second.client.auth.getSession())
      const there = yield* Effect.flip(first.client.auth.getSession())
      assert.strictEqual(here._tag, "Unauthorized")
      assert.strictEqual(there._tag, "Unauthorized")
    }))

  it.effect("lists the sign-in methods without any secret on them", () =>
    Effect.gen(function*() {
      const { client } = yield* signedUp(uniqueEmail("accounts"))
      const accounts = yield* client.auth.listAccounts()

      assert.strictEqual(accounts.length, 1)
      const account = accounts[0]!
      assert.strictEqual(account.providerId, "credential")
      assert.strictEqual(account.issuer, "local:credential")
      for (const field of ["passwordHash", "accessToken", "refreshToken", "idToken"]) {
        assert.isFalse(Object.hasOwn(account, field), `${field} must not reach a client`)
      }
    }))

  it.effect("refuses to unlink the only remaining sign-in method", () =>
    Effect.gen(function*() {
      const { client } = yield* signedUp(uniqueEmail("unlink"))
      const accounts = yield* client.auth.listAccounts()

      const error = yield* Effect.flip(
        client.auth.unlinkAccount({ payload: { accountId: accounts[0]!.id } })
      )
      assert.strictEqual(error._tag, "CannotUnlinkLastAccount")
    }))

  /**
   * What the cookie's `Max-Age` says.
   *
   * **Details**
   *
   * `rememberMe: false` is a promise about the *browser*, not only about the
   * session row: the cookie must carry no `Max-Age` at all, so that it dies
   * when the window does. Every other cookie this library writes — a plain
   * sign-in, and the one the rolling refresh re-sends — carries a `Max-Age`
   * mirroring what is left of the session, so the browser forgets it at the
   * moment the server does.
   */
  describe("cookie persistence", () => {
    it.effect("omits Max-Age entirely when the caller declined to be remembered", () =>
      Effect.gen(function*() {
        const registered = yield* signedUp(uniqueEmail("no-max-age"))

        const browser = yield* makeClient()
        const [, response] = yield* browser.client.auth.signInEmail({
          payload: {
            email: registered.email,
            password: Redacted.make(registered.password),
            rememberMe: false
          },
          responseMode: "decoded-and-response"
        })

        assert.isTrue(Option.isSome(TestHttpClient.responseCookie(response)), "no session cookie was written")
        assert.strictEqual(maxAgeSeconds(response), undefined)
      }))

    it.effect("gives an ordinary sign-in a Max-Age that mirrors the session's lifetime", () =>
      Effect.gen(function*() {
        const registered = yield* signedUp(uniqueEmail("max-age"))

        const browser = yield* makeClient()
        const [, response] = yield* browser.client.auth.signInEmail({
          payload: { email: registered.email, password: Redacted.make(registered.password) },
          responseMode: "decoded-and-response"
        })

        assert.strictEqual(maxAgeSeconds(response), sevenDays)
      }))

    it.effect("shortens Max-Age with the session when rememberMe is off but the row still persists", () =>
      Effect.gen(function*() {
        const browser = yield* makeClient()
        const [, response] = yield* browser.client.auth.signUpEmail({
          payload: {
            name: testName,
            email: uniqueEmail("short-row"),
            password: testPassword,
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
      }))
  })

  // The four tests that move the clock, on a deployment whose clock they own.
  // They run in order and share that clock, which costs them nothing: each one
  // signs its own account up first and then measures from there.
  it.layer(AuthTest.layerHttpMovingClock())("as time passes", (it) => {
    describe.sequential("on the deployment's own clock", () => {
      it.effect("requires a fresh session to change a password", () =>
        Effect.gen(function*() {
          const { client } = yield* signedUp(uniqueEmail("stale"))
          // Older than the default one-day freshAge, and still well inside the
          // seven-day expiry.
          yield* TestClock.adjust(Duration.days(2))

          const error = yield* Effect.flip(client.auth.changePassword({
            payload: {
              currentPassword: testPassword,
              newPassword: Redacted.make("a different long password")
            }
          }))

          assert.strictEqual(error._tag, "SessionNotFresh")
          if (error._tag === "SessionNotFresh") {
            assert.strictEqual(error.freshAgeSeconds, 86_400)
          }
          // The session itself is still perfectly good.
          yield* client.auth.getSession()
        }))

      it.effect("rolls the expiry forward and re-sends the cookie once updateAge has passed", () =>
        Effect.gen(function*() {
          const { client, cookies } = yield* signedUp(uniqueEmail("rolling"))
          const before = yield* client.auth.getSession()
          const token = yield* TestHttpClient.sessionCookieValue(cookies)

          yield* TestClock.adjust(Duration.days(2))

          const [after, response] = yield* client.auth.getSession({
            responseMode: "decoded-and-response"
          })

          assert.isAbove(
            DateTime.toEpochMillis(after.session.expiresAt),
            DateTime.toEpochMillis(before.session.expiresAt)
          )
          // Re-sent under the same name, carrying the same opaque token: a
          // refresh moves the expiry, it does not mint a new session.
          assert.isTrue(Option.isSome(TestHttpClient.responseCookie(response)))
          assert.strictEqual(yield* TestHttpClient.sessionCookieValue(cookies), token)

          // And it is not re-sent on a request that is not yet due.
          const [, second] = yield* client.auth.getSession({ responseMode: "decoded-and-response" })
          assert.isTrue(Option.isNone(TestHttpClient.responseCookie(second)))
        }))

      it.effect("re-sends a full Max-Age when the rolling refresh moves the expiry", () =>
        Effect.gen(function*() {
          const { client } = yield* signedUp(uniqueEmail("refresh-max-age"))
          yield* TestClock.adjust(Duration.days(2))

          const [, response] = yield* client.auth.getSession({ responseMode: "decoded-and-response" })

          // The refresh rolls the expiry to `now + expiresIn`, and the cookie
          // says exactly that: a browser holding it stops sending it at the same
          // moment the row stops being accepted.
          assert.strictEqual(maxAgeSeconds(response), sevenDays)
        }))

      it.effect("reports an expired session as Unauthorized", () =>
        Effect.gen(function*() {
          const { client } = yield* signedUp(uniqueEmail("expired"))
          yield* TestClock.adjust(Duration.days(8))

          const error = yield* Effect.flip(client.auth.getSession())
          assert.strictEqual(error._tag, "Unauthorized")
        }))
    })
  })

  // A `describe` inside this block rather than a second top-level `layer()`:
  // the deployment is the same one, so grouping keeps the file on the single
  // PGlite the block above booted.
  describe("opt-in flows", () => {
    it.effect("does not serve change-email or delete-user until a deployment asks for them", () =>
      Effect.gen(function*() {
        const { client } = yield* signedUp(uniqueEmail("opt-in-off"))

        // The endpoints are *declared* unconditionally — a schema-driven API has
        // one shape, not one per configuration — so a deployment that has not
        // opted in answers 404, which is what "this deployment does not serve
        // that" means over HTTP rather than inventing an error the contract does
        // not mention.
        assert.strictEqual(
          yield* TestHttpClient.refusedStatus(
            client.auth.changeEmail({ payload: { newEmail: uniqueEmail("opt-in-new") } })
          ),
          404
        )
        assert.strictEqual(yield* TestHttpClient.refusedStatus(client.auth.deleteUser({ payload: {} })), 404)
        assert.strictEqual(
          yield* TestHttpClient.refusedStatus(client.auth.confirmEmailChange({ query: { token: "irrelevant" } })),
          404
        )

        // And the account is still there, which is the assertion that matters.
        const session = yield* client.auth.getSession()
        assert.strictEqual(session.user.emailVerified, false)
      }))

    it.layer(AuthTest.layerHttp({ user: { changeEmail: { enabled: true }, deleteUser: { enabled: true } } }))(
      "once they are switched on",
      (it) => {
        it.effect("stops answering 404 and reaches the domain instead", () =>
          Effect.gen(function*() {
            const { client } = yield* signedUp(uniqueEmail("opt-in-on"))
            const newEmail = uniqueEmail("opt-in-next")

            // The gate is the only thing under test here: the request now gets
            // past it and into the service, which does what it does. What that is
            // — the two hops, the enumeration rules, the freshness guard — is
            // `test/http/Users.test.ts`'s subject.
            const answered = yield* client.auth.changeEmail({ payload: { newEmail } })
            assert.strictEqual(answered.success, true)
            // Reaching the service is what a 404 would have prevented, and this
            // is the evidence of it: the flow has begun. This account's own
            // address is unverified, so it begins at the second hop.
            const emails = yield* AuthTest.TestEmails
            assert.isTrue(Option.isSome(yield* emails.last(AuthTest.changeEmailVerificationKind, newEmail)))
          }))
      }
    )
  })

  describe("form_post callback", () => {
    it.effect("turns a cross-site POST into a top-level GET carrying the same parameters", () =>
      Effect.gen(function*() {
        const { client, cookies } = yield* makeClient()

        const [, response] = yield* client.auth.oauthCallbackForm({
          params: { providerId: "apple" },
          payload: { code: "the-code", state: "the-state", user: `{"name":{"firstName":"Ada"}}` },
          responseMode: "decoded-and-response"
        })

        // The whole endpoint is a hop. A cross-site POST carries no
        // `SameSite=Lax` cookie, so completing the flow here could neither read
        // this browser's session nor write one it would keep.
        assert.strictEqual(response.status, 302)
        const location = new URL(response.headers["location"] ?? "")
        assert.strictEqual(location.origin, "http://localhost:3000")
        assert.strictEqual(location.pathname, "/auth/callback/apple")
        assert.strictEqual(location.searchParams.get("code"), "the-code")
        assert.strictEqual(location.searchParams.get("state"), "the-state")
        assert.strictEqual(location.searchParams.get("user"), `{"name":{"firstName":"Ada"}}`)
        // Nothing the provider did not send.
        assert.isFalse(location.searchParams.has("error"))
        // And nothing is signed in by a hop.
        assert.strictEqual(yield* TestHttpClient.sessionCookieValue(cookies), "<absent>")
      }))

    it.effect("sends the browser to this deployment, whatever the provider named", () =>
      Effect.gen(function*() {
        // The target is built from `baseUrl` and `basePath`, never from the
        // request's own `Host` — which is attacker-controllable, and a `Location`
        // built from one is an open redirect.
        const { client } = yield* makeClient({ headers: { host: "evil.test" } })

        const [, response] = yield* client.auth.oauthCallbackForm({
          params: { providerId: "apple" },
          payload: { error: "user_cancelled_authorize" },
          responseMode: "decoded-and-response"
        })

        const location = new URL(response.headers["location"] ?? "")
        assert.strictEqual(location.origin, "http://localhost:3000")
        assert.strictEqual(location.searchParams.get("error"), "user_cancelled_authorize")
      }))

    it.effect("escapes a provider id rather than letting it shape the path", () =>
      Effect.gen(function*() {
        const { client } = yield* makeClient()

        const [, response] = yield* client.auth.oauthCallbackForm({
          params: { providerId: "../../evil" },
          payload: {},
          responseMode: "decoded-and-response"
        })

        const location = new URL(response.headers["location"] ?? "")
        assert.strictEqual(location.pathname, "/auth/callback/..%2F..%2Fevil")
      }))
  })

  // ---------------------------------------------------------------------------
  // A deployment's own policy, over HTTP
  // ---------------------------------------------------------------------------

  it.layer(AuthTest.layerHttp({
    hooks: {
      beforeUserCreate: ({ candidate }) =>
        candidate.email.includes("policy-veto")
          ? Effect.fail(new PolicyRefused({ code: "domain_not_allowed" }))
          : Effect.succeed(candidate),
      beforeSessionCreate: ({ user }) =>
        user.email.includes("policy-banned")
          ? Effect.fail(new PolicyRefused({ code: "banned" }))
          : Effect.void
    }
  }))("when a deployment installed hooks", (it) => {
    it.effect("answers 403 PolicyRefused, carrying the code the hook chose", () =>
      Effect.gen(function*() {
        const { client } = yield* makeClient()

        const refused = yield* Effect.flip(client.auth.signUpEmail({
          payload: { name: testName, email: uniqueEmail("policy-veto"), password: testPassword }
        }))

        assert.strictEqual(refused._tag, "PolicyRefused")
        if (refused._tag === "PolicyRefused") {
          // The deployment's own classification, over the wire verbatim: it is
          // what a client branches on, and it is why a hook must never build
          // one out of a secret.
          assert.strictEqual(refused.code, "domain_not_allowed")
        }
      }))

    it.effect("registers the account but writes no cookie when only the session was refused", () =>
      Effect.gen(function*() {
        const email = uniqueEmail("policy-banned")
        const { client, cookies } = yield* makeClient()

        const [registered, response] = yield* client.auth.signUpEmail({
          payload: { name: testName, email, password: testPassword },
          responseMode: "decoded-and-response"
        })

        // A success, not a refusal: the account exists, and `session: null` is
        // the shape this response already has for a deployment that withholds
        // one. What must not happen is a cookie for a session nobody minted.
        assert.strictEqual(response.status, 200)
        assert.strictEqual(registered.user.email, email)
        assert.isNull(registered.session)
        assert.isTrue(Option.isNone(TestHttpClient.responseCookie(response)))
        assert.isTrue(Option.isNone(yield* TestHttpClient.sessionCookie(cookies)))

        // And signing in is refused outright, because there the session is the
        // whole of what was asked for.
        const refused = yield* Effect.flip(client.auth.signInEmail({
          payload: { email, password: testPassword }
        }))
        assert.strictEqual(refused._tag, "PolicyRefused")
        if (refused._tag === "PolicyRefused") assert.strictEqual(refused.code, "banned")
      }))
  })
})

describe("http/Handlers dieOn", () => {
  class Broken extends Schema.TaggedError<Broken>("Broken")("Broken", {}) {}
  class Refused extends Schema.TaggedError<Refused>("Refused")("Refused", {}) {}

  const filter = AuthHandlers.dieOn(["Broken"] as const)

  it.effect("takes the named tags out of the error channel and into the defects", () =>
    Effect.gen(function*() {
      const died = yield* Effect.exit(filter(Effect.fail(new Broken())))
      assert.strictEqual(died._tag, "Failure")
      assert.isTrue(died._tag === "Failure" && Cause.hasDies(died.cause))
    }))

  it.effect("leaves every other failure exactly where it was", () =>
    Effect.gen(function*() {
      const failed: Refused = yield* Effect.flip(filter(Effect.fail(new Refused())))
      assert.strictEqual(failed._tag, "Refused")

      // And the two server faults are what `serverFault` is `dieOn` of.
      assert.deepStrictEqual([...AuthHandlers.serverFaultTags], ["PasswordHashError", "PersistenceError"])
    }))
})
