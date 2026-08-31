import { assert, describe, layer } from "@effect/vitest"
import { Duration, Effect, Option, Redacted } from "effect"
import { TestClock } from "effect/testing"
import { Passwords } from "../../src/domain/Passwords.js"
import { Sessions } from "../../src/domain/Sessions.js"
import { AccountStore, UserStore } from "../../src/domain/Stores.js"
import { changeEmailVerifyPurpose } from "../../src/domain/Users.js"
import { passwordResetPurpose, Verifications } from "../../src/domain/Verifications.js"
import { MagicLink, magicLinkPurpose } from "../../src/magic-link/MagicLink.js"
import { AuthTest, MagicLinkTest, TestEmails } from "../../src/testing/index.js"
import { tagsOf, testName, testPassword, uniqueEmail } from "../fixtures.js"

/**
 * Asks for a link and reads the token out of the outbox — which is exactly what
 * its recipient does, and the only way the token is ever available: the database
 * holds nothing but its digest.
 */
const linkFor = (options: {
  readonly email: string
  readonly name?: string | undefined
  readonly callbackURL?: string | undefined
  readonly newUserCallbackURL?: string | undefined
  readonly errorCallbackURL?: string | undefined
  readonly rememberMe?: boolean | undefined
}) =>
  Effect.gen(function*() {
    const magic = yield* MagicLink
    const emails = yield* TestEmails.TestEmails
    yield* magic.request(options)
    return yield* emails.tokenFor(MagicLinkTest.magicLinkKind, options.email)
  })

/** The events of one user, so a concurrent sibling's cannot be read as this test's. */
const forUser = (
  events: ReadonlyArray<{ readonly _tag: string }>,
  userId: string
): ReadonlyArray<{ readonly _tag: string }> =>
  events.filter((event) => "userId" in event && (event as { readonly userId: unknown }).userId === userId)

describe.sequential("magic-link/MagicLink", () => {
  layer(MagicLinkTest.layer())("a deployment that creates accounts from links", (it) => {
    it.effect("mails a link to an address with no account at all", () =>
      Effect.gen(function*() {
        const email = uniqueEmail("stranger")
        const emails = yield* TestEmails.TestEmails
        const magic = yield* MagicLink

        yield* magic.request({ email })

        const sent = yield* emails.to(email)
        assert.strictEqual(sent.length, 1)
        // The mailer is told there is nobody behind the address — a plugin's mail
        // is not always about a user the library knows.
        assert.strictEqual(sent[0]?.user, null)
        assert.strictEqual(sent[0]?.kind, MagicLinkTest.magicLinkKind)
        const url = new URL(Redacted.value(sent[0]!.url))
        assert.strictEqual(url.pathname, "/auth/magic-link/verify")
        assert.strictEqual(url.searchParams.get("token"), Redacted.value(sent[0]!.token))
      }))

    // A nested variant is the documented way to vary the plugin's settings under
    // one database. Its outbox must be its own: `MagicLinkTest.layerEmails` is a
    // module-level constant that vitest memoises across the block, and without
    // `Layer.fresh` in `layerMagicLink` the variant's mail would be recorded in
    // the parent's outbox and never be visible here.
    it.layer(MagicLinkTest.layer({ magicLink: { ttl: Duration.minutes(10) } }))(
      "a nested variant records its mail in its own outbox",
      (it) => {
        it.effect("mails the link where this deployment's tests can read it", () =>
          Effect.gen(function*() {
            const email = uniqueEmail("nested")
            const emails = yield* TestEmails.TestEmails
            const magic = yield* MagicLink

            yield* magic.request({ email })

            const sent = yield* emails.to(email)
            assert.strictEqual(sent.length, 1)
            assert.strictEqual(sent[0]?.kind, MagicLinkTest.magicLinkKind)
            // And the token it carries is claimable against this deployment.
            const token = yield* emails.tokenFor(MagicLinkTest.magicLinkKind, email)
            const verified = yield* magic.verify({ token })
            assert.strictEqual(verified.user.email, email)
          }))
      }
    )

    it.effect("creates the account when the link is followed, already verified", () =>
      Effect.gen(function*() {
        const email = uniqueEmail("new-person")
        const token = yield* linkFor({ email, name: "Ada" })

        const { events, result } = yield* AuthTest.recordingEvents(
          Effect.flatMap(MagicLink, (magic) => magic.verify({ token }))
        )

        assert.isTrue(result.userCreated)
        assert.strictEqual(result.user.email, email)
        assert.strictEqual(result.user.name, "Ada")
        // The token was delivered to the address and came back: that is the whole
        // of what verification ever proves.
        assert.isTrue(result.user.emailVerified)
        assert.deepStrictEqual(tagsOf(forUser(events, result.user.id)), ["UserCreated", "SignedIn"])
        const created = events.find((event) => event._tag === "UserCreated")
        assert.strictEqual(created?._tag === "UserCreated" ? created.method : "", "magic-link")

        // No sign-in method was invented for them: a magic link is not a stored
        // credential.
        const accounts = yield* AccountStore
        assert.deepStrictEqual(yield* accounts.listByUserId(result.user.id), [])
      }))

    it.effect("names the account after the address when the request named nobody", () =>
      Effect.gen(function*() {
        const email = uniqueEmail("nameless")
        const token = yield* linkFor({ email })
        const magic = yield* MagicLink

        const result = yield* magic.verify({ token })
        assert.strictEqual(result.user.name, email)
      }))

    it.effect("signs an existing verified user in, leaving the row alone", () =>
      Effect.gen(function*() {
        const email = uniqueEmail("returning")
        const magic = yield* MagicLink

        const first = yield* magic.verify({ token: yield* linkFor({ email, name: "Ada" }) })
        const second = yield* magic.verify({ token: yield* linkFor({ email, name: "Somebody Else" }) })

        assert.isTrue(first.userCreated)
        assert.isFalse(second.userCreated)
        assert.strictEqual(second.user.id, first.user.id)
        // The name in a later request cannot rename an existing account.
        assert.strictEqual(second.user.name, "Ada")
        // Two sessions, one per link.
        const sessions = yield* Sessions
        assert.strictEqual((yield* sessions.list(first.user.id)).length, 2)
      }))

    it.effect("destroys an unproven account's sign-in methods and sessions", () =>
      Effect.gen(function*() {
        // Somebody registers an address they do not own, and waits.
        const email = uniqueEmail("squatted")
        const passwords = yield* Passwords
        const registered = yield* passwords.signUp({ name: testName, email, password: testPassword })
        assert.isFalse(registered.user.emailVerified)

        const accounts = yield* AccountStore
        assert.strictEqual((yield* accounts.listByUserId(registered.user.id)).length, 1)

        // The address's real owner signs in with a link.
        const token = yield* linkFor({ email })
        const { events, result } = yield* AuthTest.recordingEvents(
          Effect.flatMap(MagicLink, (magic) => magic.verify({ token }))
        )

        assert.strictEqual(result.user.id, registered.user.id)
        assert.isTrue(result.user.emailVerified)
        // The password they set is gone, and so is any session it opened.
        assert.deepStrictEqual(yield* accounts.listByUserId(registered.user.id), [])
        const sessions = yield* Sessions
        const live = yield* sessions.list(registered.user.id)
        assert.deepStrictEqual(live.map((session) => session.id), [result.session.id])

        assert.deepStrictEqual(tagsOf(forUser(events, result.user.id)), [
          "AccountUnlinked",
          "SessionRevoked",
          "PluginEvent",
          "EmailVerified",
          "SignedIn"
        ])
      }))

    it.effect("retires the links the unproven account was the subject of", () =>
      Effect.gen(function*() {
        // The same squatter, one step further on: signed in on the account they
        // registered, they asked to move it to an address of their own. The
        // current address is unverified, so that flow skips its first hop and
        // the second-hop token is already in *their* mailbox.
        const email = uniqueEmail("squatted-tokens")
        const passwords = yield* Passwords
        const registered = yield* passwords.signUp({ name: testName, email, password: testPassword })
        const verifications = yield* Verifications

        const move = yield* verifications.issue({
          purpose: changeEmailVerifyPurpose,
          subject: registered.user.id,
          ttl: Duration.hours(1),
          payload: { newEmail: uniqueEmail("squatter-own") }
        })
        const reset = yield* verifications.issue({
          purpose: passwordResetPurpose,
          subject: registered.user.id,
          ttl: Duration.hours(1),
          payload: null
        })

        // The real owner signs in with a link.
        const token = yield* linkFor({ email })
        const magic = yield* MagicLink
        yield* magic.verify({ token })

        // Destroying the password and the sessions is not enough: following
        // that second hop would move the reclaimed account to the squatter's
        // address, which is the takeover the defence exists to stop.
        const moved = yield* Effect.flip(verifications.claim(changeEmailVerifyPurpose, move.token))
        assert.strictEqual(moved._tag, "InvalidToken")
        const reused = yield* Effect.flip(verifications.claim(passwordResetPurpose, reset.token))
        assert.strictEqual(reused._tag, "InvalidToken")
      }))

    it.effect("refuses a replayed link", () =>
      Effect.gen(function*() {
        const email = uniqueEmail("replay")
        const token = yield* linkFor({ email })
        const magic = yield* MagicLink

        yield* magic.verify({ token })
        const error = yield* Effect.flip(magic.verify({ token }))
        assert.strictEqual(error._tag, "InvalidToken")
      }))

    it.effect("retires the links a spent one left behind", () =>
      Effect.gen(function*() {
        const email = uniqueEmail("two-links")
        const first = yield* linkFor({ email })
        const second = yield* linkFor({ email })
        const magic = yield* MagicLink

        // Asking twice mints two independent tokens; spending either must kill
        // the other, or a few minutes of mailbox access is a lasting key.
        yield* magic.verify({ token: second })
        const error = yield* Effect.flip(magic.verify({ token: first }))
        assert.strictEqual(error._tag, "InvalidToken")
      }))

    it.effect("refuses a link once its five minutes are up", () =>
      AuthTest.freshClock(Effect.gen(function*() {
        const email = uniqueEmail("expired")
        const token = yield* linkFor({ email })
        const magic = yield* MagicLink

        yield* TestClock.adjust(Duration.minutes(6))

        const error = yield* Effect.flip(magic.verify({ token }))
        assert.strictEqual(error._tag, "InvalidToken")
      })))

    describe("redirect targets", () => {
      it.effect("resolves a path-relative callback against baseUrl", () =>
        Effect.gen(function*() {
          const email = uniqueEmail("relative")
          const token = yield* linkFor({ email, callbackURL: "/welcome" })
          const magic = yield* MagicLink

          const result = yield* magic.verify({ token })
          assert.strictEqual(result.redirectTo, `${AuthTest.testBaseUrl}/welcome`)
        }))

      it.effect("drops a foreign origin, and a protocol-relative one", () =>
        Effect.gen(function*() {
          const magic = yield* MagicLink
          const foreign = yield* linkFor({
            email: uniqueEmail("foreign"),
            callbackURL: "https://evil.test/welcome"
          })
          const protocolRelative = yield* linkFor({
            email: uniqueEmail("protocol-relative"),
            callbackURL: "//evil.test/welcome"
          })

          assert.strictEqual((yield* magic.verify({ token: foreign })).redirectTo, AuthTest.testBaseUrl)
          assert.strictEqual(
            (yield* magic.verify({ token: protocolRelative })).redirectTo,
            AuthTest.testBaseUrl
          )
        }))

      it.effect("prefers newUserCallbackURL when the link created the account", () =>
        Effect.gen(function*() {
          const email = uniqueEmail("first-time")
          const magic = yield* MagicLink

          const created = yield* magic.verify({
            token: yield* linkFor({ email, callbackURL: "/back", newUserCallbackURL: "/onboarding" })
          })
          assert.strictEqual(created.redirectTo, `${AuthTest.testBaseUrl}/onboarding`)

          // And only then: the second link is a plain sign-in.
          const returning = yield* magic.verify({
            token: yield* linkFor({ email, callbackURL: "/back", newUserCallbackURL: "/onboarding" })
          })
          assert.strictEqual(returning.redirectTo, `${AuthTest.testBaseUrl}/back`)
        }))
    })

    describe("complete", () => {
      it.effect("resolves a success into the link's own callback", () =>
        Effect.gen(function*() {
          const email = uniqueEmail("complete-ok")
          const token = yield* linkFor({ email, callbackURL: "/welcome" })
          const magic = yield* MagicLink

          const outcome = yield* magic.complete({ token })
          assert.strictEqual(outcome._tag, "Success")
          assert.strictEqual(outcome.redirectTo, `${AuthTest.testBaseUrl}/welcome`)
        }))

      it.effect("resolves an unknown token into baseUrl with a safe code", () =>
        Effect.gen(function*() {
          const magic = yield* MagicLink
          // Nothing was claimed, so there is no payload and no error URL to
          // honour: the token is not one this deployment minted.
          const outcome = yield* magic.complete({ token: Redacted.make("bm90aGluZw.not-a-token") })

          assert.strictEqual(outcome._tag, "Failure")
          if (outcome._tag === "Failure") {
            assert.strictEqual(outcome.code, "invalid_token")
            assert.strictEqual(outcome.error._tag, "InvalidToken")
          }
          assert.strictEqual(outcome.redirectTo, `${AuthTest.testBaseUrl}/?error=invalid_token`)
        }))

      it.effect("honours the errorCallbackURL the link was minted with", () =>
        Effect.gen(function*() {
          const email = uniqueEmail("complete-error")
          const magic = yield* MagicLink
          const token = yield* linkFor({ email, errorCallbackURL: "/oops" })

          // Spend it once, then replay: the second attempt claims nothing, so it
          // lands on baseUrl rather than on the link's own error page.
          yield* magic.complete({ token })
          const replayed = yield* magic.complete({ token })
          assert.strictEqual(replayed.redirectTo, `${AuthTest.testBaseUrl}/?error=invalid_token`)
        }))
    })
  })

  layer(MagicLinkTest.layer({ magicLink: { revokeUnprovenAccounts: false } }))(
    "with the unproven-account defence switched off",
    (it) => {
      it.effect("marks the address verified but keeps the credential", () =>
        Effect.gen(function*() {
          const email = uniqueEmail("kept")
          const passwords = yield* Passwords
          const registered = yield* passwords.signUp({ name: testName, email, password: testPassword })

          const token = yield* linkFor({ email })
          const magic = yield* MagicLink
          const result = yield* magic.verify({ token })

          assert.strictEqual(result.user.id, registered.user.id)
          // Delivering to the address still proves control of it…
          assert.isTrue(result.user.emailVerified)
          // …but whoever registered it keeps their way in, which is the whole
          // cost of switching this off.
          const accounts = yield* AccountStore
          assert.strictEqual((yield* accounts.listByUserId(registered.user.id)).length, 1)
        }))
    }
  )

  layer(MagicLinkTest.layer({ magicLink: { disableSignUp: true } }))(
    "a deployment that does not create accounts",
    (it) => {
      it.effect("sends nothing to an address it has never seen", () =>
        Effect.gen(function*() {
          const email = uniqueEmail("unknown")
          const magic = yield* MagicLink
          const emails = yield* TestEmails.TestEmails

          yield* magic.request({ email })

          // No row, no message — there is nothing a link to this address could
          // ever do. The endpoint above still answers exactly as it does for an
          // address that has an account.
          assert.deepStrictEqual(yield* emails.to(email), [])
        }))

      it.effect("still mails a link to an address that has an account", () =>
        Effect.gen(function*() {
          const email = uniqueEmail("known")
          const users = yield* UserStore
          const passwords = yield* Passwords
          yield* passwords.signUp({ name: testName, email, password: testPassword })

          const token = yield* linkFor({ email })
          const magic = yield* MagicLink
          const result = yield* magic.verify({ token })

          assert.isFalse(result.userCreated)
          assert.isTrue(Option.isSome(yield* users.findByEmail(email)))
        }))

      it.effect("refuses a link whose address has no account", () =>
        Effect.gen(function*() {
          // Minted straight through `Verifications`, because the request endpoint
          // would not have minted one here — which is the point of that branch.
          const email = uniqueEmail("gone")
          const verifications = yield* Verifications
          const issued = yield* verifications.issue({
            purpose: magicLinkPurpose,
            subject: email,
            ttl: Duration.minutes(5),
            payload: {
              name: null,
              callbackURL: null,
              newUserCallbackURL: null,
              errorCallbackURL: "/oops",
              rememberMe: true
            }
          })

          const magic = yield* MagicLink
          const error = yield* Effect.flip(magic.verify({ token: issued.token }))
          assert.strictEqual(error._tag, "SignUpDisabled")
        }))

      it.effect("redirects a refused link to its own error page", () =>
        Effect.gen(function*() {
          const email = uniqueEmail("gone-redirect")
          const verifications = yield* Verifications
          const issued = yield* verifications.issue({
            purpose: magicLinkPurpose,
            subject: email,
            ttl: Duration.minutes(5),
            payload: {
              name: null,
              callbackURL: null,
              newUserCallbackURL: null,
              errorCallbackURL: "/oops",
              rememberMe: true
            }
          })

          const magic = yield* MagicLink
          const outcome = yield* magic.complete({ token: issued.token })

          assert.strictEqual(outcome._tag, "Failure")
          // The claim succeeded, so the payload's error URL is available — unlike
          // the unknown-token case, which has none.
          assert.strictEqual(outcome.redirectTo, `${AuthTest.testBaseUrl}/oops?error=sign_up_disabled`)
        }))
    }
  )
})
