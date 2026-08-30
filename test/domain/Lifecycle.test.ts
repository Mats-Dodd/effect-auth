import { assert, describe, it } from "@effect/vitest"
import { DateTime, Duration, Effect, Option, Redacted } from "effect"
import { TestClock } from "effect/testing"
import { AuthConfig } from "../../src/config/AuthConfig.js"
import { Accounts } from "../../src/domain/Accounts.js"
import { Passwords } from "../../src/domain/Passwords.js"
import { Sessions } from "../../src/domain/Sessions.js"
import { oauthIssuer } from "../../src/domain/Schema.js"
import { expectSome, recordingEvents, tagsOf, TestEmails, testLayer, testTimeout } from "./harness.js"

const password = Redacted.make("correct-horse-battery")
const newPassword = Redacted.make("an-entirely-different-one")

describe("domain/lifecycle", () => {
  it.effect(
    "sign-up, verify, sign-in, browse for a fortnight, change password, sign out",
    () =>
      Effect.gen(function*() {
        const passwords = yield* Passwords
        const sessions = yield* Sessions
        const emails = yield* TestEmails
        const config = yield* AuthConfig

        const journey = Effect.gen(function*() {
          // --- register -----------------------------------------------------
          const { session: noSession, user } = yield* passwords.signUp({
            name: "Ada Lovelace",
            email: "Ada@Example.com",
            password
          })
          assert.strictEqual(user.email, "ada@example.com")
          // Verification is required, so no session yet.
          assert.strictEqual(Option.isNone(noSession), true)

          // --- confirm the address ------------------------------------------
          assert.strictEqual(
            (yield* Effect.flip(passwords.signIn({ email: "ada@example.com", password })))._tag,
            "EmailNotVerified"
          )
          const verification = yield* emails.last("verification")
          const verified = yield* passwords.verifyEmail(verification.token)
          assert.strictEqual(verified.emailVerified, true)

          // --- sign in -------------------------------------------------------
          const signedIn = yield* passwords.signIn({
            email: "ada@example.com",
            password,
            ipAddress: "203.0.113.7",
            userAgent: "vitest"
          })
          assert.strictEqual(signedIn.user.id, user.id)

          // --- a fortnight of ordinary use -----------------------------------
          // Each day's first request rolls the expiry forward once; the rest of
          // that day's requests do not write at all.
          let refreshes = 0
          for (let day = 0; day < 14; day++) {
            yield* TestClock.adjust(Duration.days(1))
            for (let request = 0; request < 3; request++) {
              const seen = yield* sessions.verify(signedIn.token)
              if (seen.refreshed) refreshes++
            }
          }
          assert.strictEqual(refreshes, 14)

          // The session outlived the seven-day window it started with, because
          // it was kept alive; it is no longer fresh, though.
          const current = yield* sessions.verify(signedIn.token)
          assert.strictEqual(yield* sessions.isFresh(current.session), false)
          assert.strictEqual(
            (yield* Effect.flip(sessions.requireFresh(current.session)))._tag,
            "SessionNotFresh"
          )

          // --- change the password on a second device ------------------------
          const phone = yield* sessions.create({ userId: user.id })
          yield* passwords.changePassword({
            userId: user.id,
            currentPassword: password,
            newPassword,
            currentSessionId: phone.session.id
          })
          // The laptop was signed out by the change; the phone was not.
          assert.strictEqual(
            (yield* Effect.flip(sessions.verify(signedIn.token)))._tag,
            "Unauthorized"
          )
          assert.strictEqual((yield* sessions.verify(phone.token)).session.id, phone.session.id)

          // --- sign out ------------------------------------------------------
          yield* sessions.signOut(phone.session)
          assert.strictEqual((yield* Effect.flip(sessions.verify(phone.token)))._tag, "Unauthorized")
          assert.strictEqual((yield* sessions.list(user.id)).length, 0)

          // --- and back in with the new password -----------------------------
          const again = yield* passwords.signIn({ email: "ada@example.com", password: newPassword })
          assert.strictEqual(yield* sessions.isFresh(again.session), true)

          const expected = DateTime.addDuration(yield* DateTime.now, config.session.expiresIn)
          assert.strictEqual(
            DateTime.toEpochMillis(again.session.expiresAt),
            DateTime.toEpochMillis(expected)
          )
          return user
        })

        const { events } = yield* recordingEvents(journey)
        assert.deepStrictEqual(tagsOf(events), [
          "UserCreated",
          "EmailVerified",
          "SignedIn",
          "SessionRevoked",
          "PasswordChanged",
          "SignedOut",
          "SignedIn"
        ])
      }).pipe(Effect.provide(testLayer({ emailPassword: { requireEmailVerification: true } }))),
    testTimeout
  )

  it.effect(
    "a password user links GitHub, signs in through it, and unlinks again",
    () =>
      Effect.gen(function*() {
        const passwords = yield* Passwords
        const accounts = yield* Accounts
        const sessions = yield* Sessions
        const emails = yield* TestEmails

        const { user } = yield* passwords.signUp({
          name: "Ada Lovelace",
          email: "ada@example.com",
          password
        })

        // The provider's verified claim alone is not enough while the local
        // address is unproven.
        const identity = {
          providerId: "github",
          issuer: oauthIssuer("github"),
          accountId: "gh-1000",
          email: "ada@example.com",
          emailVerified: true
        }
        assert.strictEqual(
          (yield* Effect.flip(accounts.linkOAuth(identity)))._tag,
          "AccountAlreadyLinked"
        )

        // Confirm the address, and the same callback now links.
        yield* passwords.sendVerificationEmail({ email: "ada@example.com" })
        yield* passwords.verifyEmail((yield* emails.last("verification")).token)

        const linked = yield* accounts.linkOAuth(identity)
        assert.strictEqual(linked.user.id, user.id)
        assert.strictEqual(linked.accountCreated, true)

        // A second callback is an ordinary sign-in through the same identity.
        const returning = yield* accounts.linkOAuth(identity)
        assert.strictEqual(returning.accountCreated, false)
        const oauthSession = yield* sessions.create({ userId: returning.user.id })
        assert.strictEqual((yield* sessions.verify(oauthSession.token)).user.id, user.id)

        // Unlinking leaves the password behind, and then refuses to go further.
        yield* accounts.unlink(linked.account.id, user.id)
        const held = yield* accounts.listForUser(user.id)
        assert.strictEqual(held.length, 1)
        assert.strictEqual(
          (yield* Effect.flip(accounts.unlink(held[0]!.id, user.id)))._tag,
          "CannotUnlinkLastAccount"
        )

        // The password still works.
        const signedIn = yield* passwords.signIn({ email: "ada@example.com", password })
        assert.strictEqual(signedIn.user.id, user.id)
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "a reset link recovers an account and signs every device out",
    () =>
      Effect.gen(function*() {
        const passwords = yield* Passwords
        const sessions = yield* Sessions
        const emails = yield* TestEmails
        const config = yield* AuthConfig

        const { session, user } = yield* passwords.signUp({
          name: "Ada Lovelace",
          email: "ada@example.com",
          password
        })
        const laptop = yield* expectSome(session, "expected a session")
        const phone = yield* sessions.create({ userId: user.id })

        // A day passes; the link is requested and used within its hour.
        yield* TestClock.adjust(Duration.days(1))
        yield* passwords.requestReset({ email: "ada@example.com" })
        const mail = yield* emails.last("reset")

        yield* TestClock.adjust(Duration.subtract(config.tokens.passwordResetTtl, Duration.minutes(1)))
        yield* passwords.resetPassword({ token: mail.token, newPassword })

        assert.strictEqual((yield* Effect.flip(sessions.verify(laptop.token)))._tag, "Unauthorized")
        assert.strictEqual((yield* Effect.flip(sessions.verify(phone.token)))._tag, "Unauthorized")

        const recovered = yield* passwords.signIn({ email: "ada@example.com", password: newPassword })
        assert.strictEqual(recovered.user.id, user.id)
        assert.strictEqual((yield* sessions.list(user.id)).length, 1)
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )
})
