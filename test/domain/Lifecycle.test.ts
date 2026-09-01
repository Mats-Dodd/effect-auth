import { assert, layer } from "@effect/vitest"
import { DateTime, Duration, Effect, Option } from "effect"
import { TestClock } from "effect/testing"
import { AuthConfig } from "../../src/config/AuthConfig.js"
import { Accounts } from "../../src/domain/Accounts.js"
import { Passwords } from "../../src/domain/Passwords.js"
import { oauthIssuer } from "../../src/domain/Schema.js"
import { requireAssuranceFor, Sessions } from "../../src/domain/Sessions.js"
import { AuthTest } from "../../src/testing/index.js"
import { completed, newPassword, signUpUser, testName, testPassword, uniqueEmail } from "../fixtures.js"

/**
 * These three keep a deployment each.
 *
 * A journey is a statement about one deployment's whole history — every event
 * it published, every session it still holds — so it cannot be read against a
 * database that a sibling is also writing to.
 */
layer(AuthTest.layer({ emailPassword: { requireEmailVerification: true } }))(
  "domain/lifecycle — verified sign-up",
  (it) => {
    it.effect("sign-up, verify, sign-in, browse for a fortnight, change password, sign out", () =>
      Effect.gen(function* () {
        const passwords = yield* Passwords
        const sessions = yield* Sessions
        const emails = yield* AuthTest.TestEmails
        const config = yield* AuthConfig
        const email = uniqueEmail("journey")

        const journey = Effect.gen(function* () {
          // --- register -----------------------------------------------------
          const { session: noSession, user } = yield* passwords.signUp({
            name: testName,
            email: email.toUpperCase(),
            password: testPassword
          })
          assert.strictEqual(user.email, email)
          // Verification is required, so no session yet.
          assert.strictEqual(Option.isNone(noSession), true)

          // --- confirm the address ------------------------------------------
          assert.strictEqual(
            (yield* Effect.flip(passwords.signIn({ email, password: testPassword })))._tag,
            "EmailNotVerified"
          )
          const verified = yield* passwords.verifyEmail(yield* emails.tokenFor("verification", email))
          assert.strictEqual(verified.emailVerified, true)

          // --- sign in -------------------------------------------------------
          const signedIn = completed(
            yield* passwords.signIn({
              email,
              password: testPassword,
              ipAddress: "203.0.113.7",
              userAgent: "vitest"
            })
          )
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
          // Freshness is now one policy among several: `{ maxAge: freshAge }`
          // is exactly what `requireFresh` meant, and the refusal is the 403
          // every assurance-guarded endpoint answers with.
          const stale = yield* Effect.flip(
            requireAssuranceFor(current.session, { maxAge: config.session.freshAge }, [])
          )
          assert.strictEqual(stale._tag, "StepUpRequired")

          // --- change the password on a second device ------------------------
          const phone = yield* sessions.createUnchecked({ userId: user.id })
          yield* passwords.changePassword({
            userId: user.id,
            currentPassword: testPassword,
            newPassword,
            currentSessionId: phone.session.id
          })
          // The laptop was signed out by the change; the phone was not.
          assert.strictEqual((yield* Effect.flip(sessions.verify(signedIn.token)))._tag, "Unauthorized")
          assert.strictEqual((yield* sessions.verify(phone.token)).session.id, phone.session.id)

          // --- sign out ------------------------------------------------------
          yield* sessions.signOut(phone.session)
          assert.strictEqual((yield* Effect.flip(sessions.verify(phone.token)))._tag, "Unauthorized")
          assert.strictEqual((yield* sessions.list(user.id)).length, 0)

          // --- and back in with the new password -----------------------------
          const again = completed(yield* passwords.signIn({ email, password: newPassword }))
          assert.strictEqual(yield* sessions.isFresh(again.session), true)

          const expected = DateTime.addDuration(yield* DateTime.now, config.session.expiresIn)
          assert.strictEqual(DateTime.toEpochMillis(again.session.expiresAt), DateTime.toEpochMillis(expected))
          return user
        })

        const { events } = yield* AuthTest.recordingEvents(journey)
        assert.deepStrictEqual(AuthTest.tagsOf(events), [
          "UserCreated",
          "EmailVerified",
          "SignedIn",
          "SessionRevoked",
          "PasswordChanged",
          "SignedOut",
          "SignedIn"
        ])
      })
    )
  }
)

layer(AuthTest.layer())("domain/lifecycle — OAuth link and unlink", (it) => {
  it.effect("a password user links GitHub, signs in through it, and unlinks again", () =>
    Effect.gen(function* () {
      const passwords = yield* Passwords
      const accounts = yield* Accounts
      const sessions = yield* Sessions
      const emails = yield* AuthTest.TestEmails
      const email = uniqueEmail("linking")

      const { user } = yield* signUpUser(email)

      // The provider's verified claim alone is not enough while the local
      // address is unproven.
      const identity = {
        providerId: "github",
        issuer: oauthIssuer("github"),
        accountId: "gh-1000",
        email,
        emailVerified: true
      }
      assert.strictEqual((yield* Effect.flip(accounts.linkOAuth(identity)))._tag, "AccountAlreadyLinked")

      // Confirm the address, and the same callback now links.
      yield* passwords.sendVerificationEmail({ email })
      yield* passwords.verifyEmail(yield* emails.tokenFor("verification", email))

      const linked = yield* accounts.linkOAuth(identity)
      assert.strictEqual(linked.user.id, user.id)
      assert.strictEqual(linked.accountCreated, true)

      // A second callback is an ordinary sign-in through the same identity.
      const returning = yield* accounts.linkOAuth(identity)
      assert.strictEqual(returning.accountCreated, false)
      const oauthSession = yield* sessions.createUnchecked({ userId: returning.user.id })
      assert.strictEqual((yield* sessions.verify(oauthSession.token)).user.id, user.id)

      // Unlinking leaves the password behind, and then refuses to go further.
      yield* accounts.unlink(linked.account.id, user.id)
      const held = yield* accounts.listForUser(user.id)
      assert.strictEqual(held.length, 1)
      assert.strictEqual((yield* Effect.flip(accounts.unlink(held[0]!.id, user.id)))._tag, "CannotUnlinkLastAccount")

      // The password still works.
      const signedIn = completed(yield* passwords.signIn({ email, password: testPassword }))
      assert.strictEqual(signedIn.user.id, user.id)
    })
  )
})

layer(AuthTest.layer())("domain/lifecycle — password reset", (it) => {
  it.effect("a reset link recovers an account and signs every device out", () =>
    Effect.gen(function* () {
      const passwords = yield* Passwords
      const sessions = yield* Sessions
      const emails = yield* AuthTest.TestEmails
      const config = yield* AuthConfig
      const email = uniqueEmail("recovery")

      const { token: laptopToken, user } = yield* signUpUser(email)
      const phone = yield* sessions.createUnchecked({ userId: user.id })

      // A day passes; the link is requested and used within its hour.
      yield* TestClock.adjust(Duration.days(1))
      yield* passwords.requestReset({ email })
      const token = yield* emails.tokenFor("reset", email)

      yield* TestClock.adjust(Duration.subtract(config.tokens.passwordResetTtl, Duration.minutes(1)))
      yield* passwords.resetPassword({ token, newPassword })

      assert.strictEqual((yield* Effect.flip(sessions.verify(laptopToken)))._tag, "Unauthorized")
      assert.strictEqual((yield* Effect.flip(sessions.verify(phone.token)))._tag, "Unauthorized")

      const recovered = completed(yield* passwords.signIn({ email, password: newPassword }))
      assert.strictEqual(recovered.user.id, user.id)
      assert.strictEqual((yield* sessions.list(user.id)).length, 1)
    })
  )
})
