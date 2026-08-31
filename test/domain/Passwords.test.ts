import { assert, describe, it, layer } from "@effect/vitest"
import { Duration, Effect, Option, Redacted } from "effect"
import { TestClock } from "effect/testing"
import { SqlClient } from "effect/unstable/sql"
import { AuthConfig } from "../../src/config/AuthConfig.js"
import type { AuthEvent } from "../../src/domain/Events.js"
import { Passwords } from "../../src/domain/Passwords.js"
import type { AccountId, UserId } from "../../src/domain/Schema.js"
import { CredentialIssuer } from "../../src/domain/Schema.js"
import { Sessions } from "../../src/domain/Sessions.js"
import { AccountStore, UserStore } from "../../src/domain/Stores.js"
import { decodeSubjectToken } from "../../src/domain/Verifications.js"
import { AuthTest, TestEmails } from "../../src/testing/index.js"
import { expectSome, newPassword, tagsOf, testName, testPassword, uniqueEmail } from "../fixtures.js"

/**
 * Registers a user.
 *
 * **Gotchas**
 *
 * Every test in the block writes to one database, so `email` must be a
 * {@link uniqueEmail}: two tests registering `ada@example.com` would collide on
 * the unique index rather than testing anything.
 */
const register = Effect.fnUntraced(function*(email: string) {
  const passwords = yield* Passwords
  return yield* passwords.signUp({ name: testName, email, password: testPassword })
})

/**
 * The events one user's flows published.
 *
 * The event hub belongs to the deployment, and the deployment is shared by
 * every test in the block, so an assertion on the whole recording would also be
 * an assertion about whatever the siblings happened to be doing.
 */
const forUser = (events: ReadonlyArray<AuthEvent>, userId: string): ReadonlyArray<AuthEvent> =>
  events.filter((event) => event.userId === userId)

/**
 * Removes a user's password credential, leaving them as an OAuth-only user
 * would be: a row in `users`, and no `local:credential` account.
 */
const dropCredential = Effect.fnUntraced(function*(userId: UserId) {
  const accounts = yield* AccountStore
  const credential = yield* expectSome(
    yield* accounts.findByIssuerAccountId(CredentialIssuer, userId),
    "expected a credential account"
  )
  assert.isTrue(yield* accounts.deleteById(credential.id, userId))
})

/**
 * Empties a credential row's hash column.
 *
 * **Gotchas**
 *
 * Raw SQL because nothing in this library can produce this state: a credential
 * row it wrote always carries a hash. A store migrated from another system may
 * not, which is the case `setPassword` has to fill in rather than duplicate.
 */
const clearPasswordHash = Effect.fnUntraced(function*(accountId: AccountId) {
  const sql = yield* SqlClient.SqlClient
  yield* Effect.orDie(sql`UPDATE accounts SET password_hash = NULL WHERE id = ${accountId}`)
})

/** The most recent e-mail of a kind sent to one address. */
const mailTo = Effect.fnUntraced(function*(kind: "verification" | "reset", address: string) {
  const emails = yield* TestEmails.TestEmails
  return yield* expectSome(yield* emails.last(kind, address), `expected a ${kind} e-mail for ${address}`)
})

layer(AuthTest.layer())("domain/Passwords", (it) => {
  // ---------------------------------------------------------------------------
  // Sign-up
  // ---------------------------------------------------------------------------

  describe("signUp", () => {
    it.effect("creates a user, a credential account and a session, and emits both events", () =>
      Effect.gen(function*() {
        const accounts = yield* AccountStore
        const sessions = yield* Sessions
        const email = uniqueEmail("signup")

        const { events, result } = yield* AuthTest.recordingEvents(register(email))
        assert.deepStrictEqual(tagsOf(forUser(events, result.user.id)), ["UserCreated", "SignedIn"])

        assert.strictEqual(result.user.email, email)
        assert.strictEqual(result.user.emailVerified, false)

        // The password lives on a `local:credential` account keyed by the user
        // id, not on the user row.
        const credential = yield* expectSome(
          yield* accounts.findByIssuerAccountId(CredentialIssuer, result.user.id),
          "expected a credential account"
        )
        assert.strictEqual(credential.userId, result.user.id)
        assert.strictEqual(credential.providerId, "credential")
        assert.notStrictEqual(credential.passwordHash, null)
        assert.notStrictEqual(credential.passwordHash, Redacted.value(testPassword))

        const established = yield* expectSome(result.session, "expected a session")
        const verified = yield* sessions.verify(established.token)
        assert.strictEqual(verified.user.id, result.user.id)
      }))

    it.effect("normalizes the e-mail address on the way in", () =>
      Effect.gen(function*() {
        const passwords = yield* Passwords
        const users = yield* UserStore
        const email = uniqueEmail("normalize")

        const { user } = yield* passwords.signUp({
          name: testName,
          email: `  ${email.toUpperCase()} `,
          password: testPassword
        })
        assert.strictEqual(user.email, email)
        assert.strictEqual(Option.isSome(yield* users.findByEmail(email)), true)

        // ... and the lookup on sign-in normalizes too.
        const signedIn = yield* passwords.signIn({ email: email.toUpperCase(), password: testPassword })
        assert.strictEqual(signedIn.user.id, user.id)
      }))

    it.effect("refuses a duplicate address with UserAlreadyExists", () =>
      Effect.gen(function*() {
        const email = uniqueEmail("duplicate")
        yield* register(email)
        const failure = yield* Effect.flip(register(email))
        assert.strictEqual(failure._tag, "UserAlreadyExists")
      }))

    it.effect("enforces the password policy at both ends", () =>
      Effect.gen(function*() {
        const passwords = yield* Passwords
        const config = yield* AuthConfig
        const shortEmail = uniqueEmail("short")
        const longEmail = uniqueEmail("long")

        const short = yield* Effect.flip(
          passwords.signUp({ name: testName, email: shortEmail, password: Redacted.make("tiny") })
        )
        if (short._tag !== "PasswordPolicyViolation") return assert.fail(`unexpected ${short._tag}`)
        assert.strictEqual(short.reason, "TooShort")
        assert.strictEqual(short.minLength, config.emailPassword.minPasswordLength)

        const long = yield* Effect.flip(
          passwords.signUp({
            name: testName,
            email: longEmail,
            password: Redacted.make("x".repeat(config.emailPassword.maxPasswordLength + 1))
          })
        )
        if (long._tag !== "PasswordPolicyViolation") return assert.fail(`unexpected ${long._tag}`)
        assert.strictEqual(long.reason, "TooLong")

        // Nothing was written for either attempt.
        const users = yield* UserStore
        assert.strictEqual(Option.isNone(yield* users.findByEmail(shortEmail)), true)
        assert.strictEqual(Option.isNone(yield* users.findByEmail(longEmail)), true)
      }))

    it.layer(AuthTest.layer({ emailPassword: { autoSignIn: false } }))("with autoSignIn off", (it) => {
      it.effect("withholds the session", () =>
        Effect.gen(function*() {
          const { session } = yield* register(uniqueEmail("no-auto-sign-in"))
          assert.strictEqual(Option.isNone(session), true)
        }))
    })
  })

  // ---------------------------------------------------------------------------
  // Sign-in
  // ---------------------------------------------------------------------------

  describe("signIn", () => {
    it.effect("accepts the right password and rejects the wrong one identically to an unknown user", () =>
      Effect.gen(function*() {
        const passwords = yield* Passwords
        const email = uniqueEmail("signin")
        const { user } = yield* register(email)

        const { events, result } = yield* AuthTest.recordingEvents(
          passwords.signIn({ email, password: testPassword })
        )
        assert.strictEqual(result.user.id, user.id)
        assert.deepStrictEqual(tagsOf(forUser(events, user.id)), ["SignedIn"])

        const wrong = yield* Effect.flip(
          passwords.signIn({ email, password: Redacted.make("wrong-password") })
        )
        const unknown = yield* Effect.flip(
          passwords.signIn({ email: uniqueEmail("nobody"), password: testPassword })
        )
        assert.strictEqual(wrong._tag, "InvalidCredentials")
        assert.strictEqual(unknown._tag, "InvalidCredentials")
      }))
  })

  // ---------------------------------------------------------------------------
  // E-mail verification
  // ---------------------------------------------------------------------------

  describe("verifyEmail", () => {
    it.effect("sendVerificationEmail is silent for an unknown or already-verified address", () =>
      Effect.gen(function*() {
        const passwords = yield* Passwords
        const emails = yield* TestEmails.TestEmails
        const users = yield* UserStore
        const email = uniqueEmail("resend")
        const stranger = uniqueEmail("stranger")
        const { user } = yield* register(email)

        yield* passwords.sendVerificationEmail({ email: stranger })
        assert.strictEqual((yield* emails.to(stranger)).length, 0)

        yield* passwords.sendVerificationEmail({ email })
        assert.strictEqual((yield* emails.to(email)).length, 1)

        yield* users.update(user.id, { emailVerified: true })
        yield* passwords.sendVerificationEmail({ email })
        assert.strictEqual((yield* emails.to(email)).length, 1)
      }))
  })

  // ---------------------------------------------------------------------------
  // Verification required — a configuration variant over the same database
  // ---------------------------------------------------------------------------

  it.layer(AuthTest.layer({ emailPassword: { requireEmailVerification: true } }))(
    "with verification required",
    (it) => {
      it.effect("withholds the session and sends a verification mail on sign-up", () =>
        Effect.gen(function*() {
          const config = yield* AuthConfig
          const email = uniqueEmail("must-verify")

          const { session, user } = yield* register(email)
          assert.strictEqual(Option.isNone(session), true)

          const mail = yield* mailTo("verification", email)
          assert.strictEqual(mail.user?.id, user.id)
          // The link is built from baseUrl and the configured path, and carries
          // the token in its query string.
          const url = new URL(Redacted.value(mail.url))
          assert.strictEqual(url.origin, new URL(config.baseUrl).origin)
          assert.strictEqual(url.pathname, config.emailPaths.verifyEmail)
          assert.strictEqual(url.searchParams.get("token"), Redacted.value(mail.token))
        }))

      it.effect("refuses an unverified address, and opens the door once it is verified", () =>
        Effect.gen(function*() {
          const passwords = yield* Passwords
          const email = uniqueEmail("unverified")
          yield* register(email)

          const failure = yield* Effect.flip(passwords.signIn({ email, password: testPassword }))
          assert.strictEqual(failure._tag, "EmailNotVerified")

          const mail = yield* mailTo("verification", email)
          const verified = yield* passwords.verifyEmail(mail.token)
          assert.strictEqual(verified.emailVerified, true)

          const signedIn = yield* passwords.signIn({ email, password: testPassword })
          assert.strictEqual(signedIn.user.emailVerified, true)
        }))

      it.effect("consumes the token exactly once and emits EmailVerified", () =>
        Effect.gen(function*() {
          const passwords = yield* Passwords
          const email = uniqueEmail("single-use")
          const { user } = yield* register(email)
          const mail = yield* mailTo("verification", email)

          const { events } = yield* AuthTest.recordingEvents(passwords.verifyEmail(mail.token))
          assert.deepStrictEqual(tagsOf(forUser(events, user.id)), ["EmailVerified"])

          // Replaying the link is refused: the row was deleted by the claim.
          const replay = yield* Effect.flip(passwords.verifyEmail(mail.token))
          assert.strictEqual(replay._tag, "InvalidToken")
        }))

      it.effect("refuses a malformed token, a forged subject and an expired one", () =>
        AuthTest.freshClock(Effect.gen(function*() {
          const passwords = yield* Passwords
          const config = yield* AuthConfig
          const email = uniqueEmail("bad-token")
          yield* register(email)
          const mail = yield* mailTo("verification", email)

          assert.strictEqual(
            (yield* Effect.flip(passwords.verifyEmail(Redacted.make("nonsense"))))._tag,
            "InvalidToken"
          )

          // The secret half is genuine but the subject names another address, so
          // the identifier does not match and the claim finds nothing.
          const parts = yield* expectSome(decodeSubjectToken(mail.token), "expected a subject token")
          const forged = Redacted.make(
            `${
              btoa(uniqueEmail("mallory")).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "")
            }.${Redacted.value(parts.secret)}`
          )
          assert.strictEqual((yield* Effect.flip(passwords.verifyEmail(forged)))._tag, "InvalidToken")

          yield* TestClock.adjust(Duration.sum(config.tokens.emailVerificationTtl, Duration.millis(1)))
          assert.strictEqual((yield* Effect.flip(passwords.verifyEmail(mail.token)))._tag, "InvalidToken")
        })))
    }
  )

  // ---------------------------------------------------------------------------
  // Reset
  // ---------------------------------------------------------------------------

  describe("reset", () => {
    it.effect("requestReset says nothing about an unknown address", () =>
      Effect.gen(function*() {
        const passwords = yield* Passwords
        const emails = yield* TestEmails.TestEmails
        const email = uniqueEmail("reset-known")
        const stranger = uniqueEmail("reset-unknown")
        const { user } = yield* register(email)

        const unknown = yield* AuthTest.recordingEvents(passwords.requestReset({ email: stranger }))
        assert.deepStrictEqual(tagsOf(forUser(unknown.events, user.id)), [])
        assert.strictEqual((yield* emails.to(stranger)).length, 0)

        const known = yield* AuthTest.recordingEvents(passwords.requestReset({ email }))
        assert.deepStrictEqual(tagsOf(forUser(known.events, user.id)), ["PasswordResetRequested"])
        assert.strictEqual((yield* emails.to(email)).length, 1)
      }))

    it.effect("keeps an untrusted landing page out of the e-mailed link", () =>
      Effect.gen(function*() {
        const passwords = yield* Passwords
        const config = yield* AuthConfig
        const email = uniqueEmail("redirect")
        yield* register(email)

        // A link in somebody's mailbox that bounces off this deployment onto an
        // attacker's page is a phishing page wearing our name, so the target is
        // validated here as well as at the HTTP edge.
        yield* passwords.requestReset({ email, redirectTo: "https://evil.test/phish" })
        const hostile = new URL(Redacted.value((yield* mailTo("reset", email)).url))
        assert.isNull(hostile.searchParams.get("callbackURL"))

        yield* passwords.requestReset({ email, redirectTo: "/\\evil.test" })
        const backslash = new URL(Redacted.value((yield* mailTo("reset", email)).url))
        assert.isNull(backslash.searchParams.get("callbackURL"))

        yield* passwords.requestReset({ email, redirectTo: "/welcome" })
        const allowed = new URL(Redacted.value((yield* mailTo("reset", email)).url))
        assert.strictEqual(allowed.searchParams.get("callbackURL"), `${new URL(config.baseUrl).origin}/welcome`)
      }))

    it.effect("resetPassword replaces the hash, revokes every session, and burns the token", () =>
      Effect.gen(function*() {
        const passwords = yield* Passwords
        const sessions = yield* Sessions
        const email = uniqueEmail("reset-full")
        const { session, user } = yield* register(email)
        const established = yield* expectSome(session, "expected a session")
        yield* sessions.create({ userId: user.id })

        assert.strictEqual((yield* sessions.list(user.id)).length, 2)

        yield* passwords.requestReset({ email })
        const mail = yield* mailTo("reset", email)

        const { events } = yield* AuthTest.recordingEvents(
          passwords.resetPassword({ token: mail.token, newPassword })
        )
        assert.deepStrictEqual(tagsOf(forUser(events, user.id)), ["SessionRevoked", "PasswordChanged"])

        // Every device is signed out.
        assert.strictEqual((yield* sessions.list(user.id)).length, 0)
        assert.strictEqual((yield* Effect.flip(sessions.verify(established.token)))._tag, "Unauthorized")

        // The old password is gone and the new one works.
        assert.strictEqual(
          (yield* Effect.flip(passwords.signIn({ email, password: testPassword })))._tag,
          "InvalidCredentials"
        )
        const signedIn = yield* passwords.signIn({ email, password: newPassword })
        assert.strictEqual(signedIn.user.id, user.id)

        // The link is single use.
        const replay = yield* Effect.flip(
          passwords.resetPassword({ token: mail.token, newPassword: Redacted.make("third-password-x") })
        )
        assert.strictEqual(replay._tag, "InvalidToken")
      }))

    it.effect("a completed reset retires every other outstanding reset link", () =>
      Effect.gen(function*() {
        const passwords = yield* Passwords
        const email = uniqueEmail("reset-retire")
        yield* register(email)

        // Two "forgot password" clicks mint two independent tokens. Somebody
        // with a few minutes of mailbox access holds the first; the owner uses
        // the second and believes the account re-secured.
        yield* passwords.requestReset({ email })
        const stolen = yield* mailTo("reset", email)
        yield* passwords.requestReset({ email })
        const used = yield* mailTo("reset", email)
        assert.notStrictEqual(Redacted.value(stolen.token), Redacted.value(used.token))

        yield* passwords.resetPassword({ token: used.token, newPassword })

        // The other link died with it.
        const replay = yield* Effect.flip(
          passwords.resetPassword({ token: stolen.token, newPassword: Redacted.make("attacker-password") })
        )
        assert.strictEqual(replay._tag, "InvalidToken")
        yield* passwords.signIn({ email, password: newPassword })
      }))

    it.effect("changing a password from inside a session retires pending reset links too", () =>
      Effect.gen(function*() {
        const passwords = yield* Passwords
        const email = uniqueEmail("reset-superseded")
        const { user } = yield* register(email)

        yield* passwords.requestReset({ email })
        const pending = yield* mailTo("reset", email)

        yield* passwords.changePassword({
          userId: user.id,
          currentPassword: testPassword,
          newPassword
        })

        const refused = yield* Effect.flip(
          passwords.resetPassword({ token: pending.token, newPassword: Redacted.make("attacker-password") })
        )
        assert.strictEqual(refused._tag, "InvalidToken")
      }))

    it.effect("resetPassword refuses an expired token and a policy violation", () =>
      AuthTest.freshClock(Effect.gen(function*() {
        const passwords = yield* Passwords
        const config = yield* AuthConfig
        const email = uniqueEmail("reset-expiry")
        yield* register(email)
        yield* passwords.requestReset({ email })
        const mail = yield* mailTo("reset", email)

        // The policy is checked before the token is claimed, so a rejected
        // password does not burn the link.
        const violation = yield* Effect.flip(
          passwords.resetPassword({ token: mail.token, newPassword: Redacted.make("tiny") })
        )
        assert.strictEqual(violation._tag, "PasswordPolicyViolation")

        yield* TestClock.adjust(Duration.sum(config.tokens.passwordResetTtl, Duration.millis(1)))
        const expired = yield* Effect.flip(passwords.resetPassword({ token: mail.token, newPassword }))
        assert.strictEqual(expired._tag, "InvalidToken")
      })))

    it.effect("resetPassword gives an OAuth-only user a password credential", () =>
      Effect.gen(function*() {
        const passwords = yield* Passwords
        const accounts = yield* AccountStore
        const email = uniqueEmail("reset-oauth-only")
        const { user } = yield* register(email)

        const credential = yield* expectSome(
          yield* accounts.findByIssuerAccountId(CredentialIssuer, user.id),
          "expected a credential account"
        )
        assert.strictEqual(yield* accounts.deleteById(credential.id, user.id), true)

        yield* passwords.requestReset({ email })
        const mail = yield* mailTo("reset", email)
        yield* passwords.resetPassword({ token: mail.token, newPassword })

        const created = yield* expectSome(
          yield* accounts.findByIssuerAccountId(CredentialIssuer, user.id),
          "reset should create the missing credential account"
        )
        assert.notStrictEqual(created.passwordHash, null)
        assert.strictEqual(
          (yield* passwords.signIn({ email, password: newPassword })).user.id,
          user.id
        )
      }))

    it.layer(AuthTest.layer({ emailDelivery: "failing" }))("with a mailer that refuses delivery", (it) => {
      it.effect("does not change what the caller sees", () =>
        Effect.gen(function*() {
          // The endpoint answers 200 either way, so a bounced message must not
          // turn into an error that distinguishes a known address from an
          // unknown one.
          const passwords = yield* Passwords
          const emails = yield* TestEmails.TestEmails
          const email = uniqueEmail("bounced")
          yield* register(email)

          yield* passwords.requestReset({ email })
          yield* passwords.sendVerificationEmail({ email })

          // The tokens were still minted and the messages still composed.
          assert.strictEqual((yield* emails.to(email)).length, 2)

          // ... and the reset link the mailer failed to deliver still works.
          const mail = yield* mailTo("reset", email)
          yield* passwords.resetPassword({ token: mail.token, newPassword })
          yield* passwords.signIn({ email, password: newPassword })
        }))
    })
  })

  // ---------------------------------------------------------------------------
  // Change password
  // ---------------------------------------------------------------------------

  describe("changePassword", () => {
    it.effect("replaces the hash and signs the other devices out", () =>
      Effect.gen(function*() {
        const passwords = yield* Passwords
        const sessions = yield* Sessions
        const email = uniqueEmail("change")
        const { session, user } = yield* register(email)
        const current = yield* expectSome(session, "expected a session")
        const other = yield* sessions.create({ userId: user.id })

        const { events } = yield* AuthTest.recordingEvents(passwords.changePassword({
          userId: user.id,
          currentPassword: testPassword,
          newPassword,
          currentSessionId: current.session.id
        }))
        assert.deepStrictEqual(tagsOf(forUser(events, user.id)), ["SessionRevoked", "PasswordChanged"])

        // The caller keeps their session; the other device does not.
        assert.strictEqual((yield* sessions.verify(current.token)).session.id, current.session.id)
        assert.strictEqual((yield* Effect.flip(sessions.verify(other.token)))._tag, "Unauthorized")

        assert.strictEqual(
          (yield* Effect.flip(passwords.signIn({ email, password: testPassword })))._tag,
          "InvalidCredentials"
        )
        yield* passwords.signIn({ email, password: newPassword })
      }))

    it.effect("keeps every session when revokeOtherSessions is false", () =>
      Effect.gen(function*() {
        const passwords = yield* Passwords
        const sessions = yield* Sessions
        const { user } = yield* register(uniqueEmail("change-keep"))
        const other = yield* sessions.create({ userId: user.id })

        yield* passwords.changePassword({
          userId: user.id,
          currentPassword: testPassword,
          newPassword,
          revokeOtherSessions: false
        })
        assert.strictEqual((yield* sessions.verify(other.token)).session.id, other.session.id)
      }))

    it.effect("refuses a wrong current password and a policy violation", () =>
      Effect.gen(function*() {
        const passwords = yield* Passwords
        const email = uniqueEmail("change-refused")
        const { user } = yield* register(email)

        const wrong = yield* Effect.flip(passwords.changePassword({
          userId: user.id,
          currentPassword: Redacted.make("not-the-password"),
          newPassword
        }))
        assert.strictEqual(wrong._tag, "InvalidCredentials")

        const violation = yield* Effect.flip(passwords.changePassword({
          userId: user.id,
          currentPassword: testPassword,
          newPassword: Redacted.make("tiny")
        }))
        assert.strictEqual(violation._tag, "PasswordPolicyViolation")

        // Neither attempt changed anything.
        yield* passwords.signIn({ email, password: testPassword })
      }))
  })

  // ---------------------------------------------------------------------------
  // Verify and set
  // ---------------------------------------------------------------------------

  describe("verifyPassword", () => {
    it.effect("answers true for the stored password and false for anything else", () =>
      Effect.gen(function*() {
        const passwords = yield* Passwords
        const { user } = yield* register(uniqueEmail("verify-password"))

        assert.isTrue(yield* passwords.verifyPassword(user.id, testPassword))
        assert.isFalse(yield* passwords.verifyPassword(user.id, Redacted.make("not-the-password")))
      }))

    it.effect("answers false, rather than failing, for a user who has no password at all", () =>
      Effect.gen(function*() {
        const passwords = yield* Passwords
        const { user } = yield* register(uniqueEmail("verify-no-credential"))
        yield* dropCredential(user.id)

        assert.isFalse(yield* passwords.verifyPassword(user.id, testPassword))
      }))
  })

  describe("setPassword", () => {
    it.effect("gives a user with no credential their first password, and links it", () =>
      Effect.gen(function*() {
        const passwords = yield* Passwords
        const accounts = yield* AccountStore
        const sessions = yield* Sessions
        const email = uniqueEmail("set-password")
        const { session, user } = yield* register(email)
        const current = yield* expectSome(session, "expected a session")
        yield* dropCredential(user.id)

        const { events } = yield* AuthTest.recordingEvents(
          passwords.setPassword({ userId: user.id, newPassword })
        )
        assert.deepStrictEqual(tagsOf(forUser(events, user.id)), ["AccountLinked"])
        const linked = events.find((event) => event._tag === "AccountLinked")
        assert.strictEqual(linked?._tag === "AccountLinked" ? linked.providerId : null, "credential")

        const credential = yield* expectSome(
          yield* accounts.findByIssuerAccountId(CredentialIssuer, user.id),
          "expected a credential account"
        )
        assert.notStrictEqual(credential.passwordHash, null)
        assert.notStrictEqual(credential.passwordHash, Redacted.value(newPassword))

        // The new credential works, and nothing that already existed was
        // invalidated: no password was replaced, so no session was revoked.
        yield* passwords.signIn({ email, password: newPassword })
        assert.strictEqual((yield* sessions.verify(current.token)).session.id, current.session.id)
      }))

    it.effect("can never replace a password: a user who has one is told so", () =>
      Effect.gen(function*() {
        const passwords = yield* Passwords
        const email = uniqueEmail("set-password-twice")
        const { user } = yield* register(email)

        const failure = yield* Effect.flip(passwords.setPassword({ userId: user.id, newPassword }))
        assert.strictEqual(failure._tag, "PasswordAlreadySet")

        // The original is untouched, and the refused one was never usable.
        yield* passwords.signIn({ email, password: testPassword })
        assert.strictEqual(
          (yield* Effect.flip(passwords.signIn({ email, password: newPassword })))._tag,
          "InvalidCredentials"
        )
      }))

    it.effect("enforces the password policy before writing anything", () =>
      Effect.gen(function*() {
        const passwords = yield* Passwords
        const accounts = yield* AccountStore
        const { user } = yield* register(uniqueEmail("set-password-policy"))
        yield* dropCredential(user.id)

        const failure = yield* Effect.flip(
          passwords.setPassword({ userId: user.id, newPassword: Redacted.make("tiny") })
        )
        assert.strictEqual(failure._tag, "PasswordPolicyViolation")
        assert.isTrue(Option.isNone(yield* accounts.findByIssuerAccountId(CredentialIssuer, user.id)))
      }))

    it.effect("fills in a credential row that carries no hash", () =>
      Effect.gen(function*() {
        const passwords = yield* Passwords
        const accounts = yield* AccountStore
        const email = uniqueEmail("set-password-hashless")
        const { user } = yield* register(email)

        // Nothing this library writes, but a migration from another system
        // might: the row exists and the hash column is empty.
        const credential = yield* expectSome(
          yield* accounts.findByIssuerAccountId(CredentialIssuer, user.id),
          "expected a credential account"
        )
        yield* clearPasswordHash(credential.id)
        assert.isNull(
          (yield* expectSome(
            yield* accounts.findByIssuerAccountId(CredentialIssuer, user.id),
            "expected a credential account"
          )).passwordHash
        )

        yield* passwords.setPassword({ userId: user.id, newPassword })
        yield* passwords.signIn({ email, password: newPassword })
      }))
  })

  // ---------------------------------------------------------------------------
  // The timing defence
  // ---------------------------------------------------------------------------

  // One verification per call, whoever the user is and whatever they have — the
  // same defence `signIn` needs, for the same reason: `verifyPassword` is what
  // re-authenticates somebody before their account is deleted.
  describe.sequential("verifyPassword (timing defence)", () => {
    const hasher = AuthTest.countingHasher()

    it.layer(AuthTest.layer({ hasher: hasher.layer }))((it) => {
      it.effect("verifies exactly one hash, with or without a credential to check", () =>
        Effect.gen(function*() {
          const passwords = yield* Passwords
          const { user } = yield* register(uniqueEmail("verify-timing"))

          const right = hasher.state.verifies
          assert.isTrue(yield* passwords.verifyPassword(user.id, testPassword))
          assert.strictEqual(hasher.state.verifies - right, 1)

          const wrong = hasher.state.verifies
          assert.isFalse(yield* passwords.verifyPassword(user.id, Redacted.make("nope")))
          assert.strictEqual(hasher.state.verifies - wrong, 1)

          yield* dropCredential(user.id)
          const none = hasher.state.verifies
          assert.isFalse(yield* passwords.verifyPassword(user.id, testPassword))
          assert.strictEqual(hasher.state.verifies - none, 1)
        }))
    })
  })

  // The counter belongs to the hashing layer, and the layer is built once for
  // the sub-block, so these two must not run beside each other. The database
  // above is still shared: only the hasher is swapped.
  describe.sequential("signIn (timing defence)", () => {
    const hasher = AuthTest.countingHasher()

    it.layer(AuthTest.layer({ hasher: hasher.layer }))((it) => {
      it.effect("verifies a hash even when the address is unknown", () =>
        Effect.gen(function*() {
          // This is the anti-enumeration defence: if the missing-user path
          // returned early, sign-in latency would answer "does this address have
          // an account?" for anyone who cared to measure it.
          const passwords = yield* Passwords
          const email = uniqueEmail("timing-known")
          yield* register(email)

          const before = hasher.state.verifies
          const failure = yield* Effect.flip(
            passwords.signIn({ email: uniqueEmail("timing-nobody"), password: testPassword })
          )
          assert.strictEqual(failure._tag, "InvalidCredentials")
          assert.strictEqual(hasher.state.verifies - before, 1)

          // The known-user path costs exactly the same one verification.
          const known = hasher.state.verifies
          yield* passwords.signIn({ email, password: testPassword })
          assert.strictEqual(hasher.state.verifies - known, 1)
        }))

      it.effect("verifies a hash even when the user has no password credential", () =>
        Effect.gen(function*() {
          const passwords = yield* Passwords
          const accounts = yield* AccountStore
          const email = uniqueEmail("timing-oauth-only")
          const { user } = yield* register(email)

          // Simulate an OAuth-only user: drop the credential account.
          const credential = yield* expectSome(
            yield* accounts.findByIssuerAccountId(CredentialIssuer, user.id),
            "expected a credential account"
          )
          assert.strictEqual(yield* accounts.deleteById(credential.id, user.id), true)

          const before = hasher.state.verifies
          const failure = yield* Effect.flip(passwords.signIn({ email, password: testPassword }))
          assert.strictEqual(failure._tag, "InvalidCredentials")
          assert.strictEqual(hasher.state.verifies - before, 1)
        }))
    })
  })
})

// -----------------------------------------------------------------------------
// The registration race, on a database of its own
// -----------------------------------------------------------------------------

/**
 * This one keeps its own deployment. The losing fibre's insert is rolled back,
 * and PGlite serves a whole block from a single connection, so a rollback here
 * would take a concurrent sibling's uncommitted writes with it.
 */
describe("domain/Passwords/signUp (registration race)", () => {
  it.effect("answers UserAlreadyExists to the loser of a concurrent registration, not a 500", () =>
    Effect.gen(function*() {
      // Both fibers pass the pre-flight lookup before either insert lands, so
      // this is the path where the unique index — not the lookup — is what
      // refuses the second one.
      const email = uniqueEmail("race")
      const results = yield* Effect.all(
        [Effect.result(register(email)), Effect.result(register(email))],
        { concurrency: 2 }
      )

      const successes = results.filter((result) => result._tag === "Success")
      const failures = results.filter((result) => result._tag === "Failure")
      assert.strictEqual(successes.length, 1)
      assert.strictEqual(failures.length, 1)
      for (const failure of failures) {
        if (failure._tag === "Failure") {
          assert.strictEqual(failure.failure._tag, "UserAlreadyExists")
        }
      }
    }).pipe(Effect.provide(AuthTest.layer())))
})

/**
 * The same reasoning as the registration race, and the same isolation: the
 * losing fibre's insert is rolled back, and a rollback on the shared PGlite
 * connection would take a concurrent sibling's uncommitted writes with it.
 */
describe("domain/Passwords/setPassword (race)", () => {
  it.effect("gives the loser of two concurrent first-passwords PasswordAlreadySet, not a 500", () =>
    Effect.gen(function*() {
      const passwords = yield* Passwords
      const email = uniqueEmail("set-password-race")
      const { user } = yield* register(email)
      yield* dropCredential(user.id)

      // Both fibres read "no credential" before either insert lands, so this is
      // the path where the unique index on `(issuer, account_id)` — not the
      // read — is what refuses the second one.
      const results = yield* Effect.all(
        [
          Effect.result(passwords.setPassword({ userId: user.id, newPassword })),
          Effect.result(passwords.setPassword({ userId: user.id, newPassword: Redacted.make("a-second-password") }))
        ],
        { concurrency: 2 }
      )

      const successes = results.filter((result) => result._tag === "Success")
      const failures = results.filter((result) => result._tag === "Failure")
      assert.strictEqual(successes.length, 1)
      assert.strictEqual(failures.length, 1)
      for (const failure of failures) {
        if (failure._tag === "Failure") {
          assert.strictEqual(failure.failure._tag, "PasswordAlreadySet")
        }
      }

      // Exactly one password was set, and it is one of the two that were asked
      // for — never a mix, and never both.
      const attempts = yield* Effect.all([
        Effect.result(passwords.signIn({ email, password: newPassword })),
        Effect.result(passwords.signIn({ email, password: Redacted.make("a-second-password") }))
      ])
      assert.strictEqual(attempts.filter((attempt) => attempt._tag === "Success").length, 1)
    }).pipe(Effect.provide(AuthTest.layer())))
})
