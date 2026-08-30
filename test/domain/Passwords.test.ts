import { assert, describe, it } from "@effect/vitest"
import { Duration, Effect, Option, Redacted } from "effect"
import { TestClock } from "effect/testing"
import { AuthConfig } from "../../src/config/AuthConfig.js"
import { decodeSubjectToken, Passwords } from "../../src/domain/Passwords.js"
import { Sessions } from "../../src/domain/Sessions.js"
import { AccountStore, UserStore } from "../../src/domain/Stores.js"
import { CredentialIssuer } from "../../src/domain/Schema.js"
import {
  countingHasher,
  expectSome,
  recordingEvents,
  tagsOf,
  TestEmails,
  testLayer,
  testTimeout
} from "./harness.js"

const password = Redacted.make("correct-horse-battery")
const newPassword = Redacted.make("a-completely-different-one")

const register = Effect.fnUntraced(function*(email = "ada@example.com") {
  const passwords = yield* Passwords
  return yield* passwords.signUp({ name: "Ada Lovelace", email, password })
})

// -----------------------------------------------------------------------------
// Sign-up
// -----------------------------------------------------------------------------

describe("domain/Passwords/signUp", () => {
  it.effect(
    "creates a user, a credential account and a session, and emits both events",
    () =>
      Effect.gen(function*() {
        const accounts = yield* AccountStore
        const sessions = yield* Sessions

        const { events, result } = yield* recordingEvents(register())
        assert.deepStrictEqual(tagsOf(events), ["UserCreated", "SignedIn"])

        assert.strictEqual(result.user.email, "ada@example.com")
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
        assert.notStrictEqual(credential.passwordHash, Redacted.value(password))

        const established = yield* expectSome(result.session, "expected a session")
        const verified = yield* sessions.verify(established.token)
        assert.strictEqual(verified.user.id, result.user.id)
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "normalizes the e-mail address on the way in",
    () =>
      Effect.gen(function*() {
        const passwords = yield* Passwords
        const users = yield* UserStore

        const { user } = yield* passwords.signUp({
          name: "Ada",
          email: "  Ada@Example.COM ",
          password
        })
        assert.strictEqual(user.email, "ada@example.com")
        assert.strictEqual(Option.isSome(yield* users.findByEmail("ada@example.com")), true)

        // ... and the lookup on sign-in normalizes too.
        const signedIn = yield* passwords.signIn({ email: "ADA@example.com", password })
        assert.strictEqual(signedIn.user.id, user.id)
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "refuses a duplicate address with UserAlreadyExists",
    () =>
      Effect.gen(function*() {
        yield* register()
        const failure = yield* Effect.flip(register())
        assert.strictEqual(failure._tag, "UserAlreadyExists")
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "answers UserAlreadyExists to the loser of a concurrent registration, not a 500",
    () =>
      Effect.gen(function*() {
        // Both fibers pass the pre-flight lookup before either insert lands, so
        // this is the path where the unique index — not the lookup — is what
        // refuses the second one.
        const results = yield* Effect.all(
          [Effect.result(register("race@example.com")), Effect.result(register("race@example.com"))],
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
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "enforces the password policy at both ends",
    () =>
      Effect.gen(function*() {
        const passwords = yield* Passwords
        const config = yield* AuthConfig

        const short = yield* Effect.flip(
          passwords.signUp({ name: "Ada", email: "short@example.com", password: Redacted.make("tiny") })
        )
        if (short._tag !== "PasswordPolicyViolation") return assert.fail(`unexpected ${short._tag}`)
        assert.strictEqual(short.reason, "TooShort")
        assert.strictEqual(short.minLength, config.emailPassword.minPasswordLength)

        const long = yield* Effect.flip(
          passwords.signUp({
            name: "Ada",
            email: "long@example.com",
            password: Redacted.make("x".repeat(config.emailPassword.maxPasswordLength + 1))
          })
        )
        if (long._tag !== "PasswordPolicyViolation") return assert.fail(`unexpected ${long._tag}`)
        assert.strictEqual(long.reason, "TooLong")

        // Nothing was written for either attempt.
        const users = yield* UserStore
        assert.strictEqual(Option.isNone(yield* users.findByEmail("short@example.com")), true)
        assert.strictEqual(Option.isNone(yield* users.findByEmail("long@example.com")), true)
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "withholds the session and sends a verification mail when verification is required",
    () =>
      Effect.gen(function*() {
        const emails = yield* TestEmails
        const config = yield* AuthConfig

        const { user, session } = yield* register()
        assert.strictEqual(Option.isNone(session), true)

        const mail = yield* emails.last("verification")
        assert.strictEqual(mail.user.id, user.id)
        // The link is built from baseUrl and the configured path, and carries
        // the token in its query string.
        const url = new URL(Redacted.value(mail.url))
        assert.strictEqual(url.origin, new URL(config.baseUrl).origin)
        assert.strictEqual(url.pathname, config.emailPaths.verifyEmail)
        assert.strictEqual(url.searchParams.get("token"), Redacted.value(mail.token))
      }).pipe(Effect.provide(testLayer({ emailPassword: { requireEmailVerification: true } }))),
    testTimeout
  )

  it.effect(
    "withholds the session when autoSignIn is off",
    () =>
      Effect.gen(function*() {
        const { session } = yield* register()
        assert.strictEqual(Option.isNone(session), true)
      }).pipe(Effect.provide(testLayer({ emailPassword: { autoSignIn: false } }))),
    testTimeout
  )
})

// -----------------------------------------------------------------------------
// Sign-in
// -----------------------------------------------------------------------------

describe("domain/Passwords/signIn", () => {
  it.effect(
    "accepts the right password and rejects the wrong one identically to an unknown user",
    () =>
      Effect.gen(function*() {
        const passwords = yield* Passwords
        const { user } = yield* register()

        const { events, result } = yield* recordingEvents(
          passwords.signIn({ email: "ada@example.com", password })
        )
        assert.strictEqual(result.user.id, user.id)
        assert.deepStrictEqual(tagsOf(events), ["SignedIn"])

        const wrong = yield* Effect.flip(
          passwords.signIn({ email: "ada@example.com", password: Redacted.make("wrong-password") })
        )
        const unknown = yield* Effect.flip(
          passwords.signIn({ email: "nobody@example.com", password })
        )
        assert.strictEqual(wrong._tag, "InvalidCredentials")
        assert.strictEqual(unknown._tag, "InvalidCredentials")
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "verifies a hash even when the address is unknown",
    () =>
      Effect.gen(function*() {
        // This is the anti-enumeration defence: if the missing-user path
        // returned early, sign-in latency would answer "does this address have
        // an account?" for anyone who cared to measure it.
        const hasher = countingHasher()
        return yield* Effect.gen(function*() {
          const passwords = yield* Passwords
          yield* register()

          const before = hasher.state.verifies
          const failure = yield* Effect.flip(
            passwords.signIn({ email: "definitely-nobody@example.com", password })
          )
          assert.strictEqual(failure._tag, "InvalidCredentials")
          assert.strictEqual(hasher.state.verifies - before, 1)

          // The known-user path costs exactly the same one verification.
          const known = hasher.state.verifies
          yield* passwords.signIn({ email: "ada@example.com", password })
          assert.strictEqual(hasher.state.verifies - known, 1)
        }).pipe(Effect.provide(testLayer(undefined, hasher.layer)))
      }),
    testTimeout
  )

  it.effect(
    "verifies a hash even when the user has no password credential",
    () =>
      Effect.gen(function*() {
        const hasher = countingHasher()
        return yield* Effect.gen(function*() {
          const passwords = yield* Passwords
          const accounts = yield* AccountStore
          const { user } = yield* register()

          // Simulate an OAuth-only user: drop the credential account.
          const credential = yield* expectSome(
            yield* accounts.findByIssuerAccountId(CredentialIssuer, user.id),
            "expected a credential account"
          )
          assert.strictEqual(yield* accounts.deleteById(credential.id, user.id), true)

          const before = hasher.state.verifies
          const failure = yield* Effect.flip(passwords.signIn({ email: "ada@example.com", password }))
          assert.strictEqual(failure._tag, "InvalidCredentials")
          assert.strictEqual(hasher.state.verifies - before, 1)
        }).pipe(Effect.provide(testLayer(undefined, hasher.layer)))
      }),
    testTimeout
  )

  it.effect(
    "refuses an unverified address when verification is required",
    () =>
      Effect.gen(function*() {
        const passwords = yield* Passwords
        const emails = yield* TestEmails
        yield* register()

        const failure = yield* Effect.flip(passwords.signIn({ email: "ada@example.com", password }))
        assert.strictEqual(failure._tag, "EmailNotVerified")

        // Verifying the address opens the door.
        const mail = yield* emails.last("verification")
        const verified = yield* passwords.verifyEmail(mail.token)
        assert.strictEqual(verified.emailVerified, true)

        const signedIn = yield* passwords.signIn({ email: "ada@example.com", password })
        assert.strictEqual(signedIn.user.emailVerified, true)
      }).pipe(Effect.provide(testLayer({ emailPassword: { requireEmailVerification: true } }))),
    testTimeout
  )
})

// -----------------------------------------------------------------------------
// E-mail verification
// -----------------------------------------------------------------------------

describe("domain/Passwords/verifyEmail", () => {
  it.effect(
    "consumes the token exactly once and emits EmailVerified",
    () =>
      Effect.gen(function*() {
        const passwords = yield* Passwords
        const emails = yield* TestEmails
        yield* register()
        const mail = yield* emails.last("verification")

        const { events } = yield* recordingEvents(passwords.verifyEmail(mail.token))
        assert.deepStrictEqual(tagsOf(events), ["EmailVerified"])

        // Replaying the link is refused: the row was deleted by the claim.
        const replay = yield* Effect.flip(passwords.verifyEmail(mail.token))
        assert.strictEqual(replay._tag, "InvalidToken")
      }).pipe(Effect.provide(testLayer({ emailPassword: { requireEmailVerification: true } }))),
    testTimeout
  )

  it.effect(
    "refuses a malformed token, a forged subject and an expired one",
    () =>
      Effect.gen(function*() {
        const passwords = yield* Passwords
        const emails = yield* TestEmails
        const config = yield* AuthConfig
        yield* register()
        const mail = yield* emails.last("verification")

        assert.strictEqual(
          (yield* Effect.flip(passwords.verifyEmail(Redacted.make("nonsense"))))._tag,
          "InvalidToken"
        )

        // The secret half is genuine but the subject names another address, so
        // the identifier does not match and the claim finds nothing.
        const parts = yield* expectSome(decodeSubjectToken(mail.token), "expected a subject token")
        const forged = Redacted.make(
          `${btoa("mallory@example.com").replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "")}.${
            Redacted.value(parts.secret)
          }`
        )
        assert.strictEqual((yield* Effect.flip(passwords.verifyEmail(forged)))._tag, "InvalidToken")

        yield* TestClock.adjust(Duration.sum(config.tokens.emailVerificationTtl, Duration.millis(1)))
        assert.strictEqual((yield* Effect.flip(passwords.verifyEmail(mail.token)))._tag, "InvalidToken")
      }).pipe(Effect.provide(testLayer({ emailPassword: { requireEmailVerification: true } }))),
    testTimeout
  )

  it.effect(
    "sendVerificationEmail is silent for an unknown or already-verified address",
    () =>
      Effect.gen(function*() {
        const passwords = yield* Passwords
        const emails = yield* TestEmails
        const users = yield* UserStore
        const { user } = yield* register()

        yield* passwords.sendVerificationEmail({ email: "nobody@example.com" })
        assert.strictEqual((yield* emails.all).length, 0)

        yield* passwords.sendVerificationEmail({ email: "ada@example.com" })
        assert.strictEqual((yield* emails.all).length, 1)

        yield* users.update(user.id, { emailVerified: true })
        yield* passwords.sendVerificationEmail({ email: "ada@example.com" })
        assert.strictEqual((yield* emails.all).length, 1)
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )
})

// -----------------------------------------------------------------------------
// Reset
// -----------------------------------------------------------------------------

describe("domain/Passwords/reset", () => {
  it.effect(
    "requestReset says nothing about an unknown address",
    () =>
      Effect.gen(function*() {
        const passwords = yield* Passwords
        const emails = yield* TestEmails
        yield* register()

        const unknown = yield* recordingEvents(passwords.requestReset({ email: "nobody@example.com" }))
        assert.deepStrictEqual(tagsOf(unknown.events), [])
        assert.strictEqual((yield* emails.all).length, 0)

        const known = yield* recordingEvents(passwords.requestReset({ email: "ada@example.com" }))
        assert.deepStrictEqual(tagsOf(known.events), ["PasswordResetRequested"])
        assert.strictEqual((yield* emails.all).length, 1)
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "keeps an untrusted landing page out of the e-mailed link",
    () =>
      Effect.gen(function*() {
        const passwords = yield* Passwords
        const emails = yield* TestEmails
        const config = yield* AuthConfig
        yield* register()

        // A link in somebody's mailbox that bounces off this deployment onto an
        // attacker's page is a phishing page wearing our name, so the target is
        // validated here as well as at the HTTP edge.
        yield* passwords.requestReset({ email: "ada@example.com", redirectTo: "https://evil.test/phish" })
        const hostile = new URL(Redacted.value((yield* emails.last("reset")).url))
        assert.isNull(hostile.searchParams.get("callbackURL"))

        yield* passwords.requestReset({ email: "ada@example.com", redirectTo: "/\\evil.test" })
        const backslash = new URL(Redacted.value((yield* emails.last("reset")).url))
        assert.isNull(backslash.searchParams.get("callbackURL"))

        yield* passwords.requestReset({ email: "ada@example.com", redirectTo: "/welcome" })
        const allowed = new URL(Redacted.value((yield* emails.last("reset")).url))
        assert.strictEqual(allowed.searchParams.get("callbackURL"), `${new URL(config.baseUrl).origin}/welcome`)
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "a mailer that refuses delivery does not change what the caller sees",
    () =>
      Effect.gen(function*() {
        // The endpoint answers 200 either way, so a bounced message must not
        // turn into an error that distinguishes a known address from an
        // unknown one.
        const passwords = yield* Passwords
        const emails = yield* TestEmails
        yield* register()

        yield* passwords.requestReset({ email: "ada@example.com" })
        yield* passwords.sendVerificationEmail({ email: "ada@example.com" })

        // The tokens were still minted and the messages still composed.
        assert.strictEqual((yield* emails.all).length, 2)

        // ... and the reset link the mailer failed to deliver still works.
        const mail = yield* emails.last("reset")
        yield* passwords.resetPassword({ token: mail.token, newPassword })
        yield* passwords.signIn({ email: "ada@example.com", password: newPassword })
      }).pipe(Effect.provide(testLayer(undefined, undefined, { emailDelivery: "failing" }))),
    testTimeout
  )

  it.effect(
    "resetPassword replaces the hash, revokes every session, and burns the token",
    () =>
      Effect.gen(function*() {
        const passwords = yield* Passwords
        const sessions = yield* Sessions
        const emails = yield* TestEmails
        const { user, session } = yield* register()
        const established = yield* expectSome(session, "expected a session")
        yield* sessions.create({ userId: user.id })

        assert.strictEqual((yield* sessions.list(user.id)).length, 2)

        yield* passwords.requestReset({ email: "ada@example.com" })
        const mail = yield* emails.last("reset")

        const { events } = yield* recordingEvents(
          passwords.resetPassword({ token: mail.token, newPassword })
        )
        assert.deepStrictEqual(tagsOf(events), ["SessionRevoked", "PasswordChanged"])

        // Every device is signed out.
        assert.strictEqual((yield* sessions.list(user.id)).length, 0)
        assert.strictEqual((yield* Effect.flip(sessions.verify(established.token)))._tag, "Unauthorized")

        // The old password is gone and the new one works.
        assert.strictEqual(
          (yield* Effect.flip(passwords.signIn({ email: "ada@example.com", password })))._tag,
          "InvalidCredentials"
        )
        const signedIn = yield* passwords.signIn({ email: "ada@example.com", password: newPassword })
        assert.strictEqual(signedIn.user.id, user.id)

        // The link is single use.
        const replay = yield* Effect.flip(
          passwords.resetPassword({ token: mail.token, newPassword: Redacted.make("third-password-x") })
        )
        assert.strictEqual(replay._tag, "InvalidToken")
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "a completed reset retires every other outstanding reset link",
    () =>
      Effect.gen(function*() {
        const passwords = yield* Passwords
        const emails = yield* TestEmails
        yield* register()

        // Two "forgot password" clicks mint two independent tokens. Somebody
        // with a few minutes of mailbox access holds the first; the owner uses
        // the second and believes the account re-secured.
        yield* passwords.requestReset({ email: "ada@example.com" })
        const stolen = yield* emails.last("reset")
        yield* passwords.requestReset({ email: "ada@example.com" })
        const used = yield* emails.last("reset")
        assert.notStrictEqual(Redacted.value(stolen.token), Redacted.value(used.token))

        yield* passwords.resetPassword({ token: used.token, newPassword })

        // The other link died with it.
        const replay = yield* Effect.flip(
          passwords.resetPassword({ token: stolen.token, newPassword: Redacted.make("attacker-password") })
        )
        assert.strictEqual(replay._tag, "InvalidToken")
        yield* passwords.signIn({ email: "ada@example.com", password: newPassword })
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "changing a password from inside a session retires pending reset links too",
    () =>
      Effect.gen(function*() {
        const passwords = yield* Passwords
        const emails = yield* TestEmails
        const { user } = yield* register()

        yield* passwords.requestReset({ email: "ada@example.com" })
        const pending = yield* emails.last("reset")

        yield* passwords.changePassword({
          userId: user.id,
          currentPassword: password,
          newPassword
        })

        const refused = yield* Effect.flip(
          passwords.resetPassword({ token: pending.token, newPassword: Redacted.make("attacker-password") })
        )
        assert.strictEqual(refused._tag, "InvalidToken")
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "resetPassword refuses an expired token and a policy violation",
    () =>
      Effect.gen(function*() {
        const passwords = yield* Passwords
        const emails = yield* TestEmails
        const config = yield* AuthConfig
        yield* register()
        yield* passwords.requestReset({ email: "ada@example.com" })
        const mail = yield* emails.last("reset")

        // The policy is checked before the token is claimed, so a rejected
        // password does not burn the link.
        const violation = yield* Effect.flip(
          passwords.resetPassword({ token: mail.token, newPassword: Redacted.make("tiny") })
        )
        assert.strictEqual(violation._tag, "PasswordPolicyViolation")

        yield* TestClock.adjust(Duration.sum(config.tokens.passwordResetTtl, Duration.millis(1)))
        const expired = yield* Effect.flip(passwords.resetPassword({ token: mail.token, newPassword }))
        assert.strictEqual(expired._tag, "InvalidToken")
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "resetPassword gives an OAuth-only user a password credential",
    () =>
      Effect.gen(function*() {
        const passwords = yield* Passwords
        const accounts = yield* AccountStore
        const emails = yield* TestEmails
        const { user } = yield* register()

        const credential = yield* expectSome(
          yield* accounts.findByIssuerAccountId(CredentialIssuer, user.id),
          "expected a credential account"
        )
        assert.strictEqual(yield* accounts.deleteById(credential.id, user.id), true)

        yield* passwords.requestReset({ email: "ada@example.com" })
        const mail = yield* emails.last("reset")
        yield* passwords.resetPassword({ token: mail.token, newPassword })

        const created = yield* expectSome(
          yield* accounts.findByIssuerAccountId(CredentialIssuer, user.id),
          "reset should create the missing credential account"
        )
        assert.notStrictEqual(created.passwordHash, null)
        assert.strictEqual(
          (yield* passwords.signIn({ email: "ada@example.com", password: newPassword })).user.id,
          user.id
        )
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )
})

// -----------------------------------------------------------------------------
// Change password
// -----------------------------------------------------------------------------

describe("domain/Passwords/changePassword", () => {
  it.effect(
    "replaces the hash and signs the other devices out",
    () =>
      Effect.gen(function*() {
        const passwords = yield* Passwords
        const sessions = yield* Sessions
        const { user, session } = yield* register()
        const current = yield* expectSome(session, "expected a session")
        const other = yield* sessions.create({ userId: user.id })

        const { events } = yield* recordingEvents(passwords.changePassword({
          userId: user.id,
          currentPassword: password,
          newPassword,
          currentSessionId: current.session.id
        }))
        assert.deepStrictEqual(tagsOf(events), ["SessionRevoked", "PasswordChanged"])

        // The caller keeps their session; the other device does not.
        assert.strictEqual((yield* sessions.verify(current.token)).session.id, current.session.id)
        assert.strictEqual((yield* Effect.flip(sessions.verify(other.token)))._tag, "Unauthorized")

        assert.strictEqual(
          (yield* Effect.flip(passwords.signIn({ email: "ada@example.com", password })))._tag,
          "InvalidCredentials"
        )
        yield* passwords.signIn({ email: "ada@example.com", password: newPassword })
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "keeps every session when revokeOtherSessions is false",
    () =>
      Effect.gen(function*() {
        const passwords = yield* Passwords
        const sessions = yield* Sessions
        const { user } = yield* register()
        const other = yield* sessions.create({ userId: user.id })

        yield* passwords.changePassword({
          userId: user.id,
          currentPassword: password,
          newPassword,
          revokeOtherSessions: false
        })
        assert.strictEqual((yield* sessions.verify(other.token)).session.id, other.session.id)
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "refuses a wrong current password and a policy violation",
    () =>
      Effect.gen(function*() {
        const passwords = yield* Passwords
        const { user } = yield* register()

        const wrong = yield* Effect.flip(passwords.changePassword({
          userId: user.id,
          currentPassword: Redacted.make("not-the-password"),
          newPassword
        }))
        assert.strictEqual(wrong._tag, "InvalidCredentials")

        const violation = yield* Effect.flip(passwords.changePassword({
          userId: user.id,
          currentPassword: password,
          newPassword: Redacted.make("tiny")
        }))
        assert.strictEqual(violation._tag, "PasswordPolicyViolation")

        // Neither attempt changed anything.
        yield* passwords.signIn({ email: "ada@example.com", password })
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )
})
