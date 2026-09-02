import { assert, describe, layer } from "@effect/vitest"
import { Duration, Effect, Option, Redacted, Result } from "effect"
import { TestClock } from "effect/testing"
import { SqlClient } from "effect/unstable/sql"
import { Passwords } from "../../src/domain/Passwords.js"
import { UserStore } from "../../src/domain/Stores.js"
import { EmailOtp, signInPurpose } from "../../src/email-otp/EmailOtp.js"
import { Verifications } from "../../src/domain/Verifications.js"
import * as EmailOtpTest from "../../src/testing/EmailOtpTest.js"
import * as AuthTest from "../../src/testing/TestLayer.js"
import { signUpUser, uniqueEmail } from "../fixtures.js"

/** Asks for a code and reads it out of the outbox, as its recipient does. */
const codeFor = Effect.fnUntraced(function* (
  email: string,
  purpose: "signIn" | "verifyEmail" | "resetPassword",
  nth = 1
) {
  const otp = yield* EmailOtp
  const issued = yield* otp.send({ email, purpose })
  return { handle: issued.handle, code: yield* EmailOtpTest.awaitCode(email, nth), expiresAt: issued.expiresAt }
})

/** How many `verifications` rows one identifier holds — the "same work" assertion. */
const rowsAt = Effect.fnUntraced(function* (identifier: string) {
  const sql = yield* SqlClient.SqlClient
  const rows = yield* sql<{ readonly count: number | string }>`
    select count(*) as count from verifications where identifier = ${identifier}`
  return Number(rows[0]?.count ?? 0)
})

describe.sequential("email-otp/EmailOtp", () => {
  layer(EmailOtpTest.layer())("the flow", (it) => {
    it.effect("signs a stranger in, creating the account", () =>
      Effect.gen(function* () {
        const email = uniqueEmail("stranger")
        const otp = yield* EmailOtp
        const { code, handle } = yield* codeFor(email, "signIn")

        // Eight digits, by default.
        assert.match(Redacted.value(code), /^\d{8}$/)

        const result = yield* otp.verify({ handle, code })
        assert.strictEqual(result._tag, "SignedIn")
        if (result._tag !== "SignedIn") return
        assert.strictEqual(result.user.email, email)
        assert.isTrue(result.user.emailVerified)
        assert.isTrue(result.userCreated)
        assert.notStrictEqual(Redacted.value(result.token).length, 0)
      })
    )

    it.effect("records emailOtp possession evidence on the session it mints", () =>
      Effect.gen(function* () {
        const email = uniqueEmail("evidence")
        const otp = yield* EmailOtp
        const { code, handle } = yield* codeFor(email, "signIn")

        const { events, result } = yield* AuthTest.recordingEvents(otp.verify({ handle, code }))
        assert.strictEqual(result._tag, "SignedIn")
        if (result._tag !== "SignedIn") return

        // On the row…
        assert.deepStrictEqual(
          result.session.methods.map((entry) => entry.method),
          ["emailOtp"]
        )
        assert.strictEqual(result.session.methods[0]?.factor, "possession")
        assert.isFalse(result.session.methods[0]?.phishingResistant)
        // …one possession factor alone is aal1.
        assert.strictEqual(result.session.aal, "aal1")

        // …and on the event beside it.
        const signedIn = events.find((event) => event._tag === "SignedIn")
        if (signedIn === undefined || signedIn._tag !== "SignedIn") {
          return assert.fail("expected a SignedIn event")
        }
        assert.strictEqual(signedIn.method, "email-otp")
        assert.deepStrictEqual(
          signedIn.methods.map((entry) => entry.method),
          ["emailOtp"]
        )
      })
    )

    it.effect("spends a code exactly once", () =>
      Effect.gen(function* () {
        const email = uniqueEmail("once")
        const otp = yield* EmailOtp
        const { code, handle } = yield* codeFor(email, "signIn")

        yield* otp.verify({ handle, code })
        const replayed = yield* Effect.result(otp.verify({ handle, code }))
        assert.strictEqual(replayed._tag, "Failure")
        if (replayed._tag !== "Failure") return
        assert.strictEqual(replayed.failure._tag, "InvalidCode")
      })
    )

    it.effect("spends at most one attempt per concurrent wrong guess, and no more than the budget", () =>
      Effect.gen(function* () {
        const email = uniqueEmail("exhaustion")
        const otp = yield* EmailOtp
        const { code, handle } = yield* codeFor(email, "signIn")
        const wrong = Redacted.make("00000000")

        // Twenty wrong guesses at once against a budget of five. Every one of
        // them is refused, and — because the claim is atomic — the losers never
        // reach a comparison, so between them they spend *at most* five: the
        // budget is a floor on how many guesses a race can buy, never a way to
        // buy more.
        const outcomes = yield* Effect.all(
          Array.from({ length: 20 }, () => Effect.result(otp.verify({ handle, code: wrong }))),
          { concurrency: "unbounded" }
        )
        assert.isTrue(outcomes.every((outcome) => outcome._tag === "Failure"))

        // And the budget is still bounded: five more sequential wrong guesses
        // spend the rest of it, whatever the race left, and then the correct
        // code is gone too.
        for (let attempt = 0; attempt < 5; attempt++) {
          yield* Effect.result(otp.verify({ handle, code: wrong }))
        }
        const exhausted = yield* Effect.result(otp.verify({ handle, code }))
        assert.strictEqual(exhausted._tag, "Failure")
      })
    )

    it.effect("burns the budget one guess at a time and then the correct code stops working", () =>
      Effect.gen(function* () {
        const email = uniqueEmail("budget")
        const otp = yield* EmailOtp
        const { code, handle } = yield* codeFor(email, "signIn")
        const wrong = Redacted.make("00000000")

        for (let attempt = 0; attempt < 5; attempt++) {
          const outcome = yield* Effect.result(otp.verify({ handle, code: wrong }))
          assert.strictEqual(outcome._tag, "Failure")
        }
        const exhausted = yield* Effect.result(otp.verify({ handle, code }))
        assert.strictEqual(exhausted._tag, "Failure")
        if (exhausted._tag !== "Failure") return
        assert.strictEqual(exhausted.failure._tag, "InvalidCode")
      })
    )

    it.effect("refuses a code issued under another purpose", () =>
      Effect.gen(function* () {
        const email = uniqueEmail("cross-purpose")
        yield* signUpUser(email)
        const otp = yield* EmailOtp
        const signIn = yield* codeFor(email, "signIn")
        const verifyEmail = yield* codeFor(email, "verifyEmail", 2)

        // The handle names the purpose, so the pairing is what is refused —
        // a sign-in code presented against the verify-email handle, and back.
        const crossed = yield* Effect.result(otp.verify({ handle: verifyEmail.handle, code: signIn.code }))
        assert.strictEqual(crossed._tag, "Failure")
        const back = yield* Effect.result(otp.verify({ handle: signIn.handle, code: verifyEmail.code }))
        assert.strictEqual(back._tag, "Failure")

        // Each still answers its own.
        const ownVerify = yield* otp.verify({ handle: verifyEmail.handle, code: verifyEmail.code })
        assert.strictEqual(ownVerify._tag, "Verified")
      })
    )

    it.effect("a sign-in code is never answerable as a step-up code", () =>
      Effect.gen(function* () {
        const email = uniqueEmail("signin-not-stepup")
        const registered = yield* signUpUser(email)
        const otp = yield* EmailOtp
        const signIn = yield* codeFor(email, "signIn")

        // Presented at the step-up door, with the step-up purpose stated: the
        // identifier a claim looks up carries the purpose, so it matches no row.
        const refused = yield* Effect.result(
          otp.verifyStepUp({
            session: registered.session,
            handle: Redacted.make(`stepUp.${Redacted.value(signIn.handle).split(".").slice(1).join(".")}`),
            code: signIn.code
          })
        )
        assert.strictEqual(refused._tag, "Failure")
        if (refused._tag !== "Failure") return
        assert.strictEqual(refused.failure._tag, "InvalidCode")

        // And nothing was consumed: the sign-in code still works.
        const result = yield* otp.verify({ handle: signIn.handle, code: signIn.code })
        assert.strictEqual(result._tag, "SignedIn")
      })
    )

    it.effect("a resend retires the prior code and its link", () =>
      Effect.gen(function* () {
        const email = uniqueEmail("resend")
        const otp = yield* EmailOtp
        const first = yield* codeFor(email, "signIn")
        const firstLink = yield* EmailOtpTest.awaitLinkToken(email)

        const second = yield* codeFor(email, "signIn", 2)
        assert.notStrictEqual(Redacted.value(second.code), Redacted.value(first.code))

        // The old code is gone…
        const stale = yield* Effect.result(otp.verify({ handle: first.handle, code: first.code }))
        assert.strictEqual(stale._tag, "Failure")
        // …and so is the link that shared its row.
        const staleLink = yield* otp.follow({ token: Redacted.make(firstLink) })
        assert.strictEqual(staleLink._tag, "Failure")

        // The one they are looking at works.
        const result = yield* otp.verify({ handle: second.handle, code: second.code })
        assert.strictEqual(result._tag, "SignedIn")
      })
    )

    it.effect("the hybrid: consuming the code retires the link", () =>
      Effect.gen(function* () {
        const email = uniqueEmail("hybrid-code")
        const otp = yield* EmailOtp
        const { code, handle } = yield* codeFor(email, "signIn")
        const token = yield* EmailOtpTest.awaitLinkToken(email)

        const result = yield* otp.verify({ handle, code })
        assert.strictEqual(result._tag, "SignedIn")

        const followed = yield* otp.follow({ token: Redacted.make(token) })
        assert.strictEqual(followed._tag, "Failure")
      })
    )

    it.effect("the hybrid: following the link retires the code", () =>
      Effect.gen(function* () {
        const email = uniqueEmail("hybrid-link")
        const otp = yield* EmailOtp
        const { code, handle } = yield* codeFor(email, "signIn")
        const token = yield* EmailOtpTest.awaitLinkToken(email)

        const followed = yield* otp.follow({ token: Redacted.make(token) })
        assert.isTrue(Result.isSuccess(followed))
        if (!Result.isSuccess(followed)) return
        assert.strictEqual(followed.success._tag, "SignedIn")
        if (followed.success._tag !== "SignedIn") return
        assert.strictEqual(followed.success.user.email, email)

        const answered = yield* Effect.result(otp.verify({ handle, code }))
        assert.strictEqual(answered._tag, "Failure")
      })
    )

    it.effect("a challenge handle presented as a link token is refused", () =>
      Effect.gen(function* () {
        // The purpose carries a payload schema, so the challenge row's payload
        // — a code hash and an attempt budget — does not decode as one. The
        // handle is therefore not a link, whoever holds it.
        const email = uniqueEmail("handle-is-not-a-link")
        const { handle } = yield* codeFor(email, "signIn")
        const raw = Redacted.value(handle).split(".").slice(1).join(".")

        const verifications = yield* Verifications
        const claimed = yield* Effect.result(verifications.claim(signInPurpose, Redacted.make(raw)))
        assert.strictEqual(claimed._tag, "Failure")
        if (claimed._tag !== "Failure") return
        assert.strictEqual(claimed.failure._tag, "InvalidToken")

        // And no session came of it either way.
        const users = yield* UserStore
        assert.isTrue(Option.isNone(yield* users.findByEmail(email)))
      })
    )

    it.effect("verifies an address without signing anybody in", () =>
      Effect.gen(function* () {
        const email = uniqueEmail("verify-email")
        const registered = yield* signUpUser(email)
        assert.isFalse(registered.user.emailVerified)

        const otp = yield* EmailOtp
        const { code, handle } = yield* codeFor(email, "verifyEmail")
        const result = yield* otp.verify({ handle, code })

        assert.strictEqual(result._tag, "Verified")
        if (result._tag !== "Verified") return
        assert.isTrue(result.user.emailVerified)
      })
    )

    it.effect("hands a reset continuation the core endpoint accepts, and signs nobody in", () =>
      Effect.gen(function* () {
        const email = uniqueEmail("reset")
        yield* signUpUser(email)
        const otp = yield* EmailOtp
        const { code, handle } = yield* codeFor(email, "resetPassword")

        const result = yield* otp.verify({ handle, code })
        assert.strictEqual(result._tag, "PasswordReset")
        if (result._tag !== "PasswordReset") return

        // It is a `password-reset` token: the library's own endpoint spends it.
        const passwords = yield* Passwords
        const replacement = Redacted.make("a-much-longer-replacement-passphrase")
        yield* passwords.resetPassword({ token: result.token, newPassword: replacement })
        const signedIn = yield* passwords.signIn({ email, password: replacement })
        assert.strictEqual(signedIn._tag, "Complete")
      })
    )

    it.effect("does the same work for a known and an unknown address", () =>
      Effect.gen(function* () {
        const stranger = uniqueEmail("unknown-work")
        const member = uniqueEmail("known-work")
        yield* signUpUser(member)
        const otp = yield* EmailOtp

        const first = yield* otp.send({ email: stranger, purpose: "signIn" })
        const second = yield* otp.send({ email: member, purpose: "signIn" })

        // Both answered a handle, and both wrote the same two rows — the link,
        // and the challenge in the namespace of its own that keeps a handle
        // from ever being redeemable as a token.
        assert.notStrictEqual(Redacted.value(first.handle).length, 0)
        assert.notStrictEqual(Redacted.value(second.handle).length, 0)
        assert.strictEqual(yield* rowsAt(`email-otp:sign-in:${stranger}`), 1)
        assert.strictEqual(yield* rowsAt(`email-otp:sign-in:${member}`), 1)
        assert.strictEqual(yield* rowsAt(`email-otp:sign-in#code:${stranger}`), 1)
        assert.strictEqual(yield* rowsAt(`email-otp:sign-in#code:${member}`), 1)

        // And both mailed exactly one message, in the order they were asked for.
        yield* EmailOtpTest.awaitDelivery(stranger)
        yield* EmailOtpTest.awaitDelivery(member)
        const emails = yield* AuthTest.TestEmails
        assert.strictEqual((yield* emails.to(stranger)).length, 1)
        assert.strictEqual((yield* emails.to(member)).length, 1)
        // The one difference is what the *mailer* is told, which only the
        // mailbox's owner ever sees.
        const strangerMail = yield* emails.last(EmailOtpTest.emailOtpKind, stranger)
        const memberMail = yield* emails.last(EmailOtpTest.emailOtpKind, member)
        assert.isTrue(Option.isSome(strangerMail) && strangerMail.value.user === null)
        assert.isTrue(Option.isSome(memberMail) && memberMail.value.user !== null)
      })
    )

    it.effect("answers a handle for an address with nothing to reset, and no code", () =>
      Effect.gen(function* () {
        const stranger = uniqueEmail("nothing-to-reset")
        const otp = yield* EmailOtp

        const issued = yield* otp.send({ email: stranger, purpose: "resetPassword" })
        assert.notStrictEqual(Redacted.value(issued.handle).length, 0)

        // The rows were written and then discarded, so the write cost matched…
        assert.strictEqual(yield* rowsAt(`email-otp:reset-password:${stranger}`), 0)
        // …and nothing was mailed to a mailbox that has no account behind it.
        const emails = yield* AuthTest.TestEmails
        assert.deepStrictEqual(yield* emails.to(stranger), [])

        // A handle naming nothing answers exactly what a wrong code does.
        const refused = yield* Effect.result(otp.verify({ handle: issued.handle, code: Redacted.make("00000000") }))
        assert.strictEqual(refused._tag, "Failure")
        if (refused._tag !== "Failure") return
        assert.strictEqual(refused.failure._tag, "InvalidCode")
      })
    )

    it.effect("elevates a session with a step-up code, and only for its own user", () =>
      Effect.gen(function* () {
        const email = uniqueEmail("step-up")
        const registered = yield* signUpUser(email)
        const otp = yield* EmailOtp

        // Somebody else's session cannot spend it — and the attempt burns the
        // code rather than leaving it replayable, because the row is claimed
        // before anything about it is judged.
        const other = yield* signUpUser(uniqueEmail("step-up-other"))
        const stolen = yield* otp.requestStepUp(registered.user)
        const refused = yield* Effect.result(
          otp.verifyStepUp({
            session: other.session,
            handle: stolen.handle,
            code: yield* EmailOtpTest.awaitCode(email)
          })
        )
        assert.strictEqual(refused._tag, "Failure")
        if (refused._tag !== "Failure") return
        assert.strictEqual(refused.failure._tag, "InvalidCode")

        const issued = yield* otp.requestStepUp(registered.user)
        const code = yield* EmailOtpTest.awaitCode(email, 2)
        const elevated = yield* otp.verifyStepUp({ session: registered.session, handle: issued.handle, code })
        assert.strictEqual(elevated.session.id, registered.session.id)
        // A password and a mailed code are two factors.
        assert.strictEqual(elevated.session.aal, "aal2")
        assert.deepStrictEqual(
          elevated.session.methods.map((entry) => entry.method),
          ["password", "emailOtp"]
        )
        // The token rotated.
        assert.notStrictEqual(Redacted.value(elevated.token), Redacted.value(registered.token))
      })
    )

    it.effect("moves an account to an address a code proved control of", () =>
      Effect.gen(function* () {
        const email = uniqueEmail("mover")
        const destination = uniqueEmail("destination")
        const registered = yield* signUpUser(email)
        const otp = yield* EmailOtp

        const issued = yield* otp.requestEmailChange({ user: registered.user, newEmail: destination })
        const code = yield* EmailOtpTest.awaitCode(destination)
        const moved = yield* otp.verifyEmailChange({ user: registered.user, handle: issued.handle, code })

        assert.strictEqual(moved.email, destination)
        assert.isTrue(moved.emailVerified)
      })
    )

    it.effect("refuses a change to an address that is already taken, and mails nobody", () =>
      Effect.gen(function* () {
        const email = uniqueEmail("mover-blocked")
        const occupied = uniqueEmail("occupied")
        const registered = yield* signUpUser(email)
        yield* signUpUser(occupied)
        const otp = yield* EmailOtp

        const before = (yield* Effect.flatMap(AuthTest.TestEmails, (outbox) => outbox.to(occupied))).length
        const issued = yield* otp.requestEmailChange({ user: registered.user, newEmail: occupied })
        // A handle either way, and the caller cannot tell.
        assert.notStrictEqual(Redacted.value(issued.handle).length, 0)
        const after = (yield* Effect.flatMap(AuthTest.TestEmails, (outbox) => outbox.to(occupied))).length
        assert.strictEqual(after, before)
      })
    )

    it.effect("refuses a change to the address the account already has", () =>
      Effect.gen(function* () {
        const email = uniqueEmail("unchanged")
        const registered = yield* signUpUser(email)
        const otp = yield* EmailOtp
        const refused = yield* Effect.result(
          otp.requestEmailChange({ user: registered.user, newEmail: email.toUpperCase() })
        )
        assert.strictEqual(refused._tag, "Failure")
        if (refused._tag !== "Failure") return
        assert.strictEqual(refused.failure._tag, "EmailUnchanged")
      })
    )

    it.effect("expires a code when its ttl runs out", () =>
      AuthTest.freshClock(
        Effect.gen(function* () {
          const email = uniqueEmail("expiry")
          const otp = yield* EmailOtp
          const { code, handle } = yield* codeFor(email, "signIn")

          yield* TestClock.adjust(Duration.minutes(11))

          const stale = yield* Effect.result(otp.verify({ handle, code }))
          assert.strictEqual(stale._tag, "Failure")
          if (stale._tag !== "Failure") return
          assert.strictEqual(stale.failure._tag, "InvalidCode")
        })
      )
    )

    it.effect("a wrong guess buys no extra time", () =>
      AuthTest.freshClock(
        Effect.gen(function* () {
          const email = uniqueEmail("no-extra-time")
          const otp = yield* EmailOtp
          const { code, handle } = yield* codeFor(email, "signIn")

          yield* TestClock.adjust(Duration.minutes(9))
          const wrong = yield* Effect.result(otp.verify({ handle, code: Redacted.make("00000000") }))
          assert.strictEqual(wrong._tag, "Failure")

          yield* TestClock.adjust(Duration.minutes(2))
          const stale = yield* Effect.result(otp.verify({ handle, code }))
          assert.strictEqual(stale._tag, "Failure")
        })
      )
    )

    it.effect("refuses a cookie that is not a handle at all", () =>
      Effect.gen(function* () {
        const otp = yield* EmailOtp
        for (const value of ["", ".", "nonsense", "signIn.", "wobble.abc"]) {
          const refused = yield* Effect.result(
            otp.verify({ handle: Redacted.make(value), code: Redacted.make("00000000") })
          )
          assert.strictEqual(refused._tag, "Failure", `expected ${JSON.stringify(value)} to be refused`)
        }
      })
    )

    it.effect("the two authenticated purposes are unreachable from the unauthenticated door", () =>
      Effect.gen(function* () {
        const email = uniqueEmail("no-back-door")
        const registered = yield* signUpUser(email)
        const otp = yield* EmailOtp
        const issued = yield* otp.requestStepUp(registered.user)
        const code = yield* EmailOtpTest.awaitCode(email)

        // The handle states `stepUp`, and `verify` refuses it before a query.
        const refused = yield* Effect.result(otp.verify({ handle: issued.handle, code }))
        assert.strictEqual(refused._tag, "Failure")

        // Nothing was consumed: the step-up code still elevates.
        const elevated = yield* otp.verifyStepUp({ session: registered.session, handle: issued.handle, code })
        assert.strictEqual(elevated.session.aal, "aal2")
      })
    )
  })

  layer(EmailOtpTest.layer({ emailOtp: { disableSignUp: true } }))("with sign-up disabled", (it) => {
    it.effect("answers a stranger identically and refuses at the spend", () =>
      Effect.gen(function* () {
        const stranger = uniqueEmail("no-signup")
        const otp = yield* EmailOtp

        const issued = yield* otp.send({ email: stranger, purpose: "signIn" })
        assert.notStrictEqual(Redacted.value(issued.handle).length, 0)
        // The same rows a member's request writes, and nothing mailed. They are
        // written and left, never written and deleted: a deletion is a round
        // trip the deliverable branch does not make, and one round trip is all
        // an attacker needs to read a registration off the clock.
        assert.strictEqual(yield* rowsAt(`email-otp:sign-in:${stranger}`), 1)
        assert.strictEqual(yield* rowsAt(`email-otp:sign-in#code:${stranger}`), 1)
        const emails = yield* AuthTest.TestEmails
        assert.deepStrictEqual(yield* emails.to(stranger), [])

        const refused = yield* Effect.result(otp.verify({ handle: issued.handle, code: Redacted.make("00000000") }))
        assert.strictEqual(refused._tag, "Failure")
        if (refused._tag !== "Failure") return
        // Never `UserNotFound`.
        assert.strictEqual(refused.failure._tag, "InvalidCode")
      })
    )

    it.effect("writes exactly the rows a member's request writes", () =>
      Effect.gen(function* () {
        const stranger = uniqueEmail("parity-stranger")
        const member = uniqueEmail("parity-member")
        yield* signUpUser(member)
        const otp = yield* EmailOtp

        yield* otp.send({ email: stranger, purpose: "signIn" })
        yield* otp.send({ email: member, purpose: "signIn" })

        // The refusal lives at the spend and nowhere earlier, so the two
        // requests are one sequence of statements with one branch — whether a
        // message is handed to the forked mailer — that never touches the
        // database at all.
        assert.strictEqual(yield* rowsAt(`email-otp:sign-in:${stranger}`), yield* rowsAt(`email-otp:sign-in:${member}`))
        assert.strictEqual(
          yield* rowsAt(`email-otp:sign-in#code:${stranger}`),
          yield* rowsAt(`email-otp:sign-in#code:${member}`)
        )
      })
    )

    it.effect("still signs a member in", () =>
      Effect.gen(function* () {
        const email = uniqueEmail("member-no-signup")
        yield* signUpUser(email)
        const otp = yield* EmailOtp
        const { code, handle } = yield* codeFor(email, "signIn")
        const result = yield* otp.verify({ handle, code })
        assert.strictEqual(result._tag, "SignedIn")
      })
    )
  })
})
