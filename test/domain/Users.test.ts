/**
 * What a signed-in person may do to their own record, at the domain seam.
 *
 * **Details**
 *
 * The HTTP tests next door prove the endpoints are wired to this service and
 * gated by the configuration. What is proved here is the behaviour those
 * endpoints inherit: that a change of address takes two hops and neither of them
 * carries the address in a URL, that an address somebody else already has is
 * answered exactly as one that is free, that a deletion needs either a fresh
 * session or a mailbox, and that nothing outstanding survives the row.
 */
import { assert, describe, layer } from "@effect/vitest"
import { Duration, Effect, Option, Redacted } from "effect"
import { TestClock } from "effect/testing"
import type { AuthEvent } from "../../src/domain/Events.js"
import { Passwords } from "../../src/domain/Passwords.js"
import type { UserId } from "../../src/domain/Schema.js"
import { Sessions } from "../../src/domain/Sessions.js"
import { UserStore, VerificationStore } from "../../src/domain/Stores.js"
import { changeEmailVerifyPurpose, Users } from "../../src/domain/Users.js"
import { identifierOf, passwordResetPurpose } from "../../src/domain/Verifications.js"
import { AuthTest, TestEmails } from "../../src/testing/index.js"
import { expectSome, tagsOf, testName, testPassword, uniqueEmail } from "../fixtures.js"

/**
 * Registers a user and hands back the row and the session sign-up established.
 *
 * **Gotchas**
 *
 * Every test in the block writes to one database, so `email` must be a
 * {@link uniqueEmail}.
 */
const register = Effect.fnUntraced(function*(email: string) {
  const passwords = yield* Passwords
  const result = yield* passwords.signUp({ name: testName, email, password: testPassword })
  const created = yield* expectSome(result.session, "sign-up should establish a session")
  return { user: result.user, session: created.session, token: created.token }
})

/**
 * Registers a user whose address is already verified — the branch of
 * `requestEmailChange` that has somebody to warn.
 *
 * The column is set through the store rather than through the verification flow:
 * what is under test is what the *change* flow does with a verified address, not
 * how it came to be verified.
 */
const registerVerified = Effect.fnUntraced(function*(email: string) {
  const users = yield* UserStore
  const registered = yield* register(email)
  const updated = yield* users.update(registered.user.id, { emailVerified: true })
  const user = yield* expectSome(updated, "the user should still be there")
  return { ...registered, user }
})

/** The events one user's flows published — the hub is shared by the block. */
const forUser = (events: ReadonlyArray<AuthEvent>, userId: string): ReadonlyArray<AuthEvent> =>
  events.filter((event) => event.userId === userId)

/** Every e-mail delivered to one address. */
const mailTo = Effect.fnUntraced(function*(address: string) {
  const emails = yield* TestEmails.TestEmails
  return yield* emails.to(address)
})

/** The link of the most recent e-mail of a kind sent to one address. */
const linkTo = Effect.fnUntraced(function*(kind: string, address: string) {
  const emails = yield* TestEmails.TestEmails
  const sent = yield* expectSome(yield* emails.last(kind, address), `expected a ${kind} e-mail for ${address}`)
  return { token: sent.token, url: Redacted.value(sent.url), user: sent.user }
})

layer(AuthTest.layer())("domain/Users", (it) => {
  // ---------------------------------------------------------------------------
  // update
  // ---------------------------------------------------------------------------

  describe("update", () => {
    it.effect("patches what the caller names and reports what actually changed", () =>
      Effect.gen(function*() {
        const users = yield* Users
        const { user } = yield* register(uniqueEmail("update"))

        const { events, result } = yield* AuthTest.recordingEvents(
          users.update({ userId: user.id, name: "Grace Hopper", image: "https://example.com/g.png" })
        )

        assert.strictEqual(result.name, "Grace Hopper")
        assert.strictEqual(result.image, "https://example.com/g.png")
        // The address is not editable here: moving an account is the change-email
        // flow, and nothing about this call touched it.
        assert.strictEqual(result.email, user.email)

        const published = forUser(events, user.id)
        assert.deepStrictEqual(tagsOf(published), ["UserUpdated"])
        const updated = published[0]
        if (updated?._tag !== "UserUpdated") return assert.fail("expected a UserUpdated event")
        assert.deepStrictEqual(updated.fields, ["name", "image"])
      }))

    it.effect("leaves an unnamed column alone, and clears the image when told to", () =>
      Effect.gen(function*() {
        const users = yield* Users
        const { user } = yield* register(uniqueEmail("update-null"))
        yield* users.update({ userId: user.id, name: "Ada", image: "https://example.com/a.png" })

        // An absent key is a column the statement does not touch …
        const renamed = yield* users.update({ userId: user.id, name: "Ada Byron" })
        assert.strictEqual(renamed.image, "https://example.com/a.png")

        // … and an explicit null is a column it clears.
        const cleared = yield* users.update({ userId: user.id, image: null })
        assert.strictEqual(cleared.image, null)
        assert.strictEqual(cleared.name, "Ada Byron")
      }))

    it.effect("names no field when the values are the ones already stored", () =>
      Effect.gen(function*() {
        const users = yield* Users
        const { user } = yield* register(uniqueEmail("update-noop"))

        const { events } = yield* AuthTest.recordingEvents(
          users.update({ userId: user.id, name: testName, image: null })
        )
        const published = forUser(events, user.id)
        assert.deepStrictEqual(tagsOf(published), ["UserUpdated"])
        const updated = published[0]
        if (updated?._tag !== "UserUpdated") return assert.fail("expected a UserUpdated event")
        assert.deepStrictEqual(updated.fields, [])
      }))

    it.effect("fails UserNotFound for an id no row has", () =>
      Effect.gen(function*() {
        const users = yield* Users
        const failure = yield* Effect.flip(
          users.update({ userId: "00000000-0000-0000-0000-000000000000" as UserId, name: "Nobody" })
        )
        assert.strictEqual(failure._tag, "UserNotFound")
      }))
  })

  // ---------------------------------------------------------------------------
  // requestEmailChange
  // ---------------------------------------------------------------------------

  describe("requestEmailChange", () => {
    it.effect("warns the address the account has now, when that address is verified", () =>
      Effect.gen(function*() {
        const users = yield* Users
        const store = yield* UserStore
        const email = uniqueEmail("change-verified")
        const newEmail = uniqueEmail("change-verified-new")
        const { user } = yield* registerVerified(email)

        assert.strictEqual(yield* users.requestEmailChange({ user, newEmail }), "ConfirmationSent")

        const confirmation = yield* linkTo(AuthTest.changeEmailConfirmationKind, email)
        // The proposed address is nowhere in the link: it travels in the token's
        // server-side payload, so the link cannot be edited into one that moves
        // the account somewhere else.
        assert.notInclude(confirmation.url, newEmail)
        assert.include(confirmation.url, "/auth/change-email/confirm")
        assert.strictEqual(confirmation.user?.id, user.id)

        // And the new address hears nothing until the first hop is followed.
        assert.deepStrictEqual(yield* mailTo(newEmail), [])
        // Nothing about the account has changed.
        const still = yield* expectSome(yield* store.findById(user.id), "the user should still be there")
        assert.strictEqual(still.email, email)
      }))

    it.effect("goes straight to the new address when the current one is unverified", () =>
      Effect.gen(function*() {
        const users = yield* Users
        const email = uniqueEmail("change-unverified")
        const newEmail = uniqueEmail("change-unverified-new")
        const { user } = yield* register(email)

        assert.strictEqual(yield* users.requestEmailChange({ user, newEmail }), "VerificationSent")

        // An unverified address is no evidence that anybody reads it, so there
        // is nobody to warn and no first hop.
        assert.deepStrictEqual(yield* mailTo(email), [])
        const verification = yield* linkTo(AuthTest.changeEmailVerificationKind, newEmail)
        assert.include(verification.url, "/auth/change-email/verify")
        assert.notInclude(verification.url, newEmail)
      }))

    it.effect("refuses the address the account already has, however it is spelled", () =>
      Effect.gen(function*() {
        const users = yield* Users
        const email = uniqueEmail("change-same")
        const { user } = yield* register(email)

        const failure = yield* Effect.flip(
          users.requestEmailChange({ user, newEmail: `  ${email.toUpperCase()} ` })
        )
        assert.strictEqual(failure._tag, "EmailUnchanged")
      }))

    it.effect("answers an address somebody else has exactly as one that is free", () =>
      Effect.gen(function*() {
        const users = yield* Users
        const verifications = yield* VerificationStore
        const email = uniqueEmail("change-taken")
        const occupied = uniqueEmail("change-occupant")
        const free = uniqueEmail("change-taken-free")
        const { user } = yield* registerVerified(email)
        yield* register(occupied)

        // Same call shape, same success, no failure to distinguish — a signed-in
        // session must not be an oracle for who else is registered here.
        assert.strictEqual(yield* users.requestEmailChange({ user, newEmail: occupied }), "Ignored")

        // And the caller's *own* mailbox says the same as it would for a free
        // address: hop one goes out either way. A confirmation that arrived
        // only for a free address would be the oracle the 200 refuses to be.
        const afterTaken = yield* mailTo(email)
        assert.strictEqual(afterTaken.length, 1)
        assert.strictEqual(afterTaken[0]?.kind, AuthTest.changeEmailConfirmationKind)
        assert.include(Redacted.value(afterTaken[0]!.url), "/auth/change-email/confirm")

        // Nothing reached the address that is somebody else's: the second hop is
        // the only message it would ever get, and it is not sent.
        assert.deepStrictEqual(yield* mailTo(occupied), [])

        // A free address is one more message of the same kind to the same
        // mailbox: same count, same kind, nothing to the new address yet.
        assert.strictEqual(yield* users.requestEmailChange({ user, newEmail: free }), "ConfirmationSent")
        const afterFree = yield* mailTo(email)
        assert.strictEqual(afterFree.length, 2)
        assert.strictEqual(afterFree[1]?.kind, AuthTest.changeEmailConfirmationKind)
        assert.deepStrictEqual(yield* mailTo(free), [])

        // The outcomes differ only in what the server writes down — the endpoint
        // answers 200 to both, which test/http/Users.test.ts pins — and neither
        // call left a hop-two row that could move the account to the address
        // somebody else has.
        assert.strictEqual(
          yield* verifications.deleteByIdentifier(identifierOf(changeEmailVerifyPurpose, user.id)),
          0
        )
      }))

    it.effect("sends nothing at all when the current address is unverified and the new one is taken", () =>
      Effect.gen(function*() {
        const users = yield* Users
        const email = uniqueEmail("change-taken-unverified")
        const occupied = uniqueEmail("change-taken-occupant")
        const { user } = yield* register(email)
        yield* register(occupied)

        // There is no first hop on this branch, and the second one goes to the
        // new address — never to the caller — so there is nothing for a taken
        // address to make observable.
        assert.strictEqual(yield* users.requestEmailChange({ user, newEmail: occupied }), "Ignored")
        assert.deepStrictEqual(yield* mailTo(email), [])
        assert.deepStrictEqual(yield* mailTo(occupied), [])
      }))

    it.effect("replaces an outstanding request rather than adding to it", () =>
      Effect.gen(function*() {
        const users = yield* Users
        const email = uniqueEmail("change-twice")
        const first = uniqueEmail("change-twice-first")
        const second = uniqueEmail("change-twice-second")
        const { user } = yield* register(email)

        yield* users.requestEmailChange({ user, newEmail: first })
        yield* users.requestEmailChange({ user, newEmail: second })

        const stale = (yield* mailTo(first))[0]
        assert.isDefined(stale)
        // Two live links would be two addresses the account could still be moved
        // to, one of which its owner has already thought better of.
        const failure = yield* Effect.flip(users.verifyEmailChange(stale!.token))
        assert.strictEqual(failure._tag, "InvalidToken")

        const fresh = (yield* mailTo(second))[0]
        const moved = yield* users.verifyEmailChange(fresh!.token)
        assert.strictEqual(moved.email, second)
      }))

    it.effect("appends a landing page it trusts, and drops one it does not", () =>
      Effect.gen(function*() {
        const users = yield* Users
        const kept = uniqueEmail("change-cb-kept")
        const refused = uniqueEmail("change-cb-refused")

        const first = yield* register(uniqueEmail("change-cb-a"))
        yield* users.requestEmailChange({ user: first.user, newEmail: kept, callbackURL: "/welcome" })
        const keptLink = yield* linkTo(AuthTest.changeEmailVerificationKind, kept)
        assert.strictEqual(
          new URL(keptLink.url).searchParams.get("callbackURL"),
          "http://localhost:3000/welcome"
        )

        const second = yield* register(uniqueEmail("change-cb-b"))
        yield* users.requestEmailChange({
          user: second.user,
          newEmail: refused,
          callbackURL: "https://evil.test/steal"
        })
        // What ends up in the link ends up in somebody's mailbox, so an origin
        // this deployment does not trust is dropped rather than carried.
        const refusedLink = yield* linkTo(AuthTest.changeEmailVerificationKind, refused)
        assert.isNull(new URL(refusedLink.url).searchParams.get("callbackURL"))
      }))
  })

  // ---------------------------------------------------------------------------
  // confirmEmailChange / verifyEmailChange
  // ---------------------------------------------------------------------------

  describe("the two hops", () => {
    it.effect("changes nothing at the first hop, and mails the second to the new address", () =>
      Effect.gen(function*() {
        const users = yield* Users
        const store = yield* UserStore
        const email = uniqueEmail("hop-one")
        const newEmail = uniqueEmail("hop-one-new")
        const { user } = yield* registerVerified(email)

        yield* users.requestEmailChange({ user, newEmail })
        const confirmation = yield* linkTo(AuthTest.changeEmailConfirmationKind, email)
        yield* users.confirmEmailChange(confirmation.token)

        // Nothing about the account has changed when the first hop succeeds …
        const still = yield* expectSome(yield* store.findById(user.id), "the user should still be there")
        assert.strictEqual(still.email, email)
        assert.strictEqual(still.emailVerified, true)

        // … and the second hop is now in the new address's mailbox.
        const verification = yield* linkTo(AuthTest.changeEmailVerificationKind, newEmail)
        assert.notInclude(verification.url, newEmail)
      }))

    it.effect("spends the first-hop token but sends no second hop when the address has been taken", () =>
      Effect.gen(function*() {
        const users = yield* Users
        const verifications = yield* VerificationStore
        const email = uniqueEmail("hop-one-taken")
        const occupied = uniqueEmail("hop-one-occupant")
        const { user } = yield* registerVerified(email)
        yield* register(occupied)

        // Hop one is mailed for a taken address exactly as for a free one, so
        // this is where the flow stops. Following it succeeds — a failure here
        // would report, to somebody watching their own inbox, that the address
        // belongs to somebody.
        yield* users.requestEmailChange({ user, newEmail: occupied })
        const confirmation = yield* linkTo(AuthTest.changeEmailConfirmationKind, email)
        yield* users.confirmEmailChange(confirmation.token)

        // Nothing reached the address that is somebody else's, and no hop-two
        // row was minted, so the account cannot be moved onto it.
        assert.deepStrictEqual(yield* mailTo(occupied), [])
        assert.strictEqual(
          yield* verifications.deleteByIdentifier(identifierOf(changeEmailVerifyPurpose, user.id)),
          0
        )

        // And the token is spent, as every claimed link is.
        const failure = yield* Effect.flip(users.confirmEmailChange(confirmation.token))
        assert.strictEqual(failure._tag, "InvalidToken")
      }))

    it.effect("burns the first-hop token, so a link that leaked cannot be replayed", () =>
      Effect.gen(function*() {
        const users = yield* Users
        const email = uniqueEmail("hop-replay")
        const { user } = yield* registerVerified(email)

        yield* users.requestEmailChange({ user, newEmail: uniqueEmail("hop-replay-new") })
        const confirmation = yield* linkTo(AuthTest.changeEmailConfirmationKind, email)
        yield* users.confirmEmailChange(confirmation.token)

        const failure = yield* Effect.flip(users.confirmEmailChange(confirmation.token))
        assert.strictEqual(failure._tag, "InvalidToken")
      }))

    it.effect("reports a token that is not one of ours as InvalidToken", () =>
      Effect.gen(function*() {
        const users = yield* Users
        const confirm = yield* Effect.flip(users.confirmEmailChange(Redacted.make("not-a-subject-token")))
        assert.strictEqual(confirm._tag, "InvalidToken")
        const verify = yield* Effect.flip(users.verifyEmailChange(Redacted.make("not-a-subject-token")))
        assert.strictEqual(verify._tag, "InvalidToken")
      }))

    it.effect("moves the account at the second hop, and the address ends up verified", () =>
      Effect.gen(function*() {
        const users = yield* Users
        const passwords = yield* Passwords
        const email = uniqueEmail("hop-two")
        const newEmail = uniqueEmail("hop-two-new")
        const { user } = yield* registerVerified(email)

        yield* users.requestEmailChange({ user, newEmail })
        const confirmation = yield* linkTo(AuthTest.changeEmailConfirmationKind, email)
        yield* users.confirmEmailChange(confirmation.token)
        const verification = yield* linkTo(AuthTest.changeEmailVerificationKind, newEmail)

        const { events, result } = yield* AuthTest.recordingEvents(users.verifyEmailChange(verification.token))
        assert.strictEqual(result.email, newEmail)
        // The link was delivered to the new address, which is the whole of what
        // verification means.
        assert.strictEqual(result.emailVerified, true)

        const published = forUser(events, user.id)
        assert.deepStrictEqual(tagsOf(published), ["EmailChanged"])
        const changed = published[0]
        if (changed?._tag !== "EmailChanged") return assert.fail("expected an EmailChanged event")
        assert.strictEqual(changed.previousEmail, email)
        assert.strictEqual(changed.email, newEmail)

        // The credential moved with the row: the new address signs in, the old
        // one is nobody's.
        assert.strictEqual((yield* passwords.signIn({ email: newEmail, password: testPassword })).user.id, user.id)
        const gone = yield* Effect.flip(passwords.signIn({ email, password: testPassword }))
        assert.strictEqual(gone._tag, "InvalidCredentials")
      }))

    it.effect("reports a collision at the second hop as UserAlreadyExists", () =>
      Effect.gen(function*() {
        const users = yield* Users
        const store = yield* UserStore
        const email = uniqueEmail("hop-race")
        const contested = uniqueEmail("hop-race-contested")
        const { user } = yield* register(email)

        // Free when the change was asked for …
        yield* users.requestEmailChange({ user, newEmail: contested })
        const verification = yield* linkTo(AuthTest.changeEmailVerificationKind, contested)
        // … and taken by the time the link was followed. The unique index is
        // what settles it, so there is no check-then-act window to lose.
        yield* register(contested)

        const failure = yield* Effect.flip(users.verifyEmailChange(verification.token))
        assert.strictEqual(failure._tag, "UserAlreadyExists")

        const unchanged = yield* expectSome(yield* store.findById(user.id), "the user should still be there")
        assert.strictEqual(unchanged.email, email)
      }))

    it.effect("retires the other hop's outstanding links when the change completes", () =>
      Effect.gen(function*() {
        const users = yield* Users
        const verifications = yield* VerificationStore
        const email = uniqueEmail("hop-retire")
        const newEmail = uniqueEmail("hop-retire-new")
        const { user } = yield* registerVerified(email)

        yield* users.requestEmailChange({ user, newEmail })
        const confirmation = yield* linkTo(AuthTest.changeEmailConfirmationKind, email)
        yield* users.confirmEmailChange(confirmation.token)
        const verification = yield* linkTo(AuthTest.changeEmailVerificationKind, newEmail)

        // A second first-hop request, made while the second hop was outstanding.
        yield* users.requestEmailChange({ user, newEmail: uniqueEmail("hop-retire-other") })
        yield* users.verifyEmailChange(verification.token)

        // Nothing this user could still move their account with survives.
        assert.strictEqual(
          yield* verifications.deleteByIdentifier(identifierOf(changeEmailVerifyPurpose, user.id)),
          0
        )
      }))

    it.effect("expires a hop, so a link that sat in a mailbox stops working", () =>
      AuthTest.freshClock(Effect.gen(function*() {
        const users = yield* Users
        const email = uniqueEmail("hop-expiry")
        const newEmail = uniqueEmail("hop-expiry-new")
        const { user } = yield* registerVerified(email)

        yield* users.requestEmailChange({ user, newEmail })
        const confirmation = yield* linkTo(AuthTest.changeEmailConfirmationKind, email)

        // The default `tokens.changeEmailTtl` is an hour.
        yield* TestClock.adjust(Duration.hours(2))
        const failure = yield* Effect.flip(users.confirmEmailChange(confirmation.token))
        assert.strictEqual(failure._tag, "InvalidToken")
      })))
  })

  // ---------------------------------------------------------------------------
  // requestDeletion, direct
  // ---------------------------------------------------------------------------

  describe("requestDeletion", () => {
    it.effect("deletes the account outright when the session is fresh", () =>
      Effect.gen(function*() {
        const users = yield* Users
        const store = yield* UserStore
        const sessions = yield* Sessions
        const verifications = yield* VerificationStore
        const passwords = yield* Passwords
        const email = uniqueEmail("delete-direct")
        const { session, user } = yield* register(email)

        // Something outstanding that must not outlive the row.
        yield* passwords.requestReset({ email })

        const { events, result } = yield* AuthTest.recordingEvents(users.requestDeletion({ user, session }))
        assert.strictEqual(result, "Deleted")

        assert.isTrue(Option.isNone(yield* store.findById(user.id)))
        // Sessions cascade with the row.
        assert.deepStrictEqual(yield* sessions.list(user.id), [])
        // And the reset link somebody could still have used is gone with it.
        assert.strictEqual(
          yield* verifications.deleteByIdentifier(identifierOf(passwordResetPurpose, user.id)),
          0
        )

        const published = forUser(events, user.id)
        assert.include(tagsOf(published), "UserDeleted")
        const deleted = published.find((event) => event._tag === "UserDeleted")
        assert.strictEqual(deleted?._tag === "UserDeleted" ? deleted.email : null, email)
      }))

    it.effect("refuses a stale session, and the account survives", () =>
      AuthTest.freshClock(Effect.gen(function*() {
        const users = yield* Users
        const store = yield* UserStore
        const email = uniqueEmail("delete-stale")
        const { session, user } = yield* register(email)

        // `session.freshAge` is a day by default; the session is older than that
        // and a stolen cookie must not be enough to destroy an account.
        yield* TestClock.adjust(Duration.days(2))
        const failure = yield* Effect.flip(users.requestDeletion({ user, session }))
        assert.strictEqual(failure._tag, "SessionNotFresh")

        assert.isTrue(Option.isSome(yield* store.findById(user.id)))
      })))

    it.effect("checks the password when one is offered", () =>
      Effect.gen(function*() {
        const users = yield* Users
        const store = yield* UserStore
        const { session, user } = yield* register(uniqueEmail("delete-password"))

        const wrong = yield* Effect.flip(
          users.requestDeletion({ user, session, password: Redacted.make("not the password") })
        )
        assert.strictEqual(wrong._tag, "InvalidCredentials")
        assert.isTrue(Option.isSome(yield* store.findById(user.id)))

        assert.strictEqual(
          yield* users.requestDeletion({ user, session, password: testPassword }),
          "Deleted"
        )
        assert.isTrue(Option.isNone(yield* store.findById(user.id)))
      }))
  })

  // ---------------------------------------------------------------------------
  // requestDeletion, confirmed by mail
  // ---------------------------------------------------------------------------

  it.layer(AuthTest.layer({ user: { deleteUser: { enabled: true, confirmByEmail: true } } }))(
    "with deletion confirmed by e-mail",
    (it) => {
      it.effect("mails a link and deletes nothing until it is followed", () =>
        Effect.gen(function*() {
          const users = yield* Users
          const store = yield* UserStore
          const email = uniqueEmail("delete-confirm")
          const { session, user } = yield* register(email)

          const outcome = yield* users.requestDeletion({ user, session, callbackURL: "/farewell" })
          assert.strictEqual(outcome, "ConfirmationSent")
          assert.isTrue(Option.isSome(yield* store.findById(user.id)))

          const link = yield* linkTo(AuthTest.deleteAccountKind, email)
          assert.include(link.url, "/auth/delete-user/callback")

          const { events, result } = yield* AuthTest.recordingEvents(
            users.confirmDeletion({ token: link.token, userId: user.id })
          )
          assert.strictEqual(result.redirectTo, "http://localhost:3000/farewell")
          assert.isTrue(Option.isNone(yield* store.findById(user.id)))
          assert.include(tagsOf(forUser(events, user.id)), "UserDeleted")
        }))

      it.effect("does not consult the session's age: the mailbox is the second factor", () =>
        AuthTest.freshClock(Effect.gen(function*() {
          const users = yield* Users
          const { session, user } = yield* register(uniqueEmail("delete-confirm-stale"))

          yield* TestClock.adjust(Duration.days(2))
          assert.strictEqual(yield* users.requestDeletion({ user, session }), "ConfirmationSent")
        })))

      it.effect("burns a link presented by the wrong person as well as refusing it", () =>
        Effect.gen(function*() {
          const users = yield* Users
          const store = yield* UserStore
          const owner = yield* register(uniqueEmail("delete-owner"))
          const stranger = yield* register(uniqueEmail("delete-stranger"))

          yield* users.requestDeletion({ user: owner.user, session: owner.session })
          const link = yield* linkTo(AuthTest.deleteAccountKind, owner.user.email)

          // Claimed before the owner is checked. Leaving it claimable would let
          // somebody who has read another person's mail park the link until they
          // had a session of their own.
          const refused = yield* Effect.flip(
            users.confirmDeletion({ token: link.token, userId: stranger.user.id })
          )
          assert.strictEqual(refused._tag, "InvalidToken")
          assert.isTrue(Option.isSome(yield* store.findById(owner.user.id)))
          assert.isTrue(Option.isSome(yield* store.findById(stranger.user.id)))

          // … and the owner cannot use it either: it is spent.
          const spent = yield* Effect.flip(
            users.confirmDeletion({ token: link.token, userId: owner.user.id })
          )
          assert.strictEqual(spent._tag, "InvalidToken")
        }))

      it.effect("replaces an outstanding deletion link rather than adding to it", () =>
        Effect.gen(function*() {
          const users = yield* Users
          const email = uniqueEmail("delete-twice")
          const { session, user } = yield* register(email)

          yield* users.requestDeletion({ user, session })
          yield* users.requestDeletion({ user, session })

          const sent = yield* mailTo(email)
          assert.strictEqual(sent.length, 2)
          const stale = yield* Effect.flip(users.confirmDeletion({ token: sent[0]!.token, userId: user.id }))
          assert.strictEqual(stale._tag, "InvalidToken")

          const done = yield* users.confirmDeletion({ token: sent[1]!.token, userId: user.id })
          // No callbackURL was asked for, so the browser goes to the deployment.
          assert.strictEqual(done.redirectTo, "http://localhost:3000")
        }))
    }
  )
})
