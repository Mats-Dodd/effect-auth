import { assert, describe, layer } from "@effect/vitest"
import { Duration, Effect, Option } from "effect"
import { TestClock } from "effect/testing"
import { Sessions } from "../../src/domain/Sessions.js"
import { AccountStore, UserStore } from "../../src/domain/Stores.js"
import { authenticatorsOf, Passkeys } from "../../src/passkeys/Passkeys.js"
import { PasskeyStore } from "../../src/passkeys/Store.js"
import * as PasskeysTest from "../../src/testing/PasskeysTest.js"
import * as AuthTest from "../../src/testing/TestLayer.js"
import { expectSome, signUpUser, uniqueEmail } from "../fixtures.js"

/** Registers one credential for a user, and hands back the authenticator that owns it. */
const enrol = Effect.fnUntraced(function* (
  email: string,
  options?: Parameters<typeof PasskeysTest.makeAuthenticator>[0]
) {
  const passkeys = yield* Passkeys
  const { user } = yield* signUpUser(email)
  const authenticator = yield* PasskeysTest.makeAuthenticator(options)
  const ceremony = yield* passkeys.registrationOptions({ user })
  const response = yield* authenticator.register(ceremony.options)
  const passkey = yield* passkeys.verifyRegistration({ user, handle: ceremony.handle, response, name: "laptop" })
  return { user, authenticator, passkey }
})

/** One authentication ceremony, start to finish. */
const signIn = Effect.fnUntraced(function* (
  authenticator: PasskeysTest.TestAuthenticator,
  overrides?: Parameters<PasskeysTest.TestAuthenticator["authenticate"]>[1]
) {
  const passkeys = yield* Passkeys
  const ceremony = yield* passkeys.authenticationOptions({ session: Option.none() })
  const response = yield* authenticator.authenticate(ceremony.options, overrides)
  return yield* passkeys.authenticate({
    handle: ceremony.handle,
    response,
    session: Option.none(),
    request: { ipAddress: null, userAgent: null }
  })
})

describe.sequential("passkeys/Passkeys", () => {
  layer(PasskeysTest.layer())("registration", (it) => {
    it.effect("stores what the authenticator reported", () =>
      Effect.gen(function* () {
        const { authenticator, passkey, user } = yield* enrol(uniqueEmail("register"))

        assert.strictEqual(passkey.userId, user.id)
        assert.strictEqual(passkey.credentialId, authenticator.credentialId)
        assert.strictEqual(passkey.name, "laptop")
        assert.isTrue(passkey.uvInitialised)
        assert.isFalse(passkey.backupEligible)
        assert.isFalse(passkey.backedUp)
        assert.deepStrictEqual(passkey.transports, ["internal"])
        assert.strictEqual(passkey.lastUsedAt, null)
        // A real COSE key came back, not a placeholder.
        assert.isTrue(passkey.publicKey.length > 32)
      })
    )

    it.effect("a second credential is offered the first in excludeCredentials", () =>
      Effect.gen(function* () {
        const passkeys = yield* Passkeys
        const { authenticator, user } = yield* enrol(uniqueEmail("exclude"))
        const ceremony = yield* passkeys.registrationOptions({ user })
        assert.deepStrictEqual(
          ceremony.options.excludeCredentials.map((descriptor) => descriptor.id),
          [authenticator.credentialId]
        )
        assert.strictEqual(ceremony.options.rp.id, PasskeysTest.testRpId)
        assert.strictEqual(ceremony.options.attestation, "none")
        assert.strictEqual(ceremony.options.authenticatorSelection.residentKey, "required")
      })
    )

    it.effect("the user handle is not the user id, and it is stable", () =>
      Effect.gen(function* () {
        const passkeys = yield* Passkeys
        const store = yield* PasskeyStore
        const { user } = yield* enrol(uniqueEmail("handle"))
        const again = yield* passkeys.registrationOptions({ user })
        const stored = yield* expectSome(yield* store.findHandle(user.id), "a handle should have been issued")

        assert.notStrictEqual(stored, user.id)
        assert.strictEqual(again.options.user.id, stored)
        // 32 random bytes, base64url.
        assert.strictEqual(stored.length, 43)
      })
    )

    it.effect("the same credential cannot be registered twice, here or elsewhere", () =>
      Effect.gen(function* () {
        const passkeys = yield* Passkeys
        const { authenticator } = yield* enrol(uniqueEmail("dup-owner"))
        const { user: other } = yield* signUpUser(uniqueEmail("dup-other"))

        const ceremony = yield* passkeys.registrationOptions({ user: other })
        const response = yield* authenticator.register(ceremony.options)
        const failure = yield* Effect.result(
          passkeys.verifyRegistration({ user: other, handle: ceremony.handle, response })
        )
        assert.strictEqual(failure._tag, "Failure")
        if (failure._tag !== "Failure") return
        assert.strictEqual(failure.failure._tag, "PasskeyVerificationFailed")
      })
    )

    it.effect("a registration handle cannot complete an authentication", () =>
      Effect.gen(function* () {
        const passkeys = yield* Passkeys
        const { authenticator, user } = yield* enrol(uniqueEmail("tag-registration"))
        const ceremony = yield* passkeys.registrationOptions({ user })
        const auth = yield* passkeys.authenticationOptions({ session: Option.none() })
        // The response is honest; the handle names a *registration* row.
        const response = yield* authenticator.authenticate(auth.options, { challenge: ceremony.options.challenge })

        const failure = yield* Effect.result(
          passkeys.verifyAuthentication({ handle: ceremony.handle, response, session: Option.none() })
        )
        assert.strictEqual(failure._tag, "Failure")
        if (failure._tag !== "Failure") return
        assert.strictEqual(failure.failure._tag, "PasskeyVerificationFailed")
      })
    )

    it.effect("an authentication handle cannot complete a registration", () =>
      Effect.gen(function* () {
        const passkeys = yield* Passkeys
        const { user } = yield* signUpUser(uniqueEmail("tag-authentication"))
        const authenticator = yield* PasskeysTest.makeAuthenticator()
        const registration = yield* passkeys.registrationOptions({ user })
        const auth = yield* passkeys.authenticationOptions({ session: Option.none() })
        const response = yield* authenticator.register(registration.options, {
          challenge: auth.options.challenge
        })

        const failure = yield* Effect.result(passkeys.verifyRegistration({ user, handle: auth.handle, response }))
        assert.strictEqual(failure._tag, "Failure")
        if (failure._tag !== "Failure") return
        assert.strictEqual(failure.failure._tag, "PasskeyVerificationFailed")
      })
    )

    it.effect("a ceremony minted for one person cannot be finished by another", () =>
      Effect.gen(function* () {
        const passkeys = yield* Passkeys
        const { user: owner } = yield* signUpUser(uniqueEmail("bound-owner"))
        const { user: other } = yield* signUpUser(uniqueEmail("bound-other"))
        const authenticator = yield* PasskeysTest.makeAuthenticator()
        const ceremony = yield* passkeys.registrationOptions({ user: owner })
        const response = yield* authenticator.register(ceremony.options)

        const failure = yield* Effect.result(
          passkeys.verifyRegistration({ user: other, handle: ceremony.handle, response })
        )
        assert.strictEqual(failure._tag, "Failure")
        if (failure._tag !== "Failure") return
        assert.strictEqual(failure.failure._tag, "PasskeyVerificationFailed")
      })
    )

    it.effect("the wrong origin is refused", () =>
      Effect.gen(function* () {
        const passkeys = yield* Passkeys
        const { user } = yield* signUpUser(uniqueEmail("origin"))
        const authenticator = yield* PasskeysTest.makeAuthenticator()
        const ceremony = yield* passkeys.registrationOptions({ user })
        const response = yield* authenticator.register(ceremony.options, { origin: "https://evil.example" })

        const failure = yield* Effect.result(passkeys.verifyRegistration({ user, handle: ceremony.handle, response }))
        assert.strictEqual(failure._tag, "Failure")
        if (failure._tag !== "Failure") return
        assert.strictEqual(failure.failure._tag, "PasskeyVerificationFailed")
      })
    )

    it.effect("the wrong rp id is refused", () =>
      Effect.gen(function* () {
        const passkeys = yield* Passkeys
        const { user } = yield* signUpUser(uniqueEmail("rpid"))
        const authenticator = yield* PasskeysTest.makeAuthenticator()
        const ceremony = yield* passkeys.registrationOptions({ user })
        const response = yield* authenticator.register(ceremony.options, { rpId: "evil.example" })

        const failure = yield* Effect.result(passkeys.verifyRegistration({ user, handle: ceremony.handle, response }))
        assert.strictEqual(failure._tag, "Failure")
        if (failure._tag !== "Failure") return
        assert.strictEqual(failure.failure._tag, "PasskeyVerificationFailed")
      })
    )

    it.effect("a challenge is single-use", () =>
      Effect.gen(function* () {
        const passkeys = yield* Passkeys
        const { user } = yield* signUpUser(uniqueEmail("single-use"))
        const authenticator = yield* PasskeysTest.makeAuthenticator()
        const ceremony = yield* passkeys.registrationOptions({ user })
        const response = yield* authenticator.register(ceremony.options)

        yield* passkeys.verifyRegistration({ user, handle: ceremony.handle, response })
        const replayed = yield* Effect.result(passkeys.verifyRegistration({ user, handle: ceremony.handle, response }))
        assert.strictEqual(replayed._tag, "Failure")
        if (replayed._tag !== "Failure") return
        assert.strictEqual(replayed.failure._tag, "ChallengeExpired")
      })
    )

    it.effect("a challenge expires", () =>
      AuthTest.freshClock(
        Effect.gen(function* () {
          const passkeys = yield* Passkeys
          const { user } = yield* signUpUser(uniqueEmail("expiry"))
          const authenticator = yield* PasskeysTest.makeAuthenticator()
          const ceremony = yield* passkeys.registrationOptions({ user })
          const response = yield* authenticator.register(ceremony.options)

          yield* TestClock.adjust(Duration.minutes(6))
          const failure = yield* Effect.result(passkeys.verifyRegistration({ user, handle: ceremony.handle, response }))
          assert.strictEqual(failure._tag, "Failure")
          if (failure._tag !== "Failure") return
          assert.strictEqual(failure.failure._tag, "ChallengeExpired")
        })
      )
    )
  })

  layer(PasskeysTest.layer())("authentication", (it) => {
    it.effect("a user-verified passkey signs in and reaches aal2 in one ceremony", () =>
      Effect.gen(function* () {
        const email = uniqueEmail("uv-signin")
        const { authenticator, user } = yield* enrol(email)
        const { events, result } = yield* AuthTest.recordingEvents(signIn(authenticator))

        assert.strictEqual(result._tag, "SignedIn")
        if (result._tag !== "SignedIn" || result.result._tag !== "Complete") {
          return assert.fail("expected a completed sign-in")
        }
        assert.strictEqual(result.result.user.id, user.id)
        assert.strictEqual(result.result.session.aal, "aal2")
        assert.deepStrictEqual(
          result.result.session.methods.map((entry) => entry.method),
          ["passkey"]
        )
        assert.strictEqual(result.result.session.methods[0]?.factor, "inherence")
        assert.isTrue(result.result.session.methods[0]?.phishingResistant)
        assert.strictEqual(result.result.session.methods[0]?.userVerified, true)

        const signedIn = events.find((event) => event._tag === "SignedIn")
        assert.isDefined(signedIn)
        if (signedIn?._tag !== "SignedIn") return
        assert.strictEqual(signedIn.method, "passkeys")
      })
    )

    it.effect("a passkey that did not verify the person is one factor", () =>
      Effect.gen(function* () {
        const { authenticator } = yield* enrol(uniqueEmail("no-uv"), { userVerified: false })
        const result = yield* signIn(authenticator)
        if (result._tag !== "SignedIn" || result.result._tag !== "Complete") {
          return assert.fail("expected a completed sign-in")
        }
        assert.strictEqual(result.result.session.aal, "aal1")
        assert.strictEqual(result.result.session.methods[0]?.factor, "possession")
        assert.strictEqual(result.result.session.methods[0]?.userVerified, false)
      })
    )

    it.effect("records the ceremony on the credential", () =>
      Effect.gen(function* () {
        const store = yield* PasskeyStore
        const { authenticator, passkey } = yield* enrol(uniqueEmail("record"), { signCount: 5 })
        yield* signIn(authenticator)
        const after = yield* expectSome(
          yield* store.findByCredentialId(authenticator.credentialId),
          "the credential should still be there"
        )
        assert.notStrictEqual(after.lastUsedAt, null)
        assert.isTrue(after.signCount > passkey.signCount)
      })
    )

    it.effect("a discoverable sign-in must present the handle this deployment issued", () =>
      Effect.gen(function* () {
        const store = yield* PasskeyStore
        const { authenticator, user } = yield* enrol(uniqueEmail("handle-check"))
        const handle = yield* expectSome(yield* store.findHandle(user.id), "issued")

        // The right one is accepted…
        const accepted = yield* signIn(authenticator, { userHandle: handle })
        assert.strictEqual(accepted._tag, "SignedIn")

        // …and one this deployment never issued is not.
        const refused = yield* Effect.result(
          signIn(authenticator, { userHandle: "not-a-handle-this-deployment-issued" })
        )
        assert.strictEqual(refused._tag, "Failure")
        if (refused._tag !== "Failure") return
        assert.strictEqual(refused.failure._tag, "PasskeyVerificationFailed")
      })
    )

    it.effect("an unknown credential is refused", () =>
      Effect.gen(function* () {
        const stranger = yield* PasskeysTest.makeAuthenticator()
        const refused = yield* Effect.result(signIn(stranger))
        assert.strictEqual(refused._tag, "Failure")
        if (refused._tag !== "Failure") return
        assert.strictEqual(refused.failure._tag, "PasskeyVerificationFailed")
      })
    )

    it.effect("a ceremony bound to a session refuses another person's credential", () =>
      Effect.gen(function* () {
        const passkeys = yield* Passkeys
        const { authenticator } = yield* enrol(uniqueEmail("bound-credential"))
        const { session } = yield* signUpUser(uniqueEmail("bound-session"))

        const ceremony = yield* passkeys.authenticationOptions({ session: Option.some(session) })
        const response = yield* authenticator.authenticate(ceremony.options)
        const refused = yield* Effect.result(
          passkeys.verifyAuthentication({ handle: ceremony.handle, response, session: Option.some(session) })
        )
        assert.strictEqual(refused._tag, "Failure")
        if (refused._tag !== "Failure") return
        assert.strictEqual(refused.failure._tag, "PasskeyVerificationFailed")
      })
    )

    it.effect("a person's own session is raised in place rather than replaced", () =>
      Effect.gen(function* () {
        const passkeys = yield* Passkeys
        const sessions = yield* Sessions
        const email = uniqueEmail("elevate")
        const { authenticator, user } = yield* enrol(email)
        const open = yield* sessions.list(user.id)
        const before = open[0]
        if (before === undefined) return assert.fail("sign-up should have left a session")
        assert.strictEqual(before.aal, "aal1")

        const ceremony = yield* passkeys.authenticationOptions({ session: Option.some(before) })
        const response = yield* authenticator.authenticate(ceremony.options)
        const outcome = yield* passkeys.authenticate({
          handle: ceremony.handle,
          response,
          session: Option.some(before),
          request: { ipAddress: null, userAgent: null }
        })

        assert.strictEqual(outcome._tag, "Elevated")
        if (outcome._tag !== "Elevated") return
        // The id survives — open tabs and the session list do too.
        assert.strictEqual(outcome.session.id, before.id)
        // Knowledge plus a user-verified passkey is two factors either way.
        assert.strictEqual(outcome.session.aal, "aal2")
        assert.deepStrictEqual(
          outcome.session.methods.map((entry) => entry.method),
          ["password", "passkey"]
        )
        // One session, not two.
        assert.strictEqual((yield* sessions.list(user.id)).length, 1)
      })
    )

    it.effect("a session belonging to somebody else is not elevated, and is not a merge", () =>
      Effect.gen(function* () {
        const passkeys = yield* Passkeys
        const { authenticator, user } = yield* enrol(uniqueEmail("other-session"))
        const { session: strangers } = yield* signUpUser(uniqueEmail("other-holder"))

        // The ceremony is unbound, so the credential decides who signs in.
        const ceremony = yield* passkeys.authenticationOptions({ session: Option.none() })
        const response = yield* authenticator.authenticate(ceremony.options)
        const outcome = yield* passkeys.authenticate({
          handle: ceremony.handle,
          response,
          session: Option.some(strangers),
          request: { ipAddress: null, userAgent: null }
        })

        assert.strictEqual(outcome._tag, "SignedIn")
        if (outcome._tag !== "SignedIn" || outcome.result._tag !== "Complete") return
        assert.strictEqual(outcome.result.user.id, user.id)
        assert.notStrictEqual(outcome.result.session.id, strangers.id)
      })
    )
  })

  layer(PasskeysTest.layer())("option documents", (it) => {
    it.effect("an address with no account is answered with plausible decoys", () =>
      Effect.gen(function* () {
        const passkeys = yield* Passkeys
        const unknown = uniqueEmail("nobody")
        const first = yield* passkeys.authenticationOptions({ session: Option.none(), email: unknown })
        const second = yield* passkeys.authenticationOptions({ session: Option.none(), email: unknown })

        assert.isTrue(first.options.allowCredentials.length > 0)
        // Deterministic: asking twice must not be a way to tell a decoy from a
        // real credential.
        assert.deepStrictEqual(
          first.options.allowCredentials.map((descriptor) => descriptor.id),
          second.options.allowCredentials.map((descriptor) => descriptor.id)
        )
        // …and a different address gets different ones.
        const elsewhere = yield* passkeys.authenticationOptions({
          session: Option.none(),
          email: uniqueEmail("nobody-else")
        })
        assert.notDeepEqual(
          first.options.allowCredentials.map((descriptor) => descriptor.id),
          elsewhere.options.allowCredentials.map((descriptor) => descriptor.id)
        )
      })
    )

    it.effect("an address with an account is answered with its real credentials", () =>
      Effect.gen(function* () {
        const passkeys = yield* Passkeys
        const email = uniqueEmail("scoped")
        const { authenticator } = yield* enrol(email)
        const scoped = yield* passkeys.authenticationOptions({ session: Option.none(), email })
        assert.deepStrictEqual(
          scoped.options.allowCredentials.map((descriptor) => descriptor.id),
          [authenticator.credentialId]
        )
      })
    )

    it.effect("no address at all is the discoverable flow: an empty list", () =>
      Effect.gen(function* () {
        const passkeys = yield* Passkeys
        const ceremony = yield* passkeys.authenticationOptions({ session: Option.none() })
        assert.deepStrictEqual(ceremony.options.allowCredentials, [])
        assert.strictEqual(ceremony.options.rpId, PasskeysTest.testRpId)
      })
    )
  })

  layer(PasskeysTest.layer())("management and the authenticators seam", (it) => {
    it.effect("ownership is in the statement, not in a check", () =>
      Effect.gen(function* () {
        const passkeys = yield* Passkeys
        const { passkey } = yield* enrol(uniqueEmail("owner"))
        const { user: stranger } = yield* signUpUser(uniqueEmail("stranger"))

        assert.isTrue(Option.isNone(yield* passkeys.rename(stranger.id, passkey.id, "mine now")))
        assert.isFalse(yield* passkeys.remove(stranger.id, passkey.id))
        // Still there, still called what its owner called it.
        const listed = yield* passkeys.list(passkey.userId)
        assert.strictEqual(listed.length, 1)
        assert.strictEqual(listed[0]?.name, "laptop")
      })
    )

    it.effect("the owner may rename and remove", () =>
      Effect.gen(function* () {
        const passkeys = yield* Passkeys
        const { passkey, user } = yield* enrol(uniqueEmail("manage"))

        const renamed = yield* expectSome(yield* passkeys.rename(user.id, passkey.id, "phone"), "the owner may rename")
        assert.strictEqual(renamed.name, "phone")
        assert.isTrue(yield* passkeys.remove(user.id, passkey.id))
        assert.deepStrictEqual(yield* passkeys.list(user.id), [])
      })
    )

    it.effect("contributes to the Authenticators seam", () =>
      Effect.gen(function* () {
        // Built from the store the deployment installed it over: reading the
        // reference here would answer the *test's* own context, which is above
        // the deployment the contribution was provided under.
        const seam = authenticatorsOf(yield* PasskeyStore)
        const { passkey, user } = yield* enrol(uniqueEmail("seam"))
        const listed = yield* seam.list === undefined ? Effect.succeed([]) : seam.list(user.id)

        assert.strictEqual(listed.length, 1)
        assert.strictEqual(listed[0]?.type, "passkey")
        assert.strictEqual(listed[0]?.id, passkey.id)
        assert.isTrue(listed[0]?.signIn)
        assert.isTrue(listed[0]?.secondFactor)
        assert.isFalse(listed[0]?.restricted)

        const revoked = yield* seam.revokeAll === undefined ? Effect.succeed(0) : seam.revokeAll(user.id)
        assert.strictEqual(revoked, 1)
      })
    )

    it.effect("a deleted user takes their credentials with them", () =>
      Effect.gen(function* () {
        const users = yield* UserStore
        const store = yield* PasskeyStore
        const { authenticator, user } = yield* enrol(uniqueEmail("cascade"))

        assert.isTrue(yield* users.delete(user.id))
        assert.isTrue(Option.isNone(yield* store.findByCredentialId(authenticator.credentialId)))
      })
    )
  })

  layer(PasskeysTest.layer())("the signature counter", (it) => {
    it.effect("two zeroes are a synced passkey, not a clone", () =>
      Effect.gen(function* () {
        // The authenticator starts at zero and stays there.
        const { authenticator } = yield* enrol(uniqueEmail("synced"), { signCount: 0 })
        const first = yield* signIn(authenticator)
        const second = yield* signIn(authenticator)
        assert.strictEqual(first._tag, "SignedIn")
        assert.strictEqual(second._tag, "SignedIn")
      })
    )

    it.effect("a regression is published and, by default, allowed", () =>
      Effect.gen(function* () {
        const { authenticator, user } = yield* enrol(uniqueEmail("regress"), { signCount: 10 })
        yield* signIn(authenticator)
        const { events, result } = yield* AuthTest.recordingEvents(signIn(authenticator, { signCount: 1 }))

        assert.strictEqual(result._tag, "SignedIn")
        const regression = events.find(
          (event) => event._tag === "PluginEvent" && event.event === "PasskeyCounterRegression"
        )
        assert.isDefined(regression)
        if (regression?._tag !== "PluginEvent") return
        assert.strictEqual(regression.plugin, "passkeys")
        assert.strictEqual(regression.userId, user.id)
        assert.strictEqual(regression.data["rejected"], false)
        // No secret in it: an id and two numbers.
        assert.deepStrictEqual(Object.keys(regression.data).sort(), [
          "passkeyId",
          "presentedSignCount",
          "rejected",
          "storedSignCount"
        ])
      })
    )

    it.effect("a tolerated regression keeps the high-water mark, so the clone keeps announcing itself", () =>
      Effect.gen(function* () {
        const store = yield* PasskeyStore
        const { authenticator } = yield* enrol(uniqueEmail("regress-mark"), { signCount: 10 })
        yield* signIn(authenticator)

        yield* signIn(authenticator, { signCount: 1 })

        // The stored counter did NOT follow the low value down. Had it, the
        // real device's next ceremony (11 > 1) and the clone's next one
        // (2 > 1) would both have looked clean, and the deployment watching
        // for the alternation would have seen one event and then nothing.
        const stored = yield* expectSome(
          yield* store.findByCredentialId(authenticator.credentialId),
          "the credential should still be there"
        )
        assert.strictEqual(stored.signCount, 12)

        const { events } = yield* AuthTest.recordingEvents(signIn(authenticator, { signCount: 2 }))
        assert.isDefined(
          events.find((event) => event._tag === "PluginEvent" && event.event === "PasskeyCounterRegression")
        )
      })
    )
  })

  layer(PasskeysTest.layer())("removing a credential", (it) => {
    it.effect("refuses to take the last way into the account away", () =>
      Effect.gen(function* () {
        const accounts = yield* AccountStore
        const { user, passkey } = yield* enrol(uniqueEmail("last-way-in"))
        // A passwordless account: the credential row goes, and the passkey is
        // the only thing left to present.
        for (const account of yield* accounts.listByUserId(user.id)) {
          yield* accounts.deleteById(account.id, user.id)
        }

        const passkeys = yield* Passkeys
        const refused = yield* Effect.flip(passkeys.remove(user.id, passkey.id))

        // `Accounts.unlink` counts a passkey as a way in; this is the other
        // half of that sum. Without it the flagship passwordless account can
        // delete its only credential and is locked out with nothing to present.
        assert.strictEqual(refused._tag, "CannotRemoveLastAuthenticator")
        assert.strictEqual((yield* passkeys.list(user.id)).length, 1)
      })
    )

    it.effect("allows it when a password is left behind", () =>
      Effect.gen(function* () {
        const { user, passkey } = yield* enrol(uniqueEmail("last-with-password"))
        const passkeys = yield* Passkeys

        assert.isTrue(yield* passkeys.remove(user.id, passkey.id))
        assert.deepStrictEqual(yield* passkeys.list(user.id), [])
      })
    )

    it.effect("allows it when another passkey is left behind", () =>
      Effect.gen(function* () {
        const accounts = yield* AccountStore
        const passkeys = yield* Passkeys
        const { user, passkey } = yield* enrol(uniqueEmail("last-of-two"))
        const second = yield* PasskeysTest.makeAuthenticator()
        const ceremony = yield* passkeys.registrationOptions({ user })
        yield* passkeys.verifyRegistration({
          user,
          handle: ceremony.handle,
          response: yield* second.register(ceremony.options)
        })
        for (const account of yield* accounts.listByUserId(user.id)) {
          yield* accounts.deleteById(account.id, user.id)
        }

        assert.isTrue(yield* passkeys.remove(user.id, passkey.id))
        assert.strictEqual((yield* passkeys.list(user.id)).length, 1)
      })
    )
  })

  layer(PasskeysTest.layer({ passkeys: { rejectCounterRegression: true } }))("a strict deployment", (it) => {
    it.effect("refuses a counter that went backwards", () =>
      Effect.gen(function* () {
        const { authenticator } = yield* enrol(uniqueEmail("strict"), { signCount: 10 })
        yield* signIn(authenticator)
        const refused = yield* Effect.result(signIn(authenticator, { signCount: 2 }))
        assert.strictEqual(refused._tag, "Failure")
        if (refused._tag !== "Failure") return
        assert.strictEqual(refused.failure._tag, "PasskeyVerificationFailed")
      })
    )
  })

  layer(PasskeysTest.layer({ passkeys: { userVerification: "required" } }))("a deployment requiring UV", (it) => {
    it.effect("refuses an authenticator that did not verify the person", () =>
      Effect.gen(function* () {
        const passkeys = yield* Passkeys
        const { user } = yield* signUpUser(uniqueEmail("uv-required"))
        const authenticator = yield* PasskeysTest.makeAuthenticator({ userVerified: false })
        const ceremony = yield* passkeys.registrationOptions({ user })
        assert.strictEqual(ceremony.options.authenticatorSelection.userVerification, "required")
        const response = yield* authenticator.register(ceremony.options)

        const refused = yield* Effect.result(passkeys.verifyRegistration({ user, handle: ceremony.handle, response }))
        assert.strictEqual(refused._tag, "Failure")
        if (refused._tag !== "Failure") return
        assert.strictEqual(refused.failure._tag, "PasskeyVerificationFailed")
      })
    )
  })
})
