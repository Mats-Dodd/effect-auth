import { assert, describe, layer } from "@effect/vitest"
import { Duration, Effect, Option, Redacted } from "effect"
import { TestClock } from "effect/testing"
import { SqlClient } from "effect/unstable/sql"
import { Sessions } from "../../src/domain/Sessions.js"
import type { User } from "../../src/domain/Schema.js"
import type { PhoneService } from "../../src/phone/index.js"
import { makeConfig, Phone } from "../../src/phone/index.js"
import { PhoneStore } from "../../src/phone/Store.js"
import * as PhoneTest from "../../src/testing/PhoneTest.js"
import { TestEmails } from "../../src/testing/TestEmails.js"
import * as AuthTest from "../../src/testing/TestLayer.js"
import { expectSome, forUser, signUpUser, uniqueEmail } from "../fixtures.js"

/** A number no other test in this file uses. */
let counter = 0
const uniqueNumber = (): string => `+1555${String(1000000 + counter++)}`

/** The deployment every test that means to send anything runs on. */
const allowed = { phone: { allowedCountries: ["1"], signIn: true } }

/** Attaches a number to a user the whole way, and answers the row. */
const attach = Effect.fnUntraced(function* (phone: PhoneService, user: User, number: string) {
  const issued = yield* phone.sendVerification({ user, phoneNumber: number })
  const code = yield* PhoneTest.codeFor(number)
  return yield* phone.verify({ user, handle: issued.handle, code: Redacted.make(code) })
})

/** Strips the proof off a stored row, leaving the claim behind. */
const unverify = (number: string) =>
  Effect.flatMap(
    SqlClient.SqlClient,
    (sql) => sql`UPDATE effect_auth_phone_numbers SET verified_at = NULL WHERE phone_e164 = ${number}`
  )

describe.sequential("phone/Phone", () => {
  layer(PhoneTest.layer(allowed))("attaching a number", (it) => {
    it.effect("sends a code and attaches the number when it is answered", () =>
      Effect.gen(function* () {
        const phone = yield* Phone
        const store = yield* PhoneStore
        const number = uniqueNumber()
        const { user } = yield* signUpUser(uniqueEmail("attach"))

        const issued = yield* phone.sendVerification({ user, phoneNumber: number })
        const code = yield* PhoneTest.codeFor(number)
        const attached = yield* phone.verify({ user, handle: issued.handle, code: Redacted.make(code) })
        assert.strictEqual(attached.phoneE164, number)

        const row = yield* expectSome(yield* store.findByUserId(user.id), "the number should be stored")
        assert.strictEqual(row.phoneE164, number)
        assert.isNotNull(row.verifiedAt)
      })
    )

    it.effect("the code goes to the number and the handle does not", () =>
      Effect.gen(function* () {
        const phone = yield* Phone
        const emails = yield* TestEmails
        const number = uniqueNumber()
        const { user } = yield* signUpUser(uniqueEmail("handle-not-sent"))

        const issued = yield* phone.sendVerification({ user, phoneNumber: number })
        const sent = yield* emails.to(number)
        assert.strictEqual(sent.length, 1)
        assert.strictEqual(sent[0]?.kind, PhoneTest.smsKind)
        const body = Redacted.value(sent[0]!.token)
        assert.include(body, yield* PhoneTest.codeFor(number))
        assert.notInclude(body, Redacted.value(issued.handle))
      })
    )

    it.effect("stores the canonical form whatever spelling was typed", () =>
      Effect.gen(function* () {
        const phone = yield* Phone
        const store = yield* PhoneStore
        const number = uniqueNumber()
        const spelled = `+1 (${number.slice(2, 5)}) ${number.slice(5, 8)}-${number.slice(8)}`
        const { user } = yield* signUpUser(uniqueEmail("canonical"))

        const issued = yield* phone.sendVerification({ user, phoneNumber: spelled })
        yield* phone.verify({
          user,
          handle: issued.handle,
          code: Redacted.make(yield* PhoneTest.codeFor(number))
        })

        const row = yield* expectSome(yield* store.findByUserId(user.id), "the number should be stored")
        assert.strictEqual(row.phoneE164, number)
        assert.isTrue(Option.isSome(yield* store.findByPhone(number)))
      })
    )

    it.effect("refuses a number that is not E.164, before anything is sent", () =>
      Effect.gen(function* () {
        const phone = yield* Phone
        const emails = yield* TestEmails
        const { user } = yield* signUpUser(uniqueEmail("malformed"))

        const outcome = yield* Effect.result(phone.sendVerification({ user, phoneNumber: "555-0100" }))
        assert.strictEqual(outcome._tag, "Failure")
        if (outcome._tag === "Failure") assert.strictEqual(outcome.failure._tag, "InvalidPhoneNumber")
        assert.deepStrictEqual(yield* emails.to("555-0100"), [])
      })
    )

    it.effect("a wrong code costs an attempt and leaves the same handle usable", () =>
      Effect.gen(function* () {
        const phone = yield* Phone
        const number = uniqueNumber()
        const { user } = yield* signUpUser(uniqueEmail("wrong-code"))

        const issued = yield* phone.sendVerification({ user, phoneNumber: number })
        const code = yield* PhoneTest.codeFor(number)

        const wrong = yield* Effect.result(phone.verify({ user, handle: issued.handle, code: Redacted.make("000000") }))
        assert.strictEqual(wrong._tag, "Failure")
        if (wrong._tag === "Failure") assert.strictEqual(wrong.failure._tag, "InvalidCode")

        const attached = yield* phone.verify({ user, handle: issued.handle, code: Redacted.make(code) })
        assert.strictEqual(attached.phoneE164, number)
      })
    )

    it.effect("a code is single use", () =>
      Effect.gen(function* () {
        const phone = yield* Phone
        const number = uniqueNumber()
        const { user } = yield* signUpUser(uniqueEmail("single-use"))

        const issued = yield* phone.sendVerification({ user, phoneNumber: number })
        const code = Redacted.make(yield* PhoneTest.codeFor(number))

        yield* phone.verify({ user, handle: issued.handle, code })
        const again = yield* Effect.result(phone.verify({ user, handle: issued.handle, code }))
        assert.strictEqual(again._tag, "Failure")
        if (again._tag === "Failure") assert.strictEqual(again.failure._tag, "InvalidCode")
      })
    )

    it.effect("somebody else's handle attaches nothing", () =>
      Effect.gen(function* () {
        const phone = yield* Phone
        const store = yield* PhoneStore
        const number = uniqueNumber()
        const { user: owner } = yield* signUpUser(uniqueEmail("handle-owner"))
        const { user: thief } = yield* signUpUser(uniqueEmail("handle-thief"))

        const issued = yield* phone.sendVerification({ user: owner, phoneNumber: number })
        const code = Redacted.make(yield* PhoneTest.codeFor(number))

        const stolen = yield* Effect.result(phone.verify({ user: thief, handle: issued.handle, code }))
        assert.strictEqual(stolen._tag, "Failure")
        if (stolen._tag === "Failure") assert.strictEqual(stolen.failure._tag, "InvalidCode")
        assert.isTrue(Option.isNone(yield* store.findByUserId(thief.id)))
      })
    )

    it.effect("a verification code cannot answer a step-up challenge", () =>
      Effect.gen(function* () {
        const phone = yield* Phone
        const number = uniqueNumber()
        const { user, session } = yield* signUpUser(uniqueEmail("cross-purpose"))
        yield* attach(phone, user, number)

        const issued = yield* phone.sendVerification({ user, phoneNumber: number })
        const code = Redacted.make(yield* PhoneTest.codeFor(number))

        const crossed = yield* Effect.result(phone.completeStepUp({ user, session, handle: issued.handle, code }))
        assert.strictEqual(crossed._tag, "Failure")
        if (crossed._tag === "Failure") assert.strictEqual(crossed.failure._tag, "InvalidCode")
      })
    )

    it.effect("a number another account holds is refused only after the code was right", () =>
      Effect.gen(function* () {
        const phone = yield* Phone
        const number = uniqueNumber()
        const { user: first } = yield* signUpUser(uniqueEmail("in-use-first"))
        const { user: second } = yield* signUpUser(uniqueEmail("in-use-second"))
        yield* attach(phone, first, number)

        // The ask is answered exactly as any other ask is: nothing here says the
        // number is taken.
        const issued = yield* phone.sendVerification({ user: second, phoneNumber: number })
        const wrong = yield* Effect.result(
          phone.verify({ user: second, handle: issued.handle, code: Redacted.make("000000") })
        )
        assert.strictEqual(wrong._tag, "Failure")
        if (wrong._tag === "Failure") assert.strictEqual(wrong.failure._tag, "InvalidCode")

        const taken = yield* Effect.result(
          phone.verify({
            user: second,
            handle: issued.handle,
            code: Redacted.make(yield* PhoneTest.codeFor(number))
          })
        )
        assert.strictEqual(taken._tag, "Failure")
        if (taken._tag === "Failure") assert.strictEqual(taken.failure._tag, "PhoneAlreadyInUse")
      })
    )

    it.effect("attaching a second number replaces the first", () =>
      Effect.gen(function* () {
        const phone = yield* Phone
        const store = yield* PhoneStore
        const first = uniqueNumber()
        const second = uniqueNumber()
        const { user } = yield* signUpUser(uniqueEmail("replace"))

        yield* attach(phone, user, first)
        yield* attach(phone, user, second)

        const row = yield* expectSome(yield* store.findByUserId(user.id), "a number should be stored")
        assert.strictEqual(row.phoneE164, second)
        assert.isTrue(Option.isNone(yield* store.findByPhone(first)))
      })
    )

    it.effect("removing detaches the number, twice over", () =>
      Effect.gen(function* () {
        const phone = yield* Phone
        const store = yield* PhoneStore
        const number = uniqueNumber()
        const { user } = yield* signUpUser(uniqueEmail("remove"))
        yield* attach(phone, user, number)

        assert.strictEqual(yield* phone.remove({ user }), 1)
        assert.isTrue(Option.isNone(yield* store.findByUserId(user.id)))
        assert.strictEqual(yield* phone.remove({ user }), 0)
      })
    )

    it.effect("publishes an issued event and a verified event, with no number in either", () =>
      Effect.gen(function* () {
        const number = uniqueNumber()
        const { user } = yield* signUpUser(uniqueEmail("events"))

        const recorded = yield* AuthTest.recordingEvents(
          Effect.gen(function* () {
            const phone = yield* Phone
            yield* attach(phone, user, number)
          })
        )

        const plugin = forUser(recorded.events, user.id).filter((event) => event._tag === "PluginEvent")
        assert.deepStrictEqual(
          plugin.map((event) => (event._tag === "PluginEvent" ? event.event : "")),
          ["PhoneOtpIssued", "PhoneOtpVerified"]
        )
        assert.isFalse(JSON.stringify(plugin).includes(number))
      })
    )
  })

  layer(PhoneTest.layer(allowed))("signing in", (it) => {
    it.effect("signs in the account that holds the number, recording restricted evidence", () =>
      Effect.gen(function* () {
        const phone = yield* Phone
        const number = uniqueNumber()
        const { user } = yield* signUpUser(uniqueEmail("sign-in"))
        yield* attach(phone, user, number)

        const issued = yield* phone.sendSignIn({ phoneNumber: number })
        const result = yield* phone.completeSignIn({
          handle: issued.handle,
          code: Redacted.make(yield* PhoneTest.codeFor(number))
        })

        assert.strictEqual(result._tag, "Complete")
        if (result._tag !== "Complete") return
        assert.strictEqual(result.user.id, user.id)
        // One restricted possession factor on its own is aal1, never aal2.
        assert.strictEqual(result.session.aal, "aal1")
        assert.deepStrictEqual(
          result.session.methods.map((method) => ({
            method: method.method,
            factor: method.factor,
            restricted: method.restricted,
            phishingResistant: method.phishingResistant
          })),
          [{ method: "sms", factor: "possession", restricted: true, phishingResistant: false }]
        )
      })
    )

    it.effect("answers a number nobody holds identically, and sends it nothing", () =>
      Effect.gen(function* () {
        const phone = yield* Phone
        const emails = yield* TestEmails
        const stranger = uniqueNumber()

        const issued = yield* phone.sendSignIn({ phoneNumber: stranger })
        // A challenge exists — the write cost is the same — but no message went.
        assert.deepStrictEqual(yield* emails.to(stranger), [])

        const outcome = yield* Effect.result(
          phone.completeSignIn({ handle: issued.handle, code: Redacted.make("000000") })
        )
        assert.strictEqual(outcome._tag, "Failure")
        if (outcome._tag === "Failure") assert.strictEqual(outcome.failure._tag, "InvalidCode")
      })
    )

    it.effect("an unverified row is not a way in", () =>
      Effect.gen(function* () {
        const phone = yield* Phone
        const number = uniqueNumber()
        const { user } = yield* signUpUser(uniqueEmail("unverified"))
        yield* attach(phone, user, number)
        yield* Effect.orDie(unverify(number))

        const emails = yield* TestEmails
        const before = (yield* emails.to(number)).length
        const issued = yield* phone.sendSignIn({ phoneNumber: number })
        // Nothing new was sent: an unproved row names nobody to sign in.
        assert.strictEqual((yield* emails.to(number)).length, before)

        const outcome = yield* Effect.result(
          phone.completeSignIn({ handle: issued.handle, code: Redacted.make("000000") })
        )
        assert.strictEqual(outcome._tag, "Failure")
        if (outcome._tag === "Failure") assert.strictEqual(outcome.failure._tag, "InvalidCode")
      })
    )

    it.effect("a sign-in code cannot attach a number", () =>
      Effect.gen(function* () {
        const phone = yield* Phone
        const number = uniqueNumber()
        const { user } = yield* signUpUser(uniqueEmail("no-cross"))
        yield* attach(phone, user, number)

        const issued = yield* phone.sendSignIn({ phoneNumber: number })
        const crossed = yield* Effect.result(
          phone.verify({
            user,
            handle: issued.handle,
            code: Redacted.make(yield* PhoneTest.codeFor(number))
          })
        )
        assert.strictEqual(crossed._tag, "Failure")
        if (crossed._tag === "Failure") assert.strictEqual(crossed.failure._tag, "InvalidCode")
      })
    )
  })

  layer(PhoneTest.layer(allowed))("raising a session", (it) => {
    it.effect("appends the evidence, re-derives the level and rotates the token", () =>
      Effect.gen(function* () {
        const phone = yield* Phone
        const sessions = yield* Sessions
        const number = uniqueNumber()
        const { user, session, token } = yield* signUpUser(uniqueEmail("step-up"))
        yield* attach(phone, user, number)

        const issued = yield* phone.sendStepUp({ user })
        const elevated = yield* phone.completeStepUp({
          user,
          session,
          handle: issued.handle,
          code: Redacted.make(yield* PhoneTest.codeFor(number))
        })

        assert.strictEqual(elevated.session.id, session.id)
        // A password sign-up plus an SMS is two distinct factors.
        assert.strictEqual(elevated.session.aal, "aal2")
        assert.include(
          elevated.session.methods.map((method) => method.method),
          "sms"
        )
        // The token this session was addressed by no longer resolves.
        const stale = yield* Effect.result(sessions.verify(token))
        assert.strictEqual(stale._tag, "Failure")
        const fresh = yield* sessions.verify(elevated.token)
        assert.strictEqual(fresh.session.id, session.id)
      })
    )

    it.effect("sends to the number on the record and takes none from the caller", () =>
      Effect.gen(function* () {
        const phone = yield* Phone
        const emails = yield* TestEmails
        const number = uniqueNumber()
        const { user } = yield* signUpUser(uniqueEmail("own-number"))
        yield* attach(phone, user, number)

        yield* phone.sendStepUp({ user })
        assert.strictEqual((yield* emails.to(number)).length, 2)
      })
    )

    it.effect("refuses a caller with no verified number", () =>
      Effect.gen(function* () {
        const phone = yield* Phone
        const { user } = yield* signUpUser(uniqueEmail("no-number"))
        const outcome = yield* Effect.result(phone.sendStepUp({ user }))
        assert.strictEqual(outcome._tag, "Failure")
        if (outcome._tag === "Failure") assert.strictEqual(outcome.failure._tag, "PhoneNotVerified")
      })
    )

    it.effect("refuses a code sent to a number the account no longer holds", () =>
      Effect.gen(function* () {
        const phone = yield* Phone
        const number = uniqueNumber()
        const replacement = uniqueNumber()
        const { user, session } = yield* signUpUser(uniqueEmail("moved"))
        yield* attach(phone, user, number)

        const issued = yield* phone.sendStepUp({ user })
        const code = Redacted.make(yield* PhoneTest.codeFor(number))

        // The number changes while the code is in flight.
        yield* attach(phone, user, replacement)

        const outcome = yield* Effect.result(phone.completeStepUp({ user, session, handle: issued.handle, code }))
        assert.strictEqual(outcome._tag, "Failure")
        if (outcome._tag === "Failure") assert.strictEqual(outcome.failure._tag, "InvalidCode")
      })
    )
  })

  layer(PhoneTest.layer(allowed))("expiry", (it) => {
    it.effect("a code stops working after its ten minutes", () =>
      AuthTest.freshClock(
        Effect.gen(function* () {
          const phone = yield* Phone
          const number = uniqueNumber()
          const { user } = yield* signUpUser(uniqueEmail("expiry"))

          const issued = yield* phone.sendVerification({ user, phoneNumber: number })
          const code = Redacted.make(yield* PhoneTest.codeFor(number))

          yield* TestClock.adjust(Duration.minutes(11))

          const outcome = yield* Effect.result(phone.verify({ user, handle: issued.handle, code }))
          assert.strictEqual(outcome._tag, "Failure")
          if (outcome._tag === "Failure") assert.strictEqual(outcome.failure._tag, "InvalidCode")
        })
      )
    )
  })

  layer(PhoneTest.layer())("the shipped defaults", (it) => {
    it.effect("refuse to send anywhere at all", () =>
      Effect.gen(function* () {
        const phone = yield* Phone
        const emails = yield* TestEmails
        const number = uniqueNumber()
        const { user } = yield* signUpUser(uniqueEmail("deny-all"))

        assert.deepStrictEqual(phone.config.allowedCountries, [])
        const outcome = yield* Effect.result(phone.sendVerification({ user, phoneNumber: number }))
        assert.strictEqual(outcome._tag, "Failure")
        if (outcome._tag === "Failure") assert.strictEqual(outcome.failure._tag, "PhoneCountryNotAllowed")
        assert.deepStrictEqual(yield* emails.to(number), [])
      })
    )

    it.effect("serve contact, and neither sign-in nor step-up", () =>
      Effect.gen(function* () {
        const phone = yield* Phone
        assert.isTrue(phone.config.contact)
        // Both of the capabilities that make a number a *factor* are off. The
        // PSTN is the one channel NIST 800-63B §3.2.9 restricts, so neither is
        // something this library turns on for a deployment that said nothing.
        assert.isFalse(phone.config.signIn)
        assert.isFalse(phone.config.stepUp)
        assert.strictEqual(phone.config.digits, 6)
        assert.strictEqual(phone.config.attempts, 5)
        assert.isTrue(Duration.equals(phone.config.ttl, Duration.minutes(10)))
      })
    )

    it.effect("do not make an attached number a second factor", () =>
      Effect.gen(function* () {
        const phone = yield* Phone
        // Contact, not a factor: `summaryOf` reads `secondFactor` off
        // `config.stepUp`, so nothing about an account's assurance moves when a
        // number is attached, and there is no restricted factor for the
        // alternate rule to have an opinion about.
        assert.isFalse(phone.config.stepUp)
        assert.isFalse(phone.config.requireAlternateSecondFactor)
      })
    )
  })

  layer(PhoneTest.layer({ phone: { allowedCountries: ["1"], stepUp: true } }))(
    "a deployment that turns step-up on",
    (it) => {
      it.effect("gets the restricted-factor rule with it, unasked", () =>
        Effect.gen(function* () {
          const phone = yield* Phone
          // The moment the number becomes somebody's second factor, the rule
          // that a restricted channel may not be their only one comes with it.
          assert.isTrue(phone.config.stepUp)
          assert.isTrue(phone.config.requireAlternateSecondFactor)

          const { user } = yield* signUpUser(uniqueEmail("stepup-default"))
          const refused = yield* Effect.result(phone.sendVerification({ user, phoneNumber: uniqueNumber() }))
          assert.strictEqual(refused._tag, "Failure")
          if (refused._tag === "Failure") {
            assert.strictEqual(refused.failure._tag, "RestrictedFactorNotAllowed")
          }
        })
      )

      it.effect("can still say that SMS stands alone, and mean it", () =>
        Effect.gen(function* () {
          // Stating it is the whole point: it is a decision, not a default.
          assert.isFalse(makeConfig({ stepUp: true, requireAlternateSecondFactor: false }).requireAlternateSecondFactor)
        })
      )
    }
  )

  layer(PhoneTest.layer({ phone: { allowedCountries: ["44"] } }))("the country allowlist", (it) => {
    it.effect("refuses a country that was not opted in", () =>
      Effect.gen(function* () {
        const phone = yield* Phone
        const { user } = yield* signUpUser(uniqueEmail("wrong-country"))
        const outcome = yield* Effect.result(phone.sendVerification({ user, phoneNumber: "+15550100000" }))
        assert.strictEqual(outcome._tag, "Failure")
        if (outcome._tag === "Failure") assert.strictEqual(outcome.failure._tag, "PhoneCountryNotAllowed")
      })
    )

    it.effect("sends to one that was", () =>
      Effect.gen(function* () {
        const phone = yield* Phone
        const emails = yield* TestEmails
        const { user } = yield* signUpUser(uniqueEmail("right-country"))
        yield* phone.sendVerification({ user, phoneNumber: "+442079460958" })
        assert.strictEqual((yield* emails.to("+442079460958")).length, 1)
      })
    )
  })
})
