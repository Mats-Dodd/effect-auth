import { assert, describe, layer } from "@effect/vitest"
import { Duration, Effect, Redacted } from "effect"
import type { AuthenticatorsService } from "../../src/domain/Authenticators.js"
import { Authenticators, list as listAuthenticators } from "../../src/domain/Authenticators.js"
import type { PhoneService } from "../../src/phone/index.js"
import { Phone, summaryOf } from "../../src/phone/index.js"
import { PhoneStore } from "../../src/phone/Store.js"
import * as PhoneTest from "../../src/testing/PhoneTest.js"
import { TestEmails } from "../../src/testing/TestEmails.js"
import type { User } from "../../src/domain/Schema.js"
import { encodeSubjectToken } from "../../src/domain/Verifications.js"
import { expectSome, signUpUser, uniqueEmail } from "../fixtures.js"

let counter = 0
const uniqueNumber = (prefix = "555"): string => `+1${prefix}${String(2000000 + counter++)}`

const attach = Effect.fnUntraced(function* (phone: PhoneService, user: User, number: string) {
  const issued = yield* phone.sendVerification({ user, phoneNumber: number })
  return yield* phone.verify({
    user,
    handle: issued.handle,
    code: Redacted.make(yield* PhoneTest.codeFor(number))
  })
})

/** The failure tag of an effect that is expected to fail. */
const failureTag = <A, E extends { readonly _tag: string }, R>(effect: Effect.Effect<A, E, R>) =>
  Effect.map(Effect.result(effect), (result) => (result._tag === "Failure" ? result.failure._tag : "Success"))

describe.sequential("phone/Limits", () => {
  layer(
    PhoneTest.layer({
      rateLimit: { enabled: true },
      phone: {
        allowedCountries: ["1"],
        signIn: true,
        stepUp: true,
        requireAlternateSecondFactor: false,
        limits: {
          destination: { name: "test-destination", limit: 2, window: Duration.hours(1) },
          prefix: { name: "test-prefix", limit: 3, window: Duration.hours(1) },
          subject: { name: "test-subject", limit: 4, window: Duration.hours(1) },
          verify: { name: "test-verify", limit: 3, window: Duration.minutes(15) }
        }
      }
    })
  )("the toll-fraud limits", (it) => {
    it.effect("counts sends against the destination number", () =>
      Effect.gen(function* () {
        const phone = yield* Phone
        const number = uniqueNumber()
        const { user } = yield* signUpUser(uniqueEmail("destination"))

        yield* phone.sendVerification({ user, phoneNumber: number })
        yield* phone.sendVerification({ user, phoneNumber: number })
        assert.strictEqual(yield* failureTag(phone.sendVerification({ user, phoneNumber: number })), "RateLimited")
      })
    )

    it.effect("a second number in another range has its own allowance", () =>
      Effect.gen(function* () {
        const phone = yield* Phone
        const spent = uniqueNumber("552")
        const fresh = uniqueNumber("553")
        const { user } = yield* signUpUser(uniqueEmail("per-number"))

        yield* phone.sendVerification({ user, phoneNumber: spent })
        yield* phone.sendVerification({ user, phoneNumber: spent })
        assert.strictEqual(yield* failureTag(phone.sendVerification({ user, phoneNumber: spent })), "RateLimited")
        yield* phone.sendVerification({ user, phoneNumber: fresh })
      })
    )

    it.effect("counts sends against the destination prefix, which a fresh number does not escape", () =>
      Effect.gen(function* () {
        const phone = yield* Phone
        const { user } = yield* signUpUser(uniqueEmail("prefix"))
        // Three numbers in one range: each has its own destination allowance,
        // and together they spend the range's.
        const first = uniqueNumber("561")
        const second = uniqueNumber("561")
        const third = uniqueNumber("561")
        const fourth = uniqueNumber("561")

        yield* phone.sendVerification({ user, phoneNumber: first })
        yield* phone.sendVerification({ user, phoneNumber: second })
        yield* phone.sendVerification({ user, phoneNumber: third })
        assert.strictEqual(yield* failureTag(phone.sendVerification({ user, phoneNumber: fourth })), "RateLimited")

        // A different range is untouched by it.
        yield* phone.sendVerification({ user, phoneNumber: uniqueNumber("562") })
      })
    )

    it.effect("counts a step-up send against the destination range too", () =>
      Effect.gen(function* () {
        const phone = yield* Phone
        const mine = uniqueNumber("565")
        const { user } = yield* signUpUser(uniqueEmail("step-up-prefix"))
        yield* attach(phone, user, mine)

        // Two more sends into the same range, from somebody else, so that only
        // the range bucket can be what refuses the step-up: my own number's
        // destination allowance and my own subject allowance are both intact.
        const other = yield* signUpUser(uniqueEmail("step-up-prefix-other"))
        yield* phone.sendVerification({ user: other.user, phoneNumber: uniqueNumber("565") })
        yield* phone.sendVerification({ user: other.user, phoneNumber: uniqueNumber("565") })

        // Premium-rate fraud pays for traffic to a block, not to one handset,
        // so the range bucket is the one that sees it — and a stolen session
        // must not be a way around it.
        assert.strictEqual(yield* failureTag(phone.sendStepUp({ user })), "RateLimited")
      })
    )

    it.effect("counts a signed-in caller's sends against them, whatever number they name", () =>
      Effect.gen(function* () {
        const phone = yield* Phone
        const { user } = yield* signUpUser(uniqueEmail("subject"))
        // Four sends, each to a number and a range of its own, so only the
        // subject bucket can be the one that stops the fifth.
        for (const prefix of ["571", "572", "573", "574"]) {
          yield* phone.sendVerification({ user, phoneNumber: uniqueNumber(prefix) })
        }
        assert.strictEqual(
          yield* failureTag(phone.sendVerification({ user, phoneNumber: uniqueNumber("575") })),
          "RateLimited"
        )

        // Somebody else still has their own.
        const other = yield* signUpUser(uniqueEmail("subject-other"))
        yield* phone.sendVerification({ user: other.user, phoneNumber: uniqueNumber("576") })
      })
    )

    it.effect("counts guesses across challenges, so a fresh code does not refresh the budget", () =>
      Effect.gen(function* () {
        const phone = yield* Phone
        const { user } = yield* signUpUser(uniqueEmail("verify-budget"))

        // Three wrong guesses, each against a code of its own — and each to a
        // number and a range of its own, so that the destination limits cannot
        // be what stops the fourth.
        for (const prefix of ["581", "582", "583"]) {
          const fresh = yield* phone.sendVerification({ user, phoneNumber: uniqueNumber(prefix) })
          assert.strictEqual(
            yield* failureTag(phone.verify({ user, handle: fresh.handle, code: Redacted.make("000000") })),
            "InvalidCode"
          )
        }
        const issued = yield* phone.sendVerification({ user, phoneNumber: uniqueNumber("584") })
        assert.strictEqual(
          yield* failureTag(phone.verify({ user, handle: issued.handle, code: Redacted.make("000000") })),
          "RateLimited"
        )
      })
    )

    it.effect("a forged handle cannot spend somebody else's allowance", () =>
      Effect.gen(function* () {
        const phone = yield* Phone
        const number = uniqueNumber("591")
        const { user } = yield* signUpUser(uniqueEmail("forged-handle"))
        yield* attach(phone, user, number)
        const issued = yield* phone.sendSignIn({ phoneNumber: number })

        // Ten handles naming the victim's number, none of them naming a row.
        // If the cross-challenge budget were keyed on the subject the caller
        // wrote into their own cookie, any stranger could spend it from
        // anywhere and lock that number out of answering its own code.
        for (let attempt = 0; attempt < 10; attempt++) {
          const forged = encodeSubjectToken(number, Redacted.make(`forgery-${attempt}`))
          assert.strictEqual(
            yield* failureTag(phone.completeSignIn({ handle: forged, code: Redacted.make("000000") })),
            "InvalidCode"
          )
        }

        // The real holder's own code still works.
        const completed = yield* phone.completeSignIn({
          handle: issued.handle,
          code: Redacted.make(yield* PhoneTest.codeFor(number))
        })
        assert.strictEqual(completed._tag, "Complete")
      })
    )

    it.effect("a refused country costs no allowance at all", () =>
      Effect.gen(function* () {
        const phone = yield* Phone
        const emails = yield* TestEmails
        const { user } = yield* signUpUser(uniqueEmail("refused-country"))

        for (let attempt = 0; attempt < 5; attempt++) {
          assert.strictEqual(
            yield* failureTag(phone.sendVerification({ user, phoneNumber: "+442079460958" })),
            "PhoneCountryNotAllowed"
          )
        }
        // The subject's own allowance is untouched, so a permitted number still
        // goes through.
        yield* phone.sendVerification({ user, phoneNumber: uniqueNumber("591") })
        assert.strictEqual((yield* emails.to("+442079460958")).length, 0)
      })
    )
  })

  layer(
    PhoneTest.layer({
      phone: { allowedCountries: ["1"], signIn: true, stepUp: true, requireAlternateSecondFactor: false }
    })
  )("the authenticator seam", (it) => {
    it.effect("contributes a restricted second factor that can also sign in", () =>
      Effect.gen(function* () {
        const phone = yield* Phone
        const number = uniqueNumber()
        const { user } = yield* signUpUser(uniqueEmail("summary"))
        yield* attach(phone, user, number)

        const summaries = yield* phone.summaries(user.id)
        assert.strictEqual(summaries.length, 1)
        const summary = summaries[0]!
        assert.strictEqual(summary.type, "phone")
        assert.strictEqual(summary.id, number)
        assert.strictEqual(summary.signIn, true)
        assert.strictEqual(summary.secondFactor, true)
        // NIST 800-63B §3.2.9, whatever else is configured.
        assert.strictEqual(summary.restricted, true)
        assert.isNotNull(summary.verifiedAt)
        // The name is masked, and does not repeat the whole number.
        assert.notStrictEqual(summary.name, number)
      })
    )

    it.effect("contributes nothing for a user with no number", () =>
      Effect.gen(function* () {
        const phone = yield* Phone
        const { user } = yield* signUpUser(uniqueEmail("no-summary"))
        assert.deepStrictEqual(yield* phone.summaries(user.id), [])
      })
    )

    it.effect("is installed underneath the deployment, so core reads it", () =>
      Effect.gen(function* () {
        const phone = yield* Phone
        const store = yield* PhoneStore
        const number = uniqueNumber()
        const { user } = yield* signUpUser(uniqueEmail("seam"))
        yield* attach(phone, user, number)

        // The reference `Accounts.unlink` and the reclaim path read is provided
        // beneath `Auth.layer`, so this is the same answer they get.
        const installed: AuthenticatorsService = yield* Effect.provide(
          Effect.succeed({}).pipe(Effect.flatMap(() => Authenticators)),
          PhoneTest.layerAuthenticators({ allowedCountries: ["1"], signIn: true })
        )
        const listed = yield* listAuthenticators(installed, user.id)
        assert.deepStrictEqual(
          listed.map((summary) => summary.type),
          ["phone"]
        )

        // And revoking sweeps the row, which is what the takeover defence needs.
        const removed = installed.revokeAll === undefined ? 0 : yield* installed.revokeAll(user.id)
        assert.strictEqual(removed, 1)
        assert.isTrue((yield* store.findByUserId(user.id))._tag === "None")
      })
    )

    it.effect("summaryOf follows the configuration rather than assuming", () =>
      Effect.gen(function* () {
        const phone = yield* Phone
        const number = uniqueNumber()
        const { user } = yield* signUpUser(uniqueEmail("summary-of"))
        yield* attach(phone, user, number)
        const store = yield* PhoneStore
        const row = yield* expectSome(yield* store.findByUserId(user.id), "the number should be stored")

        const contact = summaryOf(row, { ...phone.config, signIn: false, stepUp: false })
        assert.strictEqual(contact.signIn, false)
        assert.strictEqual(contact.secondFactor, false)
        assert.strictEqual(contact.restricted, true)
      })
    )
  })

  layer(
    PhoneTest.layer({
      phone: { allowedCountries: ["1"], requireAlternateSecondFactor: true }
    })
  )("a restricted factor may not be the only second factor", (it) => {
    it.effect("refuses to attach a number to an account that holds nothing else", () =>
      Effect.gen(function* () {
        const phone = yield* Phone
        const { user } = yield* signUpUser(uniqueEmail("sole-factor"))
        assert.strictEqual(
          yield* failureTag(phone.sendVerification({ user, phoneNumber: uniqueNumber("601") })),
          "RestrictedFactorNotAllowed"
        )
      })
    )

    it.effect("refuses before the message goes out, not after", () =>
      Effect.gen(function* () {
        const phone = yield* Phone
        const emails = yield* TestEmails
        const number = uniqueNumber("602")
        const { user } = yield* signUpUser(uniqueEmail("sole-factor-send"))
        yield* failureTag(phone.sendVerification({ user, phoneNumber: number }))
        assert.deepStrictEqual(yield* emails.to(number), [])
      })
    )
  })

  layer(
    PhoneTest.layer({
      phone: { allowedCountries: ["1"], requireAlternateSecondFactor: true },
      // A stub contributor standing in for whatever unrestricted second factor
      // a deployment installed — a TOTP plugin, a passkey.
      authenticators: {
        list: (userId) =>
          Effect.succeed([
            {
              type: "totp",
              id: `totp:${userId}`,
              name: null,
              verifiedAt: null,
              lastUsedAt: null,
              signIn: false,
              secondFactor: true,
              restricted: false
            }
          ])
      }
    })
  )("with an unrestricted second factor already held", (it) => {
    it.effect("attaching the number is permitted", () =>
      Effect.gen(function* () {
        const phone = yield* Phone
        const number = uniqueNumber("611")
        const { user } = yield* signUpUser(uniqueEmail("alternate"))
        const attached = yield* attach(phone, user, number)
        assert.strictEqual(attached.phoneE164, number)
      })
    )
  })

  layer(
    PhoneTest.layer({
      phone: { allowedCountries: ["1"], requireAlternateSecondFactor: true },
      // A contributor that holds only *restricted* factors is no alternative at
      // all: that is the whole of what the rule says.
      authenticators: {
        list: (userId) =>
          Effect.succeed([
            {
              type: "sms",
              id: `sms:${userId}`,
              name: null,
              verifiedAt: null,
              lastUsedAt: null,
              signIn: true,
              secondFactor: true,
              restricted: true
            }
          ])
      }
    })
  )("with only restricted factors already held", (it) => {
    it.effect("attaching the number is still refused", () =>
      Effect.gen(function* () {
        const phone = yield* Phone
        const { user } = yield* signUpUser(uniqueEmail("still-restricted"))
        assert.strictEqual(
          yield* failureTag(phone.sendVerification({ user, phoneNumber: uniqueNumber("621") })),
          "RestrictedFactorNotAllowed"
        )
      })
    )
  })
})
