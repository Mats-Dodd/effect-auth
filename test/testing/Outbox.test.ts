/**
 * The captured outbox as a plugin's test harness uses it — in particular the
 * SMS convention, which is a convention rather than a second outbox.
 *
 * **Details**
 *
 * A phone plugin's sender is a service of its own shape, exactly as a mailer
 * is, and it records through the same seam. What makes an SMS readable the way
 * an e-mail is, is that `to` is the phone number: the queries are all scoped by
 * recipient, so `tokenFor(smsKind, phone)` is how a test reads a code out of the
 * handset, exactly as `tokenFor(resetKind, address)` reads a link out of an
 * inbox.
 *
 * Nothing here needs a deployment: `layerEmails` is the outbox and the
 * `AuthEmails` seam, and this file asks only about the outbox.
 */
import { assert, describe, it, layer } from "@effect/vitest"
import { Effect, Option, Redacted } from "effect"
import { layerEmails, sms, smsKind, TestEmails } from "../../src/testing/TestEmails.js"

const phone = "+15550100"
const otherPhone = "+15550199"

layer(layerEmails())("testing/TestEmails — the SMS convention", (it) => {
  it.effect("records a code against the number it was sent to", () =>
    Effect.gen(function* () {
      const emails = yield* TestEmails
      const code = Redacted.make("123456")

      yield* emails.record(sms({ to: phone, code }))

      const sent = yield* emails.to(phone)
      assert.strictEqual(sent.length, 1)
      assert.strictEqual(sent[0]?.kind, "sms")
      assert.strictEqual(sent[0]?.kind, smsKind)
      assert.strictEqual(sent[0]?.to, phone)
      // A code has no link, so both fields carry the value the message actually
      // carried rather than one of them carrying nothing.
      assert.strictEqual(Redacted.value(sent[0]!.token), "123456")
      assert.strictEqual(Redacted.value(sent[0]!.url), "123456")
    })
  )

  it.effect("reads a code the way its recipient would", () =>
    Effect.gen(function* () {
      const emails = yield* TestEmails
      yield* emails.record(sms({ to: otherPhone, code: Redacted.make("222222") }))

      const token = yield* emails.tokenFor(smsKind, otherPhone)

      assert.strictEqual(Redacted.value(token), "222222")
    })
  )

  it.effect("knows no user behind a number unless it is told one", () =>
    Effect.gen(function* () {
      const emails = yield* TestEmails
      yield* emails.record(sms({ to: "+15550111", code: Redacted.make("333333") }))

      const last = yield* emails.last(smsKind, "+15550111")

      // A code sent to an unknown number must look exactly like one sent to a
      // known number, and the outbox records that rather than inventing a user.
      assert.isTrue(Option.isSome(last))
      assert.isNull(Option.getOrThrow(last).user)
    })
  )

  it.effect("scopes every query by recipient, as the mail queries are", () =>
    Effect.gen(function* () {
      const emails = yield* TestEmails
      yield* emails.record(sms({ to: "+15550122", code: Redacted.make("444444") }))
      yield* emails.record(sms({ to: "+15550133", code: Redacted.make("555555") }))

      const one = yield* emails.to("+15550122")
      const other = yield* emails.to("+15550133")

      assert.strictEqual(one.length, 1)
      assert.strictEqual(other.length, 1)
      assert.strictEqual(Redacted.value(yield* emails.tokenFor(smsKind, "+15550133")), "555555")
    })
  )
})

describe("testing/TestEmails", () => {
  it("names the SMS kind as a constant, so a plugin never spells it twice", () => {
    assert.strictEqual(smsKind, "sms")
    assert.strictEqual(sms({ to: phone, code: Redacted.make("1") }).kind, smsKind)
  })
})
