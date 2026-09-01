import { assert, describe, it } from "@effect/vitest"
import { DateTime, Duration, Effect, Schema } from "effect"
import type { AuthenticationFactor, AuthenticationMethod } from "../../src/domain/Assurance.js"
import { amrOf, AuthenticationMethodsJson, deriveAal, policyToJson } from "../../src/domain/Assurance.js"
import { StepUpRequired } from "../../src/domain/Errors.js"

const at = DateTime.makeUnsafe("2024-01-01T00:00:00.000Z")

/**
 * One log entry, stated the way a plugin states it.
 *
 * The defaults are the conservative ones — not phishing resistant, not
 * restricted, no user-verification bit — so every test says only what it is
 * actually about.
 */
const method = (
  name: string,
  factor: AuthenticationFactor,
  extra: { readonly phishingResistant?: boolean; readonly restricted?: boolean; readonly userVerified?: boolean } = {}
): AuthenticationMethod => ({
  method: name,
  completedAt: at,
  factor,
  phishingResistant: extra.phishingResistant ?? false,
  restricted: extra.restricted ?? false,
  ...(extra.userVerified === undefined ? {} : { userVerified: extra.userVerified })
})

const password = method("password", "knowledge")
const totp = method("totp", "possession")
const emailOtp = method("emailOtp", "possession")
const recoveryCode = method("recoveryCode", "possession")
const trustedDevice = method("trustedDevice", "none")
const uvPasskey = method("passkey", "inherence", { phishingResistant: true, userVerified: true })
const tapPasskey = method("passkey", "possession", { phishingResistant: true, userVerified: false })
const oauth = method("oauth:google", "knowledge")
const sms = method("sms", "possession", { restricted: true })

describe("domain/Assurance.deriveAal", () => {
  const cases: ReadonlyArray<readonly [string, ReadonlyArray<AuthenticationMethod>, string]> = [
    ["nothing was proven", [], "aal0"],
    ["a password alone is one factor", [password], "aal1"],
    ["a mailed code alone is one factor", [emailOtp], "aal1"],
    ["a user-verified passkey alone is a multi-factor ceremony", [uvPasskey], "aal2"],
    ["a passkey without the user-verification bit is one factor", [tapPasskey], "aal1"],
    ["a password and a TOTP code are two distinct factors", [password, totp], "aal2"],
    ["a password and a mailed code are two distinct factors", [password, emailOtp], "aal2"],
    ["two possession factors are still one kind of factor", [totp, emailOtp], "aal1"],
    ["a recovery code counts as possession", [password, recoveryCode], "aal2"],
    ["a recovery code alone is one factor", [recoveryCode], "aal1"],
    ["a trusted device contributes nothing", [password, trustedDevice], "aal1"],
    ["a trusted device alone proves nothing at all", [trustedDevice], "aal0"],
    ["a user-verified passkey is aal2 even beside a skip", [uvPasskey, trustedDevice], "aal2"],
    ["a restricted channel still counts as a factor", [password, sms], "aal2"]
  ]

  for (const [name, methods, expected] of cases) {
    it(name, () => {
      assert.strictEqual(deriveAal(methods), expected)
    })
  }

  it("reads the user-verification bit rather than the method name", () => {
    // `method` is an open set, so a plugin that calls its WebAuthn factor
    // something else must reach the same level on the same evidence.
    assert.strictEqual(deriveAal([method("platformKey", "inherence", { userVerified: true })]), "aal2")
  })

  it("ignores every entry that proves nothing, however many there are", () => {
    assert.strictEqual(deriveAal([trustedDevice, method("trustedDevice", "none"), method("device", "none")]), "aal0")
  })
})

describe("domain/Assurance.amrOf", () => {
  /** RFC 8176, plus nothing else. */
  const registered = new Set([
    "face",
    "fpt",
    "geo",
    "hwk",
    "iris",
    "kba",
    "mca",
    "mfa",
    "otp",
    "pin",
    "pop",
    "pwd",
    "rba",
    "retina",
    "sc",
    "sms",
    "swk",
    "tel",
    "user",
    "vbm",
    "wia"
  ])

  const cases: ReadonlyArray<readonly [string, ReadonlyArray<AuthenticationMethod>, ReadonlyArray<string>]> = [
    ["nothing", [], []],
    ["a password", [password], ["pwd"]],
    ["a TOTP code", [totp], ["otp"]],
    ["a mailed code is a code on another channel", [emailOtp], ["otp", "mca"]],
    ["a magic link says the same thing a mailed code does", [method("magic-link", "possession")], ["otp", "mca"]],
    ["an SMS code names its channel", [sms], ["otp", "sms", "mca"]],
    ["a recovery code is a one-time code", [recoveryCode], ["otp"]],
    ["a tapped passkey is a key and a proof of possession", [tapPasskey], ["swk", "pop"]],
    ["a user-verified passkey adds the person and reaches aal2", [uvPasskey], ["swk", "pop", "user", "mfa"]],
    ["federated sign-in has no registered value", [oauth], []],
    ["a trusted-device skip contributes nothing", [trustedDevice], []],
    ["two factors add mfa", [password, totp], ["pwd", "otp", "mfa"]]
  ]

  for (const [name, methods, expected] of cases) {
    it(name, () => {
      assert.deepStrictEqual(amrOf(methods), expected)
    })
  }

  it("emits registered values only, whatever a plugin called its factor", () => {
    const everything = [
      password,
      totp,
      emailOtp,
      recoveryCode,
      trustedDevice,
      uvPasskey,
      tapPasskey,
      oauth,
      sms,
      method("something-a-plugin-invented", "possession"),
      method("anonymous", "none")
    ]

    for (const value of amrOf(everything)) {
      assert.strictEqual(registered.has(value), true, `${value} is not an RFC 8176 registered value`)
    }
  })

  it("never repeats a value", () => {
    const values = amrOf([password, method("password", "knowledge"), totp, method("totp", "possession")])
    assert.deepStrictEqual(values, Array.from(new Set(values)))
  })

  it("never claims hardware it did not verify", () => {
    // Attestation is not checked anywhere in this library, so `hwk` is a claim
    // it cannot make.
    assert.strictEqual(amrOf([uvPasskey, tapPasskey]).includes("hwk"), false)
  })
})

describe("domain/Assurance.policyToJson", () => {
  it("states seconds, and leaves what the policy did not say absent", () => {
    assert.deepStrictEqual(policyToJson({ aal: "aal2", maxAge: Duration.minutes(5) }), { aal: "aal2", maxAge: 300 })
  })

  it("carries every member a policy did state", () => {
    assert.deepStrictEqual(
      policyToJson({ aal: "aal2", maxAge: Duration.hours(12), methods: ["passkey", "totp"], allowRecovery: false }),
      { aal: "aal2", maxAge: 43200, methods: ["passkey", "totp"], allowRecovery: false }
    )
  })

  it("an empty policy is an empty object, not one full of nulls", () => {
    assert.deepStrictEqual(policyToJson({}), {})
  })

  it("leaves an infinite maxAge absent — the wire has no number for it", () => {
    // `Duration.infinity` is how an endpoint says "any age will do" beside a
    // level it does insist on. `Infinity` is not a finite number, so the schema
    // refuses it and the *constructor* throws — which would turn every refusal
    // on such an endpoint into a 500 with no body the client could read.
    const encoded = policyToJson({ aal: "aal2", maxAge: Duration.infinity })
    assert.deepStrictEqual(encoded, { aal: "aal2" })
    assert.isFalse(Object.hasOwn(encoded, "maxAge"))

    // And the whole point: the refusal it feeds is constructible.
    const refusal = StepUpRequired.make({
      required: encoded,
      current: { aal: "aal1", authenticatedAt: DateTime.makeUnsafe(0), available: [] }
    })
    assert.strictEqual(refusal._tag, "StepUpRequired")
  })
})

describe("domain/Assurance.AuthenticationMethodsJson", () => {
  it.effect("round-trips a log through the text column it is stored in", () =>
    Effect.gen(function* () {
      const methods = [password, uvPasskey, trustedDevice]
      const encoded = yield* Schema.encodeEffect(AuthenticationMethodsJson)(methods)

      assert.strictEqual(typeof encoded, "string")

      const decoded = yield* Schema.decodeEffect(AuthenticationMethodsJson)(encoded)
      assert.deepStrictEqual(decoded, methods)
      // The bit the derivation reads survives the round trip; a log that lost it
      // would silently demote a passkey session to aal1.
      assert.strictEqual(deriveAal(decoded), "aal2")
    })
  )

  it.effect("keeps the user-verification key absent when the ceremony reported none", () =>
    Effect.gen(function* () {
      const encoded = yield* Schema.encodeEffect(AuthenticationMethodsJson)([password])
      assert.strictEqual(encoded.includes("userVerified"), false)
    })
  )
})
