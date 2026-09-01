import { assert, describe, it } from "@effect/vitest"
import { DateTime, Effect, Option } from "effect"
import * as Totp from "../../src/crypto/Totp.js"

const utf8 = new TextEncoder()

/**
 * RFC 6238 Appendix B's seeds. The RFC prints one twenty-byte ASCII seed and
 * says the wider modes use "the same" one; the errata settle what that means —
 * the ASCII digits repeat up to the hash's block-relevant length, which is what
 * every interoperable implementation does.
 */
const seeds = {
  "SHA-1": utf8.encode("12345678901234567890"),
  "SHA-256": utf8.encode("12345678901234567890123456789012"),
  "SHA-512": utf8.encode("1234567890123456789012345678901234567890123456789012345678901234")
} as const

/** Appendix B in full: six instants, three modes, eight digits, a 30 s period. */
const vectors: ReadonlyArray<readonly [Totp.TotpAlgorithm, number, string]> = [
  ["SHA-1", 59, "94287082"],
  ["SHA-1", 1111111109, "07081804"],
  ["SHA-1", 1111111111, "14050471"],
  ["SHA-1", 1234567890, "89005924"],
  ["SHA-1", 2000000000, "69279037"],
  ["SHA-1", 20000000000, "65353130"],
  ["SHA-256", 59, "46119246"],
  ["SHA-256", 1111111109, "68084774"],
  ["SHA-256", 1111111111, "67062674"],
  ["SHA-256", 1234567890, "91819424"],
  ["SHA-256", 2000000000, "90698825"],
  ["SHA-256", 20000000000, "77737706"],
  ["SHA-512", 59, "90693936"],
  ["SHA-512", 1111111109, "25091201"],
  ["SHA-512", 1111111111, "99943326"],
  ["SHA-512", 1234567890, "93441116"],
  ["SHA-512", 2000000000, "38618901"],
  ["SHA-512", 20000000000, "47863826"]
]

const secret = seeds["SHA-1"]

describe("crypto/Totp", () => {
  it.effect("reproduces every RFC 6238 Appendix B vector", () =>
    Effect.gen(function* () {
      for (const [algorithm, seconds, expected] of vectors) {
        const step = Totp.stepAt(DateTime.fromEpochSeconds(seconds))
        const code = yield* Totp.generate({ secret: seeds[algorithm], step, digits: 8, algorithm })
        assert.strictEqual(code, expected, `${algorithm} @ ${seconds}`)
      }
    })
  )

  it.effect("accepts the code for the current step and answers which step it was", () =>
    Effect.gen(function* () {
      const now = DateTime.fromEpochSeconds(1234567890)
      const step = Totp.stepAt(now)
      const code = yield* Totp.generate({ secret, step, digits: 8 })

      const matched = yield* Totp.verify({ secret, code, now, lastUsedStep: null, digits: 8 })
      assert.deepStrictEqual(matched, Option.some(step))
    })
  )

  it.effect("accepts one step either side and refuses two", () =>
    Effect.gen(function* () {
      const now = DateTime.fromEpochSeconds(1234567890)
      const step = Totp.stepAt(now)

      for (const delta of [-1, 0, 1]) {
        const code = yield* Totp.generate({ secret, step: step + delta, digits: 8 })
        const matched = yield* Totp.verify({ secret, code, now, lastUsedStep: null, digits: 8 })
        assert.deepStrictEqual(matched, Option.some(step + delta), `delta ${delta}`)
      }

      for (const delta of [-2, 2]) {
        const code = yield* Totp.generate({ secret, step: step + delta, digits: 8 })
        const matched = yield* Totp.verify({ secret, code, now, lastUsedStep: null, digits: 8 })
        assert.strictEqual(Option.isNone(matched), true, `delta ${delta}`)
      }
    })
  )

  it.effect("narrows the window to nothing when asked", () =>
    Effect.gen(function* () {
      const now = DateTime.fromEpochSeconds(1234567890)
      const step = Totp.stepAt(now)
      const previous = yield* Totp.generate({ secret, step: step - 1, digits: 8 })

      assert.strictEqual(
        Option.isNone(yield* Totp.verify({ secret, code: previous, now, window: 0, lastUsedStep: null, digits: 8 })),
        true
      )
    })
  )

  it.effect("refuses the step it just accepted — the replay rule", () =>
    Effect.gen(function* () {
      const now = DateTime.fromEpochSeconds(1234567890)
      const step = Totp.stepAt(now)
      const code = yield* Totp.generate({ secret, step, digits: 8 })

      const first = yield* Totp.verify({ secret, code, now, lastUsedStep: null, digits: 8 })
      assert.deepStrictEqual(first, Option.some(step))

      // The same code, in the same period, with the step it burned recorded.
      const replayed = yield* Totp.verify({ secret, code, now, lastUsedStep: step, digits: 8 })
      assert.strictEqual(Option.isNone(replayed), true)
    })
  )

  it.effect("refuses a step below the last one used, even inside the window", () =>
    Effect.gen(function* () {
      const now = DateTime.fromEpochSeconds(1234567890)
      const step = Totp.stepAt(now)
      const previous = yield* Totp.generate({ secret, step: step - 1, digits: 8 })

      // Without the rule this is a live code: it is one step back, inside the
      // window. With it, an authenticator that has already been used forwards
      // cannot be wound back.
      assert.strictEqual(
        Option.isNone(yield* Totp.verify({ secret, code: previous, now, lastUsedStep: step, digits: 8 })),
        true
      )
      // And the step after the used one is still accepted, so drift forwards
      // does not lock anybody out.
      const next = yield* Totp.generate({ secret, step: step + 1, digits: 8 })
      assert.deepStrictEqual(
        yield* Totp.verify({ secret, code: next, now, lastUsedStep: step, digits: 8 }),
        Option.some(step + 1)
      )
    })
  )

  it.effect("refuses a wrong code, a code of the wrong length, and another secret's code", () =>
    Effect.gen(function* () {
      const now = DateTime.fromEpochSeconds(1234567890)
      const step = Totp.stepAt(now)
      const code = yield* Totp.generate({ secret, step, digits: 8 })

      for (const bad of ["00000000", code.slice(1), `0${code}`, ""]) {
        assert.strictEqual(
          Option.isNone(yield* Totp.verify({ secret, code: bad, now, lastUsedStep: null, digits: 8 })),
          true,
          bad
        )
      }

      const other = utf8.encode("09876543210987654321")
      assert.strictEqual(
        Option.isNone(yield* Totp.verify({ secret: other, code, now, lastUsedStep: null, digits: 8 })),
        true
      )
    })
  )

  it.effect("defaults to SHA-1, six digits and thirty seconds", () =>
    Effect.gen(function* () {
      const now = DateTime.fromEpochSeconds(59)
      assert.strictEqual(Totp.stepAt(now), 1)
      const code = yield* Totp.generate({ secret, step: 1 })
      assert.strictEqual(code.length, 6)
      // The six-digit truncation of the eight-digit Appendix B vector.
      assert.strictEqual(code, "287082")
      assert.deepStrictEqual(yield* Totp.verify({ secret, code, now, lastUsedStep: null }), Option.some(1))
    })
  )

  it.effect("honours a non-default period", () =>
    Effect.gen(function* () {
      const now = DateTime.fromEpochSeconds(120)
      assert.strictEqual(Totp.stepAt(now, 60), 2)
      const code = yield* Totp.generate({ secret, step: 2 })
      assert.deepStrictEqual(yield* Totp.verify({ secret, code, now, period: 60, lastUsedStep: null }), Option.some(2))
    })
  )

  it("builds an otpauth URI an authenticator can scan", () => {
    const uri = Totp.otpauthUri({ issuer: "Acme Corp", account: "ada@example.com", secret })

    assert.strictEqual(
      uri,
      "otpauth://totp/Acme%20Corp:ada%40example.com" +
        "?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Acme%20Corp&algorithm=SHA1&digits=6&period=30"
    )
    // The hash is spelled without its dash in the Key Uri Format.
    assert.match(
      Totp.otpauthUri({ issuer: "a", account: "b", secret, algorithm: "SHA-256", digits: 8, period: 60 }),
      /algorithm=SHA256&digits=8&period=60$/
    )
  })

  it.effect("treats a digit count no authenticator produces as a defect", () =>
    Effect.gen(function* () {
      const failed = yield* Effect.exit(Totp.generate({ secret, step: 1, digits: 4 }))
      assert.strictEqual(failed._tag, "Failure")
    })
  )
})
