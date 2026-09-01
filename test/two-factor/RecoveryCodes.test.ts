import { assert, describe, it, layer } from "@effect/vitest"
import { Effect, Redacted } from "effect"
import { layerWebCrypto } from "../../src/internal/crypto.js"
import * as RecoveryCodes from "../../src/two-factor/RecoveryCodes.js"

describe("two-factor/RecoveryCodes", () => {
  describe("format", () => {
    it("prints twelve characters in three groups of four", () => {
      assert.strictEqual(RecoveryCodes.format("ABCDEFGHJKMN"), "ABCD-EFGH-JKMN")
    })

    it("is the inverse of normalise", () => {
      const code = "0123456789AB"
      assert.strictEqual(RecoveryCodes.normalise(RecoveryCodes.format(code)), code)
    })
  })

  describe("normalise", () => {
    it("drops the dashes it was printed with and the spaces a mail client added", () => {
      assert.strictEqual(RecoveryCodes.normalise(" ABCD-EFGH JKMN "), "ABCDEFGHJKMN")
    })

    it("folds case", () => {
      assert.strictEqual(RecoveryCodes.normalise("abcd-efgh-jkmn"), "ABCDEFGHJKMN")
    })

    it("reads Crockford's confusables as the digits they look like", () => {
      // O is zero; I and L are one. This is the whole reason the alphabet has
      // none of them: somebody transcribing a printed code will type these.
      assert.strictEqual(RecoveryCodes.normalise("OIL"), "011")
      assert.strictEqual(RecoveryCodes.normalise("oil"), "011")
    })

    it("drops a character the alphabet does not have, rather than guessing", () => {
      // `U` is excluded from Crockford's alphabet and is not a confusable of
      // anything, so a code containing one simply does not match.
      assert.strictEqual(RecoveryCodes.normalise("ABCU"), "ABC")
      assert.strictEqual(RecoveryCodes.normalise("AB!C"), "ABC")
    })

    it("leaves a code that is already normalised alone", () => {
      assert.strictEqual(RecoveryCodes.normalise("ABCDEFGHJKMN"), "ABCDEFGHJKMN")
    })
  })

  describe("alphabet", () => {
    it("is Crockford's: no I, L, O or U", () => {
      assert.strictEqual(RecoveryCodes.alphabet.length, 32)
      for (const excluded of ["I", "L", "O", "U"]) {
        assert.isFalse(RecoveryCodes.alphabet.includes(excluded), `${excluded} must not be in the alphabet`)
      }
    })
  })

  layer(layerWebCrypto)("generate", (it) => {
    it.effect("mints the number asked for, each twelve characters of the alphabet", () =>
      Effect.gen(function* () {
        const codes = yield* RecoveryCodes.generate(10)
        assert.strictEqual(codes.length, 10)
        for (const code of codes) {
          const value = Redacted.value(code)
          assert.strictEqual(value.length, RecoveryCodes.codeLength)
          for (const character of value) {
            assert.isTrue(RecoveryCodes.alphabet.includes(character), `${character} is not in the alphabet`)
          }
        }
      })
    )

    it.effect("mints distinct codes", () =>
      Effect.gen(function* () {
        const codes = yield* RecoveryCodes.generate(50)
        const distinct = new Set(codes.map(Redacted.value))
        assert.strictEqual(distinct.size, 50)
      })
    )

    it.effect("uses the whole alphabet, so the sixty bits are really there", () =>
      Effect.gen(function* () {
        // 200 codes is 2,400 characters over 32 symbols — 75 expected each.
        // Seeing every symbol at least once is a weak test of uniformity and a
        // strong test that the sampling is not masked to a subset.
        const codes = yield* RecoveryCodes.generate(200)
        const seen = new Set(codes.flatMap((code) => Array.from(Redacted.value(code))))
        assert.strictEqual(seen.size, 32)
      })
    )

    it.effect("keeps a code Redacted, so nothing can log it on the way out", () =>
      Effect.gen(function* () {
        const [code] = yield* RecoveryCodes.generate(1)
        assert.strictEqual(String(code), "<redacted>")
      })
    )
  })
})
