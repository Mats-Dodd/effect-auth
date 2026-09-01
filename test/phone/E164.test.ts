import { assert, describe, it } from "@effect/vitest"
import { Option } from "effect"
import { E164 } from "../../src/phone/index.js"

describe("phone/E164", () => {
  describe("normalize", () => {
    const accepted: ReadonlyArray<readonly [input: string, expected: string]> = [
      ["+15550100000", "+15550100000"],
      ["+1 555 010 0000", "+15550100000"],
      ["+1 (555) 010-0000", "+15550100000"],
      ["+1.555.010.0000", "+15550100000"],
      ["+1/555/010/0000", "+15550100000"],
      ["+44 20 7946 0958", "+442079460958"],
      ["  +442079460958  ", "+442079460958"],
      // Fifteen digits is the E.164 ceiling and is accepted at it.
      ["+123456789012345", "+123456789012345"],
      // Seven is the floor.
      ["+4712345", "+4712345"]
    ]

    for (const [input, expected] of accepted) {
      it(`normalises ${JSON.stringify(input)}`, () => {
        assert.deepStrictEqual(E164.normalize(input), Option.some(expected))
        assert.isTrue(E164.isValid(input))
      })
    }

    const refused: ReadonlyArray<readonly [label: string, input: string]> = [
      ["no country code", "5550100000"],
      ["a national trunk prefix", "015550100000"],
      ["a leading zero after the plus", "+015550100"],
      ["the 00 international prefix", "0015550100000"],
      ["letters", "+1555ABC0000"],
      ["an extension", "+15550100000x123"],
      ["a second plus", "+1+5550100000"],
      ["a plus in the middle", "15550100+000"],
      ["sixteen digits", "+1234567890123456"],
      ["six digits", "+123456"],
      ["nothing but a plus", "+"],
      ["the empty string", ""],
      ["full-width digits", "＋１５５５０１０００００"],
      ["a newline", "+1555010\n0000"]
    ]

    for (const [label, input] of refused) {
      it(`refuses ${label}`, () => {
        assert.isTrue(Option.isNone(E164.normalize(input)))
        assert.isFalse(E164.isValid(input))
      })
    }

    it("refuses an input longer than it will look at, without walking it", () => {
      assert.isTrue(Option.isNone(E164.normalize(`+${"1".repeat(E164.maxInputLength)}`)))
    })

    it("is idempotent: normalising its own output changes nothing", () => {
      const once = E164.normalize("+1 (555) 010-0000")
      assert.isTrue(Option.isSome(once))
      assert.deepStrictEqual(E164.normalize(Option.getOrThrow(once)), once)
    })

    it("two spellings of one number are one key", () => {
      assert.deepStrictEqual(E164.normalize("+1 (555) 010-0000"), E164.normalize("+15550100000"))
    })
  })

  describe("countryCodeOf", () => {
    it("answers nothing at all for the empty allowlist, which is the default", () => {
      assert.isTrue(Option.isNone(E164.countryCodeOf([], "+15550100000")))
      assert.isFalse(E164.isAllowed([], "+15550100000"))
    })

    it("matches by prefix", () => {
      assert.deepStrictEqual(E164.countryCodeOf(["1", "44"], "+15550100000"), Option.some("1"))
      assert.deepStrictEqual(E164.countryCodeOf(["1", "44"], "+442079460958"), Option.some("44"))
    })

    it("refuses a number outside the allowlist", () => {
      assert.isTrue(Option.isNone(E164.countryCodeOf(["1"], "+442079460958")))
    })

    it("the longest matching entry wins, so overlapping entries are not order-dependent", () => {
      assert.deepStrictEqual(E164.countryCodeOf(["1", "155"], "+15550100000"), Option.some("155"))
      assert.deepStrictEqual(E164.countryCodeOf(["155", "1"], "+15550100000"), Option.some("155"))
      assert.deepStrictEqual(E164.countryCodeOf(["1", "155"], "+14150100000"), Option.some("1"))
    })

    it("ignores entries that cannot be a calling code", () => {
      assert.isTrue(Option.isNone(E164.countryCodeOf(["", "0", "1234", "+1", "us"], "+15550100000")))
    })
  })

  describe("prefixOf", () => {
    it("is the country code and three more digits", () => {
      assert.strictEqual(E164.prefixOf("1", "+15550100000"), "+1555")
      assert.strictEqual(E164.prefixOf("44", "+442079460958"), "+44207")
    })

    it("puts two numbers in one expensive range into one bucket", () => {
      assert.strictEqual(E164.prefixOf("1", "+15550100000"), E164.prefixOf("1", "+15550199999"))
    })

    it("puts two numbers in different ranges into different buckets", () => {
      assert.notStrictEqual(E164.prefixOf("1", "+15550100000"), E164.prefixOf("1", "+15560100000"))
    })
  })

  describe("mask", () => {
    it("keeps the shape and hides the subscriber", () => {
      assert.strictEqual(E164.mask("+15550100000"), "+15…0000")
    })

    it("does not lengthen a short number into a guessable one", () => {
      assert.strictEqual(E164.mask("+12345"), "+12345")
    })
  })
})
