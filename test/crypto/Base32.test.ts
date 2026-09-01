import { assert, describe, it } from "@effect/vitest"
import { Encoding, Result } from "effect"
import { decode, encode } from "../../src/internal/base32.js"

const utf8 = new TextEncoder()
const bytes = (text: string): Uint8Array => utf8.encode(text)

/** RFC 4648 §10, with the padding the encoder does not write stripped off. */
const vectors: ReadonlyArray<readonly [string, string]> = [
  ["", ""],
  ["f", "MY"],
  ["fo", "MZXQ"],
  ["foo", "MZXW6"],
  ["foob", "MZXW6YQ"],
  ["fooba", "MZXW6YTB"],
  ["foobar", "MZXW6YTBOI"]
]

describe("crypto/Base32", () => {
  it("matches the RFC 4648 test vectors, unpadded", () => {
    for (const [plain, encoded] of vectors) {
      assert.strictEqual(encode(bytes(plain)), encoded)
    }
  })

  it("decodes what it encodes, at every length in a group", () => {
    for (let length = 0; length < 24; length++) {
      const input = new Uint8Array(length)
      for (let index = 0; index < length; index++) input[index] = (index * 37 + 11) & 0xff
      const decoded = decode(encode(input))
      assert.strictEqual(Result.isSuccess(decoded), true)
      if (Result.isSuccess(decoded)) assert.deepStrictEqual(Array.from(decoded.success), Array.from(input))
    }
  })

  it("reads a real TOTP secret back", () => {
    // The 20-byte secret of RFC 6238's SHA-1 vector, as an authenticator app
    // would be handed it.
    const secret = bytes("12345678901234567890")
    assert.strictEqual(encode(secret), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
    const decoded = decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
    assert.strictEqual(Result.isSuccess(decoded), true)
    if (Result.isSuccess(decoded)) assert.deepStrictEqual(Array.from(decoded.success), Array.from(secret))
  })

  it("accepts lowercase and trailing padding, because people paste both", () => {
    const upper = decode("MZXW6YTBOI")
    const lower = decode("mzxw6ytboi")
    const padded = decode("MZXW6YTBOI======")
    assert.strictEqual(Result.isSuccess(lower), true)
    assert.strictEqual(Result.isSuccess(padded), true)
    if (Result.isSuccess(upper) && Result.isSuccess(lower) && Result.isSuccess(padded)) {
      assert.deepStrictEqual(Array.from(lower.success), Array.from(upper.success))
      assert.deepStrictEqual(Array.from(padded.success), Array.from(upper.success))
    }
  })

  it("refuses a character outside the alphabet — 0, 1, 8 and 9 are not in it", () => {
    for (const bad of ["MZXW6YT0", "MZXW6YT1", "MZXW6YT8", "MZXW6YT9", "MZXW6YT!", "MZXW6YT="]) {
      const decoded = decode(bad)
      assert.strictEqual(Result.isFailure(decoded), true, bad)
      if (Result.isFailure(decoded)) {
        assert.strictEqual(Encoding.isEncodingError(decoded.failure), true)
        assert.strictEqual(decoded.failure.module, "Base32")
      }
    }
  })

  it("refuses a length no byte string encodes to", () => {
    for (const bad of ["M", "MZX", "MZXW6Y", "MZXW6YTBOIM"]) {
      assert.strictEqual(Result.isFailure(decode(bad)), true, bad)
    }
  })

  it("refuses a non-canonical trailing group, so one secret has one spelling", () => {
    // "MY" is `f`; "MZ" is the same byte with a fill bit set, and accepting it
    // would make two strings name one secret.
    assert.strictEqual(Result.isSuccess(decode("MY")), true)
    assert.strictEqual(Result.isFailure(decode("MZ")), true)
    assert.strictEqual(Result.isFailure(decode("MZXW6YTBOJ")), true)
  })
})
