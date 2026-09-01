import { assert, it, layer } from "@effect/vitest"
import { Crypto, Effect, Encoding, Layer, Redacted, Result } from "effect"
import * as Token from "../../src/crypto/Token.js"
import { layerWebCrypto } from "../../src/internal/crypto.js"

const base64url = /^[A-Za-z0-9_-]+$/

layer(Token.layer.pipe(Layer.provide(layerWebCrypto)))("crypto/Token", (it) => {
  it.effect("mints 32 random bytes as a 43-character base64url string", () =>
    Effect.gen(function* () {
      const tokens = yield* Token.Token
      const token = yield* tokens.generateToken
      const raw = Redacted.value(token)

      assert.strictEqual(raw.length, Token.tokenLength)
      assert.match(raw, base64url)

      const bytes = Encoding.decodeBase64Url(raw)
      assert.strictEqual(Result.isSuccess(bytes), true)
      if (Result.isSuccess(bytes)) {
        assert.strictEqual(bytes.success.length, Token.tokenBytes)
      }
    })
  )

  it.effect("never mints the same token twice", () =>
    Effect.gen(function* () {
      const tokens = yield* Token.Token
      const minted = yield* Effect.forEach(Array.from({ length: 32 }), () =>
        Effect.map(tokens.generateToken, Redacted.value)
      )

      assert.strictEqual(new Set(minted).size, minted.length)
    })
  )

  it.effect("hashes a token deterministically", () =>
    Effect.gen(function* () {
      const tokens = yield* Token.Token
      const token = Redacted.make("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE")

      const first = yield* tokens.hashToken(token)
      const second = yield* tokens.hashToken(Redacted.make(Redacted.value(token)))

      assert.strictEqual(first, second)
      // SHA-256 of the token text, base64url — a fixed vector, so a future
      // change of digest or encoding cannot slip past unnoticed.
      assert.strictEqual(first, "VtX6czP210fbQsI5QH5dpMMvTHnzXQkrE0_TWkAtnFw")
      assert.strictEqual(first.length, 43)
      assert.match(first, base64url)
    })
  )

  it.effect("gives different tokens different hashes", () =>
    Effect.gen(function* () {
      const tokens = yield* Token.Token
      const a = yield* tokens.generateToken
      const b = yield* tokens.generateToken

      const hashA = yield* tokens.hashToken(a)
      const hashB = yield* tokens.hashToken(b)

      assert.notStrictEqual(hashA, hashB)
      // The stored form must not be the token itself.
      assert.notStrictEqual(hashA, Redacted.value(a))
    })
  )

  it.effect("distinguishes tokens that differ in one character", () =>
    Effect.gen(function* () {
      const tokens = yield* Token.Token
      const hashA = yield* tokens.hashToken(Redacted.make("aaaaaaaa"))
      const hashB = yield* tokens.hashToken(Redacted.make("aaaaaaab"))

      assert.notStrictEqual(hashA, hashB)
    })
  )

  it.effect("mints a code of exactly the digits asked for, zero-padded", () =>
    Effect.gen(function* () {
      const tokens = yield* Token.Token
      const codes = yield* Effect.forEach(Array.from({ length: 256 }), () =>
        Effect.map(tokens.generateNumericCode(6), Redacted.value)
      )

      for (const code of codes) {
        assert.strictEqual(code.length, 6)
        assert.match(code, /^[0-9]{6}$/)
      }
      // Padding is not cosmetic: a code that loses its leading zero is a code
      // the person typing it cannot make match.
      assert.strictEqual(
        codes.some((code) => code.startsWith("0")),
        true
      )
      // And it is not a constant.
      assert.strictEqual(new Set(codes).size > 200, true)
    })
  )

  it.effect("draws digits uniformly — the rejection sampling is what makes it so", () =>
    Effect.gen(function* () {
      const tokens = yield* Token.Token
      const samples = 10_000
      const counts = new Array<number>(10).fill(0)

      const drawn = yield* Effect.forEach(Array.from({ length: samples }), () =>
        Effect.map(tokens.generateNumericCode(1), Redacted.value)
      )
      for (const code of drawn) counts[Number(code)]! += 1

      // Every digit appears, and none is more than a fifth off its expectation:
      // the standard deviation of a bucket is 30, so this is six sigma, which a
      // fair draw clears about once in ten billion runs. A `% 10` without the
      // discard would not be caught here — 2^32 is not divisible by 10, but the
      // bias is one part in 400 million — so the assertion below is the one
      // that speaks to the implementation, and this one to the outcome.
      const expected = samples / 10
      for (let digit = 0; digit < 10; digit++) {
        assert.strictEqual(counts[digit]! > expected * 0.8, true, `digit ${digit} is under-represented`)
        assert.strictEqual(counts[digit]! < expected * 1.2, true, `digit ${digit} is over-represented`)
      }

      // Pearson's chi-square over nine degrees of freedom. The critical value
      // at p = 10^-6 is 47.
      const chiSquare = counts.reduce((total, count) => total + (count - expected) ** 2 / expected, 0)
      assert.strictEqual(chiSquare < 47, true, `chi-square ${chiSquare} says the draw is not uniform`)
    })
  )

  it.effect("refuses a digit count it cannot draw in one sample", () =>
    Effect.gen(function* () {
      const tokens = yield* Token.Token

      for (const digits of [0, -1, 1.5, Token.maxCodeDigits + 1]) {
        const exit = yield* Effect.exit(tokens.generateNumericCode(digits))
        assert.strictEqual(exit._tag, "Failure", `${digits}`)
      }

      // The largest it will draw still works, and still spans the whole range.
      const code = yield* tokens.generateNumericCode(Token.maxCodeDigits)
      assert.strictEqual(Redacted.value(code).length, Token.maxCodeDigits)
    })
  )

  it.effect("keeps a code out of anything that gets logged", () =>
    Effect.gen(function* () {
      const tokens = yield* Token.Token
      const code = yield* tokens.generateNumericCode(6)

      assert.strictEqual(String(code), "<redacted>")
    })
  )
})

// Outside the block on purpose: this one builds its own `Token` over an
// injected `Crypto`, which is the whole point of the assertion.
it.effect("crypto/Token can be bound to an explicit Crypto instance", () =>
  Effect.gen(function* () {
    // A stubbed generator proves nothing leaks in from `globalThis`: the
    // token is exactly the bytes the injected crypto handed over.
    const stub = Crypto.make({
      randomBytes: (size) => new Uint8Array(size).fill(1),
      digest: (_algorithm, data) => Effect.succeed(data)
    })

    const tokens = Token.make(stub)
    const token = yield* tokens.generateToken

    assert.strictEqual(Redacted.value(token), Encoding.encodeBase64Url(new Uint8Array(Token.tokenBytes).fill(1)))
  })
)
