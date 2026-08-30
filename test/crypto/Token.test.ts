import { assert, describe, it } from "@effect/vitest"
import { Effect, Encoding, Redacted, Result } from "effect"
import * as Token from "../../src/crypto/Token.js"

const base64url = /^[A-Za-z0-9_-]+$/

describe("crypto/Token", () => {
  it.effect("mints 32 random bytes as a 43-character base64url string", () =>
    Effect.gen(function*() {
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
    }).pipe(Effect.provide(Token.layer)))

  it.effect("never mints the same token twice", () =>
    Effect.gen(function*() {
      const tokens = yield* Token.Token
      const minted = yield* Effect.forEach(
        Array.from({ length: 32 }),
        () => Effect.map(tokens.generateToken, Redacted.value)
      )

      assert.strictEqual(new Set(minted).size, minted.length)
    }).pipe(Effect.provide(Token.layer)))

  it.effect("hashes a token deterministically", () =>
    Effect.gen(function*() {
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
    }).pipe(Effect.provide(Token.layer)))

  it.effect("gives different tokens different hashes", () =>
    Effect.gen(function*() {
      const tokens = yield* Token.Token
      const a = yield* tokens.generateToken
      const b = yield* tokens.generateToken

      const hashA = yield* tokens.hashToken(a)
      const hashB = yield* tokens.hashToken(b)

      assert.notStrictEqual(hashA, hashB)
      // The stored form must not be the token itself.
      assert.notStrictEqual(hashA, Redacted.value(a))
    }).pipe(Effect.provide(Token.layer)))

  it.effect("distinguishes tokens that differ in one character", () =>
    Effect.gen(function*() {
      const tokens = yield* Token.Token
      const hashA = yield* tokens.hashToken(Redacted.make("aaaaaaaa"))
      const hashB = yield* tokens.hashToken(Redacted.make("aaaaaaab"))

      assert.notStrictEqual(hashA, hashB)
    }).pipe(Effect.provide(Token.layer)))

  it.effect("can be bound to an explicit WebCrypto instance", () =>
    Effect.gen(function*() {
      // A stubbed generator proves nothing leaks in from `globalThis`: the
      // token is exactly the bytes the injected crypto handed over.
      const stub = {
        getRandomValues: <A extends ArrayBufferView>(array: A): A => {
          new Uint8Array(array.buffer, array.byteOffset, array.byteLength).fill(1)
          return array
        },
        subtle: globalThis.crypto.subtle
      } as unknown as Crypto

      const tokens = Token.make(stub)
      const token = yield* tokens.generateToken

      assert.strictEqual(
        Redacted.value(token),
        Encoding.encodeBase64Url(new Uint8Array(Token.tokenBytes).fill(1))
      )
    }))
})
