import { assert, describe, it, layer } from "@effect/vitest"
import { Effect, Encoding, Layer, Redacted, Result, Schema } from "effect"
import * as PasswordHasher from "../../src/crypto/PasswordHasher.js"
import { layerWebCrypto } from "../../src/internal/crypto.js"
import { testPassword } from "../fixtures.js"

// Real cost parameters would make this file take minutes; the format, the
// dispatch and the comparison are what is under test, and they are indifferent
// to cost. The production defaults are asserted separately, from the constants.
// The hashing layers read their salt from the ambient `Crypto`; `Auth.layer`
// provides the WebCrypto-backed default, and standalone use provides it here.
const scrypt = PasswordHasher.layerScrypt({ N: 1024, r: 8, p: 1 }).pipe(Layer.provide(layerWebCrypto))
const pbkdf2 = PasswordHasher.layerPbkdf2({ iterations: 1000 }).pipe(Layer.provide(layerWebCrypto))

const password = testPassword
const wrong = Redacted.make("correct horse battery stapl3")

const hasher = PasswordHasher.PasswordHasher

// Hashing is deliberately slow, so the properties below are sampled a handful
// of times rather than fast-check's default hundred.
const sampled = { fastCheck: { numRuns: 5 } } as const

layer(scrypt)("crypto/PasswordHasher (scrypt)", (it) => {
  it.effect.prop(
    "round-trips any passphrase, and only that passphrase",
    { text: Schema.String },
    ({ text }) =>
      Effect.gen(function*() {
        const secret = Redacted.make(text)
        const hash = yield* hasher.use((_) => _.hash(secret))

        assert.strictEqual(yield* hasher.use((_) => _.verify(secret, hash)), true)
        // Appending a character always yields a different passphrase.
        assert.strictEqual(yield* hasher.use((_) => _.verify(Redacted.make(`${text}x`), hash)), false)
      }),
    sampled
  )

  it.effect("rejects a wrong password", () =>
    Effect.gen(function*() {
      const hash = yield* hasher.use((_) => _.hash(password))

      assert.strictEqual(yield* hasher.use((_) => _.verify(wrong, hash)), false)
      assert.strictEqual(yield* hasher.use((_) => _.verify(Redacted.make(""), hash)), false)
    }))

  it.effect("writes a self-describing hash with a fresh salt each time", () =>
    Effect.gen(function*() {
      const first = yield* hasher.use((_) => _.hash(password))
      const second = yield* hasher.use((_) => _.hash(password))

      assert.notStrictEqual(first, second)

      const segments = first.split("$")
      assert.strictEqual(segments.length, 4)
      assert.strictEqual(segments[0], "scrypt")
      assert.strictEqual(segments[1], "n=1024,r=8,p=1")

      const parsed = yield* PasswordHasher.parseHash(first)
      assert.strictEqual(parsed.algorithm, "scrypt")
      assert.strictEqual(parsed.salt.length, PasswordHasher.saltBytes)
      assert.strictEqual(parsed.key.length, PasswordHasher.defaultScryptOptions.dkLen)
      assert.deepStrictEqual({ ...parsed.params }, { n: "1024", r: "8", p: "1" })

      const other = yield* PasswordHasher.parseHash(second)
      assert.notDeepEqual(Array.from(parsed.salt), Array.from(other.salt))
    }))

  it.effect("round-trips salt and digest through base64url", () =>
    Effect.gen(function*() {
      const hash = yield* hasher.use((_) => _.hash(password))
      const parsed = yield* PasswordHasher.parseHash(hash)
      const segments = hash.split("$")

      assert.strictEqual(Encoding.encodeBase64Url(parsed.salt), segments[2])
      assert.strictEqual(Encoding.encodeBase64Url(parsed.key), segments[3])
      // base64url, not base64: no "+", "/" or padding in the encoded halves,
      // so a hash survives a URL or a header without escaping.
      for (const segment of [segments[2]!, segments[3]!]) {
        assert.match(segment, /^[A-Za-z0-9_-]+$/)
      }
      assert.strictEqual(Result.isSuccess(Encoding.decodeBase64Url(segments[3]!)), true)
    }))

  it.effect("verifies a pbkdf2 hash under the scrypt layer", () =>
    Effect.gen(function*() {
      const hash = yield* Effect.provide(hasher.use((_) => _.hash(password)), pbkdf2)

      assert.strictEqual(hash.startsWith("pbkdf2$"), true)
      assert.strictEqual(yield* hasher.use((_) => _.verify(password, hash)), true)
      assert.strictEqual(yield* hasher.use((_) => _.verify(wrong, hash)), false)
    }))

  it.effect("verifies with the cost the hash was written at, not today's", () =>
    Effect.gen(function*() {
      const legacy = yield* Effect.provide(
        hasher.use((_) => _.hash(password)),
        PasswordHasher.layerScrypt({ N: 512, r: 8, p: 1 }).pipe(Layer.provide(layerWebCrypto))
      )

      assert.strictEqual(legacy.split("$")[1], "n=512,r=8,p=1")
      // Today's layer runs at a different cost and still accepts it.
      assert.strictEqual(yield* hasher.use((_) => _.verify(password, legacy)), true)
    }))

  it.effect("rejects a flipped digest byte", () =>
    Effect.gen(function*() {
      const hash = yield* hasher.use((_) => _.hash(password))
      const parsed = yield* PasswordHasher.parseHash(hash)

      const key = Uint8Array.from(parsed.key)
      key[key.length - 1] = key[key.length - 1]! ^ 0x01
      const tampered = [
        "scrypt",
        "n=1024,r=8,p=1",
        Encoding.encodeBase64Url(parsed.salt),
        Encoding.encodeBase64Url(key)
      ].join("$")

      assert.strictEqual(yield* hasher.use((_) => _.verify(password, tampered)), false)
    }))

  it.effect("rejects a swapped salt", () =>
    Effect.gen(function*() {
      const hash = yield* hasher.use((_) => _.hash(password))
      const parsed = yield* PasswordHasher.parseHash(hash)

      const tampered = [
        "scrypt",
        "n=1024,r=8,p=1",
        Encoding.encodeBase64Url(new Uint8Array(PasswordHasher.saltBytes).fill(7)),
        Encoding.encodeBase64Url(parsed.key)
      ].join("$")

      assert.strictEqual(yield* hasher.use((_) => _.verify(password, tampered)), false)
    }))

  it.effect("rejects downgraded cost parameters", () =>
    Effect.gen(function*() {
      const hash = yield* hasher.use((_) => _.hash(password))
      const downgraded = hash.replace("n=1024,r=8,p=1", "n=2,r=1,p=1")

      assert.strictEqual(yield* hasher.use((_) => _.verify(password, downgraded)), false)
    }))

  it.effect("fails, rather than reporting a wrong password, on an uninterpretable hash", () =>
    Effect.gen(function*() {
      const reasons = yield* Effect.forEach(
        [
          "",
          "not-a-hash",
          "scrypt$n=1024,r=8,p=1$only-three-segments",
          "argon2id$m=65536,t=3,p=4$c2FsdA$a2V5",
          "scrypt$n=1024,r=8,p=1$$YWJjZGVmZ2hpamtsbW5vcA",
          "scrypt$nonsense$c2FsdHNhbHRzYWx0c2FsdA$YWJjZGVmZ2hpamtsbW5vcA",
          "scrypt$n=1024,r=8,p=1$c2FsdHNhbHRzYWx0c2FsdA$c2hvcnQ",
          "scrypt$n=1024,r=8,p=1$c2FsdHNhbHRzYWx0c2FsdA$!!!not-base64!!!",
          "pbkdf2$$c2FsdHNhbHRzYWx0c2FsdA$YWJjZGVmZ2hpamtsbW5vcA"
        ],
        (hash) =>
          Effect.flip(hasher.use((_) => _.verify(password, hash))).pipe(
            Effect.map((error) => error._tag)
          )
      )

      assert.deepStrictEqual(reasons, Array.from({ length: 9 }, () => "PasswordHashError"))
    }))

  it.effect("refuses absurd cost parameters instead of spending them", () =>
    Effect.gen(function*() {
      // A row a database attacker can write decides how much memory and CPU
      // every sign-in attempt against it costs, so the ceilings are refused
      // outright rather than attempted: `n=2^30, r=16` would ask for hundreds
      // of gibibytes of maxmem, once per attempt.
      const absurd = [
        "scrypt$n=1073741824,r=16,p=1$c2FsdHNhbHRzYWx0c2FsdA$YWJjZGVmZ2hpamtsbW5vcA",
        "scrypt$n=1024,r=1024,p=1$c2FsdHNhbHRzYWx0c2FsdA$YWJjZGVmZ2hpamtsbW5vcA",
        "scrypt$n=1024,r=8,p=1024$c2FsdHNhbHRzYWx0c2FsdA$YWJjZGVmZ2hpamtsbW5vcA",
        "pbkdf2$i=9007199254740991$c2FsdHNhbHRzYWx0c2FsdA$YWJjZGVmZ2hpamtsbW5vcA"
      ]

      const reasons = yield* Effect.forEach(
        absurd,
        (hash) =>
          Effect.flip(hasher.use((_) => _.verify(password, hash))).pipe(
            Effect.map((error) => error._tag)
          )
      )
      assert.deepStrictEqual(reasons, Array.from({ length: absurd.length }, () => "PasswordHashError"))

      // The ceilings are generous: a hash written with the production
      // parameters still verifies.
      const production = yield* Effect.result(
        hasher.use((_) => _.verify(password, "scrypt$n=16384,r=16,p=1$c2FsdHNhbHRzYWx0c2FsdA$YWJjZGVmZ2hpamtsbW5vcA"))
      )
      assert.strictEqual(production._tag, "Success")
    }))
})

layer(pbkdf2)("crypto/PasswordHasher (pbkdf2)", (it) => {
  it.effect.prop(
    "round-trips any passphrase, and only that passphrase",
    { text: Schema.String },
    ({ text }) =>
      Effect.gen(function*() {
        const secret = Redacted.make(text)
        const hash = yield* hasher.use((_) => _.hash(secret))

        assert.strictEqual(yield* hasher.use((_) => _.verify(secret, hash)), true)
        assert.strictEqual(yield* hasher.use((_) => _.verify(Redacted.make(`${text}x`), hash)), false)
      }),
    sampled
  )

  it.effect("writes a self-describing hash", () =>
    Effect.gen(function*() {
      const hash = yield* hasher.use((_) => _.hash(password))
      const segments = hash.split("$")

      assert.strictEqual(segments[0], "pbkdf2")
      assert.strictEqual(segments[1], "i=1000")

      const parsed = yield* PasswordHasher.parseHash(hash)
      assert.strictEqual(parsed.salt.length, PasswordHasher.saltBytes)
      assert.strictEqual(parsed.key.length, PasswordHasher.defaultPbkdf2Options.dkLen)
    }))

  it.effect("verifies a scrypt hash under the pbkdf2 layer", () =>
    Effect.gen(function*() {
      const hash = yield* Effect.provide(hasher.use((_) => _.hash(password)), scrypt)

      assert.strictEqual(hash.startsWith("scrypt$"), true)
      assert.strictEqual(yield* hasher.use((_) => _.verify(password, hash)), true)
      assert.strictEqual(yield* hasher.use((_) => _.verify(wrong, hash)), false)
    }))
})

describe("crypto/PasswordHasher", () => {
  // The documented cost needs 32 MiB of working memory, which is exactly
  // Node's default `maxmem`; without an explicit bound `scrypt` throws
  // `ERR_CRYPTO_INVALID_SCRYPT_PARAMS` and every sign-up 500s. This is the
  // only test that pays for real parameters, and it is worth it — so it stays
  // outside the cheap block, on a layer of its own.
  it.effect("works at the documented production cost", () =>
    Effect.gen(function*() {
      const hash = yield* hasher.use((_) => _.hash(password))

      assert.strictEqual(hash.split("$")[1], "n=16384,r=16,p=1")
      assert.strictEqual(yield* hasher.use((_) => _.verify(password, hash)), true)
      assert.strictEqual(yield* hasher.use((_) => _.verify(wrong, hash)), false)
    }).pipe(Effect.provide(PasswordHasher.layerScrypt().pipe(Layer.provide(layerWebCrypto)))))

  it.effect("keeps a parameter named __proto__ off Object.prototype", () =>
    Effect.gen(function*() {
      const parsed = yield* PasswordHasher.parseHash(
        "scrypt$n=1024,r=8,p=1,__proto__=polluted$c2FsdHNhbHRzYWx0c2FsdA$YWJjZGVmZ2hpamtsbW5vcA"
      )

      assert.strictEqual(Object.getPrototypeOf(parsed.params), null)
      assert.strictEqual(Object.hasOwn(parsed.params, "__proto__"), true)
      assert.strictEqual(Object.getPrototypeOf({}), Object.prototype)
    }))

  it("keeps the documented production parameters", () => {
    assert.deepStrictEqual({ ...PasswordHasher.defaultScryptOptions }, { N: 16384, r: 16, p: 1, dkLen: 64 })
    assert.deepStrictEqual({ ...PasswordHasher.defaultPbkdf2Options }, { iterations: 600_000, dkLen: 64 })
    assert.strictEqual(PasswordHasher.saltBytes, 16)
  })

  it("timingSafeEqualUint8 compares every byte regardless of where the difference is", () => {
    const reference = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])

    assert.strictEqual(PasswordHasher.timingSafeEqualUint8(reference, Uint8Array.from(reference)), true)
    assert.strictEqual(
      PasswordHasher.timingSafeEqualUint8(reference, new Uint8Array([9, 2, 3, 4, 5, 6, 7, 8])),
      false
    )
    assert.strictEqual(
      PasswordHasher.timingSafeEqualUint8(reference, new Uint8Array([1, 2, 3, 4, 5, 6, 7, 9])),
      false
    )
    assert.strictEqual(PasswordHasher.timingSafeEqualUint8(reference, reference.slice(0, 7)), false)
    assert.strictEqual(PasswordHasher.timingSafeEqualUint8(new Uint8Array(0), new Uint8Array(0)), true)
  })
})
