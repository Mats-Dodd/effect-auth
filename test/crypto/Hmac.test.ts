import { assert, it, layer } from "@effect/vitest"
import { Effect, Encoding, Layer, Redacted } from "effect"
import * as Hmac from "../../src/crypto/Hmac.js"

const hmacLayer = (secret: string): Layer.Layer<Hmac.Hmac> =>
  Layer.effect(Hmac.Hmac, Hmac.make(globalThis.crypto, Redacted.make(secret)))

const utf8 = new TextEncoder()
const message = utf8.encode("hello")

layer(hmacLayer("test-secret"))("crypto/Hmac", (it) => {
  it.effect("signs deterministically with the configured secret", () =>
    Effect.gen(function* () {
      const hmac = yield* Hmac.Hmac
      const first = yield* hmac.sign(message)
      const second = yield* hmac.sign(message)

      assert.strictEqual(first.length, 32)
      assert.deepStrictEqual(Array.from(first), Array.from(second))
      // Fixed vector: HMAC-SHA-256("test-secret", "hello"), base64url.
      assert.strictEqual(Encoding.encodeBase64Url(first), "vMiJpAZnyrcV4dwirSgGks9L8cOigO7spg2NvNjkuZM")
    })
  )

  it.effect("accepts a tag it produced", () =>
    Effect.gen(function* () {
      const hmac = yield* Hmac.Hmac
      const mac = yield* hmac.sign(message)

      assert.strictEqual(yield* hmac.verify(message, mac), true)
    })
  )

  it.effect("rejects a tampered message", () =>
    Effect.gen(function* () {
      const hmac = yield* Hmac.Hmac
      const mac = yield* hmac.sign(message)

      assert.strictEqual(yield* hmac.verify(utf8.encode("hellp"), mac), false)
      assert.strictEqual(yield* hmac.verify(utf8.encode("hello "), mac), false)
      assert.strictEqual(yield* hmac.verify(new Uint8Array(0), mac), false)
    })
  )

  it.effect("rejects a tampered tag, including a truncated one", () =>
    Effect.gen(function* () {
      const hmac = yield* Hmac.Hmac
      const mac = yield* hmac.sign(message)

      const flipped = Uint8Array.from(mac)
      flipped[0] = flipped[0]! ^ 0x01
      assert.strictEqual(yield* hmac.verify(message, flipped), false)

      const truncated = mac.slice(0, 16)
      assert.strictEqual(yield* hmac.verify(message, truncated), false)

      assert.strictEqual(yield* hmac.verify(message, new Uint8Array(32)), false)
    })
  )
})

// Outside the block on purpose: two secrets is the whole assertion, so neither
// of them can be the block's.
it.effect("crypto/Hmac does not accept a tag made under a different secret", () =>
  Effect.gen(function* () {
    const mine = yield* Effect.provide(
      Hmac.Hmac.use((hmac) => hmac.sign(message)),
      hmacLayer("secret-one")
    )
    const theirs = yield* Effect.provide(
      Hmac.Hmac.use((hmac) => hmac.sign(message)),
      hmacLayer("secret-two")
    )

    assert.notDeepEqual(Array.from(mine), Array.from(theirs))

    const accepted = yield* Effect.provide(
      Hmac.Hmac.use((hmac) => hmac.verify(message, theirs)),
      hmacLayer("secret-one")
    )
    assert.strictEqual(accepted, false)
  })
)
