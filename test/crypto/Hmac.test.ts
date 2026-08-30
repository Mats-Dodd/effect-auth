import { assert, describe, it } from "@effect/vitest"
import { Effect, Encoding, Layer, Redacted } from "effect"
import * as AuthConfig from "../../src/config/AuthConfig.js"
import * as Hmac from "../../src/crypto/Hmac.js"

const configLayer = (secret: string) =>
  AuthConfig.layer({
    baseUrl: "http://localhost:3000",
    secret: Redacted.make(secret)
  })

const hmacLayer = (secret: string) => Hmac.layer.pipe(Layer.provide(configLayer(secret)))

const utf8 = new TextEncoder()
const message = utf8.encode("hello")

describe("crypto/Hmac", () => {
  it.effect("signs deterministically with the configured secret", () =>
    Effect.gen(function*() {
      const hmac = yield* Hmac.Hmac
      const first = yield* hmac.sign(message)
      const second = yield* hmac.sign(message)

      assert.strictEqual(first.length, 32)
      assert.deepStrictEqual(Array.from(first), Array.from(second))
      // Fixed vector: HMAC-SHA-256("test-secret", "hello"), base64url.
      assert.strictEqual(
        Encoding.encodeBase64Url(first),
        "vMiJpAZnyrcV4dwirSgGks9L8cOigO7spg2NvNjkuZM"
      )
    }).pipe(Effect.provide(hmacLayer("test-secret"))))

  it.effect("accepts a tag it produced", () =>
    Effect.gen(function*() {
      const hmac = yield* Hmac.Hmac
      const mac = yield* hmac.sign(message)

      assert.strictEqual(yield* hmac.verify(message, mac), true)
    }).pipe(Effect.provide(hmacLayer("test-secret"))))

  it.effect("rejects a tampered message", () =>
    Effect.gen(function*() {
      const hmac = yield* Hmac.Hmac
      const mac = yield* hmac.sign(message)

      assert.strictEqual(yield* hmac.verify(utf8.encode("hellp"), mac), false)
      assert.strictEqual(yield* hmac.verify(utf8.encode("hello "), mac), false)
      assert.strictEqual(yield* hmac.verify(new Uint8Array(0), mac), false)
    }).pipe(Effect.provide(hmacLayer("test-secret"))))

  it.effect("rejects a tampered tag, including a truncated one", () =>
    Effect.gen(function*() {
      const hmac = yield* Hmac.Hmac
      const mac = yield* hmac.sign(message)

      const flipped = Uint8Array.from(mac)
      flipped[0] = flipped[0]! ^ 0x01
      assert.strictEqual(yield* hmac.verify(message, flipped), false)

      const truncated = mac.slice(0, 16)
      assert.strictEqual(yield* hmac.verify(message, truncated), false)

      assert.strictEqual(yield* hmac.verify(message, new Uint8Array(32)), false)
    }).pipe(Effect.provide(hmacLayer("test-secret"))))

  it.effect("does not accept a tag made under a different secret", () =>
    Effect.gen(function*() {
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
    }))
})
