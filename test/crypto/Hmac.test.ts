import { assert, it, layer } from "@effect/vitest"
import { Effect, Encoding, Layer, Option, Redacted } from "effect"
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

  it.effect("wraps a payload in the exact envelope the session cookie cache writes", () =>
    Effect.gen(function* () {
      const hmac = yield* Hmac.Hmac
      // `SessionCache.macContext`, copied rather than imported so that this
      // test fails if the module is ever changed to write a different envelope
      // than the one it is about to be rewritten on top of.
      const context = "effect-auth/session-cache/v1\n"
      const json = `{"v":1,"version":"a"}`
      const payload = utf8.encode(json)

      const envelope = yield* hmac.signedValue(context, payload)

      // Exactly what `SessionCache.encode` builds today: base64url of the JSON,
      // a dot, base64url of the tag over the context and the JSON.
      const mac = yield* hmac.sign(utf8.encode(`${context}${json}`))
      assert.strictEqual(
        envelope,
        `${Encoding.encodeBase64Url(json)}${Hmac.signedValueSeparator}${Encoding.encodeBase64Url(mac)}`
      )
    })
  )

  it.effect("reads back what it signed", () =>
    Effect.gen(function* () {
      const hmac = yield* Hmac.Hmac
      const payload = utf8.encode("a snapshot")

      const envelope = yield* hmac.signedValue("ctx/v1\n", payload)
      const opened = yield* hmac.verifySignedValue("ctx/v1\n", envelope)

      assert.strictEqual(Option.isSome(opened), true)
      if (Option.isSome(opened)) assert.deepStrictEqual(Array.from(opened.value), Array.from(payload))
    })
  )

  it.effect("refuses an envelope signed under another context", () =>
    Effect.gen(function* () {
      const hmac = yield* Hmac.Hmac

      // The whole point of the context: a tag this deployment really did
      // produce, over these exact payload bytes, is still not a tag *for* this.
      const envelope = yield* hmac.signedValue("effect-auth/trusted-device/v1\n", utf8.encode("elevate me"))

      assert.strictEqual(Option.isNone(yield* hmac.verifySignedValue("effect-auth/session-cache/v1\n", envelope)), true)
      assert.strictEqual(
        Option.isSome(yield* hmac.verifySignedValue("effect-auth/trusted-device/v1\n", envelope)),
        true
      )
    })
  )

  it.effect("refuses a tampered payload, a tampered tag and anything that is not an envelope", () =>
    Effect.gen(function* () {
      const hmac = yield* Hmac.Hmac
      const context = "ctx/v1\n"
      const envelope = yield* hmac.signedValue(context, utf8.encode("admin=false"))
      const [payload, mac] = envelope.split(".")

      const forged = `${Encoding.encodeBase64Url("admin=true")}.${mac}`
      const flipped = `${payload}.${mac![0] === "A" ? "B" : "A"}${mac!.slice(1)}`

      const rejected = [forged, flipped, payload!, `${payload}.`, `.${mac}`, `${payload}.not+base64url/`, "", "."]
      for (const value of rejected) {
        assert.strictEqual(Option.isNone(yield* hmac.verifySignedValue(context, value)), true, value)
      }
    })
  )

  it.effect("carries a payload that is not text", () =>
    Effect.gen(function* () {
      const hmac = yield* Hmac.Hmac
      const payload = Uint8Array.from([0, 1, 255, 128, 0])

      const opened = yield* hmac.verifySignedValue("ctx/v1\n", yield* hmac.signedValue("ctx/v1\n", payload))

      assert.strictEqual(Option.isSome(opened), true)
      if (Option.isSome(opened)) assert.deepStrictEqual(Array.from(opened.value), Array.from(payload))
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
// of them can be the block's. Both are built directly rather than provided as
// layers, so the two services are unambiguously distinct.
it.effect("crypto/Hmac does not accept a tag made under a different secret", () =>
  Effect.gen(function* () {
    const one = yield* Hmac.make(globalThis.crypto, Redacted.make("secret-one"))
    const two = yield* Hmac.make(globalThis.crypto, Redacted.make("secret-two"))

    const mine = yield* one.sign(message)
    const theirs = yield* two.sign(message)

    assert.notDeepEqual(Array.from(mine), Array.from(theirs))

    const accepted = yield* one.verify(message, theirs)
    assert.strictEqual(accepted, false)
  })
)
