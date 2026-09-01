import { assert, layer } from "@effect/vitest"
import { Effect, Layer, Redacted } from "effect"
import * as AuthConfig from "../../src/config/AuthConfig.js"
import { AuthCipher, layer as cipherLayer, make } from "../../src/crypto/Cipher.js"

const utf8 = new TextEncoder()

const config = AuthConfig.layer({
  baseUrl: "https://app.example.com",
  secret: Redacted.make("cipher-test-secret-at-least-32-bytes-long"),
  emailPassword: { enabled: true }
})

const totpKeyInfo = "effect-auth/test/totp-secret/v1"

layer(cipherLayer(totpKeyInfo).pipe(Layer.provideMerge(config)))("crypto/Cipher", (it) => {
  it.effect("round-trips a secret and binds it to where it is stored", () =>
    Effect.gen(function* () {
      const cipher = yield* AuthCipher
      const secret = Redacted.make("a-totp-shared-secret")

      const encrypted = yield* cipher.encrypt(secret, "authenticator:1")
      assert.match(encrypted, /^v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/)
      assert.strictEqual(encrypted.includes("a-totp-shared-secret"), false)

      const decrypted = yield* cipher.decryptText(encrypted, "authenticator:1")
      assert.strictEqual(Redacted.value(decrypted), "a-totp-shared-secret")

      // The same plaintext twice is two ciphertexts: the nonce is fresh, so a
      // dump does not say which two rows hold the same secret.
      const again = yield* cipher.encrypt(secret, "authenticator:1")
      assert.notStrictEqual(again, encrypted)
    })
  )

  it.effect("carries bytes as bytes", () =>
    Effect.gen(function* () {
      const cipher = yield* AuthCipher
      const secret = utf8.encode("12345678901234567890")

      const encrypted = yield* cipher.encrypt(Redacted.make(secret), "authenticator:2")
      const decrypted = yield* cipher.decrypt(encrypted, "authenticator:2")

      assert.deepStrictEqual(Array.from(Redacted.value(decrypted)), Array.from(secret))
    })
  )

  it.effect("refuses a ciphertext moved to another row", () =>
    Effect.gen(function* () {
      const cipher = yield* AuthCipher
      const encrypted = yield* cipher.encrypt(Redacted.make("secret"), "authenticator:1")

      const moved = yield* Effect.flip(cipher.decryptText(encrypted, "authenticator:2"))
      assert.strictEqual(moved._tag, "CipherError")
    })
  )

  it.effect("refuses a tampered, truncated or malformed envelope", () =>
    Effect.gen(function* () {
      const cipher = yield* AuthCipher
      const encrypted = yield* cipher.encrypt(Redacted.make("secret"), "authenticator:1")
      const [version, iv, ciphertext] = encrypted.split(".")

      const tampered = `${version}.${iv}.${ciphertext![0] === "A" ? "B" : "A"}${ciphertext!.slice(1)}`
      const shortIv = `${version}.${iv!.slice(1)}.${ciphertext}`

      for (const bad of [tampered, shortIv, `v2.${iv}.${ciphertext}`, `${iv}.${ciphertext}`, "secret", ""]) {
        const failed = yield* Effect.flip(cipher.decryptText(bad, "authenticator:1"))
        assert.strictEqual(failed._tag, "CipherError", bad)
      }
    })
  )

  it.effect("gives a different class of secret a different key", () =>
    Effect.gen(function* () {
      const cipher = yield* AuthCipher
      const other = yield* make("effect-auth/test/other-secret/v1")

      const encrypted = yield* cipher.encrypt(Redacted.make("secret"), "authenticator:1")

      // Same deployment secret, same AAD, different HKDF info: the ciphertext
      // of one class is not readable by the other, which is what stops a leaked
      // TOTP secret being decrypted as an OAuth token and the other way round.
      const crossed = yield* Effect.flip(other.decryptText(encrypted, "authenticator:1"))
      assert.strictEqual(crossed._tag, "CipherError")

      const own = yield* other.encrypt(Redacted.make("secret"), "authenticator:1")
      assert.strictEqual(Redacted.value(yield* other.decryptText(own, "authenticator:1")), "secret")
    })
  )

  it.effect("keeps the plaintext out of anything that gets logged", () =>
    Effect.gen(function* () {
      const cipher = yield* AuthCipher
      const encrypted = yield* cipher.encrypt(Redacted.make("shared-secret"), "authenticator:1")
      const decrypted = yield* cipher.decryptText(encrypted, "authenticator:1")

      assert.strictEqual(String(decrypted), "<redacted>")
    })
  )
})
