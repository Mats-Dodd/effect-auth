import { assert, it } from "@effect/vitest"
import { Effect, Exit, Redacted } from "effect"
import { make } from "../../src/internal/providerTokenCipher.js"

const secret = Redacted.make("provider-token-cipher-test-secret-32-bytes")

it.effect("crypto/ProviderTokenCipher authenticates ciphertext and its storage location", () =>
  Effect.gen(function*() {
    const cipher = yield* make(secret)
    const encrypted = yield* cipher.encrypt("account-a", "access_token", "provider-secret")

    assert.match(encrypted, /^v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/)
    assert.notStrictEqual(encrypted, "provider-secret")
    assert.strictEqual(
      yield* cipher.decrypt("account-a", "access_token", encrypted),
      "provider-secret"
    )

    const copiedToAnotherAccount = yield* Effect.exit(
      cipher.decrypt("account-b", "access_token", encrypted)
    )
    const copiedToAnotherField = yield* Effect.exit(
      cipher.decrypt("account-a", "refresh_token", encrypted)
    )

    assert.strictEqual(Exit.isFailure(copiedToAnotherAccount), true)
    assert.strictEqual(Exit.isFailure(copiedToAnotherField), true)
  }))

it.effect("crypto/ProviderTokenCipher rejects modified and legacy plaintext values", () =>
  Effect.gen(function*() {
    const cipher = yield* make(secret)
    const encrypted = yield* cipher.encrypt("account-a", "id_token", "provider-secret")
    const [version, iv, ciphertext] = encrypted.split(".")
    const tampered = `${version}.${iv}.${ciphertext![0] === "A" ? "B" : "A"}${ciphertext!.slice(1)}`

    assert.strictEqual(
      Exit.isFailure(yield* Effect.exit(cipher.decrypt("account-a", "id_token", tampered))),
      true
    )
    assert.strictEqual(
      Exit.isFailure(yield* Effect.exit(cipher.decrypt("account-a", "id_token", "provider-secret"))),
      true
    )
  }))
