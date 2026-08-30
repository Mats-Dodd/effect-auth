import { assert, describe, it } from "@effect/vitest"
import { DateTime, Duration, Effect, Redacted, Schema } from "effect"
import * as AuthConfig from "../src/config/AuthConfig.js"
import { verifyEmailUrl } from "../src/config/AuthEmails.js"
import { InvalidCredentials, PasswordPolicyViolation } from "../src/domain/Errors.js"
import { normalizeEmail, Session, User } from "../src/domain/Schema.js"
import { timingSafeEqualUint8 } from "../src/crypto/PasswordHasher.js"

const userEncoded = {
  id: "0193f6f0-0000-7000-8000-000000000001",
  name: "Ada Lovelace",
  email: "ada@example.com",
  emailVerified: true,
  image: null,
  createdAt: "2024-01-01T00:00:00.000Z",
  updatedAt: "2024-01-02T00:00:00.000Z"
}

describe("domain/Schema", () => {
  it.effect("round-trips a User", () =>
    Effect.gen(function*() {
      const user = yield* Schema.decodeEffect(User)(userEncoded)

      assert.strictEqual(user.name, "Ada Lovelace")
      assert.strictEqual(user.email, "ada@example.com")
      assert.strictEqual(user.emailVerified, true)
      assert.strictEqual(user.image, null)
      assert.strictEqual(DateTime.formatIso(user.createdAt), "2024-01-01T00:00:00.000Z")

      const encoded = yield* Schema.encodeEffect(User)(user)
      assert.deepStrictEqual(encoded, userEncoded)
    }))

  it.effect("builds an insert row with a generated id and timestamps", () =>
    Effect.gen(function*() {
      const row = yield* User.insert.makeEffect({
        name: "Ada Lovelace",
        email: "ada@example.com",
        emailVerified: false,
        image: null
      })

      // UUIDv7: version nibble is 7
      assert.strictEqual(row.id.length, 36)
      assert.strictEqual(row.id[14], "7")
      assert.strictEqual(DateTime.isUtc(row.createdAt), true)
      assert.strictEqual(DateTime.isUtc(row.updatedAt), true)
    }))

  it.effect("keeps the session token hash out of the JSON variant", () =>
    Effect.gen(function*() {
      const session = yield* Schema.decodeEffect(Session)({
        id: "0193f6f0-0000-7000-8000-000000000002",
        tokenHash: "R6dLdCTLmDbLDGe3AMv1M4L2GcTF7bpx6bnO2vFO8lM",
        userId: "0193f6f0-0000-7000-8000-000000000001",
        expiresAt: "2024-01-08T00:00:00.000Z",
        ipAddress: null,
        userAgent: null,
        createdAt: "2024-01-01T00:00:00.000Z",
        updatedAt: "2024-01-01T00:00:00.000Z"
      })

      assert.strictEqual(session.tokenHash, "R6dLdCTLmDbLDGe3AMv1M4L2GcTF7bpx6bnO2vFO8lM")

      const json = yield* Schema.encodeEffect(Session.json)(session)
      assert.strictEqual(Object.hasOwn(json, "tokenHash"), false)
      assert.strictEqual(Object.hasOwn(json, "id"), true)
    }))

  it("normalizes e-mail addresses", () => {
    assert.strictEqual(normalizeEmail("  Ada@Example.COM "), "ada@example.com")
  })
})

describe("domain/Errors", () => {
  it.effect("encodes a tagged error", () =>
    Effect.gen(function*() {
      const error = new PasswordPolicyViolation({ reason: "TooShort", minLength: 8, maxLength: 128 })
      const encoded = yield* Schema.encodeEffect(PasswordPolicyViolation)(error)

      assert.deepStrictEqual(encoded, {
        _tag: "PasswordPolicyViolation",
        reason: "TooShort",
        minLength: 8,
        maxLength: 128
      })

      const decoded = yield* Schema.decodeEffect(PasswordPolicyViolation)(encoded)
      assert.strictEqual(decoded instanceof PasswordPolicyViolation, true)
      assert.strictEqual(decoded.reason, "TooShort")
    }))

  it.effect("is yieldable as a typed failure", () =>
    Effect.gen(function*() {
      const failure = yield* Effect.flip(Effect.fail(new InvalidCredentials()))
      assert.strictEqual(failure._tag, "InvalidCredentials")
    }))
})

describe("config/AuthConfig", () => {
  it("applies the documented defaults", () => {
    const config = AuthConfig.make({
      baseUrl: "https://app.example.com",
      secret: Redacted.make("test-secret"),
      emailPassword: { enabled: true }
    })

    assert.strictEqual(config.basePath, "/auth")
    assert.strictEqual(config.emailPassword.enabled, true)
    assert.strictEqual(config.emailPassword.minPasswordLength, 8)
    assert.strictEqual(config.emailPassword.maxPasswordLength, 128)
    assert.strictEqual(config.emailPassword.requireEmailVerification, false)
    assert.strictEqual(Duration.toMillis(config.session.expiresIn), 7 * 24 * 60 * 60 * 1000)
    assert.strictEqual(config.cookie.secure, true)
    assert.strictEqual(AuthConfig.cookieName(config), "__Secure-effect_auth.session")
  })

  it("leaves cookies insecure on a plain-http base url", () => {
    const config = AuthConfig.make({
      baseUrl: "http://localhost:3000",
      secret: Redacted.make("test-secret")
    })

    assert.strictEqual(config.cookie.secure, false)
    assert.strictEqual(AuthConfig.cookieName(config), "effect_auth.session")
  })

  it("ignores explicitly undefined overrides", () => {
    const config = AuthConfig.make({
      baseUrl: "http://localhost:3000",
      secret: Redacted.make("test-secret"),
      session: { expiresIn: undefined }
    })

    assert.strictEqual(Duration.toMillis(config.session.expiresIn), 7 * 24 * 60 * 60 * 1000)
  })
})

describe("config/AuthEmails", () => {
  it("keeps the token redacted inside the link", () => {
    const config = AuthConfig.make({
      baseUrl: "https://app.example.com",
      secret: Redacted.make("test-secret")
    })
    const url = verifyEmailUrl(config, Redacted.make("tok3n"))

    assert.strictEqual(String(url), "<redacted>")
    assert.strictEqual(
      Redacted.value(url),
      "https://app.example.com/auth/verify-email?token=tok3n"
    )
  })
})

describe("crypto/PasswordHasher", () => {
  it("compares digests without short-circuiting", () => {
    const a = new Uint8Array([1, 2, 3, 4])
    assert.strictEqual(timingSafeEqualUint8(a, new Uint8Array([1, 2, 3, 4])), true)
    assert.strictEqual(timingSafeEqualUint8(a, new Uint8Array([1, 2, 3, 5])), false)
    assert.strictEqual(timingSafeEqualUint8(a, new Uint8Array([1, 2, 3])), false)
  })
})
