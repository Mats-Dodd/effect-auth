import { assert, describe, it } from "@effect/vitest"
import { DateTime, Duration, Effect, Redacted, Schema } from "effect"
import * as AuthConfig from "../src/config/AuthConfig.js"
import { changeEmailVerifyUrl, deleteAccountUrl, verifyEmailUrl } from "../src/config/AuthEmails.js"
import { InvalidCredentials, PasswordPolicyViolation } from "../src/domain/Errors.js"
import { normalizeEmail, scopesOf, Session, User } from "../src/domain/Schema.js"
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
    Effect.gen(function* () {
      const user = yield* Schema.decodeEffect(User)(userEncoded)

      assert.strictEqual(user.name, "Ada Lovelace")
      assert.strictEqual(user.email, "ada@example.com")
      assert.strictEqual(user.emailVerified, true)
      assert.strictEqual(user.image, null)
      assert.strictEqual(DateTime.formatIso(user.createdAt), "2024-01-01T00:00:00.000Z")

      const encoded = yield* Schema.encodeEffect(User)(user)
      assert.deepStrictEqual(encoded, userEncoded)
    })
  )

  it.effect("builds an insert row with a generated id and timestamps", () =>
    Effect.gen(function* () {
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
    })
  )

  it.effect("keeps the session token hash out of the JSON variant", () =>
    Effect.gen(function* () {
      const session = yield* Schema.decodeEffect(Session)({
        id: "0193f6f0-0000-7000-8000-000000000002",
        tokenHash: "R6dLdCTLmDbLDGe3AMv1M4L2GcTF7bpx6bnO2vFO8lM",
        userId: "0193f6f0-0000-7000-8000-000000000001",
        expiresAt: "2024-01-08T00:00:00.000Z",
        ipAddress: null,
        userAgent: null,
        rememberMe: true,
        createdAt: "2024-01-01T00:00:00.000Z",
        updatedAt: "2024-01-01T00:00:00.000Z"
      })

      assert.strictEqual(session.tokenHash, "R6dLdCTLmDbLDGe3AMv1M4L2GcTF7bpx6bnO2vFO8lM")

      const json = yield* Schema.encodeEffect(Session.json)(session)
      assert.strictEqual(Object.hasOwn(json, "tokenHash"), false)
      assert.strictEqual(Object.hasOwn(json, "id"), true)
    })
  )

  it("normalizes e-mail addresses", () => {
    assert.strictEqual(normalizeEmail("  Ada@Example.COM "), "ada@example.com")
  })
})

describe("domain/Errors", () => {
  it.effect("encodes a tagged error", () =>
    Effect.gen(function* () {
      const error = PasswordPolicyViolation.make({ reason: "TooShort", minLength: 8, maxLength: 128 })
      const encoded = yield* Schema.encodeEffect(PasswordPolicyViolation)(error)

      assert.deepStrictEqual(encoded, {
        _tag: "PasswordPolicyViolation",
        reason: "TooShort",
        minLength: 8,
        maxLength: 128
      })

      const decoded = yield* Schema.decodeEffect(PasswordPolicyViolation)(encoded)
      assert.strictEqual(Schema.is(PasswordPolicyViolation)(decoded), true)
      assert.strictEqual(decoded.reason, "TooShort")
    })
  )

  it.effect("is yieldable as a typed failure", () =>
    Effect.gen(function* () {
      const failure = yield* Effect.flip(Effect.fail(InvalidCredentials.make()))
      assert.strictEqual(failure._tag, "InvalidCredentials")
    })
  )
})

describe("domain/Schema.scopesOf", () => {
  it("splits a stored scope column on whatever the provider separated it with", () => {
    // OAuth 2.0 says spaces; several providers send commas anyway, and at least
    // one sends both.
    assert.deepStrictEqual(scopesOf("read:user user:email"), ["read:user", "user:email"])
    assert.deepStrictEqual(scopesOf("openid,email,profile"), ["openid", "email", "profile"])
    assert.deepStrictEqual(scopesOf("openid, email\tprofile"), ["openid", "email", "profile"])
  })

  it("reads an absent or empty column as no scopes at all", () => {
    assert.deepStrictEqual(scopesOf(null), [])
    assert.deepStrictEqual(scopesOf(""), [])
    assert.deepStrictEqual(scopesOf("  ,  "), [])
  })
})

describe("config/AuthConfig", () => {
  it("applies the documented defaults", () => {
    const config = AuthConfig.make({
      baseUrl: "https://app.example.com",
      secret: Redacted.make("test-secret-at-least-32-bytes-long"),
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

    // The two flows a deployment opts into, and the lifetimes of the links they
    // send. Off by default: neither is served unless it is asked for.
    assert.strictEqual(config.user.changeEmail.enabled, false)
    assert.strictEqual(config.user.deleteUser.enabled, false)
    assert.strictEqual(config.user.deleteUser.confirmByEmail, false)
    assert.strictEqual(Duration.toMillis(config.tokens.changeEmailTtl), 60 * 60 * 1000)
    assert.strictEqual(Duration.toMillis(config.tokens.deleteAccountTtl), 24 * 60 * 60 * 1000)
    assert.strictEqual(config.emailPaths.changeEmailConfirm, "/auth/change-email/confirm")
    assert.strictEqual(config.emailPaths.changeEmailVerify, "/auth/change-email/verify")
    assert.strictEqual(config.emailPaths.deleteAccount, "/auth/delete-user/callback")
  })

  it("resolves one field of a user sub-section without losing the other", () => {
    // `user` is a section of sections, so it is not resolved wholesale: stating
    // `confirmByEmail` alone must not silently switch `enabled` back off.
    const config = AuthConfig.make({
      baseUrl: "http://localhost:3000",
      secret: Redacted.make("test-secret-at-least-32-bytes-long"),
      user: { deleteUser: { confirmByEmail: true }, changeEmail: { enabled: true } }
    })

    assert.strictEqual(config.user.deleteUser.confirmByEmail, true)
    assert.strictEqual(config.user.deleteUser.enabled, false)
    assert.strictEqual(config.user.changeEmail.enabled, true)
  })

  it("leaves cookies insecure on a plain-http base url", () => {
    const config = AuthConfig.make({
      baseUrl: "http://localhost:3000",
      secret: Redacted.make("test-secret-at-least-32-bytes-long")
    })

    assert.strictEqual(config.cookie.secure, false)
    assert.strictEqual(AuthConfig.cookieName(config), "effect_auth.session")
  })

  it("ignores explicitly undefined overrides", () => {
    const config = AuthConfig.make({
      baseUrl: "http://localhost:3000",
      secret: Redacted.make("test-secret-at-least-32-bytes-long"),
      session: { expiresIn: undefined }
    })

    assert.strictEqual(Duration.toMillis(config.session.expiresIn), 7 * 24 * 60 * 60 * 1000)
  })
})

describe("config/AuthEmails", () => {
  it("keeps the token redacted inside the link", () => {
    const config = AuthConfig.make({
      baseUrl: "https://app.example.com",
      secret: Redacted.make("test-secret-at-least-32-bytes-long")
    })
    const url = verifyEmailUrl(config, Redacted.make("tok3n"))

    // `Redacted` prints as `<redacted>`, which is what keeps an accidental log
    // line from carrying the link. It gets `toString` from `Inspectable` at
    // runtime but does not declare one in its type, so the type-aware rule sees
    // `Object.prototype.toString`; that rendering is exactly the assertion.
    // oxlint-disable-next-line typescript/no-base-to-string
    assert.strictEqual(String(url), "<redacted>")
    assert.strictEqual(Redacted.value(url), "https://app.example.com/auth/verify-email?token=tok3n")
  })

  it("keeps the proposed address out of the change-email link", () => {
    const config = AuthConfig.make({
      baseUrl: "https://app.example.com",
      secret: Redacted.make("test-secret-at-least-32-bytes-long")
    })
    const url = Redacted.value(changeEmailVerifyUrl(config, Redacted.make("tok3n")))

    // The new address travels in the token's server-side payload. A link that
    // named it could be edited into one that moves the account elsewhere.
    assert.strictEqual(url, "https://app.example.com/auth/change-email/verify?token=tok3n")
    assert.isFalse(url.includes("@"))

    assert.strictEqual(
      Redacted.value(deleteAccountUrl(config, Redacted.make("tok3n"))),
      "https://app.example.com/auth/delete-user/callback?token=tok3n"
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
