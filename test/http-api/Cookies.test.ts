import { assert, describe, it } from "@effect/vitest"
import { Duration, Effect, Redacted } from "effect"
import { Headers } from "effect/unstable/http"
import * as AuthConfig from "../../src/config/AuthConfig.js"
import * as AuthCookies from "../../src/http/Cookies.js"

/** A deployment over TLS, optionally with the cookie section configured. */
const secure = (cookie?: AuthConfig.AuthConfigOptions["cookie"]): AuthConfig.AuthConfigService =>
  AuthConfig.make({
    baseUrl: "https://app.example.com",
    secret: Redacted.make("test-secret"),
    cookie
  })

const secureConfig = secure()

const devConfig = AuthConfig.make({
  baseUrl: "http://localhost:3000",
  secret: Redacted.make("test-secret")
})

describe("http/Cookies", () => {
  describe("names", () => {
    it("prefixes the cookie with __Secure- on a TLS deployment", () => {
      assert.strictEqual(AuthCookies.sessionCookieName(secureConfig), "__Secure-effect_auth.session")
      assert.strictEqual(AuthCookies.sessionCookieName(secureConfig), AuthCookies.secureSessionCookieName)
    })

    it("leaves the cookie unprefixed on a plain-HTTP deployment", () => {
      assert.strictEqual(AuthCookies.sessionCookieName(devConfig), "effect_auth.session")
      assert.strictEqual(AuthCookies.sessionCookieName(devConfig), AuthCookies.insecureSessionCookieName)
    })

    it("matches the names declared by the security schemes", () => {
      assert.strictEqual(AuthCookies.secureSessionCookieSecurity.key, AuthCookies.secureSessionCookieName)
      assert.strictEqual(AuthCookies.secureSessionCookieSecurity.in, "cookie")
      assert.strictEqual(AuthCookies.insecureSessionCookieSecurity.key, AuthCookies.insecureSessionCookieName)
      assert.strictEqual(AuthCookies.insecureSessionCookieSecurity.in, "cookie")
      assert.strictEqual(AuthCookies.bearerSecurity.scheme, "Bearer")
    })
  })

  describe("attributes", () => {
    it("writes an httpOnly, secure, sameSite=lax cookie over TLS", () => {
      const options = AuthCookies.sessionCookieOptions(secureConfig, { maxAge: Duration.days(7) })

      assert.strictEqual(options.httpOnly, true)
      assert.strictEqual(options.secure, true)
      assert.strictEqual(options.sameSite, "lax")
      assert.strictEqual(options.path, "/")
      assert.strictEqual(options.domain, undefined)
      assert.deepStrictEqual(options.maxAge, Duration.days(7))
    })

    it("never drops httpOnly, whatever the configuration says", () => {
      const options = AuthCookies.sessionCookieOptions(devConfig, { maxAge: Duration.days(1) })

      assert.strictEqual(options.httpOnly, true)
      assert.strictEqual(options.secure, false)
    })

    it("carries a configured path and domain through", () => {
      const config = secure({ path: "/app", domain: ".example.com", sameSite: "strict" })
      const options = AuthCookies.sessionCookieOptions(config, { maxAge: Duration.days(7) })

      assert.strictEqual(options.path, "/app")
      assert.strictEqual(options.domain, ".example.com")
      assert.strictEqual(options.sameSite, "strict")
    })

    it("repeats path and domain when expiring, so the browser replaces the cookie", () => {
      const config = secure({ path: "/app", domain: ".example.com" })
      const set = AuthCookies.sessionCookieOptions(config, { maxAge: Duration.days(7) })
      const expired = AuthCookies.expiredSessionCookieOptions(config)

      assert.strictEqual(expired.path, set.path)
      assert.strictEqual(expired.domain, set.domain)
      assert.strictEqual(expired.sameSite, set.sameSite)
      assert.strictEqual(expired.secure, set.secure)
      assert.strictEqual(expired.httpOnly, true)
      assert.deepStrictEqual(expired.expires, new Date(0))
      assert.strictEqual(expired.maxAge, undefined)
    })
  })

  describe("redaction", () => {
    it.effect("hides the session cookie from a rendered Headers value", () =>
      Effect.gen(function*() {
        const headers = Headers.fromInput({
          cookie: "__Secure-effect_auth.session=super-secret-token",
          authorization: "Bearer super-secret-token",
          "x-request-id": "abc"
        })

        const rendered = JSON.stringify(headers)

        assert.isFalse(rendered.includes("super-secret-token"))
        assert.isTrue(rendered.includes("<redacted>"))
        assert.isTrue(rendered.includes("abc"))
      }).pipe(Effect.provide(AuthCookies.layerRedactedHeaders())))

    it.effect("keeps the auth headers redacted when an application adds its own", () =>
      Effect.gen(function*() {
        const headers = Headers.fromInput({
          cookie: "__Secure-effect_auth.session=super-secret-token",
          "x-tenant-token": "tenant-secret"
        })

        const rendered = JSON.stringify(headers)

        assert.isFalse(rendered.includes("super-secret-token"))
        assert.isFalse(rendered.includes("tenant-secret"))
      }).pipe(Effect.provide(AuthCookies.layerRedactedHeaders(["x-tenant-token"]))))
  })
})
