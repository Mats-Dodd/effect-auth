import { assert, describe, it, layer } from "@effect/vitest"
import { Duration, Effect, Redacted } from "effect"
import { Headers } from "effect/unstable/http"
import * as AuthConfig from "../../src/config/AuthConfig.js"
import * as AuthCookies from "../../src/http/Cookies.js"

/** A deployment over TLS, optionally with the cookie section configured. */
const secure = (cookie?: AuthConfig.AuthConfigOptions["cookie"]): AuthConfig.AuthConfigService =>
  AuthConfig.make({
    baseUrl: "https://app.example.com",
    secret: Redacted.make("test-secret-at-least-32-bytes-long"),
    cookie
  })

const secureConfig = secure()

const devConfig = AuthConfig.make({
  baseUrl: "http://localhost:3000",
  secret: Redacted.make("test-secret-at-least-32-bytes-long")
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

    it("names the cookie cache beside the session, under the same prefix rule", () => {
      assert.strictEqual(AuthCookies.insecureSessionCacheCookieName, "effect_auth.session_data")
      assert.strictEqual(AuthCookies.secureSessionCacheCookieName, "__Secure-effect_auth.session_data")

      assert.strictEqual(AuthCookies.sessionCacheCookieName(secureConfig), AuthCookies.secureSessionCacheCookieName)
      assert.strictEqual(AuthCookies.sessionCacheCookieName(devConfig), AuthCookies.insecureSessionCacheCookieName)

      // Two cookies, never one name for both: the session cookie is the
      // credential and the cache cookie is a snapshot signed against it.
      assert.notStrictEqual(AuthCookies.sessionCacheCookieName(devConfig), AuthCookies.sessionCookieName(devConfig))
    })

    it("writes the cache cookie under the scheme its own name comes from", () => {
      // Not a credential and not declared by any middleware: the scheme exists
      // only because `securitySetCookie` takes the cookie's name from one.
      assert.strictEqual(AuthCookies.secureSessionCacheCookieSecurity.key, AuthCookies.secureSessionCacheCookieName)
      assert.strictEqual(AuthCookies.secureSessionCacheCookieSecurity.in, "cookie")
      assert.strictEqual(AuthCookies.insecureSessionCacheCookieSecurity.key, AuthCookies.insecureSessionCacheCookieName)
      assert.strictEqual(
        AuthCookies.sessionCacheCookieSecurity(secureConfig).key,
        AuthCookies.secureSessionCacheCookieName
      )
      assert.strictEqual(
        AuthCookies.sessionCacheCookieSecurity(devConfig).key,
        AuthCookies.insecureSessionCacheCookieName
      )
    })

    it("names the OAuth state-binding cookie __Host- prefixed over TLS", () => {
      assert.strictEqual(AuthCookies.insecureOAuthStateCookieName, "effect_auth.oauth_state")
      // __Host-, not __Secure-: host-bound, so a sibling subdomain cannot toss a
      // Domain-scoped state cookie of the same name.
      assert.strictEqual(AuthCookies.secureOAuthStateCookieName, "__Host-effect_auth.oauth_state")

      assert.strictEqual(AuthCookies.oauthStateCookieName(secureConfig), AuthCookies.secureOAuthStateCookieName)
      assert.strictEqual(AuthCookies.oauthStateCookieName(devConfig), AuthCookies.insecureOAuthStateCookieName)

      // A cookie of its own, distinct from the session and the cache.
      assert.notStrictEqual(AuthCookies.oauthStateCookieName(devConfig), AuthCookies.sessionCookieName(devConfig))
    })

    it("writes the OAuth state cookie under the scheme its own name comes from", () => {
      assert.strictEqual(AuthCookies.secureOAuthStateCookieSecurity.key, AuthCookies.secureOAuthStateCookieName)
      assert.strictEqual(AuthCookies.secureOAuthStateCookieSecurity.in, "cookie")
      assert.strictEqual(AuthCookies.insecureOAuthStateCookieSecurity.key, AuthCookies.insecureOAuthStateCookieName)
      assert.strictEqual(AuthCookies.oauthStateCookieSecurity(secureConfig).key, AuthCookies.secureOAuthStateCookieName)
      assert.strictEqual(AuthCookies.oauthStateCookieSecurity(devConfig).key, AuthCookies.insecureOAuthStateCookieName)
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

    it("gives the cache cookie the session cookie's attributes and its own lifetime", () => {
      // One helper writes both, so a snapshot is `httpOnly` and `Secure`
      // wherever the credential beside it is — and only its `Max-Age` differs.
      const config = secure({ path: "/app", domain: ".example.com" })
      const session = AuthCookies.sessionCookieOptions(config, { maxAge: Duration.days(7) })
      const snapshot = AuthCookies.sessionCookieOptions(config, { maxAge: Duration.minutes(5) })

      assert.deepStrictEqual({ ...snapshot, maxAge: undefined }, { ...session, maxAge: undefined })
      assert.strictEqual(snapshot.httpOnly, true)
      assert.deepStrictEqual(snapshot.maxAge, Duration.minutes(5))
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

    it("pins the OAuth state cookie to Path=/ with no Domain, never Strict", () => {
      // The __Host- prefix requires Path=/ and no Domain, and a cross-site
      // top-level GET callback would not ride a `Strict` cookie — so neither
      // `cookie.path`/`cookie.domain` nor a deployment's `strict` reaches it.
      const config = secure({ sameSite: "strict", path: "/app", domain: ".example.com" })
      const options = AuthCookies.oauthStateCookieOptions(config, { maxAge: Duration.minutes(10) })

      assert.strictEqual(options.sameSite, "lax")
      assert.strictEqual(options.httpOnly, true)
      assert.strictEqual(options.secure, true)
      assert.strictEqual(options.path, "/")
      assert.strictEqual(options.domain, undefined)
      assert.deepStrictEqual(options.maxAge, Duration.minutes(10))
    })

    it("follows a sameSite=none deployment so the cross-site cookie is stored", () => {
      // A `none` frontend on a different site than the auth server makes
      // `signInSocial` cross-site; a browser rejects a `SameSite=Lax`
      // `Set-Cookie` there, so the state cookie must be `SameSite=None`.
      const config = secure({ sameSite: "none" })
      const options = AuthCookies.oauthStateCookieOptions(config, { maxAge: Duration.minutes(10) })

      assert.strictEqual(options.sameSite, "none")
      assert.strictEqual(options.secure, true)
    })

    it("repeats Path=/ and no Domain when expiring the OAuth state cookie", () => {
      const config = secure({ path: "/app", domain: ".example.com" })
      const set = AuthCookies.oauthStateCookieOptions(config, { maxAge: Duration.minutes(10) })
      const expired = AuthCookies.expiredOAuthStateCookieOptions(config)

      assert.strictEqual(expired.path, set.path)
      assert.strictEqual(expired.path, "/")
      assert.strictEqual(expired.domain, set.domain)
      assert.strictEqual(expired.domain, undefined)
      assert.strictEqual(expired.sameSite, "lax")
      assert.strictEqual(expired.secure, set.secure)
      assert.strictEqual(expired.httpOnly, true)
      assert.deepStrictEqual(expired.expires, new Date(0))
      assert.strictEqual(expired.maxAge, undefined)
    })
  })

  describe("plugin cookies", () => {
    const pending = { baseName: "effect_auth.pending", hostOnly: true, maxAge: Duration.minutes(10) } as const
    const banner = { baseName: "effect_auth.banner", hostOnly: false, maxAge: Duration.minutes(10) } as const

    it("prefixes a host-only cookie __Host- over TLS and leaves it bare on plain HTTP", () => {
      assert.strictEqual(AuthCookies.pluginCookieFor(secureConfig, pending).name, "__Host-effect_auth.pending")
      assert.strictEqual(AuthCookies.pluginCookieFor(devConfig, pending).name, "effect_auth.pending")
    })

    it("prefixes a cookie that is not host-only __Secure- instead", () => {
      assert.strictEqual(AuthCookies.pluginCookieFor(secureConfig, banner).name, "__Secure-effect_auth.banner")
      assert.strictEqual(AuthCookies.pluginCookieFor(devConfig, banner).name, "effect_auth.banner")
    })

    it("decides a host-only cookie exactly as the OAuth state cookie is decided", () => {
      // The one cookie this library already writes under these rules. If the
      // helper and the hand-written original ever disagree, one of them is
      // wrong, and this is the assertion that says so.
      const options = { baseName: AuthCookies.oauthStateCookieBaseName, hostOnly: true, maxAge: Duration.minutes(10) }

      for (const config of [secureConfig, devConfig]) {
        const derived = AuthCookies.pluginCookieFor(config, options)

        assert.strictEqual(derived.name, AuthCookies.oauthStateCookieName(config))
        assert.deepStrictEqual(
          derived.options,
          AuthCookies.oauthStateCookieOptions(config, { maxAge: Duration.minutes(10) })
        )
        assert.deepStrictEqual(derived.expiredOptions, AuthCookies.expiredOAuthStateCookieOptions(config))
        assert.strictEqual(derived.security.key, AuthCookies.oauthStateCookieSecurity(config).key)
      }
    })

    it("pins a host-only cookie to Path=/ and no Domain, whatever the deployment configured", () => {
      // What the `__Host-` prefix requires of the browser. A configured path or
      // domain would make the browser reject the cookie outright.
      const config = secure({ path: "/app", domain: ".example.com" })
      const derived = AuthCookies.pluginCookieFor(config, pending)

      assert.strictEqual(derived.options.path, "/")
      assert.strictEqual(derived.options.domain, undefined)
      assert.strictEqual(derived.expiredOptions.path, "/")
      assert.strictEqual(derived.expiredOptions.domain, undefined)
    })

    it("carries the deployment's path and domain on a cookie that is not host-only", () => {
      const config = secure({ path: "/app", domain: ".example.com" })
      const derived = AuthCookies.pluginCookieFor(config, banner)

      assert.strictEqual(derived.options.path, "/app")
      assert.strictEqual(derived.options.domain, ".example.com")
      // The session cookie's own attributes, for the same configuration.
      const session = AuthCookies.sessionCookieOptions(config, { maxAge: Duration.minutes(10) })
      assert.strictEqual(derived.options.path, session.path)
      assert.strictEqual(derived.options.domain, session.domain)
    })

    it("caps sameSite away from strict, and follows a none deployment", () => {
      const strict = secure({ sameSite: "strict" })
      const none = secure({ sameSite: "none" })

      // The session cookie honours `strict`; a flow cookie may not — the
      // request that completes the flow is a top-level navigation, which a
      // `Strict` cookie would not ride.
      assert.strictEqual(AuthCookies.sessionCookieOptions(strict, { maxAge: Duration.minutes(10) }).sameSite, "strict")
      assert.strictEqual(AuthCookies.pluginCookieFor(strict, pending).options.sameSite, "lax")
      assert.strictEqual(AuthCookies.pluginCookieFor(strict, banner).options.sameSite, "lax")
      assert.strictEqual(AuthCookies.pluginCookieFor(none, pending).options.sameSite, "none")
      assert.strictEqual(AuthCookies.pluginCookieFor(secureConfig, pending).options.sameSite, "lax")
    })

    it("never lets a plugin cookie be script-readable, and follows the deployment on secure", () => {
      assert.strictEqual(AuthCookies.pluginCookieFor(secureConfig, pending).options.httpOnly, true)
      assert.strictEqual(AuthCookies.pluginCookieFor(devConfig, pending).options.httpOnly, true)
      assert.strictEqual(AuthCookies.pluginCookieFor(secureConfig, pending).options.secure, true)
      assert.strictEqual(AuthCookies.pluginCookieFor(devConfig, pending).options.secure, false)
    })

    it("carries the lifetime it was given, and expires by repeating the attributes", () => {
      const derived = AuthCookies.pluginCookieFor(secureConfig, pending)

      assert.deepStrictEqual(derived.options.maxAge, Duration.minutes(10))
      // A browser replaces a cookie only when name, path and domain all match,
      // so the expiry repeats them — and drops `maxAge` for an epoch `expires`.
      assert.strictEqual(derived.expiredOptions.maxAge, undefined)
      assert.deepStrictEqual(derived.expiredOptions.expires, new Date(0))
      assert.strictEqual(derived.expiredOptions.path, derived.options.path)
      assert.strictEqual(derived.expiredOptions.domain, derived.options.domain)
      assert.strictEqual(derived.expiredOptions.sameSite, derived.options.sameSite)
      assert.strictEqual(derived.expiredOptions.secure, derived.options.secure)
      assert.strictEqual(derived.expiredOptions.httpOnly, true)
    })

    it("writes the cookie under a scheme whose key is the name", () => {
      const derived = AuthCookies.pluginCookieFor(secureConfig, pending)

      // `securitySetCookie` takes the cookie's name from the scheme, so the two
      // cannot be allowed to drift apart.
      assert.strictEqual(derived.security.key, derived.name)
      assert.strictEqual(derived.security.in, "cookie")
    })

    it.effect("answers from the deployment's own configuration when read as an effect", () =>
      Effect.map(
        Effect.provideService(AuthCookies.pluginCookie(pending), AuthConfig.AuthConfig, secureConfig),
        (derived) => {
          assert.deepStrictEqual(derived, AuthCookies.pluginCookieFor(secureConfig, pending))
        }
      )
    )
  })

  // The redaction is a property of the fiber the value is rendered on, so each
  // of these gets the layer as its block's environment rather than an
  // `Effect.provide` inside the test body.
  layer(AuthCookies.layerRedactedHeaders())("redaction", (it) => {
    it.effect("hides the session cookie from a rendered Headers value", () =>
      Effect.sync(() => {
        const headers = Headers.fromInput({
          cookie: "__Secure-effect_auth.session=super-secret-token",
          authorization: "Bearer super-secret-token",
          "x-request-id": "abc"
        })

        const rendered = JSON.stringify(headers)

        assert.isFalse(rendered.includes("super-secret-token"))
        assert.isTrue(rendered.includes("<redacted>"))
        assert.isTrue(rendered.includes("abc"))
      })
    )
  })

  layer(AuthCookies.layerRedactedHeaders(["x-tenant-token"]))("redaction, with application names", (it) => {
    it.effect("keeps the auth headers redacted when an application adds its own", () =>
      Effect.sync(() => {
        const headers = Headers.fromInput({
          cookie: "__Secure-effect_auth.session=super-secret-token",
          "x-tenant-token": "tenant-secret"
        })

        const rendered = JSON.stringify(headers)

        assert.isFalse(rendered.includes("super-secret-token"))
        assert.isFalse(rendered.includes("tenant-secret"))
      })
    )
  })
})
