/**
 * The cookie contract: the session cookie, the two flow cookies beside it, and
 * the shape a plugin's own cookie takes.
 *
 * One place decides what a cookie is called, what attributes it is written
 * with, and which header names must never appear in a log line. The middleware
 * declaration, its implementation, and the handlers all read from here so a
 * deployment can never end up setting a cookie under one name and reading it
 * under another, and {@link pluginCookie} hands a plugin the same three
 * decisions — the `__Host-`/`__Secure-` prefix, the `SameSite` cap, and the
 * rule that an expiry repeats the attributes the cookie was set with — rather
 * than leaving each plugin to re-derive them.
 *
 * @since 0.1.0
 */
import type { Duration } from "effect"
import { Effect, Layer } from "effect"
import type { Cookies } from "effect/unstable/http"
import { Headers } from "effect/unstable/http"
import { HttpApiSecurity } from "effect/unstable/httpapi"
import type { AuthConfigService } from "../config/AuthConfig.js"
import {
  AuthConfig,
  cacheCookieName as resolveCacheCookieName,
  cookieName as resolveCookieName,
  defaultCacheCookieName,
  defaultCookieName
} from "../config/AuthConfig.js"

// -----------------------------------------------------------------------------
// Names
// -----------------------------------------------------------------------------

/**
 * The session cookie name used when the deployment is not served over TLS.
 *
 * @category constructors
 * @since 0.1.0
 */
export const insecureSessionCookieName: string = defaultCookieName

/**
 * The session cookie name used when the deployment is served over TLS.
 *
 * **Details**
 *
 * The `__Secure-` prefix is enforced by browsers: a cookie carrying it is only
 * accepted over HTTPS and only from a secure origin, so a network attacker
 * holding a plain-HTTP sibling origin cannot overwrite the session.
 *
 * @category constructors
 * @since 0.1.0
 */
export const secureSessionCookieName: string = `__Secure-${defaultCookieName}`

/**
 * The name the session cookie is actually written under for a given
 * configuration.
 *
 * **Details**
 *
 * `AuthConfig.cookieName` under the name this module uses: the `__Secure-` rule
 * is stated once, where the cookie's configuration lives, and every reader in
 * the HTTP layer goes through here.
 *
 * @category combinators
 * @since 0.1.0
 */
export const sessionCookieName: (config: AuthConfigService) => string = resolveCookieName

/**
 * The session cache cookie name used when the deployment is not served over TLS.
 *
 * @category constructors
 * @since 0.1.0
 */
export const insecureSessionCacheCookieName: string = defaultCacheCookieName

/**
 * The session cache cookie name used when the deployment is served over TLS.
 *
 * @category constructors
 * @since 0.1.0
 */
export const secureSessionCacheCookieName: string = `__Secure-${defaultCacheCookieName}`

/**
 * The name the session cache cookie is actually written under for a given
 * configuration — `AuthConfig.cacheCookieName`, as {@link sessionCookieName} is
 * `AuthConfig.cookieName`.
 *
 * @category combinators
 * @since 0.1.0
 */
export const sessionCacheCookieName: (config: AuthConfigService) => string = resolveCacheCookieName

/**
 * The name of the short-lived cookie that binds an OAuth flow to the browser
 * that started it, before any `__Secure-` prefix.
 *
 * **Details**
 *
 * A constant, not a knob — the same reasoning as {@link defaultCookieName}. It
 * holds the raw `state` value while the browser is away at the provider, so the
 * callback can require the state it comes back with to be the one *this* browser
 * was issued.
 *
 * @category constructors
 * @since 0.1.0
 */
export const oauthStateCookieBaseName = "effect_auth.oauth_state"

/**
 * The OAuth state-binding cookie name used when the deployment is not served
 * over TLS.
 *
 * @category constructors
 * @since 0.1.0
 */
export const insecureOAuthStateCookieName: string = oauthStateCookieBaseName

/**
 * The OAuth state-binding cookie name used when the deployment is served over
 * TLS — `__Host-` prefixed.
 *
 * **Details**
 *
 * `__Host-`, not the `__Secure-` prefix the session cookie uses. `__Secure-`
 * binds a cookie to TLS but not to a host: a page on a sibling subdomain can
 * set a `Domain`-scoped `__Secure-effect_auth.oauth_state` valued at a `state`
 * it obtained, and that cookie rides the callback request and passes the
 * value-equality check. `__Host-` forbids the `Domain` attribute and pins the
 * cookie to the exact host that set it, closing the tossing vector. The state
 * cookie is set and read on the same host and never legitimately carries a
 * `Domain`, so it loses nothing by being host-bound. The prefix's browser
 * requirements — `Secure`, `Path=/`, no `Domain` — are met by
 * {@link oauthStateCookieOptions}.
 *
 * @category constructors
 * @since 0.1.0
 */
export const secureOAuthStateCookieName: string = `__Host-${oauthStateCookieBaseName}`

/**
 * The name the OAuth state-binding cookie is actually written under for a given
 * configuration. On TLS it is `__Host-` prefixed (see
 * {@link secureOAuthStateCookieName}); on a plain-HTTP deployment, where the
 * `__Host-` prefix's mandatory `Secure` attribute cannot be honoured, it is the
 * bare {@link insecureOAuthStateCookieName}.
 *
 * @category combinators
 * @since 0.1.0
 */
export const oauthStateCookieName = (config: AuthConfigService): string =>
  config.cookie.secure ? secureOAuthStateCookieName : insecureOAuthStateCookieName

// -----------------------------------------------------------------------------
// Attributes
// -----------------------------------------------------------------------------

/**
 * The attributes the session cookie is written with.
 *
 * **Details**
 *
 * `httpOnly` is not configurable: script-readable session tokens are the whole
 * point of the cookie transport being safer than `localStorage`. `secure`,
 * `sameSite`, `path` and `domain` come from {@link AuthConfigService}, and
 * `maxAge` is the remaining lifetime of the session the cookie carries, so the
 * browser drops it at the same moment the server does.
 *
 * The return type is exactly what `HttpApiBuilder.securitySetCookie` and
 * `HttpServerResponse.setCookie` accept.
 *
 * @category combinators
 * @since 0.1.0
 */
export const sessionCookieOptions = (
  config: AuthConfigService,
  options: { readonly maxAge: Duration.Duration }
): NonNullable<Cookies.Cookie["options"]> => ({
  path: config.cookie.path,
  domain: config.cookie.domain,
  sameSite: config.cookie.sameSite,
  secure: config.cookie.secure,
  httpOnly: true,
  maxAge: options.maxAge
})

/**
 * The attributes used to expire the session cookie on sign-out.
 *
 * **Gotchas**
 *
 * A browser only replaces a cookie when the name, `path` and `domain` all
 * match, so the expiry must repeat the attributes the cookie was set with.
 *
 * @category combinators
 * @since 0.1.0
 */
export const expiredSessionCookieOptions = (config: AuthConfigService): NonNullable<Cookies.Cookie["options"]> => ({
  path: config.cookie.path,
  domain: config.cookie.domain,
  sameSite: config.cookie.sameSite,
  secure: config.cookie.secure,
  httpOnly: true,
  // oxlint-disable-next-line effecttsgo/global-date -- epoch constant, not a clock read
  expires: new Date(0)
})

/**
 * The attributes the OAuth state-binding cookie is written with.
 *
 * **Details**
 *
 * `httpOnly`, and `sameSite` is `"none"` when the deployment configures
 * `cookie.sameSite: "none"` and `"lax"` otherwise — never `"strict"`. A
 * `"none"` deployment runs its frontend on a different site than the auth
 * server, so `signInSocial` is a cross-site request: a browser rejects a
 * `SameSite=Lax` `Set-Cookie` on a cross-site subresource response, the state
 * cookie is never stored, and every callback fails `state_mismatch`. The
 * binding's security comes from the `httpOnly` cookie's value-equality check at
 * the callback, not from `Lax`, so following the deployment's own `sameSite`
 * does not reopen login-CSRF. `"strict"` is excluded either way: the callback
 * is reached by a top-level navigation back from the provider, which a
 * `Strict` cookie would not ride.
 *
 * `path` is fixed to `"/"` and `domain` is omitted, regardless of
 * `cookie.path`/`cookie.domain`, because the TLS name carries the `__Host-`
 * prefix — see {@link secureOAuthStateCookieName} — whose browser requirements
 * are `Secure`, `Path=/`, and no `Domain`. `maxAge` is the pending request's
 * own short lifetime so the browser drops the cookie at the same time the state
 * row expires.
 *
 * @category combinators
 * @since 0.1.0
 */
export const oauthStateCookieOptions = (
  config: AuthConfigService,
  options: { readonly maxAge: Duration.Duration }
): NonNullable<Cookies.Cookie["options"]> => ({
  path: "/",
  domain: undefined,
  sameSite: config.cookie.sameSite === "none" ? "none" : "lax",
  secure: config.cookie.secure,
  httpOnly: true,
  maxAge: options.maxAge
})

/**
 * The attributes used to expire the OAuth state-binding cookie once the
 * callback has read it. Repeats the `path`, `domain` and `sameSite`
 * {@link oauthStateCookieOptions} set — a browser only replaces a cookie when
 * the name, `path` and `domain` all match — so the fixed `Path=/` and omitted
 * `Domain` the `__Host-` prefix requires are mirrored here.
 *
 * @category combinators
 * @since 0.1.0
 */
export const expiredOAuthStateCookieOptions = (config: AuthConfigService): NonNullable<Cookies.Cookie["options"]> => ({
  path: "/",
  domain: undefined,
  sameSite: config.cookie.sameSite === "none" ? "none" : "lax",
  secure: config.cookie.secure,
  httpOnly: true,
  // oxlint-disable-next-line effecttsgo/global-date -- epoch constant, not a clock read
  expires: new Date(0)
})

// -----------------------------------------------------------------------------
// Security schemes
// -----------------------------------------------------------------------------

/**
 * The security scheme for the session cookie on a TLS deployment.
 *
 * **Gotchas**
 *
 * A security scheme's key is fixed when the middleware class is declared, so it
 * cannot depend on runtime configuration. `Authenticated` therefore declares
 * both cookie names and tries them in turn — see
 * {@link insecureSessionCookieSecurity}.
 *
 * @category constructors
 * @since 0.1.0
 */
export const secureSessionCookieSecurity: HttpApiSecurity.ApiKey = HttpApiSecurity.apiKey({
  key: secureSessionCookieName,
  in: "cookie"
})

/**
 * The security scheme for the session cookie on a plain-HTTP deployment, such
 * as local development.
 *
 * @category constructors
 * @since 0.1.0
 */
export const insecureSessionCookieSecurity: HttpApiSecurity.ApiKey = HttpApiSecurity.apiKey({
  key: insecureSessionCookieName,
  in: "cookie"
})

/**
 * The security scheme whose key is the cookie name this configuration actually
 * writes.
 *
 * **Details**
 *
 * `HttpApiBuilder.securitySetCookie` takes the cookie name from the scheme it is
 * given, so writing the cookie goes through the same two declared schemes that
 * read it. Which of them applies is decided by `cookie.secure`, exactly as
 * {@link sessionCookieName} decides the `__Secure-` prefix.
 *
 * @category combinators
 * @since 0.1.0
 */
export const sessionCookieSecurity = (config: AuthConfigService): HttpApiSecurity.ApiKey =>
  config.cookie.secure ? secureSessionCookieSecurity : insecureSessionCookieSecurity

/**
 * The security scheme for non-browser clients, which present the same opaque
 * session token as `Authorization: Bearer <token>`.
 *
 * @category constructors
 * @since 0.1.0
 */
export const bearerSecurity: HttpApiSecurity.Http = HttpApiSecurity.bearer

/**
 * The scheme the session *cache* cookie is written under on a TLS deployment.
 *
 * **Gotchas**
 *
 * This is not a credential and no middleware declares it: it is a scheme only
 * because `HttpApiBuilder.securitySetCookie` — the one way to attach a
 * `Set-Cookie` from inside a handler or a middleware — takes the cookie's name
 * from one. The cache cookie is read straight off the request instead, since
 * presenting it alone authenticates nothing.
 *
 * @category constructors
 * @since 0.1.0
 */
export const secureSessionCacheCookieSecurity: HttpApiSecurity.ApiKey = HttpApiSecurity.apiKey({
  key: secureSessionCacheCookieName,
  in: "cookie"
})

/**
 * The scheme the session cache cookie is written under on a plain-HTTP
 * deployment. See {@link secureSessionCacheCookieSecurity}.
 *
 * @category constructors
 * @since 0.1.0
 */
export const insecureSessionCacheCookieSecurity: HttpApiSecurity.ApiKey = HttpApiSecurity.apiKey({
  key: insecureSessionCacheCookieName,
  in: "cookie"
})

/**
 * The scheme whose key is the cache cookie name this configuration writes.
 *
 * @category combinators
 * @since 0.1.0
 */
export const sessionCacheCookieSecurity = (config: AuthConfigService): HttpApiSecurity.ApiKey =>
  config.cookie.secure ? secureSessionCacheCookieSecurity : insecureSessionCacheCookieSecurity

/**
 * The scheme the OAuth state-binding cookie is written under on a TLS
 * deployment.
 *
 * **Gotchas**
 *
 * A scheme only because `HttpApiBuilder.securitySetCookie` — the one way to
 * attach a `Set-Cookie` from a handler — takes the cookie's name from one. No
 * middleware declares it; the callback reads it straight off the request, since
 * presenting it alone authenticates nothing.
 *
 * @category constructors
 * @since 0.1.0
 */
export const secureOAuthStateCookieSecurity: HttpApiSecurity.ApiKey = HttpApiSecurity.apiKey({
  key: secureOAuthStateCookieName,
  in: "cookie"
})

/**
 * The scheme the OAuth state-binding cookie is written under on a plain-HTTP
 * deployment. See {@link secureOAuthStateCookieSecurity}.
 *
 * @category constructors
 * @since 0.1.0
 */
export const insecureOAuthStateCookieSecurity: HttpApiSecurity.ApiKey = HttpApiSecurity.apiKey({
  key: insecureOAuthStateCookieName,
  in: "cookie"
})

/**
 * The scheme whose key is the OAuth state-binding cookie name this
 * configuration writes.
 *
 * @category combinators
 * @since 0.1.0
 */
export const oauthStateCookieSecurity = (config: AuthConfigService): HttpApiSecurity.ApiKey =>
  config.cookie.secure ? secureOAuthStateCookieSecurity : insecureOAuthStateCookieSecurity

// -----------------------------------------------------------------------------
// Log redaction
// -----------------------------------------------------------------------------

/**
 * The header names whose values `effect-auth` never lets reach a log line or a
 * serialized `Headers` value.
 *
 * **Details**
 *
 * `cookie` and `set-cookie` are the ones that matter here: both carry the raw
 * session token. `authorization` covers the bearer transport of the same token.
 *
 * @category constructors
 * @since 0.1.0
 */
export const redactedHeaderNames: ReadonlyArray<string | RegExp> = [
  "authorization",
  "cookie",
  "set-cookie",
  "x-api-key"
]

/**
 * Registers {@link redactedHeaderNames} with `Headers.CurrentRedactedNames`.
 *
 * **When to use**
 *
 * Provide this alongside the rest of the auth stack. `Headers.CurrentRedactedNames`
 * already defaults to the same four names, so this layer exists to (a) make the
 * guarantee explicit rather than incidental, and (b) let an application add its
 * own sensitive headers without dropping the auth ones.
 *
 * **Example**
 *
 * ```ts
 * import { Layer } from "effect"
 * import { AuthCookies } from "effect-auth"
 *
 * const Redaction = AuthCookies.layerRedactedHeaders(["x-tenant-token"])
 * ```
 *
 * @category layers
 * @since 0.1.0
 */
export const layerRedactedHeaders = (additional: ReadonlyArray<string | RegExp> = []): Layer.Layer<never> =>
  Layer.succeed(Headers.CurrentRedactedNames)([...redactedHeaderNames, ...additional])

// -----------------------------------------------------------------------------
// Plugin cookies
// -----------------------------------------------------------------------------

/**
 * What a plugin has to decide about a cookie of its own.
 *
 * @category models
 * @since 0.1.0
 */
export interface PluginCookieOptions {
  /**
   * The cookie's name before any prefix — `"effect_auth.pending"`,
   * `"effect_auth.trusted_device"`.
   *
   * **Gotchas**
   *
   * Bare: {@link pluginCookie} adds the prefix the deployment's configuration
   * calls for, so a name written with one here would be double-prefixed and the
   * browser would reject it.
   */
  readonly baseName: string
  /**
   * Whether the cookie is pinned to the exact host that set it.
   *
   * `true` for anything that is a credential or binds a flow to one browser —
   * the pending-authentication token, a trusted-device marker — because a
   * sibling subdomain can set a `Domain`-scoped cookie of any name onto the
   * host that reads it. `__Host-` forbids `Domain` and closes that, at the
   * price of the deployment's own `cookie.path` and `cookie.domain`, which the
   * prefix does not permit.
   */
  readonly hostOnly: boolean
  /** How long the browser should keep it — the lifetime of whatever it carries. */
  readonly maxAge: Duration.Duration
}

/**
 * Everything needed to write, read and expire one plugin cookie.
 *
 * @category models
 * @since 0.1.0
 */
export interface PluginCookie {
  /** The name the cookie is actually written under, prefix included. */
  readonly name: string
  /**
   * The scheme {@link name} comes from.
   *
   * `HttpApiBuilder.securitySetCookie` — the one way to attach a `Set-Cookie`
   * from inside a handler — takes the cookie's name from a security scheme, so
   * a plugin needs one whether or not any middleware declares it.
   */
  readonly security: HttpApiSecurity.ApiKey
  /** The attributes it is written with. */
  readonly options: NonNullable<Cookies.Cookie["options"]>
  /** The attributes it is expired with. See {@link expiredSessionCookieOptions}. */
  readonly expiredOptions: NonNullable<Cookies.Cookie["options"]>
}

/**
 * The `SameSite` a flow cookie is written with: the deployment's own, capped
 * away from `Strict`.
 *
 * A `"none"` deployment serves its frontend on a different site than the auth
 * server, so the response that sets the cookie is a cross-site subresource
 * response and a `SameSite=Lax` `Set-Cookie` on it is dropped by the browser.
 * `"strict"` is excluded in the other direction: a flow that resumes through a
 * top-level navigation — back from a provider, out of a mail client — would not
 * carry a `Strict` cookie on the request that completes it. The security of
 * these cookies is the value they hold, not the attribute.
 */
const flowSameSite = (config: AuthConfigService): "lax" | "none" => (config.cookie.sameSite === "none" ? "none" : "lax")

/**
 * One plugin cookie, decided by the deployment's configuration.
 *
 * **When to use**
 *
 * From a plugin that needs a cookie of its own — the pending-authentication
 * token a second factor is answered against, a trusted-device marker. Every
 * such cookie goes through here, so the `__Host-`/`__Secure-` decision, the
 * `SameSite` cap and the rule that an expiry must repeat the attributes the
 * cookie was set with are made once, in the module that already makes them for
 * the session, the cache and the OAuth state cookie.
 *
 * **Details**
 *
 * `httpOnly` is not a parameter: a plugin cookie is a credential or a binding,
 * and script-readable is the one thing neither may be.
 *
 * On a TLS deployment the name carries `__Host-` when `hostOnly`, `__Secure-`
 * otherwise; on plain HTTP — local development — it is the bare `baseName`,
 * because both prefixes require the `Secure` attribute that deployment cannot
 * set. A `__Host-` cookie is written with `Path=/` and no `Domain`, which the
 * prefix requires, in place of the deployment's `cookie.path` and
 * `cookie.domain`.
 *
 * **Example**
 *
 * ```ts skip-type-checking
 * const pending = yield* AuthCookies.pluginCookie({
 *   baseName: "effect_auth.pending",
 *   hostOnly: true,
 *   maxAge: Duration.minutes(10)
 * })
 * yield* HttpApiBuilder.securitySetCookie(pending.security, token, pending.options)
 * ```
 *
 * @category combinators
 * @since 0.1.0
 */
export const pluginCookie = (options: PluginCookieOptions): Effect.Effect<PluginCookie, never, AuthConfig> =>
  Effect.map(AuthConfig, (config) => pluginCookieFor(config, options))

/**
 * {@link pluginCookie} against a configuration already in hand.
 *
 * **When to use**
 *
 * Where the configuration is a value rather than something to be read from the
 * context — a plugin's layer that already holds it, and the tests that pin the
 * attributes. {@link pluginCookie} is the same decision for a handler.
 *
 * @category combinators
 * @since 0.1.0
 */
export const pluginCookieFor = (config: AuthConfigService, options: PluginCookieOptions): PluginCookie => {
  const prefix = config.cookie.secure ? (options.hostOnly ? "__Host-" : "__Secure-") : ""
  const name = `${prefix}${options.baseName}`
  // A `__Host-` cookie may not carry `Domain` and must be `Path=/`; the
  // attributes are fixed whether or not the prefix is on the name, so that
  // a development deployment and a TLS one differ in the prefix alone.
  const path = options.hostOnly ? "/" : config.cookie.path
  const domain = options.hostOnly ? undefined : config.cookie.domain
  const sameSite = flowSameSite(config)
  return {
    name,
    security: HttpApiSecurity.apiKey({ key: name, in: "cookie" }),
    options: { path, domain, sameSite, secure: config.cookie.secure, httpOnly: true, maxAge: options.maxAge },
    // A browser replaces a cookie only when the name, `path` and `domain` all
    // match, so the expiry repeats what the cookie was set with.
    expiredOptions: {
      path,
      domain,
      sameSite,
      secure: config.cookie.secure,
      httpOnly: true,
      // oxlint-disable-next-line effecttsgo/global-date -- epoch constant, not a clock read
      expires: new Date(0)
    }
  }
}
