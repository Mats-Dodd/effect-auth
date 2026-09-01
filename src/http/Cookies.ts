/**
 * The session cookie contract.
 *
 * One place decides what the session cookie is called, what attributes it is
 * written with, and which header names must never appear in a log line. The
 * middleware declaration, its implementation, and the handlers all read from
 * here so a deployment can never end up setting a cookie under one name and
 * reading it under another.
 *
 * @since 0.1.0
 */
import type { Duration } from "effect"
import { Layer } from "effect"
import type { Cookies } from "effect/unstable/http"
import { Headers } from "effect/unstable/http"
import { HttpApiSecurity } from "effect/unstable/httpapi"
import type { AuthConfigService } from "../config/AuthConfig.js"
import {
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
