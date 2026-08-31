/**
 * The session cookie contract.
 *
 * One place decides what the session cookie is called, what attributes it is
 * written with, and which header names must never appear in a log line. The
 * middleware declaration, its implementation, and the handlers all read from
 * here so a deployment can never end up setting a cookie under one name and
 * reading it under another.
 *
 * @since 1.0.0
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
 * @since 1.0.0
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
 * @since 1.0.0
 */
export const secureSessionCookieName: string = `__Secure-${defaultCookieName}`

/**
 * The name the session cookie is actually written under for a given
 * configuration.
 *
 * @category combinators
 * @since 1.0.0
 */
export const sessionCookieName = (config: AuthConfigService): string => resolveCookieName(config)

/**
 * The session cache cookie name used when the deployment is not served over TLS.
 *
 * @category constructors
 * @since 1.0.0
 */
export const insecureSessionCacheCookieName: string = defaultCacheCookieName

/**
 * The session cache cookie name used when the deployment is served over TLS.
 *
 * @category constructors
 * @since 1.0.0
 */
export const secureSessionCacheCookieName: string = `__Secure-${defaultCacheCookieName}`

/**
 * The name the session cache cookie is actually written under for a given
 * configuration.
 *
 * @category combinators
 * @since 1.0.0
 */
export const sessionCacheCookieName = (config: AuthConfigService): string => resolveCacheCookieName(config)

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
 * @since 1.0.0
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
 * @since 1.0.0
 */
export const expiredSessionCookieOptions = (
  config: AuthConfigService
): NonNullable<Cookies.Cookie["options"]> => ({
  path: config.cookie.path,
  domain: config.cookie.domain,
  sameSite: config.cookie.sameSite,
  secure: config.cookie.secure,
  httpOnly: true,
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
 * @since 1.0.0
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
 * @since 1.0.0
 */
export const insecureSessionCookieSecurity: HttpApiSecurity.ApiKey = HttpApiSecurity.apiKey({
  key: insecureSessionCookieName,
  in: "cookie"
})

/**
 * The security scheme for non-browser clients, which present the same opaque
 * session token as `Authorization: Bearer <token>`.
 *
 * @category constructors
 * @since 1.0.0
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
 * @since 1.0.0
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
 * @since 1.0.0
 */
export const insecureSessionCacheCookieSecurity: HttpApiSecurity.ApiKey = HttpApiSecurity.apiKey({
  key: insecureSessionCacheCookieName,
  in: "cookie"
})

/**
 * The scheme whose key is the cache cookie name this configuration writes.
 *
 * @category combinators
 * @since 1.0.0
 */
export const sessionCacheCookieSecurity = (config: AuthConfigService): HttpApiSecurity.ApiKey =>
  config.cookie.secure ? secureSessionCacheCookieSecurity : insecureSessionCacheCookieSecurity

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
 * @since 1.0.0
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
 * @since 1.0.0
 */
export const layerRedactedHeaders = (
  additional: ReadonlyArray<string | RegExp> = []
): Layer.Layer<never> =>
  Layer.succeed(Headers.CurrentRedactedNames)([...redactedHeaderNames, ...additional])
