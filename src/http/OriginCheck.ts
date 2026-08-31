/**
 * Origin trust: the CSRF guard, and the open-redirect guard.
 *
 * Two different questions are answered here, and both reduce to "is this origin
 * one we trust?":
 *
 * - **Who sent this request?** A cookie travels on a cross-site request whether
 *   or not the person meant to send it. `SameSite=lax` already blocks the
 *   dangerous shapes, and {@link checkOrigin} is the second lock: a
 *   state-changing request authenticated by a cookie must not claim an `Origin`
 *   we do not trust.
 * - **Where may we send this person next?** Every `callbackURL`, `redirectTo`
 *   and `errorCallbackURL` in the API is attacker-supplied. {@link resolveUrl}
 *   turns one into a URL that is either relative to `baseUrl` or on a trusted
 *   origin, and falls back to `baseUrl` rather than refusing — a failed
 *   redirect target is not worth an error page.
 *
 * @since 1.0.0
 */
import { Array, Effect, Option, Schema } from "effect"
import { HttpServerRequest } from "effect/unstable/http"
import type { AuthConfigService } from "../config/AuthConfig.js"
import { Unauthorized } from "../domain/Errors.js"

// -----------------------------------------------------------------------------
// Origins
// -----------------------------------------------------------------------------

/**
 * The schemes an origin may be spoken over. Everything else has no origin as
 * far as this module is concerned.
 *
 * @category constructors
 * @since 1.0.0
 */
export const webProtocols: ReadonlySet<string> = new Set(["http:", "https:"])

/** `new URL(s)` as a total function: an unparseable string decodes to `None`. */
const decodeUrl = Schema.decodeOption(Schema.URLFromString)

/** `new URL(s, base)` as a total function — no base-relative schema exists. */
const resolveAgainst = Option.liftThrowable(
  (candidate: string, base: string) => new URL(candidate, base)
)

/**
 * The origin of a URL — scheme, host and port — or `None` when the string is
 * not an absolute `http(s)` URL.
 *
 * **Gotchas**
 *
 * Only `http:` and `https:` yield an origin. Every other scheme — `data:`,
 * `file:`, `javascript:`, a custom app scheme — is *opaque*, and the WHATWG
 * parser gives it the origin string `"null"`. Returning that would be
 * catastrophic in both directions: a `trustedOrigins` entry with an opaque
 * origin would make the CSRF check trust `Origin: null` (a sandboxed iframe —
 * the one case {@link claimedOrigin} exists to refuse), and would make
 * {@link resolveUrl} willing to redirect a browser to a `data:` URL. So the
 * literal `"null"` is never an origin here.
 *
 * @category combinators
 * @since 1.0.0
 */
export const originOf = (url: string): Option.Option<string> =>
  Option.flatMap(
    decodeUrl(url),
    (parsed) => webProtocols.has(parsed.protocol) ? Option.some(parsed.origin) : Option.none()
  )

/**
 * Builds the set of origins a configuration trusts: the one `baseUrl` is served
 * from, plus whatever `trustedOrigins` adds.
 *
 * **When to use**
 *
 * From `AuthConfig.make`, to compute the set once when the configuration is
 * built. {@link trustedOrigins} is the reader every request path goes through,
 * and it caches per configuration object, so calling this directly is only
 * needed where the set itself is wanted as a value.
 *
 * @category constructors
 * @since 1.0.0
 */
export const trustedOriginSet = (options: {
  readonly baseUrl: string
  readonly trustedOrigins: ReadonlyArray<string>
}): ReadonlySet<string> => new Set(Array.getSomes([options.baseUrl, ...options.trustedOrigins].map(originOf)))

/** Keyed by the configuration object, which is built once per layer. */
const originSets = new WeakMap<AuthConfigService, ReadonlySet<string>>()

/**
 * Every origin this deployment trusts.
 *
 * **Details**
 *
 * Computed once per configuration object and memoized: this is on the hot path
 * of every state-changing request and of every redirect target, and parsing the
 * same handful of URLs per request bought nothing.
 *
 * **Gotchas**
 *
 * Comparison is by origin, never by prefix. `https://app.example.com.evil.test`
 * has a different origin from `https://app.example.com` and is therefore not
 * trusted, which a `startsWith` check would get wrong.
 *
 * @category combinators
 * @since 1.0.0
 */
export const trustedOrigins = (config: AuthConfigService): ReadonlySet<string> => {
  const cached = originSets.get(config)
  if (cached !== undefined) return cached
  const origins = trustedOriginSet(config)
  originSets.set(config, origins)
  return origins
}

/**
 * Whether an origin header value is one this deployment trusts.
 *
 * @category guards
 * @since 1.0.0
 */
export const isTrustedOrigin = (config: AuthConfigService, origin: string): boolean => {
  const parsed = originOf(origin)
  return Option.isSome(parsed) && trustedOrigins(config).has(parsed.value)
}

// -----------------------------------------------------------------------------
// Open-redirect defence
// -----------------------------------------------------------------------------

/**
 * Whether a redirect candidate is a path on this deployment rather than a
 * reference to another origin.
 *
 * **Details**
 *
 * A path starts with `/` and does not continue with a second slash. It also
 * must not continue with a backslash: for an http(s) base URL the WHATWG URL
 * parser treats `\` as `/`, so `new URL("/\\evil.test", "https://app.test")`
 * is `https://evil.test/` — a protocol-relative URL wearing a path's clothes.
 *
 * @category guards
 * @since 1.0.0
 */
export const isPathRelative = (candidate: string): boolean => {
  if (!candidate.startsWith("/")) return false
  const second = candidate[1]
  return second !== "/" && second !== "\\"
}

/**
 * Turns an attacker-supplied redirect target into one that is safe to send a
 * browser to.
 *
 * **Details**
 *
 * Three outcomes, in order:
 *
 * 1. a path-relative target (`/welcome`) is resolved against `baseUrl`;
 * 2. an absolute target whose origin is trusted is kept as it is;
 * 3. anything else — a foreign origin, a `javascript:` URL, a protocol-relative
 *    `//evil.test`, an unparseable string — is replaced by `baseUrl`.
 *
 * **Gotchas**
 *
 * A protocol-relative URL is deliberately *not* treated as relative. `//evil.test`
 * parses as an absolute URL with the current scheme, and treating it as a path
 * is the classic open-redirect bug. The same holds for a backslash in that
 * second position: WHATWG URL parsing folds `\` onto `/` for http(s), so
 * `/\evil.test` resolves to `https://evil.test/` — see {@link isPathRelative}.
 * Whatever the candidate looked like, the *resolved* URL's origin is checked
 * before it is returned, so a parser quirk this code does not know about cannot
 * turn into a redirect off-origin.
 *
 * @category combinators
 * @since 1.0.0
 */
export const resolveUrl = (
  config: AuthConfigService,
  candidate: string | null | undefined
): string => {
  if (candidate === null || candidate === undefined || candidate.length === 0) return config.baseUrl
  if (isPathRelative(candidate)) {
    const resolved = resolveAgainst(candidate, config.baseUrl)
    // Belt and braces: a relative-looking candidate that nonetheless parsed
    // onto another origin is a redirect off this deployment, whatever it was.
    return Option.isSome(resolved) && trustedOrigins(config).has(resolved.value.origin)
      ? resolved.value.toString()
      : config.baseUrl
  }
  return isTrustedOrigin(config, candidate) ? candidate : config.baseUrl
}

/**
 * The same validation as {@link resolveUrl}, but answering `None` instead of
 * substituting `baseUrl`.
 *
 * **When to use**
 *
 * Where "the caller supplied nothing" and "the caller supplied something we
 * refused" need to stay distinguishable — the e-mail flows append a
 * `callbackURL` only when one was actually given.
 *
 * @category combinators
 * @since 1.0.0
 */
export const validateUrl = (
  config: AuthConfigService,
  candidate: string | null | undefined
): Option.Option<string> => {
  if (candidate === null || candidate === undefined || candidate.length === 0) return Option.none()
  const resolved = resolveUrl(config, candidate)
  return resolved === config.baseUrl && candidate !== config.baseUrl ? Option.none() : Option.some(resolved)
}

// -----------------------------------------------------------------------------
// CSRF
// -----------------------------------------------------------------------------

/**
 * HTTP methods that do not change state and therefore need no origin check.
 *
 * @category constructors
 * @since 1.0.0
 */
export const safeMethods: ReadonlySet<string> = new Set(["GET", "HEAD", "OPTIONS"])

/**
 * The origin a request claims: its `Origin` header, or the origin of its
 * `Referer` when there is no `Origin`.
 *
 * **Details**
 *
 * The parameter is the request's `Headers` — a lowercase-keyed record — so a
 * caller passes `request.headers` straight through.
 *
 * **Gotchas**
 *
 * A literal `Origin: null` is *not* treated as "no origin". It is what a
 * browser sends from a sandboxed iframe, a `data:` document, or across some
 * redirect chains: a positive signal that the initiator is untrustworthy. It
 * is returned as the claimed origin, parses as no origin at all, and therefore
 * fails {@link isTrustedOrigin}. Only a genuinely absent `Origin` *and*
 * `Referer` yields `None`.
 *
 * @category combinators
 * @since 1.0.0
 */
export const claimedOrigin = (
  headers: Readonly<Record<string, string | undefined>>
): Option.Option<string> => {
  const origin = headers["origin"]
  if (origin !== undefined && origin.length > 0) return Option.some(origin)
  const referer = headers["referer"]
  if (referer === undefined || referer.length === 0) return Option.none()
  // A referer that does not parse is as untrustworthy as an `Origin: null`.
  return Option.some(Option.getOrElse(originOf(referer), () => referer))
}

/**
 * Fails `Unauthorized` when a state-changing, cookie-authenticated request
 * claims an origin this deployment does not trust.
 *
 * **Details**
 *
 * Applied only on the cookie transports of the `Authenticated` middleware. A
 * bearer token is not attached by the browser to a cross-site request, so the
 * check would be pure cost there — and it would break every non-browser client,
 * which sends no `Origin` at all.
 *
 * **Gotchas**
 *
 * A request that claims *no* origin is allowed through. Every browser attaches
 * `Origin` to a cross-origin state-changing request, so the absent case is a
 * non-browser caller, for which `SameSite=lax` is not the relevant defence
 * anyway. Fail-closed here would reject `curl` with a copied cookie while
 * stopping no browser attack. A request that claims an origin we cannot parse
 * — `Origin: null` from a sandboxed iframe, most of all — is a different case
 * and is refused: something browser-shaped made it, and it is not us.
 *
 * @category combinators
 * @since 1.0.0
 */
export const checkOrigin = (
  config: AuthConfigService
): Effect.Effect<void, Unauthorized, HttpServerRequest.HttpServerRequest> =>
  Effect.flatMap(HttpServerRequest.HttpServerRequest, (request) => {
    if (safeMethods.has(request.method)) return Effect.void
    const claimed = claimedOrigin(request.headers)
    if (Option.isNone(claimed)) return Effect.void
    return isTrustedOrigin(config, claimed.value) ? Effect.void : Effect.fail(new Unauthorized())
  })
