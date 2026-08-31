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
import { Effect, Option } from "effect"
import { HttpServerRequest } from "effect/unstable/http"
import type { AuthConfigService } from "../config/AuthConfig.js"
import { Unauthorized } from "../domain/Errors.js"
import type { PolicyRefused } from "../domain/Hooks.js"
import * as InternalOrigins from "../internal/origins.js"

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
export const webProtocols: ReadonlySet<string> = InternalOrigins.webProtocols

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
export const originOf: (url: string) => Option.Option<string> = InternalOrigins.originOf

/**
 * Builds the set of origins a configuration trusts: the one `baseUrl` is served
 * from, plus whatever `trustedOrigins` adds.
 *
 * **When to use**
 *
 * Where the set is wanted as a value for options that are not a resolved
 * configuration. `AuthConfig.make` calls this once when the configuration is
 * built, and {@link trustedOrigins} reads the result back — which is the path
 * every request goes through.
 *
 * @category constructors
 * @since 1.0.0
 */
export const trustedOriginSet: (options: {
  readonly baseUrl: string
  readonly trustedOrigins: ReadonlyArray<string>
}) => ReadonlySet<string> = InternalOrigins.trustedOriginSet

/**
 * Every origin this deployment trusts.
 *
 * **Details**
 *
 * A field read: the set is parsed once, by `AuthConfig.make`, because this is
 * on the hot path of every state-changing request and of every redirect target,
 * and parsing the same handful of URLs per request bought nothing.
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
export const trustedOrigins = (config: AuthConfigService): ReadonlySet<string> => config.trustedOriginSet

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

/**
 * Appends an error code to a URL a browser is about to be sent to.
 *
 * **When to use**
 *
 * On the redirect target of a flow that failed — an OAuth callback, a magic
 * link — so the page the person lands on can say what went wrong. The code is a
 * fixed, safe classification chosen by this library, never a message and never
 * anything the caller supplied.
 *
 * **Gotchas**
 *
 * The URL must already have been through {@link resolveUrl}: this function
 * validates nothing, it only appends a query parameter to whatever it is given.
 *
 * @category combinators
 * @since 1.0.0
 */
export const withErrorCode = (url: string, code: string): string => {
  const parsed = new URL(url)
  parsed.searchParams.set("error", code)
  return parsed.toString()
}

/**
 * Where a browser goes when a deployment's own hook refused what the link it
 * followed was for.
 *
 * **When to use**
 *
 * On every redirect-shaped completion a `PolicyRefused` can reach — the OAuth
 * callback, a magic link, the delete-account link. They answer with one URL
 * shape, from here, so a person refused by one policy lands in the same place
 * whichever link they followed.
 *
 * **Details**
 *
 * `?error=` carries this library's own classification, `policy_refused`,
 * exactly as `invalid_token` and `unknown_provider` do; `&code=` beside it
 * carries the deployment's, verbatim, so the landing page can say *which* rule
 * it was rather than only that some rule was.
 *
 * **Gotchas**
 *
 * `code` is published to whoever followed the link — a hook that puts a secret
 * in one has published it, which is the rule `PolicyRefused` documents.
 * `errorURL` is validated by {@link resolveUrl}, so a completion with nothing
 * to go on — the usual case, because the URL the person asked for travels in a
 * token payload the refusing call has already claimed — lands on `baseUrl`.
 *
 * @category combinators
 * @since 1.0.0
 */
export const policyRefusedTarget = (
  config: AuthConfigService,
  errorURL: string | null | undefined,
  code: string
): string => {
  const url = new URL(withErrorCode(resolveUrl(config, errorURL), "policy_refused"))
  url.searchParams.set("code", code)
  return url.toString()
}

/**
 * The failure half of a redirect-shaped outcome: the error, somewhere to send
 * the browser, and the safe code that was appended to it.
 *
 * @category models
 * @since 1.0.0
 */
export interface RedirectFailure<E> {
  readonly _tag: "Failure"
  readonly error: E
  /**
   * The validated error URL, carrying `?error=<code>` — and, when a
   * deployment's own hook was what refused, `&code=<the hook's code>` beside it.
   */
  readonly redirectTo: string
  /** The safe, closed-set error code that was appended. */
  readonly code: string
}

/** A refusal among a flow's own errors, without naming the flow's union. */
const isPolicyRefused = (error: { readonly _tag: string }): error is PolicyRefused => error._tag === "PolicyRefused"

/**
 * Builds the {@link RedirectFailure} a flow answers a failed completion with.
 *
 * **When to use**
 *
 * From a flow whose failures are reported by redirecting rather than by an
 * error body — the OAuth callback, a magic link. `errorCode` is that flow's own
 * closed-set classification, which is the only part of the shape that differs
 * between them.
 *
 * **Details**
 *
 * A refusal carries the deployment's own classification beside this library's,
 * in the one shape every redirect-shaped completion answers with. `?error=` is
 * unchanged by that: a flow's `errorCode` already answers `policy_refused` for
 * that case, and it stays the closed set it was.
 *
 * @category combinators
 * @since 1.0.0
 */
export const redirectFailure = <E extends { readonly _tag: string }>(
  config: AuthConfigService,
  errorCode: (error: E) => string
): (error: E, errorURL: string | null | undefined) => RedirectFailure<E> =>
(error, errorURL) => {
  const code = errorCode(error)
  return {
    _tag: "Failure",
    error,
    redirectTo: isPolicyRefused(error)
      ? policyRefusedTarget(config, errorURL, error.code)
      : withErrorCode(resolveUrl(config, errorURL), code),
    code
  }
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
