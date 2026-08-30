/**
 * The `Authenticated` middleware implementation.
 *
 * `Middleware.ts` declares *what* authentication looks like — the context keys,
 * the three credential transports, the error. This module is the half that
 * knows how to resolve a credential: it hashes the presented token, reads the
 * session and its user in one query, performs the rolling refresh, re-sends the
 * cookie when the expiry moved, and provides `CurrentUser` / `CurrentSession` to
 * the endpoint underneath.
 *
 * **Details**
 *
 * Three schemes are declared, and `HttpApiBuilder` tries them in the order they
 * were declared, falling through to the next one whenever a handler fails. So
 * every handler here must fail `Unauthorized` for the empty credential that
 * `securityDecode` produces when the cookie or header is simply absent —
 * otherwise the fall-through would stop at the first transport and a bearer
 * client would never be reached.
 *
 * Which of the two cookie schemes is *honoured* is decided by
 * `cookie.secure`, not by which cookie the browser happened to send. A TLS
 * deployment writes `__Secure-effect_auth.session` and refuses the un-prefixed
 * name outright: the whole point of the prefix is that a network attacker on a
 * plain-HTTP sibling origin — or a compromised subdomain — cannot set it, and
 * still accepting the name they *can* set would hand that defence back (session
 * fixation). The reverse holds for a plain-HTTP deployment, which never writes
 * the prefixed name and therefore never reads it.
 *
 * The `Origin` check runs on the two cookie transports only. A cookie is
 * attached by the browser whether or not the person meant to send the request;
 * an `Authorization` header is not, and demanding an `Origin` there would
 * reject every non-browser client while stopping no attack.
 *
 * @since 1.0.0
 */
import { DateTime, Duration, Effect, Layer, Redacted } from "effect"
import type { Cookies, HttpServerRequest } from "effect/unstable/http"
import type { HttpApiSecurity } from "effect/unstable/httpapi"
import { HttpApiBuilder } from "effect/unstable/httpapi"
import type { AuthConfigShape } from "../config/AuthConfig.js"
import { AuthConfig } from "../config/AuthConfig.js"
import { Unauthorized } from "../domain/Errors.js"
import type { Session } from "../domain/Schema.js"
import { Sessions } from "../domain/Sessions.js"
import {
  expiredSessionCookieOptions,
  insecureSessionCookieSecurity,
  secureSessionCookieSecurity,
  sessionCookieOptions
} from "./Cookies.js"
import { Authenticated, CurrentSession, CurrentUser } from "./Middleware.js"
import { checkOrigin } from "./OriginCheck.js"

// -----------------------------------------------------------------------------
// Cookies
// -----------------------------------------------------------------------------

/**
 * The security scheme whose key is the cookie name this configuration actually
 * writes.
 *
 * **Details**
 *
 * `HttpApiBuilder.securitySetCookie` takes the cookie name from the scheme it is
 * given, so writing the cookie goes through the same two declared schemes that
 * read it. Which of them applies is decided by `cookie.secure`, exactly as
 * `AuthConfig.cookieName` decides the `__Secure-` prefix.
 *
 * @category combinators
 * @since 1.0.0
 */
export const sessionCookieSecurity = (config: AuthConfigShape): HttpApiSecurity.ApiKey =>
  config.cookie.secure ? secureSessionCookieSecurity : insecureSessionCookieSecurity

/**
 * How long a session has left to live at the moment this is evaluated, floored
 * at zero.
 *
 * @category combinators
 * @since 1.0.0
 */
export const remainingLifetime = (session: Session): Effect.Effect<Duration.Duration> =>
  Effect.map(DateTime.now, (now) => {
    const millis = DateTime.toEpochMillis(session.expiresAt) - DateTime.toEpochMillis(now)
    return Duration.millis(millis > 0 ? millis : 0)
  })

/**
 * Attaches the session cookie to the response being built.
 *
 * **Details**
 *
 * The cookie's `Max-Age` mirrors what is left of the session, so the browser
 * forgets it at the same moment the server does. Pass `persistent: false` — what
 * `rememberMe: false` means at this layer — to omit `Max-Age` entirely, which
 * makes it a browser-session cookie that does not survive the window closing.
 *
 * **Gotchas**
 *
 * The rolling refresh re-sends the cookie *with* a `Max-Age`, because at that
 * point nothing on the session row records whether the person asked to be
 * remembered. With the default lifetimes this cannot arise — a one-day
 * `rememberMe: false` session becomes refresh-due only at the instant it
 * expires, and expiry is checked first — but a deployment configuring
 * `updateAge` longer than `rememberMeDisabledExpiresIn` would see a
 * browser-session cookie promoted to a persistent one on refresh.
 *
 * @category combinators
 * @since 1.0.0
 */
export const setSessionCookie = (
  config: AuthConfigShape,
  session: Session,
  token: Redacted.Redacted<string>,
  options?: { readonly persistent?: boolean | undefined } | undefined
): Effect.Effect<void, never, HttpServerRequest.HttpServerRequest> =>
  Effect.flatMap(remainingLifetime(session), (maxAge) => {
    const attributes: NonNullable<Cookies.Cookie["options"]> = options?.persistent === false
      ? { ...sessionCookieOptions(config, { maxAge }), maxAge: undefined }
      : sessionCookieOptions(config, { maxAge })
    return HttpApiBuilder.securitySetCookie(sessionCookieSecurity(config), token, attributes)
  })

/**
 * Expires the session cookie on the response being built.
 *
 * **Gotchas**
 *
 * The attributes must repeat `path` and `domain`: a browser replaces a cookie
 * only when the name and both of those match, so an expiry written with
 * different attributes leaves the original cookie in place.
 *
 * @category combinators
 * @since 1.0.0
 */
export const clearSessionCookie = (
  config: AuthConfigShape
): Effect.Effect<void, never, HttpServerRequest.HttpServerRequest> =>
  HttpApiBuilder.securitySetCookie(
    sessionCookieSecurity(config),
    Redacted.make(""),
    expiredSessionCookieOptions(config)
  )

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

/**
 * Builds the {@link Authenticated} implementation from the ambient
 * configuration and session service.
 *
 * @category constructors
 * @since 1.0.0
 */
export const make = Effect.fnUntraced(function*() {
  const config = yield* AuthConfig
  const sessions = yield* Sessions

  const authenticate = (transport: { readonly cookie: boolean }) =>
    Effect.fnUntraced(function*<A, E, R>(
      httpEffect: Effect.Effect<A, E, R>,
      options: { readonly credential: Redacted.Redacted<string> }
    ) {
      // An absent cookie or header decodes to the empty credential. Failing here
      // is what lets `HttpApiBuilder` try the next declared transport.
      if (Redacted.value(options.credential).length === 0) {
        return yield* Effect.fail(new Unauthorized())
      }

      if (transport.cookie) {
        yield* checkOrigin(config)
      }

      const verified = yield* Effect.result(sessions.verify(options.credential))
      if (verified._tag === "Failure") {
        // A storage fault is the server's problem, not the caller's: reporting
        // it as `Unauthorized` would tell a signed-in person their session is
        // gone, and would sign them out of a working browser.
        if (verified.failure._tag === "PersistenceError") {
          return yield* Effect.die(verified.failure)
        }
        // `SessionExpired` and an unknown token are one answer at this layer:
        // the endpoint's contract declares only `Unauthorized`.
        return yield* Effect.fail(new Unauthorized())
      }

      const { refreshed, session, user } = verified.success
      if (transport.cookie && refreshed) {
        yield* setSessionCookie(config, session, options.credential)
      }

      return yield* httpEffect.pipe(
        Effect.provideService(CurrentUser, user),
        Effect.provideService(CurrentSession, session)
      )
    })

  const cookie = authenticate({ cookie: true })
  const bearer = authenticate({ cookie: false })

  // A transport this deployment never writes is a transport it must not read.
  // See the module header: accepting the un-prefixed name on a TLS deployment
  // would nullify the `__Secure-` prefix.
  const refused = <A, E, R>(
    _httpEffect: Effect.Effect<A, E, R>,
    _options: { readonly credential: Redacted.Redacted<string> }
  ): Effect.Effect<A, E | Unauthorized, Exclude<R, CurrentUser | CurrentSession>> =>
    Effect.fail(new Unauthorized())

  return Authenticated.of({
    secureSessionCookie: config.cookie.secure ? cookie : refused,
    sessionCookie: config.cookie.secure ? refused : cookie,
    bearer
  })
})

/**
 * Provides the {@link Authenticated} middleware implementation.
 *
 * **When to use**
 *
 * Every endpoint carrying `.middleware(Authenticated)` needs this layer, and
 * `Auth.layer` includes it. It is separate from the declaration in
 * `Middleware.ts` so that a browser client can import the contract without
 * pulling the session store in behind it.
 *
 * @category layers
 * @since 1.0.0
 */
export const layer: Layer.Layer<Authenticated, never, AuthConfig | Sessions> = Layer.effect(
  Authenticated,
  make()
)
