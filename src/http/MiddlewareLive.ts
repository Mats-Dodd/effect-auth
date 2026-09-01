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
 * The session cookie cache, when a deployment switches it on, sits between the
 * origin check and `Sessions.verify`: a request presenting a valid snapshot is
 * served from it with no database read at all, and one that is not leaves a
 * fresh snapshot behind. It applies to the cookie transports only, and never to
 * an endpoint annotated `AuthoritativeSession` — see `http/SessionCache.ts`,
 * whose module header carries the threat model this trades against.
 *
 * @since 1.0.0
 */
import { Context, DateTime, Duration, Effect, Layer, Option, Redacted } from "effect"
import { dual } from "effect/Function"
import type { Cookies, HttpServerRequest } from "effect/unstable/http"
import type { HttpApiEndpoint } from "effect/unstable/httpapi"
import { HttpApiBuilder } from "effect/unstable/httpapi"
import type { AuthConfigService } from "../config/AuthConfig.js"
import { AuthConfig } from "../config/AuthConfig.js"
import { Unauthorized } from "../domain/Errors.js"
import type { Session, UserFields, UserModel } from "../domain/Schema.js"
import { baseUserModel } from "../domain/Schema.js"
import { type Sessions, sessionsOf } from "../domain/Sessions.js"
import {
  expiredOAuthStateCookieOptions,
  expiredSessionCookieOptions,
  oauthStateCookieOptions,
  oauthStateCookieSecurity,
  sessionCookieOptions,
  sessionCookieSecurity
} from "./Cookies.js"
import type { CurrentUser } from "./Middleware.js"
import { Authenticated, AuthoritativeSession, CurrentSession, currentUserOf } from "./Middleware.js"
import { checkOrigin } from "./OriginCheck.js"
import { type SessionCache, sessionCacheOf } from "./SessionCache.js"

// -----------------------------------------------------------------------------
// Cookies
// -----------------------------------------------------------------------------

/**
 * How long a session has left to live at the moment this is evaluated, floored
 * at zero.
 *
 * @category combinators
 * @since 1.0.0
 */
export const remainingLifetime = (session: Session): Effect.Effect<Duration.Duration> =>
  Effect.map(DateTime.now, (now) => Duration.max(Duration.zero, DateTime.distance(now, session.expiresAt)))

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
 * The rolling refresh must pass `persistent` explicitly — `session.rememberMe`,
 * read off the row — or it would re-send a browser-session cookie *with* a
 * `Max-Age` and silently promote it to a persistent one.
 *
 * That promotion is not an exotic configuration: `AuthConfig` bounds
 * `updateAge` by `rememberMeDisabledExpiresIn` precisely so that the rolling
 * refresh applies to the shortest session a deployment mints, which means a
 * `rememberMe: false` session normally *does* become refresh-due before it
 * expires. (The condition is `updateAge` **shorter** than
 * `rememberMeDisabledExpiresIn`, not longer — an earlier note here had it
 * backwards.) The fix is on the row rather than in the configuration: the
 * session records the choice, so a refresh re-sends a non-persistent session as
 * a browser-session cookie and a short session goes on rolling while staying
 * short, which is what `Sessions.grantedLifetime` exists to do.
 *
 * @category combinators
 * @since 1.0.0
 */
export const setSessionCookie: {
  (
    session: Session,
    token: Redacted.Redacted,
    options?: { readonly persistent?: boolean | undefined }
  ): (config: AuthConfigService) => Effect.Effect<void, never, HttpServerRequest.HttpServerRequest>
  (
    config: AuthConfigService,
    session: Session,
    token: Redacted.Redacted,
    options?: { readonly persistent?: boolean | undefined }
  ): Effect.Effect<void, never, HttpServerRequest.HttpServerRequest>
} = dual(
  // Not an arity, because the optional `options` makes three arguments mean
  // either style. What is in the second slot does not: the data-first call has
  // the session row there, the pipeable one the redacted token.
  (args) => !Redacted.isRedacted(args[1]),
  (
    config: AuthConfigService,
    session: Session,
    token: Redacted.Redacted,
    options?: { readonly persistent?: boolean | undefined }
  ): Effect.Effect<void, never, HttpServerRequest.HttpServerRequest> =>
    Effect.flatMap(remainingLifetime(session), (maxAge) => {
      const attributes: NonNullable<Cookies.Cookie["options"]> =
        options?.persistent === false
          ? { ...sessionCookieOptions(config, { maxAge }), maxAge: undefined }
          : sessionCookieOptions(config, { maxAge })
      return HttpApiBuilder.securitySetCookie(sessionCookieSecurity(config), token, attributes)
    })
)

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
  config: AuthConfigService
): Effect.Effect<void, never, HttpServerRequest.HttpServerRequest> =>
  HttpApiBuilder.securitySetCookie(
    sessionCookieSecurity(config),
    Redacted.make(""),
    expiredSessionCookieOptions(config)
  )

/**
 * Attaches the short-lived OAuth state-binding cookie to the response being
 * built, carrying the raw `state` value.
 *
 * **When to use**
 *
 * At the *start* of an OAuth flow — `signInSocial`, `linkSocial` — so the
 * callback can require the `state` the browser comes back with to be the one
 * this browser was issued. Without it the single-use consume still stops
 * forgery and replay, but not an attacker luring a victim to a callback for a
 * `state` the attacker legitimately obtained (login CSRF). The cookie's
 * lifetime mirrors the pending request's, so the browser forgets it when the
 * state row expires.
 *
 * @category combinators
 * @since 1.0.0
 */
export const setOAuthStateCookie: {
  (
    state: Redacted.Redacted,
    options: { readonly maxAge: Duration.Duration }
  ): (config: AuthConfigService) => Effect.Effect<void, never, HttpServerRequest.HttpServerRequest>
  (
    config: AuthConfigService,
    state: Redacted.Redacted,
    options: { readonly maxAge: Duration.Duration }
  ): Effect.Effect<void, never, HttpServerRequest.HttpServerRequest>
} = dual(
  3,
  (
    config: AuthConfigService,
    state: Redacted.Redacted,
    options: { readonly maxAge: Duration.Duration }
  ): Effect.Effect<void, never, HttpServerRequest.HttpServerRequest> =>
    HttpApiBuilder.securitySetCookie(
      oauthStateCookieSecurity(config),
      state,
      oauthStateCookieOptions(config, { maxAge: options.maxAge })
    )
)

/**
 * Expires the OAuth state-binding cookie on the response being built.
 *
 * **When to use**
 *
 * At the callback, once the binding has been checked — success or failure — so
 * the single-use value never rides a second request. Repeats `path` and
 * `domain`, as {@link clearSessionCookie} does.
 *
 * @category combinators
 * @since 1.0.0
 */
export const clearOAuthStateCookie = (
  config: AuthConfigService
): Effect.Effect<void, never, HttpServerRequest.HttpServerRequest> =>
  HttpApiBuilder.securitySetCookie(
    oauthStateCookieSecurity(config),
    Redacted.make(""),
    expiredOAuthStateCookieOptions(config)
  )

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

/**
 * Builds the {@link Authenticated} implementation from the ambient
 * configuration and session service, for the user model given.
 *
 * **Details**
 *
 * `model` is how a deployment's own user columns reach a handler: the
 * authenticated user is provided through `currentUserOf(model)`, which is the
 * `CurrentUser` key with that model's shape. Nothing else about the middleware
 * — the transports, the origin check, the error — depends on it.
 *
 * @category constructors
 * @since 1.0.0
 */
export const make = Effect.fnUntraced(function* <F extends UserFields>(model: UserModel<F>) {
  const config = yield* AuthConfig
  const sessions = yield* sessionsOf(model)
  const cache = yield* sessionCacheOf(model)
  const currentUser = currentUserOf(model)

  const authenticate = (transport: { readonly cookie: boolean }) =>
    Effect.fnUntraced(function* <A, E, R>(
      httpEffect: Effect.Effect<A, E, R>,
      options: {
        readonly credential: Redacted.Redacted
        readonly endpoint: HttpApiEndpoint.Top
      }
    ) {
      // An absent cookie or header decodes to the empty credential. Failing here
      // is what lets `HttpApiBuilder` try the next declared transport.
      if (Redacted.value(options.credential).length === 0) {
        return yield* Unauthorized.make()
      }

      if (transport.cookie) {
        yield* checkOrigin(config)
      }

      // The cache is a cookie-transport optimisation and nothing else: a bearer
      // client has no jar, and an endpoint that changes a credential or an
      // identity has to see the row rather than a snapshot of it — see
      // `AuthoritativeSession`.
      const cacheable = transport.cookie && !Context.get(options.endpoint.annotations, AuthoritativeSession)

      if (cacheable) {
        const cached = yield* cache.read(options.credential)
        if (Option.isSome(cached)) {
          // No touch and no `Set-Cookie`: a snapshot expires at the instant the
          // rolling refresh becomes due, so a session that needed either would
          // not have been served from here.
          return yield* httpEffect.pipe(
            Effect.provideService(currentUser, cached.value.user),
            Effect.provideService(CurrentSession, cached.value.session)
          )
        }
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
        return yield* Unauthorized.make()
      }

      const { refreshed, session, user } = verified.success
      if (transport.cookie && refreshed) {
        // The row records whether the person asked to be remembered, so the
        // re-sent cookie keeps its persistence rather than being promoted to a
        // `Max-Age` one — see `setSessionCookie`.
        yield* setSessionCookie(config, session, options.credential, { persistent: session.rememberMe })
      }
      if (cacheable) {
        // Written after the refresh, so the snapshot carries the expiry the
        // cookie was just re-sent with.
        yield* cache.write(session, user)
      }

      return yield* httpEffect.pipe(
        Effect.provideService(currentUser, user),
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
    _options: {
      readonly credential: Redacted.Redacted
      readonly endpoint: HttpApiEndpoint.Top
    }
  ): Effect.Effect<A, E | Unauthorized, Exclude<R, CurrentUser | CurrentSession>> => Effect.fail(Unauthorized.make())

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
 * **Details**
 *
 * The layer's type does not mention the model: `Authenticated` is one key with
 * one shape whatever a deployment's user carries. What the model decides is the
 * shape of the `CurrentUser` a handler reads back — see
 * `Middleware.currentUserOf`.
 *
 * @category layers
 * @since 1.0.0
 */
export const layerFor = <F extends UserFields>(
  model: UserModel<F>
): Layer.Layer<Authenticated, never, AuthConfig | Sessions | SessionCache> => Layer.effect(Authenticated, make(model))

/**
 * {@link layerFor}, for a deployment that added no user fields of its own.
 *
 * @category layers
 * @since 1.0.0
 */
export const layer: Layer.Layer<Authenticated, never, AuthConfig | Sessions | SessionCache> = layerFor(baseUserModel)
