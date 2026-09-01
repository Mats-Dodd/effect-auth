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
 * @since 0.1.0
 */
import { Context, DateTime, Duration, Effect, Layer, Option, Redacted, Schema } from "effect"
import type { Cookies, HttpServerRequest } from "effect/unstable/http"
import { HttpServerResponse } from "effect/unstable/http"
import type { HttpApiEndpoint } from "effect/unstable/httpapi"
import { HttpApiBuilder } from "effect/unstable/httpapi"
import type { AuthConfigService } from "../config/AuthConfig.js"
import { AuthConfig } from "../config/AuthConfig.js"
import type { AssurancePolicy } from "../domain/Assurance.js"
import type { AuthenticatorsService } from "../domain/Authenticators.js"
import { Authenticators, list as listAuthenticators } from "../domain/Authenticators.js"
import { StepUpRequired, Unauthorized } from "../domain/Errors.js"
import type { Session, UserFields, UserId, UserModel, UserOf } from "../domain/Schema.js"
import { baseUserModel } from "../domain/Schema.js"
import { requireAssuranceFor, type Sessions, type SessionsService, sessionsOf } from "../domain/Sessions.js"
import type { PersistenceError, SessionWithUser } from "../domain/Stores.js"
import {
  expiredOAuthStateCookieOptions,
  expiredSessionCookieOptions,
  oauthStateCookieOptions,
  oauthStateCookieSecurity,
  sessionCookieName,
  sessionCookieOptions,
  sessionCookieSecurity
} from "./Cookies.js"
import type { CurrentUser } from "./Middleware.js"
import { Authenticated, AuthoritativeSession, CurrentSession, currentUserOf, RequireAssurance } from "./Middleware.js"
import { checkOrigin } from "./OriginCheck.js"
import { type SessionCache, sessionCacheOf } from "./SessionCache.js"

// -----------------------------------------------------------------------------
// The credential a request presented
// -----------------------------------------------------------------------------

/**
 * The session token this request presented, on either transport the library
 * accepts, or `None`.
 *
 * **Details**
 *
 * The cookie *this* deployment writes — only that name, so a TLS deployment
 * does not honour the un-prefixed one — or an `Authorization: Bearer` header,
 * for a client with no cookie jar. Exactly the pair `Authenticated` declares,
 * read without requiring it.
 *
 * @category combinators
 * @since 0.2.0
 */
export const presentedToken = (
  config: AuthConfigService,
  request: HttpServerRequest.HttpServerRequest
): Option.Option<Redacted.Redacted> => {
  const cookie = request.cookies[sessionCookieName(config)]
  if (cookie !== undefined && cookie.length > 0) return Option.some(Redacted.make(cookie))
  const authorization = request.headers["authorization"]
  if (authorization === undefined) return Option.none()
  const [scheme, ...rest] = authorization.split(" ")
  const token = rest.join(" ").trim()
  return scheme?.toLowerCase() === "bearer" && token.length > 0 ? Option.some(Redacted.make(token)) : Option.none()
}

/**
 * The session behind a request that was not required to have one.
 *
 * **When to use**
 *
 * On an *unauthenticated* endpoint that still wants to know who the browser
 * already was — which is one question: a sign-in that arrives carrying somebody
 * else's session is an upgrade, and `AuthHooks.beforeSessionMint` is where a
 * deployment acts on it. Without this the anonymous plugin's merge is reachable
 * only from a direct domain call, and every visitor who signs in to an existing
 * account is silently orphaned.
 *
 * **Gotchas**
 *
 * It never fails and never refuses: an absent, unknown, expired or unreadable
 * credential is all `None`, because none of them is a reason to turn away a
 * caller who was not asked for one in the first place. A storage failure is
 * `None` too — the sign-in proceeds without the merge rather than being taken
 * down by it.
 *
 * It goes through `Sessions.verify`, so a live session's rolling refresh
 * happens here exactly as it would anywhere else.
 *
 * @category combinators
 * @since 0.2.0
 */
export const optionalSession = <F extends UserFields>(options: {
  readonly config: AuthConfigService
  readonly sessions: SessionsService<F>
  readonly request: HttpServerRequest.HttpServerRequest
}): Effect.Effect<Option.Option<SessionWithUser<F>>> =>
  Option.match(presentedToken(options.config, options.request), {
    onNone: () => Effect.succeedNone,
    onSome: (token) =>
      Effect.match(options.sessions.verify(token), {
        onFailure: () => Option.none<SessionWithUser<F>>(),
        onSuccess: (verified) => Option.some({ session: verified.session, user: verified.user })
      })
  })

// -----------------------------------------------------------------------------
// Cookies
// -----------------------------------------------------------------------------

/**
 * How long a session has left to live at the moment this is evaluated, floored
 * at zero.
 *
 * @category combinators
 * @since 0.1.0
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
 * @since 0.1.0
 */
export const setSessionCookie = (
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
 * @since 0.1.0
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
 * @since 0.1.0
 */
export const setOAuthStateCookie = (
  config: AuthConfigService,
  state: Redacted.Redacted,
  options: { readonly maxAge: Duration.Duration }
): Effect.Effect<void, never, HttpServerRequest.HttpServerRequest> =>
  HttpApiBuilder.securitySetCookie(
    oauthStateCookieSecurity(config),
    state,
    oauthStateCookieOptions(config, { maxAge: options.maxAge })
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
 * @since 0.1.0
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
// Assurance
// -----------------------------------------------------------------------------

/**
 * The maximum age an endpoint's policy is measured against.
 *
 * **Details**
 *
 * A policy that names its own `maxAge` is taken literally — `Duration.infinity`
 * is how an endpoint says "any age will do". A policy that names none is
 * measured against `assurance.stepUpWindow` when it is a *step-up* policy, and
 * against `session.freshAge` otherwise, which is the rule `requireFresh` used
 * to state. Neither default is a second copy of the freshness *rule*: what
 * happens to the resolved policy is `Sessions.requireAssuranceFor`'s, in one
 * place, measured from `session.authenticatedAt`.
 *
 * A step-up policy is one asking for `aal2` **or** naming `methods`. Both are
 * ways of spelling "a second factor is required", and the two spellings must
 * get the same window: `{ methods: ["totp", "passkey"] }` is if anything
 * stricter than `{ aal: "aal2" }`, so admitting a proof twenty hours old there
 * while refusing it beside the other spelling would be backwards.
 *
 * @category combinators
 * @since 0.2.0
 */
export const resolveAssurancePolicy = (config: AuthConfigService, policy: AssurancePolicy): AssurancePolicy =>
  policy.maxAge !== undefined
    ? policy
    : {
        ...policy,
        maxAge:
          policy.aal === "aal2" || policy.methods !== undefined
            ? config.assurance.stepUpWindow
            : config.session.freshAge
      }

/**
 * The kinds of factor a person could step up with, for
 * `StepUpRequired.current.available`.
 *
 * **Details**
 *
 * The distinct `type`s of every authenticator the {@link Authenticators} seam
 * reports that can either sign in or serve as a second factor, in the order the
 * contributors listed them. It carries no identifier, no address and no secret
 * — the names of kinds only — which is what lets a client prompt for the right
 * factor, and degrade gracefully when the answer is an empty array, without the
 * refusal becoming an oracle.
 *
 * **Gotchas**
 *
 * A deployment that installs no factor plugin answers `[]`. That is honest
 * about the seam and not about the account: `POST /auth/reauthenticate` is
 * still open to anybody whose account has a password.
 *
 * @category combinators
 * @since 0.2.0
 */
export const availableFactors = (
  authenticators: AuthenticatorsService,
  userId: UserId
): Effect.Effect<ReadonlyArray<string>, PersistenceError> =>
  Effect.map(listAuthenticators(authenticators, userId), (summaries) => {
    const seen = new Set<string>()
    const names: Array<string> = []
    for (const summary of summaries) {
      if (!summary.signIn && !summary.secondFactor) continue
      if (seen.has(summary.type)) continue
      seen.add(summary.type)
      names.push(summary.type)
    }
    return names
  })

const encodeStepUp = Schema.encodeUnknownEffect(Schema.toCodecJson(StepUpRequired))

/**
 * A refusal for want of assurance, as the response the caller receives.
 *
 * **Details**
 *
 * The guard answers `403` directly instead of failing, and that is not a style
 * choice. `HttpApiBuilder` runs a security middleware once per declared
 * transport and treats *any* failure of one as "this transport did not
 * authenticate; try the next" — keeping only the last transport's failure. The
 * `bearer` scheme is last and answers `Unauthorized` for the empty credential a
 * cookie request carries, so a `StepUpRequired` raised on the cookie transport
 * would be silently replaced by a `401`. Returning the response makes the
 * transport *succeed*, which is what stops the loop.
 *
 * The body is the error's own JSON encoding, which is what `HttpApiBuilder`
 * would have written for it — the error is
 * declared on {@link Authenticated}, so the generated client already holds a
 * `403` decoder for it, and `test/http/StepUp.test.ts` pins the round trip
 * through that client rather than trusting this comment.
 *
 * @category combinators
 * @since 0.2.0
 */
export const stepUpResponse = (error: StepUpRequired): Effect.Effect<HttpServerResponse.HttpServerResponse> =>
  Effect.flatMap(Effect.orDie(encodeStepUp(error)), (body) =>
    Effect.orDie(HttpServerResponse.json(body, { status: 403 }))
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
 * @since 0.1.0
 */
export const make = Effect.fnUntraced(function* <F extends UserFields>(model: UserModel<F>) {
  const config = yield* AuthConfig
  const sessions = yield* sessionsOf(model)
  const cache = yield* sessionCacheOf(model)
  const authenticators = yield* Authenticators
  const currentUser = currentUserOf(model)

  const authenticate = (transport: { readonly cookie: boolean }) =>
    // `A` is fixed to `HttpServerResponse` rather than left generic because the
    // assurance guard answers with one — see `stepUpResponse`. It is what every
    // endpoint effect this middleware wraps already is.
    Effect.fnUntraced(function* <E, R>(
      httpEffect: Effect.Effect<HttpServerResponse.HttpServerResponse, E, R>,
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

      const required = Context.get(options.endpoint.annotations, RequireAssurance)

      // The assurance guard, run once for whichever path resolved the session,
      // and always before the endpoint's own effect. `available` costs a read
      // of the `Authenticators` seam and is paid only on the endpoints that
      // declare a policy.
      const guarded = (session: Session, user: UserOf<F>) =>
        Effect.gen(function* () {
          if (required !== undefined) {
            const available = yield* Effect.orDie(availableFactors(authenticators, user.id))
            const checked = yield* Effect.result(
              requireAssuranceFor(session, resolveAssurancePolicy(config, required), available)
            )
            if (checked._tag === "Failure") {
              return yield* stepUpResponse(checked.failure)
            }
          }
          return yield* httpEffect.pipe(
            Effect.provideService(currentUser, user),
            Effect.provideService(CurrentSession, session)
          )
        })

      // The cache is a cookie-transport optimisation and nothing else: a bearer
      // client has no jar, and an endpoint that changes a credential or an
      // identity has to see the row rather than a snapshot of it — see
      // `AuthoritativeSession`. An endpoint that states an assurance policy is
      // excluded for a second reason: a snapshot records the level the session
      // held when it was written, so an elevation since would be invisible to
      // it and the guard would refuse a session that has already stepped up —
      // or, if the snapshot were the newer of the two, admit one that has been
      // revoked. The decision is made against the row every time.
      const cacheable =
        transport.cookie && required === undefined && !Context.get(options.endpoint.annotations, AuthoritativeSession)

      if (cacheable) {
        const cached = yield* cache.read(options.credential)
        if (Option.isSome(cached)) {
          // No touch and no `Set-Cookie`: a snapshot expires at the instant the
          // rolling refresh becomes due, so a session that needed either would
          // not have been served from here.
          return yield* guarded(cached.value.session, cached.value.user)
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

      return yield* guarded(session, user)
    })

  const cookie = authenticate({ cookie: true })
  const bearer = authenticate({ cookie: false })

  // A transport this deployment never writes is a transport it must not read.
  // See the module header: accepting the un-prefixed name on a TLS deployment
  // would nullify the `__Secure-` prefix.
  const refused = <E, R>(
    _httpEffect: Effect.Effect<HttpServerResponse.HttpServerResponse, E, R>,
    _options: {
      readonly credential: Redacted.Redacted
      readonly endpoint: HttpApiEndpoint.Top
    }
  ): Effect.Effect<HttpServerResponse.HttpServerResponse, E | Unauthorized, Exclude<R, CurrentUser | CurrentSession>> =>
    Effect.fail(Unauthorized.make())

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
 * @since 0.1.0
 */
export const layerFor = <F extends UserFields>(
  model: UserModel<F>
): Layer.Layer<Authenticated, never, AuthConfig | Sessions | SessionCache> => Layer.effect(Authenticated, make(model))

/**
 * {@link layerFor}, for a deployment that added no user fields of its own.
 *
 * @category layers
 * @since 0.1.0
 */
export const layer: Layer.Layer<Authenticated, never, AuthConfig | Sessions | SessionCache> = layerFor(baseUserModel)
