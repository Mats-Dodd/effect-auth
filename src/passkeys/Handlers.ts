/**
 * The server implementation of {@link PasskeysApiGroup}.
 *
 * **Details**
 *
 * Built exactly as this library's own handlers are, and out of the same pieces:
 * `AuthHandlers.forGroup` is the boundary that lets a group be implemented
 * inside whatever `HttpApi` a consumer composed it into, and `clientMeta`,
 * `setSessionCookie`, `setPendingCookie` and `serverFault` are reused rather
 * than reimplemented. The handlers hold no policy: each reads the decoded
 * request, calls one method of {@link Passkeys}, and turns the result into the
 * endpoint's declared response.
 *
 * **Gotchas — the three things only the HTTP layer can do**
 *
 * *The ceremony cookie.* A challenge handle is a credential, so it travels in
 * `__Host-effect_auth.passkey` and nowhere else — never in the option document,
 * which is script-readable. It is cleared on every exit from a verify, success
 * or failure, so a single-use value never rides a second request.
 *
 * *A session beside a ceremony.* `authenticate/options` and
 * `authenticate/verify` are unauthenticated — a passkey *is* the credential —
 * but a request that happens to carry a live session is how a step-up is told
 * from a sign-in. The session is therefore read *optionally*: from the session
 * cookie, or from a bearer token, and never required.
 *
 * *One cookie per response.* A `202 MfaRequired` sets the pending-authentication
 * cookie and no session cookie; every other outcome sets at most one session
 * cookie. The two are mutually exclusive by construction — `SignInResult` is a
 * union — and the response's own `Set-Cookie` list is what pins it.
 *
 * @since 0.2.0
 */
import { DateTime, Duration, Effect, Option, Redacted } from "effect"
import { HttpApiBuilder } from "effect/unstable/httpapi"
import type { HttpServerRequest } from "effect/unstable/http"
import { RateLimiter } from "effect/unstable/persistence"
import { AuthConfig, type AuthConfigService } from "../config/AuthConfig.js"
import { NotFound } from "../domain/Errors.js"
import type { Session, User } from "../domain/Schema.js"
import { CurrentUser } from "../http/Middleware.js"
import type { PluginCookie } from "../http/Cookies.js"
import { pluginCookieFor, sessionCookieName } from "../http/Cookies.js"
import * as AuthHandlers from "../http/Handlers.js"
import { setSessionCookie } from "../http/MiddlewareLive.js"
import { requireTrustedIfPresent } from "../http/OriginCheck.js"
import type { Bucket } from "../http/RateLimits.js"
import { consumeWith } from "../http/RateLimits.js"
import { SessionCache } from "../http/SessionCache.js"
import { Sessions } from "../domain/Sessions.js"
import { PasskeysApiGroup, type PasskeySummary } from "./Api.js"
import { ChallengeExpired } from "./Errors.js"
import { Passkeys } from "./Passkeys.js"
import type { Passkey } from "./Schema.js"

// -----------------------------------------------------------------------------
// The ceremony cookie
// -----------------------------------------------------------------------------

/**
 * The name, before any prefix, of the cookie a passkey ceremony rides in.
 *
 * **Details**
 *
 * `__Host-effect_auth.passkey` on a TLS deployment, the bare name on plain
 * HTTP — {@link ceremonyCookie} makes that decision through
 * `AuthCookies.pluginCookieFor`, so the prefix rule, the `SameSite` cap and the
 * "an expiry repeats the attributes" rule are the ones this library already
 * makes for its session and OAuth-state cookies.
 *
 * @category constructors
 * @since 0.2.0
 */
export const ceremonyCookieBaseName = "effect_auth.passkey"

/**
 * The ceremony cookie for this deployment.
 *
 * @category combinators
 * @since 0.2.0
 */
export const ceremonyCookie = (config: AuthConfigService, maxAge: Duration.Duration): PluginCookie =>
  pluginCookieFor(config, { baseName: ceremonyCookieBaseName, hostOnly: true, maxAge })

// -----------------------------------------------------------------------------
// Rate limits
// -----------------------------------------------------------------------------

/**
 * The limit on minting a ceremony: six per minute per client.
 *
 * **Details**
 *
 * A ceremony writes a `verifications` row, and both option endpoints are
 * reachable without a credential, so an uncounted one is a free way to grow the
 * table every reset and callback depends on. Six rather than three, because a
 * person retrying a passkey prompt that their browser dismissed is ordinary.
 *
 * @category constructors
 * @since 0.2.0
 */
export const ceremonyBucket: Bucket = {
  name: "passkey-ceremony",
  limit: 6,
  window: Duration.seconds(60)
}

/**
 * The limit on completing a ceremony: three per ten seconds per client, the
 * same policy the password endpoints carry and — because a key carries the
 * request path — never the same counter.
 *
 * @category constructors
 * @since 0.2.0
 */
export const assertionBucket: Bucket = {
  name: "passkey-assertion",
  limit: 3,
  window: Duration.seconds(10)
}

// -----------------------------------------------------------------------------
// Projections
// -----------------------------------------------------------------------------

/**
 * A stored credential as its owner is shown it.
 *
 * @category combinators
 * @since 0.2.0
 */
export const toSummary = (passkey: Passkey): PasskeySummary => ({
  id: passkey.id,
  name: passkey.name,
  aaguid: passkey.aaguid,
  transports: passkey.transports,
  backedUp: passkey.backedUp,
  createdAt: passkey.createdAt,
  lastUsedAt: passkey.lastUsedAt
})

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

/**
 * The services the passkey handlers need.
 *
 * @category models
 * @since 0.2.0
 */
export type HandlerServices = AuthConfig | Passkeys | Sessions | SessionCache | RateLimiter.RateLimiter

const bearerPrefix = "Bearer "

/**
 * Implements the `passkeys` group of an `HttpApi` that contains it.
 *
 * **Example**
 *
 * ```ts skip-type-checking
 * import { HttpApi } from "effect/unstable/httpapi"
 * import { AuthApi, AuthHandlers } from "effect-auth"
 * import { PasskeysApiGroup, PasskeyHandlers } from "effect-auth/passkeys"
 *
 * const AppApi = HttpApi.make("app").addHttpApi(AuthApi).add(PasskeysApiGroup)
 * const HandlersLive = PasskeyHandlers.handlers(AppApi)
 * ```
 *
 * **Gotchas**
 *
 * The API passed here must be the one passed to `HttpApiBuilder.layer` — see
 * `AuthHandlers.forGroup`.
 *
 * @category layers
 * @since 0.2.0
 */
export const handlers = AuthHandlers.forGroup(PasskeysApiGroup, (handlers) =>
  Effect.gen(function* () {
    const config = yield* AuthConfig
    const passkeys = yield* Passkeys
    const sessions = yield* Sessions
    const cache = yield* SessionCache
    const limiter = yield* RateLimiter.RateLimiter

    const rateLimit = (bucket: Bucket, request: HttpServerRequest.HttpServerRequest) =>
      consumeWith({ config, limiter, bucket, request })

    /**
     * `OriginCheck.requireTrustedIfPresent`, bound to the configuration this
     * layer already resolved.
     *
     * **Gotchas**
     *
     * The published guard reads `AuthConfig` from the *request* context, which
     * would leave the whole handler layer with a request-time requirement that
     * `AuthTest.layerHttpApi`'s `extra` parameter cannot discharge. Providing
     * the configuration once, here, discharges half of it and leaves only the
     * request — which is exactly what a handler already has. The rule itself is
     * not restated: a second copy of "which origins are trusted" is the bug
     * that module exists to prevent.
     */
    const trustedOrigin = Effect.provideService(requireTrustedIfPresent, AuthConfig, config)

    const cookie = ceremonyCookie(config, passkeys.config.challengeTtl)

    const setCeremonyCookie = (handle: Redacted.Redacted, expiresAt: DateTime.Utc) =>
      Effect.gen(function* () {
        const now = yield* DateTime.now
        const maxAge = Duration.max(Duration.zero, DateTime.distance(now, expiresAt))
        const attributes = ceremonyCookie(config, maxAge)
        yield* HttpApiBuilder.securitySetCookie(attributes.security, handle, attributes.options)
      })

    const clearCeremonyCookie = HttpApiBuilder.securitySetCookie(
      cookie.security,
      Redacted.make(""),
      cookie.expiredOptions
    )

    /**
     * The handle out of the ceremony cookie, or the one answer a missing,
     * empty or unknown one gets: the ceremony is over.
     */
    const ceremonyHandle = (request: HttpServerRequest.HttpServerRequest) => {
      const presented = request.cookies[cookie.name]
      return presented === undefined || presented.length === 0
        ? Option.none<Redacted.Redacted>()
        : Option.some(Redacted.make(presented))
    }

    /**
     * The session this request happens to carry, if any.
     *
     * **Gotchas**
     *
     * Optional by construction: these endpoints are reachable by somebody who
     * cannot sign in at all, and a session is only ever an *upgrade* of what
     * the ceremony means. A storage fault is still a fault — it is re-raised
     * rather than read as "not signed in", because failing open here would turn
     * a database blip into a silently downgraded step-up.
     */
    const presentedSession = (request: HttpServerRequest.HttpServerRequest) =>
      Effect.gen(function* () {
        const cookieToken = request.cookies[sessionCookieName(config)]
        const authorization = request.headers["authorization"]
        const bearer =
          authorization !== undefined && authorization.startsWith(bearerPrefix)
            ? authorization.slice(bearerPrefix.length)
            : undefined
        const presented = cookieToken !== undefined && cookieToken.length > 0 ? cookieToken : bearer
        if (presented === undefined || presented.length === 0) {
          return Option.none<{ readonly session: Session; readonly user: User }>()
        }
        const verified = yield* Effect.result(sessions.verify(Redacted.make(presented)))
        if (verified._tag === "Failure") {
          if (verified.failure._tag === "PersistenceError") return yield* verified.failure
          return Option.none<{ readonly session: Session; readonly user: User }>()
        }
        return Option.some({ session: verified.success.session, user: verified.success.user })
      })

    return handlers
      .handle("registerOptions", ({ payload, request }) =>
        Effect.gen(function* () {
          yield* rateLimit(ceremonyBucket, request)
          const user = yield* CurrentUser
          const issued = yield* passkeys
            .registrationOptions({
              user,
              ...(payload.authenticatorAttachment === undefined
                ? {}
                : { authenticatorAttachment: payload.authenticatorAttachment })
            })
            .pipe(AuthHandlers.serverFault)
          yield* setCeremonyCookie(issued.handle, issued.expiresAt)
          return issued.options
        })
      )
      .handle("registerVerify", ({ payload, request }) =>
        Effect.gen(function* () {
          yield* rateLimit(assertionBucket, request)
          // Cleared whatever happens below: the handle addresses a row that has
          // already been claimed by the time anything can fail.
          yield* clearCeremonyCookie
          const user = yield* CurrentUser
          const handle = ceremonyHandle(request)
          // No cookie is the same state as a spent or expired one: there is no
          // ceremony here.
          if (Option.isNone(handle)) return yield* ChallengeExpired.make()
          const passkey = yield* passkeys
            .verifyRegistration({
              user,
              handle: handle.value,
              response: payload.response,
              ...(payload.name === undefined ? {} : { name: payload.name })
            })
            .pipe(AuthHandlers.serverFault)
          return toSummary(passkey)
        })
      )
      .handle("authenticateOptions", ({ payload, request }) =>
        Effect.gen(function* () {
          // Unauthenticated, and it writes a row and answers about an address
          // somebody else may own: a cross-origin form POST must not reach it.
          yield* trustedOrigin
          yield* rateLimit(ceremonyBucket, request)
          const current = yield* presentedSession(request).pipe(AuthHandlers.serverFault)
          const issued = yield* passkeys
            .authenticationOptions({
              session: Option.map(current, (held) => held.session),
              ...(payload.email === undefined ? {} : { email: payload.email })
            })
            .pipe(AuthHandlers.serverFault)
          yield* setCeremonyCookie(issued.handle, issued.expiresAt)
          return issued.options
        })
      )
      .handle("authenticateVerify", ({ payload, request }) =>
        Effect.gen(function* () {
          yield* rateLimit(assertionBucket, request)
          yield* clearCeremonyCookie
          const handle = ceremonyHandle(request)
          // No cookie is the same state as a spent or expired one: there is no
          // ceremony here.
          if (Option.isNone(handle)) return yield* ChallengeExpired.make()
          const current = yield* presentedSession(request).pipe(AuthHandlers.serverFault)
          const outcome = yield* passkeys
            .authenticate({
              handle: handle.value,
              response: payload.response,
              session: Option.map(current, (held) => held.session),
              request: { ...AuthHandlers.clientMeta(config, request), rememberMe: payload.rememberMe }
            })
            .pipe(AuthHandlers.serverFault)

          if (outcome._tag === "Elevated") {
            // The token rotated, so the cookie has to carry the new one — the
            // old one stops resolving the instant this returns. The snapshot
            // beside it names the old token and the old level, so it is
            // rewritten; `write` is a no-op unless the cookie was presented.
            yield* setSessionCookie(config, outcome.session, outcome.token, {
              persistent: outcome.session.rememberMe
            })
            yield* cache.write(outcome.session, outcome.verified.user)
            return { user: outcome.verified.user, session: outcome.session }
          }

          if (outcome.result._tag === "Challenge") {
            // The pending token, and only the pending token: no session was
            // minted, so no session cookie may be written here.
            const now = yield* DateTime.now
            yield* AuthHandlers.setPendingCookie(config, outcome.result.token, {
              maxAge: Duration.max(Duration.zero, DateTime.distance(now, outcome.result.expiresAt))
            })
            return {
              _tag: "MfaRequired" as const,
              available: outcome.result.available,
              expiresAt: outcome.result.expiresAt
            }
          }

          yield* setSessionCookie(config, outcome.result.session, outcome.result.token, {
            persistent: payload.rememberMe !== false
          })
          return { user: outcome.result.user, session: outcome.result.session }
        })
      )
      .handle("listPasskeys", () =>
        Effect.gen(function* () {
          const user = yield* CurrentUser
          const rows = yield* passkeys.list(user.id).pipe(AuthHandlers.serverFault)
          return rows.map(toSummary)
        })
      )
      .handle("renamePasskey", ({ payload }) =>
        Effect.gen(function* () {
          const user = yield* CurrentUser
          const renamed = yield* passkeys.rename(user.id, payload.id, payload.name).pipe(AuthHandlers.serverFault)
          // Ownership was in the statement, so "not yours" and "no such row"
          // arrive here as one `None` and leave as one answer.
          if (Option.isNone(renamed)) return yield* NotFound.make()
          return toSummary(renamed.value)
        })
      )
      .handle("deletePasskey", ({ payload }) =>
        Effect.gen(function* () {
          const user = yield* CurrentUser
          const removed = yield* passkeys.remove(user.id, payload.id).pipe(AuthHandlers.serverFault)
          if (!removed) return yield* NotFound.make()
          return AuthHandlers.acknowledged
        })
      )
  })
)
