/**
 * The server implementation of {@link TwoFactorApiGroup}.
 *
 * **Details**
 *
 * Built exactly as this library's own handlers are, out of the same pieces:
 * `AuthHandlers.forGroup` is the boundary that lets a group be implemented
 * inside whatever `HttpApi` a consumer composed it into, and `clientMeta`,
 * `setSessionCookie` and `serverFault` are reused rather than reimplemented.
 * Each handler reads its request, calls one method of {@link TwoFactor}, and
 * turns the result into the endpoint's declared response.
 *
 * **Gotchas — the one thing this module does that no other plugin does**
 *
 * `totp/verify` and `recovery/verify` resolve their own subject, because the
 * `Authenticated` middleware cannot express "a session, or the pending
 * authentication that exists precisely because there is no session yet". The
 * resolution is not a second authentication scheme: the pending token is
 * spent by `Verifications.claim` inside the service, and a presented session
 * token is resolved by `Sessions.verify` — the same function the middleware
 * calls, with the same rolling refresh and the same failures. What this module
 * adds around it is what the middleware would have added: the origin check,
 * and a bucket.
 *
 * @since 0.2.0
 */
import { Duration, Effect, Option, Redacted } from "effect"
import type { HttpServerRequest } from "effect/unstable/http"
import { RateLimiter } from "effect/unstable/persistence"
import type { AuthConfigService } from "../config/AuthConfig.js"
import { AuthConfig } from "../config/AuthConfig.js"
import { NotFound, Unauthorized } from "../domain/Errors.js"
import type { Session, User } from "../domain/Schema.js"
import { baseUserModel } from "../domain/Schema.js"
import { Sessions } from "../domain/Sessions.js"
import { sessionCookieName } from "../http/Cookies.js"
import * as AuthHandlers from "../http/Handlers.js"
import { CurrentUser } from "../http/Middleware.js"
import { setSessionCookie } from "../http/MiddlewareLive.js"
import { requireTrustedIfPresent } from "../http/OriginCheck.js"
import type { Bucket } from "../http/RateLimits.js"
import { consumeWith, credentials } from "../http/RateLimits.js"
import { SessionCache } from "../http/SessionCache.js"
import { TwoFactorApiGroup } from "./Api.js"
import type { ChallengeSubject } from "./TwoFactor.js"
import { clearTrustedDeviceCookie, readTrustedDeviceCookie, setTrustedDeviceCookie, TwoFactor } from "./TwoFactor.js"

/**
 * The services the two-factor handlers need.
 *
 * @category models
 * @since 0.2.0
 */
export type HandlerServices = AuthConfig | TwoFactor | Sessions | SessionCache | RateLimiter.RateLimiter

/**
 * The session token this request presented, on either transport the library
 * accepts.
 *
 * **Details**
 *
 * The cookie this deployment writes — only that name, so a TLS deployment does
 * not honour the un-prefixed one — or an `Authorization: Bearer` header, for a
 * client with no cookie jar. It is the same pair `Authenticated` declares.
 *
 * @category combinators
 * @since 0.2.0
 */
export const sessionCredential = (
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
 * The pending-authentication token this request presented, if it presented
 * one.
 *
 * @category combinators
 * @since 0.2.0
 */
export const pendingCredential = (
  config: AuthConfigService,
  request: HttpServerRequest.HttpServerRequest
): Option.Option<Redacted.Redacted> => {
  const value = request.cookies[AuthHandlers.pendingCookie(config, Duration.zero).name]
  return value === undefined || value.length === 0 ? Option.none() : Option.some(Redacted.make(value))
}

/**
 * Implements the `twoFactor` group of an `HttpApi` that contains it.
 *
 * **Example**
 *
 * ```ts skip-type-checking
 * import { HttpApi } from "effect/unstable/httpapi"
 * import { AuthApi, TwoFactor } from "effect-auth"
 *
 * const AppApi = HttpApi.make("app").addHttpApi(AuthApi).add(TwoFactor.TwoFactorApiGroup)
 * const HandlersLive = TwoFactor.handlers(AppApi)
 * ```
 *
 * @category layers
 * @since 0.2.0
 */
export const handlers = AuthHandlers.forGroup(TwoFactorApiGroup, (handlers) =>
  Effect.gen(function* () {
    const config = yield* AuthConfig
    const twoFactor = yield* TwoFactor
    const sessions = yield* Sessions
    const cache = yield* SessionCache
    const limiter = yield* RateLimiter.RateLimiter

    // Resolved here, when the layer is built, so that no handler carries a
    // request-time requirement.
    const rateLimit = (bucket: Bucket, request: HttpServerRequest.HttpServerRequest) =>
      consumeWith({ config, limiter, bucket, request })

    // The library's own guard, with the configuration it reads resolved at
    // build time like everything else here — the same check `checkOrigin`
    // makes for the cookie transport, not a second copy of it.
    const requireTrustedOrigin = requireTrustedIfPresent.pipe(Effect.provideService(AuthConfig, config))

    /**
     * Which of the two subjects is answering, and what proves it.
     *
     * The pending cookie wins when both are present: a browser that was asked
     * for a second factor is finishing that sign-in, not raising the session it
     * happened to still be holding.
     */
    /**
     * Which of the two things a verify endpoint can be answering for.
     *
     * **Gotchas**
     *
     * A refusal never clears the pending cookie, and that is deliberate. Two
     * requests carrying the same wrong code — a double-clicked Submit — race
     * inside the service: the first claims the row, compares, and puts it back
     * under the *same* handle with one attempt fewer, and the second, arriving
     * in that window, finds no row and is answered `InvalidToken`. Clearing on
     * that answer threw away a handle that a moment later named a live row
     * again, and made a typo cost the whole sign-in rather than one attempt.
     *
     * Leaving it costs nothing, because the cookie's `Max-Age` is the
     * challenge's own remaining lifetime: a genuinely dead handle stops being
     * presented at the moment the row it names would have expired anyway, and
     * a handle spent by a *successful* verify is cleared by `settle` on that
     * same response.
     */
    const subjectOf = Effect.fnUntraced(function* (request: HttpServerRequest.HttpServerRequest) {
      const pending = pendingCredential(config, request)
      if (Option.isSome(pending)) {
        return { _tag: "PendingAuth", token: pending.value } satisfies ChallengeSubject
      }
      const credential = sessionCredential(config, request)
      if (Option.isNone(credential)) return yield* Unauthorized.make()
      const verified = yield* sessions.verify(credential.value).pipe(
        AuthHandlers.serverFault,
        // A session that has expired and one that never existed are one answer
        // here, exactly as they are to the middleware's bearer transport.
        Effect.catchTag("SessionExpired", () => Unauthorized.make())
      )
      return {
        _tag: "Session",
        session: verified.session,
        user: verified.user
      } satisfies ChallengeSubject
    })

    /**
     * What both verify endpoints do once the factor has been checked: write
     * the session the caller now holds, forget the pending authentication, and
     * remember the browser if it asked to be.
     */
    const settle = Effect.fnUntraced(function* (options: {
      readonly subject: ChallengeSubject
      readonly result: {
        readonly session: Session
        readonly user: User
        readonly token: Redacted.Redacted
        readonly rememberMe: boolean
      }
      readonly request: HttpServerRequest.HttpServerRequest
      readonly trustDevice: boolean
      readonly label: string | undefined
    }) {
      const { request, result, subject } = options
      if (subject._tag === "PendingAuth") {
        // Spent, whichever way this went: a single-use value never rides a
        // second request.
        yield* AuthHandlers.clearPendingCookie(config)
      }
      yield* setSessionCookie(config, result.session, result.token, { persistent: result.rememberMe })
      if (subject._tag === "Session") {
        // The snapshot beside the cookie names the old token and the old
        // level; rewriting it is what keeps the very next request a hit.
        // `write` is a no-op unless this request presented the cache cookie.
        yield* cache.write(result.session, result.user)
      }
      if (options.trustDevice) {
        const issued = yield* twoFactor
          .trustDevice({
            userId: result.user.id,
            ...AuthHandlers.clientMeta(config, request),
            label: options.label
          })
          .pipe(AuthHandlers.serverFault)
        yield* setTrustedDeviceCookie(config, issued.value, issued.maxAge)
      }
      return { user: baseUserModel.toPublic(result.user), session: result.session }
    })

    return handlers
      .handle("totpEnroll", () =>
        Effect.gen(function* () {
          const user = yield* CurrentUser
          return yield* twoFactor.startEnrolment(user).pipe(AuthHandlers.serverFault)
        })
      )
      .handle("totpConfirm", ({ payload, request }) =>
        Effect.gen(function* () {
          yield* rateLimit(credentials, request)
          const user = yield* CurrentUser
          const codes = yield* twoFactor.confirmEnrolment(user, payload.code).pipe(AuthHandlers.serverFault)
          return { codes }
        })
      )
      .handle("totpVerify", ({ payload, request }) =>
        Effect.gen(function* () {
          // An unauthenticated POST that spends a credential and creates a
          // session: a cross-origin form must not reach it, and a caller with
          // no `Origin` at all (server to server) still may.
          yield* requireTrustedOrigin
          yield* rateLimit(credentials, request)
          const subject = yield* subjectOf(request)
          const result = yield* twoFactor
            .verify({
              factor: { _tag: "Totp", code: payload.code },
              subject,
              ...AuthHandlers.clientMeta(config, request)
            })
            // A refusal leaves the pending cookie exactly where it is — see
            // the note on `subjectOf`.
            .pipe(AuthHandlers.serverFault)
          return yield* settle({
            subject,
            result,
            request,
            trustDevice: payload.trustDevice === true,
            label: payload.label
          })
        })
      )
      .handle("totpDisable", () =>
        Effect.gen(function* () {
          const user = yield* CurrentUser
          yield* twoFactor.disable(user).pipe(AuthHandlers.serverFault)
          return AuthHandlers.acknowledged
        })
      )
      .handle("recoveryVerify", ({ payload, request }) =>
        Effect.gen(function* () {
          yield* requireTrustedOrigin
          yield* rateLimit(credentials, request)
          const subject = yield* subjectOf(request)
          const result = yield* twoFactor
            .verify({
              factor: { _tag: "RecoveryCode", code: payload.code },
              subject,
              ...AuthHandlers.clientMeta(config, request)
            })
            .pipe(AuthHandlers.serverFault)
          // Spending a recovery code forgets every remembered browser, so the
          // cookie this one may be holding is expired on the way out too.
          yield* clearTrustedDeviceCookie(config)
          return yield* settle({ subject, result, request, trustDevice: false, label: undefined })
        })
      )
      .handle("recoveryRegenerate", () =>
        Effect.gen(function* () {
          const user = yield* CurrentUser
          const codes = yield* twoFactor.regenerateRecoveryCodes(user).pipe(AuthHandlers.serverFault)
          yield* clearTrustedDeviceCookie(config)
          return { codes }
        })
      )
      .handle("devices", ({ request }) =>
        Effect.gen(function* () {
          const user = yield* CurrentUser
          const devices = yield* twoFactor
            .listDevices(user.id, readTrustedDeviceCookie(config, request))
            .pipe(AuthHandlers.serverFault)
          return devices
        })
      )
      .handle("devicesRevoke", ({ payload }) =>
        Effect.gen(function* () {
          const user = yield* CurrentUser
          const removed = yield* twoFactor.revokeDevice(payload.deviceId, user.id).pipe(AuthHandlers.serverFault)
          if (!removed) return yield* NotFound.make()
          return AuthHandlers.acknowledged
        })
      )
      .handle("devicesRevokeAll", () =>
        Effect.gen(function* () {
          const user = yield* CurrentUser
          yield* twoFactor.revokeDevices(user.id).pipe(AuthHandlers.serverFault)
          yield* clearTrustedDeviceCookie(config)
          return AuthHandlers.acknowledged
        })
      )
  })
)
