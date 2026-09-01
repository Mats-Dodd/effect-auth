/**
 * The server implementation of {@link EmailOtpApiGroup}.
 *
 * **Details**
 *
 * A plugin's handlers are built exactly as this library's own are, and out of
 * the same pieces: `AuthHandlers.forGroup` is the boundary that lets a group be
 * implemented inside whatever `HttpApi` a consumer composed it into, and
 * `clientMeta`, `redirectTo`, `setSessionCookie`, `setPendingCookie` and
 * `serverFault` are reused rather than reimplemented. The seven handlers below
 * hold no policy: each reads the decoded request, calls one method of
 * {@link EmailOtp}, and turns the result into the endpoint's declared response.
 *
 * **Gotchas**
 *
 * Two limits guard every send, and they count different things. The library's
 * own `email` bucket is per caller and per path — three a minute from one
 * network address. The plugin's {@link resendBucket} is counted against the
 * *subject*, so one address (or one account) gets one code a minute however
 * many addresses the caller sends from. The second is the one that matters:
 * without it, a caller with a thousand proxies is a mail cannon aimed at one
 * mailbox.
 *
 * A response never carries a session cookie beside a challenge. The three
 * responses that can carry a pending-authentication cookie — the 202 from
 * `verify`, the `?mfa=required` redirect from `link` — set that one and no
 * other.
 *
 * @since 0.2.0
 */
import { DateTime, Duration, Effect, Option, Redacted } from "effect"
import { HttpApiBuilder } from "effect/unstable/httpapi"
import type { HttpServerRequest } from "effect/unstable/http"
import { RateLimiter } from "effect/unstable/persistence"
import type { AuthConfigService } from "../config/AuthConfig.js"
import { AuthConfig } from "../config/AuthConfig.js"
import { InvalidCode } from "../domain/Errors.js"
import { normalizeEmail } from "../domain/Schema.js"
import { SessionCache } from "../http/SessionCache.js"
import { type PluginCookie, pluginCookieFor } from "../http/Cookies.js"
import * as AuthHandlers from "../http/Handlers.js"
import { CurrentSession, CurrentUser } from "../http/Middleware.js"
import { optionalSession, setSessionCookie } from "../http/MiddlewareLive.js"
import { Sessions } from "../domain/Sessions.js"
import { requireTrustedIfPresent } from "../http/OriginCheck.js"
import type { Bucket } from "../http/RateLimits.js"
import { consumeKeyed, consumeWith, credentials, email as emailBucket } from "../http/RateLimits.js"
import { EmailOtpApiGroup } from "./Api.js"
import { EmailOtp, handleCookieBaseName, type Issued } from "./EmailOtp.js"

/**
 * The bucket a resend cooldown is counted in: one code per window, per subject.
 *
 * **Gotchas**
 *
 * A function of the configured cooldown rather than a constant, because the
 * window is the deployment's to choose. The *name* is fixed, so two windows
 * never share a counter with anything else.
 *
 * @category constructors
 * @since 0.2.0
 */
export const resendBucket = (window: Duration.Duration): Bucket => ({
  name: "email-otp-resend",
  limit: 1,
  window
})

/**
 * The services the e-mail one-time-code handlers need.
 *
 * @category models
 * @since 0.2.0
 */
export type HandlerServices = AuthConfig | EmailOtp | Sessions | SessionCache | RateLimiter.RateLimiter

/**
 * The handle cookie for this deployment.
 *
 * **When to use**
 *
 * From a test, or from an application serving the plugin's endpoints itself.
 * The name is what a browser sends the handle back under.
 *
 * @category combinators
 * @since 0.2.0
 */
export const handleCookie = (config: AuthConfigService, maxAge: Duration.Duration): PluginCookie =>
  pluginCookieFor(config, { baseName: handleCookieBaseName, hostOnly: true, maxAge })

/**
 * How long a challenge has left to live at the moment this is evaluated,
 * floored at zero — the `Max-Age` of the cookie that names it, so the browser
 * forgets the handle when the row expires.
 *
 * @category combinators
 * @since 0.2.0
 */
export const remainingLifetime = (expiresAt: DateTime.Utc): Effect.Effect<Duration.Duration> =>
  Effect.map(DateTime.now, (now) => Duration.max(Duration.zero, DateTime.distance(now, expiresAt)))

/**
 * Implements the `emailOtp` group of an `HttpApi` that contains it.
 *
 * **Example**
 *
 * ```ts skip-type-checking
 * import { HttpApi } from "effect/unstable/httpapi"
 * import { AuthApi, EmailOtp } from "effect-auth"
 *
 * const AppApi = HttpApi.make("app").addHttpApi(AuthApi).add(EmailOtp.EmailOtpApiGroup)
 * const HandlersLive = EmailOtp.handlers(AppApi)
 * ```
 *
 * **Gotchas**
 *
 * The API passed here must be the one passed to `HttpApiBuilder.layer`: the
 * routes are read off the group *it* carries. A group merely *named* `emailOtp`,
 * or this one re-prefixed with `HttpApi.prefix`, is rejected here rather than
 * mis-served — see `AuthHandlers.forGroup`.
 *
 * @category layers
 * @since 0.2.0
 */
export const handlers = AuthHandlers.forGroup(EmailOtpApiGroup, (handlers) =>
  Effect.gen(function* () {
    const config = yield* AuthConfig
    // Resolved when the layer is built, so no handler carries a request-time
    // requirement — the same discipline every other resolution here follows.
    const sessions = yield* Sessions
    const emailOtp = yield* EmailOtp
    const cache = yield* SessionCache
    const limiter = yield* RateLimiter.RateLimiter

    const cooldown = resendBucket(emailOtp.config.resendCooldown)

    // Resolved here, when the layer is built, so that no handler carries a
    // request-time requirement.
    const rateLimit = (bucket: Bucket, request: HttpServerRequest.HttpServerRequest) =>
      consumeWith({ config, limiter, bucket, request })

    /**
     * `OriginCheck.requireTrustedIfPresent`, with the configuration this layer
     * already holds provided into it.
     *
     * The exported guard reads `AuthConfig` from the context, which would make
     * it a *request-time* requirement of this handler layer and put `AuthConfig`
     * in the layer's `RIn` where a plugin harness cannot discharge it.
     * Providing it here at layer-build time keeps one copy of the rule.
     */
    const trustedOrigin = Effect.provideService(requireTrustedIfPresent, AuthConfig, config)

    /** One code per window per subject, whatever address asks for it. */
    const resendLimit = (key: string) => consumeKeyed({ config, limiter, bucket: cooldown, key })

    /** The cookie the handle rides in, sized to the challenge it names. */
    const cookieFor = (issued: Issued): Effect.Effect<PluginCookie> =>
      Effect.map(remainingLifetime(issued.expiresAt), (maxAge) => handleCookie(config, maxAge))

    const setHandleCookie = (issued: Issued) =>
      Effect.flatMap(cookieFor(issued), (cookie) =>
        HttpApiBuilder.securitySetCookie(cookie.security, issued.handle, cookie.options)
      )

    /** Expires the handle the moment it is spent or refused — success or failure. */
    const clearHandleCookie = Effect.suspend(() => {
      const cookie = handleCookie(config, Duration.zero)
      return HttpApiBuilder.securitySetCookie(cookie.security, Redacted.make(""), cookie.expiredOptions)
    })

    /** The handle the browser sent back, or `InvalidCode` when it sent none. */
    const presentedHandle = (
      request: HttpServerRequest.HttpServerRequest
    ): Effect.Effect<Redacted.Redacted, InvalidCode, HttpServerRequest.HttpServerRequest> => {
      const name = handleCookie(config, Duration.zero).name
      const value = request.cookies[name]
      return value === undefined || value.length === 0
        ? Effect.flatMap(clearHandleCookie, () => InvalidCode.make())
        : Effect.succeed(Redacted.make(value))
    }

    return handlers
      .handle("send", ({ payload, request }) =>
        Effect.gen(function* () {
          // An unauthenticated POST that sends mail and writes rows: a
          // cross-origin form post reaches it with no cookie at all, so an
          // Origin or Referer that is present has to be trusted. A request
          // carrying neither — a server, a script — passes.
          yield* trustedOrigin
          // The caller's own bucket, and then the address's.
          yield* rateLimit(emailBucket, request)
          yield* resendLimit(normalizeEmail(payload.email))
          const issued = yield* emailOtp.send(payload).pipe(AuthHandlers.serverFault)
          yield* setHandleCookie(issued)
          // The same answer for a known address, an unknown one, a deployment
          // that would refuse to create the account, and a message that could
          // not be delivered.
          return AuthHandlers.acknowledged
        })
      )
      .handle("verify", ({ payload, request }) =>
        Effect.gen(function* () {
          // An unauthenticated POST that mints a session. The handle cookie is
          // `SameSite` capped away from `Strict`, so it is not what stops a
          // cross-site form post from signing somebody's browser into an
          // attacker's account — this is. Same rule as `send` beside it, and
          // as every other sign-in door in this library.
          yield* trustedOrigin
          yield* rateLimit(credentials, request)
          const handle = yield* presentedHandle(request)
          const result = yield* emailOtp
            .verify({
              handle,
              code: payload.code,
              // Who the browser already was. A visitor with a basket answering
              // a code for the account they had all along is an upgrade, and
              // `beforeSessionMint` is where a deployment merges the two.
              current: Option.getOrUndefined(yield* optionalSession({ config, sessions, request })),
              ...AuthHandlers.clientMeta(config, request)
            })
            .pipe(AuthHandlers.serverFault)
          // Spent or refused, the handle does not ride a second request.
          yield* clearHandleCookie

          switch (result._tag) {
            case "SignedIn": {
              yield* setSessionCookie(config, result.session, result.token, { persistent: result.rememberMe })
              return { _tag: "SignedIn" as const, user: result.user, session: result.session }
            }
            case "Challenge": {
              // No session cookie on this branch, by construction: there is no
              // session. The pending-authentication token is the only thing set.
              yield* AuthHandlers.setPendingCookie(config, result.challenge.token, {
                maxAge: yield* remainingLifetime(result.challenge.expiresAt)
              })
              return {
                _tag: "MfaRequired" as const,
                available: result.challenge.available,
                expiresAt: result.challenge.expiresAt
              }
            }
            case "Verified":
              return { _tag: "Verified" as const }
            case "PasswordReset":
              return { _tag: "PasswordReset" as const, token: result.token, expiresAt: result.expiresAt }
          }
        })
      )
      .handle("link", ({ query, request }) =>
        Effect.gen(function* () {
          yield* rateLimit(credentials, request)
          // A query parameter is decoded as a plain string — query strings do
          // not go through the JSON codec — so it is redacted here, before
          // anything can log it.
          const outcome = yield* emailOtp
            .follow({
              token: Redacted.make(query.token),
              current: Option.getOrUndefined(yield* optionalSession({ config, sessions, request })),
              ...AuthHandlers.clientMeta(config, request)
            })
            .pipe(AuthHandlers.serverFault)
          // A link spends the same row a code does, so the handle the browser
          // may still be holding names nothing.
          yield* clearHandleCookie

          if (outcome._tag === "SignedIn") {
            yield* setSessionCookie(config, outcome.session, outcome.token, { persistent: outcome.rememberMe })
            return AuthHandlers.redirectTo(outcome.redirectTo)
          }
          if (outcome._tag === "Challenge") {
            // A browser that arrived by a top-level navigation cannot be
            // answered with a 202, so the pending token goes in its cookie and
            // the landing page is told by `?mfa=required`. No session cookie.
            yield* AuthHandlers.setPendingCookie(config, outcome.challenge.token, {
              maxAge: yield* remainingLifetime(outcome.challenge.expiresAt)
            })
            return AuthHandlers.redirectTo(AuthHandlers.withMfaRequired(outcome.redirectTo))
          }
          // Success or failure, the browser arrived by a top-level navigation
          // and leaves by one, and no cookie is set: no session exists.
          return AuthHandlers.redirectTo(outcome.redirectTo)
        })
      )
      .handle("stepUpSend", ({ request }) =>
        Effect.gen(function* () {
          yield* rateLimit(emailBucket, request)
          const user = yield* CurrentUser
          // Keyed on the account, not the address it happens to carry.
          yield* resendLimit(user.id)
          const issued = yield* emailOtp.requestStepUp(user).pipe(AuthHandlers.serverFault)
          yield* setHandleCookie(issued)
          return AuthHandlers.acknowledged
        })
      )
      .handle("stepUpVerify", ({ payload, request }) =>
        Effect.gen(function* () {
          yield* rateLimit(credentials, request)
          const user = yield* CurrentUser
          const session = yield* CurrentSession
          const handle = yield* presentedHandle(request)
          const elevated = yield* emailOtp
            .verifyStepUp({ session, handle, code: payload.code })
            .pipe(AuthHandlers.serverFault)
          yield* clearHandleCookie
          // `elevate` rotates the token, so the cookie has to carry the new one
          // — the old one stops resolving the instant this returns.
          yield* setSessionCookie(config, elevated.session, elevated.token, {
            persistent: elevated.session.rememberMe
          })
          // And the snapshot beside it names the old token and the old level.
          // Rewriting it is what keeps the very next request a hit; `write` is
          // a no-op unless this request presented the cookie.
          yield* cache.write(elevated.session, user)
          return { user, session: elevated.session }
        })
      )
      .handle("changeEmailSend", ({ payload, request }) =>
        Effect.gen(function* () {
          yield* rateLimit(emailBucket, request)
          const user = yield* CurrentUser
          yield* resendLimit(user.id)
          const issued = yield* emailOtp
            .requestEmailChange({ user, newEmail: payload.newEmail })
            .pipe(AuthHandlers.serverFault)
          yield* setHandleCookie(issued)
          return AuthHandlers.acknowledged
        })
      )
      .handle("changeEmailVerify", ({ payload, request }) =>
        Effect.gen(function* () {
          yield* rateLimit(credentials, request)
          const user = yield* CurrentUser
          const handle = yield* presentedHandle(request)
          yield* emailOtp.verifyEmailChange({ user, handle, code: payload.code }).pipe(AuthHandlers.serverFault)
          yield* clearHandleCookie
          return AuthHandlers.acknowledged
        })
      )
  })
)
