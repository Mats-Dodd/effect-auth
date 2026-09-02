/**
 * The server implementation of {@link PhoneApiGroup}.
 *
 * **Details**
 *
 * Built exactly as this library's own handlers are, out of the same pieces:
 * `AuthHandlers.forGroup` is the boundary that lets the group be implemented
 * inside whatever `HttpApi` a consumer composed it into, and `clientMeta`,
 * `serverFault`, `setSessionCookie` and `setPendingCookie` are reused rather
 * than reimplemented. No handler holds policy: each reads the decoded request,
 * spends the one rate limit that is about the *caller* rather than the
 * destination, calls one method of {@link Phone}, and turns the result into the
 * endpoint's declared response.
 *
 * **Gotchas**
 *
 * A capability that is switched off answers `404` rather than disappearing from
 * the document — the same shape `signInEmail` has under `emailPassword.enabled:
 * false`. The endpoints are declared unconditionally so that a generated client
 * is the same client whoever serves it.
 *
 * The handle cookie is written on the way out of every `send` and expired on the
 * way out of a `verify` that **succeeded**, so a single-use value never rides a
 * second request. A refusal deliberately leaves it: a wrong guess puts the row
 * back under the same handle with one attempt fewer, and expiring the cookie
 * there would spend the rest of somebody's budget for them. Its `Max-Age` is
 * the challenge's own lifetime, so a dead handle stops being presented anyway.
 * The three cookies have three names, so two flows in two tabs do not eat each
 * other's handle.
 *
 * @since 0.2.0
 */
import { DateTime, Duration, Effect, Option, Redacted } from "effect"
import type { HttpServerRequest } from "effect/unstable/http"
import { HttpApiBuilder } from "effect/unstable/httpapi"
import { RateLimiter } from "effect/unstable/persistence"
import type { AuthConfigService } from "../config/AuthConfig.js"
import { AuthConfig } from "../config/AuthConfig.js"
import { InvalidCode } from "../domain/Errors.js"
import { SignInResult } from "../domain/SignIn.js"
import { SessionCache } from "../http/SessionCache.js"
import type { PluginCookie } from "../http/Cookies.js"
import { pluginCookieFor } from "../http/Cookies.js"
import * as AuthHandlers from "../http/Handlers.js"
import { CurrentSession, CurrentUser } from "../http/Middleware.js"
import { setSessionCookie } from "../http/MiddlewareLive.js"
import { requireTrustedIfPresent } from "../http/OriginCheck.js"
import type { Bucket } from "../http/RateLimits.js"
import { consumeWith } from "../http/RateLimits.js"
import { PhoneApiGroup } from "./Api.js"
import type { IssuedChallenge } from "./Phone.js"
import { Phone, signInCookieBaseName, stepUpCookieBaseName, verifyCookieBaseName } from "./Phone.js"

/**
 * The services the phone handlers need.
 *
 * **Gotchas**
 *
 * Four, and none of them a store: everything the flows touch is behind
 * {@link Phone}, which is what makes this layer composable over a deployment the
 * plugin knows nothing else about. `SessionCache` is here for one line — the
 * step-up path rewrites the snapshot beside the rotated cookie, exactly as
 * `/auth/reauthenticate` does.
 *
 * @category models
 * @since 0.2.0
 */
export type HandlerServices = AuthConfig | Phone | SessionCache | RateLimiter.RateLimiter

/**
 * The cookie a handle of each purpose rides in.
 *
 * **Details**
 *
 * `hostOnly`, so `__Host-` on a TLS deployment: a sibling subdomain can set a
 * `Domain`-scoped cookie of any name onto the host that reads it, and this one
 * is what binds an attempt budget to a browser. The lifetime is the challenge's
 * own, so the cookie and the row expire together.
 *
 * @category combinators
 * @since 0.2.0
 */
export const handleCookie = (config: AuthConfigService, baseName: string, maxAge: Duration.Duration): PluginCookie =>
  pluginCookieFor(config, { baseName, hostOnly: true, maxAge })

/** The remaining lifetime of a challenge, never negative. */
const remaining = (expiresAt: DateTime.Utc): Effect.Effect<Duration.Duration> =>
  Effect.map(DateTime.now, (now) => Duration.max(Duration.zero, DateTime.distance(now, expiresAt)))

/**
 * Implements the `phone` group of an `HttpApi` that contains it.
 *
 * **Example**
 *
 * ```ts skip-type-checking
 * import { HttpApi } from "effect/unstable/httpapi"
 * import { AuthApi, Phone } from "effect-auth"
 *
 * const AppApi = HttpApi.make("app").addHttpApi(AuthApi).add(Phone.PhoneApiGroup)
 * const HandlersLive = Phone.handlers(AppApi)
 * ```
 *
 * @category layers
 * @since 0.2.0
 */
export const handlers = AuthHandlers.forGroup(PhoneApiGroup, (handlers) =>
  Effect.gen(function* () {
    const config = yield* AuthConfig
    const phone = yield* Phone
    const cache = yield* SessionCache
    const limiter = yield* RateLimiter.RateLimiter

    // Resolved here, when the layer is built, so that no handler carries a
    // request-time requirement.
    /**
     * `OriginCheck.requireTrustedIfPresent` with the configuration it reads
     * resolved here, when the layer is built.
     *
     * The rule itself is not restated — a second copy of "which origins are
     * trusted" is the bug that module exists to prevent. What is bound here is
     * only *where the configuration comes from*, so that no handler carries an
     * `AuthConfig` requirement into request time.
     */
    const trustedOrigin = Effect.provideService(requireTrustedIfPresent, AuthConfig, config)

    const rateLimit = (bucket: Bucket, request: HttpServerRequest.HttpServerRequest) =>
      consumeWith({ config, limiter, bucket, request })

    /** The per-client half of the toll-fraud limits; the other three are keyed on the destination and live in the service. */
    const limitSends = (request: HttpServerRequest.HttpServerRequest) => rateLimit(phone.config.limits.client, request)

    /** Writes a handle into its cookie for exactly as long as the challenge lives. */
    const setHandle = (
      baseName: string,
      issued: IssuedChallenge
    ): Effect.Effect<void, never, HttpServerRequest.HttpServerRequest> =>
      Effect.flatMap(remaining(issued.expiresAt), (maxAge) => {
        const cookie = handleCookie(config, baseName, maxAge)
        return HttpApiBuilder.securitySetCookie(cookie.security, issued.handle, cookie.options)
      })

    /** Expires a handle cookie, whichever way the answer went. */
    const clearHandle = (baseName: string): Effect.Effect<void, never, HttpServerRequest.HttpServerRequest> => {
      const cookie = handleCookie(config, baseName, Duration.zero)
      return HttpApiBuilder.securitySetCookie(cookie.security, Redacted.make(""), cookie.expiredOptions)
    }

    /** The handle this request presented, or nothing. */
    const readHandle = (
      baseName: string,
      request: HttpServerRequest.HttpServerRequest
    ): Option.Option<Redacted.Redacted> => {
      const name = handleCookie(config, baseName, Duration.zero).name
      const value = request.cookies[name]
      return value === undefined || value.length === 0 ? Option.none() : Option.some(Redacted.make(value))
    }

    return handlers
      .handle("sendVerification", ({ payload, request }) =>
        Effect.gen(function* () {
          if (!phone.config.contact) return AuthHandlers.notServed
          yield* limitSends(request)
          const user = yield* CurrentUser
          const issued = yield* phone
            .sendVerification({ user, phoneNumber: payload.phoneNumber })
            .pipe(AuthHandlers.serverFault)
          yield* setHandle(verifyCookieBaseName, issued)
          return AuthHandlers.acknowledged
        })
      )
      .handle("verify", ({ payload, request }) =>
        Effect.gen(function* () {
          if (!phone.config.contact) return AuthHandlers.notServed
          yield* rateLimit(phone.config.limits.client, request)
          const user = yield* CurrentUser
          // The handle rides in the cookie and nowhere else, so a body that
          // carries only a code is the whole of the request. No cookie is the
          // same answer as a wrong code.
          const handle = yield* Effect.fromOption(readHandle(verifyCookieBaseName, request), () => InvalidCode.make())
          const attached = yield* phone
            .verify({ user, handle, code: Redacted.make(payload.code) })
            .pipe(AuthHandlers.serverFault)
          // Cleared on success only. A wrong guess leaves the row in place under
          // the *same* handle with one attempt fewer, so a cookie expired here
          // would spend somebody's remaining attempts for them.
          yield* clearHandle(verifyCookieBaseName)
          return { phoneNumber: attached.phoneE164, verifiedAt: attached.verifiedAt }
        })
      )
      .handle("remove", () =>
        Effect.gen(function* () {
          if (!phone.config.contact) return AuthHandlers.notServed
          const user = yield* CurrentUser
          yield* phone.remove({ user }).pipe(AuthHandlers.serverFault)
          return AuthHandlers.acknowledged
        })
      )
      .handle("signInSend", ({ payload, request }) =>
        Effect.gen(function* () {
          if (!phone.config.signIn) return AuthHandlers.notServed
          // Unauthenticated, and it sends a message: a cross-origin form post
          // reaches it carrying no cookie at all, so the cookie-shaped defence
          // in `Authenticated` never sees it.
          yield* trustedOrigin
          yield* limitSends(request)
          const issued = yield* phone.sendSignIn({ phoneNumber: payload.phoneNumber }).pipe(AuthHandlers.serverFault)
          yield* setHandle(signInCookieBaseName, issued)
          return AuthHandlers.acknowledged
        })
      )
      .handle("signInVerify", ({ payload, request }) =>
        Effect.gen(function* () {
          if (!phone.config.signIn) return AuthHandlers.notServed
          // Unauthenticated and it mints a session. Without this, a site that
          // already held a code — its own handset's — could post it from a
          // visitor's browser and sign that browser into the attacker's
          // account. The handle cookie is `SameSite` capped rather than
          // `Strict`, so it is not the thing that stops that.
          yield* trustedOrigin
          yield* rateLimit(phone.config.limits.client, request)
          const handle = yield* Effect.fromOption(readHandle(signInCookieBaseName, request), () => InvalidCode.make())
          const result = yield* phone
            .completeSignIn({
              handle,
              code: Redacted.make(payload.code),
              rememberMe: payload.rememberMe,
              ...AuthHandlers.clientMeta(config, request)
            })
            .pipe(AuthHandlers.serverFault)
          yield* clearHandle(signInCookieBaseName)

          // The pending token, and only the pending token: no session was
          // minted, so no session cookie may be written here. The shared helper
          // is the whole branch, cookie and `202` together.
          if (SignInResult.$is("Challenge")(result)) return yield* AuthHandlers.mfaRequired(config, result)

          yield* setSessionCookie(config, result.session, result.token, {
            persistent: result.session.rememberMe
          })
          return { user: result.user, session: result.session }
        })
      )
      .handle("stepUpSend", ({ request }) =>
        Effect.gen(function* () {
          if (!phone.config.stepUp) return AuthHandlers.notServed
          yield* limitSends(request)
          const user = yield* CurrentUser
          const issued = yield* phone.sendStepUp({ user }).pipe(AuthHandlers.serverFault)
          yield* setHandle(stepUpCookieBaseName, issued)
          return AuthHandlers.acknowledged
        })
      )
      .handle("stepUpVerify", ({ payload, request }) =>
        Effect.gen(function* () {
          if (!phone.config.stepUp) return AuthHandlers.notServed
          yield* rateLimit(phone.config.limits.client, request)
          const user = yield* CurrentUser
          const session = yield* CurrentSession
          const handle = yield* Effect.fromOption(readHandle(stepUpCookieBaseName, request), () => InvalidCode.make())
          const elevated = yield* phone
            .completeStepUp({ user, session, handle, code: Redacted.make(payload.code) })
            .pipe(AuthHandlers.serverFault)
          yield* clearHandle(stepUpCookieBaseName)
          // `elevate` rotates the token, so the cookie has to carry the new one
          // — the old one stops resolving the instant this returns — and the
          // snapshot beside it names the old token and the old level.
          yield* setSessionCookie(config, elevated.session, elevated.token, {
            persistent: elevated.session.rememberMe
          })
          yield* cache.write(elevated.session, user)
          return { user, session: elevated.session }
        })
      )
  })
)
