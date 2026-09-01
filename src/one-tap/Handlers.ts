/**
 * The server implementation of {@link OneTapApiGroup}.
 *
 * **Details**
 *
 * Two handlers, and between them one job: move the nonce into and out of a
 * `__Host-` cookie, and turn `SignIn`'s two outcomes into the endpoint's
 * two statuses. Everything else is {@link OneTap}, which is itself mostly the
 * OAuth module.
 *
 * **Gotchas**
 *
 * The nonce cookie is expired on the way out of the callback whichever way it
 * went. A nonce is single-use by construction — the credential it was signed
 * into is — so leaving it set would mean a page that failed once retried with a
 * binding the server no longer considers fresh.
 *
 * @since 0.2.0
 */
import { DateTime, Duration, Effect, Redacted } from "effect"
import type { HttpServerRequest } from "effect/unstable/http"
import { HttpApiBuilder } from "effect/unstable/httpapi"
import { RateLimiter } from "effect/unstable/persistence"
import type { AuthConfigService } from "../config/AuthConfig.js"
import { AuthConfig } from "../config/AuthConfig.js"
import type { PluginCookie } from "../http/Cookies.js"
import { pluginCookieFor } from "../http/Cookies.js"
import * as AuthHandlers from "../http/Handlers.js"
import { setSessionCookie } from "../http/MiddlewareLive.js"
import { requireTrustedIfPresent } from "../http/OriginCheck.js"
import { consumeWith, credentials } from "../http/RateLimits.js"
import { OneTapApiGroup } from "./Api.js"
import { csrfCookieName, nonceCookieBaseName, OneTap } from "./OneTap.js"

/**
 * The services the One Tap handlers need.
 *
 * @category models
 * @since 0.2.0
 */
export type HandlerServices = AuthConfig | OneTap | RateLimiter.RateLimiter

/**
 * The cookie the nonce rides in, for this deployment.
 *
 * **When to use**
 *
 * To read the cookie's *name* — a deployment clearing it by hand, a test
 * asserting on it. The handlers write and expire it themselves.
 *
 * @category combinators
 * @since 0.2.0
 */
export const nonceCookie = (config: AuthConfigService, maxAge: Duration.Duration): PluginCookie =>
  pluginCookieFor(config, { baseName: nonceCookieBaseName, hostOnly: true, maxAge })

/**
 * Implements the `oneTap` group of an `HttpApi` that contains it.
 *
 * **Example**
 *
 * ```ts skip-type-checking
 * import { HttpApi } from "effect/unstable/httpapi"
 * import { AuthApi, OneTap } from "effect-auth"
 *
 * const AppApi = HttpApi.make("app").addHttpApi(AuthApi).add(OneTap.OneTapApiGroup)
 * const HandlersLive = OneTap.handlers(AppApi)
 * ```
 *
 * @category layers
 * @since 0.2.0
 */
export const handlers = AuthHandlers.forGroup(OneTapApiGroup, (handlers) =>
  Effect.gen(function* () {
    const config = yield* AuthConfig
    const oneTap = yield* OneTap
    const limiter = yield* RateLimiter.RateLimiter

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

    const rateLimit = (request: HttpServerRequest.HttpServerRequest) =>
      consumeWith({ config, limiter, bucket: credentials, request })

    const readCookie = (request: HttpServerRequest.HttpServerRequest, name: string): string | undefined => {
      const value = request.cookies[name]
      return value === undefined || value.length === 0 ? undefined : value
    }

    return handlers
      .handle("nonce", ({ request }) =>
        Effect.gen(function* () {
          yield* rateLimit(request)
          const issued = yield* oneTap.mintNonce
          const now = yield* DateTime.now
          const cookie = nonceCookie(config, Duration.max(Duration.zero, DateTime.distance(now, issued.expiresAt)))
          yield* HttpApiBuilder.securitySetCookie(cookie.security, Redacted.make(issued.nonce), cookie.options)
          return issued
        })
      )
      .handle("callback", ({ payload, request }) =>
        Effect.gen(function* () {
          // Unauthenticated, and it creates rows: a cross-origin form post
          // reaches it carrying no cookie at all, which is exactly why the
          // cookie-shaped defence inside `Authenticated` never sees it.
          yield* trustedOrigin
          yield* rateLimit(request)
          const expired = nonceCookie(config, Duration.zero)
          const result = yield* oneTap
            .callback({
              credential: payload.credential,
              nonce: payload.nonce,
              expectedNonce: readCookie(request, expired.name),
              csrfToken: payload.csrfToken,
              csrfCookie: readCookie(request, csrfCookieName),
              rememberMe: payload.rememberMe,
              ...AuthHandlers.clientMeta(config, request)
            })
            .pipe(
              AuthHandlers.serverFault,
              // Whichever way it went. The credential the nonce was signed into
              // is spent, so a nonce left behind is one a retry would present
              // against a ceremony that no longer exists.
              Effect.onExit(() =>
                HttpApiBuilder.securitySetCookie(expired.security, Redacted.make(""), expired.expiredOptions)
              )
            )

          if (result._tag === "Challenge") {
            // The pending token, and only the pending token: no session was
            // minted, so no session cookie may be written here.
            const now = yield* DateTime.now
            yield* AuthHandlers.setPendingCookie(config, result.token, {
              maxAge: Duration.max(Duration.zero, DateTime.distance(now, result.expiresAt))
            })
            return { _tag: "MfaRequired" as const, available: result.available, expiresAt: result.expiresAt }
          }

          yield* setSessionCookie(config, result.session, result.token, {
            persistent: result.session.rememberMe
          })
          return { user: result.user, session: result.session }
        })
      )
  })
)
