/**
 * The server implementation of {@link UsernameApiGroup}.
 *
 * **Details**
 *
 * Built out of the same pieces this library's own handlers are:
 * `AuthHandlers.forGroup` is the boundary that lets a group be implemented
 * inside whatever `HttpApi` a consumer composed it into, and `clientMeta`,
 * `setSessionCookie`, `setPendingCookie` and `serverFault` are reused rather
 * than reimplemented. No policy lives here: each handler reads the decoded
 * request, calls one method of {@link Username}, and turns the result into the
 * endpoint's declared response.
 *
 * **Gotchas**
 *
 * `signIn` and `available` are unauthenticated `POST`s — one mints a session
 * row, the other drives an oracle — so both call
 * `OriginCheck.requireTrustedIfPresent`. The `Authenticated` middleware applies
 * the cookie-transport origin check for `set`, and a cross-origin form post
 * reaches an endpoint with no cookie at all, which is exactly what that
 * middleware cannot see.
 *
 * @since 0.2.0
 */
import { DateTime, Duration, Effect } from "effect"
import type { HttpServerRequest } from "effect/unstable/http"
import { RateLimiter } from "effect/unstable/persistence"
import { AuthConfig } from "../config/AuthConfig.js"
import * as AuthHandlers from "../http/Handlers.js"
import { CurrentUser } from "../http/Middleware.js"
import { setSessionCookie } from "../http/MiddlewareLive.js"
import { requireTrustedIfPresent } from "../http/OriginCheck.js"
import type { Bucket } from "../http/RateLimits.js"
import { consumeWith, credentials } from "../http/RateLimits.js"
import { UsernameApiGroup } from "./Api.js"
import { Username } from "./Username.js"

/**
 * The limit on the availability oracle: ten a minute per client.
 *
 * **Details**
 *
 * Its own bucket, not `credentials`: the two answer different questions and a
 * shared counter would let somebody enumerate names until sign-in stopped
 * working — better-auth's one-knob mistake, applied to send and verify.
 * Deliberately looser than `credentials`, because a person choosing a name
 * really does try several.
 *
 * @category constructors
 * @since 0.2.0
 */
export const availability: Bucket = {
  name: "username-availability",
  limit: 10,
  window: Duration.seconds(60)
}

/**
 * The services the username handlers need.
 *
 * @category models
 * @since 0.2.0
 */
export type HandlerServices = AuthConfig | Username | RateLimiter.RateLimiter

/**
 * Implements the `username` group of an `HttpApi` that contains it.
 *
 * **Example**
 *
 * ```ts skip-type-checking
 * import { HttpApi } from "effect/unstable/httpapi"
 * import { AuthApi, UsernameApi } from "effect-auth"
 *
 * const AppApi = HttpApi.make("app").addHttpApi(AuthApi).add(UsernameApi.UsernameApiGroup)
 * const HandlersLive = UsernameApi.handlers(AppApi)
 * ```
 *
 * @category layers
 * @since 0.2.0
 */
export const handlers = AuthHandlers.forGroup(UsernameApiGroup, (handlers) =>
  Effect.gen(function* () {
    const config = yield* AuthConfig
    const username = yield* Username
    const limiter = yield* RateLimiter.RateLimiter

    // Resolved here, when the layer is built, so that no handler carries a
    // request-time requirement.
    const rateLimit = (bucket: Bucket, request: HttpServerRequest.HttpServerRequest) =>
      consumeWith({ config, limiter, bucket, request })

    // The same discipline, and the reason it is not simply `yield*
    // requireTrustedIfPresent`: that effect reads `AuthConfig` from the context
    // when it runs, which would make every handler using it carry a
    // request-time requirement the router has no reason to satisfy. The
    // configuration is already in hand, so it is handed over once. The rule
    // itself is not restated — `OriginCheck` owns it.
    const requireTrustedOrigin = Effect.provideService(requireTrustedIfPresent, AuthConfig, config)

    return handlers
      .handle("signIn", ({ payload, request }) =>
        Effect.gen(function* () {
          yield* rateLimit(credentials, request)
          yield* requireTrustedOrigin
          const result = yield* username
            .signIn({
              username: payload.username,
              password: payload.password,
              rememberMe: payload.rememberMe,
              ...AuthHandlers.clientMeta(config, request)
            })
            .pipe(AuthHandlers.serverFault)

          if (result._tag === "Challenge") {
            // The pending token, and only the pending token: no session was
            // minted, so no session cookie may be written here. A response
            // carrying both would be a half-authenticated credential the second
            // factor no longer gates.
            const now = yield* DateTime.now
            yield* AuthHandlers.setPendingCookie(config, result.token, {
              maxAge: Duration.max(Duration.zero, DateTime.distance(now, result.expiresAt))
            })
            return { _tag: "MfaRequired" as const, available: result.available, expiresAt: result.expiresAt }
          }

          yield* setSessionCookie(config, result.session, result.token, {
            persistent: payload.rememberMe !== false
          })
          return { user: result.user, session: result.session }
        })
      )
      .handle("set", ({ payload }) =>
        Effect.gen(function* () {
          // Ownership is the service's: it writes for the caller's own id and
          // has no parameter that could name somebody else's.
          const user = yield* CurrentUser
          const record = yield* username
            .set({ userId: user.id, username: payload.username })
            .pipe(AuthHandlers.serverFault)
          return { username: record.username, usernameKey: record.usernameKey }
        })
      )
      .handle("available", ({ payload, request }) =>
        Effect.gen(function* () {
          // The switch first: a deployment that did not opt in serves nothing
          // here, and spends no rate-limit budget deciding so.
          if (!username.config.availability) return AuthHandlers.notServed
          yield* rateLimit(availability, request)
          yield* requireTrustedOrigin
          const free = yield* username.available(payload.username).pipe(AuthHandlers.serverFault)
          return { available: free }
        })
      )
  })
)
