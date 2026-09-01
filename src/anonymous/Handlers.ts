/**
 * The server implementation of {@link AnonymousApiGroup}.
 *
 * **Gotchas**
 *
 * `signIn` is an unauthenticated `POST` that writes two rows, so it carries
 * both of the defences that shape of endpoint needs: a per-client rate-limit
 * bucket of its own, and `OriginCheck.requireTrustedIfPresent`, because a
 * cross-origin form post reaches it with no cookie at all and the
 * `Authenticated` middleware's origin check therefore never sees it.
 *
 * @since 0.2.0
 */
import { Duration, Effect } from "effect"
import type { HttpServerRequest } from "effect/unstable/http"
import { RateLimiter } from "effect/unstable/persistence"
import { AuthConfig } from "../config/AuthConfig.js"
import * as AuthHandlers from "../http/Handlers.js"
import { SessionCache } from "../http/SessionCache.js"
import { CurrentUser } from "../http/Middleware.js"
import { setSessionCookie } from "../http/MiddlewareLive.js"
import { requireTrustedIfPresent } from "../http/OriginCheck.js"
import type { Bucket } from "../http/RateLimits.js"
import { consumeWith } from "../http/RateLimits.js"
import { AnonymousApiGroup } from "./Api.js"
import { Anonymous } from "./Anonymous.js"

/**
 * The limit on becoming an anonymous visitor: five a minute per client.
 *
 * **Details**
 *
 * Its own bucket, because each call writes a `users` row, a marker row and a
 * `sessions` row for a caller who has proved nothing. better-auth's anonymous
 * plugin has no limit at all here, which makes it a free row-writing endpoint.
 * Loose enough that a person clearing cookies is never inconvenienced.
 *
 * @category constructors
 * @since 0.2.0
 */
export const anonymousSignIn: Bucket = {
  name: "anonymous-sign-in",
  limit: 5,
  window: Duration.seconds(60)
}

/**
 * The services the anonymous handlers need.
 *
 * @category models
 * @since 0.2.0
 */
export type HandlerServices = AuthConfig | Anonymous | SessionCache | RateLimiter.RateLimiter

/**
 * Implements the `anonymous` group of an `HttpApi` that contains it.
 *
 * @category layers
 * @since 0.2.0
 */
export const handlers = AuthHandlers.forGroup(AnonymousApiGroup, (handlers) =>
  Effect.gen(function* () {
    const config = yield* AuthConfig
    const anonymous = yield* Anonymous
    const limiter = yield* RateLimiter.RateLimiter
    const cache = yield* SessionCache

    // Resolved here, when the layer is built, so that no handler carries a
    // request-time requirement — the configuration included, which is why the
    // origin guard is closed over rather than yielded per request.
    const rateLimit = (bucket: Bucket, request: HttpServerRequest.HttpServerRequest) =>
      consumeWith({ config, limiter, bucket, request })
    const requireTrustedOrigin = Effect.provideService(requireTrustedIfPresent, AuthConfig, config)

    return handlers
      .handle("signIn", ({ request }) =>
        Effect.gen(function* () {
          yield* rateLimit(anonymousSignIn, request)
          yield* requireTrustedOrigin
          const result = yield* anonymous
            .signIn(AuthHandlers.clientMeta(config, request))
            .pipe(AuthHandlers.serverFault)
          // An anonymous session is not remembered across a browser restart:
          // there is nothing to come back to, and a persistent cookie for an
          // account nobody owns is a row that outlives its usefulness.
          yield* setSessionCookie(config, result.session, result.token, { persistent: false })
          return { user: result.user, session: result.session }
        })
      )
      .handle("delete", () =>
        Effect.gen(function* () {
          const user = yield* CurrentUser
          // Ownership is the service's: it takes the caller's own row and has
          // no parameter that could name somebody else's.
          yield* anonymous.discard(user).pipe(AuthHandlers.serverFault)
          // The session went with the row, so the cookie has to go too — the
          // browser would otherwise present a token nothing resolves.
          yield* AuthHandlers.clearSessionCookies(config, cache)
          return AuthHandlers.acknowledged
        })
      )
  })
)
