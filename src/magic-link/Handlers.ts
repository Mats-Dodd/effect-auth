/**
 * The server implementation of {@link MagicLinkApiGroup}.
 *
 * **Details**
 *
 * A plugin's handlers are built exactly as this library's own are, and out of the
 * same pieces: `AuthHandlers.forGroup` is the boundary that lets a group be
 * implemented inside whatever `HttpApi` a consumer composed it into, and
 * `clientMeta`, `redirectTo`, `setSessionCookie` and `serverFault` are reused
 * rather than reimplemented. The three handlers below hold no policy: each reads
 * the decoded request, calls one method of {@link MagicLink}, and turns the
 * result into the endpoint's declared response.
 *
 * **Gotchas**
 *
 * The rate limits are the library's own two buckets — `email` for asking for a
 * link, `credentials` for spending one — but not the library's own *counters*:
 * a key carries the request path, so the magic link endpoints are limited
 * independently of `/auth/sign-in/email`.
 *
 * @since 1.0.0
 */
import { Effect, Redacted } from "effect"
import type { HttpServerRequest } from "effect/unstable/http"
import { RateLimiter } from "effect/unstable/persistence"
import { AuthConfig } from "../config/AuthConfig.js"
import * as AuthHandlers from "../http/Handlers.js"
import { setSessionCookie } from "../http/MiddlewareLive.js"
import type { Bucket } from "../http/RateLimits.js"
import { consumeWith, credentials, email as emailBucket } from "../http/RateLimits.js"
import { MagicLinkApiGroup } from "./Api.js"
import { MagicLink } from "./MagicLink.js"

/**
 * The services the magic link handlers need.
 *
 * **Gotchas**
 *
 * Three, and none of them a store: everything else the flow touches is behind
 * {@link MagicLink}, which is what makes this layer composable over a deployment
 * the plugin knows nothing else about.
 *
 * @category models
 * @since 1.0.0
 */
export type HandlerServices = AuthConfig | MagicLink | RateLimiter.RateLimiter

/**
 * Implements the `magicLink` group of an `HttpApi` that contains it.
 *
 * **Example**
 *
 * ```ts skip-type-checking
 * import { HttpApi } from "effect/unstable/httpapi"
 * import { AuthApi, MagicLink } from "effect-auth"
 *
 * const AppApi = HttpApi.make("app").addHttpApi(AuthApi).add(MagicLink.MagicLinkApiGroup)
 * const HandlersLive = MagicLink.handlers(AppApi)
 * ```
 *
 * **Gotchas**
 *
 * The API passed here must be the one passed to `HttpApiBuilder.layer`: the
 * routes are read off the group *it* carries. A group merely *named* `magicLink`,
 * or this one re-prefixed with `HttpApi.prefix`, is rejected here rather than
 * mis-served — see `AuthHandlers.forGroup`.
 *
 * @category layers
 * @since 1.0.0
 */
export const handlers = AuthHandlers.forGroup(MagicLinkApiGroup, (handlers) =>
  Effect.gen(function*() {
    const config = yield* AuthConfig
    const magicLink = yield* MagicLink
    const limiter = yield* RateLimiter.RateLimiter

    // Resolved here, when the layer is built, so that no handler carries a
    // request-time requirement.
    const rateLimit = (bucket: Bucket, request: HttpServerRequest.HttpServerRequest) =>
      consumeWith({ config, limiter, bucket, request })

    return handlers
      .handle("signIn", ({ payload, request }) =>
        Effect.gen(function*() {
          // The mail bucket, not the credential one: this endpoint sends a
          // message to an address somebody else may own.
          yield* rateLimit(emailBucket, request)
          yield* magicLink.request({
            email: payload.email,
            name: payload.name,
            callbackURL: payload.callbackURL,
            newUserCallbackURL: payload.newUserCallbackURL,
            errorCallbackURL: payload.errorCallbackURL,
            rememberMe: payload.rememberMe
          }).pipe(AuthHandlers.serverFault)
          // The same answer for a known address, an unknown one, and a message
          // that could not be delivered.
          return AuthHandlers.acknowledged
        }))
      .handle("verify", ({ query, request }) =>
        Effect.gen(function*() {
          yield* rateLimit(credentials, request)
          // A query parameter is decoded as a plain string — query strings do not
          // go through the JSON codec — so it is redacted here, before anything
          // can log it.
          const outcome = yield* magicLink.complete({
            token: Redacted.make(query.token),
            ...AuthHandlers.clientMeta(config, request)
          }).pipe(AuthHandlers.serverFault)

          if (outcome._tag === "Success") {
            yield* setSessionCookie(config, outcome.session, outcome.token, {
              persistent: outcome.rememberMe
            })
          }
          // Success or failure, the browser arrived by a top-level navigation and
          // leaves by one. A deployment's own refusal is one of those failures
          // and `complete` has already resolved it into the link's own error
          // URL carrying `?error=policy_refused&code=…` — the token was claimed
          // before either hook was asked, so the link is spent whichever way it
          // went, and no cookie is set: no session exists.
          return AuthHandlers.redirectTo(outcome.redirectTo)
        }))
      .handle("exchange", ({ payload, request }) =>
        Effect.gen(function*() {
          yield* rateLimit(credentials, request)
          const result = yield* magicLink.verify({
            token: payload.token,
            ...AuthHandlers.clientMeta(config, request)
          }).pipe(AuthHandlers.serverFault)

          // A browser calling this is signed in as well as answered, which is
          // what makes the two endpoints interchangeable.
          yield* setSessionCookie(config, result.session, result.token, {
            persistent: result.rememberMe
          })
          return { user: result.user, session: result.session }
        }))
  }))
