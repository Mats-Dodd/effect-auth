/**
 * The built-in rate limits.
 *
 * Four endpoints are worth spending a counter on: the two that verify a
 * password (`sign-in`, `sign-up`) and the two that send mail to an arbitrary
 * address (`request-password-reset`, `send-verification-email`). The first pair
 * is what a credential-stuffing run hits; the second is what turns the service
 * into somebody else's mail cannon.
 *
 * **Details**
 *
 * Buckets are keyed by `(bucket, path, client ip)` and counted with the fixed-window
 * algorithm of `unstable/persistence`'s `RateLimiter`, over the process-local
 * store {@link layerStore} builds. A deployment running more than one process
 * should count in a shared `RateLimiterStore` instead — the store is a layer of
 * its own for exactly that reason.
 *
 * @since 1.0.0
 */
import { Duration, Effect, Layer, Option } from "effect"
import { HttpServerRequest } from "effect/unstable/http"
import { RateLimiter } from "effect/unstable/persistence"
import type { AuthConfigService } from "../config/AuthConfig.js"
import { AuthConfig } from "../config/AuthConfig.js"
import { RateLimited } from "../domain/Errors.js"
import { authLogAnnotations } from "../internal/effects.js"
import { makeStore } from "../internal/rateLimiterStore.js"

// -----------------------------------------------------------------------------
// Buckets
// -----------------------------------------------------------------------------

/**
 * One configured limit: how many requests, over what window.
 *
 * @category models
 * @since 1.0.0
 */
export interface Bucket {
  /** Names the policy. Part of the key, so two buckets never share a count. */
  readonly name: string
  readonly limit: number
  readonly window: Duration.Duration
}

/**
 * The limit applied to the two endpoints that verify a password: three attempts
 * per ten seconds per client.
 *
 * @category constructors
 * @since 1.0.0
 */
export const credentials: Bucket = {
  name: "credentials",
  limit: 3,
  window: Duration.seconds(10)
}

/**
 * The limit applied to the two endpoints that send mail: three per minute per
 * client.
 *
 * @category constructors
 * @since 1.0.0
 */
export const email: Bucket = {
  name: "email",
  limit: 3,
  window: Duration.seconds(60)
}

// -----------------------------------------------------------------------------
// Client identity
// -----------------------------------------------------------------------------

/**
 * The bucket key used when no client address can be derived.
 *
 * **Details**
 *
 * Requests that share this key share one counter, which is the fail-closed
 * behaviour the security checklist asks for: with no way to tell callers apart,
 * the safe answer is to treat them as one caller rather than as unlimited
 * distinct ones.
 *
 * @category constructors
 * @since 1.0.0
 */
export const sharedKey = "shared"

/**
 * Derives a client address from the configured header chain, falling back to
 * the connection's remote address.
 *
 * **Details**
 *
 * Only the first hop of the first configured header that is present is used —
 * `x-forwarded-for: <client>, <proxy>, <proxy>` is read left to right, and the
 * leftmost entry is the one the client itself supplied.
 *
 * **Gotchas**
 *
 * That leftmost entry is *forgeable* unless a reverse proxy you control
 * overwrites the header. If nothing overwrites it, configure
 * `rateLimit.ipHeaders: []`: every request then falls into the shared bucket,
 * which throttles everyone a little instead of throttling nobody at all.
 *
 * @category combinators
 * @since 1.0.0
 */
export const clientAddress = (
  config: AuthConfigService,
  request: HttpServerRequest.HttpServerRequest
): Option.Option<string> => {
  for (const header of config.rateLimit.ipHeaders) {
    const value = request.headers[header.toLowerCase()]
    if (value === undefined) continue
    const first = value.split(",")[0]?.trim()
    if (first !== undefined && first.length > 0) return Option.some(first)
  }
  return request.remoteAddress
}

/**
 * The path a request was made to, without its query string.
 *
 * @category combinators
 * @since 1.0.0
 */
export const requestPath = (request: HttpServerRequest.HttpServerRequest): string => {
  const url = request.url
  const query = url.indexOf("?")
  return query === -1 ? url : url.slice(0, query)
}

/**
 * The key a request is counted under: `<bucket>:<path>:<client>`.
 *
 * **Details**
 *
 * The path is part of the key, as the specification asks — a limit is "three
 * per ten seconds per (ip, path)". Two endpoints sharing a bucket therefore
 * share the *policy*, not the counter: signing up does not spend the attempts
 * that signing in is allowed.
 *
 * @category combinators
 * @since 1.0.0
 */
export const keyFor = (
  bucket: Bucket,
  path: string,
  client: Option.Option<string>
): string => `effect-auth:${bucket.name}:${path}:${Option.getOrElse(client, () => sharedKey)}`

// -----------------------------------------------------------------------------
// Consumption
// -----------------------------------------------------------------------------

/**
 * How long a caller is told to wait, in whole seconds and never less than one.
 *
 * @category combinators
 * @since 1.0.0
 */
export const retryAfterSeconds = (retryAfter: Duration.Duration): number =>
  Math.max(1, Math.ceil(Duration.toMillis(retryAfter) / 1000))

/**
 * Consumes one token from a bucket for the current request, failing
 * `RateLimited` when the bucket is empty.
 *
 * **Details**
 *
 * `RateLimiter.RateLimitExceeded` carries the bucket key, which for these
 * limits is a client IP address; it is therefore translated rather than
 * declared on an endpoint. A failure of the *store* is a server fault, not the
 * caller's, so by default it is logged and the request is let through — a
 * broken counter must not take the sign-in endpoint down with it. Set
 * `rateLimit.failClosed` to answer `RateLimited` instead, which is the right
 * trade where a shared store makes "the counter is unavailable" something an
 * attacker can arrange.
 *
 * @category combinators
 * @since 1.0.0
 */
export const consume = (
  bucket: Bucket
): Effect.Effect<
  void,
  RateLimited,
  AuthConfig | RateLimiter.RateLimiter | HttpServerRequest.HttpServerRequest
> =>
  Effect.gen(function*() {
    const config = yield* AuthConfig
    const limiter = yield* RateLimiter.RateLimiter
    const request = yield* HttpServerRequest.HttpServerRequest
    return yield* consumeWith({ config, limiter, bucket, request })
  })

/**
 * {@link consume}, with everything it reads from the environment passed in.
 *
 * **When to use**
 *
 * From a handler whose services were resolved once when its layer was built.
 * The `HttpApi` builder wraps anything a handler still requires at request time
 * in a router-scoped service, so resolving `AuthConfig` and the limiter up front
 * is what keeps the handler layer's requirements plain.
 *
 * @category combinators
 * @since 1.0.0
 */
export const consumeWith = (options: {
  readonly config: AuthConfigService
  readonly limiter: RateLimiter.RateLimiter
  readonly bucket: Bucket
  readonly request: HttpServerRequest.HttpServerRequest
}): Effect.Effect<void, RateLimited> =>
  Effect.gen(function*() {
    const { bucket, config, limiter, request } = options
    if (!config.rateLimit.enabled) return
    const key = keyFor(bucket, requestPath(request), clientAddress(config, request))

    const result = yield* Effect.result(limiter.consume({
      algorithm: "fixed-window",
      onExceeded: "fail",
      window: bucket.window,
      limit: bucket.limit,
      key
    }))
    if (result._tag === "Success") return

    const reason = result.failure.reason
    if (reason._tag === "RateLimitExceeded") {
      return yield* Effect.fail(new RateLimited({ retryAfterSeconds: retryAfterSeconds(reason.retryAfter) }))
    }
    const failClosed = config.rateLimit.failClosed
    yield* Effect.logWarning(
      failClosed
        ? "the rate limiter store failed; request refused (rateLimit.failClosed)"
        : "the rate limiter store failed; request allowed"
    ).pipe(Effect.annotateLogs({ ...authLogAnnotations, bucket: bucket.name }))
    if (failClosed) {
      // No counter means no way to tell an ordinary caller from a run of
      // guesses, so the window's own length is what the caller is told to wait.
      return yield* Effect.fail(new RateLimited({ retryAfterSeconds: retryAfterSeconds(bucket.window) }))
    }
  })

/**
 * Applies a bucket to an effect: consume first, run second.
 *
 * @category combinators
 * @since 1.0.0
 */
export const limit = <A, E, R>(
  bucket: Bucket,
  effect: Effect.Effect<A, E, R>
): Effect.Effect<
  A,
  E | RateLimited,
  R | AuthConfig | RateLimiter.RateLimiter | HttpServerRequest.HttpServerRequest
> => Effect.flatMap(consume(bucket), () => effect)

// -----------------------------------------------------------------------------
// Layer
// -----------------------------------------------------------------------------

/**
 * The default store: counters held in process-local memory, with the expired
 * ones deleted by a sweep that runs for as long as the layer's scope.
 *
 * **Details**
 *
 * `options.sweepInterval` is how often the sweep runs; it defaults to one
 * minute, which is no shorter than either bucket above, so a window is dead by
 * the time it is collected. Nothing else about the store's arithmetic differs
 * from `RateLimiter.layerStoreMemory`.
 *
 * **Gotchas**
 *
 * The sweep bounds the store's *size*, not the count of any live window: a
 * caller that keeps spending its allowance keeps its counter.
 *
 * @category layers
 * @since 1.0.0
 */
export const layerStore = (
  options?: { readonly sweepInterval?: Duration.Duration | undefined } | undefined
): Layer.Layer<RateLimiter.RateLimiterStore> =>
  Layer.effect(
    RateLimiter.RateLimiterStore,
    Effect.map(makeStore(options), (evicting) => evicting.store)
  )

/**
 * The default rate limiter: fixed windows counted in process-local memory.
 *
 * **Gotchas**
 *
 * Process-local means per-instance. Behind a load balancer with four instances
 * the effective limit is four times what is configured. Count in a shared store
 * to fix that — `RateLimiter.layer.pipe(Layer.provide(myStore))` is this layer
 * with {@link layerStore} swapped out, and `Auth.layer` merges this one only as
 * a default.
 *
 * The store deletes an expired window rather than holding it, which
 * `RateLimiter.layerStoreMemory` does not: it resets an expired counter the
 * next time its key is used, and never deletes it. A key embeds the client
 * address — taken by default from a header the client itself can forge — so
 * that store keeps one entry per unauthenticated request made with a fresh
 * spoofed address, for the life of the process, and nothing bounds how many.
 * That is why this layer does not install it.
 *
 * @category layers
 * @since 1.0.0
 */
export const layer: Layer.Layer<RateLimiter.RateLimiter> = RateLimiter.layer.pipe(
  Layer.provide(layerStore())
)
