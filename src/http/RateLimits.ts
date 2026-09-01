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
 * @since 0.1.0
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
 * @since 0.1.0
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
 * @since 0.1.0
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
 * @since 0.1.0
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
 * @since 0.1.0
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
 * @since 0.1.0
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
 * Whether a `%XX` escape is one the router leaves *literal* rather than
 * decoding.
 *
 * **Details**
 *
 * Mirrors find-my-way's `decodeComponentChar`: these are the escapes that
 * `decodeURI` would leave alone — the URI-reserved set `# $ & + , / : ; = ? @`
 * and `%25` ('%'). `high`/`low` are the two hex-digit char codes after the `%`;
 * any other pair (including a malformed one) is not literal, which is the signal
 * that the path needs a real `decodeURI` pass. Hex digits are matched
 * case-insensitively, exactly as the router matches them.
 */
const isRouterLiteralEscape = (high: number, low: number): boolean => {
  switch (high) {
    case 50: // "2"
      return (
        low === 53 || // %25 %
        low === 51 || // %23 #
        low === 52 || // %24 $
        low === 54 || // %26 &
        low === 66 ||
        low === 98 || // %2B +
        low === 67 ||
        low === 99 || // %2C ,
        low === 70 ||
        low === 102 // %2F /
      )
    case 51: // "3"
      return (
        low === 65 ||
        low === 97 || // %3A :
        low === 66 ||
        low === 98 || // %3B ;
        low === 68 ||
        low === 100 || // %3D =
        low === 70 ||
        low === 102 // %3F ?
      )
    case 52: // "4"
      return low === 48 // %40 @
    default:
      return false
  }
}

/**
 * Strips the query and decodes the percent escapes, the way the router's
 * `safeDecodeURI` does.
 *
 * **Details**
 *
 * The query is whatever follows the first `?`, `;` or `#` — the three
 * separators find-my-way honours, not `?` alone. A path with any escape that is
 * not {@link isRouterLiteralEscape} is run through `decodeURI`, so `%6C` becomes
 * `l` but `%2F` stays `%2F` (as the router keeps it literal). `%25` is
 * re-doubled to `%2525` first so `decodeURI` yields a single literal `%` rather
 * than decoding twice.
 *
 * **Gotchas**
 *
 * A malformed escape (`%zz`, a truncated `%e0`) makes `decodeURI` throw — as it
 * does inside the router, which then refuses the route. Decoding therefore falls
 * back to the undecoded (but query-stripped) path rather than throwing the
 * request out of the limiter.
 */
const stripQueryAndDecode = (raw: string): string => {
  let path = raw
  let shouldDecode = false
  for (let i = 1; i < path.length; i++) {
    const charCode = path.charCodeAt(i)
    if (charCode === 37) {
      // "%"
      const high = path.charCodeAt(i + 1)
      const low = path.charCodeAt(i + 2)
      if (!isRouterLiteralEscape(high, low)) {
        shouldDecode = true
      } else {
        if (high === 50 && low === 53) {
          // %25 → %2525, so decodeURI yields one "%"
          shouldDecode = true
          path = path.slice(0, i + 1) + "25" + path.slice(i + 1)
          i += 2
        }
        i += 2
      }
    } else if (charCode === 63 || charCode === 59 || charCode === 35) {
      // "?" ";" "#"
      path = path.slice(0, i)
      break
    }
  }
  if (!shouldDecode) return path
  try {
    return decodeURI(path)
  } catch {
    return path
  }
}

/**
 * The canonical routing path a request is counted under: `request.url` reduced
 * to the very path the router dispatched on.
 *
 * **Details**
 *
 * Keying on the raw URL is a rate-limit *bypass*: `/auth/sign-in/emai%6C` and
 * `/auth/sign-in/email` reach the same handler, but counted apart they hand an
 * attacker a fresh bucket per spelling — rotate the encodings of the unreserved
 * letters and one IP gets an unbounded supply of credential/email allowances.
 * So this reproduces the router's own canonicalisation of the path (effect's
 * find-my-way, at its default `caseSensitive: false`, `ignoreTrailingSlash` and
 * `ignoreDuplicateSlashes: true`), in the router's order: normalise a leading
 * absolute-URI form to its path, collapse duplicate slashes, strip the query and
 * `decodeURI` the escapes ({@link stripQueryAndDecode}), trim a trailing slash,
 * lower-case. Every spelling that routes alike collapses to one key; `%2F` stays
 * literal, since the router never turns it into a separator.
 *
 * @category combinators
 * @since 0.1.0
 */
export const requestPath = (request: HttpServerRequest.HttpServerRequest): string => {
  let path = request.url
  // find-my-way rewrites a full `scheme://host/…` form to its path first.
  if (path.charCodeAt(0) !== 47) path = path.replace(/^https?:\/\/.*?\//, "/")
  path = path.replace(/\/\/+/g, "/") // ignoreDuplicateSlashes
  path = stripQueryAndDecode(path) // safeDecodeURI: query strip + decodeURI
  if (path.length > 1 && path.charCodeAt(path.length - 1) === 47) {
    path = path.slice(0, -1) // ignoreTrailingSlash
  }
  return path.toLowerCase() // caseSensitive: false
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
 * @since 0.1.0
 */
export const keyFor = (bucket: Bucket, path: string, client: Option.Option<string>): string =>
  `effect-auth:${bucket.name}:${path}:${Option.getOrElse(client, () => sharedKey)}`

// -----------------------------------------------------------------------------
// Consumption
// -----------------------------------------------------------------------------

/**
 * How long a caller is told to wait, in whole seconds and never less than one.
 *
 * @category combinators
 * @since 0.1.0
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
 * @since 0.1.0
 */
export const consume = (
  bucket: Bucket
): Effect.Effect<void, RateLimited, AuthConfig | RateLimiter.RateLimiter | HttpServerRequest.HttpServerRequest> =>
  Effect.gen(function* () {
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
 * @since 0.1.0
 */
export const consumeWith = (options: {
  readonly config: AuthConfigService
  readonly limiter: RateLimiter.RateLimiter
  readonly bucket: Bucket
  readonly request: HttpServerRequest.HttpServerRequest
}): Effect.Effect<void, RateLimited> =>
  spend({
    config: options.config,
    limiter: options.limiter,
    bucket: options.bucket,
    key: keyFor(options.bucket, requestPath(options.request), clientAddress(options.config, options.request))
  })

/**
 * The key a bucket counted against an identifier is spent under:
 * `<bucket>:<identifier>`.
 *
 * **Details**
 *
 * No path and no client address. That is the whole difference from
 * {@link keyFor}, and it is the point: a resend cooldown belongs to the address
 * being mailed and a lockout to the account being guessed at, so neither may be
 * escaped by rotating an IP or by asking through a second endpoint that shares
 * the policy.
 *
 * @category combinators
 * @since 0.2.0
 */
export const keyedKeyFor = (bucket: Bucket, key: string): string => `effect-auth:${bucket.name}:${key}`

/**
 * Consumes one token from a bucket counted against an arbitrary identifier
 * rather than against the caller's address.
 *
 * **When to use**
 *
 * For the limits whose subject is a *thing* and not a caller: the cooldown
 * between two codes sent to one address, the lockout after a run of wrong codes
 * against one account. {@link consumeWith} is still the right helper for
 * "three attempts per ten seconds per client"; this one is for "one mail per
 * minute per address", which an attacker with a thousand addresses of their own
 * must not be able to sidestep.
 *
 * **Gotchas**
 *
 * The identifier is part of a shared counter's key, so hash or normalise
 * anything that is a secret or a person's own text before passing it —
 * a normalised e-mail address or a `UserId` is the intended shape.
 *
 * A bucket spent through here and the same bucket spent through
 * {@link consumeWith} share the *policy* and never the counter: the keys differ
 * in shape, which is what {@link keyedKeyFor} exists to guarantee.
 *
 * `always` spends the bucket whether or not `rateLimit.enabled` is set. Reach
 * for it when the bucket is not a throttle but a *security control* — the
 * lockout after a run of wrong second-factor codes against one account is the
 * one this library ships. `rateLimit.enabled` is documented as whether the
 * built-in limits are applied, and a deployment turns it off because it has its
 * own edge limiter in front — which throttles by address and knows nothing
 * about how many times one account has been guessed at. Letting that switch
 * silently remove a brute-force bound on a six-digit code is a foot-gun, so a
 * control that must not be switched off says so at the call site.
 *
 * @category combinators
 * @since 0.2.0
 */
export const consumeKeyed = (options: {
  readonly config: AuthConfigService
  readonly limiter: RateLimiter.RateLimiter
  readonly bucket: Bucket
  readonly key: string
  /**
   * Spend the bucket even when `rateLimit.enabled` is `false`. For a bucket
   * that is a security control rather than a throttle.
   */
  readonly always?: boolean | undefined
}): Effect.Effect<void, RateLimited> =>
  spend({
    config: options.config,
    limiter: options.limiter,
    bucket: options.bucket,
    key: keyedKeyFor(options.bucket, options.key),
    ...(options.always === undefined ? {} : { always: options.always })
  })

/** The arithmetic both consumers share, over a key that is already built. */
const spend = (options: {
  readonly config: AuthConfigService
  readonly limiter: RateLimiter.RateLimiter
  readonly bucket: Bucket
  readonly key: string
  readonly always?: boolean | undefined
}): Effect.Effect<void, RateLimited> =>
  Effect.gen(function* () {
    const { bucket, config, key, limiter } = options
    if (!config.rateLimit.enabled && options.always !== true) return

    const result = yield* Effect.result(
      limiter.consume({
        algorithm: "fixed-window",
        onExceeded: "fail",
        window: bucket.window,
        limit: bucket.limit,
        key
      })
    )
    if (result._tag === "Success") return

    const reason = result.failure.reason
    if (reason._tag === "RateLimitExceeded") {
      return yield* RateLimited.make({ retryAfterSeconds: retryAfterSeconds(reason.retryAfter) })
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
      return yield* RateLimited.make({ retryAfterSeconds: retryAfterSeconds(bucket.window) })
    }
  })

/**
 * Applies a bucket to an effect: consume first, run second.
 *
 * @category combinators
 * @since 0.1.0
 */
export const limit = <A, E, R>(
  bucket: Bucket,
  effect: Effect.Effect<A, E, R>
): Effect.Effect<A, E | RateLimited, R | AuthConfig | RateLimiter.RateLimiter | HttpServerRequest.HttpServerRequest> =>
  Effect.flatMap(consume(bucket), () => effect)

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
 * @since 0.1.0
 */
export const layerStore = (options?: {
  readonly sweepInterval?: Duration.Duration | undefined
}): Layer.Layer<RateLimiter.RateLimiterStore> =>
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
 * @since 0.1.0
 */
export const layer: Layer.Layer<RateLimiter.RateLimiter> = RateLimiter.layer.pipe(Layer.provide(layerStore()))
