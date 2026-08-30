import { assert, describe, it, layer } from "@effect/vitest"
import { Duration, Effect, Layer, Option, Redacted } from "effect"
import { HttpServerRequest } from "effect/unstable/http"
import { RateLimiter } from "effect/unstable/persistence"
import * as AuthConfig from "../../src/config/AuthConfig.js"
import { RateLimited } from "../../src/domain/Errors.js"
import {
  clientAddress,
  consume,
  credentials,
  email,
  keyFor,
  layer as rateLimiterLayer,
  limit,
  requestPath,
  retryAfterSeconds,
  sharedKey
} from "../../src/http/RateLimits.js"

const baseUrl = "https://app.example.com"

const configLayer = (rateLimit?: {
  readonly enabled?: boolean
  readonly ipHeaders?: ReadonlyArray<string>
  readonly failClosed?: boolean
}) =>
  AuthConfig.layer({
    baseUrl,
    secret: Redacted.make("test-secret"),
    rateLimit
  })

const config = (ipHeaders: ReadonlyArray<string>): AuthConfig.AuthConfigService =>
  AuthConfig.make({
    baseUrl,
    secret: Redacted.make("test-secret"),
    rateLimit: { ipHeaders }
  })

const request = (options?: {
  readonly path?: string
  readonly headers?: Record<string, string>
  readonly remoteAddress?: string
}) => {
  const base = HttpServerRequest.fromWeb(
    new Request(`${baseUrl}${options?.path ?? "/auth/sign-in/email"}`, {
      method: "POST",
      headers: options?.headers ?? {}
    })
  )
  return options?.remoteAddress === undefined
    ? base
    : base.modify({ remoteAddress: Option.some(options.remoteAddress) })
}

/** A limiter whose store is broken: every consumption is a server fault. */
const brokenLimiter = Layer.succeed(RateLimiter.RateLimiter)({
  [RateLimiter.TypeId]: RateLimiter.TypeId,
  consume: () =>
    Effect.fail(
      new RateLimiter.RateLimiterError({
        reason: new RateLimiter.RateLimitStoreError({ message: "the store is down" })
      })
    ),
  adaptiveConsume: () => Effect.die("unused"),
  adaptiveFeedback: () => Effect.die("unused")
})

/**
 * A deployment with real counters.
 *
 * `Layer.fresh` matters: a nested `it.layer` forks its parent's memo map and
 * memoises by object identity, so without it a variant sub-block would be
 * handed the counters the enclosing block had already spent.
 */
const counting = (rateLimit?: Parameters<typeof configLayer>[0]) =>
  Layer.mergeAll(configLayer(rateLimit), Layer.fresh(rateLimiterLayer))

/** A deployment whose counters always fault. */
const faulting = (rateLimit?: Parameters<typeof configLayer>[0]) =>
  Layer.mergeAll(configLayer(rateLimit), brokenLimiter)

/**
 * One consumption of `bucket` by the caller `options` describes, as a Result —
 * the block's layer supplies the configuration and the counters, so repeated
 * calls inside a test spend the *same* counter.
 */
const attempt = (bucket: typeof credentials, options?: Parameters<typeof request>[0]) =>
  Effect.result(consume(bucket)).pipe(
    Effect.provideService(HttpServerRequest.HttpServerRequest, request(options))
  )

describe("http/RateLimits", () => {
  describe("client identity", () => {
    it("reads the first hop of the first configured header that is present", () => {
      const c = config(["x-real-ip", "x-forwarded-for"])
      assert.deepStrictEqual(
        clientAddress(c, request({ headers: { "x-forwarded-for": "203.0.113.7, 10.0.0.1, 10.0.0.2" } })),
        Option.some("203.0.113.7")
      )
      assert.deepStrictEqual(
        clientAddress(
          c,
          request({ headers: { "x-real-ip": "198.51.100.4", "x-forwarded-for": "203.0.113.7" } })
        ),
        Option.some("198.51.100.4")
      )
    })

    it("falls back to the connection's remote address", () => {
      assert.deepStrictEqual(
        clientAddress(config(["x-forwarded-for"]), request({ remoteAddress: "192.0.2.9" })),
        Option.some("192.0.2.9")
      )
    })

    it("ignores the headers entirely when none are configured", () => {
      assert.deepStrictEqual(
        clientAddress(config([]), request({ headers: { "x-forwarded-for": "203.0.113.7" } })),
        Option.none()
      )
    })

    it("answers None when nothing identifies the caller", () => {
      assert.deepStrictEqual(clientAddress(config(["x-forwarded-for"]), request()), Option.none())
    })
  })

  describe("keys", () => {
    it("keys on the bucket, the path and the client", () => {
      assert.strictEqual(
        keyFor(credentials, "/auth/sign-in/email", Option.some("203.0.113.7")),
        "effect-auth:credentials:/auth/sign-in/email:203.0.113.7"
      )
    })

    it("falls into one shared bucket when the caller cannot be identified", () => {
      assert.strictEqual(
        keyFor(email, "/auth/request-password-reset", Option.none()),
        `effect-auth:email:/auth/request-password-reset:${sharedKey}`
      )
    })

    it("drops the query string from the path", () => {
      assert.strictEqual(requestPath(request({ path: "/auth/verify-email?token=abc" })), "/auth/verify-email")
      assert.strictEqual(requestPath(request({ path: "/auth/sign-in/email" })), "/auth/sign-in/email")
    })

    it("rounds a retry hint up to a whole second, and never to zero", () => {
      assert.strictEqual(retryAfterSeconds(Duration.millis(1)), 1)
      assert.strictEqual(retryAfterSeconds(Duration.millis(1500)), 2)
      assert.strictEqual(retryAfterSeconds(Duration.seconds(10)), 10)
    })
  })
})

// The counters are shared by every test in the block, so each of these claims a
// client address of its own — which is also what makes them concurrency-safe.
layer(counting())("http/RateLimits/consume", (it) => {
  it.effect("allows the configured number of attempts and then refuses", () =>
    Effect.gen(function*() {
      const headers = { "x-forwarded-for": "203.0.113.7" }

      for (let i = 0; i < credentials.limit; i++) {
        const allowed = yield* attempt(credentials, { headers })
        assert.strictEqual(allowed._tag, "Success", `attempt ${i + 1}`)
      }

      const refused = yield* attempt(credentials, { headers })
      assert.strictEqual(refused._tag, "Failure")
      if (refused._tag === "Failure") {
        assert.instanceOf(refused.failure, RateLimited)
        assert.isAtLeast(refused.failure.retryAfterSeconds, 1)
      }
    }))

  it.effect("counts each path separately, so signing up does not spend sign-in's attempts", () =>
    Effect.gen(function*() {
      const headers = { "x-forwarded-for": "203.0.113.8" }

      for (let i = 0; i < credentials.limit; i++) {
        const allowed = yield* attempt(credentials, { path: "/auth/sign-in/email", headers })
        assert.strictEqual(allowed._tag, "Success")
      }
      const refused = yield* attempt(credentials, { path: "/auth/sign-in/email", headers })
      assert.strictEqual(refused._tag, "Failure")

      const other = yield* attempt(credentials, { path: "/auth/sign-up/email", headers })
      assert.strictEqual(other._tag, "Success")
    }))

  it.effect("runs the effect only when a token was available", () =>
    Effect.gen(function*() {
      const headers = { "x-forwarded-for": "203.0.113.10" }
      let ran = 0

      const spend = () =>
        Effect.result(limit(email, Effect.sync(() => ++ran))).pipe(
          Effect.provideService(
            HttpServerRequest.HttpServerRequest,
            request({ path: "/auth/request-password-reset", headers })
          )
        )

      for (let i = 0; i < email.limit; i++) {
        yield* spend()
      }
      assert.strictEqual(ran, email.limit)

      const refused = yield* spend()
      assert.strictEqual(refused._tag, "Failure")
      assert.strictEqual(ran, email.limit)
    }))

  it.layer(counting({ ipHeaders: [] }))("with no trusted headers", (it) => {
    it.effect("fails closed: two unidentifiable callers share one counter", () =>
      Effect.gen(function*() {
        // Different claimed addresses, but nothing is configured to trust them,
        // so they are one caller as far as the counter is concerned.
        for (let i = 0; i < credentials.limit; i++) {
          const allowed = yield* attempt(credentials, { headers: { "x-forwarded-for": `203.0.113.${i}` } })
          assert.strictEqual(allowed._tag, "Success")
        }
        const refused = yield* attempt(credentials, { headers: { "x-forwarded-for": "203.0.113.99" } })
        assert.strictEqual(refused._tag, "Failure")
      }))
  })

  it.layer(faulting({ enabled: false }))("with the limits switched off", (it) => {
    it.effect("does nothing at all", () =>
      Effect.gen(function*() {
        for (let i = 0; i < credentials.limit + 2; i++) {
          const result = yield* attempt(credentials)
          assert.strictEqual(result._tag, "Success")
        }
      }))
  })

  it.layer(faulting())("with a broken store", (it) => {
    it.effect("lets the request through", () =>
      Effect.gen(function*() {
        const result = yield* attempt(credentials)
        // A broken counter is a server fault, not the caller's: it is logged
        // and the request proceeds rather than taking sign-in down.
        assert.strictEqual(result._tag, "Success")
      }))
  })

  it.layer(faulting({ failClosed: true }))("with a broken store, failing closed", (it) => {
    it.effect("refuses instead", () =>
      Effect.gen(function*() {
        // The other trade: with a shared, remote store, "the counter is
        // unavailable" is something an attacker can arrange, and failing open
        // there removes every limit at once.
        const result = yield* attempt(credentials)
        assert.strictEqual(result._tag, "Failure")
        if (result._tag !== "Failure") return
        assert.instanceOf(result.failure, RateLimited)
        assert.strictEqual(
          result.failure.retryAfterSeconds,
          retryAfterSeconds(credentials.window)
        )
      }))
  })
})
