import { assert, describe, it } from "@effect/vitest"
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

const config = (ipHeaders: ReadonlyArray<string>): AuthConfig.AuthConfigShape =>
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

const consuming = (
  bucket: typeof credentials,
  options?: Parameters<typeof request>[0],
  layers?: Layer.Layer<AuthConfig.AuthConfig | RateLimiter.RateLimiter>
) =>
  Effect.result(consume(bucket)).pipe(
    Effect.provideService(HttpServerRequest.HttpServerRequest, request(options)),
    Effect.provide(layers ?? Layer.mergeAll(configLayer(), rateLimiterLayer))
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

  describe("consume", () => {
    it.effect("allows the configured number of attempts and then refuses", () =>
      Effect.gen(function*() {
        const headers = { "x-forwarded-for": "203.0.113.7" }
        const layers = Layer.mergeAll(configLayer(), rateLimiterLayer)
        const shared = yield* Layer.build(layers)

        const attempt = () =>
          Effect.result(consume(credentials)).pipe(
            Effect.provideService(HttpServerRequest.HttpServerRequest, request({ headers })),
            Effect.provideContext(shared)
          )

        for (let i = 0; i < credentials.limit; i++) {
          const allowed = yield* attempt()
          assert.strictEqual(allowed._tag, "Success", `attempt ${i + 1}`)
        }

        const refused = yield* attempt()
        assert.strictEqual(refused._tag, "Failure")
        if (refused._tag === "Failure") {
          assert.instanceOf(refused.failure, RateLimited)
          assert.isAtLeast(refused.failure.retryAfterSeconds, 1)
        }
      }))

    it.effect("counts each path separately, so signing up does not spend sign-in's attempts", () =>
      Effect.gen(function*() {
        const headers = { "x-forwarded-for": "203.0.113.8" }
        const shared = yield* Layer.build(Layer.mergeAll(configLayer(), rateLimiterLayer))

        const attempt = (path: string) =>
          Effect.result(consume(credentials)).pipe(
            Effect.provideService(HttpServerRequest.HttpServerRequest, request({ path, headers })),
            Effect.provideContext(shared)
          )

        for (let i = 0; i < credentials.limit; i++) {
          const allowed = yield* attempt("/auth/sign-in/email")
          assert.strictEqual(allowed._tag, "Success")
        }
        const refused = yield* attempt("/auth/sign-in/email")
        assert.strictEqual(refused._tag, "Failure")

        const other = yield* attempt("/auth/sign-up/email")
        assert.strictEqual(other._tag, "Success")
      }))

    it.effect("fails closed: two unidentifiable callers share one counter", () =>
      Effect.gen(function*() {
        const shared = yield* Layer.build(Layer.mergeAll(configLayer({ ipHeaders: [] }), rateLimiterLayer))

        const attempt = (forwardedFor: string) =>
          Effect.result(consume(credentials)).pipe(
            Effect.provideService(
              HttpServerRequest.HttpServerRequest,
              request({ headers: { "x-forwarded-for": forwardedFor } })
            ),
            Effect.provideContext(shared)
          )

        // Different claimed addresses, but nothing is configured to trust them,
        // so they are one caller as far as the counter is concerned.
        for (let i = 0; i < credentials.limit; i++) {
          const allowed = yield* attempt(`203.0.113.${i}`)
          assert.strictEqual(allowed._tag, "Success")
        }
        const refused = yield* attempt("203.0.113.99")
        assert.strictEqual(refused._tag, "Failure")
      }))

    it.effect("does nothing at all when the limits are switched off", () =>
      Effect.gen(function*() {
        const layers = Layer.mergeAll(configLayer({ enabled: false }), brokenLimiter)
        for (let i = 0; i < credentials.limit + 2; i++) {
          const result = yield* consuming(credentials, undefined, layers)
          assert.strictEqual(result._tag, "Success")
        }
      }))

    it.effect("lets the request through when the store itself fails", () =>
      Effect.gen(function*() {
        const layers = Layer.mergeAll(configLayer(), brokenLimiter)
        const result = yield* consuming(credentials, undefined, layers)
        // A broken counter is a server fault, not the caller's: it is logged
        // and the request proceeds rather than taking sign-in down.
        assert.strictEqual(result._tag, "Success")
      }))

    it.effect("refuses instead when the deployment asked to fail closed", () =>
      Effect.gen(function*() {
        // The other trade: with a shared, remote store, "the counter is
        // unavailable" is something an attacker can arrange, and failing open
        // there removes every limit at once.
        const layers = Layer.mergeAll(configLayer({ failClosed: true }), brokenLimiter)
        const result = yield* consuming(credentials, undefined, layers)
        assert.strictEqual(result._tag, "Failure")
        if (result._tag !== "Failure") return
        assert.instanceOf(result.failure, RateLimited)
        assert.strictEqual(
          result.failure.retryAfterSeconds,
          retryAfterSeconds(credentials.window)
        )
      }))
  })

  describe("limit", () => {
    it.effect("runs the effect only when a token was available", () =>
      Effect.gen(function*() {
        const headers = { "x-forwarded-for": "203.0.113.10" }
        const shared = yield* Layer.build(Layer.mergeAll(configLayer(), rateLimiterLayer))
        let ran = 0

        const attempt = () =>
          Effect.result(limit(email, Effect.sync(() => ++ran))).pipe(
            Effect.provideService(
              HttpServerRequest.HttpServerRequest,
              request({ path: "/auth/request-password-reset", headers })
            ),
            Effect.provideContext(shared)
          )

        for (let i = 0; i < email.limit; i++) {
          yield* attempt()
        }
        assert.strictEqual(ran, email.limit)

        const refused = yield* attempt()
        assert.strictEqual(refused._tag, "Failure")
        assert.strictEqual(ran, email.limit)
      }))
  })
})
