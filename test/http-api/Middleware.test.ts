import { assert, describe, it } from "@effect/vitest"
import { Context, DateTime, Duration, Effect, Redacted, Schema } from "effect"
import { TestClock } from "effect/testing"
import { HttpApiEndpoint, HttpApiMiddleware } from "effect/unstable/httpapi"
import * as AuthConfig from "../../src/config/AuthConfig.js"
import { SessionNotFresh } from "../../src/domain/Errors.js"
import { Session, SessionId, UserId } from "../../src/domain/Schema.js"
import {
  Authenticated,
  AuthoritativeSession,
  CurrentSession,
  CurrentUser,
  requireFresh
} from "../../src/http/Middleware.js"

const configWith = (freshAge: Duration.Duration): AuthConfig.AuthConfigService =>
  AuthConfig.make({
    baseUrl: "https://app.example.com",
    secret: Redacted.make("test-secret"),
    session: { freshAge }
  })

/**
 * `requireFresh` against a deployment whose `freshAge` is `freshAge`, for the
 * session the caller made. The only two things any of these tests vary.
 */
const freshnessOf = (freshAge: Duration.Duration, session: Session) =>
  requireFresh.pipe(
    Effect.provideService(CurrentSession, session),
    Effect.provideService(AuthConfig.AuthConfig, configWith(freshAge))
  )

const makeSession = Effect.gen(function*() {
  const now = yield* DateTime.now
  return Session.make({
    id: SessionId.make("0193f6f0-0000-7000-8000-0000000000aa"),
    tokenHash: "not-the-raw-token",
    userId: UserId.make("0193f6f0-0000-7000-8000-000000000001"),
    expiresAt: DateTime.addDuration(now, Duration.days(7)),
    ipAddress: null,
    userAgent: null,
    createdAt: now,
    updatedAt: now
  })
})

const security = (Authenticated as unknown as {
  readonly security: Record<string, { readonly _tag: string; readonly key?: string; readonly in?: string }>
}).security

describe("http/Middleware", () => {
  describe("Authenticated", () => {
    it("is security middleware", () => {
      assert.isTrue(HttpApiMiddleware.isSecurity(Authenticated as never))
    })

    it("tries the secure cookie, then the plain cookie, then a bearer token", () => {
      assert.deepStrictEqual(Object.keys(security), ["secureSessionCookie", "sessionCookie", "bearer"])

      assert.strictEqual(security.secureSessionCookie?._tag, "ApiKey")
      assert.strictEqual(security.secureSessionCookie?.key, "__Secure-effect_auth.session")
      assert.strictEqual(security.secureSessionCookie?.in, "cookie")

      assert.strictEqual(security.sessionCookie?._tag, "ApiKey")
      assert.strictEqual(security.sessionCookie?.key, "effect_auth.session")
      assert.strictEqual(security.sessionCookie?.in, "cookie")

      assert.strictEqual(security.bearer?._tag, "Http")
    })

    it("declares Unauthorized and is required on generated clients", () => {
      assert.strictEqual((Authenticated as unknown as { readonly error: ReadonlySet<unknown> }).error.size, 1)
      assert.isTrue((Authenticated as unknown as { readonly requiredForClient: boolean }).requiredForClient)
    })

    it("keys the principal under distinct service ids", () => {
      assert.strictEqual(CurrentSession.key, "effect-auth/CurrentSession")
      assert.strictEqual(CurrentUser.key, "effect-auth/CurrentUser")
    })
  })

  /**
   * The annotation the cookie cache is switched off by, read exactly as
   * `MiddlewareLive` reads it.
   *
   * **Gotchas**
   *
   * *Which* of this library's endpoints carry it is pinned in
   * `test/http-api/AuthApi.test.ts`; what is pinned here is the mechanism a
   * plugin's own endpoint opts in through, and the default an endpoint that says
   * nothing gets.
   */
  describe("AuthoritativeSession", () => {
    const plain = HttpApiEndpoint.get("plain", "/plain", { success: Schema.String })
      .middleware(Authenticated)

    const authoritative = HttpApiEndpoint.get("authoritative", "/authoritative", { success: Schema.String })
      .middleware(Authenticated)
      .annotate(AuthoritativeSession, true)

    it("defaults to false, so an endpoint that says nothing is cacheable", () => {
      assert.isFalse(Context.get(plain.annotations, AuthoritativeSession))
    })

    it("is true on an endpoint that annotates it", () => {
      assert.isTrue(Context.get(authoritative.annotations, AuthoritativeSession))
    })

    it("is a reference on the endpoint's annotations, not a middleware of its own", () => {
      assert.strictEqual(AuthoritativeSession.key, "effect-auth/AuthoritativeSession")
      // Annotating changes nothing else about the endpoint: the same middleware,
      // the same declared errors, and therefore the same client and the same
      // OpenAPI document.
      assert.deepStrictEqual(
        Array.from(authoritative.middlewares),
        Array.from(plain.middlewares)
      )
    })
  })

  describe("requireFresh", () => {
    it.effect("passes for a session created within freshAge", () =>
      Effect.gen(function*() {
        const session = yield* makeSession
        yield* TestClock.adjust(Duration.hours(23))

        yield* freshnessOf(Duration.days(1), session)
      }))

    it.effect("fails once the session is older than freshAge", () =>
      Effect.gen(function*() {
        const session = yield* makeSession
        yield* TestClock.adjust(Duration.hours(25))

        const error = yield* Effect.flip(freshnessOf(Duration.days(1), session))

        assert.instanceOf(error, SessionNotFresh)
        assert.strictEqual(error.freshAgeSeconds, 86_400)
      }))

    it.effect("reports the configured window, not the default", () =>
      Effect.gen(function*() {
        const session = yield* makeSession
        yield* TestClock.adjust(Duration.minutes(10))

        const error = yield* Effect.flip(freshnessOf(Duration.minutes(5), session))

        assert.strictEqual(error.freshAgeSeconds, 300)
      }))
  })
})
