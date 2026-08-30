import { assert, describe, it } from "@effect/vitest"
import { DateTime, Duration, Effect, Option, PubSub, Redacted } from "effect"
import { TestClock } from "effect/testing"
import { OAuthProviderError, OAuthStateMismatch } from "../../src/domain/Errors.js"
import type { AuthEvent } from "../../src/domain/Events.js"
import { AuthEvents } from "../../src/domain/Events.js"
import { oauthIssuer, User } from "../../src/domain/Schema.js"
import { AccountStore, UserStore } from "../../src/domain/Stores.js"
import { decodeTokens, errorCode, OAuthFlow, withErrorCode } from "../../src/oauth/Flow.js"
import {
  authorizeUrl,
  flowLayer,
  formOf,
  json,
  mockProvider,
  mockServer,
  paramsOf,
  providerOrigin,
  redirect,
  testTimeout,
  tokenUrl,
  userInfoUrl
} from "./harness.js"

/**
 * A provider that behaves: it hands back a token for any code, and reports one
 * identity. Each test gets its own server so the recorded requests are its own.
 */
const wellBehaved = (identity?: {
  readonly sub?: string
  readonly email?: string
  readonly email_verified?: boolean
}) => {
  const server = mockServer()
  server.on(tokenUrl, () =>
    json({
      access_token: "provider-access-token",
      token_type: "bearer",
      refresh_token: "provider-refresh-token",
      expires_in: 3600,
      scope: "profile email"
    }))
  server.on(userInfoUrl, () =>
    json({
      sub: identity?.sub ?? "provider-subject-1",
      email: identity?.email ?? "ada@example.com",
      email_verified: identity?.email_verified ?? true,
      name: "Ada Lovelace",
      picture: "https://cdn.test/ada.png"
    }))
  return server
}

describe("oauth/Flow", () => {
  describe("decodeTokens", () => {
    const now = DateTime.makeUnsafe(1_000_000)

    it("reads a well-formed token response, string expiries included", () => {
      const tokens = decodeTokens({
        access_token: "at",
        token_type: "bearer",
        refresh_token: "rt",
        // Some providers send these as strings, which is legal enough.
        expires_in: "3600",
        refresh_token_expires_in: 7200,
        scope: "profile email",
        id_token: "it"
      }, now)
      assert.isNotNull(tokens)
      if (tokens === null) return
      assert.strictEqual(Redacted.value(tokens.accessToken), "at")
      assert.strictEqual(tokens.refreshToken === null ? null : Redacted.value(tokens.refreshToken), "rt")
      assert.strictEqual(tokens.idToken === null ? null : Redacted.value(tokens.idToken), "it")
      assert.strictEqual(tokens.scope, "profile email")
      assert.strictEqual(
        tokens.accessTokenExpiresAt === null ? 0 : DateTime.toEpochMillis(tokens.accessTokenExpiresAt),
        1_000_000 + 3_600_000
      )
      assert.strictEqual(
        tokens.refreshTokenExpiresAt === null ? 0 : DateTime.toEpochMillis(tokens.refreshTokenExpiresAt),
        1_000_000 + 7_200_000
      )
      // Claims are the flow's to fill in, after verification.
      assert.isNull(tokens.idTokenClaims)
    })

    it("reads an error body, and anything else without an access token, as nothing", () => {
      assert.isNull(decodeTokens({ error: "invalid_grant" }, now))
      assert.isNull(decodeTokens({ access_token: "" }, now))
      assert.isNull(decodeTokens("not an object", now))
      assert.isNull(decodeTokens(["not an object either"], now))
      assert.isNull(decodeTokens(null, now))
    })

    it("does not read an inherited property as a token", () => {
      // A body is a provider-controlled record: `{"__proto__": {...}}` parsed
      // from JSON leaves an own key, but the *prototype* must never answer.
      const hostile = JSON.parse('{"__proto__": {"access_token": "inherited"}}') as unknown
      assert.isNull(decodeTokens(hostile, now))
    })
  })

  describe("errorCode", () => {
    it("is a closed set that never echoes the provider", () => {
      assert.strictEqual(errorCode(new OAuthStateMismatch()), "state_mismatch")
      const reasons = [
        ["UnknownProvider", "unknown_provider"],
        ["AccessDenied", "access_denied"],
        ["TokenExchangeFailed", "token_exchange_failed"],
        ["UserInfoFailed", "user_info_failed"],
        ["IdTokenInvalid", "id_token_invalid"],
        ["ProviderUnavailable", "provider_unavailable"]
      ] as const
      for (const [reason, code] of reasons) {
        assert.strictEqual(errorCode(new OAuthProviderError({ providerId: "mock", reason })), code)
      }
    })

    it("appends the code without disturbing the rest of the URL", () => {
      assert.strictEqual(
        withErrorCode("https://app.example.com/sign-in?next=/dashboard", "access_denied"),
        "https://app.example.com/sign-in?next=%2Fdashboard&error=access_denied"
      )
    })
  })

  describe("start", () => {
    it.effect(
      "builds an authorization URL with PKCE S256 and a single-use state",
      () =>
        Effect.gen(function*() {
          const flow = yield* OAuthFlow
          const started = yield* flow.start({
            providerId: "mock",
            callbackURL: "/welcome",
            scopes: ["extra:scope"]
          })

          const params = paramsOf(started.url)
          assert.isTrue(started.url.startsWith(authorizeUrl))
          assert.strictEqual(params.get("response_type"), "code")
          assert.strictEqual(params.get("client_id"), "mock-client-id")
          assert.strictEqual(
            params.get("redirect_uri"),
            "https://app.example.com/auth/callback/mock"
          )
          assert.strictEqual(params.get("scope"), "profile email extra:scope")
          assert.strictEqual(params.get("state"), Redacted.value(started.state))
          assert.strictEqual(params.get("code_challenge_method"), "S256")
          assert.isNotNull(params.get("code_challenge"))
          // A plain OAuth2 provider gets no nonce: there is no id_token to echo it.
          assert.isNull(params.get("nonce"))
        }).pipe(Effect.provide(flowLayer({ providers: [mockProvider()], fetch: wellBehaved().fetch }))),
      testTimeout
    )

    it.effect(
      "refuses an id nobody registered, before touching the database",
      () =>
        Effect.gen(function*() {
          const flow = yield* OAuthFlow
          const result = yield* Effect.result(flow.start({ providerId: "__proto__" }))
          assert.strictEqual(result._tag, "Failure")
          if (result._tag !== "Failure") return
          assert.strictEqual(result.failure._tag, "OAuthProviderError")
          if (result.failure._tag !== "OAuthProviderError") return
          assert.strictEqual(result.failure.reason, "UnknownProvider")
        }).pipe(Effect.provide(flowLayer({ providers: [mockProvider()], fetch: wellBehaved().fetch }))),
      testTimeout
    )

    it.effect(
      "cannot have its own parameters overridden by a provider's extras",
      () =>
        Effect.gen(function*() {
          const flow = yield* OAuthFlow
          const started = yield* flow.start({ providerId: "mock" })
          const params = paramsOf(started.url)
          assert.strictEqual(params.get("state"), Redacted.value(started.state))
          assert.strictEqual(params.get("code_challenge_method"), "S256")
          assert.strictEqual(params.get("access_type"), "offline")
        }).pipe(Effect.provide(flowLayer({
          providers: [
            mockProvider({
              authorizationParams: {
                access_type: "offline",
                state: "attacker-chosen",
                code_challenge_method: "plain",
                redirect_uri: "https://evil.test/collect"
              }
            })
          ],
          fetch: wellBehaved().fetch
        }))),
      testTimeout
    )

    it.effect(
      "falls back to baseUrl for a callbackURL on an untrusted origin",
      () =>
        Effect.gen(function*() {
          const flow = yield* OAuthFlow
          const started = yield* flow.start({
            providerId: "mock",
            callbackURL: "https://evil.test/collect"
          })
          const done = yield* flow.callback({
            providerId: "mock",
            code: "authorization-code",
            state: Redacted.value(started.state)
          })
          assert.strictEqual(done.redirectTo, "https://app.example.com")
        }).pipe(Effect.provide(flowLayer({ providers: [mockProvider()], fetch: wellBehaved().fetch }))),
      testTimeout
    )
  })

  describe("callback", () => {
    it.effect(
      "runs the whole flow: code exchange, identity, user, account, session",
      () => {
        const server = wellBehaved()
        return Effect.gen(function*() {
          const flow = yield* OAuthFlow
          const users = yield* UserStore
          const accounts = yield* AccountStore

          const started = yield* flow.start({
            providerId: "mock",
            callbackURL: "/welcome",
            rememberMe: true
          })
          const challenge = paramsOf(started.url).get("code_challenge")

          const done = yield* flow.callback({
            providerId: "mock",
            code: "authorization-code",
            state: Redacted.value(started.state),
            ipAddress: "203.0.113.7",
            userAgent: "vitest"
          })

          assert.strictEqual(done.user.email, "ada@example.com")
          assert.isTrue(done.user.emailVerified)
          assert.isTrue(done.userCreated)
          assert.isTrue(done.accountCreated)
          assert.isFalse(done.linked)
          assert.strictEqual(done.redirectTo, "https://app.example.com/welcome")
          assert.isNotNull(done.session)
          assert.isNotNull(done.token)
          assert.strictEqual(done.session?.ipAddress, "203.0.113.7")

          // The account is keyed by the provider's subject under the synthetic
          // issuer a provider with no OIDC issuer gets.
          assert.strictEqual(done.account.issuer, oauthIssuer("mock"))
          assert.strictEqual(done.account.accountId, "provider-subject-1")
          const stored = yield* accounts.findByIssuerAccountId(oauthIssuer("mock"), "provider-subject-1")
          assert.isTrue(Option.isSome(stored))
          if (Option.isSome(stored)) {
            assert.strictEqual(stored.value.accessToken, "provider-access-token")
            assert.strictEqual(stored.value.refreshToken, "provider-refresh-token")
            assert.strictEqual(stored.value.scope, "profile email")
            assert.isNotNull(stored.value.accessTokenExpiresAt)
          }
          const user = yield* users.findByEmail("ada@example.com")
          assert.isTrue(Option.isSome(user))

          // The token request is `client_secret_post`, carries the PKCE
          // verifier whose challenge went out, and refuses redirects.
          const exchange = server.to(tokenUrl)[0]
          assert.isDefined(exchange)
          if (exchange === undefined) return
          assert.strictEqual(exchange.method, "POST")
          assert.strictEqual(exchange.redirect, "manual")
          const form = formOf(exchange)
          assert.strictEqual(form.get("grant_type"), "authorization_code")
          assert.strictEqual(form.get("code"), "authorization-code")
          assert.strictEqual(form.get("client_id"), "mock-client-id")
          assert.strictEqual(form.get("client_secret"), "mock-client-secret")
          assert.strictEqual(form.get("redirect_uri"), "https://app.example.com/auth/callback/mock")
          assert.isNotNull(form.get("code_verifier"))
          assert.notStrictEqual(form.get("code_verifier"), challenge)

          const info = server.to(userInfoUrl)[0]
          assert.isDefined(info)
          assert.strictEqual(info?.redirect, "manual")
          assert.strictEqual(info?.headers.authorization, "Bearer provider-access-token")
        }).pipe(Effect.provide(flowLayer({ providers: [mockProvider()], fetch: server.fetch })))
      },
      testTimeout
    )

    it.effect(
      "signs an existing identity in rather than provisioning a second user",
      () => {
        const server = wellBehaved()
        return Effect.gen(function*() {
          const flow = yield* OAuthFlow

          const first = yield* flow.start({ providerId: "mock" })
          const created = yield* flow.callback({
            providerId: "mock",
            code: "code-1",
            state: Redacted.value(first.state)
          })

          const second = yield* flow.start({ providerId: "mock" })
          const signedIn = yield* flow.callback({
            providerId: "mock",
            code: "code-2",
            state: Redacted.value(second.state)
          })

          assert.strictEqual(signedIn.user.id, created.user.id)
          assert.isFalse(signedIn.userCreated)
          assert.isFalse(signedIn.accountCreated)
          assert.strictEqual(signedIn.account.id, created.account.id)
          assert.notStrictEqual(
            Redacted.value(signedIn.token!),
            Redacted.value(created.token!)
          )
        }).pipe(Effect.provide(flowLayer({ providers: [mockProvider()], fetch: server.fetch })))
      },
      testTimeout
    )

    it.effect(
      "publishes SignedIn with the provider's method",
      () => {
        const server = wellBehaved()
        return Effect.gen(function*() {
          const flow = yield* OAuthFlow
          const hub = yield* AuthEvents
          const subscription = yield* hub.subscribe

          const started = yield* flow.start({ providerId: "mock" })
          yield* flow.callback({
            providerId: "mock",
            code: "authorization-code",
            state: Redacted.value(started.state)
          })

          const remaining = yield* PubSub.remaining(subscription)
          const events: ReadonlyArray<AuthEvent> = yield* PubSub.takeUpTo(subscription, remaining)
          const tags = events.map((event) => event._tag)
          assert.deepStrictEqual(tags, ["UserCreated", "AccountLinked", "SignedIn"])
          const signedIn = events.find((event) => event._tag === "SignedIn")
          assert.strictEqual(signedIn?._tag === "SignedIn" ? signedIn.method : "", "oauth:mock")
        }).pipe(Effect.provide(flowLayer({ providers: [mockProvider()], fetch: server.fetch })))
      },
      testTimeout
    )

    it.effect(
      "links to the signed-in user without minting a second session",
      () => {
        const server = wellBehaved()
        return Effect.gen(function*() {
          const flow = yield* OAuthFlow

          // Somebody signs in with the provider, which provisions the user.
          const first = yield* flow.start({ providerId: "mock" })
          const signedIn = yield* flow.callback({
            providerId: "mock",
            code: "code-1",
            state: Redacted.value(first.state)
          })

          const linking = yield* flow.start({
            providerId: "mock",
            linkUserId: signedIn.user.id,
            callbackURL: "/settings/accounts"
          })
          const linked = yield* flow.callback({
            providerId: "mock",
            code: "code-2",
            state: Redacted.value(linking.state)
          })

          assert.isTrue(linked.linked)
          assert.isNull(linked.session)
          assert.isNull(linked.token)
          assert.strictEqual(linked.user.id, signedIn.user.id)
          assert.strictEqual(linked.redirectTo, "https://app.example.com/settings/accounts")
        }).pipe(Effect.provide(flowLayer({ providers: [mockProvider()], fetch: server.fetch })))
      },
      testTimeout
    )
  })

  describe("state", () => {
    it.effect(
      "is single-use: a replayed callback is refused",
      () => {
        const server = wellBehaved()
        return Effect.gen(function*() {
          const flow = yield* OAuthFlow
          const started = yield* flow.start({ providerId: "mock" })
          yield* flow.callback({
            providerId: "mock",
            code: "code-1",
            state: Redacted.value(started.state)
          })

          const replay = yield* Effect.result(flow.callback({
            providerId: "mock",
            code: "code-1",
            state: Redacted.value(started.state)
          }))
          assert.strictEqual(replay._tag, "Failure")
          if (replay._tag === "Failure") assert.strictEqual(replay.failure._tag, "OAuthStateMismatch")

          // The replay never reached the provider.
          assert.strictEqual(server.to(tokenUrl).length, 1)
        }).pipe(Effect.provide(flowLayer({ providers: [mockProvider()], fetch: server.fetch })))
      },
      testTimeout
    )

    it.effect(
      "expires after ten minutes",
      () => {
        const server = wellBehaved()
        return Effect.gen(function*() {
          const flow = yield* OAuthFlow
          const started = yield* flow.start({ providerId: "mock" })

          yield* TestClock.adjust(Duration.minutes(10))
          const late = yield* Effect.result(flow.callback({
            providerId: "mock",
            code: "code-1",
            state: Redacted.value(started.state)
          }))
          assert.strictEqual(late._tag, "Failure")
          if (late._tag === "Failure") assert.strictEqual(late.failure._tag, "OAuthStateMismatch")
          assert.strictEqual(server.to(tokenUrl).length, 0)
        }).pipe(Effect.provide(flowLayer({ providers: [mockProvider()], fetch: server.fetch })))
      },
      testTimeout
    )

    it.effect(
      "refuses a forged state, a missing state, and one minted for another provider",
      () => {
        const server = wellBehaved()
        const other = mockProvider({ id: "other" })
        return Effect.gen(function*() {
          const flow = yield* OAuthFlow

          const forged = yield* Effect.result(flow.callback({
            providerId: "mock",
            code: "code",
            state: "a-state-nobody-minted"
          }))
          assert.strictEqual(forged._tag, "Failure")

          const missing = yield* Effect.result(flow.callback({ providerId: "mock", code: "code" }))
          assert.strictEqual(missing._tag, "Failure")
          if (missing._tag === "Failure") assert.strictEqual(missing.failure._tag, "OAuthStateMismatch")

          const started = yield* flow.start({ providerId: "mock" })
          const crossed = yield* Effect.result(flow.callback({
            providerId: "other",
            code: "code",
            state: Redacted.value(started.state)
          }))
          assert.strictEqual(crossed._tag, "Failure")
          if (crossed._tag === "Failure") assert.strictEqual(crossed.failure._tag, "OAuthStateMismatch")

          assert.strictEqual(server.to(tokenUrl).length, 0)
        }).pipe(Effect.provide(flowLayer({ providers: [mockProvider(), other], fetch: server.fetch })))
      },
      testTimeout
    )
  })

  describe("refusing redirects", () => {
    it.effect(
      "refuses to follow a redirect from the token endpoint",
      () => {
        const server = wellBehaved()
        server.on(tokenUrl, () => redirect("http://169.254.169.254/latest/meta-data/"))
        return Effect.gen(function*() {
          const flow = yield* OAuthFlow
          const started = yield* flow.start({ providerId: "mock" })
          const result = yield* Effect.result(flow.callback({
            providerId: "mock",
            code: "code",
            state: Redacted.value(started.state)
          }))

          assert.strictEqual(result._tag, "Failure")
          if (result._tag === "Failure" && result.failure._tag === "OAuthProviderError") {
            assert.strictEqual(result.failure.reason, "ProviderUnavailable")
          } else {
            assert.fail("expected an OAuthProviderError")
          }

          // One request, and the hop was never taken.
          assert.strictEqual(server.requests.length, 1)
          assert.strictEqual(server.requests[0]?.redirect, "manual")
          assert.isUndefined(
            server.requests.find((request) => request.url.startsWith("http://169.254.169.254"))
          )
        }).pipe(Effect.provide(flowLayer({ providers: [mockProvider()], fetch: server.fetch })))
      },
      testTimeout
    )

    it.effect(
      "refuses to follow a redirect from the user-info endpoint",
      () => {
        const server = wellBehaved()
        server.on(userInfoUrl, () => redirect("http://169.254.169.254/latest/meta-data/", 307))
        return Effect.gen(function*() {
          const flow = yield* OAuthFlow
          const started = yield* flow.start({ providerId: "mock" })
          const result = yield* Effect.result(flow.callback({
            providerId: "mock",
            code: "code",
            state: Redacted.value(started.state)
          }))

          assert.strictEqual(result._tag, "Failure")
          if (result._tag === "Failure" && result.failure._tag === "OAuthProviderError") {
            assert.strictEqual(result.failure.reason, "ProviderUnavailable")
          } else {
            assert.fail("expected an OAuthProviderError")
          }
          assert.strictEqual(server.requests.length, 2)
        }).pipe(Effect.provide(flowLayer({ providers: [mockProvider()], fetch: server.fetch })))
      },
      testTimeout
    )
  })

  describe("provider failures", () => {
    it.effect(
      "reports a refused consent screen as AccessDenied, and consumes the state",
      () => {
        const server = wellBehaved()
        return Effect.gen(function*() {
          const flow = yield* OAuthFlow
          const started = yield* flow.start({ providerId: "mock" })
          const refused = yield* Effect.result(flow.callback({
            providerId: "mock",
            state: Redacted.value(started.state),
            error: "access_denied"
          }))
          assert.strictEqual(refused._tag, "Failure")
          if (refused._tag === "Failure" && refused.failure._tag === "OAuthProviderError") {
            assert.strictEqual(refused.failure.reason, "AccessDenied")
          } else {
            assert.fail("expected an OAuthProviderError")
          }

          // The state was spent even though the flow failed: a refused request
          // is finished, and its state must not be redeemable afterwards.
          const replay = yield* Effect.result(flow.callback({
            providerId: "mock",
            code: "code",
            state: Redacted.value(started.state)
          }))
          assert.strictEqual(replay._tag, "Failure")
          if (replay._tag === "Failure") assert.strictEqual(replay.failure._tag, "OAuthStateMismatch")
        }).pipe(Effect.provide(flowLayer({ providers: [mockProvider()], fetch: server.fetch })))
      },
      testTimeout
    )

    it.effect(
      "reports an error body from the token endpoint as TokenExchangeFailed",
      () => {
        const server = wellBehaved()
        server.on(tokenUrl, () => json({ error: "invalid_grant", error_description: "code is spent" }))
        return Effect.gen(function*() {
          const flow = yield* OAuthFlow
          const started = yield* flow.start({ providerId: "mock" })
          const result = yield* Effect.result(flow.callback({
            providerId: "mock",
            code: "code",
            state: Redacted.value(started.state)
          }))
          assert.strictEqual(result._tag, "Failure")
          if (result._tag === "Failure" && result.failure._tag === "OAuthProviderError") {
            assert.strictEqual(result.failure.reason, "TokenExchangeFailed")
            // Nothing of the provider's own message survives into the error.
            assert.notInclude(JSON.stringify(result.failure), "invalid_grant")
          } else {
            assert.fail("expected an OAuthProviderError")
          }
        }).pipe(Effect.provide(flowLayer({ providers: [mockProvider()], fetch: server.fetch })))
      },
      testTimeout
    )

    it.effect(
      "reports a user-info endpoint with no usable identity as UserInfoFailed",
      () => {
        const server = wellBehaved()
        server.on(userInfoUrl, () => json({ name: "no subject, no address" }))
        return Effect.gen(function*() {
          const flow = yield* OAuthFlow
          const started = yield* flow.start({ providerId: "mock" })
          const result = yield* Effect.result(flow.callback({
            providerId: "mock",
            code: "code",
            state: Redacted.value(started.state)
          }))
          assert.strictEqual(result._tag, "Failure")
          if (result._tag === "Failure" && result.failure._tag === "OAuthProviderError") {
            assert.strictEqual(result.failure.reason, "UserInfoFailed")
          } else {
            assert.fail("expected an OAuthProviderError")
          }
        }).pipe(Effect.provide(flowLayer({ providers: [mockProvider()], fetch: server.fetch })))
      },
      testTimeout
    )
  })

  describe("complete", () => {
    it.effect(
      "answers a success with the validated callback URL",
      () => {
        const server = wellBehaved()
        return Effect.gen(function*() {
          const flow = yield* OAuthFlow
          const started = yield* flow.start({
            providerId: "mock",
            callbackURL: "https://console.example.com/welcome",
            errorCallbackURL: "https://console.example.com/oops"
          })
          const outcome = yield* flow.complete({
            providerId: "mock",
            code: "code",
            state: Redacted.value(started.state)
          })
          assert.strictEqual(outcome._tag, "Success")
          if (outcome._tag !== "Success") return
          assert.strictEqual(outcome.redirectTo, "https://console.example.com/welcome")
        }).pipe(Effect.provide(flowLayer({
          providers: [mockProvider()],
          fetch: server.fetch,
          trustedOrigins: ["https://console.example.com"]
        })))
      },
      testTimeout
    )

    it.effect(
      "turns a failure into a redirect to the stored error URL with a safe code",
      () => {
        const server = wellBehaved()
        server.on(tokenUrl, () => json({ error: "invalid_grant" }))
        return Effect.gen(function*() {
          const flow = yield* OAuthFlow
          const started = yield* flow.start({
            providerId: "mock",
            errorCallbackURL: "/sign-in"
          })
          const outcome = yield* flow.complete({
            providerId: "mock",
            code: "code",
            state: Redacted.value(started.state)
          })
          assert.strictEqual(outcome._tag, "Failure")
          if (outcome._tag !== "Failure") return
          assert.strictEqual(outcome.code, "token_exchange_failed")
          assert.strictEqual(
            outcome.redirectTo,
            "https://app.example.com/sign-in?error=token_exchange_failed"
          )
        }).pipe(Effect.provide(flowLayer({ providers: [mockProvider()], fetch: server.fetch })))
      },
      testTimeout
    )

    it.effect(
      "falls back to baseUrl when the state — and with it the error URL — is gone",
      () => {
        const server = wellBehaved()
        return Effect.gen(function*() {
          const flow = yield* OAuthFlow
          const outcome = yield* flow.complete({
            providerId: "mock",
            code: "code",
            state: "a-state-nobody-minted"
          })
          assert.strictEqual(outcome._tag, "Failure")
          if (outcome._tag !== "Failure") return
          assert.strictEqual(outcome.code, "state_mismatch")
          assert.strictEqual(outcome.redirectTo, "https://app.example.com/?error=state_mismatch")
        }).pipe(Effect.provide(flowLayer({ providers: [mockProvider()], fetch: server.fetch })))
      },
      testTimeout
    )

    it.effect(
      "never sends the browser to an untrusted error URL",
      () => {
        const server = wellBehaved()
        server.on(tokenUrl, () => json({ error: "invalid_grant" }))
        return Effect.gen(function*() {
          const flow = yield* OAuthFlow
          const started = yield* flow.start({
            providerId: "mock",
            errorCallbackURL: "https://evil.test/collect"
          })
          const outcome = yield* flow.complete({
            providerId: "mock",
            code: "code",
            state: Redacted.value(started.state)
          })
          assert.strictEqual(outcome._tag, "Failure")
          if (outcome._tag !== "Failure") return
          assert.isTrue(outcome.redirectTo.startsWith("https://app.example.com"))
        }).pipe(Effect.provide(flowLayer({ providers: [mockProvider()], fetch: server.fetch })))
      },
      testTimeout
    )
  })

  describe("linking onto an existing local account", () => {
    const localUser = (options: { readonly emailVerified: boolean }) =>
      Effect.gen(function*() {
        const users = yield* UserStore
        const row = yield* Effect.orDie(User.insert.makeEffect({
          name: "Ada",
          email: "ada@example.com",
          emailVerified: options.emailVerified,
          image: null
        }))
        return yield* users.create(row)
      })

    const attempt = Effect.fnUntraced(function*() {
      const flow = yield* OAuthFlow
      const started = yield* flow.start({ providerId: "mock" })
      return yield* Effect.result(flow.callback({
        providerId: "mock",
        code: "code",
        state: Redacted.value(started.state)
      }))
    })

    it.effect(
      "links implicitly when the provider is trusted and says the address is verified",
      () => {
        const server = wellBehaved()
        return Effect.gen(function*() {
          const existing = yield* localUser({ emailVerified: false })
          const result = yield* attempt()
          assert.strictEqual(result._tag, "Success")
          if (result._tag !== "Success") return
          assert.strictEqual(result.success.user.id, existing.id)
          assert.isFalse(result.success.userCreated)
          assert.isTrue(result.success.accountCreated)
        }).pipe(Effect.provide(flowLayer({
          providers: [mockProvider()],
          fetch: server.fetch,
          trustedProviders: ["mock"]
        })))
      },
      testTimeout
    )

    it.effect(
      "refuses to link an untrusted provider onto an unverified local account",
      () => {
        const server = wellBehaved()
        return Effect.gen(function*() {
          yield* localUser({ emailVerified: false })
          const result = yield* attempt()
          assert.strictEqual(result._tag, "Failure")
          if (result._tag !== "Failure") return
          assert.strictEqual(result.failure._tag, "AccountAlreadyLinked")
        }).pipe(Effect.provide(flowLayer({ providers: [mockProvider()], fetch: server.fetch })))
      },
      testTimeout
    )

    it.effect(
      "reports that refusal to the browser as a safe error code",
      () => {
        const server = wellBehaved()
        return Effect.gen(function*() {
          yield* localUser({ emailVerified: false })
          const flow = yield* OAuthFlow
          const started = yield* flow.start({ providerId: "mock", errorCallbackURL: "/sign-in" })
          const outcome = yield* flow.complete({
            providerId: "mock",
            code: "code",
            state: Redacted.value(started.state)
          })
          assert.strictEqual(outcome._tag, "Failure")
          if (outcome._tag !== "Failure") return
          assert.strictEqual(outcome.code, "account_already_linked")
          assert.strictEqual(
            outcome.redirectTo,
            "https://app.example.com/sign-in?error=account_already_linked"
          )
        }).pipe(Effect.provide(flowLayer({ providers: [mockProvider()], fetch: server.fetch })))
      },
      testTimeout
    )

    it.effect(
      "will not link a provider that does not say the address is verified, however trusted",
      () => {
        const server = wellBehaved({ email_verified: false })
        return Effect.gen(function*() {
          yield* localUser({ emailVerified: true })
          const result = yield* attempt()
          assert.strictEqual(result._tag, "Failure")
          if (result._tag !== "Failure") return
          assert.strictEqual(result.failure._tag, "AccountAlreadyLinked")
        }).pipe(Effect.provide(flowLayer({
          providers: [mockProvider()],
          fetch: server.fetch,
          trustedProviders: ["mock"]
        })))
      },
      testTimeout
    )
  })

  describe("the provider's origin", () => {
    it.effect(
      "is the only place the client secret is ever sent",
      () => {
        const server = wellBehaved()
        return Effect.gen(function*() {
          const flow = yield* OAuthFlow
          const started = yield* flow.start({ providerId: "mock" })
          yield* flow.callback({
            providerId: "mock",
            code: "code",
            state: Redacted.value(started.state)
          })
          const leaked = server.requests.filter((request) =>
            request.body.includes("mock-client-secret") &&
            !request.url.startsWith(`${providerOrigin}/token`)
          )
          assert.deepStrictEqual(leaked, [])
        }).pipe(Effect.provide(flowLayer({ providers: [mockProvider()], fetch: server.fetch })))
      },
      testTimeout
    )
  })
})
