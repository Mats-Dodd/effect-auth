import { assert, describe, it, layer } from "@effect/vitest"
import { DateTime, Duration, Effect, Option, Redacted } from "effect"
import { TestClock } from "effect/testing"
import { OAuthProviderError, OAuthStateMismatch } from "../../src/domain/Errors.js"
import { oauthIssuer, User } from "../../src/domain/Schema.js"
import { AccountStore, UserStore } from "../../src/domain/Stores.js"
import { decodeTokens, errorCode, OAuthFlow } from "../../src/oauth/Flow.js"
import { withErrorCode } from "../../src/http/OriginCheck.js"
import { AuthTest, MockProvider } from "../../src/testing/index.js"
import { testName, uniqueEmail } from "../fixtures.js"

/** The origin this deployment is served from. */
const appOrigin = "https://app.example.com"

/**
 * One stubbed provider for the whole block, which is why the block is
 * sequential: a test that replaces a route (or reads the request log) is
 * describing the server every one of its siblings shares.
 */
const server = MockProvider.mockServer()

/**
 * Restores the well-behaved routes — a token for any code, and one identity —
 * and forgets what earlier tests asked for.
 *
 * **Gotchas**
 *
 * Every test that reaches the provider must give its own `identity`: the block
 * shares one database, so two tests provisioning `provider-subject-1` would
 * collide on the account's unique index rather than testing anything.
 */
const wellBehaved = (identity?: { readonly sub?: string; readonly email?: string; readonly emailVerified?: boolean }) =>
  Effect.sync(() => {
    server.clear()
    server.on(MockProvider.tokenUrl, () =>
      MockProvider.json({
        access_token: "provider-access-token",
        token_type: "bearer",
        refresh_token: "provider-refresh-token",
        expires_in: 3600,
        scope: "profile email"
      })
    )
    server.on(MockProvider.userInfoUrl, () =>
      MockProvider.json({
        sub: identity?.sub ?? "provider-subject-1",
        email: identity?.email ?? "ada@example.com",
        email_verified: identity?.emailVerified ?? true,
        name: testName,
        picture: "https://cdn.test/ada.png"
      })
    )
    return server
  })

/** An address, and the provider subject that reports it. */
const someone = (label: string) => {
  const email = uniqueEmail(label)
  return { sub: email, email }
}

const provider = MockProvider.mockProvider()

/** A second registration, for the state that must not cross between them. */
const other = MockProvider.mockProvider({ id: "other" })

/** One whose extras try to take over the parameters the flow sets itself. */
const extras = MockProvider.mockProvider({
  id: "extras",
  authorizationParams: {
    access_type: "offline",
    state: "attacker-chosen",
    code_challenge_method: "plain",
    redirect_uri: "https://evil.test/collect"
  }
})

/** A public PKCE client: there is no secret, so none is sent. */
const publicClient = MockProvider.mockProvider({ id: "public", clientSecret: undefined })

const flowLayer = AuthTest.layerFlow({
  providers: [provider, other, extras, publicClient],
  fetch: server.fetch,
  baseUrl: appOrigin,
  trustedOrigins: ["https://console.example.com"]
})

/** The same deployment, but with `mock` in `trustedProviders`. */
const trustingLayer = AuthTest.layerFlow({
  providers: [provider, other, extras],
  fetch: server.fetch,
  baseUrl: appOrigin,
  trustedProviders: ["mock"]
})

/** A local account, registered by e-mail rather than through a provider. */
const localUser = Effect.fnUntraced(function* (options: { readonly email: string; readonly emailVerified: boolean }) {
  const users = yield* UserStore
  const row = yield* Effect.orDie(
    User.insert.makeEffect({
      name: testName,
      email: options.email,
      emailVerified: options.emailVerified,
      image: null
    })
  )
  return yield* users.create(row)
})

/** Starts a flow and hands the callback the state it minted. */
const attempt = Effect.fnUntraced(function* (providerId = "mock") {
  const flow = yield* OAuthFlow
  const started = yield* flow.start({ providerId })
  return yield* Effect.result(
    flow.callback({
      providerId,
      code: "code",
      state: Redacted.value(started.state)
    })
  )
})

describe.sequential("oauth/Flow", () => {
  describe("decodeTokens", () => {
    const now = DateTime.makeUnsafe(1_000_000)

    it("reads a well-formed token response, string expiries included", () => {
      const tokens = decodeTokens(
        {
          access_token: "at",
          token_type: "bearer",
          refresh_token: "rt",
          // Some providers send these as strings, which is legal enough.
          expires_in: "3600",
          refresh_token_expires_in: 7200,
          scope: "profile email",
          id_token: "it"
        },
        now
      )
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

  layer(flowLayer)((it) => {
    describe("start", () => {
      it.effect("builds an authorization URL with PKCE S256 and a single-use state", () =>
        Effect.gen(function* () {
          const flow = yield* OAuthFlow
          const started = yield* flow.start({
            providerId: "mock",
            callbackURL: "/welcome",
            scopes: ["extra:scope"]
          })

          const params = MockProvider.paramsOf(started.url)
          assert.isTrue(started.url.startsWith(MockProvider.authorizeUrl))
          assert.strictEqual(params.get("response_type"), "code")
          assert.strictEqual(params.get("client_id"), "mock-client-id")
          assert.strictEqual(params.get("redirect_uri"), `${appOrigin}/auth/callback/mock`)
          assert.strictEqual(params.get("scope"), "profile email extra:scope")
          assert.strictEqual(params.get("state"), Redacted.value(started.state))
          assert.strictEqual(params.get("code_challenge_method"), "S256")
          assert.isNotNull(params.get("code_challenge"))
          // A plain OAuth2 provider gets no nonce: there is no id_token to echo it.
          assert.isNull(params.get("nonce"))
        })
      )

      it.effect("refuses an id nobody registered, before touching the database", () =>
        Effect.gen(function* () {
          const flow = yield* OAuthFlow
          const result = yield* Effect.result(flow.start({ providerId: "__proto__" }))
          assert.strictEqual(result._tag, "Failure")
          if (result._tag !== "Failure") return
          assert.strictEqual(result.failure._tag, "OAuthProviderError")
          if (result.failure._tag !== "OAuthProviderError") return
          assert.strictEqual(result.failure.reason, "UnknownProvider")
        })
      )

      it.effect("cannot have its own parameters overridden by a provider's extras", () =>
        Effect.gen(function* () {
          const flow = yield* OAuthFlow
          const started = yield* flow.start({ providerId: "extras" })
          const params = MockProvider.paramsOf(started.url)
          assert.strictEqual(params.get("state"), Redacted.value(started.state))
          assert.strictEqual(params.get("code_challenge_method"), "S256")
          assert.strictEqual(params.get("redirect_uri"), `${appOrigin}/auth/callback/extras`)
          assert.strictEqual(params.get("access_type"), "offline")
        })
      )

      it.effect("falls back to baseUrl for a callbackURL on an untrusted origin", () =>
        Effect.gen(function* () {
          yield* wellBehaved(someone("untrusted-callback"))
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
          assert.strictEqual(done.redirectTo, appOrigin)
        })
      )
    })

    describe("callback", () => {
      it.effect("runs the whole flow: code exchange, identity, user, account, session", () =>
        Effect.gen(function* () {
          const who = someone("whole-flow")
          yield* wellBehaved(who)
          const flow = yield* OAuthFlow
          const users = yield* UserStore
          const accounts = yield* AccountStore

          const started = yield* flow.start({
            providerId: "mock",
            callbackURL: "/welcome",
            rememberMe: true
          })
          const challenge = MockProvider.paramsOf(started.url).get("code_challenge")

          const done = yield* flow.callback({
            providerId: "mock",
            code: "authorization-code",
            state: Redacted.value(started.state),
            ipAddress: "203.0.113.7",
            userAgent: "vitest"
          })

          assert.strictEqual(done.user.email, who.email)
          assert.isTrue(done.user.emailVerified)
          assert.isTrue(done.userCreated)
          assert.isTrue(done.accountCreated)
          assert.isFalse(done.linked)
          assert.strictEqual(done.redirectTo, `${appOrigin}/welcome`)
          assert.isNotNull(done.session)
          assert.isNotNull(done.token)
          assert.strictEqual(done.session?.ipAddress, "203.0.113.7")

          // The account is keyed by the provider's subject under the synthetic
          // issuer a provider with no OIDC issuer gets.
          assert.strictEqual(done.account.issuer, oauthIssuer("mock"))
          assert.strictEqual(done.account.accountId, who.sub)
          const stored = yield* accounts.findByIssuerAccountId(oauthIssuer("mock"), who.sub)
          assert.isTrue(Option.isSome(stored))
          if (Option.isSome(stored)) {
            assert.strictEqual(stored.value.accessToken, "provider-access-token")
            assert.strictEqual(stored.value.refreshToken, "provider-refresh-token")
            assert.strictEqual(stored.value.scope, "profile email")
            assert.isNotNull(stored.value.accessTokenExpiresAt)
          }
          const user = yield* users.findByEmail(who.email)
          assert.isTrue(Option.isSome(user))

          // The token request is `client_secret_post`, carries the PKCE
          // verifier whose challenge went out, and refuses redirects.
          const exchange = server.to(MockProvider.tokenUrl)[0]
          assert.isDefined(exchange)
          if (exchange === undefined) return
          assert.strictEqual(exchange.method, "POST")
          assert.strictEqual(exchange.redirect, "manual")
          const form = MockProvider.formOf(exchange)
          assert.strictEqual(form.get("grant_type"), "authorization_code")
          assert.strictEqual(form.get("code"), "authorization-code")
          assert.strictEqual(form.get("client_id"), "mock-client-id")
          assert.strictEqual(form.get("client_secret"), "mock-client-secret")
          assert.strictEqual(form.get("redirect_uri"), `${appOrigin}/auth/callback/mock`)
          assert.isNotNull(form.get("code_verifier"))
          assert.notStrictEqual(form.get("code_verifier"), challenge)

          const info = server.to(MockProvider.userInfoUrl)[0]
          assert.isDefined(info)
          assert.strictEqual(info?.redirect, "manual")
          assert.strictEqual(info?.headers.authorization, "Bearer provider-access-token")
        })
      )

      it.effect("signs an existing identity in rather than provisioning a second user", () =>
        Effect.gen(function* () {
          yield* wellBehaved(someone("returning"))
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
          assert.notStrictEqual(Redacted.value(signedIn.token!), Redacted.value(created.token!))
        })
      )

      it.effect("publishes SignedIn with the provider's method", () =>
        Effect.gen(function* () {
          yield* wellBehaved(someone("events"))
          const flow = yield* OAuthFlow

          // The hub belongs to the deployment, which this block shares: the
          // recording is only this test's because the block is sequential.
          const { events } = yield* AuthTest.recordingEvents(
            Effect.gen(function* () {
              const started = yield* flow.start({ providerId: "mock" })
              yield* flow.callback({
                providerId: "mock",
                code: "authorization-code",
                state: Redacted.value(started.state)
              })
            })
          )

          assert.deepStrictEqual(AuthTest.tagsOf(events), ["UserCreated", "AccountLinked", "SignedIn"])
          const signedIn = events.find((event) => event._tag === "SignedIn")
          assert.strictEqual(signedIn?._tag === "SignedIn" ? signedIn.method : "", "oauth:mock")
        })
      )

      it.effect("links to the signed-in user without minting a second session", () =>
        Effect.gen(function* () {
          yield* wellBehaved(someone("linking"))
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
          assert.strictEqual(linked.redirectTo, `${appOrigin}/settings/accounts`)
        })
      )
    })

    describe("state", () => {
      it.effect("is single-use: a replayed callback is refused", () =>
        Effect.gen(function* () {
          yield* wellBehaved(someone("replay"))
          const flow = yield* OAuthFlow
          const started = yield* flow.start({ providerId: "mock" })
          yield* flow.callback({
            providerId: "mock",
            code: "code-1",
            state: Redacted.value(started.state)
          })

          const replay = yield* Effect.result(
            flow.callback({
              providerId: "mock",
              code: "code-1",
              state: Redacted.value(started.state)
            })
          )
          assert.strictEqual(replay._tag, "Failure")
          if (replay._tag === "Failure") assert.strictEqual(replay.failure._tag, "OAuthStateMismatch")

          // The replay never reached the provider.
          assert.strictEqual(server.to(MockProvider.tokenUrl).length, 1)
        })
      )

      it.effect("expires after ten minutes", () =>
        // The block's own clock, not an `AuthTest.freshClock`: `Flow.make`
        // captures the context the state is issued and consumed under when the
        // layer is built (`Flow.ts`, `stateServices`), so an inner clock would
        // move the callback's time and not the state's. Safe because the block
        // is sequential and every expiry in it is relative to now.
        Effect.gen(function* () {
          yield* wellBehaved(someone("expiry"))
          const flow = yield* OAuthFlow
          const started = yield* flow.start({ providerId: "mock" })

          yield* TestClock.adjust(Duration.minutes(10))
          const late = yield* Effect.result(
            flow.callback({
              providerId: "mock",
              code: "code-1",
              state: Redacted.value(started.state)
            })
          )
          assert.strictEqual(late._tag, "Failure")
          if (late._tag === "Failure") assert.strictEqual(late.failure._tag, "OAuthStateMismatch")
          assert.strictEqual(server.to(MockProvider.tokenUrl).length, 0)
        })
      )

      it.effect("refuses a forged state, a missing state, and one minted for another provider", () =>
        Effect.gen(function* () {
          yield* wellBehaved(someone("mismatch"))
          const flow = yield* OAuthFlow

          const forged = yield* Effect.result(
            flow.callback({
              providerId: "mock",
              code: "code",
              state: "a-state-nobody-minted"
            })
          )
          assert.strictEqual(forged._tag, "Failure")

          const missing = yield* Effect.result(flow.callback({ providerId: "mock", code: "code" }))
          assert.strictEqual(missing._tag, "Failure")
          if (missing._tag === "Failure") assert.strictEqual(missing.failure._tag, "OAuthStateMismatch")

          const started = yield* flow.start({ providerId: "mock" })
          const crossed = yield* Effect.result(
            flow.callback({
              providerId: "other",
              code: "code",
              state: Redacted.value(started.state)
            })
          )
          assert.strictEqual(crossed._tag, "Failure")
          if (crossed._tag === "Failure") assert.strictEqual(crossed.failure._tag, "OAuthStateMismatch")

          assert.strictEqual(server.to(MockProvider.tokenUrl).length, 0)
        })
      )
    })

    describe("refusing redirects", () => {
      it.effect("refuses to follow a redirect from the token endpoint", () =>
        Effect.gen(function* () {
          yield* wellBehaved(someone("token-redirect"))
          server.on(MockProvider.tokenUrl, () => MockProvider.redirect("http://169.254.169.254/latest/meta-data/"))

          const result = yield* attempt()
          assert.strictEqual(result._tag, "Failure")
          if (result._tag === "Failure" && result.failure._tag === "OAuthProviderError") {
            assert.strictEqual(result.failure.reason, "ProviderUnavailable")
          } else {
            assert.fail("expected an OAuthProviderError")
          }

          // One request, and the hop was never taken.
          assert.strictEqual(server.requests.length, 1)
          assert.strictEqual(server.requests[0]?.redirect, "manual")
          assert.isUndefined(server.requests.find((request) => request.url.startsWith("http://169.254.169.254")))
        })
      )

      it.effect("refuses to follow a redirect from the user-info endpoint", () =>
        Effect.gen(function* () {
          yield* wellBehaved(someone("userinfo-redirect"))
          server.on(MockProvider.userInfoUrl, () =>
            MockProvider.redirect("http://169.254.169.254/latest/meta-data/", 307)
          )

          const result = yield* attempt()
          assert.strictEqual(result._tag, "Failure")
          if (result._tag === "Failure" && result.failure._tag === "OAuthProviderError") {
            assert.strictEqual(result.failure.reason, "ProviderUnavailable")
          } else {
            assert.fail("expected an OAuthProviderError")
          }
          assert.strictEqual(server.requests.length, 2)
        })
      )
    })

    describe("provider failures", () => {
      it.effect("reports a refused consent screen as AccessDenied, and consumes the state", () =>
        Effect.gen(function* () {
          yield* wellBehaved(someone("access-denied"))
          const flow = yield* OAuthFlow
          const started = yield* flow.start({ providerId: "mock" })
          const refused = yield* Effect.result(
            flow.callback({
              providerId: "mock",
              state: Redacted.value(started.state),
              error: "access_denied"
            })
          )
          assert.strictEqual(refused._tag, "Failure")
          if (refused._tag === "Failure" && refused.failure._tag === "OAuthProviderError") {
            assert.strictEqual(refused.failure.reason, "AccessDenied")
          } else {
            assert.fail("expected an OAuthProviderError")
          }

          // The state was spent even though the flow failed: a refused request
          // is finished, and its state must not be redeemable afterwards.
          const replay = yield* Effect.result(
            flow.callback({
              providerId: "mock",
              code: "code",
              state: Redacted.value(started.state)
            })
          )
          assert.strictEqual(replay._tag, "Failure")
          if (replay._tag === "Failure") assert.strictEqual(replay.failure._tag, "OAuthStateMismatch")
        })
      )

      it.effect("reports an error body from the token endpoint as TokenExchangeFailed", () =>
        Effect.gen(function* () {
          yield* wellBehaved(someone("token-error"))
          server.on(MockProvider.tokenUrl, () =>
            MockProvider.json({ error: "invalid_grant", error_description: "code is spent" })
          )

          const result = yield* attempt()
          assert.strictEqual(result._tag, "Failure")
          if (result._tag === "Failure" && result.failure._tag === "OAuthProviderError") {
            assert.strictEqual(result.failure.reason, "TokenExchangeFailed")
            // Nothing of the provider's own message survives into the error.
            assert.notInclude(JSON.stringify(result.failure), "invalid_grant")
          } else {
            assert.fail("expected an OAuthProviderError")
          }
        })
      )

      it.effect("reports a user-info endpoint with no usable identity as UserInfoFailed", () =>
        Effect.gen(function* () {
          yield* wellBehaved(someone("no-identity"))
          server.on(MockProvider.userInfoUrl, () => MockProvider.json({ name: "no subject, no address" }))

          const result = yield* attempt()
          assert.strictEqual(result._tag, "Failure")
          if (result._tag === "Failure" && result.failure._tag === "OAuthProviderError") {
            assert.strictEqual(result.failure.reason, "UserInfoFailed")
          } else {
            assert.fail("expected an OAuthProviderError")
          }
        })
      )
    })

    describe("complete", () => {
      it.effect("answers a success with the validated callback URL", () =>
        Effect.gen(function* () {
          yield* wellBehaved(someone("complete"))
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
        })
      )

      it.effect("turns a failure into a redirect to the stored error URL with a safe code", () =>
        Effect.gen(function* () {
          yield* wellBehaved(someone("complete-failure"))
          server.on(MockProvider.tokenUrl, () => MockProvider.json({ error: "invalid_grant" }))
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
          assert.strictEqual(outcome.redirectTo, `${appOrigin}/sign-in?error=token_exchange_failed`)
        })
      )

      it.effect("falls back to baseUrl when the state — and with it the error URL — is gone", () =>
        Effect.gen(function* () {
          yield* wellBehaved(someone("complete-no-state"))
          const flow = yield* OAuthFlow
          const outcome = yield* flow.complete({
            providerId: "mock",
            code: "code",
            state: "a-state-nobody-minted"
          })
          assert.strictEqual(outcome._tag, "Failure")
          if (outcome._tag !== "Failure") return
          assert.strictEqual(outcome.code, "state_mismatch")
          assert.strictEqual(outcome.redirectTo, `${appOrigin}/?error=state_mismatch`)
        })
      )

      it.effect("never sends the browser to an untrusted error URL", () =>
        Effect.gen(function* () {
          yield* wellBehaved(someone("untrusted-error-url"))
          server.on(MockProvider.tokenUrl, () => MockProvider.json({ error: "invalid_grant" }))
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
          assert.isTrue(outcome.redirectTo.startsWith(appOrigin))
        })
      )
    })

    describe("linking onto an existing local account", () => {
      it.effect("refuses to link an untrusted provider onto an unverified local account", () =>
        Effect.gen(function* () {
          const who = someone("untrusted-link")
          yield* wellBehaved(who)
          yield* localUser({ email: who.email, emailVerified: false })

          const result = yield* attempt()
          assert.strictEqual(result._tag, "Failure")
          if (result._tag !== "Failure") return
          assert.strictEqual(result.failure._tag, "AccountAlreadyLinked")
        })
      )

      it.effect("reports that refusal to the browser as a safe error code", () =>
        Effect.gen(function* () {
          const who = someone("refusal-code")
          yield* wellBehaved(who)
          yield* localUser({ email: who.email, emailVerified: false })

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
          assert.strictEqual(outcome.redirectTo, `${appOrigin}/sign-in?error=account_already_linked`)
        })
      )

      // A configuration variant: everything above the database is rebuilt with
      // `mock` trusted, and the database itself is the block's.
      it.layer(trustingLayer)("with the provider trusted", (it) => {
        it.effect("links implicitly when the provider says the address is verified", () =>
          Effect.gen(function* () {
            const who = someone("trusted-link")
            yield* wellBehaved(who)
            const existing = yield* localUser({ email: who.email, emailVerified: false })

            const result = yield* attempt()
            assert.strictEqual(result._tag, "Success")
            if (result._tag !== "Success") return
            assert.strictEqual(result.success.user.id, existing.id)
            assert.isFalse(result.success.userCreated)
            assert.isTrue(result.success.accountCreated)
          })
        )

        it.effect("will not link a provider that does not say the address is verified", () =>
          Effect.gen(function* () {
            const who = someone("trusted-unverified")
            yield* wellBehaved({ ...who, emailVerified: false })
            yield* localUser({ email: who.email, emailVerified: true })

            const result = yield* attempt()
            assert.strictEqual(result._tag, "Failure")
            if (result._tag !== "Failure") return
            assert.strictEqual(result.failure._tag, "AccountAlreadyLinked")
          })
        )
      })
    })

    describe("the provider's origin", () => {
      it.effect("is the only place the client secret is ever sent", () =>
        Effect.gen(function* () {
          yield* wellBehaved(someone("secret"))
          const flow = yield* OAuthFlow
          const started = yield* flow.start({ providerId: "mock" })
          yield* flow.callback({
            providerId: "mock",
            code: "code",
            state: Redacted.value(started.state)
          })
          const leaked = server.requests.filter(
            (request) => request.body.includes("mock-client-secret") && !request.url.startsWith(MockProvider.tokenUrl)
          )
          assert.deepStrictEqual(leaked, [])
        })
      )

      it.effect("gets no client_secret at all from a public client, which has none", () =>
        Effect.gen(function* () {
          yield* wellBehaved(someone("public-client"))
          const flow = yield* OAuthFlow
          const started = yield* flow.start({ providerId: "public" })
          yield* flow.callback({
            providerId: "public",
            code: "code",
            state: Redacted.value(started.state)
          })

          const exchange = server.to(MockProvider.tokenUrl)[0]
          assert.isDefined(exchange)
          if (exchange === undefined) return
          const form = MockProvider.formOf(exchange)
          assert.strictEqual(form.get("grant_type"), "authorization_code")
          assert.strictEqual(form.get("client_id"), "mock-client-id")
          assert.isNotNull(form.get("code_verifier"))
          // Not an empty one: the parameter is absent, which is what a provider
          // distinguishes a public client by.
          assert.isNull(form.get("client_secret"))
        })
      )
    })
  })
})
