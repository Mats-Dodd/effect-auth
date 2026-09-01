import { assert, describe, layer } from "@effect/vitest"
import { DateTime, Duration, Effect, Redacted } from "effect"
import { TestClock } from "effect/testing"
import { Account, oauthIssuer, User } from "../../src/domain/Schema.js"
import { AccountStore, UserStore } from "../../src/domain/Stores.js"
import { OAuthFlow } from "../../src/oauth/Flow.js"
import { AuthTest, MockProvider } from "../../src/testing/index.js"
import { expectSome, testName, uniqueEmail } from "../fixtures.js"

/** The origin this deployment is served from. */
const appOrigin = "https://app.example.com"

/**
 * One stubbed provider for the whole block, which is why the block is
 * sequential: a test that replaces the token route (or reads the request log) is
 * describing the server every one of its siblings shares.
 */
const server = MockProvider.mockServer()

/** How long the provider says its access tokens live. */
const tokenLifetime = 3600

/**
 * Restores the token endpoint's well-behaved answer — a rotated pair — and
 * forgets what earlier tests asked for.
 */
const wellBehaved = Effect.sync(() => {
  server.clear()
  server.on(MockProvider.tokenUrl, () =>
    MockProvider.json({
      access_token: "refreshed-access-token",
      token_type: "bearer",
      refresh_token: "rotated-refresh-token",
      expires_in: tokenLifetime
    })
  )
  return server
})

/** The provider whose tokens these tests refresh. */
const provider = MockProvider.mockProvider({
  // Microsoft's rule, and the reason `extraParams` exists: a refresh request
  // that has to repeat something. The reserved entry must not survive.
  tokenRefresh: { params: { scope: "profile email offline_access", client_id: "attacker-chosen" } }
})

/** A provider this deployment must not spend refresh tokens for. */
const frozen = MockProvider.mockProvider({ id: "frozen", tokenRefresh: { enabled: false } })

const flowLayer = AuthTest.layerFlow({
  providers: [provider, frozen],
  fetch: server.fetch,
  baseUrl: appOrigin
})

/** What {@link linked} may vary about the account it writes. */
interface AccountOptions {
  readonly providerId?: string | undefined
  readonly accessToken?: string | null | undefined
  readonly refreshToken?: string | null | undefined
  readonly expiresIn?: number | null | undefined
  readonly scope?: string | null | undefined
}

/**
 * A user with one linked account, written straight to the stores.
 *
 * **Gotchas**
 *
 * Every test in the block shares one database, so `label` must be distinct: the
 * account's `(issuer, accountId)` is derived from it.
 */
const linked = Effect.fnUntraced(function* (label: string, options?: AccountOptions) {
  const users = yield* UserStore
  const accounts = yield* AccountStore
  const email = uniqueEmail(label)
  const user = yield* users.create(
    yield* Effect.orDie(User.insert.makeEffect({ name: testName, email, emailVerified: true, image: null }))
  )
  const providerId = options?.providerId ?? "mock"
  const expiresIn = options?.expiresIn === undefined ? tokenLifetime : options.expiresIn
  const now = yield* DateTime.now
  const account = yield* accounts.create(
    yield* Effect.orDie(
      Account.insert.makeEffect({
        issuer: oauthIssuer(providerId),
        accountId: `subject-${email}`,
        providerId,
        userId: user.id,
        accessToken: options?.accessToken === undefined ? "stored-access-token" : options.accessToken,
        refreshToken: options?.refreshToken === undefined ? "stored-refresh-token" : options.refreshToken,
        idToken: null,
        accessTokenExpiresAt: expiresIn === null ? null : DateTime.addDuration(now, Duration.seconds(expiresIn)),
        refreshTokenExpiresAt: null,
        scope: options?.scope === undefined ? "profile email" : options.scope,
        passwordHash: null
      })
    )
  )
  return { account, user }
})

/** The account as it is stored now. */
const reload = Effect.fnUntraced(function* (id: Account["id"], userId: User["id"]) {
  const accounts = yield* AccountStore
  return yield* expectSome(yield* accounts.findByIdAndUserId(id, userId), "expected the account to still exist")
})

describe.sequential("oauth/Refresh", () => {
  layer(flowLayer)((it) => {
    describe("accessToken", () => {
      it.effect("hands back the stored token without spending anything when it has life left", () =>
        Effect.gen(function* () {
          yield* wellBehaved
          const flow = yield* OAuthFlow
          const { account, user } = yield* linked("fresh-token")

          const result = yield* flow.accessToken({ userId: user.id, accountId: account.id })
          assert.strictEqual(Redacted.value(result.accessToken), "stored-access-token")
          assert.deepStrictEqual(result.scopes, ["profile", "email"])
          assert.strictEqual(result.providerId, "mock")
          assert.strictEqual(result.accountId, account.id)
          assert.isNull(result.idToken)

          // The whole point of the expiry arithmetic: no round trip, no write.
          assert.strictEqual(server.to(MockProvider.tokenUrl).length, 0)
        })
      )

      it.effect("refreshes a token that is inside the skew, and sends a well-formed request", () =>
        AuthTest.freshClock(
          Effect.gen(function* () {
            yield* wellBehaved
            const flow = yield* OAuthFlow
            const { account, user } = yield* linked("near-expiry")

            // Four seconds left: inside `accessTokenSkew`, which is five.
            yield* TestClock.adjust(Duration.seconds(tokenLifetime - 4))
            const result = yield* flow.accessToken({ userId: user.id, accountId: account.id })
            assert.strictEqual(Redacted.value(result.accessToken), "refreshed-access-token")

            const request = server.to(MockProvider.tokenUrl)[0]
            assert.isDefined(request)
            if (request === undefined) return
            assert.strictEqual(request.method, "POST")
            assert.strictEqual(request.redirect, "manual")
            const form = MockProvider.formOf(request)
            assert.strictEqual(form.get("grant_type"), "refresh_token")
            assert.strictEqual(form.get("refresh_token"), "stored-refresh-token")
            assert.strictEqual(form.get("client_id"), "mock-client-id")
            assert.strictEqual(form.get("client_secret"), "mock-client-secret")
            // A configured extra rides along; one the flow owns does not.
            assert.strictEqual(form.get("scope"), "profile email offline_access")
            assert.strictEqual(form.getAll("client_id").length, 1)
            // Nothing of the authorization-code grant survives into a refresh.
            assert.isNull(form.get("code"))
            assert.isNull(form.get("code_verifier"))
            assert.isNull(form.get("redirect_uri"))
          })
        )
      )

      it.effect("treats a token the provider gave no expiry for as one that has not expired", () =>
        Effect.gen(function* () {
          yield* wellBehaved
          const flow = yield* OAuthFlow
          const { account, user } = yield* linked("no-expiry", { expiresIn: null })

          const result = yield* flow.accessToken({ userId: user.id, accountId: account.id })
          assert.strictEqual(Redacted.value(result.accessToken), "stored-access-token")
          assert.strictEqual(server.to(MockProvider.tokenUrl).length, 0)
        })
      )

      it.effect("refreshes an account that has no access token at all", () =>
        Effect.gen(function* () {
          yield* wellBehaved
          const flow = yield* OAuthFlow
          const { account, user } = yield* linked("no-access-token", { accessToken: null, expiresIn: null })

          const result = yield* flow.accessToken({ userId: user.id, accountId: account.id })
          assert.strictEqual(Redacted.value(result.accessToken), "refreshed-access-token")
        })
      )

      it.effect("answers AccessTokenMissing when there is nothing to hand over and no way to get one", () =>
        Effect.gen(function* () {
          yield* wellBehaved
          const flow = yield* OAuthFlow
          const { account, user } = yield* linked("nothing-to-hand-over", {
            accessToken: null,
            refreshToken: null,
            expiresIn: null
          })

          const failure = yield* Effect.flip(flow.accessToken({ userId: user.id, accountId: account.id }))
          assert.strictEqual(failure._tag, "TokenRefreshFailed")
          if (failure._tag !== "TokenRefreshFailed") return
          assert.strictEqual(failure.reason, "AccessTokenMissing")
          assert.strictEqual(failure.accountId, account.id)
        })
      )

      it.effect("hands an expiring token back rather than failing when it cannot be refreshed", () =>
        Effect.gen(function* () {
          yield* wellBehaved
          const flow = yield* OAuthFlow
          // Expired an hour ago, and no refresh token: the caller gets what
          // there is, and finds out from the provider that it is no good.
          const { account, user } = yield* linked("stale-but-all-there-is", {
            refreshToken: null,
            expiresIn: -tokenLifetime
          })

          const result = yield* flow.accessToken({ userId: user.id, accountId: account.id })
          assert.strictEqual(Redacted.value(result.accessToken), "stored-access-token")
          assert.strictEqual(server.to(MockProvider.tokenUrl).length, 0)
        })
      )
    })

    describe("refreshTokens", () => {
      it.effect("spends the refresh token whatever the stored expiry says, and stores what comes back", () =>
        Effect.gen(function* () {
          yield* wellBehaved
          const flow = yield* OAuthFlow
          const { account, user } = yield* linked("unconditional")

          const { events, result } = yield* AuthTest.recordingEvents(
            flow.refreshTokens({ userId: user.id, accountId: account.id })
          )
          assert.strictEqual(Redacted.value(result.accessToken), "refreshed-access-token")
          assert.strictEqual(Redacted.value(result.refreshToken), "rotated-refresh-token")
          assert.isNotNull(result.accessTokenExpiresAt)
          assert.strictEqual(server.to(MockProvider.tokenUrl).length, 1)

          assert.deepStrictEqual(AuthTest.tagsOf(events.filter((event) => event.userId === user.id)), [
            "TokensRefreshed"
          ])
          const refreshed = events.find((event) => event._tag === "TokensRefreshed")
          assert.strictEqual(refreshed?._tag === "TokensRefreshed" ? refreshed.accountId : null, account.id)
          assert.strictEqual(refreshed?._tag === "TokensRefreshed" ? refreshed.providerId : null, "mock")

          const stored = yield* reload(account.id, user.id)
          assert.strictEqual(stored.accessToken, "refreshed-access-token")
          assert.strictEqual(stored.refreshToken, "rotated-refresh-token")
        })
      )

      it.effect("keeps the stored refresh token, and the granted scope, when the response omits them", () =>
        Effect.gen(function* () {
          yield* wellBehaved
          server.on(MockProvider.tokenUrl, () =>
            MockProvider.json({
              access_token: "refreshed-without-rotation",
              token_type: "bearer",
              expires_in: tokenLifetime,
              // A provider that echoes a *narrower* scope on a refresh must not
              // be able to shrink what the person consented to.
              scope: "profile"
            })
          )
          const flow = yield* OAuthFlow
          const { account, user } = yield* linked("kept-refresh-token")

          const result = yield* flow.refreshTokens({ userId: user.id, accountId: account.id })
          assert.strictEqual(Redacted.value(result.refreshToken), "stored-refresh-token")
          assert.deepStrictEqual(result.scopes, ["profile", "email"])

          const stored = yield* reload(account.id, user.id)
          assert.strictEqual(stored.refreshToken, "stored-refresh-token")
          assert.strictEqual(stored.scope, "profile email")
        })
      )

      it.effect("refuses an account that is not the caller's, exactly as it refuses one that is not there", () =>
        Effect.gen(function* () {
          yield* wellBehaved
          const flow = yield* OAuthFlow
          const mine = yield* linked("mine")
          const theirs = yield* linked("theirs")

          const notMine = yield* Effect.flip(flow.refreshTokens({ userId: mine.user.id, accountId: theirs.account.id }))
          assert.strictEqual(notMine._tag, "NotFound")

          const nobodys = yield* Effect.flip(flow.accessToken({ userId: mine.user.id, accountId: theirs.account.id }))
          assert.strictEqual(nobodys._tag, "NotFound")

          // Neither probe reached the provider.
          assert.strictEqual(server.to(MockProvider.tokenUrl).length, 0)
        })
      )
    })

    describe("failure reasons", () => {
      it.effect("reports an account whose provider this deployment does not serve", () =>
        Effect.gen(function* () {
          yield* wellBehaved
          const flow = yield* OAuthFlow
          // Expiring, so the refresh path is the one under test: the account's
          // provider is simply not one this deployment serves any more.
          const { account, user } = yield* linked("provider-gone", { providerId: "retired", expiresIn: 1 })

          const failure = yield* Effect.flip(flow.refreshTokens({ userId: user.id, accountId: account.id }))
          assert.strictEqual(failure._tag, "TokenRefreshFailed")
          if (failure._tag !== "TokenRefreshFailed") return
          assert.strictEqual(failure.reason, "ProviderNotSupported")

          // ... and `accessToken` simply does not try, because there is nothing
          // to try with.
          const stored = yield* flow.accessToken({ userId: user.id, accountId: account.id })
          assert.strictEqual(Redacted.value(stored.accessToken), "stored-access-token")
        })
      )

      it.effect("reports a provider whose refresh tokens must not be spent", () =>
        Effect.gen(function* () {
          yield* wellBehaved
          const flow = yield* OAuthFlow
          const { account, user } = yield* linked("refresh-disabled", { providerId: "frozen" })

          const failure = yield* Effect.flip(flow.refreshTokens({ userId: user.id, accountId: account.id }))
          assert.strictEqual(failure._tag, "TokenRefreshFailed")
          if (failure._tag !== "TokenRefreshFailed") return
          assert.strictEqual(failure.reason, "RefreshNotSupported")
          assert.strictEqual(server.to(MockProvider.tokenUrl).length, 0)
        })
      )

      it.effect("reports an account that never got a refresh token", () =>
        Effect.gen(function* () {
          yield* wellBehaved
          const flow = yield* OAuthFlow
          const { account, user } = yield* linked("no-refresh-token", { refreshToken: null })

          const failure = yield* Effect.flip(flow.refreshTokens({ userId: user.id, accountId: account.id }))
          assert.strictEqual(failure._tag, "TokenRefreshFailed")
          if (failure._tag !== "TokenRefreshFailed") return
          assert.strictEqual(failure.reason, "RefreshTokenMissing")
          assert.strictEqual(server.to(MockProvider.tokenUrl).length, 0)
        })
      )

      it.effect("reports a provider that answered and refused, without echoing what it said", () =>
        Effect.gen(function* () {
          yield* wellBehaved
          server.on(MockProvider.tokenUrl, () =>
            MockProvider.json({ error: "invalid_grant", error_description: "token revoked by the user" })
          )
          const flow = yield* OAuthFlow
          const { account, user } = yield* linked("refresh-rejected")

          const failure = yield* Effect.flip(flow.refreshTokens({ userId: user.id, accountId: account.id }))
          assert.strictEqual(failure._tag, "TokenRefreshFailed")
          if (failure._tag !== "TokenRefreshFailed") return
          assert.strictEqual(failure.reason, "RefreshRejected")
          // Everything the error carries, serialized: the check is that no
          // fragment of the provider's message survives *anywhere* in it.
          assert.notInclude(JSON.stringify(failure), "invalid_grant")

          // A rejected refresh leaves the stored pair alone: the access token
          // may still be good, and the caller may want to tell them apart.
          const stored = yield* reload(account.id, user.id)
          assert.strictEqual(stored.accessToken, "stored-access-token")
          assert.strictEqual(stored.refreshToken, "stored-refresh-token")
        })
      )

      it.effect("reports a 4xx from the token endpoint as a refusal too", () =>
        Effect.gen(function* () {
          yield* wellBehaved
          server.on(MockProvider.tokenUrl, () => MockProvider.json({ error: "invalid_client" }, 401))
          const flow = yield* OAuthFlow
          const { account, user } = yield* linked("refresh-401")

          const failure = yield* Effect.flip(flow.refreshTokens({ userId: user.id, accountId: account.id }))
          assert.strictEqual(failure._tag, "TokenRefreshFailed")
          if (failure._tag !== "TokenRefreshFailed") return
          assert.strictEqual(failure.reason, "RefreshRejected")
        })
      )

      it.effect("reports a token endpoint that answers with a redirect as unavailable, and follows nothing", () =>
        Effect.gen(function* () {
          yield* wellBehaved
          server.on(MockProvider.tokenUrl, () => MockProvider.redirect("http://169.254.169.254/latest/meta-data/"))
          const flow = yield* OAuthFlow
          const { account, user } = yield* linked("refresh-redirect")

          const failure = yield* Effect.flip(flow.refreshTokens({ userId: user.id, accountId: account.id }))
          assert.strictEqual(failure._tag, "TokenRefreshFailed")
          if (failure._tag !== "TokenRefreshFailed") return
          assert.strictEqual(failure.reason, "ProviderUnavailable")

          assert.strictEqual(server.requests.length, 1)
          assert.strictEqual(server.requests[0]?.redirect, "manual")
          assert.isUndefined(server.requests.find((request) => request.url.startsWith("http://169.254.169.254")))
        })
      )
    })

    describe("the refreshed account", () => {
      it.effect("carries the id_token the refresh returned, and keeps the old one when it returns none", () =>
        Effect.gen(function* () {
          yield* wellBehaved
          const flow = yield* OAuthFlow
          const { account, user } = yield* linked("id-token")

          server.on(MockProvider.tokenUrl, () =>
            MockProvider.json({
              access_token: "with-id-token",
              token_type: "bearer",
              id_token: "a-fresh-id-token",
              expires_in: tokenLifetime
            })
          )
          const withId = yield* flow.refreshTokens({ userId: user.id, accountId: account.id })
          assert.strictEqual(withId.idToken === null ? null : Redacted.value(withId.idToken), "a-fresh-id-token")

          yield* wellBehaved
          const without = yield* flow.refreshTokens({ userId: user.id, accountId: account.id })
          assert.strictEqual(without.idToken === null ? null : Redacted.value(without.idToken), "a-fresh-id-token")

          const stored = yield* reload(account.id, user.id)
          assert.strictEqual(stored.idToken, "a-fresh-id-token")
        })
      )
    })
  })
})
