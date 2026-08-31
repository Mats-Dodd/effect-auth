import { assert, describe, layer } from "@effect/vitest"
import { Effect, Fiber, Latch, Option, Redacted } from "effect"
import { TestClock } from "effect/testing"
import { Token } from "../../src/crypto/Token.js"
import { oauthIssuer } from "../../src/domain/Schema.js"
import { AccountStore } from "../../src/domain/Stores.js"
import { OAuthFlow } from "../../src/oauth/Flow.js"
import type { OAuthTokens } from "../../src/oauth/Provider.js"
import { exchangeDeadline, userInfoDeadline } from "../../src/oauth/Provider.js"
import { AuthTest, MockProvider } from "../../src/testing/index.js"
import { testName, uniqueEmail } from "../fixtures.js"

/** The origin this deployment is served from. */
const appOrigin = "https://app.example.com"

/**
 * One stubbed provider for the whole block, which is why the block is
 * sequential: every test here reads the request log to say whether the code was
 * posted at all, and that log is shared.
 */
const server = MockProvider.mockServer()

/**
 * The well-behaved routes, and a fresh request log.
 *
 * **Gotchas**
 *
 * Every test that reaches user-info must give its own `sub`: the block shares
 * one database, so two tests provisioning one subject would collide on the
 * account's unique index rather than testing anything.
 */
const wellBehaved = (identity: { readonly sub: string; readonly email: string }) =>
  Effect.sync(() => {
    server.clear()
    server.on(MockProvider.tokenUrl, () =>
      MockProvider.json({
        access_token: "provider-access-token",
        token_type: "bearer",
        refresh_token: "provider-refresh-token",
        expires_in: 3600,
        scope: "profile email"
      }))
    server.on(MockProvider.userInfoUrl, () =>
      MockProvider.json({
        sub: identity.sub,
        email: identity.email,
        email_verified: true,
        name: testName,
        picture: "https://cdn.test/ada.png"
      }))
    return server
  })

/** An address, and the provider subject that reports it. */
const someone = (label: string) => {
  const email = uniqueEmail(label)
  return { sub: email, email }
}

/** The ordinary provider: no override, so the generic runner owns the exchange. */
const generic = MockProvider.mockProvider()

/**
 * What the `owning` override was handed, kept so the assertion can read it after
 * the flow has finished.
 *
 * The keys are recorded too: the seam is the assertion. An override sees the
 * code, the verifier, the redirect URI and a `fallback` — and never the client
 * secret, which stays inside the flow's own token request.
 */
let handed: {
  readonly code: string
  readonly codeVerifier: string
  readonly redirectUri: string
  readonly keys: ReadonlyArray<string>
  readonly calls: number
} | null = null

/** The tokens the owning override mints instead of posting the code anywhere. */
const mintedByOverride: OAuthTokens = MockProvider.tokensOf("override-minted-access-token", {
  scope: "profile email"
})

/**
 * A provider whose exchange is genuinely not an OAuth2 token request: it ignores
 * `fallback` entirely and produces the tokens itself.
 */
const owning = MockProvider.mockProvider({
  id: "owning",
  exchange: (options) =>
    Effect.sync(() => {
      handed = {
        code: options.code,
        codeVerifier: options.codeVerifier,
        redirectUri: options.redirectUri,
        keys: Object.keys(options).sort(),
        calls: (handed?.calls ?? 0) + 1
      }
      return mintedByOverride
    })
})

/**
 * The override the escape hatch is actually shaped for: it runs the request the
 * flow built and post-processes what comes back, so secret resolution and
 * reserved-parameter filtering still happen — on the flow's side of the seam,
 * where the override cannot see or disturb them.
 */
const decorating = MockProvider.mockProvider({
  id: "decorating",
  exchange: ({ fallback }) =>
    Effect.map(fallback, (tokens): OAuthTokens => ({
      ...tokens,
      scope: tokens.scope === null ? "decorated" : `${tokens.scope} decorated`
    }))
})

/** Opened the moment the hanging provider's `userInfo` is entered. */
const reachedUserInfo = Latch.makeUnsafe()

/** A provider whose `userInfo` never answers, and never uses `fetchJson` either. */
const hanging = MockProvider.mockProvider({
  id: "hanging",
  userInfo: () => Effect.andThen(reachedUserInfo.open, Effect.never)
})

/** Opened the moment the stalling provider's override is entered. */
const reachedExchange = Latch.makeUnsafe()

/**
 * The other half of "the override owns everything": one that ignores `fallback`,
 * so nothing the flow built — and nothing `resilient` bounds — is running inside
 * it, and then never answers.
 */
const stalling = MockProvider.mockProvider({
  id: "stalling",
  exchange: () => Effect.andThen(reachedExchange.open, Effect.never)
})

const flowLayer = AuthTest.layerFlow({
  providers: [generic, owning, decorating, hanging, stalling],
  fetch: server.fetch,
  baseUrl: appOrigin
})

describe.sequential("oauth/Flow (exchange and deadlines)", () => {
  layer(flowLayer)((it) => {
    describe("the exchange override", () => {
      it.effect("hands an owning override the code, the verifier and the redirect URI, and posts nothing", () =>
        Effect.gen(function*() {
          const who = someone("exchange-owning")
          yield* wellBehaved(who)
          const flow = yield* OAuthFlow
          const tokens = yield* Token
          const accounts = yield* AccountStore

          const started = yield* flow.start({ providerId: "owning" })
          const challenge = MockProvider.paramsOf(started.url).get("code_challenge")
          const done = yield* flow.callback({
            providerId: "owning",
            code: "authorization-code",
            state: Redacted.value(started.state)
          })

          assert.isNotNull(handed)
          if (handed === null) return
          assert.strictEqual(handed.calls, 1)
          assert.strictEqual(handed.code, "authorization-code")
          // The redirect URI is the one the flow would have sent itself, so an
          // override that decorates the default does not have to re-derive it.
          assert.strictEqual(handed.redirectUri, `${appOrigin}/auth/callback/owning`)
          // Not merely "a string": it is the verifier whose challenge went out
          // in the redirect, which is the only one the provider will accept.
          assert.strictEqual(yield* tokens.hashToken(Redacted.make(handed.codeVerifier)), challenge)
          // The seam, stated as a list: no client secret crosses it.
          assert.deepStrictEqual([...handed.keys], ["code", "codeVerifier", "fallback", "redirectUri"])

          // "Present means this function owns it: nothing else posts the code."
          assert.deepStrictEqual([...server.to(MockProvider.tokenUrl)], [])

          // And what it produced is what the rest of the flow runs on: the
          // user-info request carries the override's access token, and so does
          // the stored account.
          const info = server.to(MockProvider.userInfoUrl)[0]
          assert.isDefined(info)
          assert.strictEqual(info?.headers.authorization, "Bearer override-minted-access-token")
          assert.strictEqual(done.user.email, who.email)
          const stored = yield* accounts.findByIssuerAccountId(oauthIssuer("owning"), who.sub)
          assert.isTrue(Option.isSome(stored))
          if (Option.isSome(stored)) {
            assert.strictEqual(stored.value.accessToken, "override-minted-access-token")
          }
        }))

      it.effect("lets a decorating override run the flow's own request and post-process it", () =>
        Effect.gen(function*() {
          const who = someone("exchange-decorating")
          yield* wellBehaved(who)
          const flow = yield* OAuthFlow
          const accounts = yield* AccountStore

          const started = yield* flow.start({ providerId: "decorating" })
          yield* flow.callback({
            providerId: "decorating",
            code: "authorization-code",
            state: Redacted.value(started.state)
          })

          // `fallback` really is the flow's request: it was posted once, as
          // `client_secret_post`, with the PKCE verifier and the redirect URI —
          // none of which the override had to assemble, or could have got wrong.
          const posted = server.to(MockProvider.tokenUrl)
          assert.strictEqual(posted.length, 1)
          const form = MockProvider.formOf(posted[0]!)
          assert.strictEqual(form.get("grant_type"), "authorization_code")
          assert.strictEqual(form.get("code"), "authorization-code")
          assert.strictEqual(form.get("client_secret"), "mock-client-secret")
          assert.strictEqual(form.get("redirect_uri"), `${appOrigin}/auth/callback/decorating`)
          assert.isNotNull(form.get("code_verifier"))

          // And the post-processing survived into the account row: what the
          // override returned is what the flow stored, not what the provider
          // sent.
          const stored = yield* accounts.findByIssuerAccountId(oauthIssuer("decorating"), who.sub)
          assert.isTrue(Option.isSome(stored))
          if (Option.isSome(stored)) {
            assert.strictEqual(stored.value.scope, "profile email decorated")
            assert.strictEqual(stored.value.accessToken, "provider-access-token")
          }
        }))

      it.effect("leaves the generic path alone for a provider that declares no override", () =>
        Effect.gen(function*() {
          const who = someone("exchange-generic")
          yield* wellBehaved(who)
          const flow = yield* OAuthFlow
          const accounts = yield* AccountStore

          assert.isUndefined(generic.exchange)

          const started = yield* flow.start({ providerId: "mock" })
          const done = yield* flow.callback({
            providerId: "mock",
            code: "authorization-code",
            state: Redacted.value(started.state)
          })

          // Byte for byte the request the flow has always sent: the escape hatch
          // costs the ordinary provider nothing.
          const posted = server.to(MockProvider.tokenUrl)
          assert.strictEqual(posted.length, 1)
          assert.strictEqual(posted[0]?.method, "POST")
          assert.strictEqual(posted[0]?.redirect, "manual")
          const form = MockProvider.formOf(posted[0]!)
          assert.strictEqual(form.get("grant_type"), "authorization_code")
          assert.strictEqual(form.get("code"), "authorization-code")
          assert.strictEqual(form.get("client_id"), "mock-client-id")
          assert.strictEqual(form.get("client_secret"), "mock-client-secret")
          assert.strictEqual(form.get("redirect_uri"), `${appOrigin}/auth/callback/mock`)
          assert.isNotNull(form.get("code_verifier"))

          assert.strictEqual(done.user.email, who.email)
          const stored = yield* accounts.findByIssuerAccountId(oauthIssuer("mock"), who.sub)
          assert.isTrue(Option.isSome(stored))
          if (Option.isSome(stored)) {
            assert.strictEqual(stored.value.accessToken, "provider-access-token")
            assert.strictEqual(stored.value.scope, "profile email")
          }
        }))
    })

    describe("the exchange deadline", () => {
      it.effect("bounds an override that owns the exchange and never answers", () =>
        Effect.gen(function*() {
          yield* wellBehaved(someone("exchange-stalling"))
          const flow = yield* OAuthFlow

          const started = yield* flow.start({ providerId: "stalling" })
          const fiber = yield* Effect.forkChild(Effect.result(flow.callback({
            providerId: "stalling",
            code: "authorization-code",
            state: Redacted.value(started.state)
          })))

          // Inside the override before the clock moves: the deadline only runs
          // once the effect it bounds has started.
          yield* reachedExchange.await
          yield* TestClock.adjust(exchangeDeadline)

          const result = yield* Fiber.join(fiber)
          assert.strictEqual(result._tag, "Failure")
          if (result._tag !== "Failure") return
          assert.strictEqual(result.failure._tag, "OAuthProviderError")
          if (result.failure._tag !== "OAuthProviderError") return
          // Same closed set as every other exchange that could not be made.
          assert.strictEqual(result.failure.reason, "ProviderUnavailable")
          assert.strictEqual(result.failure.providerId, "stalling")

          // The override never touched `fallback`, so the bound cannot have come
          // from `resilient`: nothing was posted at all, and the flow still let
          // go of the callback fiber.
          assert.deepStrictEqual([...server.to(MockProvider.tokenUrl)], [])
        }))
    })

    describe("the userInfo deadline", () => {
      it.effect("gives a provider's whole userInfo one deadline, however it spends it", () =>
        Effect.gen(function*() {
          yield* wellBehaved(someone("exchange-hanging"))
          const flow = yield* OAuthFlow

          const started = yield* flow.start({ providerId: "hanging" })
          const fiber = yield* Effect.forkChild(Effect.result(flow.callback({
            providerId: "hanging",
            code: "authorization-code",
            state: Redacted.value(started.state)
          })))

          // Wait for the exchange to finish and the provider to be inside
          // `userInfo` before moving the clock: the deadline is only running
          // once the effect it bounds has started.
          yield* reachedUserInfo.await
          yield* TestClock.adjust(userInfoDeadline)

          const result = yield* Fiber.join(fiber)
          assert.strictEqual(result._tag, "Failure")
          if (result._tag !== "Failure") return
          assert.strictEqual(result.failure._tag, "OAuthProviderError")
          if (result.failure._tag !== "OAuthProviderError") return
          // The mapped reason is one the closed set already had: a provider that
          // will not answer in time is one that is unavailable, and no new
          // reason leaks out of the flow to the browser.
          assert.strictEqual(result.failure.reason, "ProviderUnavailable")
          assert.strictEqual(result.failure.providerId, "hanging")

          // This provider never touched `fetchJson`, so the bound cannot have
          // come from the helper's per-request timeout. It is the flow's, which
          // is the point of putting it there: an implementation cannot opt out.
          assert.deepStrictEqual([...server.to(MockProvider.userInfoUrl)], [])
        }))
    })
  })
})
