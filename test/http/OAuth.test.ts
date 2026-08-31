import { assert, describe, layer } from "@effect/vitest"
import { Context, DateTime, Effect, Layer, Option, Redacted, Ref } from "effect"
import { OAuthStateMismatch } from "../../src/domain/Errors.js"
import { Sessions } from "../../src/domain/Sessions.js"
import { AccountStore, UserStore } from "../../src/domain/Stores.js"
import * as AuthHandlers from "../../src/http/Handlers.js"
import type { CallbackOutcome, StartOptions } from "../../src/oauth/Flow.js"
import { OAuthFlow } from "../../src/oauth/Flow.js"
import { AuthTest, TestHttpClient } from "../../src/testing/index.js"
import { uniqueEmail } from "../fixtures.js"

/**
 * Drives the OAuth endpoints without a provider.
 *
 * **Details**
 *
 * `OAuthFlow` is the seam the handlers talk to, and everything behind it — the
 * state, PKCE, the token exchange, `id_token` verification, the linking rules —
 * has its own suite in `test/oauth`. What is left to check here is exactly what
 * this stub makes visible: which options the handlers pass in, and what they do
 * with an outcome.
 *
 * **Gotchas**
 *
 * The staged outcome and the recorded starts are one deployment's, and the
 * block shares one deployment: `reset` at the top of a test is what makes
 * `starts` mean "this test's", and is why the block is sequential.
 */
class StubFlow extends Context.Service<StubFlow, {
  /** The next outcome `GET /callback/:providerId` will resolve to. */
  readonly setOutcome: (outcome: CallbackOutcome) => Effect.Effect<void>
  /** Every `start` the handlers made since the last `reset`. */
  readonly starts: Effect.Effect<ReadonlyArray<StartOptions>>
  /** Forgets the recorded starts and the staged outcome. */
  readonly reset: Effect.Effect<void>
}>()("test/http/StubFlow") {}

const stubLayer = Layer.effectContext(Effect.gen(function*() {
  const started = yield* Ref.make<ReadonlyArray<StartOptions>>([])
  const outcome = yield* Ref.make<Option.Option<CallbackOutcome>>(Option.none())

  return Context.make(StubFlow, {
    setOutcome: (next: CallbackOutcome) => Ref.set(outcome, Option.some(next)),
    starts: Ref.get(started),
    reset: Effect.andThen(Ref.set(started, []), Ref.set(outcome, Option.none()))
  }).pipe(
    Context.add(OAuthFlow, {
      start: (options) =>
        Effect.as(
          Ref.update(started, (all) => [...all, options]),
          {
            providerId: options.providerId,
            url: `https://provider.test/authorize?client_id=x&state=nonce&provider=${options.providerId}`,
            state: Redacted.make("nonce"),
            expiresAt: DateTime.makeUnsafe(0)
          }
        ),
      callback: () => Effect.die("the handlers must call `complete`, not `callback`"),
      accessToken: () => Effect.die("the stub flow holds no provider tokens"),
      refreshTokens: () => Effect.die("the stub flow holds no provider tokens"),
      complete: () =>
        Effect.flatMap(
          Ref.get(outcome),
          Option.match({
            onNone: () => Effect.die("no outcome was staged"),
            onSome: Effect.succeed
          })
        )
    })
  )
}))

/** The whole server stack, with the stub standing in for the flow. */
const stubbed = Layer.mergeAll(
  AuthHandlers.layer(AuthTest.TestApi).pipe(
    Layer.provideMerge(stubLayer.pipe(Layer.provideMerge(AuthTest.layer())))
  ),
  AuthTest.layerPlatform
)

/** A real session for a signed-up user, minted outside any HTTP request. */
const mintSession = Effect.fnUntraced(function*(email: string) {
  const users = yield* UserStore
  const accounts = yield* AccountStore
  const sessions = yield* Sessions
  const user = Option.getOrThrow(yield* users.findByEmail(email))
  const account = (yield* accounts.listByUserId(user.id))[0]!
  const created = yield* sessions.create({ userId: user.id })
  return { user, account, session: created.session, token: created.token }
})

/** Signs a new account up, and mints a session for it outside the browser. */
const withSession = Effect.fnUntraced(function*(label: string) {
  const browser = yield* TestHttpClient.signedUp({ email: uniqueEmail(label) })
  return yield* mintSession(browser.email)
})

describe.sequential("http/Handlers OAuth", () => {
  layer(stubbed)((it) => {
    it.effect("answers the authorization URL to navigate to", () =>
      Effect.gen(function*() {
        const stub = yield* StubFlow
        yield* stub.reset
        const { client } = yield* TestHttpClient.makeClient(AuthTest.TestApi)
        const started = yield* client.auth.signInSocial({
          payload: {
            providerId: "github",
            callbackURL: "/welcome",
            errorCallbackURL: "/oops",
            scopes: ["repo"],
            rememberMe: false
          }
        })

        assert.isTrue(started.redirect)
        assert.isTrue(started.url.startsWith("https://provider.test/authorize"))

        const [options] = yield* stub.starts
        assert.strictEqual(options?.providerId, "github")
        assert.strictEqual(options?.callbackURL, "/welcome")
        assert.strictEqual(options?.errorCallbackURL, "/oops")
        assert.deepStrictEqual(options?.scopes, ["repo"])
        assert.strictEqual(options?.rememberMe, false)
        // A sign-in is not a link: nobody is being attached to anybody.
        assert.isTrue(options?.linkUserId === undefined || options.linkUserId === null)
      }))

    it.effect("passes the signed-in user along when a provider is being linked", () =>
      Effect.gen(function*() {
        const stub = yield* StubFlow
        yield* stub.reset
        const browser = yield* TestHttpClient.signedUp({ email: uniqueEmail("link") })
        yield* browser.client.auth.linkSocial({ payload: { providerId: "github" } })

        const [options] = yield* stub.starts
        assert.strictEqual(options?.linkUserId, browser.user.id)
      }))

    it.effect("refuses to start a link for a caller with no session", () =>
      Effect.gen(function*() {
        const { client } = yield* TestHttpClient.makeClient(AuthTest.TestApi)
        const error = yield* Effect.flip(client.auth.linkSocial({ payload: { providerId: "github" } }))
        assert.strictEqual(error._tag, "Unauthorized")
      }))

    it.effect("sets the session cookie and redirects where the flow says", () =>
      Effect.gen(function*() {
        const minted = yield* withSession("callback-cookie")
        const stub = yield* StubFlow
        yield* stub.reset
        yield* stub.setOutcome({
          _tag: "Success",
          providerId: "github",
          user: minted.user,
          account: minted.account,
          session: minted.session,
          token: minted.token,
          redirectTo: "http://localhost:3000/welcome",
          userCreated: false,
          accountCreated: true,
          linked: false,
          rememberMe: true
        })

        const fresh = yield* TestHttpClient.makeClient(AuthTest.TestApi)
        const [, response] = yield* fresh.client.auth.oauthCallback({
          params: { providerId: "github" },
          query: { code: "the-code", state: "nonce" },
          responseMode: "decoded-and-response"
        })

        assert.strictEqual(response.status, 302)
        assert.strictEqual(response.headers["location"], "http://localhost:3000/welcome")
        assert.strictEqual(
          yield* TestHttpClient.sessionCookieValue(fresh.cookies),
          Redacted.value(minted.token)
        )
        // The browser is now signed in as that user.
        const current = yield* fresh.client.auth.getSession()
        assert.strictEqual(current.user.id, minted.user.id)
      }))

    it.effect("sets no cookie when the callback only linked an account", () =>
      Effect.gen(function*() {
        const minted = yield* withSession("callback-link")
        const stub = yield* StubFlow
        yield* stub.reset
        // A link flow carries no session: the person was already signed in, and
        // minting a second session for them would be a silent upgrade.
        yield* stub.setOutcome({
          _tag: "Success",
          providerId: "github",
          user: minted.user,
          account: minted.account,
          session: null,
          token: null,
          redirectTo: "http://localhost:3000/settings",
          userCreated: false,
          accountCreated: true,
          linked: true,
          rememberMe: true
        })

        const fresh = yield* TestHttpClient.makeClient(AuthTest.TestApi)
        const [, response] = yield* fresh.client.auth.oauthCallback({
          params: { providerId: "github" },
          query: { code: "the-code", state: "nonce" },
          responseMode: "decoded-and-response"
        })

        assert.strictEqual(response.status, 302)
        assert.strictEqual(response.headers["location"], "http://localhost:3000/settings")
        assert.isTrue(Option.isNone(TestHttpClient.responseCookie(response)))
      }))

    it.effect("writes a browser-session cookie when the flow was started with rememberMe: false", () =>
      Effect.gen(function*() {
        const minted = yield* withSession("callback-remember")
        const stub = yield* StubFlow
        yield* stub.reset
        // The choice travelled in the state row from `POST /sign-in/social`.
        yield* stub.setOutcome({
          _tag: "Success",
          providerId: "github",
          user: minted.user,
          account: minted.account,
          session: minted.session,
          token: minted.token,
          redirectTo: "http://localhost:3000/welcome",
          userCreated: false,
          accountCreated: true,
          linked: false,
          rememberMe: false
        })

        const fresh = yield* TestHttpClient.makeClient(AuthTest.TestApi)
        const [, response] = yield* fresh.client.auth.oauthCallback({
          params: { providerId: "github" },
          query: { code: "the-code", state: "nonce" },
          responseMode: "decoded-and-response"
        })

        const cookie = Option.getOrThrow(TestHttpClient.responseCookie(response))
        // No `Max-Age`: the cookie dies with the window, which is what the
        // person asked for — and what the password path already did.
        assert.strictEqual(cookie.options?.maxAge, undefined)
      }))

    it.effect("redirects to the error URL with a safe code, rather than failing", () =>
      Effect.gen(function*() {
        const stub = yield* StubFlow
        yield* stub.reset
        yield* stub.setOutcome({
          _tag: "Failure",
          error: new OAuthStateMismatch(),
          redirectTo: "http://localhost:3000/oops?error=state_mismatch",
          code: "state_mismatch"
        })

        const { client, cookies } = yield* TestHttpClient.makeClient(AuthTest.TestApi)
        const [, response] = yield* client.auth.oauthCallback({
          params: { providerId: "github" },
          query: { error: "access_denied" },
          responseMode: "decoded-and-response"
        })

        // A browser that arrived by a top-level navigation leaves by one.
        assert.strictEqual(response.status, 302)
        assert.strictEqual(
          response.headers["location"],
          "http://localhost:3000/oops?error=state_mismatch"
        )
        assert.strictEqual(yield* TestHttpClient.sessionCookieValue(cookies), "<absent>")
      }))
  })
})

layer(AuthTest.layerHttp())("http/Handlers without any OAuth provider", (it) => {
  it.effect("reports an unknown provider instead of requiring an HttpClient", () =>
    Effect.gen(function*() {
      const { client } = yield* TestHttpClient.makeClient(AuthTest.TestApi)
      const error = yield* Effect.flip(client.auth.signInSocial({ payload: { providerId: "github" } }))

      assert.strictEqual(error._tag, "OAuthProviderError")
      if (error._tag === "OAuthProviderError") {
        assert.strictEqual(error.reason, "UnknownProvider")
        assert.strictEqual(error.providerId, "github")
      }
    }))

  it.effect("still answers the callback with a redirect carrying a safe code", () =>
    Effect.gen(function*() {
      const { client } = yield* TestHttpClient.makeClient(AuthTest.TestApi)
      const [, response] = yield* client.auth.oauthCallback({
        params: { providerId: "github" },
        query: { code: "irrelevant", state: "irrelevant" },
        responseMode: "decoded-and-response"
      })

      assert.strictEqual(response.status, 302)
      assert.strictEqual(
        response.headers["location"],
        "http://localhost:3000/?error=unknown_provider"
      )
    }))
})
