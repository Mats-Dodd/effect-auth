import { assert, describe, layer } from "@effect/vitest"
import { Context, DateTime, Effect, Layer, Option, Redacted, Ref } from "effect"
import { OAuthStateMismatch } from "../../src/domain/Errors.js"
import type { Account, User } from "../../src/domain/Schema.js"
import { Sessions } from "../../src/domain/Sessions.js"
import { AccountStore, UserStore } from "../../src/domain/Stores.js"
import { insecureOAuthStateCookieName } from "../../src/http/Cookies.js"
import * as AuthHandlers from "../../src/http/Handlers.js"
import type { CallbackOutcome, RefreshedTokens, StartOptions, TokenSelector } from "../../src/oauth/Flow.js"
import { OAuthFlow } from "../../src/oauth/Flow.js"
import { AuthTest, TestHttpClient } from "../../src/testing/index.js"
import { uniqueEmail } from "../fixtures.js"

/** One call the handlers made to a token method, and which one it was. */
interface TokenCall extends TokenSelector {
  readonly method: "accessToken" | "refreshTokens"
}

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
class StubFlow extends Context.Service<
  StubFlow,
  {
    /** The next outcome `GET /callback/:providerId` will resolve to. */
    readonly setOutcome: (outcome: CallbackOutcome) => Effect.Effect<void>
    /** What the two token methods will answer with. */
    readonly setTokens: (tokens: RefreshedTokens) => Effect.Effect<void>
    /** Every `start` the handlers made since the last `reset`. */
    readonly starts: Effect.Effect<ReadonlyArray<StartOptions>>
    /** Every token method call the handlers made since the last `reset`. */
    readonly tokenCalls: Effect.Effect<ReadonlyArray<TokenCall>>
    /** Forgets the recorded calls and everything staged. */
    readonly reset: Effect.Effect<void>
  }
>()("effect-auth/test/http/OAuth.test/StubFlow") {}

const stubLayer = Layer.effectContext(
  Effect.gen(function* () {
    const started = yield* Ref.make<ReadonlyArray<StartOptions>>([])
    const outcome = yield* Ref.make<Option.Option<CallbackOutcome>>(Option.none())
    const tokens = yield* Ref.make<Option.Option<RefreshedTokens>>(Option.none())
    const calls = yield* Ref.make<ReadonlyArray<TokenCall>>([])

    /** Records the selector the handler built, and answers what was staged. */
    const answerTokens = (method: TokenCall["method"]) => (selector: TokenSelector) =>
      Effect.flatMap(
        Ref.update(calls, (all) => [...all, { ...selector, method }]),
        () =>
          Effect.flatMap(
            Ref.get(tokens),
            Option.match({
              onNone: () => Effect.die("no provider tokens were staged"),
              onSome: Effect.succeed
            })
          )
      )

    return Context.make(StubFlow, {
      setOutcome: (next: CallbackOutcome) => Ref.set(outcome, Option.some(next)),
      setTokens: (next: RefreshedTokens) => Ref.set(tokens, Option.some(next)),
      starts: Ref.get(started),
      tokenCalls: Ref.get(calls),
      reset: Effect.andThen(
        Effect.andThen(Ref.set(started, []), Ref.set(outcome, Option.none())),
        Effect.andThen(Ref.set(tokens, Option.none()), Ref.set(calls, []))
      )
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
        accessToken: answerTokens("accessToken"),
        refreshTokens: answerTokens("refreshTokens"),
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
  })
)

/** The whole server stack, with the stub standing in for the flow. */
const stubbed = Layer.mergeAll(
  AuthHandlers.layer(AuthTest.TestApi).pipe(Layer.provideMerge(stubLayer.pipe(Layer.provideMerge(AuthTest.layer())))),
  AuthTest.layerPlatform
)

/** A real session for a signed-up user, minted outside any HTTP request. */
const mintSession = Effect.fnUntraced(function* (email: string) {
  const users = yield* UserStore
  const accounts = yield* AccountStore
  const sessions = yield* Sessions
  const user = Option.getOrThrow(yield* users.findByEmail(email))
  const account = (yield* accounts.listByUserId(user.id))[0]!
  const created = yield* sessions.createUnchecked({ userId: user.id })
  return { user, account, session: created.session, token: created.token }
})

/** The one account a freshly signed-up user holds: their credential. */
const onlyAccount = Effect.fnUntraced(function* (userId: User["id"]) {
  const accounts = yield* AccountStore
  return (yield* accounts.listByUserId(userId))[0]!
})

/** What the stubbed flow answers a token request with. */
const staged = (accountId: Account["id"]): RefreshedTokens => ({
  accessToken: Redacted.make("an-access-token"),
  accessTokenExpiresAt: DateTime.makeUnsafe(1_000_000),
  idToken: Redacted.make("an-id-token"),
  scopes: ["profile", "email"],
  providerId: "github",
  accountId,
  refreshToken: Redacted.make("a-refresh-token"),
  refreshTokenExpiresAt: null
})

/**
 * Client options that plant the OAuth state-binding cookie a browser would hold
 * after starting a flow, its value the raw `state`. Injected as a request
 * header rather than through a real `signInSocial` call, so a block full of
 * callback tests does not spend the shared credential rate-limit bucket — and
 * because the callback is each client's first request, its empty cookie jar
 * leaves the injected `cookie` header in place. The deployment here is plain
 * HTTP, so the un-prefixed name is the one written.
 */
const stateBinding = (state: string): TestHttpClient.ClientOptions => ({
  headers: { cookie: `${insecureOAuthStateCookieName}=${state}` }
})

/** Signs a new account up, and mints a session for it outside the browser. */
const withSession = Effect.fnUntraced(function* (label: string) {
  const browser = yield* TestHttpClient.signedUp({ email: uniqueEmail(label) })
  return yield* mintSession(browser.email)
})

describe.sequential("http/Handlers OAuth", () => {
  layer(stubbed)((it) => {
    it.effect("answers the authorization URL to navigate to", () =>
      Effect.gen(function* () {
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
      })
    )

    it.effect("emits the state-binding cookie holding the raw state on signInSocial", () =>
      Effect.gen(function* () {
        const stub = yield* StubFlow
        yield* stub.reset
        const { client } = yield* TestHttpClient.makeClient(AuthTest.TestApi)
        const [, response] = yield* client.auth.signInSocial({
          payload: {
            providerId: "github",
            callbackURL: "/welcome",
            errorCallbackURL: "/oops",
            scopes: ["repo"],
            rememberMe: false
          },
          responseMode: "decoded-and-response"
        })

        // Deleting `setOAuthStateCookie` from the handler must break this: the
        // callback binding has nothing to compare against without it.
        const cookie = Option.getOrThrow(TestHttpClient.responseCookie(response, insecureOAuthStateCookieName))
        assert.strictEqual(cookie.value, "nonce")
        assert.strictEqual(cookie.options?.httpOnly, true)
      })
    )

    it.effect("round-trips signInSocial's cookie through the jar to the callback", () =>
      Effect.gen(function* () {
        const minted = yield* withSession("callback-roundtrip")
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
          challenge: null,
          accountCreated: true,
          linked: false,
          rememberMe: true
        })

        // One client, one jar, no injected header: `signInSocial`'s `Set-Cookie`
        // lands in the jar, and the callback on the same client sends it back —
        // the whole binding, start to finish, through the browser's own jar.
        const { client, cookies } = yield* TestHttpClient.makeClient(AuthTest.TestApi)
        yield* client.auth.signInSocial({
          payload: {
            providerId: "github",
            callbackURL: "/welcome",
            errorCallbackURL: "/oops",
            scopes: ["repo"],
            rememberMe: true
          }
        })

        const [, response] = yield* client.auth.oauthCallback({
          params: { providerId: "github" },
          query: { code: "the-code", state: "nonce" },
          responseMode: "decoded-and-response"
        })

        assert.strictEqual(response.status, 302)
        assert.strictEqual(response.headers["location"], "http://localhost:3000/welcome")
        assert.strictEqual(yield* TestHttpClient.sessionCookieValue(cookies), Redacted.value(minted.token))
        // The single-use state cookie is expired on the successful callback.
        const cleared = TestHttpClient.responseCookie(response, insecureOAuthStateCookieName)
        assert.isTrue(Option.isSome(cleared))
        assert.strictEqual(Option.getOrThrow(cleared).value, "")
      })
    )

    it.effect("passes the signed-in user along when a provider is being linked", () =>
      Effect.gen(function* () {
        const stub = yield* StubFlow
        yield* stub.reset
        const browser = yield* TestHttpClient.signedUp({ email: uniqueEmail("link") })
        yield* browser.client.auth.linkSocial({ payload: { providerId: "github" } })

        const [options] = yield* stub.starts
        assert.strictEqual(options?.linkUserId, browser.user.id)
      })
    )

    it.effect("refuses to start a link for a caller with no session", () =>
      Effect.gen(function* () {
        const { client } = yield* TestHttpClient.makeClient(AuthTest.TestApi)
        const error = yield* Effect.flip(client.auth.linkSocial({ payload: { providerId: "github" } }))
        assert.strictEqual(error._tag, "Unauthorized")
      })
    )

    it.effect("sets the session cookie and redirects where the flow says", () =>
      Effect.gen(function* () {
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
          challenge: null,
          accountCreated: true,
          linked: false,
          rememberMe: true
        })

        // The browser holds the state-binding cookie the flow set when it
        // started (its value is the raw `state`), so the callback accepts the
        // matching `state` the provider echoed back.
        const fresh = yield* TestHttpClient.makeClient(AuthTest.TestApi, stateBinding("nonce"))
        const [, response] = yield* fresh.client.auth.oauthCallback({
          params: { providerId: "github" },
          query: { code: "the-code", state: "nonce" },
          responseMode: "decoded-and-response"
        })

        assert.strictEqual(response.status, 302)
        assert.strictEqual(response.headers["location"], "http://localhost:3000/welcome")
        assert.strictEqual(yield* TestHttpClient.sessionCookieValue(fresh.cookies), Redacted.value(minted.token))
        // The browser is now signed in as that user.
        const current = yield* fresh.client.auth.getSession()
        assert.strictEqual(current.user.id, minted.user.id)
      })
    )

    it.effect("sets no cookie when the callback only linked an account", () =>
      Effect.gen(function* () {
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
          challenge: null,
          accountCreated: true,
          linked: true,
          rememberMe: true
        })

        const fresh = yield* TestHttpClient.makeClient(AuthTest.TestApi, stateBinding("nonce"))
        const [, response] = yield* fresh.client.auth.oauthCallback({
          params: { providerId: "github" },
          query: { code: "the-code", state: "nonce" },
          responseMode: "decoded-and-response"
        })

        assert.strictEqual(response.status, 302)
        assert.strictEqual(response.headers["location"], "http://localhost:3000/settings")
        assert.isTrue(Option.isNone(TestHttpClient.responseCookie(response)))
      })
    )

    it.effect("writes a browser-session cookie when the flow was started with rememberMe: false", () =>
      Effect.gen(function* () {
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
          challenge: null,
          accountCreated: true,
          linked: false,
          rememberMe: false
        })

        const fresh = yield* TestHttpClient.makeClient(AuthTest.TestApi, stateBinding("nonce"))
        const [, response] = yield* fresh.client.auth.oauthCallback({
          params: { providerId: "github" },
          query: { code: "the-code", state: "nonce" },
          responseMode: "decoded-and-response"
        })

        const cookie = Option.getOrThrow(TestHttpClient.responseCookie(response))
        // No `Max-Age`: the cookie dies with the window, which is what the
        // person asked for — and what the password path already did.
        assert.strictEqual(cookie.options?.maxAge, undefined)
      })
    )

    it.effect("redirects to the error URL with a safe code, rather than failing", () =>
      Effect.gen(function* () {
        const stub = yield* StubFlow
        yield* stub.reset
        yield* stub.setOutcome({
          _tag: "Failure",
          error: OAuthStateMismatch.make(),
          redirectTo: "http://localhost:3000/oops?error=state_mismatch",
          code: "state_mismatch"
        })

        // The binding passes (this browser holds the state cookie), so the
        // callback reaches `complete`, which resolves the flow's own failure
        // into the redirect the state row named.
        const { client, cookies } = yield* TestHttpClient.makeClient(AuthTest.TestApi, stateBinding("nonce"))
        const [, response] = yield* client.auth.oauthCallback({
          params: { providerId: "github" },
          query: { state: "nonce", error: "access_denied" },
          responseMode: "decoded-and-response"
        })

        // A browser that arrived by a top-level navigation leaves by one.
        assert.strictEqual(response.status, 302)
        assert.strictEqual(response.headers["location"], "http://localhost:3000/oops?error=state_mismatch")
        assert.strictEqual(yield* TestHttpClient.sessionCookieValue(cookies), "<absent>")
      })
    )

    it.effect("turns away a callback whose browser never started the flow", () =>
      Effect.gen(function* () {
        const stub = yield* StubFlow
        yield* stub.reset
        // Staged, but it must never be reached: the binding is checked before
        // the state is consumed, and this browser holds no state cookie.
        yield* stub.setOutcome({
          _tag: "Failure",
          error: OAuthStateMismatch.make(),
          redirectTo: "http://localhost:3000/oops?error=state_mismatch",
          code: "state_mismatch"
        })

        // No `signInSocial` on this client: it is the victim's browser, lured to
        // a callback for a `state` the attacker legitimately obtained.
        const { client, cookies } = yield* TestHttpClient.makeClient(AuthTest.TestApi)
        const [, response] = yield* client.auth.oauthCallback({
          params: { providerId: "github" },
          query: { code: "the-code", state: "attacker-state" },
          responseMode: "decoded-and-response"
        })

        // Rejected before `complete`: the redirect is to the default error URL
        // (baseUrl), not the errorURL a consumed state row would have carried,
        // and it carries the same safe `state_mismatch` code.
        assert.strictEqual(response.status, 302)
        assert.strictEqual(response.headers["location"], "http://localhost:3000/?error=state_mismatch")
        // No session was minted for the victim.
        assert.strictEqual(yield* TestHttpClient.sessionCookieValue(cookies), "<absent>")
        // The state cookie is expired on a mismatch too, not only on success —
        // `clearOAuthStateCookie` runs before the binding is even checked.
        const cleared = TestHttpClient.responseCookie(response, insecureOAuthStateCookieName)
        assert.isTrue(Option.isSome(cleared))
        assert.strictEqual(Option.getOrThrow(cleared).value, "")
        // The flow was never asked to complete.
        assert.deepStrictEqual(yield* stub.starts, [])
      })
    )

    // ---------------------------------------------------------------------------
    // Provider tokens
    //
    // Declared beside the tests above rather than in a `describe` of their own:
    // `layer()` closes its scope after the last test it collected, and it does
    // not see into a nested suite that some of its siblings are not in.
    // ---------------------------------------------------------------------------

    it.effect("hands the flow the caller's own user id, and answers the credential", () =>
      Effect.gen(function* () {
        const stub = yield* StubFlow
        yield* stub.reset
        const browser = yield* TestHttpClient.signedUp({ email: uniqueEmail("access-token") })
        const account = yield* onlyAccount(browser.user.id)
        yield* stub.setTokens(staged(account.id))

        const answer = yield* browser.client.auth.getAccessToken({ payload: { accountId: account.id } })

        // A bearer credential for somebody's account at the provider: it
        // reaches the response body as a `Redacted`, and a log line never.
        assert.strictEqual(Redacted.value(answer.accessToken), "an-access-token")
        assert.strictEqual(answer.idToken === null ? null : Redacted.value(answer.idToken), "an-id-token")
        assert.deepStrictEqual(answer.scopes, ["profile", "email"])
        assert.strictEqual(answer.providerId, "github")
        assert.strictEqual(answer.accountId, account.id)

        // The selector is half session and half request: naming somebody
        // else's account can only ever be a `NotFound`.
        assert.deepStrictEqual(yield* stub.tokenCalls, [
          { method: "accessToken", userId: browser.user.id, accountId: account.id }
        ])
      })
    )

    it.effect("spends the refresh token only when asked to, and reports the new pair", () =>
      Effect.gen(function* () {
        const stub = yield* StubFlow
        yield* stub.reset
        const browser = yield* TestHttpClient.signedUp({ email: uniqueEmail("refresh-token") })
        const account = yield* onlyAccount(browser.user.id)
        yield* stub.setTokens(staged(account.id))

        const answer = yield* browser.client.auth.refreshToken({ payload: { accountId: account.id } })
        assert.strictEqual(Redacted.value(answer.refreshToken), "a-refresh-token")
        assert.strictEqual(Redacted.value(answer.accessToken), "an-access-token")

        assert.deepStrictEqual(yield* stub.tokenCalls, [
          { method: "refreshTokens", userId: browser.user.id, accountId: account.id }
        ])
      })
    )

    it.effect("refuses a caller with no session, without asking the flow anything", () =>
      Effect.gen(function* () {
        const stub = yield* StubFlow
        yield* stub.reset
        const browser = yield* TestHttpClient.signedUp({ email: uniqueEmail("token-no-session") })
        const account = yield* onlyAccount(browser.user.id)

        const { client } = yield* TestHttpClient.makeClient(AuthTest.TestApi)
        const error = yield* Effect.flip(client.auth.getAccessToken({ payload: { accountId: account.id } }))
        assert.strictEqual(error._tag, "Unauthorized")
        assert.deepStrictEqual(yield* stub.tokenCalls, [])
      })
    )
  })
})

layer(AuthTest.layerHttp())("http/Handlers without any OAuth provider", (it) => {
  it.effect("reports an unknown provider instead of requiring an HttpClient", () =>
    Effect.gen(function* () {
      const { client } = yield* TestHttpClient.makeClient(AuthTest.TestApi)
      const error = yield* Effect.flip(client.auth.signInSocial({ payload: { providerId: "github" } }))

      assert.strictEqual(error._tag, "OAuthProviderError")
      if (error._tag === "OAuthProviderError") {
        assert.strictEqual(error.reason, "UnknownProvider")
        assert.strictEqual(error.providerId, "github")
      }
    })
  )

  it.effect("still answers the callback with a redirect carrying a safe code", () =>
    Effect.gen(function* () {
      const { client } = yield* TestHttpClient.makeClient(AuthTest.TestApi)
      const [, response] = yield* client.auth.oauthCallback({
        params: { providerId: "github" },
        query: { code: "irrelevant", state: "irrelevant" },
        responseMode: "decoded-and-response"
      })

      assert.strictEqual(response.status, 302)
      assert.strictEqual(response.headers["location"], "http://localhost:3000/?error=unknown_provider")
    })
  )
})
