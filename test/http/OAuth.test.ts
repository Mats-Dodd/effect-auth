import { assert, describe, it } from "@effect/vitest"
import { Context, DateTime, Effect, Layer, Option, Redacted, Ref } from "effect"
import { OAuthStateMismatch } from "../../src/domain/Errors.js"
import { Sessions } from "../../src/domain/Sessions.js"
import { AccountStore, UserStore } from "../../src/domain/Stores.js"
import * as AuthHandlers from "../../src/http/Handlers.js"
import { layer as middlewareLayer } from "../../src/http/MiddlewareLive.js"
import type { CallbackOutcome, StartOptions } from "../../src/oauth/Flow.js"
import { OAuthFlow } from "../../src/oauth/Flow.js"
import {
  makeClient,
  platformLayer,
  responseCookie,
  sessionCookieValue,
  servicesLayer,
  signedUp,
  TestApi,
  testLayer,
  testTimeout
} from "./harness.js"

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
 */
class StubFlow extends Context.Service<StubFlow, {
  /** The next outcome `GET /callback/:providerId` will resolve to. */
  readonly setOutcome: (outcome: CallbackOutcome) => Effect.Effect<void>
  /** Every `start` the handlers made, in order. */
  readonly starts: Effect.Effect<ReadonlyArray<StartOptions>>
}>()("test/http/StubFlow") {}

const stubLayer = Layer.effectContext(Effect.gen(function*() {
  const started = yield* Ref.make<ReadonlyArray<StartOptions>>([])
  const outcome = yield* Ref.make<Option.Option<CallbackOutcome>>(Option.none())

  return Context.make(StubFlow, {
    setOutcome: (next: CallbackOutcome) => Ref.set(outcome, Option.some(next)),
    starts: Ref.get(started)
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

const withOAuth = () => {
  const services = stubLayer.pipe(Layer.provideMerge(servicesLayer()))
  const server = AuthHandlers.layer(TestApi).pipe(
    Layer.provide(middlewareLayer),
    Layer.provideMerge(services)
  )
  return Layer.mergeAll(server, platformLayer)
}

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

describe("http/Handlers OAuth", () => {
  it.effect(
    "answers the authorization URL to navigate to",
    () =>
      Effect.gen(function*() {
        const { client } = yield* makeClient()
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

        const stub = yield* StubFlow
        const [options] = yield* stub.starts
        assert.strictEqual(options?.providerId, "github")
        assert.strictEqual(options?.callbackURL, "/welcome")
        assert.strictEqual(options?.errorCallbackURL, "/oops")
        assert.deepStrictEqual(options?.scopes, ["repo"])
        assert.strictEqual(options?.rememberMe, false)
        // A sign-in is not a link: nobody is being attached to anybody.
        assert.isTrue(options?.linkUserId === undefined || options.linkUserId === null)
      }).pipe(Effect.provide(withOAuth())),
    testTimeout
  )

  it.effect(
    "passes the signed-in user along when a provider is being linked",
    () =>
      Effect.gen(function*() {
        const browser = yield* signedUp()
        yield* browser.client.auth.linkSocial({ payload: { providerId: "github" } })

        const stub = yield* StubFlow
        const [options] = yield* stub.starts
        assert.strictEqual(options?.linkUserId, browser.user.id)
      }).pipe(Effect.provide(withOAuth())),
    testTimeout
  )

  it.effect(
    "refuses to start a link for a caller with no session",
    () =>
      Effect.gen(function*() {
        const { client } = yield* makeClient()
        const error = yield* Effect.flip(client.auth.linkSocial({ payload: { providerId: "github" } }))
        assert.strictEqual(error._tag, "Unauthorized")
      }).pipe(Effect.provide(withOAuth())),
    testTimeout
  )

  it.effect(
    "sets the session cookie and redirects where the flow says",
    () =>
      Effect.gen(function*() {
        const browser = yield* signedUp()
        const minted = yield* mintSession(browser.email)
        const stub = yield* StubFlow
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

        const fresh = yield* makeClient()
        const [, response] = yield* fresh.client.auth.oauthCallback({
          params: { providerId: "github" },
          query: { code: "the-code", state: "nonce" },
          responseMode: "decoded-and-response"
        })

        assert.strictEqual(response.status, 302)
        assert.strictEqual(response.headers["location"], "http://localhost:3000/welcome")
        assert.strictEqual(
          yield* sessionCookieValue(fresh.cookies),
          Redacted.value(minted.token)
        )
        // The browser is now signed in as that user.
        const current = yield* fresh.client.auth.getSession()
        assert.strictEqual(current.user.id, minted.user.id)
      }).pipe(Effect.provide(withOAuth())),
    testTimeout
  )

  it.effect(
    "sets no cookie when the callback only linked an account",
    () =>
      Effect.gen(function*() {
        const browser = yield* signedUp()
        const minted = yield* mintSession(browser.email)
        const stub = yield* StubFlow
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

        const fresh = yield* makeClient()
        const [, response] = yield* fresh.client.auth.oauthCallback({
          params: { providerId: "github" },
          query: { code: "the-code", state: "nonce" },
          responseMode: "decoded-and-response"
        })

        assert.strictEqual(response.status, 302)
        assert.strictEqual(response.headers["location"], "http://localhost:3000/settings")
        assert.isTrue(Option.isNone(responseCookie(response)))
      }).pipe(Effect.provide(withOAuth())),
    testTimeout
  )

  it.effect(
    "writes a browser-session cookie when the flow was started with rememberMe: false",
    () =>
      Effect.gen(function*() {
        const browser = yield* signedUp()
        const minted = yield* mintSession(browser.email)
        const stub = yield* StubFlow
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

        const fresh = yield* makeClient()
        const [, response] = yield* fresh.client.auth.oauthCallback({
          params: { providerId: "github" },
          query: { code: "the-code", state: "nonce" },
          responseMode: "decoded-and-response"
        })

        const cookie = Option.getOrThrow(responseCookie(response))
        // No `Max-Age`: the cookie dies with the window, which is what the
        // person asked for — and what the password path already did.
        assert.strictEqual(cookie.options?.maxAge, undefined)
      }).pipe(Effect.provide(withOAuth())),
    testTimeout
  )

  it.effect(
    "redirects to the error URL with a safe code, rather than failing",
    () =>
      Effect.gen(function*() {
        const stub = yield* StubFlow
        yield* stub.setOutcome({
          _tag: "Failure",
          error: new OAuthStateMismatch(),
          redirectTo: "http://localhost:3000/oops?error=state_mismatch",
          code: "state_mismatch"
        })

        const { client, cookies } = yield* makeClient()
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
        assert.strictEqual(yield* sessionCookieValue(cookies), "<absent>")
      }).pipe(Effect.provide(withOAuth())),
    testTimeout
  )
})

describe("http/Handlers without any OAuth provider", () => {
  it.effect(
    "reports an unknown provider instead of requiring an HttpClient",
    () =>
      Effect.gen(function*() {
        const { client } = yield* makeClient()
        const error = yield* Effect.flip(client.auth.signInSocial({ payload: { providerId: "github" } }))

        assert.strictEqual(error._tag, "OAuthProviderError")
        if (error._tag === "OAuthProviderError") {
          assert.strictEqual(error.reason, "UnknownProvider")
          assert.strictEqual(error.providerId, "github")
        }
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "still answers the callback with a redirect carrying a safe code",
    () =>
      Effect.gen(function*() {
        const { client } = yield* makeClient()
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
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )
})
