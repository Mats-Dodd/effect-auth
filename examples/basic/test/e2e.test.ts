/**
 * The example app, end to end, through the generated `HttpApiClient`.
 *
 * Every request below crosses the real pipeline: JSON encoding, the router, the
 * `Authenticated` middleware, the cookie, the database. The only substitution
 * is infrastructural — `AuthTest.layer` swaps the example's Postgres and its
 * console mailer for an in-memory database and a capturing outbox, because a
 * test has to be able to read the token out of the e-mail the way a person
 * reads it out of their inbox.
 */
import { assert, it } from "@effect/vitest"
import { Effect, Layer, Option, Redacted, Ref } from "effect"
import { FileSystem, Path } from "effect"
import {
  Cookies,
  Etag,
  HttpClient,
  HttpClientRequest,
  HttpEffect,
  HttpPlatform,
  HttpRouter,
  HttpServerRequest,
  HttpServerResponse
} from "effect/unstable/http"
import { HttpApiBuilder, HttpApiClient, HttpApiMiddleware } from "effect/unstable/httpapi"
import { Authenticated, AuthCookies, AuthHandlers } from "effect-auth"
import { AuthTest } from "effect-auth/testing"
import { AppApi } from "../src/Api.js"
import * as Todos from "../src/Todos.js"

const baseUrl = AuthTest.testBaseUrl

const PlatformLive = Layer.mergeAll(Path.layer, Etag.layerWeak, HttpPlatform.layer).pipe(
  Layer.provideMerge(FileSystem.layerNoop({}))
)

/**
 * The example's server, over the test deployment.
 */
const ServerLive = Layer.mergeAll(
  AuthHandlers.layer(AppApi),
  Todos.layer,
  PlatformLive
).pipe(
  Layer.provideMerge(
    AuthTest.layer({
      // The flow below is only interesting if the address has to be proven.
      emailPassword: { requireEmailVerification: true },
      trustedOrigins: [baseUrl]
    })
  )
)

/**
 * A generated client wired to the router, with a cookie jar the test can read.
 *
 * `HttpEffect.toHandled` rather than the router effect on its own: it is what a
 * server adapter calls, and it is the only thing that runs the *pre-response*
 * handlers — which is how the session cookie is attached. Driving the router
 * directly would silently drop every `Set-Cookie`.
 */
const makeClient = Effect.fnUntraced(function*() {
  const jar = yield* Ref.make(Cookies.empty)
  const routes = yield* HttpRouter.toHttpEffect(HttpApiBuilder.layer(AppApi))

  const transport = HttpClient.make(Effect.fnUntraced(function*(request: HttpClientRequest.HttpClientRequest) {
    const sent = yield* Ref.make(Option.none<HttpServerResponse.HttpServerResponse>())
    yield* HttpEffect.toHandled(routes, (_request, response) => Ref.set(sent, Option.some(response))).pipe(
      Effect.provideService(HttpServerRequest.HttpServerRequest, HttpServerRequest.fromClientRequest(request))
    )
    return HttpServerResponse.toClientResponse(
      Option.getOrElse(yield* Ref.get(sent), () => HttpServerResponse.empty({ status: 500 }))
    )
  }))

  const client = yield* HttpApiClient.makeWith(AppApi, {
    httpClient: HttpClient.withCookiesRef(transport, jar),
    baseUrl
  }).pipe(
    Effect.provide(
      HttpApiMiddleware.layerClient(Authenticated, ({ next, request }) => next(request))
    )
  )

  return { client, jar } as const
})

const cookieValue = (jar: Ref.Ref<Cookies.Cookies>) =>
  Effect.map(
    Ref.get(jar),
    (cookies) =>
      Option.match(Cookies.get(cookies, AuthCookies.insecureSessionCookieName), {
        onNone: () => "<absent>",
        onSome: (cookie) => cookie.value
      })
  )

const email = "ada@example.com"
const password = "correct horse battery staple"
const newPassword = "a-much-longer-replacement-passphrase"

it.effect(
  "sign-up, verify, sign-in, use a protected endpoint, change password, sign out",
  () =>
    Effect.gen(function*() {
      const { client, jar } = yield* makeClient()
      const emails = yield* AuthTest.TestEmails

      // 1. Register. Verification is required, so no session is handed out and
      //    no cookie is set — the account exists, but cannot be used yet.
      const signedUp = yield* client.auth.signUpEmail({
        payload: { name: "Ada Lovelace", email, password: Redacted.make(password) }
      })
      assert.strictEqual(signedUp.user.email, email)
      assert.strictEqual(signedUp.user.emailVerified, false)
      assert.strictEqual(signedUp.session, null)
      assert.strictEqual(yield* cookieValue(jar), "<absent>")

      // 2. Signing in before the address is proven is refused, by tag.
      const refused = yield* Effect.flip(
        client.auth.signInEmail({ payload: { email, password: Redacted.make(password) } })
      )
      assert.strictEqual(refused._tag, "EmailNotVerified")

      // 3. The verification link arrived. Follow it.
      const token = yield* emails.tokenFor("verification")
      const verified = yield* client.auth.verifyEmail({ query: { token: Redacted.value(token) } })
      assert.strictEqual(verified.success, true)

      // 4. Now sign-in works, and sets the session cookie.
      const signedIn = yield* client.auth.signInEmail({
        payload: { email, password: Redacted.make(password) }
      })
      assert.strictEqual(signedIn.user.email, email)
      const cookie = yield* cookieValue(jar)
      assert.notStrictEqual(cookie, "<absent>")

      // 5. The session reads back, over the cookie alone.
      const session = yield* client.auth.getSession()
      assert.strictEqual(session.user.id, signedIn.user.id)

      // 6. The application's own protected endpoints see `CurrentUser`.
      const todo = yield* client.todos.create({ payload: { title: "write the analytical engine" } })
      assert.strictEqual(todo.ownerId, signedIn.user.id)
      const todos = yield* client.todos.list()
      assert.deepStrictEqual(todos.map((t) => t.title), ["write the analytical engine"])

      // 7. A sensitive operation: the current password is required.
      const changed = yield* client.auth.changePassword({
        payload: {
          currentPassword: Redacted.make(password),
          newPassword: Redacted.make(newPassword),
          revokeOtherSessions: true
        }
      })
      assert.strictEqual(changed.success, true)

      // 8. Signing out clears the cookie and the session behind it.
      const out = yield* client.auth.signOut()
      assert.strictEqual(out.success, true)
      assert.strictEqual(yield* cookieValue(jar), "")

      const afterSignOut = yield* Effect.flip(client.auth.getSession())
      assert.strictEqual(afterSignOut._tag, "Unauthorized")

      // 9. The new password is the one that works now.
      const again = yield* client.auth.signInEmail({
        payload: { email, password: Redacted.make(newPassword) }
      })
      assert.strictEqual(again.user.id, signedIn.user.id)

      const stale = yield* Effect.flip(
        client.auth.signInEmail({ payload: { email, password: Redacted.make(password) } })
      )
      assert.strictEqual(stale._tag, "InvalidCredentials")
    }).pipe(Effect.provide(ServerLive)),
  AuthTest.testTimeout
)

it.effect(
  "an anonymous request never reaches the application's handlers",
  () =>
    Effect.gen(function*() {
      const { client } = yield* makeClient()
      const refused = yield* Effect.flip(client.todos.list())
      assert.strictEqual(refused._tag, "Unauthorized")
    }).pipe(Effect.provide(ServerLive)),
  AuthTest.testTimeout
)

it.effect(
  "a password reset revokes every session and installs the new password",
  () =>
    Effect.gen(function*() {
      const { client, jar } = yield* makeClient()
      const emails = yield* AuthTest.TestEmails

      yield* client.auth.signUpEmail({
        payload: { name: "Grace Hopper", email: "grace@example.com", password: Redacted.make(password) }
      })
      const verification = yield* emails.tokenFor("verification")
      yield* client.auth.verifyEmail({ query: { token: Redacted.value(verification) } })
      yield* client.auth.signInEmail({
        payload: { email: "grace@example.com", password: Redacted.make(password) }
      })
      assert.notStrictEqual(yield* cookieValue(jar), "<absent>")

      // An unknown address answers exactly the same way, so the endpoint says
      // nothing about who has an account.
      const unknown = yield* client.auth.requestPasswordReset({
        payload: { email: "nobody@example.com" }
      })
      assert.strictEqual(unknown.success, true)
      assert.strictEqual(Option.isNone(yield* emails.last("reset")), true)

      yield* client.auth.requestPasswordReset({ payload: { email: "grace@example.com" } })
      const reset = yield* emails.tokenFor("reset")

      const done = yield* client.auth.resetPassword({
        payload: { token: reset, newPassword: Redacted.make(newPassword) }
      })
      assert.strictEqual(done.success, true)

      // Every session was revoked, including the one this client holds.
      const afterReset = yield* Effect.flip(client.auth.getSession())
      assert.strictEqual(afterReset._tag, "Unauthorized")

      // The token was single-use.
      const replayed = yield* Effect.flip(
        client.auth.resetPassword({
          payload: { token: reset, newPassword: Redacted.make(newPassword) }
        })
      )
      assert.strictEqual(replayed._tag, "InvalidToken")

      const signedIn = yield* client.auth.signInEmail({
        payload: { email: "grace@example.com", password: Redacted.make(newPassword) }
      })
      assert.strictEqual(signedIn.user.email, "grace@example.com")
    }).pipe(Effect.provide(ServerLive)),
  AuthTest.testTimeout
)
