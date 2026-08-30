/**
 * The example app, end to end, through the generated `HttpApiClient`.
 *
 * Every request below crosses the real pipeline: JSON encoding, the router, the
 * `Authenticated` middleware, the cookie, the database. The only substitution
 * is infrastructural — `AuthTest.layerHttpApi` swaps the example's Postgres and
 * its console mailer for an in-memory database and a capturing outbox, because
 * a test has to be able to read the token out of the e-mail the way a person
 * reads it out of their inbox.
 *
 * The whole file runs on one deployment: `layer()` builds the stack once, in
 * `beforeAll`, so the database boots and migrates once rather than once per
 * test. That is why every account below gets an address of its own.
 */
import { assert, layer } from "@effect/vitest"
import { Effect, Layer, Option, Redacted } from "effect"
import { AuthTest, TestHttpClient } from "effect-auth/testing"
import { AppApi } from "../src/Api.js"
import * as Todos from "../src/Todos.js"

const baseUrl = AuthTest.testBaseUrl

/**
 * The example's server, over the test deployment: the shipped
 * `AuthTest.layerHttpApi` implements `effect-auth`'s own group against the
 * application's composed API and supplies the platform services, and the
 * application adds its own handlers on top.
 */
const ServerLive = Todos.layer.pipe(
  Layer.provideMerge(
    AuthTest.layerHttpApi(AppApi, {
      // The flow below is only interesting if the address has to be proven.
      emailPassword: { requireEmailVerification: true },
      trustedOrigins: [baseUrl]
    })
  )
)

/**
 * A generated client wired to the router, with a cookie jar the test can read —
 * the one the library ships, driving the application's own API.
 */
const makeClient = () => TestHttpClient.makeClient(AppApi)

const cookieValue = TestHttpClient.sessionCookieValue

/** An address no sibling test will use: the database is shared. */
const uniqueEmail = (label: string) => `${label}-${globalThis.crypto.randomUUID()}@example.com`

const password = "correct horse battery staple"
const newPassword = "a-much-longer-replacement-passphrase"

layer(ServerLive)("examples/basic", (it) => {
  it.effect("sign-up, verify, sign-in, use a protected endpoint, change password, sign out", () =>
    Effect.gen(function*() {
      const email = uniqueEmail("ada")
      const { client, cookies } = yield* makeClient()
      const emails = yield* AuthTest.TestEmails

      // 1. Register. Verification is required, so no session is handed out and
      //    no cookie is set — the account exists, but cannot be used yet.
      const signedUp = yield* client.auth.signUpEmail({
        payload: { name: "Ada Lovelace", email, password: Redacted.make(password) }
      })
      assert.strictEqual(signedUp.user.email, email)
      assert.strictEqual(signedUp.user.emailVerified, false)
      assert.strictEqual(signedUp.session, null)
      assert.strictEqual(yield* cookieValue(cookies), "<absent>")

      // 2. Signing in before the address is proven is refused, by tag.
      const refused = yield* Effect.flip(
        client.auth.signInEmail({ payload: { email, password: Redacted.make(password) } })
      )
      assert.strictEqual(refused._tag, "EmailNotVerified")

      // 3. The verification link arrived. Follow it.
      const token = yield* emails.tokenFor("verification", email)
      const verified = yield* client.auth.verifyEmail({ query: { token: Redacted.value(token) } })
      assert.strictEqual(verified.success, true)

      // 4. Now sign-in works, and sets the session cookie.
      const signedIn = yield* client.auth.signInEmail({
        payload: { email, password: Redacted.make(password) }
      })
      assert.strictEqual(signedIn.user.email, email)
      const cookie = yield* cookieValue(cookies)
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
      assert.strictEqual(yield* cookieValue(cookies), "")

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
    }))

  it.effect("an anonymous request never reaches the application's handlers", () =>
    Effect.gen(function*() {
      const { client } = yield* makeClient()
      const refused = yield* Effect.flip(client.todos.list())
      assert.strictEqual(refused._tag, "Unauthorized")
    }))

  it.effect("a password reset revokes every session and installs the new password", () =>
    Effect.gen(function*() {
      const email = uniqueEmail("grace")
      const unknown = uniqueEmail("nobody")
      const { client, cookies } = yield* makeClient()
      const emails = yield* AuthTest.TestEmails

      yield* client.auth.signUpEmail({
        payload: { name: "Grace Hopper", email, password: Redacted.make(password) }
      })
      const verification = yield* emails.tokenFor("verification", email)
      yield* client.auth.verifyEmail({ query: { token: Redacted.value(verification) } })
      yield* client.auth.signInEmail({ payload: { email, password: Redacted.make(password) } })
      assert.notStrictEqual(yield* cookieValue(cookies), "<absent>")

      // An unknown address answers exactly the same way, so the endpoint says
      // nothing about who has an account.
      const acknowledged = yield* client.auth.requestPasswordReset({ payload: { email: unknown } })
      assert.strictEqual(acknowledged.success, true)
      assert.strictEqual(Option.isNone(yield* emails.last("reset", unknown)), true)

      yield* client.auth.requestPasswordReset({ payload: { email } })
      const reset = yield* emails.tokenFor("reset", email)

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
        payload: { email, password: Redacted.make(newPassword) }
      })
      assert.strictEqual(signedIn.user.email, email)
    }))
})
