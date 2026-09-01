/**
 * The example app, end to end, through the generated `HttpApiClient`.
 *
 * Every request below crosses the real pipeline: JSON encoding, the router, the
 * `Authenticated` middleware, the cookie, the database. The only substitution
 * is infrastructural — `AuthTest.layerHttpApi` swaps the example's Postgres and
 * its console mailers for an in-memory database and a capturing outbox, because
 * a test has to be able to read the token out of the e-mail the way a person
 * reads it out of their inbox. The example's own `Mailer.layer` and
 * `Mailer.emailOtpLayer` print those credentials instead, which is the only reason
 * they are not the ones under test here.
 *
 * The whole file runs on one deployment: `layer()` builds the stack once, in
 * `beforeAll`, so the database boots and migrates once rather than once per
 * test. That is why every account below gets an address of its own.
 */
import { assert, layer } from "@effect/vitest"
import { Duration, Effect, Layer, Option, Random, Redacted } from "effect"
import { EmailOtp, Stores } from "effect-auth"
import { AuthTest, EmailOtpTest, TestHttpClient } from "effect-auth/testing"
import { AppApi } from "../src/Api.js"
import { auth, freeTodoLimit } from "../src/Auth.js"
import * as Todos from "../src/Todos.js"

/**
 * The completed half of a sign-in's two-status success.
 *
 * `signInEmail` answers `SessionWithUser` on 200 or `MfaRequired` on 202. This
 * deployment installs no factor plugin, so the second is unreachable — saying
 * so turns it into a failed assertion rather than an `undefined` two lines on.
 */
const completeSignIn = <S, U>(
  result: { readonly _tag: "MfaRequired" } | { readonly user: U; readonly session: S }
): { readonly user: U; readonly session: S } => {
  if ("_tag" in result) {
    throw new Error("expected a completed sign-in; the deployment answered MfaRequired")
  }
  return result
}

const baseUrl = AuthTest.testBaseUrl

/**
 * The example's server, over the test deployment.
 *
 * Three things about it are the point of the example rather than of the test:
 * `user.model` is the deployment's own, so the `plan` column exists and the
 * endpoints carry it; the magic link plugin goes in through `layerHttpApi`'s
 * third parameter, which provides it the *same* deployment build the auth
 * handlers get; and the application's own group is merged on top exactly as
 * `App.ts` merges it.
 */
const ServerLive = Todos.layer.pipe(
  Layer.provideMerge(
    AuthTest.layerHttpApi(
      AppApi,
      {
        // The flow below is only interesting if the address has to be proven.
        emailPassword: { requireEmailVerification: true },
        // Off by default in production; this deployment serves both.
        user: {
          model: auth.model,
          changeEmail: { enabled: true },
          deleteUser: { enabled: true }
        },
        trustedOrigins: [baseUrl]
      },
      EmailOtp.handlers(AppApi).pipe(Layer.provide(EmailOtpTest.layerEmailOtp({ ttl: Duration.minutes(10) })))
    )
  )
)

/**
 * A generated client wired to the router, with a cookie jar the test can read —
 * the one the library ships, driving the application's own API.
 */
const makeClient = () => TestHttpClient.makeClient(AppApi)

const cookieValue = TestHttpClient.sessionCookieValue

/**
 * An address no sibling test will use: the database is shared, and the tests in
 * this file run concurrently against it.
 *
 * An `Effect` rather than a plain function, because the randomness comes from
 * Effect's `Random` — the same service a test can pin with `Random.withSeed`
 * when it needs the run to repeat exactly.
 */
const uniqueEmail = (label: string) =>
  Effect.map(Random.nextIntBetween(0, Number.MAX_SAFE_INTEGER), (n) => `${label}-${n}@example.com`)

const password = "correct horse battery staple"
const newPassword = "a-much-longer-replacement-passphrase"

layer(ServerLive)("examples/basic", (it) => {
  it.effect("sign-up, verify, sign-in, use a protected endpoint, change password, sign out", () =>
    Effect.gen(function* () {
      const email = yield* uniqueEmail("ada")
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
      // The deployment's own field, filled in from the model's default because
      // the body said nothing about it.
      assert.strictEqual(signedUp.user.plan, "free")

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
      const signedIn = completeSignIn(
        yield* client.auth.signInEmail({
          payload: { email, password: Redacted.make(password) }
        })
      )
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
      assert.deepStrictEqual(
        todos.map((t) => t.title),
        ["write the analytical engine"]
      )

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
      const again = completeSignIn(
        yield* client.auth.signInEmail({
          payload: { email, password: Redacted.make(newPassword) }
        })
      )
      assert.strictEqual(again.user.id, signedIn.user.id)

      const stale = yield* Effect.flip(
        client.auth.signInEmail({ payload: { email, password: Redacted.make(password) } })
      )
      assert.strictEqual(stale._tag, "InvalidCredentials")
    })
  )

  it.effect("an anonymous request never reaches the application's handlers", () =>
    Effect.gen(function* () {
      const { client } = yield* makeClient()
      const refused = yield* Effect.flip(client.todos.list())
      assert.strictEqual(refused._tag, "Unauthorized")
    })
  )

  it.effect("a password reset revokes every session and installs the new password", () =>
    Effect.gen(function* () {
      const email = yield* uniqueEmail("grace")
      const unknown = yield* uniqueEmail("nobody")
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

      const signedIn = completeSignIn(
        yield* client.auth.signInEmail({
          payload: { email, password: Redacted.make(newPassword) }
        })
      )
      assert.strictEqual(signedIn.user.email, email)
    })
  )

  it.effect("the deployment's own user field reaches its own handler, and update-user changes it", () =>
    Effect.gen(function* () {
      const email = yield* uniqueEmail("katherine")
      const { client } = yield* makeClient()
      const emails = yield* AuthTest.TestEmails

      // A client may state `plan` at sign-up, because it was declared with
      // `UserField.withDefault`.
      const signedUp = yield* client.auth.signUpEmail({
        payload: { name: "Katherine Johnson", email, password: Redacted.make(password), plan: "free" }
      })
      assert.strictEqual(signedUp.user.plan, "free")

      const verification = yield* emails.tokenFor("verification", email)
      yield* client.auth.verifyEmail({ query: { token: Redacted.value(verification) } })
      yield* client.auth.signInEmail({ payload: { email, password: Redacted.make(password) } })

      // `Todos.ts` reads `plan` off `auth.CurrentUser` — the same context key the
      // middleware fills, seen through this deployment's model.
      for (let n = 0; n < freeTodoLimit; n++) {
        yield* client.todos.create({ payload: { title: `orbit ${n}` } })
      }
      const capped = yield* Effect.flip(client.todos.create({ payload: { title: "one too many" } }))
      assert.strictEqual(capped._tag, "TodoLimitReached")

      // `POST /auth/update-user` patches the deployment's own column beside the
      // base ones, and answers with the user it wrote.
      const upgraded = yield* client.auth.updateUser({
        payload: { name: "Katherine G. Johnson", plan: "pro" }
      })
      assert.strictEqual(upgraded.user.plan, "pro")
      assert.strictEqual(upgraded.user.name, "Katherine G. Johnson")

      // …and the application's handler sees the new value on the next request.
      const allowed = yield* client.todos.create({ payload: { title: "one more" } })
      assert.strictEqual(allowed.title, "one more")

      // An absent key leaves the column alone.
      const renamed = yield* client.auth.updateUser({ payload: { name: "Katherine Johnson" } })
      assert.strictEqual(renamed.user.plan, "pro")
    })
  )

  it.effect("an account with no password can be given one, and signs in with it afterwards", () =>
    Effect.gen(function* () {
      const email = yield* uniqueEmail("dorothy")
      const { client } = yield* makeClient()
      const emails = yield* AuthTest.TestEmails
      const accounts = yield* Stores.AccountStore

      yield* client.auth.signUpEmail({
        payload: { name: "Dorothy Vaughan", email, password: Redacted.make(password) }
      })
      const verification = yield* emails.tokenFor("verification", email)
      yield* client.auth.verifyEmail({ query: { token: Redacted.value(verification) } })
      const signedIn = completeSignIn(
        yield* client.auth.signInEmail({
          payload: { email, password: Redacted.make(password) }
        })
      )

      // The shape `POST /auth/set-password` exists for is an account provisioned
      // through a provider: a session, and no credential to sign in with. The
      // example has no provider configured, so the store makes one — dropping the
      // credential row leaves exactly that account behind.
      const removed = yield* accounts.deleteByUserId(signedIn.user.id)
      assert.strictEqual(removed, 1)

      const noCredential = yield* Effect.flip(
        client.auth.signInEmail({ payload: { email, password: Redacted.make(password) } })
      )
      assert.strictEqual(noCredential._tag, "InvalidCredentials")

      // The session is untouched by any of that, and it is fresh, so the account
      // may give itself a first password.
      const set = yield* client.auth.setPassword({
        payload: { newPassword: Redacted.make(newPassword) }
      })
      assert.strictEqual(set.success, true)

      // It is a first password, never a replacement: asking twice is refused.
      const again = yield* Effect.flip(client.auth.setPassword({ payload: { newPassword: Redacted.make(password) } }))
      assert.strictEqual(again._tag, "PasswordAlreadySet")

      const back = completeSignIn(
        yield* client.auth.signInEmail({
          payload: { email, password: Redacted.make(newPassword) }
        })
      )
      assert.strictEqual(back.user.id, signedIn.user.id)
    })
  )

  it.effect("an e-mailed code signs a stranger in, and provisions the account it names", () =>
    Effect.gen(function* () {
      const email = yield* uniqueEmail("mary")
      const { client, cookies } = yield* makeClient()
      const emails = yield* AuthTest.TestEmails

      // The plugin's endpoint, on the application's own composed API. It answers
      // 200 for every well-formed address — this one has no account at all.
      const acknowledged = yield* client.emailOtp.send({
        payload: { email, name: "Mary Jackson", purpose: "signIn", callbackURL: "/welcome" }
      })
      assert.strictEqual(acknowledged.success, true)

      // The message went to the address, with no user behind it: that `null` is
      // why the plugin carries a mailer of its own instead of a method on
      // `AuthEmails`.
      const code = yield* EmailOtpTest.awaitCode(email)
      const delivered = yield* emails.last(EmailOtpTest.emailOtpKind, email)
      assert.strictEqual(Option.isSome(delivered), true)
      if (Option.isSome(delivered)) assert.strictEqual(delivered.value.user, null)

      // `verify` claims the challenge, creates the account, answers a session
      // and sets the cookie. The handle rode in a cookie of its own, which the
      // jar carried back for us.
      const verified = yield* client.emailOtp.verify({ payload: { code } })
      assert.strictEqual(verified._tag, "SignedIn")
      if (verified._tag !== "SignedIn") return
      assert.strictEqual(verified.user.email, email)
      // Answered a code that was delivered to the address, so it is proven.
      assert.strictEqual(verified.user.emailVerified, true)
      assert.notStrictEqual(yield* cookieValue(cookies), "<absent>")

      // The plugin's group is not parameterized by this deployment's user fields,
      // so `verify` answers the base projection — the custom column is one
      // `GET /auth/session` away, and the cookie it just set works immediately.
      // The account was provisioned through the base-typed `UserStore`, and the
      // model's default filled `plan` in anyway.
      const session = yield* client.auth.getSession()
      assert.strictEqual(session.user.id, verified.user.id)
      assert.strictEqual(session.user.plan, "free")

      // A code is spendable exactly once, and the link minted beside it went
      // with it: both are the same row's two doors.
      const replayed = yield* Effect.flip(client.emailOtp.verify({ payload: { code } }))
      assert.strictEqual(replayed._tag, "InvalidCode")
    })
  )
})
