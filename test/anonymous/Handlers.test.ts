import { assert, describe, layer } from "@effect/vitest"
import { Effect, Option } from "effect"
import { Anonymous, isSyntheticEmail } from "../../src/anonymous/index.js"
import { UserStore } from "../../src/domain/Stores.js"
import * as AnonymousTest from "../../src/testing/AnonymousTest.js"
import * as TestHttpClient from "../../src/testing/TestHttpClient.js"
import { testName, testPassword, uniqueEmail } from "../fixtures.js"

/** A browser addressing this block's deployment, with a jar the test can read. */
const makeClient = (options?: TestHttpClient.ClientOptions) => TestHttpClient.makeClient(AnonymousTest.TestApi, options)

describe.sequential("anonymous/Handlers", () => {
  layer(AnonymousTest.layerHttp())("the endpoints", (it) => {
    it.effect("takes no body, sets a session cookie, and answers a visitor at aal0", () =>
      Effect.gen(function* () {
        const { client, cookies } = yield* makeClient()

        const result = yield* client.anonymous.signIn()
        assert.isTrue(isSyntheticEmail(result.user.email))
        assert.strictEqual(result.session.aal, "aal0")
        assert.deepStrictEqual([...result.session.methods], [])
        assert.isTrue(Option.isSome(yield* TestHttpClient.sessionCookie(cookies)))

        // The cookie it wrote is a working session.
        const session = yield* client.auth.getSession()
        assert.strictEqual(session.user.id, result.user.id)
      })
    )

    it.effect("lets a visitor adopt their own account in place", () =>
      Effect.gen(function* () {
        const anonymous = yield* Anonymous
        const { client } = yield* makeClient()
        const result = yield* client.anonymous.signIn()

        // `setPassword` carries the empty freshness policy, which admits aal0 —
        // so acquiring a first credential is reachable without first becoming
        // somebody, which is what adoption in place means.
        yield* client.auth.setPassword({ payload: { newPassword: testPassword } })

        // And the plugin's own seam then clears the marker, because the account
        // now really does hold a way in.
        assert.strictEqual(yield* anonymous.adopt({ userId: result.user.id }), "Adopted")
        assert.isFalse(yield* anonymous.isAnonymous(result.user.id))
      })
    )

    it.effect("discards the visitor, clears the cookies, and refuses a real account", () =>
      Effect.gen(function* () {
        const users = yield* UserStore
        const { client } = yield* makeClient()
        const visitor = yield* client.anonymous.signIn()

        assert.deepStrictEqual(yield* client.anonymous.delete(), { success: true })
        assert.isTrue(Option.isNone(yield* users.findById(visitor.user.id)))
        // The cookie went with the row, so the browser is signed out.
        const after = yield* Effect.flip(client.auth.getSession())
        assert.strictEqual(after._tag, "Unauthorized")

        const { client: member } = yield* makeClient()
        yield* member.auth.signUpEmail({
          payload: { name: testName, email: uniqueEmail("http-real"), password: testPassword }
        })
        const refused = yield* Effect.flip(member.anonymous.delete())
        assert.strictEqual(refused._tag, "NotAnonymous")
      })
    )

    it.effect("requires a session to discard one", () =>
      Effect.gen(function* () {
        const { client } = yield* makeClient()
        const failure = yield* Effect.flip(client.anonymous.delete())
        assert.strictEqual(failure._tag, "Unauthorized")
      })
    )

    it.effect("refuses a cross-origin sign-in that names an untrusted origin", () =>
      Effect.gen(function* () {
        // The endpoint writes two rows for a caller who has proved nothing, and
        // a cross-origin form post reaches it carrying no cookie at all — which
        // is exactly what the Authenticated middleware's origin check cannot see.
        const { client } = yield* makeClient({ headers: { origin: "https://evil.test" } })
        const failure = yield* Effect.flip(client.anonymous.signIn())
        assert.strictEqual(failure._tag, "OriginNotAllowed")
      })
    )

    it.effect("passes a request that names no origin at all", () =>
      Effect.gen(function* () {
        // A server-to-server caller attaches none, and no cross-site defence is
        // relevant to it.
        const { client } = yield* makeClient()
        const result = yield* client.anonymous.signIn()
        assert.isTrue(isSyntheticEmail(result.user.email))
      })
    )
  })

  layer(AnonymousTest.layerHttp())("merge on sign-in, over HTTP", (it) => {
    it.effect("upgrades the browser: the visitor is merged away and the account survives", () =>
      Effect.gen(function* () {
        const anonymous = yield* Anonymous
        const users = yield* UserStore
        const { client } = yield* makeClient()

        // One browser, one jar. It browses as a visitor …
        const visitor = yield* client.anonymous.signIn()
        assert.isTrue(yield* anonymous.isAnonymous(visitor.user.id))

        // … and then signs in to the account it had all along. The cookie the
        // visitor session set rides along, which is the whole seam: nothing in
        // the payload says "I was somebody else".
        const email = uniqueEmail("http-merge")
        yield* client.auth.signUpEmail({ payload: { name: testName, email, password: testPassword } })
        yield* client.auth.signOut()
        yield* client.anonymous.signIn()
        const second = yield* client.anonymous.signIn()

        const signedIn = yield* client.auth.signInEmail({ payload: { email, password: testPassword } })
        assert.isFalse("_tag" in signedIn)
        if ("_tag" in signedIn) return

        // The visitor the browser was carrying is gone; the account is not, and
        // the browser now holds its session.
        assert.isTrue(Option.isNone(yield* users.findById(second.user.id)))
        assert.notStrictEqual(signedIn.user.id, second.user.id)
        const session = yield* client.auth.getSession()
        assert.strictEqual(session.user.email, email)
      })
    )

    it.effect("leaves a browser carrying no session alone", () =>
      Effect.gen(function* () {
        const users = yield* UserStore
        const email = uniqueEmail("http-no-merge")
        const { client } = yield* makeClient()
        yield* client.auth.signUpEmail({ payload: { name: testName, email, password: testPassword } })
        yield* client.auth.signOut()

        const signedIn = yield* client.auth.signInEmail({ payload: { email, password: testPassword } })
        assert.isFalse("_tag" in signedIn)
        if ("_tag" in signedIn) return
        assert.isTrue(Option.isSome(yield* users.findById(signedIn.user.id)))
      })
    )
  })

  layer(AnonymousTest.layerHttp({ rateLimit: { enabled: true, ipHeaders: ["x-forwarded-for"] } }))(
    "with rate limiting on",
    (it) => {
      it.effect("limits how many visitors one client may invent", () =>
        Effect.gen(function* () {
          const { client } = yield* makeClient({ headers: { "x-forwarded-for": "198.51.100.9" } })
          // Five a minute; the sixth is refused.
          for (let attempt = 0; attempt < 5; attempt++) {
            yield* client.anonymous.signIn()
          }
          const limited = yield* Effect.flip(client.anonymous.signIn())
          assert.strictEqual(limited._tag, "RateLimited")

          // A different client has its own allowance: the bucket is per caller,
          // not global.
          const { client: other } = yield* makeClient({ headers: { "x-forwarded-for": "198.51.100.10" } })
          yield* other.anonymous.signIn()
        })
      )
    }
  )
})
