import { assert, describe, layer } from "@effect/vitest"
import { Effect, Option, Redacted, Ref } from "effect"
import { Cookies } from "effect/unstable/http"
import { insecureSessionCacheCookieName } from "../../src/http/Cookies.js"
import { AuthTest, TestHttpClient } from "../../src/testing/index.js"
import { testName, testPasswordText, uniqueEmail } from "../fixtures.js"

/**
 * The counter every assertion in this file reads.
 *
 * **Gotchas**
 *
 * One counter for the whole block, so the block runs sequentially: a concurrent
 * sibling's session lookup would land in the same tally.
 */
const store = AuthTest.countingSessionStore()

const cached = AuthTest.layerHttp({ cookieCache: { enabled: true }, sessionStore: store.layer })

const signedUp = (email: string, options?: TestHttpClient.ClientOptions) =>
  TestHttpClient.signedUp({ ...options, email, name: testName, password: testPasswordText })

describe.sequential("http/SessionCache over HTTP", () => {
  layer(cached)("enabled", (it) => {
    it.effect("serves a second request from the cookie, with no session read", () =>
      Effect.gen(function*() {
        const email = uniqueEmail("cache-hit")
        const { client, cookies } = yield* signedUp(email)

        // Sign-up establishes the session; the first authenticated request is
        // what reads it and writes the snapshot.
        const [fresh, first] = yield* client.auth.getSession({ responseMode: "decoded-and-response" })
        assert.isTrue(Option.isSome(TestHttpClient.responseCacheCookie(first)))
        assert.isTrue(Option.isSome(yield* TestHttpClient.sessionCacheCookie(cookies)))

        const before = store.state.reads
        const [session, second] = yield* client.auth.getSession({ responseMode: "decoded-and-response" })

        assert.strictEqual(store.state.reads, before, "a cache hit must not touch the session store")
        // And it answers with the same thing the database did.
        assert.strictEqual(session.session.id, fresh.session.id)
        assert.strictEqual(session.user.email, email)
        // A hit writes nothing: no session cookie, no fresh snapshot.
        assert.isTrue(Option.isNone(TestHttpClient.responseCacheCookie(second)))
        assert.isTrue(Option.isNone(TestHttpClient.responseCookie(second)))
      }))

    it.effect("falls back to the database when the snapshot is garbage", () =>
      Effect.gen(function*() {
        const email = uniqueEmail("cache-garbage")
        const { client, cookies } = yield* signedUp(email)
        yield* client.auth.getSession()

        yield* Ref.update(cookies, Cookies.setUnsafe(insecureSessionCacheCookieName, "not-a-snapshot"))

        const before = store.state.reads
        const [session, response] = yield* client.auth.getSession({ responseMode: "decoded-and-response" })

        assert.strictEqual(session.user.email, email)
        assert.strictEqual(store.state.reads, before + 1, "an unreadable snapshot is a miss")
        // And the miss leaves a fresh one behind.
        assert.isTrue(Option.isSome(TestHttpClient.responseCacheCookie(response)))
      }))

    it.effect("reads the database for an endpoint that must see the row", () =>
      Effect.gen(function*() {
        const { client } = yield* signedUp(uniqueEmail("cache-authoritative"))
        yield* client.auth.getSession()

        const before = store.state.reads
        // `changePassword` is annotated `AuthoritativeSession`; the wrong
        // password is enough to prove the middleware went to the database first.
        const error = yield* Effect.flip(client.auth.changePassword({
          payload: {
            currentPassword: Redacted.make("not the password"),
            newPassword: Redacted.make("a new password entirely")
          }
        }))

        assert.strictEqual(error._tag, "InvalidCredentials")
        assert.strictEqual(store.state.reads, before + 1, "an authoritative endpoint bypasses the cache")
      }))

    it.effect("clears both cookies on sign-out", () =>
      Effect.gen(function*() {
        const { client, cookies } = yield* signedUp(uniqueEmail("cache-sign-out"))
        yield* client.auth.getSession()

        const [, response] = yield* client.auth.signOut({ responseMode: "decoded-and-response" })

        assert.strictEqual(
          Option.getOrUndefined(Option.map(TestHttpClient.responseCookie(response), (cookie) => cookie.value)),
          ""
        )
        assert.strictEqual(
          Option.getOrUndefined(Option.map(TestHttpClient.responseCacheCookie(response), (cookie) => cookie.value)),
          ""
        )
        assert.strictEqual(yield* TestHttpClient.sessionCookieValue(cookies), "")

        const error = yield* Effect.flip(client.auth.getSession())
        assert.strictEqual(error._tag, "Unauthorized")
      }))
  })
})
