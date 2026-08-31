import { assert, describe, layer } from "@effect/vitest"
import { Duration, Effect, Layer, Option, Redacted, Ref } from "effect"
import { TestClock } from "effect/testing"
import type { HttpClientResponse } from "effect/unstable/http"
import { Cookies } from "effect/unstable/http"
import { insecureSessionCacheCookieName, secureSessionCacheCookieName } from "../../src/http/Cookies.js"
import { SessionCache } from "../../src/http/SessionCache.js"
import { AuthTest, TestHttpClient } from "../../src/testing/index.js"
import { expectSome, newPassword, testName, testPassword, testPasswordText, uniqueEmail } from "../fixtures.js"

/**
 * The counter every assertion in this file reads.
 *
 * **Gotchas**
 *
 * One counter for the whole block, so the block runs sequentially: a concurrent
 * sibling's session lookup would land in the same tally. Every deployment in
 * this file — the nested variants included — wraps the same counter, so a test
 * reads it immediately before the request it is about rather than assuming a
 * number.
 */
const store = AuthTest.countingSessionStore()

const cached = AuthTest.layerHttp({ cookieCache: { enabled: true }, sessionStore: store.layer })

/**
 * A deployment with a `TestClock` of its own, which a test may move.
 *
 * **Gotchas**
 *
 * The clock has to be part of the deployment: `HttpApiBuilder` captures each
 * handler's services when the layer is built, so a clock provided inside a test
 * body would govern the client and nothing behind the router.
 *
 * And it has to be a *new* deployment rather than {@link cached} with a clock
 * piped onto it: a nested `it.layer` inherits the enclosing block's memo map, so
 * re-using that layer value would resolve to the build the block above already
 * made — on the block's own clock, which the fresh one would then not be.
 */
const movingClock = AuthTest
  .layerHttp({ cookieCache: { enabled: true }, sessionStore: store.layer })
  .pipe(Layer.provideMerge(Layer.fresh(TestClock.layer())))

const makeClient = (options?: TestHttpClient.ClientOptions) =>
  TestHttpClient.makeClient(AuthTest.TestApi, options)

const signedUp = (email: string, options?: TestHttpClient.ClientOptions) =>
  TestHttpClient.signedUp({ ...options, email, name: testName, password: testPasswordText })

/** The `Max-Age` a response's *cache* cookie was written with, in seconds. */
const cacheMaxAgeSeconds = (
  response: HttpClientResponse.HttpClientResponse,
  name: string = insecureSessionCacheCookieName
): number | undefined => {
  const cookie = TestHttpClient.responseCacheCookie(response, name)
  if (Option.isNone(cookie)) return undefined
  const maxAge = cookie.value.options?.maxAge
  return maxAge === undefined ? undefined : Duration.toSeconds(Duration.fromInputUnsafe(maxAge))
}

/** The value of a cookie a response wrote, or `"<absent>"` when it wrote none. */
const writtenValue = (cookie: Option.Option<Cookies.Cookie>): string =>
  Option.match(cookie, { onNone: () => "<absent>", onSome: (found) => found.value })

/** The five minute default the cookie cache is written with. */
const defaultCacheSeconds = 300

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

    it.effect("refuses a snapshot minted for another browser's session", () =>
      Effect.gen(function*() {
        const email = uniqueEmail("cache-binding")
        const first = yield* signedUp(email)
        const mine = yield* first.client.auth.getSession()
        const stolen = yield* expectSome(
          yield* TestHttpClient.sessionCacheCookie(first.cookies),
          "the first browser should hold a snapshot"
        )

        // The same account in a second browser: a different session row, and
        // therefore a different token.
        const second = yield* makeClient()
        yield* second.client.auth.signInEmail({ payload: { email, password: testPassword } })
        const theirs = yield* second.client.auth.getSession()
        assert.notStrictEqual(theirs.session.id, mine.session.id)

        // The first browser's snapshot, presented beside the second browser's
        // session cookie. It verifies — it is this deployment's own signature —
        // and it is still refused, because `tokenHash` binds it to a token this
        // request did not present.
        yield* Ref.update(second.cookies, Cookies.setUnsafe(insecureSessionCacheCookieName, stolen.value))

        const before = store.state.reads
        const [session, response] = yield* second.client.auth.getSession({
          responseMode: "decoded-and-response"
        })

        assert.strictEqual(store.state.reads, before + 1, "a snapshot that is not this session's is a miss")
        assert.strictEqual(session.session.id, theirs.session.id)
        assert.strictEqual(session.user.email, email)
        // And the miss replaced it with this browser's own.
        assert.isTrue(Option.isSome(TestHttpClient.responseCacheCookie(response)))
      }))

    it.effect("writes no snapshot from an endpoint that must see the row", () =>
      Effect.gen(function*() {
        const { client } = yield* signedUp(uniqueEmail("cache-authoritative-write"))
        yield* client.auth.getSession()

        const before = store.state.reads
        const [, response] = yield* client.auth.changePassword({
          payload: { currentPassword: testPassword, newPassword },
          responseMode: "decoded-and-response"
        })

        assert.strictEqual(store.state.reads, before + 1, "an authoritative endpoint reads")
        // Bypassed in both directions: a snapshot taken here would be one this
        // endpoint had already decided not to trust.
        assert.isTrue(Option.isNone(TestHttpClient.responseCacheCookie(response)))
      }))

    it.effect("clears both cookies when every session is revoked", () =>
      Effect.gen(function*() {
        const { client, cookies } = yield* signedUp(uniqueEmail("cache-revoke-all"))
        yield* client.auth.getSession()

        const [, response] = yield* client.auth.revokeSessions({ responseMode: "decoded-and-response" })

        assert.strictEqual(writtenValue(TestHttpClient.responseCookie(response)), "")
        assert.strictEqual(writtenValue(TestHttpClient.responseCacheCookie(response)), "")
        assert.strictEqual(writtenValue(yield* TestHttpClient.sessionCacheCookie(cookies)), "")

        // Clearing only the session cookie would have left this browser signed
        // in behind a snapshot nothing reads the database for.
        const error = yield* Effect.flip(client.auth.getSession())
        assert.strictEqual(error._tag, "Unauthorized")
      }))

    it.effect("clears both cookies when a password reset ends every session", () =>
      Effect.gen(function*() {
        const email = uniqueEmail("cache-reset")
        const { client } = yield* signedUp(email)
        const emails = yield* AuthTest.TestEmails
        yield* client.auth.getSession()

        yield* client.auth.requestPasswordReset({ payload: { email } })
        const sent = yield* expectSome(
          yield* emails.last(AuthTest.resetKind, email),
          "a reset e-mail should have gone out"
        )

        const [, response] = yield* client.auth.resetPassword({
          payload: { token: Redacted.make(TestHttpClient.tokenOf(sent)), newPassword },
          responseMode: "decoded-and-response"
        })

        assert.strictEqual(writtenValue(TestHttpClient.responseCookie(response)), "")
        assert.strictEqual(writtenValue(TestHttpClient.responseCacheCookie(response)), "")

        const error = yield* Effect.flip(client.auth.getSession())
        assert.strictEqual(error._tag, "Unauthorized")
      }))

    it.effect("leaves a bearer client out of it entirely", () =>
      Effect.gen(function*() {
        const browser = yield* signedUp(uniqueEmail("cache-bearer"))
        const token = yield* TestHttpClient.sessionCookieValue(browser.cookies)
        const api = yield* makeClient({ bearerToken: () => token })

        const before = store.state.reads
        const [, first] = yield* api.client.auth.getSession({ responseMode: "decoded-and-response" })
        const [, second] = yield* api.client.auth.getSession({ responseMode: "decoded-and-response" })

        // A header-only client has no jar to write to, and letting a cookie
        // decide what such a request sees is exactly what must not happen.
        assert.strictEqual(store.state.reads, before + 2, "every bearer request reads the session")
        assert.isTrue(Option.isNone(TestHttpClient.responseCacheCookie(first)))
        assert.isTrue(Option.isNone(TestHttpClient.responseCacheCookie(second)))
        assert.isTrue(Option.isNone(yield* TestHttpClient.sessionCacheCookie(api.cookies)))
      }))

    // A configuration variant: everything above the database is rebuilt for the
    // sub-block, and the database itself is inherited from the block above.
    it.layer(AuthTest.layerHttp({
      cookieCache: { enabled: true, version: "v2" },
      sessionStore: store.layer
    }))("when the version has been bumped", (it) => {
      it.effect("misses a snapshot written under the old version, then hits the new one", () =>
        Effect.gen(function*() {
          const { client, cookies } = yield* signedUp(uniqueEmail("cache-version"))
          const cache = yield* SessionCache
          yield* client.auth.getSession()

          const written = yield* expectSome(
            yield* TestHttpClient.sessionCacheCookie(cookies),
            "the first request should have written a snapshot"
          )
          const snapshot = yield* expectSome(
            yield* cache.decode(written.value),
            "this deployment should read back what it just wrote"
          )

          // The same snapshot, signed by this same deployment, claiming the
          // version it ran under before the bump. Nothing about it is forged:
          // what is stale is the version alone.
          const stale = yield* cache.encode({ ...snapshot, version: "v1" })
          yield* Ref.update(cookies, Cookies.setUnsafe(insecureSessionCacheCookieName, stale))

          const before = store.state.reads
          const [session, missed] = yield* client.auth.getSession({ responseMode: "decoded-and-response" })

          assert.strictEqual(store.state.reads, before + 1, "a bumped version invalidates every snapshot")
          assert.strictEqual(session.session.id, snapshot.session.id)
          assert.isTrue(Option.isSome(TestHttpClient.responseCacheCookie(missed)))

          // One miss, and one only: what the miss wrote carries the current
          // version.
          const [, hit] = yield* client.auth.getSession({ responseMode: "decoded-and-response" })
          assert.strictEqual(store.state.reads, before + 1)
          assert.isTrue(Option.isNone(TestHttpClient.responseCacheCookie(hit)))
        }))
    })

    it.layer(AuthTest.layerHttp({
      cookieCache: { enabled: true },
      cookie: { secure: true },
      sessionStore: store.layer
    }))("when the deployment is served over TLS", (it) => {
      it.effect("writes and reads the snapshot under the __Secure- name", () =>
        Effect.gen(function*() {
          const { client } = yield* signedUp(uniqueEmail("cache-secure"))
          const [, first] = yield* client.auth.getSession({ responseMode: "decoded-and-response" })

          const cookie = yield* expectSome(
            TestHttpClient.responseCacheCookie(first, secureSessionCacheCookieName),
            "the prefixed cache cookie name was not used"
          )
          assert.strictEqual(cookie.options?.secure, true)
          assert.strictEqual(cookie.options?.httpOnly, true)
          // One name, not both: the un-prefixed twin is a name a plain-HTTP
          // sibling origin can set, so this deployment neither writes nor reads
          // it.
          assert.isTrue(Option.isNone(TestHttpClient.responseCacheCookie(first)))

          const before = store.state.reads
          yield* client.auth.getSession()
          assert.strictEqual(store.state.reads, before, "the prefixed snapshot is read back")

          // And it is the prefixed one that sign-out expires.
          const [, out] = yield* client.auth.signOut({ responseMode: "decoded-and-response" })
          assert.strictEqual(
            writtenValue(TestHttpClient.responseCacheCookie(out, secureSessionCacheCookieName)),
            ""
          )
        }))
    })

    it.layer(AuthTest.layerHttp({ sessionStore: store.layer }))(
      "when the deployment did not opt in",
      (it) => {
        it.effect("writes no snapshot at all, and reads the session every time", () =>
          Effect.gen(function*() {
            const { client, cookies } = yield* signedUp(uniqueEmail("cache-off"))

            const before = store.state.reads
            const [, first] = yield* client.auth.getSession({ responseMode: "decoded-and-response" })
            const [, second] = yield* client.auth.getSession({ responseMode: "decoded-and-response" })

            assert.strictEqual(store.state.reads, before + 2, "the default deployment caches nothing")
            assert.isTrue(Option.isNone(TestHttpClient.responseCacheCookie(first)))
            assert.isTrue(Option.isNone(TestHttpClient.responseCacheCookie(second)))
            assert.isTrue(Option.isNone(yield* TestHttpClient.sessionCacheCookie(cookies)))

            // Nor does sign-out expire a cookie this deployment never wrote.
            const [, out] = yield* client.auth.signOut({ responseMode: "decoded-and-response" })
            assert.isTrue(Option.isNone(TestHttpClient.responseCacheCookie(out)))
          }))
      }
    )

    it.layer(movingClock)("as time passes", (it) => {
      describe.sequential("on the deployment's own clock", () => {
        it.effect("clamps the snapshot to the refresh instant, and refreshes when it arrives", () =>
          Effect.gen(function*() {
            const { client } = yield* signedUp(uniqueEmail("cache-clamp"))

            // A fresh seven-day session becomes refresh-due in a day, so the
            // five minute cache lifetime is what binds.
            const [, first] = yield* client.auth.getSession({ responseMode: "decoded-and-response" })
            assert.strictEqual(cacheMaxAgeSeconds(first), defaultCacheSeconds)

            // Two minutes before the rolling refresh is due. The snapshot from
            // a day ago is long gone, so this request reaches the database —
            // and the one it leaves behind may not outlive the refresh.
            yield* TestClock.adjust(Duration.minutes(24 * 60 - 2))
            const touches = store.state.touches
            const [, clamped] = yield* client.auth.getSession({ responseMode: "decoded-and-response" })

            assert.strictEqual(store.state.touches, touches, "not yet due for a refresh")
            assert.strictEqual(cacheMaxAgeSeconds(clamped), 120)
            assert.isTrue(Option.isNone(TestHttpClient.responseCookie(clamped)))

            // Past the refresh instant: the snapshot has expired exactly when
            // the rolling refresh became due, so this request rolls the expiry
            // forward, re-sends the session cookie, and starts a fresh window.
            yield* TestClock.adjust(Duration.minutes(3))
            const [, refreshed] = yield* client.auth.getSession({ responseMode: "decoded-and-response" })

            assert.strictEqual(store.state.touches, touches + 1, "the refresh happens when it always did")
            assert.isTrue(Option.isSome(TestHttpClient.responseCookie(refreshed)))
            assert.strictEqual(cacheMaxAgeSeconds(refreshed), defaultCacheSeconds)
          }))

        it.effect("keeps answering a session revoked elsewhere until the snapshot expires", () =>
          Effect.gen(function*() {
            const email = uniqueEmail("cache-revoked-elsewhere")
            const owner = yield* signedUp(email)
            const other = yield* makeClient()
            yield* other.client.auth.signInEmail({ payload: { email, password: testPassword } })
            // The second browser's first authenticated request takes a snapshot.
            yield* other.client.auth.getSession()

            // The owner ends every session but their own — the second browser's
            // row is gone from the database.
            yield* owner.client.auth.revokeOtherSessions()

            const before = store.state.reads
            const stale = yield* other.client.auth.getSession()
            assert.strictEqual(store.state.reads, before, "a valid snapshot is served without a read")
            assert.strictEqual(stale.user.email, email)

            // This is the documented cost, and this is its exact size: once the
            // snapshot expires the next request reaches the database and the
            // revocation bites.
            yield* TestClock.adjust(Duration.minutes(6))
            const refused = yield* Effect.flip(other.client.auth.getSession())
            assert.strictEqual(refused._tag, "Unauthorized")
          }))
      })
    })
  })
})
