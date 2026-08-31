import { assert, describe, it, layer } from "@effect/vitest"
import { DateTime, Duration, Effect, Encoding, Option, Result } from "effect"
import { AuthConfig } from "../../src/config/AuthConfig.js"
import { Passwords } from "../../src/domain/Passwords.js"
import { refreshDueAt } from "../../src/domain/Sessions.js"
import { cacheExpiry, SessionCache, sessionSnapshot } from "../../src/http/SessionCache.js"
import { AuthTest } from "../../src/testing/index.js"
import { expectSome, testName, testPassword, uniqueEmail } from "../fixtures.js"

/** A session and its user, straight from a sign-up. */
const signedUp = (email: string) =>
  Effect.gen(function*() {
    const passwords = yield* Passwords
    const result = yield* passwords.signUp({ name: testName, email, password: testPassword })
    const created = yield* expectSome(result.session, "sign-up should establish a session")
    return { user: result.user, session: created.session, token: created.token }
  })

layer(AuthTest.layer({ cookieCache: { enabled: true } }))("http/SessionCache", (it) => {
  it.effect("round-trips a snapshot through the signed cookie value", () =>
    Effect.gen(function*() {
      const cache = yield* SessionCache
      const { session, user } = yield* signedUp(uniqueEmail("cache-roundtrip"))
      const now = yield* DateTime.now

      const value = yield* cache.encode({
        version: "",
        tokenHash: session.tokenHash,
        expiresAt: DateTime.addDuration(now, Duration.minutes(5)),
        session,
        user
      })
      const decoded = yield* expectSome(yield* cache.decode(value), "the value it just signed should decode")

      assert.strictEqual(decoded.session.id, session.id)
      assert.strictEqual(decoded.session.tokenHash, session.tokenHash)
      assert.strictEqual(decoded.user.id, user.id)
      assert.strictEqual(decoded.user.email, user.email)
    }))

  it.effect("refuses a payload that was edited, and a tag that was", () =>
    Effect.gen(function*() {
      const cache = yield* SessionCache
      const { session, user } = yield* signedUp(uniqueEmail("cache-tamper"))
      const now = yield* DateTime.now

      const value = yield* cache.encode({
        version: "",
        tokenHash: session.tokenHash,
        expiresAt: DateTime.addDuration(now, Duration.minutes(5)),
        session,
        user
      })
      const [payload, mac] = value.split(".")

      // The payload says somebody else's address, and the tag no longer covers
      // it.
      const raw = Encoding.decodeBase64UrlString(payload!)
      assert.isTrue(Result.isSuccess(raw))
      const edited = Result.isSuccess(raw) ? raw.success : ""
      const forged = `${Encoding.encodeBase64Url(edited.replace(user.email, "mallory@example.com"))}.${mac}`
      assert.isTrue(Option.isNone(yield* cache.decode(forged)))

      // The tag is somebody else's bytes.
      assert.isTrue(Option.isNone(yield* cache.decode(`${payload}.${Encoding.encodeBase64Url("not-a-tag")}`)))

      // And a value that is not two halves at all.
      assert.isTrue(Option.isNone(yield* cache.decode(payload!)))
    }))

  it.effect("keeps the token hash out of the session half of a snapshot", () =>
    Effect.gen(function*() {
      const { session } = yield* signedUp(uniqueEmail("cache-snapshot"))
      const snapshot = yield* sessionSnapshot(session)

      assert.isFalse("tokenHash" in snapshot)
      assert.strictEqual(snapshot["id"], session.id)
    }))

  it.effect("expires a snapshot at the first of the three bounds", () =>
    Effect.gen(function*() {
      const config = yield* AuthConfig
      const { session } = yield* signedUp(uniqueEmail("cache-expiry"))
      const now = yield* DateTime.now

      // A fresh seven-day session becomes refresh-due in a day, so the five
      // minute cache lifetime is what binds.
      assert.strictEqual(
        DateTime.toEpochMillis(cacheExpiry(config, session, now)),
        DateTime.toEpochMillis(DateTime.addDuration(now, config.cookieCache.maxAge))
      )

      // A moment before the refresh is due, the refresh instant binds instead.
      const late = DateTime.subtractDuration(refreshDueAt(session, config), Duration.seconds(1))
      assert.strictEqual(
        DateTime.toEpochMillis(cacheExpiry(config, session, late)),
        DateTime.toEpochMillis(refreshDueAt(session, config))
      )
    }))
})

describe("http/SessionCache (disabled)", () => {
  it.effect("is still provided, switched off, when a deployment did not ask for it", () =>
    Effect.gen(function*() {
      const cache = yield* SessionCache
      assert.isFalse(cache.enabled)
    }).pipe(Effect.provide(AuthTest.layer())))
})
