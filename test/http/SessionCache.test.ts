import { assert, layer } from "@effect/vitest"
import { DateTime, Duration, Effect, Encoding, Option, Redacted, Result } from "effect"
import { AuthConfig } from "../../src/config/AuthConfig.js"
import * as HmacCrypto from "../../src/crypto/Hmac.js"
import { baseUserModel, Session, SessionId, UserId } from "../../src/domain/Schema.js"
import { refreshDueAt } from "../../src/domain/Sessions.js"
import {
  cacheCookieSeparator,
  cacheExpiry,
  macContext,
  make as makeSessionCache,
  SessionCache,
  sessionSnapshot
} from "../../src/http/SessionCache.js"
import { ambientCrypto, encodeUtf8 } from "../../src/internal/crypto.js"
import { AuthTest } from "../../src/testing/index.js"
import { expectSome, signUpUser, uniqueEmail } from "../fixtures.js"

layer(AuthTest.layer({ cookieCache: { enabled: true } }))("http/SessionCache", (it) => {
  it.effect("round-trips a snapshot through the signed cookie value", () =>
    Effect.gen(function* () {
      const cache = yield* SessionCache
      const { session, user } = yield* signUpUser(uniqueEmail("cache-roundtrip"))
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
    })
  )

  it.effect("writes the envelope this module built by hand before Hmac grew one", () =>
    Effect.gen(function* () {
      const cache = yield* SessionCache
      const hmac = yield* HmacCrypto.Hmac
      const { session, user } = yield* signUpUser(uniqueEmail("cache-envelope"))
      const now = yield* DateTime.now

      const value = yield* cache.encode({
        version: "",
        tokenHash: session.tokenHash,
        expiresAt: DateTime.addDuration(now, Duration.minutes(5)),
        session,
        user
      })

      // The construction this module wrote inline until `Hmac.signedValue`
      // took it over: `base64url(payload) "." base64url(mac over context ‖
      // payload)`. Recomputed here from the payload the envelope carries, so
      // this fails the moment the format moves — which would silently make
      // every outstanding snapshot in every browser a miss.
      const at = value.indexOf(cacheCookieSeparator)
      const json = Result.getOrThrow(Encoding.decodeBase64UrlString(value.slice(0, at)))
      const mac = yield* hmac.sign(encodeUtf8(`${macContext}${json}`))
      assert.strictEqual(
        value,
        `${Encoding.encodeBase64Url(json)}${cacheCookieSeparator}${Encoding.encodeBase64Url(mac)}`
      )
      // And the separator is the envelope's own, not a second spelling of it.
      assert.strictEqual(cacheCookieSeparator, HmacCrypto.signedValueSeparator)
    })
  )

  it.effect("refuses a payload that was edited, and a tag that was", () =>
    Effect.gen(function* () {
      const cache = yield* SessionCache
      const { session, user } = yield* signUpUser(uniqueEmail("cache-tamper"))
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
    })
  )

  it.effect("keeps the token hash out of the session half of a snapshot", () =>
    Effect.gen(function* () {
      const { session } = yield* signUpUser(uniqueEmail("cache-snapshot"))
      const snapshot = yield* sessionSnapshot(session)

      assert.isFalse("tokenHash" in snapshot)
      assert.strictEqual(snapshot["id"], session.id)
    })
  )

  it.effect("expires a snapshot at the first of the three bounds", () =>
    Effect.gen(function* () {
      const config = yield* AuthConfig
      const { session } = yield* signUpUser(uniqueEmail("cache-expiry"))
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
    })
  )

  it.effect("never outlives the session itself, whatever the other two bounds say", () =>
    Effect.gen(function* () {
      const config = yield* AuthConfig
      const now = yield* DateTime.now
      // A session with a minute left: shorter than the five minute cache
      // lifetime, and shorter than the granted lifetime the refresh instant is
      // derived from — so the third bound is the one that binds.
      const ending = Session.make({
        id: SessionId.make("0193f6f0-0000-7000-8000-0000000000ca"),
        tokenHash: "not-the-raw-token",
        userId: UserId.make("0193f6f0-0000-7000-8000-0000000000cb"),
        expiresAt: DateTime.addDuration(now, Duration.minutes(1)),
        ipAddress: null,
        userAgent: null,
        rememberMe: true,
        authenticatedAt: now,
        aal: "aal1",
        methods: [],
        createdAt: now,
        updatedAt: now
      })

      assert.isTrue(DateTime.isLessThan(ending.expiresAt, refreshDueAt(ending, config)))
      assert.strictEqual(
        DateTime.toEpochMillis(cacheExpiry(config, ending, now)),
        DateTime.toEpochMillis(ending.expiresAt)
      )
    })
  )

  it.effect("refuses a snapshot another deployment's secret signed", () =>
    Effect.gen(function* () {
      const cache = yield* SessionCache
      const { session, user } = yield* signUpUser(uniqueEmail("cache-secret"))
      const now = yield* DateTime.now
      const payload = {
        version: "",
        tokenHash: session.tokenHash,
        expiresAt: DateTime.addDuration(now, Duration.minutes(5)),
        session,
        user
      }

      // The same deployment in every respect but the key the tag is computed
      // with — which is what rotating `AuthConfig.secret` produces.
      const rogue = yield* makeSessionCache(baseUserModel).pipe(
        Effect.provideService(
          HmacCrypto.Hmac,
          yield* HmacCrypto.make(ambientCrypto(), Redacted.make("another deployment's secret entirely"))
        )
      )

      const ours = yield* cache.encode(payload)
      const theirs = yield* rogue.encode(payload)

      // Neither one reads the other's, and a rotation is therefore mass cache
      // invalidation rather than a decode this deployment would act on.
      assert.isTrue(Option.isNone(yield* cache.decode(theirs)))
      assert.isTrue(Option.isNone(yield* rogue.decode(ours)))
      // Each still reads its own, so what failed above is the tag and nothing
      // about the payload.
      assert.isTrue(Option.isSome(yield* cache.decode(ours)))
      assert.isTrue(Option.isSome(yield* rogue.decode(theirs)))
    })
  )

  it.effect("refuses a tag the shared Hmac produced for something that is not a snapshot", () =>
    Effect.gen(function* () {
      const cache = yield* SessionCache
      const hmac = yield* HmacCrypto.Hmac
      const { session, user } = yield* signUpUser(uniqueEmail("cache-domain"))
      const now = yield* DateTime.now

      const value = yield* cache.encode({
        version: "",
        tokenHash: session.tokenHash,
        expiresAt: DateTime.addDuration(now, Duration.minutes(5)),
        session,
        user
      })
      const json = value.split(".")[0]!

      // `Hmac` is published for plugins to sign values of their own with. One
      // that signed a caller-influenced JSON document would otherwise be a tag
      // factory for this cookie: the envelope alone verifies, and a forged
      // snapshot is a request served as somebody else with no database read at
      // all. The MAC covers a context string this module alone writes, so a tag
      // over the bare payload is not a tag for a snapshot.
      const decoded = Encoding.decodeBase64UrlString(json)
      if (Result.isFailure(decoded)) {
        assert.fail("the payload half should be base64url")
      }
      const bare = yield* hmac.sign(encodeUtf8(decoded.success))
      assert.isTrue(Option.isNone(yield* cache.decode(`${json}.${Encoding.encodeBase64Url(bare)}`)))

      // The same bytes with the context in front are the tag this module wrote.
      assert.isTrue(Option.isSome(yield* cache.decode(value)))
    })
  )

  // Nested rather than a `describe` that provides `AuthTest.layer()` inside the
  // test body: an `it.layer` forks this block's memo map, so the deployment
  // whose only difference is the configuration inherits the PGlite this block
  // already booted instead of booting one to read a boolean.
  it.layer(AuthTest.layer())("with no deployment asking for it", (it) => {
    it.effect("is still provided, switched off", () =>
      Effect.gen(function* () {
        const cache = yield* SessionCache
        assert.isFalse(cache.enabled)
      })
    )
  })
})
