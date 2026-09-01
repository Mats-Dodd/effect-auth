import { assert, describe, layer } from "@effect/vitest"
import { DateTime, Duration, Effect, Redacted } from "effect"
import { TestClock } from "effect/testing"
import { AuthConfig, make as makeAuthConfig } from "../../src/config/AuthConfig.js"
import { grantedLifetime, isFreshAt, refreshDueAt, Sessions } from "../../src/domain/Sessions.js"
import { SessionStore } from "../../src/domain/Stores.js"
import { AuthTest } from "../../src/testing/index.js"
import { forUser, signUpUser, uniqueEmail } from "../fixtures.js"

layer(AuthTest.layer())("domain/Sessions", (it) => {
  describe("create", () => {
    it.effect("mints a hashed session and returns the raw token exactly once", () =>
      Effect.gen(function*() {
        const sessions = yield* Sessions
        const config = yield* AuthConfig
        const { user } = yield* signUpUser(uniqueEmail("create"))

        const { session, token } = yield* sessions.create({
          userId: user.id,
          ipAddress: "203.0.113.7",
          userAgent: "vitest"
        })

        // The raw token never reaches the row.
        assert.notStrictEqual(session.tokenHash, Redacted.value(token))
        assert.strictEqual(Redacted.value(token).length, 43)
        assert.strictEqual(session.ipAddress, "203.0.113.7")
        // Absent `rememberMe` defaults to a remembered session.
        assert.strictEqual(session.rememberMe, true)

        const now = yield* DateTime.now
        const expected = DateTime.addDuration(now, config.session.expiresIn)
        assert.strictEqual(DateTime.toEpochMillis(session.expiresAt), DateTime.toEpochMillis(expected))

        const verified = yield* sessions.verify(token)
        assert.strictEqual(verified.session.id, session.id)
        assert.strictEqual(verified.user.id, user.id)
        assert.strictEqual(verified.refreshed, false)
        // The flag is on the verified session, where middleware reads it.
        assert.strictEqual(verified.session.rememberMe, true)
      }))

    it.effect("honours rememberMe: false with the short lifetime", () =>
      Effect.gen(function*() {
        const sessions = yield* Sessions
        const config = yield* AuthConfig
        const { user } = yield* signUpUser(uniqueEmail("remember-me"))

        const { session, token } = yield* sessions.create({ userId: user.id, rememberMe: false })

        // The choice is stored, not just consumed for the lifetime …
        assert.strictEqual(session.rememberMe, false)
        assert.strictEqual(
          Duration.toMillis(grantedLifetime(session, config)),
          Duration.toMillis(config.session.rememberMeDisabledExpiresIn)
        )
        assert.notStrictEqual(
          Duration.toMillis(config.session.rememberMeDisabledExpiresIn),
          Duration.toMillis(config.session.expiresIn)
        )

        // … so it is still there when the session is verified.
        const verified = yield* sessions.verify(token)
        assert.strictEqual(verified.session.rememberMe, false)
      }))
  })

  describe("verify", () => {
    it.effect("refuses an unknown token with Unauthorized", () =>
      Effect.gen(function*() {
        const sessions = yield* Sessions
        const failure = yield* Effect.flip(sessions.verify(Redacted.make("not-a-token")))
        assert.strictEqual(failure._tag, "Unauthorized")
      }))

    it.effect("rolls the expiry forward exactly once per updateAge", () =>
      AuthTest.freshClock(Effect.gen(function*() {
        const sessions = yield* Sessions
        const config = yield* AuthConfig
        const { user } = yield* signUpUser(uniqueEmail("update-age"))
        const created = yield* sessions.create({ userId: user.id })

        // One millisecond before the refresh is due: read-only.
        yield* TestClock.adjust(Duration.subtract(config.session.updateAge, Duration.millis(1)))
        const early = yield* sessions.verify(created.token)
        assert.strictEqual(early.refreshed, false)
        assert.strictEqual(
          DateTime.toEpochMillis(early.session.expiresAt),
          DateTime.toEpochMillis(created.session.expiresAt)
        )

        // The instant it is due: refreshed, and the expiry moves by exactly the
        // elapsed time, because a refresh writes `now + lifetime`.
        yield* TestClock.adjust(Duration.millis(1))
        const due = yield* sessions.verify(created.token)
        assert.strictEqual(due.refreshed, true)
        assert.strictEqual(
          DateTime.toEpochMillis(due.session.expiresAt) - DateTime.toEpochMillis(created.session.expiresAt),
          Duration.toMillis(config.session.updateAge)
        )

        // The window has reset: no second write on the next request.
        assert.strictEqual((yield* sessions.verify(created.token)).refreshed, false)

        // One more updateAge and it fires again — exactly once.
        yield* TestClock.adjust(config.session.updateAge)
        assert.strictEqual((yield* sessions.verify(created.token)).refreshed, true)
        assert.strictEqual((yield* sessions.verify(created.token)).refreshed, false)
      })))

    it.effect("fails SessionExpired past the expiry and drops the row", () =>
      AuthTest.freshClock(Effect.gen(function*() {
        const sessions = yield* Sessions
        const store = yield* SessionStore
        const config = yield* AuthConfig
        const { user } = yield* signUpUser(uniqueEmail("expiry"))
        const created = yield* sessions.create({ userId: user.id })

        yield* TestClock.adjust(Duration.sum(config.session.expiresIn, Duration.millis(1)))

        const failure = yield* Effect.flip(sessions.verify(created.token))
        assert.strictEqual(failure._tag, "SessionExpired")

        // The dead row is cleaned up on the way out, so a replay of the same
        // token is indistinguishable from one that never existed.
        const remaining = yield* store.findByTokenHash(created.session.tokenHash)
        assert.strictEqual(remaining._tag, "None")
        assert.strictEqual((yield* Effect.flip(sessions.verify(created.token)))._tag, "Unauthorized")
      })))

    // A configuration variant: everything above the database is rebuilt for
    // this sub-block, and the database itself is inherited from the block above.
    it.layer(AuthTest.layer({ session: { updateAge: Duration.hours(1) } }))(
      "with a one-hour updateAge",
      (it) => {
        it.effect("a refresh keeps a rememberMe:false session short", () =>
          AuthTest.freshClock(Effect.gen(function*() {
            const sessions = yield* Sessions
            const config = yield* AuthConfig
            const { user } = yield* signUpUser(uniqueEmail("short-refresh"))
            const created = yield* sessions.create({ userId: user.id, rememberMe: false })

            yield* TestClock.adjust(config.session.updateAge)
            const refreshed = yield* sessions.verify(created.token)
            assert.strictEqual(refreshed.refreshed, true)

            // The refresh must not promote a one-day session to the configured
            // seven-day lifetime.
            assert.strictEqual(
              Duration.toMillis(grantedLifetime(refreshed.session, config)),
              Duration.toMillis(config.session.rememberMeDisabledExpiresIn)
            )
          })))
      }
    )

    it.effect("rejects an updateAge longer than the short session lifetime", () =>
      Effect.sync(() => assert.throws(
        () => makeAuthConfig({
          baseUrl: AuthTest.testBaseUrl,
          secret: AuthTest.testSecret,
          session: { updateAge: Duration.days(3) }
        }),
        /updateAge must be shorter/
      )))
  })

  describe("freshness", () => {
    it.effect("is fresh until freshAge has elapsed since creation", () =>
      AuthTest.freshClock(Effect.gen(function*() {
        const sessions = yield* Sessions
        const config = yield* AuthConfig
        const { user } = yield* signUpUser(uniqueEmail("fresh"))
        const created = yield* sessions.create({ userId: user.id })

        assert.strictEqual(yield* sessions.isFresh(created.session), true)
        yield* sessions.requireFresh(created.session)

        yield* TestClock.adjust(Duration.subtract(config.session.freshAge, Duration.millis(1)))
        assert.strictEqual(yield* sessions.isFresh(created.session), true)

        yield* TestClock.adjust(Duration.millis(1))
        assert.strictEqual(yield* sessions.isFresh(created.session), false)

        const failure = yield* Effect.flip(sessions.requireFresh(created.session))
        assert.strictEqual(failure._tag, "SessionNotFresh")
        assert.strictEqual(failure.freshAgeSeconds, Duration.toSeconds(config.session.freshAge))
      })))

    it.effect("a rolling refresh does not restore freshness", () =>
      AuthTest.freshClock(Effect.gen(function*() {
        // Freshness tracks createdAt on purpose: a month of ordinary browsing is
        // not evidence that the account's owner is at the keyboard.
        const sessions = yield* Sessions
        const config = yield* AuthConfig
        const { user } = yield* signUpUser(uniqueEmail("stale"))
        const created = yield* sessions.create({ userId: user.id })

        yield* TestClock.adjust(Duration.sum(config.session.freshAge, Duration.millis(1)))
        const refreshed = yield* sessions.verify(created.token)
        assert.strictEqual(refreshed.refreshed, true)
        assert.strictEqual(yield* sessions.isFresh(refreshed.session), false)
      })))
  })

  describe("revocation", () => {
    it.effect("revoke removes one session and only the owner's", () =>
      Effect.gen(function*() {
        const sessions = yield* Sessions
        const ada = yield* signUpUser(uniqueEmail("ada"))
        const bob = yield* signUpUser(uniqueEmail("bob"))

        const { events } = yield* AuthTest.recordingEvents(sessions.revoke(ada.session.id, ada.user.id))
        assert.deepStrictEqual(AuthTest.tagsOf(forUser(events, ada.user.id)), ["SessionRevoked"])

        assert.strictEqual((yield* Effect.flip(sessions.verify(ada.token)))._tag, "Unauthorized")

        // Ada cannot revoke Bob's session by guessing its id.
        const stranger = yield* Effect.flip(sessions.revoke(bob.session.id, ada.user.id))
        assert.strictEqual(stranger._tag, "NotFound")
        assert.strictEqual((yield* sessions.verify(bob.token)).session.id, bob.session.id)
      }))

    it.effect("revokeOthers keeps the current session, revokeAll keeps none", () =>
      Effect.gen(function*() {
        const sessions = yield* Sessions
        const { user } = yield* signUpUser(uniqueEmail("devices"))
        const laptop = yield* sessions.create({ userId: user.id })
        const phone = yield* sessions.create({ userId: user.id })
        const tablet = yield* sessions.create({ userId: user.id })

        // Four: the one sign-up established, plus three.
        assert.strictEqual((yield* sessions.list(user.id)).length, 4)

        const others = yield* AuthTest.recordingEvents(sessions.revokeOthers(user.id, laptop.session.id))
        assert.strictEqual(others.result, 3)
        assert.deepStrictEqual(AuthTest.tagsOf(forUser(others.events, user.id)), ["SessionRevoked"])
        assert.strictEqual((yield* Effect.flip(sessions.verify(phone.token)))._tag, "Unauthorized")
        assert.strictEqual((yield* Effect.flip(sessions.verify(tablet.token)))._tag, "Unauthorized")
        assert.strictEqual((yield* sessions.verify(laptop.token)).session.id, laptop.session.id)

        assert.strictEqual(yield* sessions.revokeAll(user.id), 1)
        assert.strictEqual((yield* sessions.list(user.id)).length, 0)
      }))

    it.effect("list omits expired sessions", () =>
      AuthTest.freshClock(Effect.gen(function*() {
        const sessions = yield* Sessions
        const config = yield* AuthConfig
        const { user } = yield* signUpUser(uniqueEmail("listing"))
        yield* sessions.create({ userId: user.id, rememberMe: false })

        assert.strictEqual((yield* sessions.list(user.id)).length, 2)

        yield* TestClock.adjust(
          Duration.sum(config.session.rememberMeDisabledExpiresIn, Duration.millis(1))
        )
        assert.strictEqual((yield* sessions.list(user.id)).length, 1)
      })))
  })

  describe("arithmetic", () => {
    it.effect("refreshDueAt is expiresAt - expiresIn + updateAge for an ordinary session", () =>
      Effect.gen(function*() {
        const sessions = yield* Sessions
        const config = yield* AuthConfig
        const { user } = yield* signUpUser(uniqueEmail("arithmetic"))
        const { session } = yield* sessions.create({ userId: user.id })

        const expected = DateTime.addDuration(
          DateTime.subtractDuration(session.expiresAt, config.session.expiresIn),
          config.session.updateAge
        )
        assert.strictEqual(
          DateTime.toEpochMillis(refreshDueAt(session, config)),
          DateTime.toEpochMillis(expected)
        )

        const now = yield* DateTime.now
        assert.strictEqual(isFreshAt(session, config, now), true)
      }))
  })
})
