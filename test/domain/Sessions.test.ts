import { assert, describe, it } from "@effect/vitest"
import { DateTime, Duration, Effect, Redacted } from "effect"
import { TestClock } from "effect/testing"
import { AuthConfig } from "../../src/config/AuthConfig.js"
import { Passwords } from "../../src/domain/Passwords.js"
import { grantedLifetime, isFreshAt, refreshDueAt, Sessions } from "../../src/domain/Sessions.js"
import { SessionStore } from "../../src/domain/Stores.js"
import { expectSome, recordingEvents, tagsOf, testLayer, testTimeout } from "./harness.js"

/**
 * Registers a user and returns their first session.
 *
 * **Gotchas**
 *
 * Each test builds its own database and its own `TestClock`; sharing a layer
 * across a block would share the clock, and `TestClock.adjust` in one test
 * would move time under another.
 */
const signUp = Effect.fnUntraced(function*(email: string) {
  const passwords = yield* Passwords
  const result = yield* passwords.signUp({
    name: "Ada Lovelace",
    email,
    password: Redacted.make("correct-horse-battery")
  })
  const session = yield* expectSome(result.session, "sign-up should establish a session")
  return { user: result.user, ...session }
})

describe("domain/Sessions/create", () => {
  it.effect(
    "mints a hashed session and returns the raw token exactly once",
    () =>
      Effect.gen(function*() {
        const sessions = yield* Sessions
        const config = yield* AuthConfig
        const { user } = yield* signUp("ada@example.com")

        const { session, token } = yield* sessions.create({
          userId: user.id,
          ipAddress: "203.0.113.7",
          userAgent: "vitest"
        })

        // The raw token never reaches the row.
        assert.notStrictEqual(session.tokenHash, Redacted.value(token))
        assert.strictEqual(Redacted.value(token).length, 43)
        assert.strictEqual(session.ipAddress, "203.0.113.7")

        const now = yield* DateTime.now
        const expected = DateTime.addDuration(now, config.session.expiresIn)
        assert.strictEqual(DateTime.toEpochMillis(session.expiresAt), DateTime.toEpochMillis(expected))

        const verified = yield* sessions.verify(token)
        assert.strictEqual(verified.session.id, session.id)
        assert.strictEqual(verified.user.id, user.id)
        assert.strictEqual(verified.refreshed, false)
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "honours rememberMe: false with the short lifetime",
    () =>
      Effect.gen(function*() {
        const sessions = yield* Sessions
        const config = yield* AuthConfig
        const { user } = yield* signUp("ada@example.com")

        const { session } = yield* sessions.create({ userId: user.id, rememberMe: false })

        assert.strictEqual(
          Duration.toMillis(grantedLifetime(session, config)),
          Duration.toMillis(config.session.rememberMeDisabledExpiresIn)
        )
        assert.notStrictEqual(
          Duration.toMillis(config.session.rememberMeDisabledExpiresIn),
          Duration.toMillis(config.session.expiresIn)
        )
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )
})

describe("domain/Sessions/verify", () => {
  it.effect(
    "refuses an unknown token with Unauthorized",
    () =>
      Effect.gen(function*() {
        const sessions = yield* Sessions
        const failure = yield* Effect.flip(sessions.verify(Redacted.make("not-a-token")))
        assert.strictEqual(failure._tag, "Unauthorized")
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "rolls the expiry forward exactly once per updateAge",
    () =>
      Effect.gen(function*() {
        const sessions = yield* Sessions
        const config = yield* AuthConfig
        const { user } = yield* signUp("ada@example.com")
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
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "a refresh keeps a rememberMe:false session short",
    () =>
      Effect.gen(function*() {
        const sessions = yield* Sessions
        const config = yield* AuthConfig
        const { user } = yield* signUp("ada@example.com")
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
      }).pipe(Effect.provide(testLayer({ session: { updateAge: Duration.hours(1) } }))),
    testTimeout
  )

  it.effect(
    "a session shorter than updateAge is never refresh-due at birth",
    () =>
      Effect.gen(function*() {
        // Read as `expiresAt - expiresIn + updateAge <= now` with the
        // *configured* expiresIn, a freshly created one-day session would be due
        // for refresh immediately and would silently gain the seven-day
        // lifetime its owner declined.
        const sessions = yield* Sessions
        const { user } = yield* signUp("ada@example.com")
        const created = yield* sessions.create({ userId: user.id, rememberMe: false })

        assert.strictEqual((yield* sessions.verify(created.token)).refreshed, false)
      }).pipe(Effect.provide(testLayer({ session: { updateAge: Duration.days(3) } }))),
    testTimeout
  )

  it.effect(
    "fails SessionExpired past the expiry and drops the row",
    () =>
      Effect.gen(function*() {
        const sessions = yield* Sessions
        const store = yield* SessionStore
        const config = yield* AuthConfig
        const { user } = yield* signUp("ada@example.com")
        const created = yield* sessions.create({ userId: user.id })

        yield* TestClock.adjust(Duration.sum(config.session.expiresIn, Duration.millis(1)))

        const failure = yield* Effect.flip(sessions.verify(created.token))
        assert.strictEqual(failure._tag, "SessionExpired")

        // The dead row is cleaned up on the way out, so a replay of the same
        // token is indistinguishable from one that never existed.
        const remaining = yield* store.findByTokenHash(created.session.tokenHash)
        assert.strictEqual(remaining._tag, "None")
        assert.strictEqual((yield* Effect.flip(sessions.verify(created.token)))._tag, "Unauthorized")
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )
})

describe("domain/Sessions/freshness", () => {
  it.effect(
    "is fresh until freshAge has elapsed since creation",
    () =>
      Effect.gen(function*() {
        const sessions = yield* Sessions
        const config = yield* AuthConfig
        const { user } = yield* signUp("ada@example.com")
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
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "a rolling refresh does not restore freshness",
    () =>
      Effect.gen(function*() {
        // Freshness tracks createdAt on purpose: a month of ordinary browsing is
        // not evidence that the account's owner is at the keyboard.
        const sessions = yield* Sessions
        const config = yield* AuthConfig
        const { user } = yield* signUp("ada@example.com")
        const created = yield* sessions.create({ userId: user.id })

        yield* TestClock.adjust(Duration.sum(config.session.freshAge, Duration.millis(1)))
        const refreshed = yield* sessions.verify(created.token)
        assert.strictEqual(refreshed.refreshed, true)
        assert.strictEqual(yield* sessions.isFresh(refreshed.session), false)
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )
})

describe("domain/Sessions/revocation", () => {
  it.effect(
    "revoke removes one session and only the owner's",
    () =>
      Effect.gen(function*() {
        const sessions = yield* Sessions
        const ada = yield* signUp("ada@example.com")
        const bob = yield* signUp("bob@example.com")

        const { events } = yield* recordingEvents(sessions.revoke(ada.session.id, ada.user.id))
        assert.deepStrictEqual(tagsOf(events), ["SessionRevoked"])

        assert.strictEqual((yield* Effect.flip(sessions.verify(ada.token)))._tag, "Unauthorized")

        // Ada cannot revoke Bob's session by guessing its id.
        const stranger = yield* Effect.flip(sessions.revoke(bob.session.id, ada.user.id))
        assert.strictEqual(stranger._tag, "NotFound")
        assert.strictEqual((yield* sessions.verify(bob.token)).session.id, bob.session.id)
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "revokeOthers keeps the current session, revokeAll keeps none",
    () =>
      Effect.gen(function*() {
        const sessions = yield* Sessions
        const { user } = yield* signUp("ada@example.com")
        const laptop = yield* sessions.create({ userId: user.id })
        const phone = yield* sessions.create({ userId: user.id })
        const tablet = yield* sessions.create({ userId: user.id })

        // Four: the one sign-up established, plus three.
        assert.strictEqual((yield* sessions.list(user.id)).length, 4)

        const others = yield* recordingEvents(sessions.revokeOthers(user.id, laptop.session.id))
        assert.strictEqual(others.result, 3)
        assert.deepStrictEqual(tagsOf(others.events), ["SessionRevoked"])
        assert.strictEqual((yield* Effect.flip(sessions.verify(phone.token)))._tag, "Unauthorized")
        assert.strictEqual((yield* Effect.flip(sessions.verify(tablet.token)))._tag, "Unauthorized")
        assert.strictEqual((yield* sessions.verify(laptop.token)).session.id, laptop.session.id)

        assert.strictEqual(yield* sessions.revokeAll(user.id), 1)
        assert.strictEqual((yield* sessions.list(user.id)).length, 0)
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )

  it.effect(
    "list omits expired sessions",
    () =>
      Effect.gen(function*() {
        const sessions = yield* Sessions
        const config = yield* AuthConfig
        const { user } = yield* signUp("ada@example.com")
        yield* sessions.create({ userId: user.id, rememberMe: false })

        assert.strictEqual((yield* sessions.list(user.id)).length, 2)

        yield* TestClock.adjust(
          Duration.sum(config.session.rememberMeDisabledExpiresIn, Duration.millis(1))
        )
        assert.strictEqual((yield* sessions.list(user.id)).length, 1)
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )
})

describe("domain/Sessions/arithmetic", () => {
  it.effect(
    "refreshDueAt is expiresAt - expiresIn + updateAge for an ordinary session",
    () =>
      Effect.gen(function*() {
        const sessions = yield* Sessions
        const config = yield* AuthConfig
        const { user } = yield* signUp("ada@example.com")
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
      }).pipe(Effect.provide(testLayer())),
    testTimeout
  )
})
