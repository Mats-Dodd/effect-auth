import { assert, describe, layer } from "@effect/vitest"
import { DateTime, Duration, Effect, Redacted } from "effect"
import { TestClock } from "effect/testing"
import { AuthConfig, make as makeAuthConfig } from "../../src/config/AuthConfig.js"
import { deriveAal } from "../../src/domain/Assurance.js"
import type { Evidence } from "../../src/domain/Sessions.js"
import {
  grantedLifetime,
  isFreshAt,
  meetsAssurance,
  recoveryCodeMethod,
  refreshDueAt,
  requireAssurance,
  requireAssuranceFor,
  Sessions
} from "../../src/domain/Sessions.js"
import { SessionStore } from "../../src/domain/Stores.js"
import { CurrentSession } from "../../src/http/Middleware.js"
import { AuthTest } from "../../src/testing/index.js"
import { forUser, signUpUser, uniqueEmail } from "../fixtures.js"

/** A knowledge factor, as the password path records one. */
const password: Evidence = { method: "password", factor: "knowledge", phishingResistant: false, restricted: false }

/** A possession factor, as an authenticator app records one. */
const totp: Evidence = { method: "totp", factor: "possession", phishingResistant: false, restricted: false }

/** A recovery code: possession, and the one method `allowRecovery: false` strikes out. */
const recovery: Evidence = {
  method: recoveryCodeMethod,
  factor: "possession",
  phishingResistant: false,
  restricted: false
}

/** A trusted-device skip: a true statement that proves nothing. */
const trustedDevice: Evidence = {
  method: "trustedDevice",
  factor: "none",
  phishingResistant: false,
  restricted: false
}

layer(AuthTest.layer())("domain/Sessions", (it) => {
  describe("create", () => {
    it.effect("mints a hashed session and returns the raw token exactly once", () =>
      Effect.gen(function* () {
        const sessions = yield* Sessions
        const config = yield* AuthConfig
        const { user } = yield* signUpUser(uniqueEmail("create"))

        const { session, token } = yield* sessions.createUnchecked({
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
      })
    )

    it.effect("honours rememberMe: false with the short lifetime", () =>
      Effect.gen(function* () {
        const sessions = yield* Sessions
        const config = yield* AuthConfig
        const { user } = yield* signUpUser(uniqueEmail("remember-me"))

        const { session, token } = yield* sessions.createUnchecked({ userId: user.id, rememberMe: false })

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
      })
    )
  })

  describe("verify", () => {
    it.effect("refuses an unknown token with Unauthorized", () =>
      Effect.gen(function* () {
        const sessions = yield* Sessions
        const failure = yield* Effect.flip(sessions.verify(Redacted.make("not-a-token")))
        assert.strictEqual(failure._tag, "Unauthorized")
      })
    )

    it.effect("rolls the expiry forward exactly once per updateAge", () =>
      AuthTest.freshClock(
        Effect.gen(function* () {
          const sessions = yield* Sessions
          const config = yield* AuthConfig
          const { user } = yield* signUpUser(uniqueEmail("update-age"))
          const created = yield* sessions.createUnchecked({ userId: user.id })

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
        })
      )
    )

    it.effect("fails SessionExpired past the expiry and drops the row", () =>
      AuthTest.freshClock(
        Effect.gen(function* () {
          const sessions = yield* Sessions
          const store = yield* SessionStore
          const config = yield* AuthConfig
          const { user } = yield* signUpUser(uniqueEmail("expiry"))
          const created = yield* sessions.createUnchecked({ userId: user.id })

          yield* TestClock.adjust(Duration.sum(config.session.expiresIn, Duration.millis(1)))

          const failure = yield* Effect.flip(sessions.verify(created.token))
          assert.strictEqual(failure._tag, "SessionExpired")

          // The dead row is cleaned up on the way out, so a replay of the same
          // token is indistinguishable from one that never existed.
          const remaining = yield* store.findByTokenHash(created.session.tokenHash)
          assert.strictEqual(remaining._tag, "None")
          assert.strictEqual((yield* Effect.flip(sessions.verify(created.token)))._tag, "Unauthorized")
        })
      )
    )

    // A configuration variant: everything above the database is rebuilt for
    // this sub-block, and the database itself is inherited from the block above.
    it.layer(AuthTest.layer({ session: { updateAge: Duration.hours(1) } }))("with a one-hour updateAge", (it) => {
      it.effect("a refresh keeps a rememberMe:false session short", () =>
        AuthTest.freshClock(
          Effect.gen(function* () {
            const sessions = yield* Sessions
            const config = yield* AuthConfig
            const { user } = yield* signUpUser(uniqueEmail("short-refresh"))
            const created = yield* sessions.createUnchecked({ userId: user.id, rememberMe: false })

            yield* TestClock.adjust(config.session.updateAge)
            const refreshed = yield* sessions.verify(created.token)
            assert.strictEqual(refreshed.refreshed, true)

            // The refresh must not promote a one-day session to the configured
            // seven-day lifetime.
            assert.strictEqual(
              Duration.toMillis(grantedLifetime(refreshed.session, config)),
              Duration.toMillis(config.session.rememberMeDisabledExpiresIn)
            )
          })
        )
      )
    })

    it.effect("rejects an updateAge longer than the short session lifetime", () =>
      Effect.sync(() =>
        assert.throws(
          () =>
            makeAuthConfig({
              baseUrl: AuthTest.testBaseUrl,
              secret: AuthTest.testSecret,
              session: { updateAge: Duration.days(3) }
            }),
          /updateAge must be shorter/
        )
      )
    )
  })

  describe("freshness", () => {
    it.effect("is fresh until freshAge has elapsed since the last interactive authentication", () =>
      AuthTest.freshClock(
        Effect.gen(function* () {
          const sessions = yield* Sessions
          const config = yield* AuthConfig
          const { user } = yield* signUpUser(uniqueEmail("fresh"))
          const created = yield* sessions.createUnchecked({ userId: user.id, methods: [password] })
          // The maxAge-only policy is exactly what `requireFresh` used to be.
          const stillFresh = { maxAge: config.session.freshAge }

          assert.strictEqual(yield* sessions.isFresh(created.session), true)
          yield* requireAssuranceFor(created.session, stillFresh, [])

          yield* TestClock.adjust(Duration.subtract(config.session.freshAge, Duration.millis(1)))
          assert.strictEqual(yield* sessions.isFresh(created.session), true)

          yield* TestClock.adjust(Duration.millis(1))
          assert.strictEqual(yield* sessions.isFresh(created.session), false)

          const failure = yield* Effect.flip(requireAssuranceFor(created.session, stillFresh, ["totp"]))
          assert.strictEqual(failure._tag, "StepUpRequired")
          assert.deepStrictEqual(failure.required, { maxAge: Duration.toSeconds(config.session.freshAge) })
          assert.strictEqual(failure.current.aal, "aal1")
          assert.deepStrictEqual(failure.current.available, ["totp"])
          assert.strictEqual(
            DateTime.toEpochMillis(failure.current.authenticatedAt),
            DateTime.toEpochMillis(created.session.authenticatedAt)
          )
        })
      )
    )

    it.effect("a rolling refresh moves the expiry and never authenticatedAt", () =>
      AuthTest.freshClock(
        Effect.gen(function* () {
          // Freshness tracks `authenticatedAt` on purpose: a month of ordinary
          // browsing is not evidence that the account's owner is at the keyboard.
          const sessions = yield* Sessions
          const config = yield* AuthConfig
          const { user } = yield* signUpUser(uniqueEmail("stale"))
          const created = yield* sessions.createUnchecked({ userId: user.id, methods: [password] })

          yield* TestClock.adjust(Duration.sum(config.session.freshAge, Duration.millis(1)))
          const refreshed = yield* sessions.verify(created.token)
          assert.strictEqual(refreshed.refreshed, true)
          assert.strictEqual(yield* sessions.isFresh(refreshed.session), false)

          // The invariant this whole wave rests on.
          assert.strictEqual(
            DateTime.toEpochMillis(refreshed.session.authenticatedAt),
            DateTime.toEpochMillis(created.session.authenticatedAt)
          )
          assert.strictEqual(refreshed.session.aal, created.session.aal)
          assert.deepStrictEqual(refreshed.session.methods, created.session.methods)
          assert.notStrictEqual(
            DateTime.toEpochMillis(refreshed.session.expiresAt),
            DateTime.toEpochMillis(created.session.expiresAt)
          )
        })
      )
    )
  })

  describe("evidence", () => {
    it.effect("records the log it was given and the level derived from it", () =>
      Effect.gen(function* () {
        const sessions = yield* Sessions
        const { user } = yield* signUpUser(uniqueEmail("evidence"))

        const { session } = yield* sessions.createUnchecked({ userId: user.id, methods: [password, totp] })

        assert.deepStrictEqual(
          session.methods.map((entry) => entry.method),
          ["password", "totp"]
        )
        // Two distinct factors, so `deriveAal` — the only thing in this library
        // that computes a level — reaches aal2.
        assert.strictEqual(session.aal, "aal2")
        assert.strictEqual(session.aal, deriveAal(session.methods))
        const now = yield* DateTime.now
        for (const entry of session.methods) {
          assert.strictEqual(DateTime.toEpochMillis(entry.completedAt), DateTime.toEpochMillis(now))
        }
        assert.strictEqual(DateTime.toEpochMillis(session.authenticatedAt), DateTime.toEpochMillis(now))
      })
    )

    it.effect("a mint that states no evidence says so, and reaches aal0", () =>
      Effect.gen(function* () {
        const sessions = yield* Sessions
        const { user } = yield* signUpUser(uniqueEmail("no-evidence"))

        // Fail closed: a session nobody described is not credited with a level
        // it did not earn.
        const { session } = yield* sessions.createUnchecked({ userId: user.id })

        assert.deepStrictEqual(session.methods, [])
        assert.strictEqual(session.aal, "aal0")
      })
    )

    it.effect("evidence that states when it completed keeps it", () =>
      AuthTest.freshClock(
        Effect.gen(function* () {
          const sessions = yield* Sessions
          const { user } = yield* signUpUser(uniqueEmail("replayed"))
          const earlier = yield* DateTime.now
          yield* TestClock.adjust(Duration.minutes(5))

          // The first factor, carried through a pending second one: it happened
          // five minutes ago and the log must not claim otherwise.
          const { session } = yield* sessions.createUnchecked({
            userId: user.id,
            methods: [{ ...password, completedAt: earlier }, totp]
          })

          assert.strictEqual(DateTime.toEpochMillis(session.methods[0]!.completedAt), DateTime.toEpochMillis(earlier))
          assert.strictEqual(
            DateTime.toEpochMillis(session.methods[1]!.completedAt),
            DateTime.toEpochMillis(yield* DateTime.now)
          )
        })
      )
    )
  })

  describe("assurance", () => {
    it.effect("a policy that states nothing admits every session", () =>
      Effect.gen(function* () {
        const sessions = yield* Sessions
        const { user } = yield* signUpUser(uniqueEmail("open-policy"))
        const { session } = yield* sessions.createUnchecked({ userId: user.id })
        const now = yield* DateTime.now

        assert.strictEqual(meetsAssurance(session, {}, now), true)
        yield* requireAssuranceFor(session, {}, [])
      })
    )

    it.effect("aal is compared on the frozen ordering", () =>
      Effect.gen(function* () {
        const sessions = yield* Sessions
        const { user } = yield* signUpUser(uniqueEmail("levels"))
        const anonymous = yield* sessions.createUnchecked({ userId: user.id })
        const single = yield* sessions.createUnchecked({ userId: user.id, methods: [password] })
        const both = yield* sessions.createUnchecked({ userId: user.id, methods: [password, totp] })
        const now = yield* DateTime.now

        assert.strictEqual(meetsAssurance(anonymous.session, { aal: "aal1" }, now), false)
        assert.strictEqual(meetsAssurance(single.session, { aal: "aal1" }, now), true)
        assert.strictEqual(meetsAssurance(single.session, { aal: "aal2" }, now), false)
        assert.strictEqual(meetsAssurance(both.session, { aal: "aal2" }, now), true)
        // A level below what the session reached still passes.
        assert.strictEqual(meetsAssurance(both.session, { aal: "aal0" }, now), true)
      })
    )

    it.effect("a method requirement is met by a live entry only", () =>
      Effect.gen(function* () {
        const sessions = yield* Sessions
        const { user } = yield* signUpUser(uniqueEmail("methods-policy"))
        const created = yield* sessions.createUnchecked({ userId: user.id, methods: [password, trustedDevice] })
        const now = yield* DateTime.now

        assert.strictEqual(meetsAssurance(created.session, { methods: ["password"] }, now), true)
        assert.strictEqual(meetsAssurance(created.session, { methods: ["passkey"] }, now), false)
        // A skip proves nothing, so it satisfies nothing — even by name.
        assert.strictEqual(meetsAssurance(created.session, { methods: ["trustedDevice"] }, now), false)
      })
    )

    it.effect("allowRecovery: false strikes recovery codes out before judging", () =>
      Effect.gen(function* () {
        const sessions = yield* Sessions
        const { user } = yield* signUpUser(uniqueEmail("recovery"))
        const created = yield* sessions.createUnchecked({ userId: user.id, methods: [password, recovery] })
        const now = yield* DateTime.now

        // Password plus recovery code is two distinct factors, so the session
        // really is aal2 …
        assert.strictEqual(created.session.aal, "aal2")
        assert.strictEqual(meetsAssurance(created.session, { aal: "aal2" }, now), true)
        // … but an endpoint that refuses recovery sees only the password.
        assert.strictEqual(meetsAssurance(created.session, { aal: "aal2", allowRecovery: false }, now), false)
        assert.strictEqual(meetsAssurance(created.session, { aal: "aal1", allowRecovery: false }, now), true)
        assert.strictEqual(
          meetsAssurance(created.session, { methods: [recoveryCodeMethod], allowRecovery: false }, now),
          false
        )
      })
    )

    it.effect("maxAge is measured from authenticatedAt and members are conjunctive", () =>
      AuthTest.freshClock(
        Effect.gen(function* () {
          const sessions = yield* Sessions
          const { user } = yield* signUpUser(uniqueEmail("max-age"))
          const created = yield* sessions.createUnchecked({ userId: user.id, methods: [password, totp] })

          yield* TestClock.adjust(Duration.minutes(4))
          const inside = yield* DateTime.now
          assert.strictEqual(
            meetsAssurance(created.session, { aal: "aal2", maxAge: Duration.minutes(5) }, inside),
            true
          )

          yield* TestClock.adjust(Duration.minutes(2))
          const outside = yield* DateTime.now
          // The level still holds; the age no longer does, and both must.
          assert.strictEqual(meetsAssurance(created.session, { aal: "aal2" }, outside), true)
          assert.strictEqual(
            meetsAssurance(created.session, { aal: "aal2", maxAge: Duration.minutes(5) }, outside),
            false
          )
        })
      )
    )

    it.effect("the refusal reports what the session has and what could raise it", () =>
      Effect.gen(function* () {
        const sessions = yield* Sessions
        const { user } = yield* signUpUser(uniqueEmail("refusal"))
        const created = yield* sessions.createUnchecked({ userId: user.id, methods: [password] })

        const failure = yield* Effect.flip(
          requireAssuranceFor(created.session, { aal: "aal2", methods: ["totp", "passkey"] }, ["totp", "recoveryCode"])
        )

        assert.strictEqual(failure._tag, "StepUpRequired")
        assert.deepStrictEqual(failure.required, { aal: "aal2", methods: ["totp", "passkey"] })
        assert.strictEqual(failure.current.aal, "aal1")
        assert.deepStrictEqual(failure.current.available, ["totp", "recoveryCode"])
      })
    )

    it.effect("requireAssurance reads the session behind the request", () =>
      Effect.gen(function* () {
        const sessions = yield* Sessions
        const { user } = yield* signUpUser(uniqueEmail("current"))
        const weak = yield* sessions.createUnchecked({ userId: user.id, methods: [password] })
        const strong = yield* sessions.createUnchecked({ userId: user.id, methods: [password, totp] })

        yield* Effect.provideService(requireAssurance({ aal: "aal2" }, []), CurrentSession, strong.session)
        const failure = yield* Effect.flip(
          Effect.provideService(requireAssurance({ aal: "aal2" }, []), CurrentSession, weak.session)
        )
        assert.strictEqual(failure._tag, "StepUpRequired")
      })
    )
  })

  describe("elevate", () => {
    it.effect("appends the evidence, re-derives the level and re-stamps the moment", () =>
      AuthTest.freshClock(
        Effect.gen(function* () {
          const sessions = yield* Sessions
          const { user } = yield* signUpUser(uniqueEmail("elevate"))
          const created = yield* sessions.createUnchecked({ userId: user.id, methods: [password] })
          assert.strictEqual(created.session.aal, "aal1")

          yield* TestClock.adjust(Duration.minutes(30))
          const { session } = yield* sessions.elevate(created.session, totp)

          assert.strictEqual(session.id, created.session.id)
          assert.deepStrictEqual(
            session.methods.map((entry) => entry.method),
            ["password", "totp"]
          )
          assert.strictEqual(session.aal, "aal2")
          assert.strictEqual(session.aal, deriveAal(session.methods))
          // The first factor keeps the moment it was actually proved …
          assert.strictEqual(
            DateTime.toEpochMillis(session.methods[0]!.completedAt),
            DateTime.toEpochMillis(created.session.methods[0]!.completedAt)
          )
          // … and the session is freshly authenticated as of the second one.
          const now = yield* DateTime.now
          assert.strictEqual(DateTime.toEpochMillis(session.authenticatedAt), DateTime.toEpochMillis(now))
          assert.strictEqual(DateTime.toEpochMillis(session.methods[1]!.completedAt), DateTime.toEpochMillis(now))
        })
      )
    )

    it.effect("rotates the token: the old one stops resolving and the new one works", () =>
      Effect.gen(function* () {
        const sessions = yield* Sessions
        const { user } = yield* signUpUser(uniqueEmail("rotate"))
        const created = yield* sessions.createUnchecked({ userId: user.id, methods: [password] })

        const elevated = yield* sessions.elevate(created.session, totp)

        assert.notStrictEqual(Redacted.value(elevated.token), Redacted.value(created.token))
        // A token captured at aal1 does not inherit aal2 — it stops working.
        assert.strictEqual((yield* Effect.flip(sessions.verify(created.token)))._tag, "Unauthorized")
        const verified = yield* sessions.verify(elevated.token)
        assert.strictEqual(verified.session.id, created.session.id)
        assert.strictEqual(verified.session.aal, "aal2")
        // One row, still: the device list and every open tab survive.
        assert.strictEqual((yield* sessions.list(user.id)).length, 2)
      })
    )

    it.effect("publishes SessionElevated naming the one factor that was added", () =>
      Effect.gen(function* () {
        const sessions = yield* Sessions
        const { user } = yield* signUpUser(uniqueEmail("elevated-event"))
        const created = yield* sessions.createUnchecked({ userId: user.id, methods: [password] })

        const recorded = yield* AuthTest.recordingEvents(sessions.elevate(created.session, totp))

        const events = forUser(recorded.events, user.id)
        assert.deepStrictEqual(AuthTest.tagsOf(events), ["SessionElevated"])
        const elevated = events[0]
        if (elevated === undefined || elevated._tag !== "SessionElevated") {
          return assert.fail("expected a SessionElevated event")
        }
        assert.strictEqual(elevated.method, "totp")
        assert.strictEqual(elevated.sessionId, created.session.id)
        assert.strictEqual(elevated.userId, user.id)
      })
    )

    it.effect("a trusted-device skip is recorded and weighs nothing", () =>
      Effect.gen(function* () {
        const sessions = yield* Sessions
        const { user } = yield* signUpUser(uniqueEmail("skip"))
        const created = yield* sessions.createUnchecked({ userId: user.id, methods: [password] })

        const { session } = yield* sessions.elevate(created.session, trustedDevice)

        assert.strictEqual(session.methods.length, 2)
        assert.strictEqual(session.aal, "aal1")
      })
    )

    it.effect("elevating a session that has been revoked writes nothing", () =>
      Effect.gen(function* () {
        const sessions = yield* Sessions
        const { user } = yield* signUpUser(uniqueEmail("gone"))
        const created = yield* sessions.createUnchecked({ userId: user.id, methods: [password] })
        yield* sessions.revoke(created.session.id, user.id)

        const failure = yield* Effect.flip(sessions.elevate(created.session, totp))

        assert.strictEqual(failure._tag, "PersistenceError")
        assert.strictEqual((yield* sessions.list(user.id)).length, 1)
      })
    )
  })

  describe("revocation", () => {
    it.effect("revoke removes one session and only the owner's", () =>
      Effect.gen(function* () {
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
      })
    )

    it.effect("revokeOthers keeps the current session, revokeAll keeps none", () =>
      Effect.gen(function* () {
        const sessions = yield* Sessions
        const { user } = yield* signUpUser(uniqueEmail("devices"))
        const laptop = yield* sessions.createUnchecked({ userId: user.id })
        const phone = yield* sessions.createUnchecked({ userId: user.id })
        const tablet = yield* sessions.createUnchecked({ userId: user.id })

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
      })
    )

    it.effect("list omits expired sessions", () =>
      AuthTest.freshClock(
        Effect.gen(function* () {
          const sessions = yield* Sessions
          const config = yield* AuthConfig
          const { user } = yield* signUpUser(uniqueEmail("listing"))
          yield* sessions.createUnchecked({ userId: user.id, rememberMe: false })

          assert.strictEqual((yield* sessions.list(user.id)).length, 2)

          yield* TestClock.adjust(Duration.sum(config.session.rememberMeDisabledExpiresIn, Duration.millis(1)))
          assert.strictEqual((yield* sessions.list(user.id)).length, 1)
        })
      )
    )
  })

  describe("arithmetic", () => {
    it.effect("refreshDueAt is expiresAt - expiresIn + updateAge for an ordinary session", () =>
      Effect.gen(function* () {
        const sessions = yield* Sessions
        const config = yield* AuthConfig
        const { user } = yield* signUpUser(uniqueEmail("arithmetic"))
        const { session } = yield* sessions.createUnchecked({ userId: user.id })

        const expected = DateTime.addDuration(
          DateTime.subtractDuration(session.expiresAt, config.session.expiresIn),
          config.session.updateAge
        )
        assert.strictEqual(DateTime.toEpochMillis(refreshDueAt(session, config)), DateTime.toEpochMillis(expected))

        const now = yield* DateTime.now
        assert.strictEqual(isFreshAt(session, config, now), true)
      })
    )
  })
})
