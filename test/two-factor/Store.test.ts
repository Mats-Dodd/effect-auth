/**
 * The two-factor plugin's three tables, on whichever database
 * `EFFECT_AUTH_TEST_DATABASE` names.
 *
 * **Details**
 *
 * Nothing here writes SQL or reads a catalog: every case goes through the store,
 * so the same assertions are true on all three dialects and the conditional
 * upsert behind the TOTP enrolment is proven wherever it runs — the pg and
 * sqlite `ON CONFLICT … DO UPDATE … WHERE` and the MySQL
 * `ON DUPLICATE KEY UPDATE … IF(…)` have to agree, and this is the file that
 * says so.
 */
import { assert, describe, layer } from "@effect/vitest"
import { DateTime, Duration, Effect, Layer, Option } from "effect"
import type { UserId } from "../../src/domain/Schema.js"
import { insertRow } from "../../src/internal/effects.js"
import * as TwoFactorTest from "../../src/testing/TwoFactorTest.js"
import { RecoveryCode, TotpEnrolment, TrustedDevice } from "../../src/two-factor/Schema.js"
import { layer as storeLayer, TwoFactorStore } from "../../src/two-factor/Store.js"
import { signUpUser, uniqueEmail } from "../fixtures.js"

/**
 * The plugin's three tables over the same deployment its service runs on, so a
 * row can have a real user to point at.
 */
const testLayer = storeLayer.pipe(Layer.provideMerge(TwoFactorTest.layer()))

layer(testLayer)("two-factor/Store", (it) => {
  /** A registered account, and the store, for one test. */
  const registered = (label: string) =>
    Effect.gen(function* () {
      const store = yield* TwoFactorStore
      const { user } = yield* signUpUser(uniqueEmail(label))
      return { store, userId: user.id }
    })

  const pending = (userId: UserId, secret = "v1.pending") =>
    insertRow(TotpEnrolment.insert, {
      userId,
      secretCiphertext: secret,
      verifiedAt: null,
      lastUsedStep: null
    })

  describe("the TOTP enrolment", () => {
    it.effect("writes a pending row and reads it back", () =>
      Effect.gen(function* () {
        const { store, userId } = yield* registered("totp-write")
        const stored = yield* store.upsertPendingTotp(yield* pending(userId))
        assert.isTrue(Option.isSome(stored))
        const found = yield* store.findTotp(userId)
        assert.isTrue(Option.isSome(found))
        if (Option.isNone(found)) return
        assert.strictEqual(found.value.secretCiphertext, "v1.pending")
        assert.strictEqual(found.value.verifiedAt, null)
        assert.strictEqual(found.value.lastUsedStep, null)
      })
    )

    it.effect("replaces a pending enrolment — abandoning one regenerates it", () =>
      Effect.gen(function* () {
        const { store, userId } = yield* registered("totp-replace")
        yield* store.upsertPendingTotp(yield* pending(userId, "v1.first"))
        const second = yield* store.upsertPendingTotp(yield* pending(userId, "v1.second"))
        assert.isTrue(Option.isSome(second))
        const found = yield* store.findTotp(userId)
        assert.strictEqual(Option.getOrThrow(found).secretCiphertext, "v1.second")
      })
    )

    it.effect("refuses to replace a confirmed enrolment", () =>
      Effect.gen(function* () {
        const { store, userId } = yield* registered("totp-confirmed")
        yield* store.upsertPendingTotp(yield* pending(userId, "v1.proved"))
        const now = yield* DateTime.now
        yield* store.confirmTotp(userId, now, 100)

        const replaced = yield* store.upsertPendingTotp(yield* pending(userId, "v1.attacker"))

        assert.isTrue(Option.isNone(replaced), "a proved second factor may not be swapped for one the caller chose")
        const found = yield* store.findTotp(userId)
        assert.strictEqual(Option.getOrThrow(found).secretCiphertext, "v1.proved")
        assert.strictEqual(Option.getOrThrow(found).lastUsedStep, 100)
      })
    )

    it.effect("lets an abandoned enrolment be restarted, and confirms the replacement", () =>
      Effect.gen(function* () {
        const { store, userId } = yield* registered("totp-restart")
        // The whole enrolment cycle in one case, because it is the one the
        // conditional upsert is written for: while `verified_at` is NULL a
        // second enrolment wins, and the moment it is not, none does.
        yield* store.upsertPendingTotp(yield* pending(userId, "v1.abandoned"))
        const restarted = yield* store.upsertPendingTotp(yield* pending(userId, "v1.restarted"))
        assert.isTrue(Option.isSome(restarted))

        const now = yield* DateTime.now
        const confirmed = yield* store.confirmTotp(userId, now, 42)

        assert.isTrue(Option.isSome(confirmed))
        const found = Option.getOrThrow(yield* store.findTotp(userId))
        assert.strictEqual(found.secretCiphertext, "v1.restarted", "the abandoned secret must not be the live one")
        assert.isNotNull(found.verifiedAt)
        assert.strictEqual(found.lastUsedStep, 42)
        assert.isTrue(yield* store.consumeTotpStep(userId, 43), "the restarted enrolment is a working credential")
      })
    )

    it.effect("confirms exactly once", () =>
      Effect.gen(function* () {
        const { store, userId } = yield* registered("totp-confirm-once")
        yield* store.upsertPendingTotp(yield* pending(userId))
        const now = yield* DateTime.now

        const first = yield* store.confirmTotp(userId, now, 10)
        const second = yield* store.confirmTotp(userId, now, 11)

        assert.isTrue(Option.isSome(first))
        assert.isTrue(Option.isNone(second), "a second confirmation must not re-stamp the enrolment")
        assert.strictEqual(Option.getOrThrow(yield* store.findTotp(userId)).lastUsedStep, 10)
      })
    )
  })

  describe("the replay guard", () => {
    it.effect("never accepts a step for an enrolment nobody proved", () =>
      Effect.gen(function* () {
        const { store, userId } = yield* registered("step-pending")
        yield* store.upsertPendingTotp(yield* pending(userId))
        assert.isFalse(yield* store.consumeTotpStep(userId, 500), "verified_at NULL is not a credential")
      })
    )

    it.effect("accepts a step above the last one and refuses that one and everything below it", () =>
      Effect.gen(function* () {
        const { store, userId } = yield* registered("step-order")
        yield* store.upsertPendingTotp(yield* pending(userId))
        const now = yield* DateTime.now
        yield* store.confirmTotp(userId, now, 100)

        assert.isFalse(yield* store.consumeTotpStep(userId, 99), "a step below the last used one is a replay")
        // RFC 6238 §5.2 asks for "at or below", not "equal to": the code for
        // the accepted step is still valid for the rest of its period.
        assert.isFalse(yield* store.consumeTotpStep(userId, 100), "the step just used is a replay")
        assert.isTrue(yield* store.consumeTotpStep(userId, 101))
        assert.strictEqual(Option.getOrThrow(yield* store.findTotp(userId)).lastUsedStep, 101)
      })
    )

    it.effect("lets exactly one of two concurrent submissions of the same code through", () =>
      Effect.gen(function* () {
        const { store, userId } = yield* registered("step-race")
        yield* store.upsertPendingTotp(yield* pending(userId))
        const now = yield* DateTime.now
        yield* store.confirmTotp(userId, now, 1)

        const outcomes = yield* Effect.all(
          [store.consumeTotpStep(userId, 2), store.consumeTotpStep(userId, 2), store.consumeTotpStep(userId, 2)],
          { concurrency: "unbounded" }
        )

        assert.strictEqual(outcomes.filter((accepted) => accepted).length, 1)
      })
    )
  })

  describe("recovery codes", () => {
    const codesFor = (userId: UserId, hashes: ReadonlyArray<string>) =>
      Effect.forEach(hashes, (codeHash) => insertRow(RecoveryCode.insert, { userId, codeHash, usedAt: null }))

    it.effect("writes a set and counts what is unspent", () =>
      Effect.gen(function* () {
        const { store, userId } = yield* registered("codes-write")
        yield* store.replaceRecoveryCodes(userId, yield* codesFor(userId, ["h1", "h2", "h3"]))
        assert.strictEqual(yield* store.countRecoveryCodes(userId), 3)
      })
    )

    it.effect("replaces the whole set, spent codes included", () =>
      Effect.gen(function* () {
        const { store, userId } = yield* registered("codes-replace")
        yield* store.replaceRecoveryCodes(userId, yield* codesFor(userId, ["r1", "r2"]))
        const now = yield* DateTime.now
        yield* store.consumeRecoveryCode(userId, "r1", now)

        yield* store.replaceRecoveryCodes(userId, yield* codesFor(userId, ["r3", "r4", "r5"]))

        assert.strictEqual(yield* store.countRecoveryCodes(userId), 3)
        assert.isFalse(yield* store.consumeRecoveryCode(userId, "r2", now), "a regenerated set retires the old one")
      })
    )

    it.effect("spends a code once", () =>
      Effect.gen(function* () {
        const { store, userId } = yield* registered("codes-once")
        yield* store.replaceRecoveryCodes(userId, yield* codesFor(userId, ["s1", "s2"]))
        const now = yield* DateTime.now

        assert.isTrue(yield* store.consumeRecoveryCode(userId, "s1", now))
        assert.isFalse(yield* store.consumeRecoveryCode(userId, "s1", now))
        assert.strictEqual(yield* store.countRecoveryCodes(userId), 1)
      })
    )

    it.effect("lets exactly one of three concurrent uses of one code through", () =>
      Effect.gen(function* () {
        const { store, userId } = yield* registered("codes-race")
        yield* store.replaceRecoveryCodes(userId, yield* codesFor(userId, ["c1"]))
        const now = yield* DateTime.now

        const outcomes = yield* Effect.all(
          [
            store.consumeRecoveryCode(userId, "c1", now),
            store.consumeRecoveryCode(userId, "c1", now),
            store.consumeRecoveryCode(userId, "c1", now)
          ],
          { concurrency: "unbounded" }
        )

        assert.strictEqual(outcomes.filter((spent) => spent).length, 1)
      })
    )

    it.effect("gives twelve people their first set at once", () =>
      Effect.gen(function* () {
        // A first set is the case that used to deadlock on MySQL: the `DELETE`
        // that clears the previous set matches nothing, and under REPEATABLE
        // READ a predicate that matches nothing takes a next-key lock over the
        // gap it scanned — one gap that every new holder shares, and that each
        // of them then needs an insert-intention lock inside.
        const store = yield* TwoFactorStore
        const users = yield* Effect.forEach(
          Array.from({ length: 12 }, (_, index) => index),
          (index) => Effect.map(signUpUser(uniqueEmail(`codes-storm-${index}`)), ({ user }) => user.id),
          { concurrency: "unbounded" }
        )
        yield* Effect.forEach(
          users,
          (userId) =>
            Effect.flatMap(
              codesFor(
                userId,
                ["a", "b", "c", "d"].map((letter) => `${letter}-${userId}`)
              ),
              (written) => store.replaceRecoveryCodes(userId, written)
            ),
          { concurrency: "unbounded" }
        )
        const counts = yield* Effect.forEach(users, (userId) => store.countRecoveryCodes(userId))
        assert.deepStrictEqual(
          [...counts],
          users.map(() => 4)
        )
      })
    )

    it.effect("keeps one set when one person regenerates twelve times at once", () =>
      Effect.gen(function* () {
        const { store, userId } = yield* registered("codes-regenerate-storm")
        yield* store.replaceRecoveryCodes(userId, yield* codesFor(userId, ["g0", "g1"]))
        yield* Effect.forEach(
          Array.from({ length: 12 }, (_, index) => index),
          (index) =>
            Effect.flatMap(codesFor(userId, [`g${index}-x`, `g${index}-y`]), (written) =>
              store.replaceRecoveryCodes(userId, written)
            ),
          { concurrency: "unbounded" }
        )
        // Every replacement writes two, and each one clears what it found.
        assert.isAtLeast(yield* store.countRecoveryCodes(userId), 2)
      })
    )

    it.effect("is another person's code to nobody", () =>
      Effect.gen(function* () {
        const { store, userId } = yield* registered("codes-owner")
        const other = yield* registered("codes-thief")
        yield* store.replaceRecoveryCodes(userId, yield* codesFor(userId, ["owned"]))
        const now = yield* DateTime.now

        assert.isFalse(yield* store.consumeRecoveryCode(other.userId, "owned", now))
        assert.strictEqual(yield* store.countRecoveryCodes(userId), 1)
      })
    )
  })

  describe("trusted devices", () => {
    const device = (userId: UserId, tokenHash: string, expiresAt: DateTime.Utc, label: string | null = null) =>
      insertRow(TrustedDevice.insert, {
        userId,
        tokenHash,
        expiresAt,
        userAgent: "a browser",
        ipAddress: "203.0.113.7",
        label
      })

    it.effect("remembers a browser and rotates its token when it is used", () =>
      Effect.gen(function* () {
        const { store, userId } = yield* registered("device-rotate")
        const now = yield* DateTime.now
        const expiresAt = DateTime.addDuration(now, Duration.days(30))
        const created = yield* store.createDevice(yield* device(userId, "d1", expiresAt))

        const used = yield* store.useDevice("d1", "d2", now)

        assert.isTrue(Option.isSome(used))
        if (Option.isNone(used)) return
        assert.strictEqual(used.value.id, created.id, "the row survives; only its token changes")
        assert.strictEqual(used.value.tokenHash, "d2")
        // Absolute, and never moved by use: a rolling window would be a
        // permanent bypass for whoever holds the cookie.
        assert.deepStrictEqual(used.value.expiresAt, created.expiresAt)
        assert.isTrue(Option.isNone(yield* store.useDevice("d1", "d3", now)), "the old token must stop working")
      })
    )

    it.effect("refuses an expired device, and does not revive it", () =>
      Effect.gen(function* () {
        const { store, userId } = yield* registered("device-expired")
        const now = yield* DateTime.now
        const expired = DateTime.subtractDuration(now, Duration.minutes(1))
        yield* store.createDevice(yield* device(userId, "old", expired))

        assert.isTrue(Option.isNone(yield* store.useDevice("old", "new", now)))
        assert.deepStrictEqual(yield* store.listDevices(userId, now), [])
      })
    )

    it.effect("lists the live devices and hides the expired ones", () =>
      Effect.gen(function* () {
        const { store, userId } = yield* registered("device-list")
        const now = yield* DateTime.now
        yield* store.createDevice(yield* device(userId, "live", DateTime.addDuration(now, Duration.days(1)), "laptop"))
        yield* store.createDevice(yield* device(userId, "dead", DateTime.subtractDuration(now, Duration.days(1))))

        const listed = yield* store.listDevices(userId, now)

        assert.strictEqual(listed.length, 1)
        assert.strictEqual(listed[0]?.label, "laptop")
        assert.strictEqual(listed[0]?.userAgent, "a browser")
        assert.strictEqual(listed[0]?.ipAddress, "203.0.113.7")
      })
    )

    it.effect("revokes one device, and only its owner's", () =>
      Effect.gen(function* () {
        const { store, userId } = yield* registered("device-revoke")
        const other = yield* registered("device-other")
        const now = yield* DateTime.now
        const mine = yield* store.createDevice(
          yield* device(userId, "mine", DateTime.addDuration(now, Duration.days(1)))
        )

        assert.isFalse(yield* store.deleteDevice(mine.id, other.userId), "ownership lives in the statement")
        assert.isTrue(yield* store.deleteDevice(mine.id, userId))
        assert.isFalse(yield* store.deleteDevice(mine.id, userId))
      })
    )

    it.effect("forgets every device of one person and nobody else's", () =>
      Effect.gen(function* () {
        const { store, userId } = yield* registered("device-revoke-all")
        const other = yield* registered("device-spared")
        const now = yield* DateTime.now
        const soon = DateTime.addDuration(now, Duration.days(1))
        yield* store.createDevice(yield* device(userId, "a", soon))
        yield* store.createDevice(yield* device(userId, "b", soon))
        yield* store.createDevice(yield* device(other.userId, "c", soon))

        assert.strictEqual(yield* store.deleteDevices(userId), 2)
        assert.strictEqual((yield* store.listDevices(other.userId, now)).length, 1)
      })
    )
  })
})
