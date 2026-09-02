/**
 * The conditional upsert behind a TOTP enrolment, on whichever database
 * `EFFECT_AUTH_TEST_DATABASE` names.
 *
 * **Details**
 *
 * `TwoFactorStore.upsertPendingTotp` is one of the two call sites
 * `Mutations.upsertAndRead` exists for, and it is the one where being wrong is a
 * takeover: "abandoning an enrolment regenerates it" and "an active enrolment
 * may not be silently replaced" are the same statement, and a dialect that
 * expressed only the first half would let anyone who could reach the endpoint
 * swap a proved second factor for one they chose.
 *
 * The three dialects reach that guarantee by three different statements —
 * PostgreSQL and SQLite by `INSERT ... ON CONFLICT (user_id) DO UPDATE ...
 * WHERE verified_at IS NULL RETURNING`, MySQL by `INSERT ... ON DUPLICATE KEY
 * UPDATE col = IF(...)` and a read-back — so the outcome is asserted here rather
 * than the SQL. `test/sql/Dialect.unit.test.ts` covers the statements
 * themselves.
 *
 * The row count is asserted in every case. `user_id` is the primary key, so a
 * second row is impossible by construction on all three — which is exactly why
 * a port that had quietly stopped resolving the conflict would fail here with a
 * write error rather than with a wrong answer.
 */
import { assert, describe, layer } from "@effect/vitest"
import { DateTime, Effect, Fiber, Layer, Option } from "effect"
import type { Result } from "effect"
import { SqlClient } from "effect/unstable/sql"
import type { UserId } from "../../src/domain/Schema.js"
import { insertRow } from "../../src/internal/effects.js"
import * as TwoFactorTest from "../../src/testing/TwoFactorTest.js"
import { TotpEnrolment } from "../../src/two-factor/Schema.js"
import { layer as storeLayer, TwoFactorStore } from "../../src/two-factor/Store.js"
import { signUpUser, uniqueEmail } from "../fixtures.js"

/**
 * The store over the plugin's own tables and a deployment that can register a
 * person for them to point at. `layerDeployment` rather than `layer`: nothing
 * here goes through the plugin's service, only through the seam beneath it.
 */
const testLayer = storeLayer.pipe(Layer.provideMerge(TwoFactorTest.layerDeployment()))

/** A forked enrolment that failed is a defect in the port, and says which one. */
const assertSucceeded = <A, E>(result: Result.Result<A, E>): void => {
  if (result._tag === "Failure") {
    assert.fail(`a concurrent enrolment must not fail: ${String(result.failure)}`)
  }
}

layer(testLayer)("two-factor/EnrolmentUpsert", (it) => {
  /** A registered account, and the store, for one test. */
  const registered = (label: string) =>
    Effect.gen(function* () {
      const store = yield* TwoFactorStore
      const { user } = yield* signUpUser(uniqueEmail(label))
      return { store, userId: user.id }
    })

  /** A pending enrolment carrying one secret. */
  const pending = (userId: UserId, secret: string) =>
    insertRow(TotpEnrolment.insert, { userId, secretCiphertext: secret, verifiedAt: null, lastUsedStep: null })

  /** How many enrolment rows the person has. One, always, on every dialect. */
  const rowsFor = (userId: UserId) =>
    Effect.map(
      Effect.flatMap(
        SqlClient.SqlClient,
        (sql) => sql<{ readonly userId: string }>`SELECT user_id AS "userId" FROM effect_auth_totp
          WHERE user_id = ${userId}`
      ),
      (rows) => rows.length
    )

  describe("an abandoned enrolment", () => {
    it.effect("is replaced by the next one, secret and stamps and all", () =>
      Effect.gen(function* () {
        const { store, userId } = yield* registered("upsert-abandoned")

        const first = yield* store.upsertPendingTotp(yield* pending(userId, "v1.abandoned"))
        assert.isTrue(Option.isSome(first), "a person with no enrolment gets one")

        // Nobody ever proved the first secret, so offering a second one is a
        // person restarting the flow — the commonest thing that happens to a
        // pending enrolment.
        const second = yield* store.upsertPendingTotp(yield* pending(userId, "v1.restarted"))
        assert.isTrue(Option.isSome(second), "an unproved enrolment may be replaced")
        assert.strictEqual(Option.getOrThrow(second).secretCiphertext, "v1.restarted")

        const found = Option.getOrThrow(yield* store.findTotp(userId))
        assert.strictEqual(found.secretCiphertext, "v1.restarted", "the first secret is gone, not shadowed")
        assert.strictEqual(found.verifiedAt, null)
        assert.strictEqual(found.lastUsedStep, null)
        assert.strictEqual(yield* rowsFor(userId), 1)
      })
    )
  })

  describe("a confirmed enrolment", () => {
    it.effect("is not replaced, and the caller is told so rather than obeyed", () =>
      Effect.gen(function* () {
        const { store, userId } = yield* registered("upsert-confirmed")
        yield* store.upsertPendingTotp(yield* pending(userId, "v1.proved"))
        const confirmedAt = yield* DateTime.now
        const confirmed = Option.getOrThrow(yield* store.confirmTotp(userId, confirmedAt, 4242))

        const replaced = yield* store.upsertPendingTotp(yield* pending(userId, "v1.attacker"))

        assert.isTrue(Option.isNone(replaced), "a proved second factor may not be swapped for one the caller chose")

        // Not merely "the answer was None": every column of the row has to be
        // what confirmation left there. An `ON DUPLICATE KEY UPDATE` whose
        // assignments were ordered wrongly would answer `None` from its
        // read-back and still have overwritten the secret.
        const found = Option.getOrThrow(yield* store.findTotp(userId))
        assert.strictEqual(found.secretCiphertext, "v1.proved")
        assert.strictEqual(found.lastUsedStep, 4242, "the replay guard survives a refused replacement")
        assert.deepStrictEqual(found.verifiedAt, confirmed.verifiedAt)
        assert.deepStrictEqual(found.createdAt, confirmed.createdAt, "even the stamp the upsert would rewrite")
        assert.strictEqual(yield* rowsFor(userId), 1)
      })
    )
  })

  describe("two enrolments at once", () => {
    it.effect("leave one row, whichever of them the database let through last", () =>
      Effect.gen(function* () {
        const { store, userId } = yield* registered("upsert-race")
        const offered = ["v1.left", "v1.right"]

        // Real fibers, and no transaction around the test body: what arbitrates
        // is the primary key, on PostgreSQL and MySQL by a row lock and on
        // SQLite by serialised writers.
        // Forked one at a time — a concurrent `forEach` would own the children
        // and interrupt them as it finished — and joined afterwards, so both are
        // in flight together.
        const fibers = yield* Effect.forEach(offered, (secret) =>
          Effect.forkChild(Effect.result(Effect.flatMap(pending(userId, secret), store.upsertPendingTotp)))
        )
        const results = yield* Effect.forEach(fibers, Fiber.join)

        // Neither side loses: a conditional upsert resolves the collision inside
        // the statement, so nothing here is ever a `UniqueViolation` a caller
        // would have to retry.
        for (const result of results) {
          assertSucceeded(result)
        }

        assert.strictEqual(yield* rowsFor(userId), 1, "one person, one authenticator-app enrolment")
        const found = Option.getOrThrow(yield* store.findTotp(userId))
        assert.include(offered, found.secretCiphertext, "the surviving row is one of the two that were offered")
        assert.strictEqual(found.verifiedAt, null, "and it is pending, because neither of them was ever proved")
      })
    )
  })
})
