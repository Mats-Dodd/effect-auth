/**
 * What two requests arriving at once do to one row.
 *
 * **Details**
 *
 * Every case here forks real fibers and lets the database arbitrate. That is the
 * point: a transaction wrapping the whole test would reserve one connection and
 * serialise the fibers on it, and the test would then pass against a database
 * with no locking at all.
 *
 * The guarantees are the same on every dialect and each is reached differently —
 * PostgreSQL and MySQL take row locks, SQLite serialises its writers behind
 * `BEGIN IMMEDIATE`. `Dialect.test.ts` asserts those mechanisms one at a time;
 * this file asserts only the outcome, which is what the domain depends on.
 */
import { assert, describe, layer } from "@effect/vitest"
import { Duration, Effect, Fiber, Option, Schema } from "effect"
import type { Result } from "effect"
import { SqlClient } from "effect/unstable/sql"
import {
  AccountStore,
  isUniqueViolation,
  PersistenceError,
  UserStore,
  VerificationStore,
  WithAuthTransaction
} from "../../src/domain/Stores.js"
import { AuthTest } from "../../src/testing/index.js"
import { uniqueEmail } from "../fixtures.js"
import { createOauthAccount, createUser, createVerification, unique } from "./helpers.js"

/** Both outcomes of running `effect` twice, on two forked fibers. */
const race = <A, E, R>(
  effect: Effect.Effect<A, E, R>
): Effect.Effect<readonly [Result.Result<A, E>, Result.Result<A, E>], never, R> =>
  Effect.gen(function* () {
    const left = yield* Effect.forkChild(Effect.result(effect))
    const right = yield* Effect.forkChild(Effect.result(effect))
    return [yield* Fiber.join(left), yield* Fiber.join(right)] as const
  })

/**
 * The value the one winning fiber produced.
 *
 * Both halves are asserted here rather than at each call site: "one of them won"
 * is only half the guarantee — the other has to have lost for the reason the
 * domain branches on, rather than by falling over.
 */
const oneWinner = <A, E>(results: readonly [Result.Result<A, E>, Result.Result<A, E>]): A => {
  let winner: Option.Option<A> = Option.none()
  for (const result of results) {
    if (result._tag === "Success") {
      if (Option.isSome(winner)) return assert.fail("expected one winner, both writes succeeded")
      winner = Option.some(result.success)
    } else if (!Schema.is(PersistenceError)(result.failure)) {
      return assert.fail("expected the loser to fail with a PersistenceError")
    } else {
      assert.isTrue(isUniqueViolation(result.failure), "the loser has to be able to tell it lost a race")
    }
  }
  return Option.isSome(winner) ? winner.value : assert.fail("expected one of the two writes to succeed")
}

layer(AuthTest.layerStores)("sql/Concurrency", (it) => {
  describe("uniqueness under a race", () => {
    it.effect("registers one address once, however many arrive together", () =>
      Effect.gen(function* () {
        const sql = yield* SqlClient.SqlClient
        const email = uniqueEmail("race-signup")

        const winner = oneWinner(yield* race(createUser(email)))

        // The index, not the application, is what makes this true — so the
        // assertion is about the table rather than about the two answers.
        const rows = yield* sql<{ readonly id: string }>`SELECT id FROM users WHERE email = ${email}`
        assert.strictEqual(rows.length, 1)
        assert.strictEqual(rows[0]?.id, winner.id)
      })
    )

    it.effect("provisions one OAuth identity once", () =>
      Effect.gen(function* () {
        const sql = yield* SqlClient.SqlClient
        const accounts = yield* AccountStore
        const user = yield* createUser(uniqueEmail("race-oauth"))
        const accountId = unique("gh-race")

        const winner = oneWinner(yield* race(createOauthAccount(user.id, "github", accountId)))

        assert.strictEqual(yield* accounts.countByUserId(user.id), 1)
        const rows = yield* sql<{ readonly id: string }>`SELECT id FROM accounts WHERE account_id = ${accountId}`
        assert.strictEqual(rows.length, 1)
        assert.strictEqual(rows[0]?.id, winner.id)
      })
    )
  })

  describe("exactly-once consumption", () => {
    it.effect("hands the row to exactly one of two concurrent consumers", () =>
      Effect.gen(function* () {
        const verifications = yield* VerificationStore
        const identifier = unique("password-reset")
        yield* createVerification(identifier, "race-hash", Duration.hours(1))

        // Neither consumer fails: losing is answering `None`, which is what
        // makes a reset link spendable exactly once rather than an error a
        // caller has to interpret.
        const results = yield* race(verifications.consume(identifier, "race-hash"))
        const answers = results.map((result) =>
          result._tag === "Success" ? result.success : assert.fail("a consumer failed rather than answering None")
        )

        assert.strictEqual(answers.filter(Option.isSome).length, 1)
        assert.strictEqual(answers.filter(Option.isNone).length, 1)
      })
    )
  })

  describe("the reclaim lock", () => {
    it.effect("serialises two transactions that take the same user row", () =>
      Effect.gen(function* () {
        const users = yield* UserStore
        const accounts = yield* AccountStore
        const transaction = yield* WithAuthTransaction
        const user = yield* createUser(uniqueEmail("race-lock"))

        // What each fiber saw when it looked. `Accounts.unlink`'s last-method
        // guard is only sound if these are 0 and 1: two fibers that both saw the
        // same number are two fibers that both believed they were alone.
        const observed: Array<number> = []
        const link = (providerId: string) =>
          transaction.run(
            Effect.gen(function* () {
              yield* users.lockUserRow(user.id)
              const existing = yield* accounts.listByUserIdForUpdate(user.id)
              observed.push(existing.length)
              yield* createOauthAccount(user.id, providerId, unique(providerId))
            })
          )

        const left = yield* Effect.forkChild(link("github"))
        const right = yield* Effect.forkChild(link("google"))
        yield* Fiber.join(left)
        yield* Fiber.join(right)

        assert.deepStrictEqual(
          [...observed].sort((left, right) => left - right),
          [0, 1]
        )
        assert.strictEqual(yield* accounts.countByUserId(user.id), 2)
      })
    )
  })

  describe("rollback", () => {
    it.effect("leaves nothing behind for the transaction running beside it", () =>
      Effect.gen(function* () {
        const users = yield* UserStore
        const transaction = yield* WithAuthTransaction
        const doomed = uniqueEmail("race-rollback-doomed")
        const kept = uniqueEmail("race-rollback-kept")

        const fails = transaction.run(
          Effect.gen(function* () {
            yield* createUser(doomed)
            return yield* Effect.fail("boom" as const)
          })
        )
        const succeeds = transaction.run(Effect.asVoid(createUser(kept)))

        const left = yield* Effect.forkChild(Effect.result(fails))
        const right = yield* Effect.forkChild(Effect.result(succeeds))
        const failed = yield* Fiber.join(left)
        const survived = yield* Fiber.join(right)

        // A rollback that took its neighbour's writes with it would be a
        // transaction that is not a transaction — and on a one-connection
        // database that is exactly the mistake that hides.
        assert.strictEqual(failed._tag, "Failure")
        assert.strictEqual(survived._tag, "Success")
        assert.isTrue(Option.isNone(yield* users.findByEmail(doomed)))
        assert.isTrue(Option.isSome(yield* users.findByEmail(kept)))
      })
    )
  })
})
