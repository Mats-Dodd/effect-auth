/**
 * What a store does with a failure the database hands it.
 *
 * **Details**
 *
 * The domain never sees an `SqlError`: every store wraps one in a
 * `PersistenceError` that names the operation, keeps the driver failure in
 * `cause` for the log, and classifies it into `kind` so a caller can tell a lost
 * race from any other storage failure without importing a driver's error type.
 *
 * That classification is part of the support claim for every dialect, and it is
 * the whole of this file: a duplicate is a `UniqueViolation` on PostgreSQL,
 * SQLite and MySQL alike, anything else is `Unknown`, and a transaction that
 * fails leaves nothing behind. The foreign-key case doubles as the proof that
 * SQLite has its foreign keys switched on — without the pragma the orphan row
 * would simply be written.
 */
import { assert, describe, layer } from "@effect/vitest"
import { DateTime, Duration, Effect, Option, Schema } from "effect"
import { SqlError } from "effect/unstable/sql"
import { Session, UserId } from "../../src/domain/Schema.js"
import {
  isUniqueViolation,
  PersistenceError,
  SessionStore,
  UserStore,
  WithAuthTransaction
} from "../../src/domain/Stores.js"
import { AuthTest } from "../../src/testing/index.js"
import { uniqueEmail } from "../fixtures.js"
import { createOauthAccount, createSession, createUser, unique } from "./helpers.js"

/**
 * The `PersistenceError` a write failed with.
 *
 * A write that succeeded, or failed with anything else, fails the test here
 * rather than at a later assertion that would read as if the classification
 * were wrong.
 */
const persistenceFailure = <A, E extends { readonly _tag: string }, R>(
  effect: Effect.Effect<A, E, R>
): Effect.Effect<PersistenceError, never, R> =>
  Effect.map(Effect.result(effect), (result) => {
    if (result._tag === "Success") return assert.fail("expected the write to fail")
    if (!Schema.is(PersistenceError)(result.failure)) {
      return assert.fail(`expected a PersistenceError, got ${result.failure._tag}`)
    }
    return result.failure
  })

layer(AuthTest.layerStores)("sql/Errors", (it) => {
  describe("unique violations", () => {
    it.effect("classifies a duplicate e-mail", () =>
      Effect.gen(function* () {
        const email = uniqueEmail("duplicate")
        yield* createUser(email)
        const failure = yield* persistenceFailure(createUser(email))

        assert.strictEqual(failure.operation, "UserStore.create")
        // the driver failure survives in `cause` for logs, and is classified into
        // `kind` so the domain can tell a lost race from any other storage failure
        // without importing the SQL driver's error type
        assert.strictEqual(SqlError.isSqlError(failure.cause), true)
        assert.strictEqual(SqlError.isSqlError(failure.cause) ? failure.cause.reason._tag : "", "UniqueViolation")
        assert.strictEqual(failure.kind, "UniqueViolation")
        assert.isTrue(isUniqueViolation(failure))
      })
    )

    it.effect("classifies a duplicate session token hash", () =>
      Effect.gen(function* () {
        const user = yield* createUser(uniqueEmail("duplicate-session"))
        const hash = unique("hash-duplicate")
        yield* createSession(user.id, hash, Duration.days(1))

        const failure = yield* persistenceFailure(createSession(user.id, hash, Duration.days(1)))
        assert.strictEqual(failure.operation, "SessionStore.create")
        assert.strictEqual(failure.kind, "UniqueViolation")
        assert.isTrue(isUniqueViolation(failure))
      })
    )

    it.effect("classifies a duplicate OAuth identity", () =>
      Effect.gen(function* () {
        const user = yield* createUser(uniqueEmail("duplicate-account"))
        const accountId = unique("gh-duplicate")
        yield* createOauthAccount(user.id, "github", accountId)

        // The unique index is on (issuer, account_id): one GitHub account
        // cannot be provisioned twice, whoever is asking for it.
        const other = yield* createUser(uniqueEmail("duplicate-account-other"))
        const failure = yield* persistenceFailure(createOauthAccount(other.id, "github", accountId))
        assert.strictEqual(failure.operation, "AccountStore.create")
        assert.strictEqual(failure.kind, "UniqueViolation")
        assert.isTrue(isUniqueViolation(failure))
      })
    )
  })

  describe("everything else", () => {
    it.effect("reports a foreign-key violation as an unclassified failure", () =>
      Effect.gen(function* () {
        const sessions = yield* SessionStore
        const now = yield* DateTime.now
        const row = yield* Session.insert.makeEffect({
          tokenHash: unique("hash-orphan"),
          userId: UserId.make(unique("no-such-user")),
          expiresAt: DateTime.addDuration(now, Duration.days(1)),
          ipAddress: null,
          userAgent: null
        })

        const failure = yield* persistenceFailure(sessions.create(row))
        assert.strictEqual(failure.operation, "SessionStore.create")
        // Not a lost race: retrying this would fail for ever, so a caller that
        // treats `UniqueViolation` as "somebody beat me to it" must not see one.
        assert.strictEqual(failure.kind, "Unknown")
        assert.isFalse(isUniqueViolation(failure))
      })
    )
  })

  describe("transactions", () => {
    it.effect("rolls every write back when the effect fails", () =>
      Effect.gen(function* () {
        const transaction = yield* WithAuthTransaction
        const users = yield* UserStore
        const sessions = yield* SessionStore
        const email = uniqueEmail("tx-bad")
        const hash = unique("hash-rollback")

        const failure = yield* Effect.flip(
          transaction.run(
            Effect.gen(function* () {
              const user = yield* createUser(email)
              yield* createSession(user.id, hash, Duration.days(1))
              return yield* Effect.fail("boom" as const)
            })
          )
        )

        assert.strictEqual(failure, "boom")
        assert.strictEqual(Option.isNone(yield* users.findByEmail(email)), true)
        assert.strictEqual(Option.isNone(yield* sessions.findByTokenHash(hash)), true)
      })
    )
  })
})
