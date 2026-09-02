/**
 * The SQL `WithAuthTransaction`: the domain's transaction runner over
 * `sql.withTransaction`, with a driver failure reported as a
 * `PersistenceError` and anything the wrapped effect failed with passed
 * through untouched.
 *
 * **Details — the MySQL liveness check**
 *
 * On MySQL a transaction can end without anybody in this process saying so.
 * InnoDB answers a deadlock by rolling the *whole* transaction back; a lock-wait
 * timeout does the same where `innodb_rollback_on_timeout` is on; and any DDL
 * statement commits implicitly. After one of those the connection is out of the
 * transaction and in autocommit, so every statement that follows lands
 * immediately and permanently — and the `COMMIT` at the end reports success over
 * a body only half of which is stored.
 *
 * That is only reachable when the body *recovers* the failure that caused it —
 * a hook that logs and continues, a store call wrapped in `Effect.result` — but
 * a transaction that says it committed when it did not is the worst answer this
 * seam can give, so the outermost transaction asks the database rather than
 * trusting the shape of the effect: it takes a savepoint of its own on the way
 * in and releases it on the way out. A savepoint does not survive an implicit
 * rollback, so a `RELEASE` that fails is proof that the transaction the body ran
 * in is gone, and the run fails with a `PersistenceError` instead of committing.
 * Two extra statements, on MySQL only, per domain transaction.
 *
 * PostgreSQL needs none of it: a failed statement poisons the transaction rather
 * than ending it, and `COMMIT` on a poisoned transaction rolls back and says so.
 * SQLite serialises writers instead of deadlocking them. Both therefore keep
 * Effect's savepoint for a nested `run`, and MySQL — where a savepoint is the
 * thing a deadlock destroys — opens nothing inside a transaction it is already
 * in, exactly as `Mutations.atomically` does for a store's own statements.
 *
 * Not exported from the package: `SqlStores.layerFor` is the public door.
 *
 * @internal
 */
import { Effect, Option } from "effect"
import { SqlClient, SqlError } from "effect/unstable/sql"
import type { WithAuthTransactionService } from "../../domain/Stores.js"
import { PersistenceError, WithAuthTransaction } from "../../domain/Stores.js"
import { dialectOf, identifier } from "../Dialect.js"

/**
 * The savepoint the outermost MySQL transaction proves itself with.
 *
 * One fixed name is enough because only the outermost run takes one — a nested
 * run is the outer one and opens nothing — and a second savepoint of this name
 * would silently replace the first.
 */
const liveness = "effect_auth_transaction"

/** @internal */
export const make: Effect.Effect<WithAuthTransactionService, never, SqlClient.SqlClient> = Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient
  const dialect = yield* dialectOf(sql)
  const name = identifier(sql, liveness)

  /** What a `RELEASE` of a savepoint that is no longer there means. */
  const ended = (cause: SqlError.SqlError): PersistenceError =>
    PersistenceError.make({
      operation: "WithAuthTransaction.run",
      kind: "Unknown",
      cause: new Error(
        "the MySQL transaction was rolled back before it could commit: InnoDB ends the whole transaction on a deadlock, on a lock-wait timeout where innodb_rollback_on_timeout is set, and on any DDL statement. Writes the body made after that point are already committed and cannot be taken back.",
        { cause }
      )
    })

  /** The body, bracketed by the savepoint that says the transaction survived it. */
  const proven = <A, E, R>(effect: Effect.Effect<A, E, R>): Effect.Effect<A, E | PersistenceError, R> =>
    Effect.gen(function* () {
      // Unprepared, as Effect's own transaction statements are: `SAVEPOINT` is
      // not a statement MySQL's binary protocol prepares.
      yield* Effect.mapError(sql`SAVEPOINT ${name}`.unprepared, ended)
      const value = yield* effect
      yield* Effect.mapError(sql`RELEASE SAVEPOINT ${name}`.unprepared, ended)
      return value
    })

  /**
   * The outermost transaction is the one that commits, so it is the one that
   * has to prove there is still a transaction to commit — and, on MySQL, the
   * only one that opens anything at all. A nested run is the caller's own
   * transaction, for the reason `Mutations.atomically` gives: a savepoint taken
   * inside a MySQL transaction is exactly what a deadlock takes away.
   */
  const transaction = <A, E, R>(
    effect: Effect.Effect<A, E, R>
  ): Effect.Effect<A, E | PersistenceError | SqlError.SqlError, R> =>
    dialect === "mysql"
      ? Effect.flatMap(
          Effect.serviceOption(sql.transactionService),
          Option.match({
            onNone: (): Effect.Effect<A, E | PersistenceError | SqlError.SqlError, R> =>
              sql.withTransaction(proven(effect)),
            onSome: (): Effect.Effect<A, E | PersistenceError | SqlError.SqlError, R> => effect
          })
        )
      : sql.withTransaction(effect)

  return WithAuthTransaction.of({
    run: <A, E, R>(effect: Effect.Effect<A, E, R>): Effect.Effect<A, E | PersistenceError, R> =>
      Effect.mapError(transaction(effect), (error): E | PersistenceError =>
        SqlError.isSqlError(error)
          ? PersistenceError.make({ operation: "WithAuthTransaction.run", cause: error })
          : error
      )
  })
})
