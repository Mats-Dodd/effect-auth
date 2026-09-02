/**
 * The SQL `WithAuthTransaction`: the domain's transaction runner over
 * `sql.withTransaction`, with a driver failure reported as a
 * `PersistenceError` and anything the wrapped effect failed with passed
 * through untouched.
 *
 * Not exported from the package: `SqlStores.layerFor` is the public door.
 *
 * @internal
 */
import { Effect } from "effect"
import { SqlClient, SqlError } from "effect/unstable/sql"
import type { WithAuthTransactionService } from "../../domain/Stores.js"
import { PersistenceError, WithAuthTransaction } from "../../domain/Stores.js"

/** @internal */
export const make: Effect.Effect<WithAuthTransactionService, never, SqlClient.SqlClient> = Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient
  return WithAuthTransaction.of({
    run: <A, E, R>(effect: Effect.Effect<A, E, R>): Effect.Effect<A, E | PersistenceError, R> =>
      Effect.mapError(sql.withTransaction(effect), (error): E | PersistenceError =>
        SqlError.isSqlError(error)
          ? PersistenceError.make({ operation: "WithAuthTransaction.run", cause: error })
          : error
      )
  })
})
