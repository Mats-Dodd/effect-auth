/**
 * The SQL `VerificationStore`.
 *
 * **Details**
 *
 * `consume` is the exactly-once claim — the statement behind every
 * password-reset token, e-mail verification link and OAuth state — and it is
 * written on `Mutations.consumeOne`: one guarded `DELETE … RETURNING` on
 * PostgreSQL and SQLite, and on MySQL a plain read that picks the row followed
 * by a locking read of it by primary key that decides the claim. Two concurrent
 * callers cannot both be handed the row on any of the three; the reasoning for
 * MySQL's shape, and the InnoDB gap lock it exists to avoid, is in that helper's
 * own documentation.
 *
 * **Gotchas**
 *
 * `deleteByIdentifier` is a range delete, and on MySQL a range delete takes
 * next-key locks over the index range it scans. Many of them racing inserts
 * under one identifier can deadlock — measured at twelve concurrent retirements
 * of one identifier, well past anything the domain does with it (it retires the
 * siblings of a value that has just been claimed, once). A deadlock surfaces as
 * a `PersistenceError` of kind `Unknown` and the retirement is simply not made,
 * which is the same failure mode as the driver going away.
 *
 * Not exported from the package: `SqlStores.layerFor` is the public door.
 *
 * @internal
 */
import { DateTime, Effect, Schema } from "effect"
import type { Statement } from "effect/unstable/sql"
import { SqlClient, SqlSchema } from "effect/unstable/sql"
import type { PersistenceError, VerificationStoreService } from "../../domain/Stores.js"
import { VerificationStore } from "../../domain/Stores.js"
import { Verification } from "../../domain/Schema.js"
import { dialectOf } from "../Dialect.js"
import { consumeOne, deleteAndCount, insertAndRead } from "../Mutations.js"
import { persist } from "./internal.js"

// -----------------------------------------------------------------------------
// The table
// -----------------------------------------------------------------------------

const verificationsTable = "verifications"

/** The primary key: how a mutation helper names a row again on MySQL. */
const verificationKey: ReadonlyArray<string> = ["id"]

// -----------------------------------------------------------------------------
// Column projections
// -----------------------------------------------------------------------------

const verificationColumns = `id, identifier, value_hash AS "valueHash", payload, expires_at AS "expiresAt", created_at AS "createdAt", updated_at AS "updatedAt"`

// -----------------------------------------------------------------------------
// Request schemas
// -----------------------------------------------------------------------------

const IsoString = Schema.DateTimeUtcFromString

const ConsumeRequest = Schema.Struct({
  identifier: Schema.String,
  valueHash: Schema.String,
  now: IsoString
})

/** @internal */
export const make: Effect.Effect<VerificationStoreService, never, SqlClient.SqlClient> = Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient
  const dialect = yield* dialectOf(sql)
  const verificationCols = sql.literal(verificationColumns)

  const insertVerification = SqlSchema.findOne({
    Request: Verification.insert,
    Result: Verification,
    execute: (row) =>
      insertAndRead({
        sql,
        dialect,
        table: verificationsTable,
        key: verificationKey,
        columns: verificationCols,
        record: {
          id: row.id,
          identifier: row.identifier,
          value_hash: row.valueHash,
          payload: row.payload,
          expires_at: row.expiresAt,
          created_at: row.createdAt,
          updated_at: row.updatedAt
        }
      })
  })

  /**
   * The whole race-safety story: the row is claimed under the expiry guard and
   * handed to exactly one caller, whichever dialect arbitrates it.
   */
  const consumeVerification = SqlSchema.findOneOption({
    Request: ConsumeRequest,
    Result: Verification,
    execute: (row) =>
      consumeOne({
        sql,
        dialect,
        table: verificationsTable,
        key: verificationKey,
        columns: verificationCols,
        where: sql`identifier = ${row.identifier} AND value_hash = ${row.valueHash} AND expires_at > ${row.now}`
      })
  })

  /** The two bulk deletes: the same statement under two predicates, counted. */
  const deleteVerifications = (operation: string, where: Statement.Fragment): Effect.Effect<number, PersistenceError> =>
    persist(operation)(deleteAndCount({ sql, dialect, table: verificationsTable, key: verificationKey, where }))

  return VerificationStore.of({
    create: (verification) => persist("VerificationStore.create")(insertVerification(verification)),

    consume: (identifier, valueHash) =>
      persist("VerificationStore.consume")(
        Effect.flatMap(DateTime.now, (now) => consumeVerification({ identifier, valueHash, now }))
      ),

    deleteByIdentifier: (identifier) =>
      deleteVerifications("VerificationStore.deleteByIdentifier", sql`identifier = ${identifier}`),

    deleteExpired: Effect.flatMap(DateTime.now, (now) =>
      deleteVerifications("VerificationStore.deleteExpired", sql`expires_at <= ${DateTime.formatIso(now)}`)
    )
  })
})
