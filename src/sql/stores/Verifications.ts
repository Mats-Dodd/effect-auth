/**
 * The SQL `VerificationStore`.
 *
 * **Details**
 *
 * `consume` is a single `DELETE ... RETURNING` guarded by the expiry, which is
 * what makes password-reset tokens, e-mail verification links and OAuth state
 * genuinely single-use: two concurrent callers cannot both be handed the row.
 *
 * Not exported from the package: `SqlStores.layerFor` is the public door.
 *
 * @internal
 */
import { DateTime, Effect, Schema } from "effect"
import { SqlClient, SqlSchema } from "effect/unstable/sql"
import type { VerificationStoreService } from "../../domain/Stores.js"
import { VerificationStore } from "../../domain/Stores.js"
import { Verification } from "../../domain/Schema.js"
import { persist } from "./internal.js"

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

const NowRequest = Schema.Struct({ now: IsoString })

/** @internal */
export const make: Effect.Effect<VerificationStoreService, never, SqlClient.SqlClient> = Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient
  const verificationCols = sql.literal(verificationColumns)

  const insertVerification = SqlSchema.findOne({
    Request: Verification.insert,
    Result: Verification,
    execute: (row) =>
      sql`INSERT INTO verifications (id, identifier, value_hash, payload, expires_at, created_at, updated_at)
        VALUES (${row.id}, ${row.identifier}, ${row.valueHash}, ${row.payload}, ${row.expiresAt}, ${row.createdAt}, ${row.updatedAt})
        RETURNING ${verificationCols}`
  })

  /**
   * The whole race-safety story: one statement claims the row, guarded by the
   * expiry, and hands it to exactly one caller.
   */
  const consumeVerification = SqlSchema.findOneOption({
    Request: ConsumeRequest,
    Result: Verification,
    execute: (row) =>
      sql`DELETE FROM verifications
        WHERE identifier = ${row.identifier}
          AND value_hash = ${row.valueHash}
          AND expires_at > ${row.now}
        RETURNING ${verificationCols}`
  })

  const deleteVerificationsByIdentifier = SqlSchema.findAll({
    Request: Schema.String,
    Result: Schema.Struct({ id: Schema.String }),
    execute: (identifier) => sql`DELETE FROM verifications WHERE identifier = ${identifier} RETURNING id`
  })

  const deleteExpiredVerifications = SqlSchema.findAll({
    Request: NowRequest,
    Result: Schema.Struct({ id: Schema.String }),
    execute: (row) => sql`DELETE FROM verifications WHERE expires_at <= ${row.now} RETURNING id`
  })

  return VerificationStore.of({
    create: (verification) => persist("VerificationStore.create")(insertVerification(verification)),

    consume: (identifier, valueHash) =>
      persist("VerificationStore.consume")(
        Effect.flatMap(DateTime.now, (now) => consumeVerification({ identifier, valueHash, now }))
      ),

    deleteByIdentifier: (identifier) =>
      persist("VerificationStore.deleteByIdentifier")(
        Effect.map(deleteVerificationsByIdentifier(identifier), (rows) => rows.length)
      ),

    deleteExpired: persist("VerificationStore.deleteExpired")(
      Effect.flatMap(DateTime.now, (now) => Effect.map(deleteExpiredVerifications({ now }), (rows) => rows.length))
    )
  })
})
