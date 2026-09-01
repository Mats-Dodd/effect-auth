/**
 * The phone plugin's own persistence: one table, four statements.
 *
 * **Details**
 *
 * A plugin never adds a column to a core table, so the number lives in
 * `effect_auth_phone_numbers` behind a service of the plugin's own — the same
 * arrangement the four core stores have, at a fifth of the size. Two database
 * constraints carry the rules that matter, so that no code path can forget
 * them: the number is the primary key (one handset belongs to one account) and
 * `user_id` is unique (one account holds one number).
 *
 * **Gotchas**
 *
 * Every method takes a number that has already been through
 * {@link E164.normalize}. Nothing here normalises, because a store that
 * silently rewrote its own key would make the key mean two things.
 *
 * @since 0.2.0
 */
import type { Option } from "effect"
import { Context, DateTime, Effect, Layer, Schema } from "effect"
import { Model } from "effect/unstable/schema"
import { SqlClient, SqlError, SqlSchema } from "effect/unstable/sql"
import type { UserId } from "../domain/Schema.js"
import { UserId as UserIdSchema } from "../domain/Schema.js"
import type { PersistenceFailureKind } from "../domain/Stores.js"
import { PersistenceError } from "../domain/Stores.js"
import { insertRow } from "../internal/effects.js"
import { phoneNumbersTable } from "./Migrations.js"

// -----------------------------------------------------------------------------
// The model
// -----------------------------------------------------------------------------

/**
 * A phone number, as it is stored.
 *
 * **Gotchas**
 *
 * `verifiedAt` is nullable and every read this plugin makes filters on it: a
 * row whose `verifiedAt` is null has not been proved and can neither sign
 * anybody in nor raise a session's assurance. This plugin only ever writes it
 * non-null — the row is written at the moment possession is proved, not when
 * the number is claimed — so a null there is either a deployment's own import
 * or a hand-written row, and both read as unproven.
 *
 * The number is not a secret: it is the account's own contact detail, and its
 * owner reads it back from their record. It is not `Model.Sensitive`, and the
 * plugin's HTTP surface still never echoes one it was not given.
 *
 * @category models
 * @since 0.2.0
 */
export class PhoneNumber extends Model.Class<PhoneNumber>("effect-auth/phone/PhoneNumber")({
  phoneE164: Schema.String,
  userId: UserIdSchema,
  verifiedAt: Schema.NullOr(Schema.DateTimeUtcFromString),
  createdAt: Model.DateTimeInsert
}) {}

/**
 * Whether a stored row is one somebody proved they hold.
 *
 * @category guards
 * @since 0.2.0
 */
export const isVerified = (row: PhoneNumber): boolean => row.verifiedAt !== null

// -----------------------------------------------------------------------------
// Service
// -----------------------------------------------------------------------------

/**
 * What {@link PhoneStoreService.claim} takes.
 *
 * @category models
 * @since 0.2.0
 */
export interface ClaimOptions {
  /** The canonical number, already through `E164.normalize`. */
  readonly phoneE164: string
  /** Who proved they hold it. */
  readonly userId: UserId
}

/**
 * The {@link PhoneStore} service definition.
 *
 * @category models
 * @since 0.2.0
 */
export interface PhoneStoreService {
  /** The row for a number, whether or not it is verified. */
  readonly findByPhone: (phoneE164: string) => Effect.Effect<Option.Option<PhoneNumber>, PersistenceError>

  /** The row a user holds, whether or not it is verified. */
  readonly findByUserId: (userId: UserId) => Effect.Effect<Option.Option<PhoneNumber>, PersistenceError>

  /**
   * Records that `userId` proved they hold `phoneE164`, replacing whatever
   * number they held before.
   *
   * **Details**
   *
   * Two statements in one transaction: the caller's previous row goes, and the
   * new one is written verified. Replacing rather than adding is what keeps
   * "one account, one number" a fact about the table instead of a rule in a
   * handler.
   *
   * Fails with a `PersistenceError` whose `kind` is `"UniqueViolation"` when
   * the number already belongs to somebody else — the primary key refuses it,
   * so no read-then-write can lose that race.
   */
  readonly claim: (options: ClaimOptions) => Effect.Effect<PhoneNumber, PersistenceError>

  /**
   * Removes the number a user holds, answering how many rows went.
   *
   * **Gotchas**
   *
   * This is what the `Authenticators` seam's `revokeAll` calls, from inside
   * somebody else's transaction and under their row lock, so it is one
   * statement and does no other IO.
   */
  readonly deleteForUser: (userId: UserId) => Effect.Effect<number, PersistenceError>
}

/**
 * The phone plugin's table. See {@link PhoneStoreService}.
 *
 * @category services
 * @since 0.2.0
 */
export class PhoneStore extends Context.Service<PhoneStore, PhoneStoreService>()(
  "effect-auth/phone/Store/PhoneStore"
) {}

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

const columns = `phone_e164 AS "phoneE164", user_id AS "userId", verified_at AS "verifiedAt", created_at AS "createdAt"`

/**
 * Classifies a driver failure for the plugin, which acts on exactly one
 * distinction: the number already belongs to somebody. Identical to
 * `SqlStores`' own `kindOf`, and for the same reason — it is the only failure
 * a caller can do anything about.
 */
const kindOf = (cause: unknown): PersistenceFailureKind =>
  SqlError.isSqlError(cause) && cause.reason._tag === "UniqueViolation" ? "UniqueViolation" : "Unknown"

const fail = (operation: string) => (cause: unknown) => PersistenceError.make({ operation, kind: kindOf(cause), cause })

const persist =
  (operation: string) =>
  <A, E, R>(effect: Effect.Effect<A, E, R>): Effect.Effect<A, PersistenceError, R> =>
    Effect.mapError(effect, fail(operation))

/**
 * Builds the {@link PhoneStore} implementation over an ambient `SqlClient`.
 *
 * @category constructors
 * @since 0.2.0
 */
export const make: Effect.Effect<PhoneStoreService, never, SqlClient.SqlClient> = Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient
  const cols = sql.literal(columns)

  const selectByPhone = SqlSchema.findOneOption({
    Request: Schema.String,
    Result: PhoneNumber,
    execute: (phoneE164) => sql`SELECT ${cols} FROM ${sql.literal(phoneNumbersTable)} WHERE phone_e164 = ${phoneE164}`
  })

  const selectByUserId = SqlSchema.findOneOption({
    Request: Schema.String,
    Result: PhoneNumber,
    execute: (userId) => sql`SELECT ${cols} FROM ${sql.literal(phoneNumbersTable)} WHERE user_id = ${userId}`
  })

  const insertPhone = SqlSchema.findOne({
    Request: PhoneNumber.insert,
    Result: PhoneNumber,
    execute: (row) =>
      sql`INSERT INTO ${sql.literal(phoneNumbersTable)} (phone_e164, user_id, verified_at, created_at)
        VALUES (${row.phoneE164}, ${row.userId}, ${row.verifiedAt}, ${row.createdAt})
        RETURNING ${cols}`
  })

  const deleteByUserId = SqlSchema.findAll({
    Request: Schema.String,
    Result: Schema.Struct({ phone_e164: Schema.String }),
    execute: (userId) =>
      sql`DELETE FROM ${sql.literal(phoneNumbersTable)} WHERE user_id = ${userId} RETURNING phone_e164`
  })

  const claim = (options: ClaimOptions) =>
    persist("PhoneStore.claim")(
      sql.withTransaction(
        Effect.gen(function* () {
          const now = yield* DateTime.now
          // The caller's previous number goes first, so that the unique
          // constraint on `user_id` is a statement about the table rather than
          // something this has to work around.
          yield* deleteByUserId(options.userId)
          const row = yield* insertRow(PhoneNumber.insert, {
            phoneE164: options.phoneE164,
            userId: options.userId,
            verifiedAt: now
          })
          return yield* insertPhone(row)
        })
      )
    )

  return PhoneStore.of({
    findByPhone: (phoneE164) => persist("PhoneStore.findByPhone")(selectByPhone(phoneE164)),
    findByUserId: (userId) => persist("PhoneStore.findByUserId")(selectByUserId(userId)),
    claim,
    deleteForUser: (userId) =>
      persist("PhoneStore.deleteForUser")(Effect.map(deleteByUserId(userId), (rows) => rows.length))
  })
})

/**
 * Provides {@link PhoneStore} over an ambient `SqlClient`.
 *
 * **Gotchas**
 *
 * Provide it below both halves of the plugin: the service that serves the
 * endpoints, and the `Authenticators` contributor, which goes *underneath* the
 * deployment. One layer, memoised by the `SqlClient` it is built over, so both
 * read the same statements.
 *
 * @category layers
 * @since 0.2.0
 */
export const layer: Layer.Layer<PhoneStore, never, SqlClient.SqlClient> = Layer.effect(PhoneStore, make)
