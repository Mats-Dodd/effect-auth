/**
 * The three tables behind {@link TwoFactor}, as one service.
 *
 * **Details**
 *
 * A seam of the plugin's own, on the terms the core stores are declared: an
 * interface, a key, and one SQL implementation. Every statement that spends
 * something is a *guarded* write that answers with what it wrote — never a
 * read, a check and a write — so two requests racing over one code, one step or
 * one device cannot both win:
 *
 * - {@link TwoFactorStoreService.consumeTotpStep} refuses a step at or below
 *   the one already recorded, in the predicate.
 * - {@link TwoFactorStoreService.consumeRecoveryCode} refuses a code that
 *   already has a `used_at`, in the predicate.
 * - {@link TwoFactorStoreService.useDevice} rotates the token *and* checks the
 *   absolute expiry in the predicate, so an expired device cannot be revived by
 *   using it.
 *
 * **Gotchas**
 *
 * Those guarded writes reach the database through `Mutations`, which is where
 * the fact that MySQL has no `RETURNING` is dealt with: PostgreSQL and SQLite
 * run the single statement they always ran, and MySQL takes the row's key under
 * `SELECT ... FOR UPDATE`, writes, and reads back by that key inside one
 * transaction. The guard is therefore evaluated exactly once on every dialect,
 * which is what keeps "exactly one of two racing callers wins" true.
 *
 * `last_used_step` is the one numeric column in this library. `@effect/sql`
 * drivers disagree about `bigint`: PGlite hands back a `number`, others a
 * `string`. It is normalised on the way in, exactly as SQLite's integer
 * booleans are in `SqlStores`.
 *
 * @since 0.2.0
 */
import { Array, Context, DateTime, Effect, Layer, Option, Predicate, Schema } from "effect"
import type { SqlError } from "effect/unstable/sql"
import { SqlClient } from "effect/unstable/sql"
import type { UserId } from "../domain/Schema.js"
import { PersistenceError } from "../domain/Stores.js"
import { dialectOf } from "../sql/Dialect.js"
import * as Mutations from "../sql/Mutations.js"
import { RecoveryCode, TotpEnrolment, TrustedDevice } from "./Schema.js"

// -----------------------------------------------------------------------------
// Projections
// -----------------------------------------------------------------------------

const totpColumns = `user_id AS "userId", secret_ciphertext AS "secretCiphertext", verified_at AS "verifiedAt", last_used_step AS "lastUsedStep", created_at AS "createdAt"`

const deviceColumns = `id, user_id AS "userId", token_hash AS "tokenHash", expires_at AS "expiresAt", last_used_at AS "lastUsedAt", user_agent AS "userAgent", ip_address AS "ipAddress", label, created_at AS "createdAt"`

/** A row as the driver hands it over, before it is decoded. */
type Row = Record<string, unknown>

/** The three tables this plugin owns, and what names a row in each again. */
const totp = "effect_auth_totp"
const recoveryCodes = "effect_auth_recovery_codes"
const trustedDevices = "effect_auth_trusted_devices"

/** An enrolment is one per person, so the person names it. */
const totpKey = ["user_id"]

/** Both of the other two carry a generated id of their own. */
const rowKey = ["id"]

// -----------------------------------------------------------------------------
// Service
// -----------------------------------------------------------------------------

/**
 * The {@link TwoFactorStore} service definition.
 *
 * @category models
 * @since 0.2.0
 */
export interface TwoFactorStoreService {
  /** The person's enrolment, pending or active, or `None`. */
  readonly findTotp: (userId: UserId) => Effect.Effect<Option.Option<TotpEnrolment>, PersistenceError>

  /**
   * Writes a *pending* enrolment, replacing a pending one that is already
   * there and refusing — `None` — to touch an active one.
   *
   * **Details**
   *
   * One `INSERT ... ON CONFLICT (user_id) DO UPDATE ... WHERE verified_at IS
   * NULL`, so "abandoning an enrolment regenerates it" and "an active
   * enrolment may not be silently replaced" are the same statement. A second
   * factor that could be swapped without proving the first one is a takeover.
   */
  readonly upsertPendingTotp: (
    enrolment: typeof TotpEnrolment.insert.Type
  ) => Effect.Effect<Option.Option<TotpEnrolment>, PersistenceError>

  /**
   * Marks a pending enrolment active and records the step that proved it.
   * `None` when there is nothing pending — including when a concurrent request
   * confirmed it first.
   */
  readonly confirmTotp: (
    userId: UserId,
    verifiedAt: DateTime.Utc,
    step: number
  ) => Effect.Effect<Option.Option<TotpEnrolment>, PersistenceError>

  /**
   * Records `step` as used, and answers whether it was allowed to be.
   *
   * **Details**
   *
   * `WHERE verified_at IS NOT NULL AND (last_used_step IS NULL OR
   * last_used_step < step)` — the replay rule, in the predicate. RFC 6238 §5.2
   * asks for "at or below", not "equal to": within one period a code stays
   * valid, so a code read off a shoulder or a phishing page works a second time
   * unless every step up to and including the accepted one is refused
   * afterwards. Two requests carrying the same code produce exactly one `true`.
   */
  readonly consumeTotpStep: (userId: UserId, step: number) => Effect.Effect<boolean, PersistenceError>

  /** Removes the enrolment, and answers whether there was one. */
  readonly deleteTotp: (userId: UserId) => Effect.Effect<boolean, PersistenceError>

  /**
   * Replaces the person's whole recovery-code set, in one transaction.
   *
   * **Gotchas**
   *
   * Every previous code — used or not — is deleted. Regenerating is what a
   * person does when they think the old ones leaked, so leaving any of them
   * live would defeat it.
   */
  readonly replaceRecoveryCodes: (
    userId: UserId,
    codes: ReadonlyArray<typeof RecoveryCode.insert.Type>
  ) => Effect.Effect<void, PersistenceError>

  /**
   * Spends one recovery code, and answers whether it was there to spend.
   *
   * One `UPDATE ... WHERE used_at IS NULL RETURNING`, so two requests carrying
   * the same code produce exactly one `true`.
   */
  readonly consumeRecoveryCode: (
    userId: UserId,
    codeHash: string,
    usedAt: DateTime.Utc
  ) => Effect.Effect<boolean, PersistenceError>

  /** How many of the person's recovery codes are still unspent. */
  readonly countRecoveryCodes: (userId: UserId) => Effect.Effect<number, PersistenceError>

  /** Removes every recovery code the person has, and answers how many went. */
  readonly deleteRecoveryCodes: (userId: UserId) => Effect.Effect<number, PersistenceError>

  /** Remembers a browser. */
  readonly createDevice: (device: typeof TrustedDevice.insert.Type) => Effect.Effect<TrustedDevice, PersistenceError>

  /**
   * Spends a device token and issues its successor, or `None` when the token
   * names no live device.
   *
   * **Details**
   *
   * `WHERE token_hash = $presented AND expires_at > $now` — the absolute expiry
   * is inside the predicate, so an expired device is not merely unreadable but
   * unusable, and `expires_at` itself is not moved. The returned row carries
   * the *new* token hash.
   */
  readonly useDevice: (
    tokenHash: string,
    nextTokenHash: string,
    now: DateTime.Utc
  ) => Effect.Effect<Option.Option<TrustedDevice>, PersistenceError>

  /** The person's live devices, newest first. Expired rows are not listed. */
  readonly listDevices: (
    userId: UserId,
    now: DateTime.Utc
  ) => Effect.Effect<ReadonlyArray<TrustedDevice>, PersistenceError>

  /**
   * Forgets one device of `userId`, and answers whether it was theirs.
   * Ownership is in the statement, so this cannot revoke somebody else's.
   */
  readonly deleteDevice: (id: string, userId: UserId) => Effect.Effect<boolean, PersistenceError>

  /** Forgets every device of `userId`, and answers how many went. */
  readonly deleteDevices: (userId: UserId) => Effect.Effect<number, PersistenceError>
}

/**
 * The two-factor plugin's persistence seam. See {@link TwoFactorStoreService}.
 *
 * @category services
 * @since 0.2.0
 */
export class TwoFactorStore extends Context.Service<TwoFactorStore, TwoFactorStoreService>()(
  "effect-auth/two-factor/Store/TwoFactorStore"
) {}

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

const fail = (operation: string) => (cause: unknown) => PersistenceError.make({ operation, cause })

const persist =
  (operation: string) =>
  <A, E, R>(effect: Effect.Effect<A, E, R>): Effect.Effect<A, PersistenceError, R> =>
    Effect.mapError(effect, fail(operation))

/**
 * The one MySQL failure this store recovers from rather than reporting.
 *
 * **Details**
 *
 * {@link TwoFactorStoreService.replaceRecoveryCodes} deletes a person's whole
 * set and writes a new one in one transaction. Under InnoDB's default
 * REPEATABLE READ the `DELETE ... WHERE user_id = ?` takes a *gap* lock on
 * `effect_auth_recovery_codes_user_id_idx`, and when it matches nothing — which
 * is exactly what generating a first set looks like — that gap is one two
 * different people's ids can share. Both transactions then need an
 * insert-intention lock inside a gap the other holds, and InnoDB reports
 * `ER_LOCK_DEADLOCK`. Two accounts generating codes at the same moment
 * reproduce it in seconds.
 *
 * No ordering of the two statements removes it without weakening what the
 * operation promises — that the whole previous set goes — so the transaction is
 * retried, which is what MySQL's own message asks for and what the operation
 * makes safe: it *replaces* a set, so running it twice leaves what running it
 * once would have. Three attempts, no delay (a delay would need a real clock,
 * and these tests run on a `TestClock`), and only for this failure.
 *
 * PostgreSQL and SQLite do not take gap locks and never reach here.
 */
const isDeadlock = (error: SqlError.SqlError): boolean => Predicate.isTagged(error.reason, "DeadlockError")

/**
 * `bigint` reaches this library as a `number` under PGlite and as a `string`
 * under drivers that refuse to narrow it. The column holds a TOTP step, which
 * is well inside `Number.MAX_SAFE_INTEGER` for the next hundred thousand years,
 * so one normalisation covers both.
 */
const readStep = (value: unknown): unknown => (typeof value === "string" ? Number(value) : value)

/**
 * Builds the SQL implementation of {@link TwoFactorStore}.
 *
 * @category constructors
 * @since 0.2.0
 */
export const make: Effect.Effect<TwoFactorStoreService, never, SqlClient.SqlClient> = Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient
  const dialect = yield* dialectOf(sql)
  const totpCols = sql.literal(totpColumns)
  const deviceCols = sql.literal(deviceColumns)
  const userIdCol = sql.literal("user_id")
  const idCol = sql.literal("id")

  const decodeTotp = Schema.decodeUnknownEffect(TotpEnrolment)
  const decodeDevice = Schema.decodeUnknownEffect(TrustedDevice)
  const encodeTotpInsert = Schema.encodeUnknownEffect(TotpEnrolment.insert)
  const encodeCodeInsert = Schema.encodeUnknownEffect(RecoveryCode.insert)
  const encodeDeviceInsert = Schema.encodeUnknownEffect(TrustedDevice.insert)

  const readTotp = (operation: string, row: Row): Effect.Effect<TotpEnrolment, PersistenceError> =>
    Effect.mapError(decodeTotp({ ...row, lastUsedStep: readStep(row["lastUsedStep"]) }), fail(operation))

  const firstTotp =
    (operation: string) =>
    (rows: ReadonlyArray<Row>): Effect.Effect<Option.Option<TotpEnrolment>, PersistenceError> =>
      Option.match(Array.head(rows), {
        onNone: (): Effect.Effect<Option.Option<TotpEnrolment>, PersistenceError> => Effect.succeedNone,
        onSome: (row) => Effect.asSome(readTotp(operation, row))
      })

  const readDevice = (operation: string, row: Row): Effect.Effect<TrustedDevice, PersistenceError> =>
    Effect.mapError(decodeDevice(row), fail(operation))

  const iso = DateTime.formatIso

  /** {@link isDeadlock}, applied where it is the only failure worth another go. */
  const retryDeadlocks = <A, R>(
    effect: Effect.Effect<A, SqlError.SqlError, R>
  ): Effect.Effect<A, SqlError.SqlError, R> =>
    dialect === "mysql" ? Effect.retry(effect, { times: 2, while: isDeadlock }) : effect

  return TwoFactorStore.of({
    findTotp: (userId) =>
      persist("TwoFactorStore.findTotp")(
        sql<Row>`SELECT ${totpCols} FROM effect_auth_totp WHERE user_id = ${userId}`
      ).pipe(Effect.flatMap(firstTotp("TwoFactorStore.findTotp"))),

    upsertPendingTotp: (enrolment) =>
      persist("TwoFactorStore.upsertPendingTotp")(
        Effect.gen(function* () {
          // The row was built from the model, so an encoding failure here is
          // this library's bug rather than something a caller can act on.
          const row = yield* Effect.orDie(encodeTotpInsert(enrolment))
          return yield* Mutations.upsertAndRead<Row>({
            sql,
            dialect,
            table: totp,
            record: {
              user_id: row.userId,
              secret_ciphertext: row.secretCiphertext,
              created_at: row.createdAt,
              last_used_step: null,
              verified_at: null
            },
            conflict: totpKey,
            // MySQL's `ON DUPLICATE KEY UPDATE` evaluates its assignments left
            // to right and each one sees what the one before it wrote, so a
            // column the condition reads goes last. Here the rule costs nothing
            // — `verified_at` is assigned `NULL` when the guard holds and its
            // own value when it does not, so it cannot move the guard either way
            // — but the ordering is what keeps that true of the *next* column
            // somebody adds, and it is the ordering `Mutations` documents.
            update: ["secret_ciphertext", "created_at", "last_used_step", "verified_at"],
            condition: (current) => sql`${current("verified_at")} IS NULL`,
            columns: totpCols,
            // What "the enrolment is now the one I just wrote" looks like: a
            // pending row for this person. A confirmed row fails the predicate,
            // which is the `None` PostgreSQL expresses as an empty `RETURNING`.
            readBack: sql`user_id = ${row.userId} AND verified_at IS NULL`
          })
        })
      ).pipe(Effect.flatMap(firstTotp("TwoFactorStore.upsertPendingTotp"))),

    confirmTotp: (userId, verifiedAt, step) =>
      persist("TwoFactorStore.confirmTotp")(
        Mutations.updateAndRead<Row>({
          sql,
          dialect,
          table: totp,
          key: totpKey,
          set: { verified_at: iso(verifiedAt), last_used_step: step },
          where: sql`user_id = ${userId} AND verified_at IS NULL`,
          columns: totpCols
        })
      ).pipe(Effect.flatMap(firstTotp("TwoFactorStore.confirmTotp"))),

    consumeTotpStep: (userId, step) =>
      persist("TwoFactorStore.consumeTotpStep")(
        Effect.map(
          Mutations.updateAndRead({
            sql,
            dialect,
            table: totp,
            key: totpKey,
            set: { last_used_step: step },
            where: sql`user_id = ${userId}
              AND verified_at IS NOT NULL
              AND (last_used_step IS NULL OR last_used_step < ${step})`,
            columns: userIdCol
          }),
          (rows) => rows.length > 0
        )
      ),

    deleteTotp: (userId) =>
      persist("TwoFactorStore.deleteTotp")(
        Effect.map(
          Mutations.deleteAndCount({ sql, dialect, table: totp, key: totpKey, where: sql`user_id = ${userId}` }),
          (count) => count > 0
        )
      ),

    replaceRecoveryCodes: (userId, codes) =>
      persist("TwoFactorStore.replaceRecoveryCodes")(
        sql
          .withTransaction(
            Effect.gen(function* () {
              yield* sql`DELETE FROM effect_auth_recovery_codes WHERE user_id = ${userId}`
              if (codes.length === 0) return
              const rows = yield* Effect.orDie(Effect.forEach(codes, (code) => encodeCodeInsert(code)))
              yield* sql`INSERT INTO effect_auth_recovery_codes ${sql.insert(
                rows.map((row) => ({
                  id: row.id,
                  user_id: row.userId,
                  code_hash: row.codeHash,
                  used_at: null,
                  created_at: row.createdAt
                }))
              )}`
            })
          )
          .pipe(retryDeadlocks)
      ),

    consumeRecoveryCode: (userId, codeHash, usedAt) =>
      persist("TwoFactorStore.consumeRecoveryCode")(
        Effect.map(
          Mutations.updateAndRead({
            sql,
            dialect,
            table: recoveryCodes,
            key: rowKey,
            set: { used_at: iso(usedAt) },
            where: sql`user_id = ${userId} AND code_hash = ${codeHash} AND used_at IS NULL`,
            columns: idCol
          }),
          (rows) => rows.length > 0
        )
      ),

    countRecoveryCodes: (userId) =>
      persist("TwoFactorStore.countRecoveryCodes")(
        Effect.map(
          sql<Row>`SELECT id FROM effect_auth_recovery_codes WHERE user_id = ${userId} AND used_at IS NULL`,
          (rows) => rows.length
        )
      ),

    deleteRecoveryCodes: (userId) =>
      persist("TwoFactorStore.deleteRecoveryCodes")(
        Mutations.deleteAndCount({
          sql,
          dialect,
          table: recoveryCodes,
          key: rowKey,
          where: sql`user_id = ${userId}`
        })
      ),

    createDevice: (device) =>
      persist("TwoFactorStore.createDevice")(
        Effect.gen(function* () {
          const row = yield* Effect.orDie(encodeDeviceInsert(device))
          const rows = yield* Mutations.insertAndRead<Row>({
            sql,
            dialect,
            table: trustedDevices,
            key: rowKey,
            record: {
              id: row.id,
              user_id: row.userId,
              token_hash: row.tokenHash,
              expires_at: row.expiresAt,
              last_used_at: row.lastUsedAt,
              user_agent: row.userAgent,
              ip_address: row.ipAddress,
              label: row.label,
              created_at: row.createdAt
            },
            columns: deviceCols
          })
          return yield* Option.match(Array.head(rows), {
            onNone: () =>
              Effect.fail(
                PersistenceError.make({
                  operation: "TwoFactorStore.createDevice",
                  cause: "the statement returned no row"
                })
              ),
            onSome: (created) => readDevice("TwoFactorStore.createDevice", created)
          })
        })
      ),

    useDevice: (tokenHash, nextTokenHash, now) =>
      persist("TwoFactorStore.useDevice")(
        Mutations.updateAndRead<Row>({
          sql,
          dialect,
          table: trustedDevices,
          key: rowKey,
          set: { token_hash: nextTokenHash, last_used_at: iso(now) },
          where: sql`token_hash = ${tokenHash} AND expires_at > ${iso(now)}`,
          columns: deviceCols
        })
      ).pipe(
        Effect.flatMap((rows) =>
          Option.match(Array.head(rows), {
            onNone: (): Effect.Effect<Option.Option<TrustedDevice>, PersistenceError> => Effect.succeedNone,
            onSome: (row) => Effect.asSome(readDevice("TwoFactorStore.useDevice", row))
          })
        )
      ),

    listDevices: (userId, now) =>
      persist("TwoFactorStore.listDevices")(
        sql<Row>`SELECT ${deviceCols} FROM effect_auth_trusted_devices
          WHERE user_id = ${userId} AND expires_at > ${iso(now)}
          ORDER BY created_at DESC`
      ).pipe(Effect.flatMap((rows) => Effect.forEach(rows, (row) => readDevice("TwoFactorStore.listDevices", row)))),

    deleteDevice: (id, userId) =>
      persist("TwoFactorStore.deleteDevice")(
        Effect.map(
          Mutations.deleteAndCount({
            sql,
            dialect,
            table: trustedDevices,
            key: rowKey,
            where: sql`id = ${id} AND user_id = ${userId}`
          }),
          (count) => count > 0
        )
      ),

    deleteDevices: (userId) =>
      persist("TwoFactorStore.deleteDevices")(
        Mutations.deleteAndCount({
          sql,
          dialect,
          table: trustedDevices,
          key: rowKey,
          where: sql`user_id = ${userId}`
        })
      )
  })
})

/**
 * Provides {@link TwoFactorStore} over the ambient `SqlClient`.
 *
 * @category layers
 * @since 0.2.0
 */
export const layer: Layer.Layer<TwoFactorStore, never, SqlClient.SqlClient> = Layer.effect(TwoFactorStore, make)
