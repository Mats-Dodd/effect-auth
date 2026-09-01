/**
 * The three tables behind {@link TwoFactor}, as one service.
 *
 * **Details**
 *
 * A seam of the plugin's own, on the terms the core stores are declared: an
 * interface, a key, and one SQL implementation. Every statement that spends
 * something is a single guarded `UPDATE ... RETURNING` — never a read, a check
 * and a write — so two requests racing over one code, one step or one device
 * cannot both win:
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
 * `last_used_step` is the one numeric column in this library. `@effect/sql`
 * drivers disagree about `bigint`: PGlite hands back a `number`, others a
 * `string`. It is normalised on the way in, exactly as SQLite's integer
 * booleans are in `SqlStores`.
 *
 * @since 0.2.0
 */
import { Array, Context, DateTime, Effect, Layer, Option, Schema } from "effect"
import { SqlClient } from "effect/unstable/sql"
import type { UserId } from "../domain/Schema.js"
import { PersistenceError } from "../domain/Stores.js"
import { RecoveryCode, TotpEnrolment, TrustedDevice } from "./Schema.js"

// -----------------------------------------------------------------------------
// Projections
// -----------------------------------------------------------------------------

const totpColumns = `user_id AS "userId", secret_ciphertext AS "secretCiphertext", verified_at AS "verifiedAt", last_used_step AS "lastUsedStep", created_at AS "createdAt"`

const deviceColumns = `id, user_id AS "userId", token_hash AS "tokenHash", expires_at AS "expiresAt", last_used_at AS "lastUsedAt", user_agent AS "userAgent", ip_address AS "ipAddress", label, created_at AS "createdAt"`

/** A row as the driver hands it over, before it is decoded. */
type Row = Record<string, unknown>

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
  const totpCols = sql.literal(totpColumns)
  const deviceCols = sql.literal(deviceColumns)

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
          return yield* sql<Row>`INSERT INTO effect_auth_totp (user_id, secret_ciphertext, verified_at, last_used_step, created_at)
            VALUES (${row.userId}, ${row.secretCiphertext}, NULL, NULL, ${row.createdAt})
            ON CONFLICT (user_id) DO UPDATE
              SET secret_ciphertext = excluded.secret_ciphertext,
                  verified_at = NULL,
                  last_used_step = NULL,
                  created_at = excluded.created_at
              WHERE effect_auth_totp.verified_at IS NULL
            RETURNING ${totpCols}`
        })
      ).pipe(Effect.flatMap(firstTotp("TwoFactorStore.upsertPendingTotp"))),

    confirmTotp: (userId, verifiedAt, step) =>
      persist("TwoFactorStore.confirmTotp")(
        sql<Row>`UPDATE effect_auth_totp
          SET verified_at = ${iso(verifiedAt)}, last_used_step = ${step}
          WHERE user_id = ${userId} AND verified_at IS NULL
          RETURNING ${totpCols}`
      ).pipe(Effect.flatMap(firstTotp("TwoFactorStore.confirmTotp"))),

    consumeTotpStep: (userId, step) =>
      persist("TwoFactorStore.consumeTotpStep")(
        Effect.map(
          sql<Row>`UPDATE effect_auth_totp
            SET last_used_step = ${step}
            WHERE user_id = ${userId}
              AND verified_at IS NOT NULL
              AND (last_used_step IS NULL OR last_used_step < ${step})
            RETURNING user_id`,
          (rows) => rows.length > 0
        )
      ),

    deleteTotp: (userId) =>
      persist("TwoFactorStore.deleteTotp")(
        Effect.map(
          sql<Row>`DELETE FROM effect_auth_totp WHERE user_id = ${userId} RETURNING user_id`,
          (rows) => rows.length > 0
        )
      ),

    replaceRecoveryCodes: (userId, codes) =>
      persist("TwoFactorStore.replaceRecoveryCodes")(
        sql.withTransaction(
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
      ),

    consumeRecoveryCode: (userId, codeHash, usedAt) =>
      persist("TwoFactorStore.consumeRecoveryCode")(
        Effect.map(
          sql<Row>`UPDATE effect_auth_recovery_codes
            SET used_at = ${iso(usedAt)}
            WHERE user_id = ${userId} AND code_hash = ${codeHash} AND used_at IS NULL
            RETURNING id`,
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
        Effect.map(
          sql<Row>`DELETE FROM effect_auth_recovery_codes WHERE user_id = ${userId} RETURNING id`,
          (rows) => rows.length
        )
      ),

    createDevice: (device) =>
      persist("TwoFactorStore.createDevice")(
        Effect.gen(function* () {
          const row = yield* Effect.orDie(encodeDeviceInsert(device))
          const rows = yield* sql<Row>`INSERT INTO effect_auth_trusted_devices
            (id, user_id, token_hash, expires_at, last_used_at, user_agent, ip_address, label, created_at)
            VALUES (${row.id}, ${row.userId}, ${row.tokenHash}, ${row.expiresAt}, ${row.lastUsedAt}, ${row.userAgent}, ${row.ipAddress}, ${row.label}, ${row.createdAt})
            RETURNING ${deviceCols}`
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
        sql<Row>`UPDATE effect_auth_trusted_devices
          SET token_hash = ${nextTokenHash}, last_used_at = ${iso(now)}
          WHERE token_hash = ${tokenHash} AND expires_at > ${iso(now)}
          RETURNING ${deviceCols}`
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
          sql<Row>`DELETE FROM effect_auth_trusted_devices WHERE id = ${id} AND user_id = ${userId} RETURNING id`,
          (rows) => rows.length > 0
        )
      ),

    deleteDevices: (userId) =>
      persist("TwoFactorStore.deleteDevices")(
        Effect.map(
          sql<Row>`DELETE FROM effect_auth_trusted_devices WHERE user_id = ${userId} RETURNING id`,
          (rows) => rows.length
        )
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
