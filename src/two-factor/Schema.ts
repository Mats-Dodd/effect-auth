/**
 * The three rows this plugin owns.
 *
 * **Details**
 *
 * One `Model.Class` per table, declared the way the core models are: the
 * generated columns come from the model, every secret column is
 * `Model.Sensitive` — so it is absent from the JSON variant and can never
 * reach a response or the OpenAPI document — and every timestamp is
 * `DateTimeUtcFromString`, which is what makes an expiry comparable inside a
 * SQL predicate.
 *
 * **Gotchas**
 *
 * `TotpEnrolment` has no `id`: a person has one authenticator-app enrolment and
 * `user_id` is the primary key, which is what lets the enrolment be replaced by
 * a single `ON CONFLICT` statement.
 *
 * @since 0.2.0
 */
import { Schema } from "effect"
import { Model } from "effect/unstable/schema"
import { UserId } from "../domain/Schema.js"

/**
 * A person's authenticator-app enrolment.
 *
 * **Details**
 *
 * `verifiedAt` is the state machine: `null` is a *pending* enrolment — a secret
 * that has been shown to somebody but never proved — and a pending enrolment is
 * never accepted for authentication. `lastUsedStep` is the replay guard: the
 * TOTP step this enrolment last authenticated with, which no later code may be
 * at or below.
 *
 * @category models
 * @since 0.2.0
 */
export class TotpEnrolment extends Model.Class<TotpEnrolment>("effect-auth/two-factor/TotpEnrolment")({
  userId: UserId,
  /** The shared secret, encrypted under `AuthCipher` with the user id as AAD. */
  secretCiphertext: Model.Sensitive(Schema.String),
  /** When a code proved the enrolment. `null` while it is pending. */
  verifiedAt: Schema.NullOr(Schema.DateTimeUtcFromString),
  /** The last step accepted, or `null` if none ever was. */
  lastUsedStep: Schema.NullOr(Schema.Finite),
  createdAt: Model.DateTimeInsert
}) {}

/**
 * The id of a {@link RecoveryCode} row.
 *
 * @category models
 * @since 0.2.0
 */
export const RecoveryCodeId = Schema.String.pipe(Schema.brand("RecoveryCodeId"))

/**
 * The type of a {@link RecoveryCodeId}.
 *
 * @category models
 * @since 0.2.0
 */
export type RecoveryCodeId = typeof RecoveryCodeId.Type

/**
 * One recovery code, as it is stored.
 *
 * **Details**
 *
 * One row per code rather than one blob per person, so that a code is spent by
 * a single-row `UPDATE ... WHERE used_at IS NULL RETURNING` — atomically, with
 * an audit trail, and with no compare-and-set over a document. `codeHash` is a
 * keyed digest (`Hmac`): a 60-bit code against a fast hash is hours of GPU
 * time, and a salted slow KDF cannot be indexed, so one verification would cost
 * as many KDF runs as the person has codes.
 *
 * @category models
 * @since 0.2.0
 */
export class RecoveryCode extends Model.Class<RecoveryCode>("effect-auth/two-factor/RecoveryCode")({
  id: Model.UuidV7Insert(RecoveryCodeId),
  userId: UserId,
  /** `Hmac.sign` of the normalised code, base64url. Never the code. */
  codeHash: Model.Sensitive(Schema.String),
  /** When it was spent. `null` while it is still good. */
  usedAt: Schema.NullOr(Schema.DateTimeUtcFromString),
  createdAt: Model.DateTimeInsert
}) {}

/**
 * The id of a {@link TrustedDevice} row.
 *
 * @category models
 * @since 0.2.0
 */
export const TrustedDeviceId = Schema.String.pipe(Schema.brand("TrustedDeviceId"))

/**
 * The type of a {@link TrustedDeviceId}.
 *
 * @category models
 * @since 0.2.0
 */
export type TrustedDeviceId = typeof TrustedDeviceId.Type

/**
 * One browser that may skip the interactive second factor.
 *
 * **Details**
 *
 * `expiresAt` is absolute and set once, at creation: a rolling window would be
 * a permanent bypass for whoever holds the cookie. The identifier rotates on
 * every use — `tokenHash` is replaced, the expiry is not — so a stolen copy
 * stops working the moment the real browser signs in again.
 *
 * @category models
 * @since 0.2.0
 */
export class TrustedDevice extends Model.Class<TrustedDevice>("effect-auth/two-factor/TrustedDevice")({
  id: Model.UuidV7Insert(TrustedDeviceId),
  userId: UserId,
  /** `Hmac.sign` of the device token, base64url. Never the token. */
  tokenHash: Model.Sensitive(Schema.String),
  /** Absolute, and never moved. */
  expiresAt: Schema.DateTimeUtcFromString,
  lastUsedAt: Model.DateTimeInsert,
  /** Recorded so a person can recognise the row in their own device list. */
  userAgent: Schema.NullOr(Schema.String),
  /** Recorded for the same reason. Never used for authorization. */
  ipAddress: Schema.NullOr(Schema.String),
  /** What the person called it, if anything. */
  label: Schema.NullOr(Schema.String),
  createdAt: Model.DateTimeInsert
}) {}

/**
 * The `method` an authenticator-app code is recorded under on a session's
 * evidence log.
 *
 * **Details**
 *
 * It lives here rather than beside the service because `Api.ts` names it in the
 * assurance policy the factor-management endpoints carry, and `TwoFactor.ts`
 * imports `Api.ts`. One constant, no cycle, and no second spelling of the
 * string that decides whether a session may turn the second factor off.
 *
 * @category constructors
 * @since 0.2.0
 */
export const totpMethod = "totp"
