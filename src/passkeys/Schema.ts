/**
 * The rows this plugin owns.
 *
 * **Details**
 *
 * Two tables, and neither of them is a column on a core one. `effect_auth_passkeys`
 * holds one row per registered credential; `effect_auth_passkey_users` holds the
 * per-user WebAuthn *handle*, which is the opaque identifier an authenticator
 * stores beside a discoverable credential and hands back on sign-in.
 *
 * **Gotchas — why the handle is not the user id**
 *
 * WebAuthn requires `user.id` to be an opaque byte string of at most 64 bytes
 * that the relying party can map back to an account. A `users.id` satisfies the
 * mechanics and fails the intent: it is a database key that appears in URLs, in
 * logs and in other tables, and an authenticator — a synced one especially —
 * keeps it for the life of the credential and shows it to the person on a
 * credential-management screen. A random 32-byte value per user costs one row
 * and one join and leaks nothing.
 *
 * @since 0.2.0
 */
import { Schema } from "effect"
import { Model } from "effect/unstable/schema"
import { UserId } from "../domain/Schema.js"
import { AuthenticatorTransportsJson } from "./Wire.js"

// -----------------------------------------------------------------------------
// Identifiers
// -----------------------------------------------------------------------------

/**
 * The primary key of a row in `effect_auth_passkeys` — a UUIDv7, as every id
 * this library writes is.
 *
 * **Gotchas**
 *
 * Not the *credential* id. The credential id is chosen by the authenticator and
 * is globally unique by its own construction; this is the handle a person's own
 * management endpoints name a credential by, so that a rename or a delete never
 * has to put an authenticator-chosen value on a URL.
 *
 * @category models
 * @since 0.2.0
 */
export const PasskeyId: Schema.brand<Schema.String, "PasskeyId"> = Schema.String.pipe(Schema.brand("PasskeyId"))

/**
 * The type of a {@link PasskeyId}.
 *
 * @category models
 * @since 0.2.0
 */
export type PasskeyId = typeof PasskeyId.Type

// -----------------------------------------------------------------------------
// Passkey
// -----------------------------------------------------------------------------

/**
 * One registered WebAuthn credential.
 *
 * **Details**
 *
 * `publicKey` is the COSE key the authenticator produced, stored base64url in a
 * `text` column — there is no blob helper in this library's model vocabulary and
 * every migration it ships is all-text, so the codec does the work.
 *
 * `backupEligible` is set once, at registration, and never written again: it is
 * a property of the credential, not of its current state, and an authenticator
 * that changed its mind about it would be describing a different credential.
 * `backedUp` and `uvInitialised` are updated on every ceremony, because both
 * genuinely move — a passkey gets synced, and an authenticator that had no PIN
 * acquires one.
 *
 * **Gotchas**
 *
 * `publicKey` is `Model.Sensitive` although a public key is not a secret. It is
 * precautionary and it is about *shape*, not confidentiality: the variant
 * machinery is what stops a row reaching a response body by accident, and
 * nothing outside the verifier has any business reading these bytes.
 *
 * @category models
 * @since 0.2.0
 */
export class Passkey extends Model.Class<Passkey>("effect-auth/passkeys/Passkey")({
  id: Model.UuidV7Insert(PasskeyId),
  userId: UserId,
  /**
   * The authenticator's own credential id, base64url. Unique across the table.
   *
   * WebAuthn caps a *raw* credential id at 1023 bytes, which is 1364 characters
   * base64url — the bound the `credential` column role is sized from, stated
   * here so it is the domain's and not only MySQL's.
   */
  credentialId: Schema.String.pipe(Schema.check(Schema.isMaxLength(1364))),
  /** The COSE public key, stored base64url. */
  publicKey: Model.Sensitive(Schema.Uint8ArrayFromBase64Url),
  /** The authenticator's use counter, or `0` for the many that do not keep one. */
  signCount: Schema.Int,
  /** How the browser said this credential is reached. A JSON array in a `text` column. */
  transports: AuthenticatorTransportsJson,
  /** The authenticator model's identifier, or the all-zero UUID when it declared none. */
  aaguid: Schema.String,
  /** Whether the credential may ever be backed up. Immutable. */
  backupEligible: Schema.Boolean,
  /** Whether it currently is. Re-read from every ceremony. */
  backedUp: Schema.Boolean,
  /** Whether the authenticator has ever verified the person to itself. */
  uvInitialised: Schema.Boolean,
  /** Whatever the person called it, or `null`. */
  name: Schema.NullOr(Schema.String),
  createdAt: Model.DateTimeInsert,
  /** When it last completed an authentication, or `null` if it never has. */
  lastUsedAt: Schema.NullOr(Schema.DateTimeUtcFromString)
}) {}

// -----------------------------------------------------------------------------
// Handle
// -----------------------------------------------------------------------------

/**
 * How many bytes of randomness a WebAuthn user handle carries.
 *
 * **Details**
 *
 * 32, which base64url-encodes to 43 characters — comfortably inside WebAuthn's
 * 64-byte ceiling on `user.id` and inside the column's `varchar(86)`.
 *
 * @category constructors
 * @since 0.2.0
 */
export const handleBytes = 32

/**
 * A user's WebAuthn handle: the opaque `user.id` this deployment issues them.
 *
 * @category models
 * @since 0.2.0
 */
export const PasskeyUser = Schema.Struct({
  userId: UserId,
  /** 32 random bytes, base64url. Never the user id — see the module header. */
  handle: Schema.String
})

/**
 * The type of a {@link PasskeyUser}.
 *
 * @category models
 * @since 0.2.0
 */
export type PasskeyUser = typeof PasskeyUser.Type
