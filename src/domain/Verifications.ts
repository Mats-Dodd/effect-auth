/**
 * Single-use, expiring tokens — the mechanism behind every e-mail link.
 *
 * A verification is a secret handed to somebody out of band (a mailbox, a
 * message) that comes back exactly once. `Verifications` owns the three
 * operations that make that work: minting one ({@link VerificationsService.issue}),
 * claiming it atomically ({@link VerificationsService.claim}), and retiring the
 * ones a claim invalidated ({@link VerificationsService.retire}).
 *
 * **Details**
 *
 * The shape is lifted straight out of the password flows, where it was written
 * twice, and generalized on exactly one axis: a {@link TokenPurpose}. A purpose
 * names the row (`<name>:<subject>` — see {@link identifierOf}) and, optionally,
 * declares a schema for a payload that travels with the token. That is what lets
 * a plugin — a magic link, a change-email confirmation — mint tokens of its own
 * without a second copy of this module and without a table of its own.
 *
 * Nothing here stores a secret. The 43-character random half is hashed with
 * SHA-256 and only the digest reaches the database; claiming is a single
 * `DELETE ... RETURNING` guarded by the expiry, which is the whole of the
 * single-use and replay story.
 *
 * **Gotchas**
 *
 * A payload is stored *unencrypted* in the `verifications` table, so it is
 * server-side state, not a secret: put an address or a callback URL in one,
 * never a credential.
 *
 * @since 1.0.0
 */
import { Context, DateTime, type Duration, Effect, Encoding, Layer, Option, Redacted, Result, Schema } from "effect"
import { Token } from "../crypto/Token.js"
import { insertRow } from "../internal/effects.js"
import { InvalidToken } from "./Errors.js"
import type { UserId, Verification } from "./Schema.js"
import { Verification as VerificationModel } from "./Schema.js"
import type { PersistenceError } from "./Stores.js"
import { VerificationStore } from "./Stores.js"

// -----------------------------------------------------------------------------
// Subject tokens
// -----------------------------------------------------------------------------

/**
 * The separator between a subject-token's subject and its secret. Neither half
 * can contain it: the subject is base64url encoded and the secret is a
 * base64url token.
 *
 * @category constructors
 * @since 1.0.0
 */
export const subjectTokenSeparator = "."

/**
 * Pairs the subject a single-use token belongs to with the secret itself.
 *
 * @category models
 * @since 1.0.0
 */
export interface SubjectToken {
  /** The user id, normalized e-mail address, or whatever else names the row. */
  readonly subject: string
  /** The 43-character random half, the only part that is hashed and stored. */
  readonly secret: Redacted.Redacted
}

/**
 * Builds the token that goes into an e-mail link:
 * `<base64url(subject)>.<secret>`.
 *
 * **Details**
 *
 * `Verification.identifier` is namespaced by subject (`password-reset:<userId>`,
 * `email-verify:<email>`), and `VerificationStore.consume` — the atomic
 * single-use claim — needs both the identifier and the value hash. A recipient
 * presenting only a bare secret could not name the row, so the subject travels
 * with it. The subject is not a secret; the 256 bits of randomness beside it
 * are, and only their digest is stored.
 *
 * @category constructors
 * @since 1.0.0
 */
export const encodeSubjectToken = (subject: string, secret: Redacted.Redacted): Redacted.Redacted =>
  Redacted.make(`${Encoding.encodeBase64Url(subject)}${subjectTokenSeparator}${Redacted.value(secret)}`)

/**
 * Splits a subject token back into its subject and its secret, or `None` when
 * it is not a subject token at all.
 *
 * @category combinators
 * @since 1.0.0
 */
export const decodeSubjectToken = (token: Redacted.Redacted): Option.Option<SubjectToken> => {
  const raw = Redacted.value(token)
  const at = raw.indexOf(subjectTokenSeparator)
  if (at <= 0 || at === raw.length - 1) return Option.none()
  const subject = Encoding.decodeBase64UrlString(raw.slice(0, at))
  if (Result.isFailure(subject)) return Option.none()
  return Option.some({ subject: subject.success, secret: Redacted.make(raw.slice(at + 1)) })
}

// -----------------------------------------------------------------------------
// Purposes
// -----------------------------------------------------------------------------

/**
 * What a purpose's payload schema has to be: a codec that needs no services to
 * run, because it is decoded on the request path with nothing provided to it.
 *
 * @category models
 * @since 1.0.0
 */
export interface PurposePayload extends Schema.ConstraintCodec<unknown> {}

/**
 * What a class of single-use tokens is called, and what travels inside one.
 *
 * **Details**
 *
 * `name` namespaces the rows: every identifier this purpose writes is
 * `<name>:<subject>` (see {@link identifierOf}), so two purposes can never
 * claim each other's tokens even when the subject is the same person.
 *
 * `payload` is the JSON-string codec the `verifications.payload` column is
 * written through, or `null` for a purpose that carries nothing. Purposes are
 * built by {@link purpose}, never by hand.
 *
 * @category models
 * @since 1.0.0
 */
export interface TokenPurpose<P> {
  /** The namespace of every row this purpose writes. */
  readonly name: string
  /**
   * The codec the payload column is stored through, or `null` when this purpose
   * declares no payload.
   */
  readonly payload: Schema.ConstraintCodec<P, string> | null
  /**
   * Reads the stored payload column back.
   *
   * **Details**
   *
   * Carried on the purpose rather than derived from `payload` at the call site
   * because the two cases cannot be bridged by a null check: a purpose that
   * declares no payload answers with `null`, and only the constructor — where
   * `P` is still `null` rather than a type parameter — can say so without an
   * assertion. A malformed or absent payload is `InvalidToken`, exactly as a
   * malformed token is: both mean the link is not one this deployment minted.
   */
  readonly decodePayload: (stored: string | null) => Effect.Effect<P, InvalidToken>
}

/**
 * Declares a class of single-use tokens.
 *
 * **Example**
 *
 * ```ts
 * import { Schema } from "effect"
 * import { Verifications } from "effect-auth"
 *
 * const emailChange = Verifications.purpose(
 *   "change-email-verify",
 *   Schema.Struct({ newEmail: Schema.String })
 * )
 * ```
 *
 * **Gotchas**
 *
 * Declare one per module, at module scope: a purpose is inert data, and two
 * purposes with the same `name` are the same rows.
 *
 * @category constructors
 * @since 1.0.0
 */
export function purpose(name: string): TokenPurpose<null>
export function purpose<S extends PurposePayload>(name: string, payload: S): TokenPurpose<S["Type"]>
export function purpose(name: string, payload?: PurposePayload): TokenPurpose<unknown> {
  if (payload === undefined) {
    return { name, payload: null, decodePayload: () => Effect.succeed(null) }
  }
  const json = Schema.fromJsonString(payload)
  const decode = Schema.decodeEffect(json)
  return {
    name,
    payload: json,
    decodePayload: (stored) =>
      stored === null ? Effect.fail(InvalidToken.make()) : Effect.mapError(decode(stored), () => InvalidToken.make())
  }
}

/**
 * The `verifications.identifier` a purpose writes for one subject:
 * `<purpose>:<subject>`.
 *
 * **Gotchas**
 *
 * The subject is used verbatim. An e-mail address must therefore be normalized
 * by the caller — `normalizeEmail` — before it reaches here, or the same person
 * gets two namespaces.
 *
 * @category combinators
 * @since 1.0.0
 */
export const identifierOf = (purpose: TokenPurpose<unknown>, subject: string): string => `${purpose.name}:${subject}`

/**
 * The purpose of an e-mail verification link.
 *
 * @category constructors
 * @since 1.0.0
 */
export const emailVerifyPurpose: TokenPurpose<null> = purpose("email-verify")

/**
 * The purpose of a password reset link.
 *
 * @category constructors
 * @since 1.0.0
 */
export const passwordResetPurpose: TokenPurpose<null> = purpose("password-reset")

/**
 * What travels with either hop of an e-mail change: the address being moved to.
 *
 * **Gotchas**
 *
 * Server-side state in the `verifications` table, not a claim in a URL. That is
 * the whole reason the payload exists — see the module header.
 *
 * @category models
 * @since 1.0.0
 */
export const ChangeEmailPayload = Schema.Struct({
  newEmail: Schema.String
})

/**
 * The type of a {@link ChangeEmailPayload}.
 *
 * @category models
 * @since 1.0.0
 */
export type ChangeEmailPayload = typeof ChangeEmailPayload.Type

/**
 * What travels with an account-deletion link: where to send the browser
 * afterwards.
 *
 * @category models
 * @since 1.0.0
 */
export const DeleteAccountPayload = Schema.Struct({
  callbackURL: Schema.NullOr(Schema.String)
})

/**
 * The type of a {@link DeleteAccountPayload}.
 *
 * @category models
 * @since 1.0.0
 */
export type DeleteAccountPayload = typeof DeleteAccountPayload.Type

/**
 * The first hop of an e-mail change: the link sent to the address the account
 * currently has. Its subject is the user's id.
 *
 * @category constructors
 * @since 1.0.0
 */
export const changeEmailConfirmPurpose: TokenPurpose<ChangeEmailPayload> = purpose(
  "change-email-confirm",
  ChangeEmailPayload
)

/**
 * The second hop: the link sent to the new address, which is what actually
 * changes the column. Its subject is the user's id.
 *
 * @category constructors
 * @since 1.0.0
 */
export const changeEmailVerifyPurpose: TokenPurpose<ChangeEmailPayload> = purpose(
  "change-email-verify",
  ChangeEmailPayload
)

/**
 * An account-deletion confirmation link. Its subject is the user's id.
 *
 * @category constructors
 * @since 1.0.0
 */
export const deleteAccountPurpose: TokenPurpose<DeleteAccountPayload> = purpose("delete-account", DeleteAccountPayload)

/**
 * Every purpose this library mints tokens under whose subject is a **user id**.
 *
 * **When to use**
 *
 * Wherever an account stops being the account those tokens were minted against.
 *
 * *A user is deleted.* Whatever is outstanding for them has to go with the row:
 * a link that outlives the account it names is a link that will one day name
 * somebody else's.
 *
 * *An account is re-secured.* A password reset, and the magic link plugin's
 * takeover defence, both destroy the ways into an account that somebody else
 * may have set up — and an outstanding link is one of those ways. A
 * `change-email-verify` token in particular moves the account to the address
 * that asked for it, so leaving one alive would hand back everything the reset
 * just took away.
 *
 * **Gotchas**
 *
 * `email-verify` is not in the list and cannot be: its subject is the address,
 * not the id. A caller retiring tokens for a user retires that one separately,
 * against `normalizeEmail(user.email)`.
 *
 * @category constructors
 * @since 1.0.0
 */
export const userSubjectPurposes: ReadonlyArray<TokenPurpose<unknown>> = [
  passwordResetPurpose,
  changeEmailConfirmPurpose,
  changeEmailVerifyPurpose,
  deleteAccountPurpose
]

/**
 * Retires every outstanding token whose subject is this user — one call for
 * each of the {@link userSubjectPurposes}.
 *
 * **When to use**
 *
 * Wherever an account stops being the account those tokens were minted against:
 * a deletion, a password reset, a magic-link takeover defence. See
 * {@link userSubjectPurposes} for what each of those has to destroy, and for
 * why `email-verify` is not among them.
 *
 * @category combinators
 * @since 1.0.0
 */
export const retireUserSubjectTokens = (
  verifications: VerificationsService,
  userId: UserId
): Effect.Effect<void, PersistenceError> =>
  Effect.forEach(userSubjectPurposes, (purpose) => verifications.retire(purpose, userId), { discard: true })

// -----------------------------------------------------------------------------
// Service
// -----------------------------------------------------------------------------

/**
 * What {@link VerificationsService.issue} needs to know.
 *
 * @category models
 * @since 1.0.0
 */
export interface IssueOptions<P> {
  /** The class of token to mint. */
  readonly purpose: TokenPurpose<P>
  /** Who or what the token is about — a user id, a normalized address. */
  readonly subject: string
  /** How long the token may be claimed for. */
  readonly ttl: Duration.Duration
  /** What travels with it, `null` for a purpose that declares no payload. */
  readonly payload: P
}

/**
 * A minted token.
 *
 * **Gotchas**
 *
 * `token` is the only copy that will ever exist — the database holds its digest.
 * Put it in a link and drop it.
 *
 * @category models
 * @since 1.0.0
 */
export interface Issued {
  readonly token: Redacted.Redacted
  readonly expiresAt: DateTime.Utc
  readonly identifier: string
}

/**
 * A claimed token: what it was about, what travelled with it, and the row it
 * consumed.
 *
 * @category models
 * @since 1.0.0
 */
export interface Claimed<P> {
  readonly subject: string
  readonly payload: P
  readonly identifier: string
  /** The consumed row, for a caller that wants its `createdAt` or its id. */
  readonly verification: Verification
}

/**
 * The {@link Verifications} service definition.
 *
 * @category models
 * @since 1.0.0
 */
export interface VerificationsService {
  /**
   * Mints a single-use token, stores its digest under the purpose's identifier,
   * and answers with the token itself.
   */
  readonly issue: <P>(options: IssueOptions<P>) => Effect.Effect<Issued, PersistenceError>

  /**
   * Claims a token: one atomic `DELETE ... RETURNING` guarded by the expiry.
   *
   * **Gotchas**
   *
   * Every way of failing is one answer, `InvalidToken`: a token that is not a
   * subject token at all, one whose row is unknown, already claimed or expired,
   * and one whose payload no longer decodes. Distinguishing them would tell a
   * caller whether a token was ever issued.
   */
  readonly claim: <P>(
    purpose: TokenPurpose<P>,
    token: Redacted.Redacted
  ) => Effect.Effect<Claimed<P>, InvalidToken | PersistenceError>

  /**
   * Deletes every outstanding token of one purpose for one subject, and answers
   * how many went.
   *
   * **When to use**
   *
   * Straight after a claim. Asking for a password reset twice mints two
   * independent tokens, and once one has been used the other must not still
   * work — somebody with transient mailbox access would otherwise hold a key to
   * an account its owner believes they have just re-secured.
   */
  readonly retire: (purpose: TokenPurpose<unknown>, subject: string) => Effect.Effect<number, PersistenceError>
}

/**
 * Mints and claims single-use tokens. See {@link VerificationsService}.
 *
 * @category services
 * @since 1.0.0
 */
export class Verifications extends Context.Service<Verifications, VerificationsService>()(
  "effect-auth/domain/Verifications"
) {}

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

/**
 * Builds the {@link Verifications} implementation over the token service and the
 * verification store.
 *
 * @category constructors
 * @since 1.0.0
 */
export const make: Effect.Effect<VerificationsService, never, Token | VerificationStore> = Effect.gen(function* () {
  const tokens = yield* Token
  const store = yield* VerificationStore

  const issue = Effect.fnUntraced(function* <P>(options: IssueOptions<P>) {
    const secret = yield* tokens.generateToken
    const valueHash = yield* tokens.hashToken(secret)
    const now = yield* DateTime.now
    const expiresAt = DateTime.addDuration(now, options.ttl)
    const identifier = identifierOf(options.purpose, options.subject)
    // A payload that does not fit the schema its own purpose declared is a
    // programming error, not a request the caller can fix.
    const payload =
      options.purpose.payload === null
        ? null
        : yield* Effect.orDie(Schema.encodeEffect(options.purpose.payload)(options.payload))
    const row = yield* insertRow(VerificationModel.insert, {
      identifier,
      valueHash,
      payload,
      expiresAt
    })
    yield* store.create(row)
    return {
      token: encodeSubjectToken(options.subject, secret),
      expiresAt,
      identifier
    } satisfies Issued
  })

  const claim = Effect.fnUntraced(function* <P>(purpose: TokenPurpose<P>, token: Redacted.Redacted) {
    const parts = yield* Effect.fromOption(decodeSubjectToken(token), () => InvalidToken.make())
    const valueHash = yield* tokens.hashToken(parts.secret)
    const identifier = identifierOf(purpose, parts.subject)
    const consumed = yield* store.consume(identifier, valueHash)
    // An expired row was never claimable and a claimed row is already gone:
    // both are `None` here, and both are one and the same answer.
    const verification = yield* Effect.fromOption(consumed, () => InvalidToken.make())
    const payload = yield* purpose.decodePayload(verification.payload)
    return { subject: parts.subject, payload, identifier, verification } satisfies Claimed<P>
  })

  const retire = (purpose: TokenPurpose<unknown>, subject: string): Effect.Effect<number, PersistenceError> =>
    store.deleteByIdentifier(identifierOf(purpose, subject))

  return Verifications.of({ issue, claim, retire })
})

/**
 * Provides {@link Verifications}.
 *
 * @category layers
 * @since 1.0.0
 */
export const layer: Layer.Layer<Verifications, never, Token | VerificationStore> = Layer.effect(Verifications, make)
