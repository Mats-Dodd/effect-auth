/**
 * The pending half of an OAuth authorization request.
 *
 * Between "the browser was sent to the provider" and "the browser came back"
 * the server has to remember four things: which provider this was, where the
 * person should land afterwards, the PKCE code verifier whose challenge went
 * out in the redirect, and — for OIDC — the nonce the `id_token` must echo.
 * That is what a state row is.
 *
 * **Details**
 *
 * The row lives in the `verifications` table and is claimed with
 * `VerificationStore.consume`, a single `DELETE ... RETURNING` guarded by the
 * expiry. That one statement is the whole CSRF and replay story: two callbacks
 * carrying the same `state` cannot both be served, an expired request cannot be
 * served at all, and a callback carrying a `state` nobody issued matches
 * nothing.
 *
 * **Gotchas**
 *
 * The `state` value that travels through the browser is a 43-character random
 * token; what is stored is its SHA-256 digest, in *both* the `identifier` and
 * the `value_hash` column. The specification writes the identifier as
 * `oauth-state:<nonce>`; storing the raw nonce there would put a live CSRF
 * token in cleartext in the database, which the security checklist ("state
 * nonce hashed at rest") forbids, so the digest is what names the row. The
 * provider the state was issued for is carried in the payload and re-checked on
 * consumption, so a state minted for one provider cannot be redeemed at
 * another's callback.
 *
 * @since 1.0.0
 */
import { DateTime, Effect, Option, Redacted, Schema } from "effect"
import { AuthConfig } from "../config/AuthConfig.js"
import { Token } from "../crypto/Token.js"
import { OAuthStateMismatch } from "../domain/Errors.js"
import type { UserId } from "../domain/Schema.js"
import { oauthStateIdentifier, UserId as UserIdSchema, Verification } from "../domain/Schema.js"
import type { PersistenceError } from "../domain/Stores.js"
import { VerificationStore } from "../domain/Stores.js"
import { insertRow } from "../internal/effects.js"

// -----------------------------------------------------------------------------
// Payload
// -----------------------------------------------------------------------------

/**
 * What a state row remembers, stored as JSON in `verifications.payload`.
 *
 * **Gotchas**
 *
 * `payload` is a `Model.Sensitive` column: it holds the PKCE code verifier and
 * so never appears in a JSON projection of the model.
 *
 * @category models
 * @since 1.0.0
 */
export const StatePayload = Schema.Struct({
  /** The provider this request was started for. Re-checked on the callback. */
  providerId: Schema.String,
  /**
   * Where to send the browser after a successful callback, already validated
   * against `trustedOrigins` by the caller that started the flow.
   */
  callbackURL: Schema.NullOr(Schema.String),
  /** Where to send the browser when the callback fails. Also pre-validated. */
  errorURL: Schema.NullOr(Schema.String),
  /** The PKCE verifier whose S256 challenge went out in the redirect. */
  codeVerifier: Schema.String,
  /** The OIDC nonce the `id_token` must echo, or `null` for plain OAuth2. */
  nonce: Schema.NullOr(Schema.String),
  /**
   * Set when this flow is linking a provider to an already signed-in user
   * (`POST /auth/link-social`) rather than signing anybody in.
   */
  linkUserId: Schema.NullOr(UserIdSchema),
  /** Whether the session this callback creates should be a long-lived one. */
  rememberMe: Schema.Boolean
})

/**
 * The type of a {@link StatePayload}.
 *
 * @category models
 * @since 1.0.0
 */
export type StatePayload = typeof StatePayload.Type

const StateJson = Schema.fromJsonString(StatePayload)

// -----------------------------------------------------------------------------
// Issuing
// -----------------------------------------------------------------------------

/**
 * What {@link issue} needs to know.
 *
 * @category models
 * @since 1.0.0
 */
export interface IssueOptions {
  readonly providerId: string
  readonly callbackURL?: string | null | undefined
  readonly errorURL?: string | null | undefined
  readonly linkUserId?: UserId | null | undefined
  readonly rememberMe?: boolean | undefined
  /**
   * Whether to mint an OIDC nonce. `true` for a provider with an issuer, whose
   * `id_token` must then echo it.
   */
  readonly withNonce: boolean
}

/**
 * A minted, stored authorization request.
 *
 * @category models
 * @since 1.0.0
 */
export interface IssuedState {
  /** The opaque value that travels as `state`. Only its digest is stored. */
  readonly state: Redacted.Redacted<string>
  /** The PKCE verifier, sent later on the token request. */
  readonly codeVerifier: Redacted.Redacted<string>
  /** The `code_challenge` that goes out now: base64url SHA-256 of the verifier. */
  readonly codeChallenge: string
  /** The nonce that goes out now, when one was requested. */
  readonly nonce: string | null
  /** When this request stops being redeemable. */
  readonly expiresAt: DateTime.Utc
}

/**
 * The `code_challenge_method` this library sends. There is no `plain`
 * fallback: a downgrade to `plain` makes PKCE decorative.
 *
 * @category constructors
 * @since 1.0.0
 */
export const codeChallengeMethod = "S256"

/**
 * Mints a state nonce and a PKCE verifier and stores the pending request.
 *
 * @category combinators
 * @since 1.0.0
 */
export const issue: (
  options: IssueOptions
) => Effect.Effect<IssuedState, PersistenceError, AuthConfig | Token | VerificationStore> = Effect.fnUntraced(
  function*(options: IssueOptions) {
    const config = yield* AuthConfig
    const tokens = yield* Token
    const store = yield* VerificationStore

    const state = yield* tokens.generateToken
    const stateHash = yield* tokens.hashToken(state)
    const codeVerifier = yield* tokens.generateToken
    // `hashToken` is base64url of the SHA-256 of the value's UTF-8 bytes, which
    // is exactly the PKCE S256 transformation.
    const codeChallenge = yield* tokens.hashToken(codeVerifier)
    const nonce = options.withNonce ? Redacted.value(yield* tokens.generateToken) : null

    const now = yield* DateTime.now
    const expiresAt = DateTime.addDuration(now, config.tokens.oauthStateTtl)

    const payload = yield* Effect.orDie(Schema.encodeEffect(StateJson)({
      providerId: options.providerId,
      callbackURL: options.callbackURL ?? null,
      errorURL: options.errorURL ?? null,
      codeVerifier: Redacted.value(codeVerifier),
      nonce,
      linkUserId: options.linkUserId ?? null,
      rememberMe: options.rememberMe ?? true
    }))

    const row = yield* insertRow(Verification.insert, {
      identifier: oauthStateIdentifier(stateHash),
      valueHash: stateHash,
      payload,
      expiresAt
    })
    yield* store.create(row)

    return { state, codeVerifier, codeChallenge, nonce, expiresAt } satisfies IssuedState
  }
)

// -----------------------------------------------------------------------------
// Consuming
// -----------------------------------------------------------------------------

/**
 * Claims a pending authorization request, atomically and exactly once.
 *
 * **Details**
 *
 * Unknown, already consumed, expired and issued-for-another-provider all fail
 * the same `OAuthStateMismatch`. The distinctions are not the caller's
 * business: each of them means "this callback does not belong to a request this
 * server started", and separating them would tell somebody probing the endpoint
 * which of their guesses was closest.
 *
 * @category combinators
 * @since 1.0.0
 */
export const consume: (
  providerId: string,
  state: Redacted.Redacted<string>
) => Effect.Effect<StatePayload, OAuthStateMismatch | PersistenceError, Token | VerificationStore> = Effect
  .fnUntraced(
    function*(providerId: string, state: Redacted.Redacted<string>) {
      const tokens = yield* Token
      const store = yield* VerificationStore

      const stateHash = yield* tokens.hashToken(state)
      const claimed = yield* store.consume(oauthStateIdentifier(stateHash), stateHash)
      if (Option.isNone(claimed)) {
        return yield* Effect.fail(new OAuthStateMismatch())
      }

      const payload = claimed.value.payload
      if (payload === null) {
        return yield* Effect.fail(new OAuthStateMismatch())
      }

      const decoded = yield* Effect.mapError(
        Schema.decodeEffect(StateJson)(payload),
        () => new OAuthStateMismatch()
      )
      if (decoded.providerId !== providerId) {
        return yield* Effect.fail(new OAuthStateMismatch())
      }
      return decoded
    }
  )
