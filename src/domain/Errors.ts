/**
 * The tagged error contract of `effect-auth`.
 *
 * These errors are part of the public API: they are declared in the endpoint
 * error unions, encoded over the wire, and matched by tag on the client. Each
 * one is a `Schema.TaggedError`, so it can be yielded inside `Effect.gen`,
 * decoded by the generated client, and rendered in OpenAPI.
 *
 * **Details**
 *
 * Every field here is safe to hand to an unauthenticated caller. No error
 * carries a secret, a token, a password hash, or anything that would let an
 * attacker distinguish "this account exists" from "it does not" — the sign-in
 * and password-reset flows deliberately collapse those cases (see
 * `InvalidCredentials` and the always-200 reset endpoints).
 *
 * @since 0.1.0
 */
import { Schema } from "effect"
import { HttpApiError } from "effect/unstable/httpapi"
import type { PolicyRefused } from "./Hooks.js"
import { AccountId } from "./Schema.js"
import type { PersistenceError } from "./Stores.js"

// -----------------------------------------------------------------------------
// Reused built-ins
// -----------------------------------------------------------------------------

/**
 * A request presented no session, or a session that is no longer valid.
 *
 * **Details**
 *
 * This is `HttpApiError.Unauthorized` re-exported: it already renders as an
 * empty `401` and is understood by the HttpApi builders, clients and OpenAPI
 * generation.
 *
 * @category errors
 * @since 0.1.0
 */
export const Unauthorized = HttpApiError.Unauthorized

/**
 * The type of an {@link Unauthorized} error.
 *
 * @category errors
 * @since 0.1.0
 */
export type Unauthorized = HttpApiError.Unauthorized

/**
 * The addressed resource — a session to revoke, an account to unlink — does not
 * exist, or does not belong to the caller. The two cases are deliberately
 * indistinguishable.
 *
 * @category errors
 * @since 0.1.0
 */
export const NotFound = HttpApiError.NotFound

/**
 * The type of a {@link NotFound} error.
 *
 * @category errors
 * @since 0.1.0
 */
export type NotFound = HttpApiError.NotFound

// -----------------------------------------------------------------------------
// Credentials
// -----------------------------------------------------------------------------

/**
 * The supplied e-mail/password pair did not match a sign-in method.
 *
 * **Details**
 *
 * Raised identically when the user does not exist, when the password is wrong,
 * and when the account has no password credential. The sign-in path always
 * performs a password verification — against a dummy hash when there is no
 * user — so neither the response nor its timing reveals which case occurred.
 *
 * @category errors
 * @since 0.1.0
 */
export class InvalidCredentials extends Schema.TaggedError<InvalidCredentials>("effect-auth/InvalidCredentials")(
  "InvalidCredentials",
  {},
  {
    description: "The credentials provided did not match a known sign-in method",
    httpApiStatus: 401
  }
) {}

/**
 * The account exists and the password was correct, but the address has not been
 * verified and `emailPassword.requireEmailVerification` is enabled.
 *
 * @category errors
 * @since 0.1.0
 */
export class EmailNotVerified extends Schema.TaggedError<EmailNotVerified>("effect-auth/EmailNotVerified")(
  "EmailNotVerified",
  {},
  {
    description: "The account's e-mail address has not been verified",
    httpApiStatus: 403
  }
) {}

/**
 * Sign-up was attempted with an e-mail address that already has an account.
 *
 * @category errors
 * @since 0.1.0
 */
export class UserAlreadyExists extends Schema.TaggedError<UserAlreadyExists>("effect-auth/UserAlreadyExists")(
  "UserAlreadyExists",
  {},
  {
    description: "An account already exists for that e-mail address",
    httpApiStatus: 409
  }
) {}

/**
 * An operation referenced a user that does not exist.
 *
 * **Gotchas**
 *
 * Never surface this from an unauthenticated endpoint keyed by e-mail address —
 * it would be a user-enumeration oracle. It is for authenticated operations
 * whose subject vanished concurrently.
 *
 * @category errors
 * @since 0.1.0
 */
export class UserNotFound extends Schema.TaggedError<UserNotFound>("effect-auth/UserNotFound")(
  "UserNotFound",
  {},
  {
    description: "No user matched the request",
    httpApiStatus: 404
  }
) {}

/**
 * The requested password does not satisfy the configured policy.
 *
 * **Details**
 *
 * `minLength` and `maxLength` echo the active policy so a client can render a
 * precise message without hard-coding the server's configuration.
 *
 * @category errors
 * @since 0.1.0
 */
export class PasswordPolicyViolation extends Schema.TaggedError<PasswordPolicyViolation>(
  "effect-auth/PasswordPolicyViolation"
)(
  "PasswordPolicyViolation",
  {
    reason: Schema.Literals(["TooShort", "TooLong"]),
    minLength: Schema.Finite,
    maxLength: Schema.Finite
  },
  {
    description: "The password did not satisfy the configured password policy",
    httpApiStatus: 422
  }
) {}

/**
 * A change-email request named the address the account already has.
 *
 * **Details**
 *
 * The one case `changeEmail` refuses out loud. Every other outcome — including
 * "that address already belongs to somebody else" — answers `200`, because the
 * endpoint would otherwise tell a signed-in caller which addresses are
 * registered. Naming your *own* address leaks nothing: the caller already knows
 * it.
 *
 * @category errors
 * @since 0.1.0
 */
export class EmailUnchanged extends Schema.TaggedError<EmailUnchanged>("effect-auth/EmailUnchanged")(
  "EmailUnchanged",
  {},
  {
    description: "The requested address is the one the account already has",
    httpApiStatus: 400
  }
) {}

/**
 * `setPassword` was called for a user who already has a password.
 *
 * **Gotchas**
 *
 * This endpoint adds a credential; it never replaces one. Changing a known
 * password is `changePassword` (which asks for the current one) and replacing a
 * forgotten one is the reset flow (which proves control of the mailbox). If
 * `setPassword` could overwrite, a stolen session would be enough to lock the
 * owner out — which is exactly what the fresh-session guard alone does not
 * prevent for ever.
 *
 * @category errors
 * @since 0.1.0
 */
export class PasswordAlreadySet extends Schema.TaggedError<PasswordAlreadySet>("effect-auth/PasswordAlreadySet")(
  "PasswordAlreadySet",
  {},
  {
    description: "The account already has a password credential",
    httpApiStatus: 409
  }
) {}

// -----------------------------------------------------------------------------
// Sessions
// -----------------------------------------------------------------------------

/**
 * The presented session existed but its expiry has passed.
 *
 * @category errors
 * @since 0.1.0
 */
export class SessionExpired extends Schema.TaggedError<SessionExpired>("effect-auth/SessionExpired")(
  "SessionExpired",
  {},
  {
    description: "The session has expired",
    httpApiStatus: 401
  }
) {}

/**
 * The session is valid but too old for a sensitive operation.
 *
 * **Details**
 *
 * Raised by the `requireFresh` guard that changing a password or unlinking an
 * account runs first. The caller must re-authenticate; `freshAgeSeconds` is the
 * configured window a session must have been created within.
 *
 * @category errors
 * @since 0.1.0
 */
export class SessionNotFresh extends Schema.TaggedError<SessionNotFresh>("effect-auth/SessionNotFresh")(
  "SessionNotFresh",
  {
    freshAgeSeconds: Schema.Finite
  },
  {
    description: "The session is not fresh enough for this operation",
    httpApiStatus: 403
  }
) {}

// -----------------------------------------------------------------------------
// Verification values
// -----------------------------------------------------------------------------

/**
 * A verification token — e-mail verification, password reset — was not
 * recognised, was already used, or did not belong to the stated identifier.
 *
 * **Details**
 *
 * Consumption is a single atomic statement, so a token that loses a race
 * reports exactly this, and reports nothing about which of the causes applied.
 *
 * @category errors
 * @since 0.1.0
 */
export class InvalidToken extends Schema.TaggedError<InvalidToken>("effect-auth/InvalidToken")(
  "InvalidToken",
  {},
  {
    description: "The verification token is invalid or has already been used",
    httpApiStatus: 400
  }
) {}

/**
 * A verification token was well-formed and known, but its lifetime has passed.
 *
 * **Gotchas**
 *
 * No endpoint in v1 declares or raises this. `VerificationStore.consume` is a
 * single conditional `DELETE ... RETURNING`, so an expired token leaves no row
 * to inspect and is indistinguishable from an unknown or an already-used one —
 * deliberately, because distinguishing them would leak whether a token was ever
 * issued. Every flow answers {@link InvalidToken}. The class stays exported for
 * an application that holds the row itself and can tell the difference.
 *
 * @category errors
 * @since 0.1.0
 */
export class TokenExpired extends Schema.TaggedError<TokenExpired>("effect-auth/TokenExpired")(
  "TokenExpired",
  {},
  {
    description: "The verification token has expired",
    httpApiStatus: 400
  }
) {}

// -----------------------------------------------------------------------------
// OAuth
// -----------------------------------------------------------------------------

/**
 * The `state` parameter returned by the provider did not match a pending,
 * unexpired, unconsumed authorization request.
 *
 * **Details**
 *
 * This is the CSRF check of the OAuth flow. It also covers a replayed callback:
 * state rows are consumed atomically and are therefore single-use.
 *
 * @category errors
 * @since 0.1.0
 */
export class OAuthStateMismatch extends Schema.TaggedError<OAuthStateMismatch>("effect-auth/OAuthStateMismatch")(
  "OAuthStateMismatch",
  {},
  {
    description: "The OAuth state did not match a pending authorization request",
    httpApiStatus: 400
  }
) {}

/**
 * The set of safe, non-leaking reasons an OAuth exchange can fail.
 *
 * @category models
 * @since 0.1.0
 */
export const OAuthFailureReason = Schema.Literals([
  /** The provider id is not registered with this instance. */
  "UnknownProvider",
  /** The user declined at the provider's consent screen. */
  "AccessDenied",
  /** The provider rejected the authorization code exchange. */
  "TokenExchangeFailed",
  /** The provider's user-info endpoint failed or returned an unusable body. */
  "UserInfoFailed",
  /** An OIDC `id_token` failed signature, issuer, audience, expiry or nonce validation. */
  "IdTokenInvalid",
  /** The provider could not be reached, or answered with a redirect where none is permitted. */
  "ProviderUnavailable",
  /**
   * The client secret could not be produced.
   *
   * **Details**
   *
   * Only a provider whose secret is *minted* rather than configured can report
   * this — Apple, whose secret is a short-lived ES256 assertion signed with the
   * deployment's private key. A malformed key, or a signing primitive the
   * runtime does not offer, lands here rather than as a token exchange the
   * provider silently refuses.
   */
  "ClientSecretUnavailable"
])

/**
 * The type of an {@link OAuthFailureReason}.
 *
 * @category models
 * @since 0.1.0
 */
export type OAuthFailureReason = typeof OAuthFailureReason.Type

/**
 * An OAuth or OIDC exchange with a provider failed.
 *
 * **Gotchas**
 *
 * `reason` is a closed set on purpose. Provider responses are never echoed:
 * they routinely contain the authorization code, the client secret used in the
 * failed request, or raw account data.
 *
 * @category errors
 * @since 0.1.0
 */
export class OAuthProviderError extends Schema.TaggedError<OAuthProviderError>("effect-auth/OAuthProviderError")(
  "OAuthProviderError",
  {
    providerId: Schema.String,
    reason: OAuthFailureReason
  },
  {
    description: "The OAuth provider exchange failed",
    httpApiStatus: 502
  }
) {}

/**
 * Why a stored provider token could not be turned into a usable access token.
 *
 * **Details**
 *
 * A closed set, and each member is a *configuration or provider* condition the
 * caller can act on — reconnect the account, ask the provider again later — not
 * a description of somebody else's credentials.
 *
 * @category models
 * @since 0.1.0
 */
export const TokenRefreshReason = Schema.Literals([
  /** The account belongs to a provider this instance no longer serves. */
  "ProviderNotSupported",
  /** The provider is served, but refreshing is switched off for it. */
  "RefreshNotSupported",
  /** The account has no refresh token: the provider never issued one, or it was consumed. */
  "RefreshTokenMissing",
  /** The account has no access token at all, and none could be obtained. */
  "AccessTokenMissing",
  /** The provider refused the refresh — usually a revoked or expired grant. */
  "RefreshRejected",
  /** The provider could not be reached, or answered with a redirect where none is permitted. */
  "ProviderUnavailable"
])

/**
 * The type of a {@link TokenRefreshReason}.
 *
 * @category models
 * @since 0.1.0
 */
export type TokenRefreshReason = typeof TokenRefreshReason.Type

/**
 * A provider access token could not be produced for one of the caller's linked
 * accounts.
 *
 * **Gotchas**
 *
 * `accountId` is echoed because the caller named it; nothing else about the
 * account, and nothing the provider said, is. A refusal from a provider
 * routinely quotes the refresh token it refused.
 *
 * @category errors
 * @since 0.1.0
 */
export class TokenRefreshFailed extends Schema.TaggedError<TokenRefreshFailed>("effect-auth/TokenRefreshFailed")(
  "TokenRefreshFailed",
  {
    accountId: AccountId,
    reason: TokenRefreshReason
  },
  {
    description: "The provider tokens for that account could not be refreshed",
    httpApiStatus: 400
  }
) {}

/**
 * Why an OIDC discovery document could not be turned into a provider.
 *
 * @category models
 * @since 0.1.0
 */
export const DiscoveryFailureReason = Schema.Literals([
  /** The discovery endpoint could not be read, or answered with a redirect. */
  "Unreachable",
  /** The document was not JSON, or not an object. */
  "Malformed",
  /** The document declared no `issuer`. */
  "IssuerMissing",
  /** The document's `issuer` is not the one the deployment configured. */
  "IssuerMismatch",
  /** The document declared no authorization or no token endpoint. */
  "EndpointsMissing",
  /** The document declared no `jwks_uri`, and none was configured. */
  "KeysMissing"
])

/**
 * The type of a {@link DiscoveryFailureReason}.
 *
 * @category models
 * @since 0.1.0
 */
export type DiscoveryFailureReason = typeof DiscoveryFailureReason.Type

/**
 * An OIDC discovery document could not be turned into a provider configuration.
 *
 * **Gotchas**
 *
 * This is a *start-up* failure: discovery runs when the stack is built, so a
 * deployment whose provider cannot be discovered fails to boot rather than
 * serving an endpoint that answers `UnknownProvider`. It reaches no endpoint's
 * error union, and `id` is the provider id the deployment wrote down — never
 * anything the remote document said.
 *
 * @category errors
 * @since 0.1.0
 */
export class DiscoveryError extends Schema.TaggedError<DiscoveryError>("effect-auth/DiscoveryError")(
  "DiscoveryError",
  {
    id: Schema.String,
    reason: DiscoveryFailureReason
  },
  {
    description: "An OIDC discovery document could not be turned into a provider",
    httpApiStatus: 500
  }
) {}

// -----------------------------------------------------------------------------
// Accounts
// -----------------------------------------------------------------------------

/**
 * The provider identity resolves to an e-mail address that already belongs to a
 * different local account, and the trust rules do not permit linking it
 * implicitly.
 *
 * **Details**
 *
 * Implicit linking on a matching e-mail is only allowed when the provider says
 * the address is verified AND either the provider is listed in
 * `trustedProviders` or the local account's own address is already verified.
 * Otherwise the user must sign in with the existing method and link
 * deliberately.
 *
 * @category errors
 * @since 0.1.0
 */
export class AccountAlreadyLinked extends Schema.TaggedError<AccountAlreadyLinked>("effect-auth/AccountAlreadyLinked")(
  "AccountAlreadyLinked",
  {
    providerId: Schema.String
  },
  {
    description: "An account with that e-mail address already exists and cannot be linked implicitly",
    httpApiStatus: 409
  }
) {}

/**
 * Unlinking the account would leave the user with no way to sign in.
 *
 * @category errors
 * @since 0.1.0
 */
export class CannotUnlinkLastAccount extends Schema.TaggedError<CannotUnlinkLastAccount>(
  "effect-auth/CannotUnlinkLastAccount"
)(
  "CannotUnlinkLastAccount",
  {},
  {
    description: "Refusing to remove the only remaining sign-in method",
    httpApiStatus: 409
  }
) {}

// -----------------------------------------------------------------------------
// Cross-cutting
// -----------------------------------------------------------------------------

/**
 * The caller exceeded a configured rate limit.
 *
 * **Details**
 *
 * The HTTP layer maps `RateLimiter.RateLimitExceeded` onto this error rather
 * than exposing it directly: the built-in error carries the bucket key, which
 * for these limits is a client IP address.
 *
 * @category errors
 * @since 0.1.0
 */
export class RateLimited extends Schema.TaggedError<RateLimited>("effect-auth/RateLimited")(
  "RateLimited",
  {
    retryAfterSeconds: Schema.Finite
  },
  {
    description: "Too many requests",
    httpApiStatus: 429
  }
) {}

/**
 * The `AuthEmails` implementation failed to deliver a message.
 *
 * **Gotchas**
 *
 * Endpoints that send mail (`requestPasswordReset`, `sendVerificationEmail`)
 * answer `200` regardless of the outcome, so this error is for logs and for the
 * caller of the domain services — it is not part of those endpoints' contract.
 *
 * @category errors
 * @since 0.1.0
 */
export class EmailDeliveryError extends Schema.TaggedError<EmailDeliveryError>("effect-auth/EmailDeliveryError")(
  "EmailDeliveryError",
  {
    reason: Schema.String,
    cause: Schema.optional(Schema.Defect())
  },
  {
    description: "The e-mail could not be delivered",
    httpApiStatus: 500
  }
) {}

/**
 * The password hasher could not complete an operation.
 *
 * **Details**
 *
 * A wrong password is not an error — `PasswordHasher.verify` answers `false`.
 * This is raised only when a stored hash cannot be interpreted or the
 * primitive is unavailable on this runtime, both of which are server faults and
 * must not be reported to the caller as invalid credentials.
 *
 * @category errors
 * @since 0.1.0
 */
export class PasswordHashError extends Schema.TaggedError<PasswordHashError>("effect-auth/PasswordHashError")(
  "PasswordHashError",
  {
    reason: Schema.String,
    cause: Schema.optional(Schema.Defect())
  },
  {
    description: "The password hashing primitive failed",
    httpApiStatus: 500
  }
) {}

/**
 * Every error `effect-auth` can raise.
 *
 * **Gotchas**
 *
 * Not every member reaches a caller. {@link PasswordHashError} and
 * `PersistenceError` are server faults: the HTTP layer turns them into defects,
 * so they render as an opaque `500` and appear in no endpoint's declared error
 * union. They are members here because a program that calls the domain services
 * directly — without the HTTP layer — can observe them.
 *
 * `PolicyRefused` is declared in `domain/Hooks.ts`, beside the hooks that are
 * the only thing able to raise it, and joins the union here.
 *
 * @category errors
 * @since 0.1.0
 */
export type AuthError =
  | Unauthorized
  | NotFound
  | InvalidCredentials
  | EmailNotVerified
  | UserAlreadyExists
  | UserNotFound
  | PasswordPolicyViolation
  | EmailUnchanged
  | PasswordAlreadySet
  | SessionExpired
  | SessionNotFresh
  | InvalidToken
  | TokenExpired
  | OAuthStateMismatch
  | OAuthProviderError
  | TokenRefreshFailed
  | DiscoveryError
  | AccountAlreadyLinked
  | CannotUnlinkLastAccount
  | PolicyRefused
  | RateLimited
  | EmailDeliveryError
  | PasswordHashError
  | PersistenceError
