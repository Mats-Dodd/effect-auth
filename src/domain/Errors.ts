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
 * @since 1.0.0
 */
import { Schema } from "effect"
import { HttpApiError } from "effect/unstable/httpapi"
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
 * @since 1.0.0
 */
export const Unauthorized = HttpApiError.Unauthorized

/**
 * The type of an {@link Unauthorized} error.
 *
 * @category errors
 * @since 1.0.0
 */
export type Unauthorized = HttpApiError.Unauthorized

/**
 * The addressed resource — a session to revoke, an account to unlink — does not
 * exist, or does not belong to the caller. The two cases are deliberately
 * indistinguishable.
 *
 * @category errors
 * @since 1.0.0
 */
export const NotFound = HttpApiError.NotFound

/**
 * The type of a {@link NotFound} error.
 *
 * @category errors
 * @since 1.0.0
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
 * @since 1.0.0
 */
export class InvalidCredentials
  extends Schema.TaggedError<InvalidCredentials>("effect-auth/InvalidCredentials")("InvalidCredentials", {}, {
    description: "The credentials provided did not match a known sign-in method",
    httpApiStatus: 401
  })
{}

/**
 * The account exists and the password was correct, but the address has not been
 * verified and `emailPassword.requireEmailVerification` is enabled.
 *
 * @category errors
 * @since 1.0.0
 */
export class EmailNotVerified
  extends Schema.TaggedError<EmailNotVerified>("effect-auth/EmailNotVerified")("EmailNotVerified", {}, {
    description: "The account's e-mail address has not been verified",
    httpApiStatus: 403
  })
{}

/**
 * Sign-up was attempted with an e-mail address that already has an account.
 *
 * @category errors
 * @since 1.0.0
 */
export class UserAlreadyExists
  extends Schema.TaggedError<UserAlreadyExists>("effect-auth/UserAlreadyExists")("UserAlreadyExists", {}, {
    description: "An account already exists for that e-mail address",
    httpApiStatus: 409
  })
{}

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
 * @since 1.0.0
 */
export class UserNotFound
  extends Schema.TaggedError<UserNotFound>("effect-auth/UserNotFound")("UserNotFound", {}, {
    description: "No user matched the request",
    httpApiStatus: 404
  })
{}

/**
 * The requested password does not satisfy the configured policy.
 *
 * **Details**
 *
 * `minLength` and `maxLength` echo the active policy so a client can render a
 * precise message without hard-coding the server's configuration.
 *
 * @category errors
 * @since 1.0.0
 */
export class PasswordPolicyViolation extends Schema.TaggedError<PasswordPolicyViolation>(
  "effect-auth/PasswordPolicyViolation"
)("PasswordPolicyViolation", {
  reason: Schema.Literals(["TooShort", "TooLong"]),
  minLength: Schema.Finite,
  maxLength: Schema.Finite
}, {
  description: "The password did not satisfy the configured password policy",
  httpApiStatus: 422
}) {}

// -----------------------------------------------------------------------------
// Sessions
// -----------------------------------------------------------------------------

/**
 * The presented session existed but its expiry has passed.
 *
 * @category errors
 * @since 1.0.0
 */
export class SessionExpired
  extends Schema.TaggedError<SessionExpired>("effect-auth/SessionExpired")("SessionExpired", {}, {
    description: "The session has expired",
    httpApiStatus: 401
  })
{}

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
 * @since 1.0.0
 */
export class SessionNotFresh
  extends Schema.TaggedError<SessionNotFresh>("effect-auth/SessionNotFresh")("SessionNotFresh", {
    freshAgeSeconds: Schema.Finite
  }, {
    description: "The session is not fresh enough for this operation",
    httpApiStatus: 403
  })
{}

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
 * @since 1.0.0
 */
export class InvalidToken extends Schema.TaggedError<InvalidToken>("effect-auth/InvalidToken")("InvalidToken", {}, {
  description: "The verification token is invalid or has already been used",
  httpApiStatus: 400
}) {}

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
 * @since 1.0.0
 */
export class TokenExpired extends Schema.TaggedError<TokenExpired>("effect-auth/TokenExpired")("TokenExpired", {}, {
  description: "The verification token has expired",
  httpApiStatus: 400
}) {}

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
 * @since 1.0.0
 */
export class OAuthStateMismatch
  extends Schema.TaggedError<OAuthStateMismatch>("effect-auth/OAuthStateMismatch")("OAuthStateMismatch", {}, {
    description: "The OAuth state did not match a pending authorization request",
    httpApiStatus: 400
  })
{}

/**
 * The set of safe, non-leaking reasons an OAuth exchange can fail.
 *
 * @category models
 * @since 1.0.0
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
  "ProviderUnavailable"
])

/**
 * The type of an {@link OAuthFailureReason}.
 *
 * @category models
 * @since 1.0.0
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
 * @since 1.0.0
 */
export class OAuthProviderError
  extends Schema.TaggedError<OAuthProviderError>("effect-auth/OAuthProviderError")("OAuthProviderError", {
    providerId: Schema.String,
    reason: OAuthFailureReason
  }, {
    description: "The OAuth provider exchange failed",
    httpApiStatus: 502
  })
{}

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
 * @since 1.0.0
 */
export class AccountAlreadyLinked
  extends Schema.TaggedError<AccountAlreadyLinked>("effect-auth/AccountAlreadyLinked")("AccountAlreadyLinked", {
    providerId: Schema.String
  }, {
    description: "An account with that e-mail address already exists and cannot be linked implicitly",
    httpApiStatus: 409
  })
{}

/**
 * Unlinking the account would leave the user with no way to sign in.
 *
 * @category errors
 * @since 1.0.0
 */
export class CannotUnlinkLastAccount extends Schema.TaggedError<CannotUnlinkLastAccount>(
  "effect-auth/CannotUnlinkLastAccount"
)("CannotUnlinkLastAccount", {}, {
  description: "Refusing to remove the only remaining sign-in method",
  httpApiStatus: 409
}) {}

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
 * @since 1.0.0
 */
export class RateLimited extends Schema.TaggedError<RateLimited>("effect-auth/RateLimited")("RateLimited", {
  retryAfterSeconds: Schema.Finite
}, {
  description: "Too many requests",
  httpApiStatus: 429
}) {}

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
 * @since 1.0.0
 */
export class EmailDeliveryError
  extends Schema.TaggedError<EmailDeliveryError>("effect-auth/EmailDeliveryError")("EmailDeliveryError", {
    reason: Schema.String,
    cause: Schema.optional(Schema.Defect())
  }, {
    description: "The e-mail could not be delivered",
    httpApiStatus: 500
  })
{}

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
 * @since 1.0.0
 */
export class PasswordHashError
  extends Schema.TaggedError<PasswordHashError>("effect-auth/PasswordHashError")("PasswordHashError", {
    reason: Schema.String,
    cause: Schema.optional(Schema.Defect())
  }, {
    description: "The password hashing primitive failed",
    httpApiStatus: 500
  })
{}

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
 * @category errors
 * @since 1.0.0
 */
export type AuthError =
  | Unauthorized
  | NotFound
  | InvalidCredentials
  | EmailNotVerified
  | UserAlreadyExists
  | UserNotFound
  | PasswordPolicyViolation
  | SessionExpired
  | SessionNotFresh
  | InvalidToken
  | TokenExpired
  | OAuthStateMismatch
  | OAuthProviderError
  | AccountAlreadyLinked
  | CannotUnlinkLastAccount
  | RateLimited
  | EmailDeliveryError
  | PasswordHashError
  | PersistenceError
