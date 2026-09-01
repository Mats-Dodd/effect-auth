/**
 * The HTTP contract of `effect-auth`.
 *
 * Every endpoint the library serves is declared here, once, as an
 * `HttpApiGroup`. The declaration is the single source of truth shared by the
 * server (`HttpApiBuilder.group`), the generated client, and the OpenAPI
 * document — so a change to a payload or an error union cannot get out of step
 * between them.
 *
 * This module is import-safe from a browser: it pulls in schemas and the
 * middleware *declaration*, never a store, a hasher or a node builtin.
 *
 * @since 0.1.0
 */
import { Schema } from "effect"
import { HttpApi, HttpApiEndpoint, HttpApiGroup, HttpApiSchema, OpenApi } from "effect/unstable/httpapi"
import {
  CannotUnlinkLastAccount,
  EmailNotVerified,
  EmailUnchanged,
  InvalidCredentials,
  InvalidToken,
  NotFound,
  OAuthProviderError,
  OAuthStateMismatch,
  PasswordAlreadySet,
  PasswordPolicyViolation,
  RateLimited,
  StepUpRequired,
  TokenRefreshFailed,
  UserAlreadyExists,
  UserNotFound
} from "../domain/Errors.js"
import { PolicyRefused } from "../domain/Hooks.js"
import type { UserExtras, UserExtrasEncoded, UserFields, UserModel } from "../domain/Schema.js"
import {
  AccountId,
  AccountPublic,
  baseUserModel,
  Email,
  makeSessionWithUser,
  makeSignUpResponse,
  makeUserResponse,
  SessionId,
  SessionPublic
} from "../domain/Schema.js"
import { Authenticated, AuthoritativeSession, freshSession, RequireAssurance } from "./Middleware.js"
import { OriginNotAllowed } from "./OriginCheck.js"

// -----------------------------------------------------------------------------
// Shared schemas
// -----------------------------------------------------------------------------

/**
 * A secret carried in a request body.
 *
 * **Details**
 *
 * Decoding a payload containing one yields a `Redacted<string>`, so a password
 * or a reset token is already redacted by the time a handler sees it and cannot
 * be logged by accident. Encoding — what a client does when it sends the
 * request — unwraps it again.
 *
 * @category models
 * @since 0.1.0
 */
const nonEmptyBounded = (maxLength: number) =>
  Schema.String.pipe(Schema.check(Schema.isMinLength(1), Schema.isMaxLength(maxLength)))

/** Conservative wire limits applied before values reach crypto, storage, or a mailer. */
export const Secret = Schema.Redacted(nonEmptyBounded(4096))
export const InputName = nonEmptyBounded(256)
export const InputUrl = nonEmptyBounded(2048)
export const InputToken = nonEmptyBounded(4096)
export const InputProviderId = nonEmptyBounded(128)
export const InputScope = nonEmptyBounded(256)
export const InputScopes = Schema.Array(InputScope).pipe(Schema.check(Schema.isMaxLength(64)))
const ResponseSecret = Schema.Redacted(Schema.String)

/**
 * The response of an endpoint whose only interesting outcome is "it worked".
 *
 * **Gotchas**
 *
 * `requestPasswordReset` and `sendVerificationEmail` answer this whether or not
 * the address belongs to an account. That is deliberate: a distinguishable
 * response would be a user-enumeration oracle.
 *
 * @category models
 * @since 0.1.0
 */
export const Ok = Schema.Struct({
  success: Schema.Boolean
})

/**
 * The type of an {@link Ok} response.
 *
 * @category models
 * @since 0.1.0
 */
export type Ok = typeof Ok.Type

/**
 * The response that starts an OAuth flow: where the browser must be sent.
 *
 * **Details**
 *
 * The authorization URL is returned rather than answered as a `302` so that a
 * single-page application can decide how to navigate — and so the response
 * remains a normal JSON body that `fetch` can read.
 *
 * @category models
 * @since 0.1.0
 */
export const OAuthRedirect = Schema.Struct({
  /** The provider's authorization URL, with `state` and `code_challenge`. */
  url: Schema.String,
  /** Always `true`; present so a client can branch on the shape alone. */
  redirect: Schema.Boolean
})

/**
 * The type of an {@link OAuthRedirect} response.
 *
 * @category models
 * @since 0.1.0
 */
export type OAuthRedirect = typeof OAuthRedirect.Type

/**
 * The second half of a sign-in's success: the credential was accepted and a
 * further factor is owed before a session exists.
 *
 * **Details**
 *
 * Answered on **202**, not as an error, because nothing went wrong — the caller
 * asked to sign in and is being told what remains. A deployment with no factor
 * plugin installed never produces it, so its wire is byte-identical to `0.1.0`'s.
 *
 * The pending-authentication token travels in the `__Host-effect_auth.pending`
 * cookie and nowhere else: it is a credential, and a body a script can read is
 * not where a credential belongs. A response carrying this **never** carries a
 * session cookie.
 *
 * `available` names kinds of factor — `"totp"`, `"passkey"` — and carries no
 * identifier, no address and no secret, so a 202 tells an attacker who guessed
 * a password nothing they could not already infer. There is no user id and no
 * e-mail address in it for the same reason.
 *
 * @category models
 * @since 0.2.0
 */
export const MfaRequired = Schema.Struct({
  _tag: Schema.tag("MfaRequired"),
  /** The kinds of second factor this person can answer with. */
  available: Schema.Array(Schema.String),
  /** When the pending-authentication token stops being accepted. */
  expiresAt: Schema.DateTimeUtcFromString
}).pipe(HttpApiSchema.status(202))

/**
 * The type of an {@link MfaRequired} response.
 *
 * @category models
 * @since 0.2.0
 */
export type MfaRequired = typeof MfaRequired.Type

/**
 * A `302` response carrying a `Location` header and no body.
 *
 * **Details**
 *
 * Used by the OAuth callback, which is reached by a top-level browser
 * navigation from the provider and must therefore answer with a real redirect.
 * The target is always validated against `trustedOrigins` before it is written.
 *
 * @category models
 * @since 0.1.0
 */
export const Redirect = HttpApiSchema.WithHeaders(HttpApiSchema.Empty(302), { location: Schema.String })

// -----------------------------------------------------------------------------
// Payloads
// -----------------------------------------------------------------------------

/**
 * The body of `POST /auth/sign-up/email`, before a deployment's own user fields
 * are laid alongside it.
 *
 * **Gotchas**
 *
 * There is no `emailVerified` field, and there never will be: verification is
 * derived from a consumed token or a trusted provider claim, never from what a
 * client asserts about itself.
 *
 * @category models
 * @since 0.1.0
 */
export const SignUpEmailPayload = Schema.Struct({
  name: InputName,
  email: Email,
  password: Secret,
  image: Schema.optional(InputUrl),
  /** Where a verification e-mail should send the user. Validated against `trustedOrigins`. */
  callbackURL: Schema.optional(InputUrl),
  rememberMe: Schema.optional(Schema.Boolean)
})

/**
 * The schema {@link makeSignUpEmailPayload} builds.
 *
 * @category models
 * @since 0.1.0
 */
export interface SignUpEmailPayloadSchema<F extends UserFields> extends Schema.Codec<
  typeof SignUpEmailPayload.Type & UserExtras<F, "jsonCreate">,
  typeof SignUpEmailPayload.Encoded & UserExtrasEncoded<F, "jsonCreate">
> {}

/**
 * The body of `POST /auth/sign-up/email` for a model parameterized by `F`:
 * {@link SignUpEmailPayload} with the model's own settable fields alongside it.
 *
 * **Details**
 *
 * The custom half is the model's `jsonCreate` variant, so a field declared with
 * `UserField.withDefault` is optional here and one declared `readOnly` or
 * `hidden` is absent — a client cannot state what the application owns. An
 * excess key is dropped rather than refused, which is what makes an older client
 * keep working when a deployment adds a field.
 *
 * @category constructors
 * @since 0.1.0
 */
export const makeSignUpEmailPayload = <F extends UserFields>(model: UserModel<F>): SignUpEmailPayloadSchema<F> =>
  model.withExtras(SignUpEmailPayload, "jsonCreate")

/**
 * The type of a {@link makeSignUpEmailPayload}.
 *
 * @category models
 * @since 0.1.0
 */
export type SignUpEmailOf<F extends UserFields> = SignUpEmailPayloadSchema<F>["Type"]

/**
 * The body of `POST /auth/sign-in/email`.
 *
 * @category models
 * @since 0.1.0
 */
export const SignInEmailPayload = Schema.Struct({
  email: Email,
  password: Secret,
  /** When `false` the session expires in a day rather than the configured `expiresIn`. */
  rememberMe: Schema.optional(Schema.Boolean),
  callbackURL: Schema.optional(InputUrl)
})

/**
 * The body of `POST /auth/revoke-session`.
 *
 * @category models
 * @since 0.1.0
 */
export const RevokeSessionPayload = Schema.Struct({
  sessionId: SessionId
})

/**
 * The body of `POST /auth/request-password-reset`.
 *
 * @category models
 * @since 0.1.0
 */
export const RequestPasswordResetPayload = Schema.Struct({
  email: Email,
  /** Where the reset link should land. Validated against `trustedOrigins`. */
  redirectTo: Schema.optional(InputUrl)
})

/**
 * The body of `POST /auth/reset-password`.
 *
 * @category models
 * @since 0.1.0
 */
export const ResetPasswordPayload = Schema.Struct({
  token: Secret,
  newPassword: Secret
})

/**
 * The body of `POST /auth/change-password`.
 *
 * @category models
 * @since 0.1.0
 */
export const ChangePasswordPayload = Schema.Struct({
  currentPassword: Secret,
  newPassword: Secret,
  /** Sign every other device out. Defaults to `true` in the handler. */
  revokeOtherSessions: Schema.optional(Schema.Boolean)
})

/**
 * The body of `POST /auth/reauthenticate`.
 *
 * @category models
 * @since 0.2.0
 */
export const ReauthenticatePayload = Schema.Struct({
  password: Secret
})

/**
 * The body of `POST /auth/send-verification-email`.
 *
 * @category models
 * @since 0.1.0
 */
export const SendVerificationEmailPayload = Schema.Struct({
  email: Email,
  callbackURL: Schema.optional(InputUrl)
})

/**
 * The query string of `GET /auth/verify-email`.
 *
 * @category models
 * @since 0.1.0
 */
export const VerifyEmailQuery = Schema.Struct({
  token: InputToken,
  callbackURL: Schema.optional(InputUrl)
})

/**
 * The query string of every endpoint whose only input is a token from a link.
 *
 * **Gotchas**
 *
 * It decodes to a plain `string` rather than to a {@link Secret}: query strings
 * do not go through the JSON codec, so there is no transformation to hang the
 * redaction on. Each handler wraps it with `Redacted.make` as its first act,
 * before anything can log it.
 *
 * @category models
 * @since 0.1.0
 */
export const TokenQuery = Schema.Struct({
  token: InputToken
})

/**
 * The body of `POST /auth/update-user`, before a deployment's own user fields
 * are laid alongside it.
 *
 * **Gotchas**
 *
 * `image` is `optional(NullOr(...))` and the two mean different things: an
 * absent key leaves the column alone, an explicit `null` clears it. `email` is
 * deliberately absent — moving an account to another address is the two-hop
 * change-email flow, never a profile edit.
 *
 * @category models
 * @since 0.1.0
 */
export const UpdateUserPayload = Schema.Struct({
  name: Schema.optional(InputName),
  image: Schema.optional(Schema.NullOr(InputUrl))
})

/**
 * The schema {@link makeUpdateUserPayload} builds.
 *
 * @category models
 * @since 0.1.0
 */
export interface UpdateUserPayloadSchema<F extends UserFields> extends Schema.Codec<
  typeof UpdateUserPayload.Type & UserExtras<F, "jsonUpdate">,
  typeof UpdateUserPayload.Encoded & UserExtrasEncoded<F, "jsonUpdate">
> {}

/**
 * The body of `POST /auth/update-user` for a model parameterized by `F`:
 * {@link UpdateUserPayload} with the model's own writable fields alongside it.
 *
 * **Details**
 *
 * The custom half is the model's `jsonUpdate` variant, so a field declared
 * `readOnly` or `hidden` is absent and cannot be stated by a client. An excess
 * key is dropped rather than refused.
 *
 * @category constructors
 * @since 0.1.0
 */
export const makeUpdateUserPayload = <F extends UserFields>(model: UserModel<F>): UpdateUserPayloadSchema<F> =>
  model.withExtras(UpdateUserPayload, "jsonUpdate")

/**
 * The type of a {@link makeUpdateUserPayload}.
 *
 * @category models
 * @since 0.1.0
 */
export type UpdateUserOf<F extends UserFields> = UpdateUserPayloadSchema<F>["Type"]

/**
 * The body of `POST /auth/change-email`.
 *
 * @category models
 * @since 0.1.0
 */
export const ChangeEmailPayload = Schema.Struct({
  /** The address to move the account to. */
  newEmail: Email,
  /** Where the link should land once the change completes. Validated against `trustedOrigins`. */
  callbackURL: Schema.optional(InputUrl)
})

/**
 * The body of `POST /auth/delete-user`.
 *
 * @category models
 * @since 0.1.0
 */
export const DeleteUserPayload = Schema.Struct({
  /**
   * The caller's current password, where they have one.
   *
   * **Gotchas**
   *
   * Optional because an OAuth-only account has none. Omitting it does not skip a
   * check: the deployment's `user.deleteUser.confirmByEmail` setting decides
   * whether a mailbox or a fresh session is the second factor.
   */
  password: Schema.optional(Secret),
  /** Where to send the browser once the account is gone. */
  callbackURL: Schema.optional(InputUrl)
})

/**
 * What `POST /auth/delete-user` did.
 *
 * @category models
 * @since 0.1.0
 */
export const DeleteUserResponse = Schema.Struct({
  success: Schema.Boolean,
  /**
   * `"Deleted"` when the account is already gone, `"ConfirmationSent"` when a
   * link was mailed and nothing has been deleted yet.
   */
  status: Schema.Literals(["Deleted", "ConfirmationSent"])
})

/**
 * The type of a {@link DeleteUserResponse}.
 *
 * @category models
 * @since 0.1.0
 */
export type DeleteUserResponse = typeof DeleteUserResponse.Type

/**
 * The body of `POST /auth/set-password`.
 *
 * @category models
 * @since 0.1.0
 */
export const SetPasswordPayload = Schema.Struct({
  newPassword: Secret
})

/**
 * The body of the two endpoints that name one of the caller's linked accounts.
 *
 * @category models
 * @since 0.1.0
 */
export const AccountSelection = Schema.Struct({
  accountId: AccountId
})

/**
 * A provider access token for one of the caller's linked accounts.
 *
 * **Gotchas**
 *
 * This is the one response in the library that carries a credential for
 * *another* system. `accessToken` and `idToken` decode to `Redacted`, so a
 * client that logs the response body logs `<redacted>` — but the value is on the
 * wire, so serve these endpoints over TLS and do not cache their responses.
 *
 * @category models
 * @since 0.1.0
 */
export const AccessTokenResponse = Schema.Struct({
  accessToken: ResponseSecret,
  accessTokenExpiresAt: Schema.NullOr(Schema.DateTimeUtcFromString),
  idToken: Schema.NullOr(ResponseSecret),
  /** The granted scopes, split out of the stored `scope` column. */
  scopes: Schema.Array(Schema.String),
  providerId: Schema.String,
  accountId: AccountId
})

/**
 * The type of an {@link AccessTokenResponse}.
 *
 * @category models
 * @since 0.1.0
 */
export type AccessTokenResponse = typeof AccessTokenResponse.Type

/**
 * {@link AccessTokenResponse} together with the refresh token the account now
 * holds.
 *
 * **Details**
 *
 * A provider that rotates refresh tokens returns a new one and the old one stops
 * working, so a client that stores tokens of its own has to be told. A provider
 * that does not rotate them gets the stored one back unchanged.
 *
 * @category models
 * @since 0.1.0
 */
export const RefreshTokenResponse = Schema.Struct({
  ...AccessTokenResponse.fields,
  refreshToken: ResponseSecret,
  refreshTokenExpiresAt: Schema.NullOr(Schema.DateTimeUtcFromString)
})

/**
 * The type of a {@link RefreshTokenResponse}.
 *
 * @category models
 * @since 0.1.0
 */
export type RefreshTokenResponse = typeof RefreshTokenResponse.Type

/**
 * The body of `POST /auth/sign-in/social`.
 *
 * @category models
 * @since 0.1.0
 */
export const SignInSocialPayload = Schema.Struct({
  providerId: InputProviderId,
  /** Where to land after a successful callback. Validated against `trustedOrigins`. */
  callbackURL: Schema.optional(InputUrl),
  /** Where to land when the flow fails. Validated against `trustedOrigins`. */
  errorCallbackURL: Schema.optional(InputUrl),
  /** Extra scopes to request on top of the provider's configured set. */
  scopes: Schema.optional(InputScopes),
  rememberMe: Schema.optional(Schema.Boolean)
})

/**
 * The path parameters of `GET /auth/callback/:providerId`.
 *
 * @category models
 * @since 0.1.0
 */
export const OAuthCallbackParams = Schema.Struct({
  providerId: InputProviderId
})

/**
 * The query string of `GET /auth/callback/:providerId`.
 *
 * **Gotchas**
 *
 * Every field is optional because the provider decides what comes back: a
 * success carries `code` and `state`, a refusal carries `error` and no `code`.
 * A missing `state` is an `OAuthStateMismatch`, never a crash.
 *
 * @category models
 * @since 0.1.0
 */
export const OAuthCallbackQuery = Schema.Struct({
  code: Schema.optional(InputToken),
  state: Schema.optional(InputToken),
  error: Schema.optional(nonEmptyBounded(256)),
  error_description: Schema.optional(nonEmptyBounded(1024)),
  /**
   * A provider-specific extra, forwarded to the provider's `userInfo`.
   *
   * **Gotchas**
   *
   * Apple's, which carries a JSON object with the person's name — once, on the
   * first authorization, and never again. Nothing signs it, so it is used for
   * display fields and never for an identity.
   */
  user: Schema.optional(nonEmptyBounded(4096))
})

/**
 * The body of `POST /auth/callback/:providerId` — a provider that answers with
 * `response_mode=form_post` rather than a redirect.
 *
 * **Details**
 *
 * The same fields as {@link OAuthCallbackQuery}, as
 * `application/x-www-form-urlencoded`, because that is what the provider's
 * browser-side form submits. The endpoint does nothing but redirect to the `GET`
 * twin — see the endpoint's own description for why.
 *
 * @category models
 * @since 0.1.0
 */
export const OAuthCallbackForm = Schema.Struct({
  code: Schema.optional(InputToken),
  state: Schema.optional(InputToken),
  error: Schema.optional(nonEmptyBounded(256)),
  error_description: Schema.optional(nonEmptyBounded(1024)),
  user: Schema.optional(nonEmptyBounded(4096))
}).pipe(HttpApiSchema.asFormUrlEncoded())

/**
 * The body of `POST /auth/link-social`.
 *
 * @category models
 * @since 0.1.0
 */
export const LinkSocialPayload = Schema.Struct({
  providerId: InputProviderId,
  callbackURL: Schema.optional(InputUrl),
  errorCallbackURL: Schema.optional(InputUrl),
  scopes: Schema.optional(InputScopes)
})

/**
 * The body of `POST /auth/unlink-account`.
 *
 * @category models
 * @since 0.1.0
 */
export const UnlinkAccountPayload = Schema.Struct({
  accountId: AccountId
})

// -----------------------------------------------------------------------------
// Group
// -----------------------------------------------------------------------------

/**
 * Every endpoint `effect-auth` serves, under the `/auth` prefix, for a model
 * parameterized by `F`.
 *
 * **Details**
 *
 * The group is deliberately mixed: `.middleware(Authenticated)` is applied per
 * endpoint rather than to the group, because sign-in, sign-up, the callback and
 * the two "always answer 200" mail endpoints must remain reachable without a
 * session. Endpoints that do carry the middleware inherit its `Unauthorized`
 * error automatically — it is not repeated in their `error` list.
 *
 * Three endpoints carry the model: sign-up takes it in its payload and answers
 * with it, sign-in and `GET /session` answer with it. Everything else is the
 * same group whatever a deployment declared.
 *
 * **Gotchas**
 *
 * The return type is inferred rather than annotated — a group's type *is* the
 * union of its twenty-nine endpoint types, and writing that down would be a second
 * copy of this declaration to keep in step. {@link AuthApiGroupOf} names it, and
 * is the one `ReturnType` in the library.
 *
 * @category constructors
 * @since 0.1.0
 */
export const makeAuthApiGroup = <F extends UserFields>(model: UserModel<F>) =>
  HttpApiGroup.make("auth")
    .add(
      HttpApiEndpoint.post("signUpEmail", "/sign-up/email", {
        payload: makeSignUpEmailPayload(model),
        success: makeSignUpResponse(model),
        error: [UserAlreadyExists, PasswordPolicyViolation, PolicyRefused, RateLimited, OriginNotAllowed]
      }).annotateMerge(
        OpenApi.annotations({
          summary: "Create an account with an e-mail address and password",
          description:
            "Sets the session cookie and answers a session, unless the configuration withholds one (email verification required, or autoSignIn off), in which case session is null. Sends a verification mail when one is configured. PolicyRefused is a deployment's own hook declining the registration, and nothing was written when it is returned; a hook that instead declines only the session answers 200 with session null, because the account does exist."
        })
      ),
      HttpApiEndpoint.post("signInEmail", "/sign-in/email", {
        payload: SignInEmailPayload,
        success: [makeSessionWithUser(model), MfaRequired],
        error: [InvalidCredentials, EmailNotVerified, PolicyRefused, RateLimited, OriginNotAllowed]
      }).annotateMerge(
        OpenApi.annotations({
          summary: "Sign in with an e-mail address and password",
          description:
            "An Origin or Referer that is present and untrusted is refused with OriginNotAllowed: this is an unauthenticated POST that mints a session, so without it a cross-site form post signs a visitor's browser into an account the attacker controls. A request claiming neither header — a server, a script — passes. Answers InvalidCredentials identically for an unknown address and a wrong password, and takes the same time to do it. PolicyRefused is a deployment's own hook declining the session — a suspension, say — and is raised only after the password has been verified, so it is never an answer somebody guessing an address can obtain. Success is a two-status union: 200 with the session and its user, or 202 with MfaRequired when a factor plugin owes a second factor, in which case the pending-authentication token is set in the __Host-effect_auth.pending cookie and no session cookie is written."
        })
      ),
      HttpApiEndpoint.post("reauthenticate", "/reauthenticate", {
        payload: ReauthenticatePayload,
        success: makeSessionWithUser(model),
        error: [InvalidCredentials, RateLimited]
      })
        .middleware(Authenticated)
        // The password is checked against the stored hash and the session row
        // is rewritten: neither may be decided from a snapshot.
        .annotate(AuthoritativeSession, true)
        .annotateMerge(
          OpenApi.annotations({
            summary: "Prove the password again, raising the session's assurance",
            description:
              "The one step-up method this library ships; a factor plugin adds its own. It appends a password entry to the session's methods, recomputes its level, re-stamps authenticatedAt and rotates the opaque token — the session id is kept, so open tabs and the session list survive, while a token captured before the step-up does not inherit it. The cookie is re-set with the new token. Runs the same one-verification-per-call discipline as sign-in, so a wrong password costs exactly what a right one does. It carries no RequireAssurance annotation of its own: this is the endpoint that satisfies them."
          })
        ),
      HttpApiEndpoint.post("signOut", "/sign-out", {
        success: Ok
      })
        .middleware(Authenticated)
        .annotateMerge(
          OpenApi.annotations({
            summary: "Revoke the current session and clear the cookie"
          })
        ),
      HttpApiEndpoint.get("getSession", "/session", {
        success: makeSessionWithUser(model)
      })
        .middleware(Authenticated)
        .annotateMerge(
          OpenApi.annotations({
            summary: "Read the current session and its user",
            description: "Performs the rolling refresh, and re-sets the cookie when the expiry moved."
          })
        ),
      HttpApiEndpoint.get("listSessions", "/sessions", {
        success: Schema.Array(SessionPublic)
      })
        .middleware(Authenticated)
        .annotateMerge(
          OpenApi.annotations({
            summary: "List the caller's unexpired sessions"
          })
        ),
      HttpApiEndpoint.post("revokeSession", "/revoke-session", {
        payload: RevokeSessionPayload,
        success: Ok,
        error: NotFound
      })
        .middleware(Authenticated)
        // A revocation is a mutation, and a session revoked in another browser
        // must not still be able to drive it through the cache's snapshot: this
        // reads the row anyway, so the annotation costs it nothing.
        .annotate(AuthoritativeSession, true)
        .annotateMerge(
          OpenApi.annotations({
            summary: "Revoke one of the caller's sessions",
            description: "A session belonging to another user is reported as NotFound."
          })
        ),
      HttpApiEndpoint.post("revokeSessions", "/revoke-sessions", {
        success: Ok
      })
        .middleware(Authenticated)
        .annotateMerge(
          OpenApi.annotations({
            summary: "Revoke every session of the caller, including this one"
          })
        ),
      HttpApiEndpoint.post("revokeOtherSessions", "/revoke-other-sessions", {
        success: Ok
      })
        .middleware(Authenticated)
        // Revoking the caller's other sessions is a mutation keyed on the
        // current session's id, which must be the row's and not a snapshot's.
        .annotate(AuthoritativeSession, true)
        .annotateMerge(
          OpenApi.annotations({
            summary: "Revoke every session of the caller except this one"
          })
        ),
      HttpApiEndpoint.post("requestPasswordReset", "/request-password-reset", {
        payload: RequestPasswordResetPayload,
        success: Ok,
        error: [RateLimited, OriginNotAllowed]
      }).annotateMerge(
        OpenApi.annotations({
          summary: "Send a password reset link",
          description:
            "Always succeeds for a well-formed address, whether or not it has an account. An Origin or Referer that is present and untrusted is refused with OriginNotAllowed."
        })
      ),
      HttpApiEndpoint.post("resetPassword", "/reset-password", {
        payload: ResetPasswordPayload,
        success: Ok,
        error: [InvalidToken, PasswordPolicyViolation]
      }).annotateMerge(
        OpenApi.annotations({
          summary: "Set a new password using a reset token",
          description:
            "The token is single-use, and every existing session is revoked on success. An expired token is reported as InvalidToken: consumption is a single conditional delete, so a used, an unknown and an expired token are indistinguishable by design."
        })
      ),
      HttpApiEndpoint.post("changePassword", "/change-password", {
        payload: ChangePasswordPayload,
        success: Ok,
        error: [InvalidCredentials, PasswordPolicyViolation]
      })
        .middleware(Authenticated)
        // The password it checks has to be the one in the database, not one a
        // snapshot remembered: see `AuthoritativeSession`.
        .annotate(AuthoritativeSession, true)
        // A stolen but stale cookie must not be enough to take the account over
        // permanently: the caller has to have authenticated recently as well as
        // knowing the current password.
        .annotate(RequireAssurance, freshSession)
        .annotateMerge(
          OpenApi.annotations({
            summary: "Change the caller's password",
            description:
              "Requires the current password, and a session that authenticated within the deployment's session.freshAge — POST /auth/reauthenticate, or a factor plugin's own step-up, is how a stale one is raised. StepUpRequired names the policy that was not met and what the session actually holds."
          })
        ),
      HttpApiEndpoint.post("sendVerificationEmail", "/send-verification-email", {
        payload: SendVerificationEmailPayload,
        success: Ok,
        error: [RateLimited, OriginNotAllowed]
      }).annotateMerge(
        OpenApi.annotations({
          summary: "Send an e-mail verification link",
          description:
            "Always succeeds for a well-formed address, whether or not it has an account. An Origin or Referer that is present and untrusted is refused with OriginNotAllowed."
        })
      ),
      HttpApiEndpoint.get("verifyEmail", "/verify-email", {
        query: VerifyEmailQuery,
        success: Ok,
        error: InvalidToken
      }).annotateMerge(
        OpenApi.annotations({
          summary: "Consume an e-mail verification token",
          description: "An expired token is reported as InvalidToken, for the reason given on reset-password."
        })
      ),
      HttpApiEndpoint.post("signInSocial", "/sign-in/social", {
        payload: SignInSocialPayload,
        success: OAuthRedirect,
        error: [OAuthProviderError, PolicyRefused, RateLimited]
      }).annotateMerge(
        OpenApi.annotations({
          summary: "Begin an OAuth sign-in",
          description:
            "Mints single-use state and a PKCE S256 challenge, then returns the authorization URL. Unauthenticated and it writes a row per call, so it is rate limited on the same policy as the credential endpoints. PolicyRefused belongs to the flow this starts rather than to this call: a deployment hook that declines the account it provisions or the session it mints is reported by the callback, which redirects with ?error=policy_refused&code=... because a browser that arrived by a top-level navigation has to leave by one."
        })
      ),
      HttpApiEndpoint.get("oauthCallback", "/callback/:providerId", {
        params: OAuthCallbackParams,
        query: OAuthCallbackQuery,
        success: Redirect,
        error: [OAuthStateMismatch, OAuthProviderError]
      }).annotateMerge(
        OpenApi.annotations({
          summary: "Complete an OAuth flow",
          description:
            "Consumes the state atomically, exchanges the code, links or creates the account, sets the cookie and redirects to the validated callbackURL."
        })
      ),
      HttpApiEndpoint.get("listAccounts", "/accounts", {
        success: Schema.Array(AccountPublic)
      })
        .middleware(Authenticated)
        .annotateMerge(
          OpenApi.annotations({
            summary: "List the caller's sign-in methods"
          })
        ),
      HttpApiEndpoint.post("linkSocial", "/link-social", {
        payload: LinkSocialPayload,
        success: OAuthRedirect,
        error: [OAuthProviderError, PolicyRefused]
      })
        .middleware(Authenticated)
        .annotateMerge(
          OpenApi.annotations({
            summary: "Begin linking an OAuth provider to the signed-in account",
            description:
              "PolicyRefused belongs to the flow this starts rather than to this call: a deployment hook that declines the link is reported by the callback, which redirects with ?error=policy_refused&code=... because a browser that arrived by a top-level navigation has to leave by one."
          })
        ),
      HttpApiEndpoint.post("unlinkAccount", "/unlink-account", {
        payload: UnlinkAccountPayload,
        success: Ok,
        error: [CannotUnlinkLastAccount, NotFound]
      })
        .middleware(Authenticated)
        // Unlinking counts the sign-in methods a user has *now*.
        .annotate(AuthoritativeSession, true)
        // Removing a way in is as permanent as changing one.
        .annotate(RequireAssurance, freshSession)
        .annotateMerge(
          OpenApi.annotations({
            summary: "Remove one of the caller's sign-in methods",
            description:
              "Refuses to remove the last one, and requires a session that authenticated within session.freshAge."
          })
        ),
      HttpApiEndpoint.post("updateUser", "/update-user", {
        payload: makeUpdateUserPayload(model),
        success: makeUserResponse(model),
        error: UserNotFound
      })
        .middleware(Authenticated)
        .annotateMerge(
          OpenApi.annotations({
            summary: "Edit the caller's own profile",
            description:
              "Patches the fields the body names — the base name and image, plus whichever of the deployment's own user fields a client may write. An absent key leaves the column alone; an explicit null image clears it. The address is not editable here: moving an account to another one is the change-email flow."
          })
        ),
      HttpApiEndpoint.post("changeEmail", "/change-email", {
        payload: ChangeEmailPayload,
        success: Ok,
        error: [EmailUnchanged, PolicyRefused, RateLimited]
      })
        .middleware(Authenticated)
        // The current address decides which hop is sent, and whether it is
        // verified is a fact about the row, not about a snapshot.
        .annotate(AuthoritativeSession, true)
        // The address is the account's recovery path, so a stale cookie must
        // not be enough to start moving it.
        .annotate(RequireAssurance, freshSession)
        .annotateMerge(
          OpenApi.annotations({
            summary: "Start moving the account to another e-mail address",
            description:
              "Answers 200 whether or not the address is free: telling a caller that an address is taken would make this an oracle for who is registered. Requires a session that authenticated within session.freshAge. A verified current address gets a confirmation link first; an unverified one goes straight to verifying the new address. Nothing has changed when this returns. PolicyRefused is a deployment's own hook declining the change, and carries the code that hook chose."
          })
        ),
      HttpApiEndpoint.get("confirmEmailChange", "/change-email/confirm", {
        query: TokenQuery,
        success: Ok,
        error: InvalidToken
      }).annotateMerge(
        OpenApi.annotations({
          summary: "Confirm an e-mail change from the current address",
          description:
            "Consumes the first-hop token and sends the second hop to the new address. Nothing about the account has changed yet."
        })
      ),
      HttpApiEndpoint.get("verifyEmailChange", "/change-email/verify", {
        query: TokenQuery,
        success: Ok,
        error: [InvalidToken, UserAlreadyExists]
      }).annotateMerge(
        OpenApi.annotations({
          summary: "Complete an e-mail change from the new address",
          description:
            "Consumes the second-hop token and moves the account, which ends up verified — the link was delivered to the address it names. UserAlreadyExists means somebody claimed that address between the two hops."
        })
      ),
      HttpApiEndpoint.post("deleteUser", "/delete-user", {
        payload: DeleteUserPayload,
        success: DeleteUserResponse,
        // `StepUpRequired` is restated here, though `Authenticated` declares
        // it for every endpoint it wraps: `Users.requestDeletion` raises it
        // itself, and an endpoint's own union should name what its handler can
        // do. The other four assurance-annotated endpoints do not, because the
        // refusal there is the middleware's alone.
        error: [InvalidCredentials, PolicyRefused, StepUpRequired, RateLimited]
      })
        .middleware(Authenticated)
        // A password is verified against the stored hash, and the row is about
        // to be destroyed: neither may be decided from a snapshot.
        .annotate(AuthoritativeSession, true)
        .annotate(RequireAssurance, freshSession)
        .annotateMerge(
          OpenApi.annotations({
            summary: "Delete the caller's own account",
            description:
              "With user.deleteUser.confirmByEmail off this needs a session that authenticated within session.freshAge and answers Deleted, having removed the row, its sessions and its sign-in methods. With it on it mails a confirmation link and answers ConfirmationSent, and nothing is removed until that link is followed. PolicyRefused is a deployment's own hook declining the deletion, and is raised only once the caller has proved who they are."
          })
        ),
      HttpApiEndpoint.get("deleteUserCallback", "/delete-user/callback", {
        query: TokenQuery,
        success: Redirect,
        error: InvalidToken
      })
        .middleware(Authenticated)
        .annotate(AuthoritativeSession, true)
        .annotateMerge(
          OpenApi.annotations({
            summary: "Complete an account deletion from the mailed link",
            description:
              "The link has to be followed by the account's own signed-in browser: the token is claimed first and only then checked against the caller, so a link presented by anybody else is burnt as well as refused. A deployment hook that refuses the deletion is not an error here but a redirect carrying ?error=policy_refused&code=..., because the browser arrived by a top-level navigation and has to leave by one — and the link is spent either way."
          })
        ),
      HttpApiEndpoint.post("setPassword", "/set-password", {
        payload: SetPasswordPayload,
        success: Ok,
        error: [PasswordAlreadySet, PasswordPolicyViolation, RateLimited]
      })
        .middleware(Authenticated)
        // Whether a credential already exists is exactly what this endpoint
        // branches on.
        .annotate(AuthoritativeSession, true)
        // Adding a credential is adding a way in, so the same rule as changing
        // one.
        .annotate(RequireAssurance, freshSession)
        .annotateMerge(
          OpenApi.annotations({
            summary: "Give an account without one its first password",
            description:
              "For an account provisioned through a provider. It can never replace an existing password — that is change-password, or the reset flow — and requires a session that authenticated within session.freshAge. Nothing is revoked: no credential was invalidated."
          })
        ),
      HttpApiEndpoint.post("getAccessToken", "/get-access-token", {
        payload: AccountSelection,
        success: AccessTokenResponse,
        error: [NotFound, TokenRefreshFailed]
      })
        .middleware(Authenticated)
        // What comes back is a third party's credential, and the refresh this
        // may run rotates the one on the row. A session revoked elsewhere must
        // not still be able to spend either through a snapshot of itself.
        .annotate(AuthoritativeSession, true)
        .annotateMerge(
          OpenApi.annotations({
            summary: "A usable provider access token for one of the caller's accounts",
            description:
              "Refreshes first only if the stored token is about to expire. An account that is not the caller's is reported as NotFound, exactly as one that does not exist."
          })
        ),
      HttpApiEndpoint.post("refreshToken", "/refresh-token", {
        payload: AccountSelection,
        success: RefreshTokenResponse,
        error: [NotFound, TokenRefreshFailed]
      })
        .middleware(Authenticated)
        // It rewrites the stored provider credentials and hands back a refresh
        // token whose life is measured in months: the cache's revocation lag
        // has no business anywhere near it. Both handlers read the account row
        // anyway, so the annotation costs this endpoint nothing.
        .annotate(AuthoritativeSession, true)
        .annotateMerge(
          OpenApi.annotations({
            summary: "Spend one of the caller's refresh tokens",
            description:
              "Unconditional, unlike get-access-token. For a client that has learnt the stored access token is no good. The granted scope is never overwritten by a refresh."
          })
        ),
      HttpApiEndpoint.post("oauthCallbackForm", "/callback/:providerId", {
        params: OAuthCallbackParams,
        payload: OAuthCallbackForm,
        success: Redirect
      }).annotateMerge(
        OpenApi.annotations({
          summary: "Receive a form_post OAuth callback",
          description:
            "Providers configured with response_mode=form_post (Apple) return the code by posting a form to this path. A cross-site POST carries no SameSite=Lax cookie, so this endpoint does not complete the flow: it answers a 302 to the GET twin with the same parameters as a query string, and that top-level navigation does carry the cookies."
        })
      )
    )
    .prefix("/auth")
    .annotateMerge(
      OpenApi.annotations({
        title: "Auth",
        description: "Sessions, e-mail/password sign-in, and OAuth account linking."
      })
    )

/**
 * The type {@link makeAuthApiGroup} builds, for a model parameterized by `F`.
 *
 * **Gotchas**
 *
 * The one `ReturnType` in the library, and a deliberate exception to the
 * convention against them: a group's type is the union of every endpoint it
 * declares, so the alternative is a second, hand-written copy of
 * {@link makeAuthApiGroup} that no compiler keeps in step with the first.
 * `AuthApiGroupOf<{}>` is what {@link AuthApiGroup} extends.
 *
 * @category models
 * @since 0.1.0
 */
export type AuthApiGroupOf<F extends UserFields = {}> = ReturnType<typeof makeAuthApiGroup<F>>

/**
 * Every endpoint `effect-auth` serves for a deployment that added no user
 * fields of its own — and the group `AuthApi`, `AuthHandlers.layer(api)` and
 * `AuthClient.make()` are all declared against.
 *
 * **Details**
 *
 * A class rather than the value {@link makeAuthApiGroup} returns, for two
 * reasons: it is the shape every existing consumer's `groups.auth` constraint
 * names, and it keeps the inferred group type behind a single named declaration
 * in the emitted types instead of inlining it at each use.
 *
 * @category models
 * @since 0.1.0
 */
export class AuthApiGroup extends makeAuthApiGroup(baseUserModel) {}

/**
 * The `effect-auth` endpoints as a standalone `HttpApi`, ready to be merged
 * into an application's own API.
 *
 * **Example**
 *
 * ```ts
 * import { HttpApi } from "effect/unstable/httpapi"
 * import { AuthApi } from "effect-auth"
 *
 * const MyApi = HttpApi.make("app").addHttpApi(AuthApi)
 * ```
 *
 * **Gotchas**
 *
 * The `/auth` prefix is baked into the group, and it cannot be changed with
 * `HttpApi.prefix`: that rewrites the endpoint paths *in the type*, so the
 * result no longer satisfies the `groups.auth` constraint that
 * `AuthHandlers.layer` and `AuthClient.make` use to prove they are building
 * against this group. Serving the endpoints somewhere else is a deployment
 * concern — mount the whole server under a path, or put a path-rewriting proxy
 * in front of it — and `AuthConfig.basePath` is how you tell the library where
 * that is, so the callback URI and the links in outgoing e-mails point at the
 * same place the endpoints are reachable from.
 *
 * @category models
 * @since 0.1.0
 */
export const AuthApi = HttpApi.make("effect-auth").add(AuthApiGroup)

/**
 * {@link AuthApi} for a model parameterized by `F`: the same endpoints, with the
 * deployment's own user fields in the three that carry a user.
 *
 * **Example**
 *
 * ```ts
 * import { HttpApi } from "effect/unstable/httpapi"
 * import { makeAuthApi, makeUserModel } from "effect-auth"
 *
 * const model = makeUserModel({})
 * const MyApi = HttpApi.make("app").addHttpApi(makeAuthApi(model))
 * ```
 *
 * **Gotchas**
 *
 * Hand the *same* model to `Auth.layer({ user: { model } })`,
 * `AuthHandlers.layer(api, model)` and `AuthClient.make({ api, model })`. Two
 * models with the same fields are two different types, and the compiler says so
 * at the first of those three call sites that disagrees.
 *
 * @category constructors
 * @since 0.1.0
 */
export const makeAuthApi = <F extends UserFields>(
  model: UserModel<F>
): HttpApi.HttpApi<"effect-auth", AuthApiGroupOf<F>> => HttpApi.make("effect-auth").add(makeAuthApiGroup(model))
