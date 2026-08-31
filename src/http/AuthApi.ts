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
 * @since 1.0.0
 */
import { Schema } from "effect"
import { HttpApi, HttpApiEndpoint, HttpApiGroup, HttpApiSchema, OpenApi } from "effect/unstable/httpapi"
import {
  CannotUnlinkLastAccount,
  EmailNotVerified,
  InvalidCredentials,
  InvalidToken,
  NotFound,
  OAuthProviderError,
  OAuthStateMismatch,
  PasswordPolicyViolation,
  RateLimited,
  SessionNotFresh,
  UserAlreadyExists
} from "../domain/Errors.js"
import type { UserExtras, UserExtrasEncoded, UserFields, UserModel } from "../domain/Schema.js"
import {
  AccountId,
  AccountPublic,
  baseUserModel,
  makeSessionWithUser,
  makeSignUpResponse,
  SessionId,
  SessionPublic
} from "../domain/Schema.js"
import { Authenticated } from "./Middleware.js"

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
 * @since 1.0.0
 */
export const Secret = Schema.Redacted(Schema.String)

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
 * @since 1.0.0
 */
export const Ok = Schema.Struct({
  success: Schema.Boolean
})

/**
 * The type of an {@link Ok} response.
 *
 * @category models
 * @since 1.0.0
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
 * @since 1.0.0
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
 * @since 1.0.0
 */
export type OAuthRedirect = typeof OAuthRedirect.Type

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
 * @since 1.0.0
 */
export const Redirect = HttpApiSchema.WithHeaders(
  HttpApiSchema.Empty(302),
  { location: Schema.String }
)

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
 * @since 1.0.0
 */
export const SignUpEmailPayload = Schema.Struct({
  name: Schema.String,
  email: Schema.String,
  password: Secret,
  image: Schema.optional(Schema.String),
  /** Where a verification e-mail should send the user. Validated against `trustedOrigins`. */
  callbackURL: Schema.optional(Schema.String),
  rememberMe: Schema.optional(Schema.Boolean)
})

/**
 * The schema {@link makeSignUpEmailPayload} builds.
 *
 * @category models
 * @since 1.0.0
 */
export interface SignUpEmailPayloadSchema<F extends UserFields> extends
  Schema.Codec<
    typeof SignUpEmailPayload.Type & UserExtras<F, "jsonCreate">,
    typeof SignUpEmailPayload.Encoded & UserExtrasEncoded<F, "jsonCreate">
  >
{}

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
 * @since 1.0.0
 */
export const makeSignUpEmailPayload = <F extends UserFields>(
  model: UserModel<F>
): SignUpEmailPayloadSchema<F> => model.withExtras(SignUpEmailPayload, "jsonCreate")

/**
 * The type of a {@link makeSignUpEmailPayload}.
 *
 * @category models
 * @since 1.0.0
 */
export type SignUpEmailOf<F extends UserFields> = SignUpEmailPayloadSchema<F>["Type"]

/**
 * The body of `POST /auth/sign-in/email`.
 *
 * @category models
 * @since 1.0.0
 */
export const SignInEmailPayload = Schema.Struct({
  email: Schema.String,
  password: Secret,
  /** When `false` the session expires in a day rather than the configured `expiresIn`. */
  rememberMe: Schema.optional(Schema.Boolean),
  callbackURL: Schema.optional(Schema.String)
})

/**
 * The body of `POST /auth/revoke-session`.
 *
 * @category models
 * @since 1.0.0
 */
export const RevokeSessionPayload = Schema.Struct({
  sessionId: SessionId
})

/**
 * The body of `POST /auth/request-password-reset`.
 *
 * @category models
 * @since 1.0.0
 */
export const RequestPasswordResetPayload = Schema.Struct({
  email: Schema.String,
  /** Where the reset link should land. Validated against `trustedOrigins`. */
  redirectTo: Schema.optional(Schema.String)
})

/**
 * The body of `POST /auth/reset-password`.
 *
 * @category models
 * @since 1.0.0
 */
export const ResetPasswordPayload = Schema.Struct({
  token: Secret,
  newPassword: Secret
})

/**
 * The body of `POST /auth/change-password`.
 *
 * @category models
 * @since 1.0.0
 */
export const ChangePasswordPayload = Schema.Struct({
  currentPassword: Secret,
  newPassword: Secret,
  /** Sign every other device out. Defaults to `true` in the handler. */
  revokeOtherSessions: Schema.optional(Schema.Boolean)
})

/**
 * The body of `POST /auth/send-verification-email`.
 *
 * @category models
 * @since 1.0.0
 */
export const SendVerificationEmailPayload = Schema.Struct({
  email: Schema.String,
  callbackURL: Schema.optional(Schema.String)
})

/**
 * The query string of `GET /auth/verify-email`.
 *
 * @category models
 * @since 1.0.0
 */
export const VerifyEmailQuery = Schema.Struct({
  token: Schema.String,
  callbackURL: Schema.optional(Schema.String)
})

/**
 * The body of `POST /auth/sign-in/social`.
 *
 * @category models
 * @since 1.0.0
 */
export const SignInSocialPayload = Schema.Struct({
  providerId: Schema.String,
  /** Where to land after a successful callback. Validated against `trustedOrigins`. */
  callbackURL: Schema.optional(Schema.String),
  /** Where to land when the flow fails. Validated against `trustedOrigins`. */
  errorCallbackURL: Schema.optional(Schema.String),
  /** Extra scopes to request on top of the provider's configured set. */
  scopes: Schema.optional(Schema.Array(Schema.String)),
  rememberMe: Schema.optional(Schema.Boolean)
})

/**
 * The path parameters of `GET /auth/callback/:providerId`.
 *
 * @category models
 * @since 1.0.0
 */
export const OAuthCallbackParams = Schema.Struct({
  providerId: Schema.String
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
 * @since 1.0.0
 */
export const OAuthCallbackQuery = Schema.Struct({
  code: Schema.optional(Schema.String),
  state: Schema.optional(Schema.String),
  error: Schema.optional(Schema.String),
  error_description: Schema.optional(Schema.String)
})

/**
 * The body of `POST /auth/link-social`.
 *
 * @category models
 * @since 1.0.0
 */
export const LinkSocialPayload = Schema.Struct({
  providerId: Schema.String,
  callbackURL: Schema.optional(Schema.String),
  errorCallbackURL: Schema.optional(Schema.String),
  scopes: Schema.optional(Schema.Array(Schema.String))
})

/**
 * The body of `POST /auth/unlink-account`.
 *
 * @category models
 * @since 1.0.0
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
 * union of its nineteen endpoint types, and writing that down would be a second
 * copy of this declaration to keep in step. {@link AuthApiGroupOf} names it, and
 * is the one `ReturnType` in the library.
 *
 * @category constructors
 * @since 1.0.0
 */
export const makeAuthApiGroup = <F extends UserFields>(model: UserModel<F>) =>
  HttpApiGroup.make("auth")
    .add(
      HttpApiEndpoint.post("signUpEmail", "/sign-up/email", {
        payload: makeSignUpEmailPayload(model),
        success: makeSignUpResponse(model),
        error: [UserAlreadyExists, PasswordPolicyViolation, RateLimited]
      }).annotateMerge(OpenApi.annotations({
        summary: "Create an account with an e-mail address and password",
        description:
          "Sets the session cookie and answers a session, unless the configuration withholds one (email verification required, or autoSignIn off), in which case session is null. Sends a verification mail when one is configured."
      })),
      HttpApiEndpoint.post("signInEmail", "/sign-in/email", {
        payload: SignInEmailPayload,
        success: makeSessionWithUser(model),
        error: [InvalidCredentials, EmailNotVerified, RateLimited]
      }).annotateMerge(OpenApi.annotations({
        summary: "Sign in with an e-mail address and password",
        description:
          "Answers InvalidCredentials identically for an unknown address and a wrong password, and takes the same time to do it."
      })),
      HttpApiEndpoint.post("signOut", "/sign-out", {
        success: Ok
      })
        .middleware(Authenticated)
        .annotateMerge(OpenApi.annotations({
          summary: "Revoke the current session and clear the cookie"
        })),
      HttpApiEndpoint.get("getSession", "/session", {
        success: makeSessionWithUser(model)
      })
        .middleware(Authenticated)
        .annotateMerge(OpenApi.annotations({
          summary: "Read the current session and its user",
          description: "Performs the rolling refresh, and re-sets the cookie when the expiry moved."
        })),
      HttpApiEndpoint.get("listSessions", "/sessions", {
        success: Schema.Array(SessionPublic)
      })
        .middleware(Authenticated)
        .annotateMerge(OpenApi.annotations({
          summary: "List the caller's unexpired sessions"
        })),
      HttpApiEndpoint.post("revokeSession", "/revoke-session", {
        payload: RevokeSessionPayload,
        success: Ok,
        error: NotFound
      })
        .middleware(Authenticated)
        .annotateMerge(OpenApi.annotations({
          summary: "Revoke one of the caller's sessions",
          description: "A session belonging to another user is reported as NotFound."
        })),
      HttpApiEndpoint.post("revokeSessions", "/revoke-sessions", {
        success: Ok
      })
        .middleware(Authenticated)
        .annotateMerge(OpenApi.annotations({
          summary: "Revoke every session of the caller, including this one"
        })),
      HttpApiEndpoint.post("revokeOtherSessions", "/revoke-other-sessions", {
        success: Ok
      })
        .middleware(Authenticated)
        .annotateMerge(OpenApi.annotations({
          summary: "Revoke every session of the caller except this one"
        })),
      HttpApiEndpoint.post("requestPasswordReset", "/request-password-reset", {
        payload: RequestPasswordResetPayload,
        success: Ok,
        error: RateLimited
      }).annotateMerge(OpenApi.annotations({
        summary: "Send a password reset link",
        description: "Always succeeds for a well-formed address, whether or not it has an account."
      })),
      HttpApiEndpoint.post("resetPassword", "/reset-password", {
        payload: ResetPasswordPayload,
        success: Ok,
        error: [InvalidToken, PasswordPolicyViolation]
      }).annotateMerge(OpenApi.annotations({
        summary: "Set a new password using a reset token",
        description:
          "The token is single-use, and every existing session is revoked on success. An expired token is reported as InvalidToken: consumption is a single conditional delete, so a used, an unknown and an expired token are indistinguishable by design."
      })),
      HttpApiEndpoint.post("changePassword", "/change-password", {
        payload: ChangePasswordPayload,
        success: Ok,
        error: [InvalidCredentials, SessionNotFresh, PasswordPolicyViolation]
      })
        .middleware(Authenticated)
        .annotateMerge(OpenApi.annotations({
          summary: "Change the caller's password",
          description: "Requires the current password and a session no older than the configured freshAge."
        })),
      HttpApiEndpoint.post("sendVerificationEmail", "/send-verification-email", {
        payload: SendVerificationEmailPayload,
        success: Ok,
        error: RateLimited
      }).annotateMerge(OpenApi.annotations({
        summary: "Send an e-mail verification link",
        description: "Always succeeds for a well-formed address, whether or not it has an account."
      })),
      HttpApiEndpoint.get("verifyEmail", "/verify-email", {
        query: VerifyEmailQuery,
        success: Ok,
        error: InvalidToken
      }).annotateMerge(OpenApi.annotations({
        summary: "Consume an e-mail verification token",
        description: "An expired token is reported as InvalidToken, for the reason given on reset-password."
      })),
      HttpApiEndpoint.post("signInSocial", "/sign-in/social", {
        payload: SignInSocialPayload,
        success: OAuthRedirect,
        error: [OAuthProviderError, RateLimited]
      }).annotateMerge(OpenApi.annotations({
        summary: "Begin an OAuth sign-in",
        description:
          "Mints single-use state and a PKCE S256 challenge, then returns the authorization URL. Unauthenticated and it writes a row per call, so it is rate limited on the same policy as the credential endpoints."
      })),
      HttpApiEndpoint.get("oauthCallback", "/callback/:providerId", {
        params: OAuthCallbackParams,
        query: OAuthCallbackQuery,
        success: Redirect,
        error: [OAuthStateMismatch, OAuthProviderError]
      }).annotateMerge(OpenApi.annotations({
        summary: "Complete an OAuth flow",
        description:
          "Consumes the state atomically, exchanges the code, links or creates the account, sets the cookie and redirects to the validated callbackURL."
      })),
      HttpApiEndpoint.get("listAccounts", "/accounts", {
        success: Schema.Array(AccountPublic)
      })
        .middleware(Authenticated)
        .annotateMerge(OpenApi.annotations({
          summary: "List the caller's sign-in methods"
        })),
      HttpApiEndpoint.post("linkSocial", "/link-social", {
        payload: LinkSocialPayload,
        success: OAuthRedirect,
        error: OAuthProviderError
      })
        .middleware(Authenticated)
        .annotateMerge(OpenApi.annotations({
          summary: "Begin linking an OAuth provider to the signed-in account"
        })),
      HttpApiEndpoint.post("unlinkAccount", "/unlink-account", {
        payload: UnlinkAccountPayload,
        success: Ok,
        error: [CannotUnlinkLastAccount, NotFound, SessionNotFresh]
      })
        .middleware(Authenticated)
        .annotateMerge(OpenApi.annotations({
          summary: "Remove one of the caller's sign-in methods",
          description: "Refuses to remove the last one, and requires a fresh session."
        }))
    )
    .prefix("/auth")
    .annotateMerge(OpenApi.annotations({
      title: "Auth",
      description: "Sessions, e-mail/password sign-in, and OAuth account linking."
    }))

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
 * @since 1.0.0
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
 * @since 1.0.0
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
 * @since 1.0.0
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
 * @since 1.0.0
 */
export const makeAuthApi = <F extends UserFields>(
  model: UserModel<F>
): HttpApi.HttpApi<"effect-auth", AuthApiGroupOf<F>> => HttpApi.make("effect-auth").add(makeAuthApiGroup(model))
