/**
 * The HTTP contract of the e-mail one-time-code plugin.
 *
 * Seven endpoints under `/auth/email-otp`: ask for a code, answer one, follow
 * the link that was sent beside it, and the two authenticated pairs that raise
 * a session's assurance and move an account's address.
 *
 * This module is import-safe from a browser, exactly as `http/AuthApi.ts` is: it
 * pulls in schemas and the group declaration, never a store, a mailer or a node
 * builtin. It is what `EmailOtpClient` and the server implementation share.
 *
 * @since 0.2.0
 */
import { Schema } from "effect"
import { HttpApi, HttpApiEndpoint, HttpApiGroup, OpenApi } from "effect/unstable/httpapi"
import { EmailUnchanged, InvalidCode, RateLimited, UserAlreadyExists } from "../domain/Errors.js"
import { PolicyRefused } from "../domain/Hooks.js"
import { Email, SessionPublic, SessionWithUser, UserPublic } from "../domain/Schema.js"
import { InputName, InputToken, InputUrl, MfaRequired, Ok, Redirect, Secret } from "../http/AuthApi.js"
import { Authenticated, AuthoritativeSession, freshSession, RequireAssurance } from "../http/Middleware.js"
import { OriginNotAllowed } from "../http/OriginCheck.js"

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/**
 * The deployment does not create accounts from e-mail codes, and the address the
 * code names has none.
 *
 * **Gotchas**
 *
 * Reachable only from `verify`, the JSON endpoint; the browser endpoint answers
 * every failure with a redirect carrying `?error=sign_up_disabled`.
 *
 * Asking for a code for an unknown address under `disableSignUp` still answers
 * `200`, still writes the same rows and still sets the same cookie: the refusal
 * happens where the code is spent, never where it is requested, so the send
 * endpoint stays free of an enumeration oracle.
 *
 * @category errors
 * @since 0.2.0
 */
export class SignUpDisabled extends Schema.TaggedError<SignUpDisabled>("effect-auth/email-otp/SignUpDisabled")(
  "SignUpDisabled",
  {},
  {
    description: "This deployment does not create accounts from e-mail codes",
    httpApiStatus: 403
  }
) {}

// -----------------------------------------------------------------------------
// Purposes
// -----------------------------------------------------------------------------

/**
 * The purposes an unauthenticated caller may ask for a code under.
 *
 * **Details**
 *
 * Three, and they are three different rows: a code minted to sign in can never
 * be answered as a code to reset a password, because the row it names is
 * namespaced by the purpose and a claim under another one matches nothing. The
 * two authenticated purposes — `stepUp` and `changeEmail` — are not here at all:
 * they have endpoints of their own, so a code phished under "confirm your
 * e-mail address" can never elevate a session.
 *
 * There is deliberately no `signUp` member. Signing up is what a `signIn` code
 * *does* when the address turns out to have no account and `disableSignUp` is
 * off — the magic-link semantics this module carries forward. A caller-declared
 * split would have to behave differently for a known and an unknown address,
 * which is precisely the enumeration oracle this endpoint exists to avoid.
 *
 * @category models
 * @since 0.2.0
 */
export const SendPurpose: Schema.Literals<["signIn", "verifyEmail", "resetPassword"]> = Schema.Literals([
  "signIn",
  "verifyEmail",
  "resetPassword"
])

/**
 * The type of a {@link SendPurpose}.
 *
 * @category models
 * @since 0.2.0
 */
export type SendPurpose = typeof SendPurpose.Type

// -----------------------------------------------------------------------------
// Payloads
// -----------------------------------------------------------------------------

/** A code is eight digits; the bound is what reaches the constant-time compare. */
const InputOtpCode = Schema.String.pipe(Schema.check(Schema.isMinLength(1), Schema.isMaxLength(16)))

/**
 * The code a person types back, as it crosses the wire.
 *
 * @category models
 * @since 0.2.0
 */
export const OtpCode: Schema.Redacted<typeof InputOtpCode> = Schema.Redacted(InputOtpCode)

/**
 * The body of `POST /auth/email-otp/send`.
 *
 * **Details**
 *
 * Every URL here is validated against `trustedOrigins` before it is stored in
 * the challenge's payload, and one that does not survive that is dropped rather
 * than refused — the code is worth sending without it. None of them is ever
 * echoed back to the caller, and none of them travels in the link.
 *
 * @category models
 * @since 0.2.0
 */
export const EmailOtpSendPayload = Schema.Struct({
  email: Email,
  /** What the code is for. See {@link SendPurpose}. */
  purpose: SendPurpose,
  /** The display name to give the account, if this code ends up creating one. */
  name: Schema.optional(InputName),
  /** Where to land after the link beside the code is followed. */
  callbackURL: Schema.optional(InputUrl),
  /** Where to land instead when the link created the account. */
  newUserCallbackURL: Schema.optional(InputUrl),
  /** Where to land when following the link fails. */
  errorCallbackURL: Schema.optional(InputUrl),
  /** When `false` the session the code establishes expires in a day. */
  rememberMe: Schema.optional(Schema.Boolean)
})

/**
 * The type of an {@link EmailOtpSendPayload}.
 *
 * @category models
 * @since 0.2.0
 */
export type EmailOtpSendPayload = typeof EmailOtpSendPayload.Type

/**
 * The body of `POST /auth/email-otp/verify`, and of both `verify` halves of the
 * authenticated pairs.
 *
 * **Gotchas**
 *
 * There is no handle in it. The handle is in the `__Host-effect_auth.email_otp_handle`
 * cookie the send endpoint set, which is what binds an attempt budget to the
 * browser that asked for the code — see `Challenges`.
 *
 * @category models
 * @since 0.2.0
 */
export const EmailOtpVerifyPayload = Schema.Struct({
  code: OtpCode
})

/**
 * The type of an {@link EmailOtpVerifyPayload}.
 *
 * @category models
 * @since 0.2.0
 */
export type EmailOtpVerifyPayload = typeof EmailOtpVerifyPayload.Type

/**
 * The query string of `GET /auth/email-otp/link`.
 *
 * **Gotchas**
 *
 * A plain `string` rather than a {@link Secret}: query strings do not go through
 * the JSON codec, so there is no transformation to hang the redaction on. The
 * handler wraps it with `Redacted.make` as its first act.
 *
 * @category models
 * @since 0.2.0
 */
export const EmailOtpLinkQuery = Schema.Struct({
  token: InputToken
})

/**
 * The type of an {@link EmailOtpLinkQuery}.
 *
 * @category models
 * @since 0.2.0
 */
export type EmailOtpLinkQuery = typeof EmailOtpLinkQuery.Type

/**
 * The body of `POST /auth/email-otp/change-email/send`: the address the account
 * is to be moved to, which is where the code goes.
 *
 * @category models
 * @since 0.2.0
 */
export const EmailOtpChangeEmailPayload = Schema.Struct({
  newEmail: Email
})

/**
 * The type of an {@link EmailOtpChangeEmailPayload}.
 *
 * @category models
 * @since 0.2.0
 */
export type EmailOtpChangeEmailPayload = typeof EmailOtpChangeEmailPayload.Type

// -----------------------------------------------------------------------------
// Responses
// -----------------------------------------------------------------------------

/**
 * A code that signed somebody in.
 *
 * @category models
 * @since 0.2.0
 */
export const EmailOtpSignedIn = Schema.Struct({
  _tag: Schema.tag("SignedIn"),
  user: UserPublic,
  session: SessionPublic
})

/**
 * The type of an {@link EmailOtpSignedIn}.
 *
 * @category models
 * @since 0.2.0
 */
export type EmailOtpSignedIn = typeof EmailOtpSignedIn.Type

/**
 * A code that proved control of an address, and nothing more: no session was
 * established.
 *
 * @category models
 * @since 0.2.0
 */
export const EmailOtpVerified = Schema.Struct({
  _tag: Schema.tag("Verified")
})

/**
 * The type of an {@link EmailOtpVerified}.
 *
 * @category models
 * @since 0.2.0
 */
export type EmailOtpVerified = typeof EmailOtpVerified.Type

/**
 * A code answered under the `resetPassword` purpose: a short-lived continuation
 * the caller spends at `POST /auth/reset-password`.
 *
 * **Gotchas**
 *
 * Answering a reset code does **not** sign anybody in. Whoever holds the code
 * has proved control of the mailbox, which is what entitles them to set a new
 * password — and setting one is what revokes the account's sessions. Handing
 * out a session first would let a stolen code be used without ever changing the
 * password, leaving the theft invisible.
 *
 * @category models
 * @since 0.2.0
 */
export const EmailOtpPasswordReset = Schema.Struct({
  _tag: Schema.tag("PasswordReset"),
  /** The continuation token. Spend it at `POST /auth/reset-password`. */
  token: Secret,
  /** When it stops being accepted. */
  expiresAt: Schema.DateTimeUtcFromString
})

/**
 * The type of an {@link EmailOtpPasswordReset}.
 *
 * @category models
 * @since 0.2.0
 */
export type EmailOtpPasswordReset = typeof EmailOtpPasswordReset.Type

/**
 * What answering a code can mean, when it worked.
 *
 * **Details**
 *
 * One tagged union rather than three endpoints, because the caller of `verify`
 * does not choose the purpose — the cookie the send endpoint set does. Branch on
 * `_tag`.
 *
 * @category models
 * @since 0.2.0
 */
export const EmailOtpResult: Schema.Union<
  [typeof EmailOtpSignedIn, typeof EmailOtpVerified, typeof EmailOtpPasswordReset]
> = Schema.Union([EmailOtpSignedIn, EmailOtpVerified, EmailOtpPasswordReset])

/**
 * The type of an {@link EmailOtpResult}.
 *
 * @category models
 * @since 0.2.0
 */
export type EmailOtpResult = typeof EmailOtpResult.Type

// -----------------------------------------------------------------------------
// Group
// -----------------------------------------------------------------------------

/**
 * The path every endpoint of this plugin is served under.
 *
 * **Gotchas**
 *
 * Baked into the group, and not changeable with `HttpApi.prefix` — that rewrites
 * the endpoint paths in the type, so the result no longer satisfies the
 * `groups.emailOtp` constraint `EmailOtp.handlers` and `EmailOtpClient.make`
 * check against. See `AuthApi`'s own note: mounting the server elsewhere is a
 * deployment concern, and `AuthConfig.basePath` is how the library is told.
 *
 * @category constructors
 * @since 0.2.0
 */
export const emailOtpPrefix = "/auth/email-otp"

/**
 * The path the e-mailed link points at.
 *
 * @category constructors
 * @since 0.2.0
 */
export const emailOtpLinkPath = `${emailOtpPrefix}/link`

/**
 * The seven endpoints the e-mail one-time-code plugin serves.
 *
 * **Details**
 *
 * A class, for the same two reasons `AuthApiGroup` is one: it is the shape a
 * consumer's `groups.emailOtp` constraint names, and it keeps the inferred group
 * type behind a single named declaration in the emitted types.
 *
 * Three of the seven carry no middleware — a code *is* the credential, and the
 * send endpoint has to be reachable by somebody who cannot sign in at all. The
 * other four are the two authenticated pairs, and each carries
 * `AuthoritativeSession`, because both rewrite the row the request authenticated
 * with and neither may be decided from a cookie-cache snapshot.
 *
 * @category models
 * @since 0.2.0
 */
export class EmailOtpApiGroup extends HttpApiGroup.make("emailOtp")
  .add(
    HttpApiEndpoint.post("send", "/send", {
      payload: EmailOtpSendPayload,
      success: Ok,
      error: [RateLimited, OriginNotAllowed]
    }).annotateMerge(
      OpenApi.annotations({
        summary: "Send a one-time code to an e-mail address",
        description:
          "Always answers 200 for a well-formed address, whether or not it has an account, whether or not this deployment would create one, and whether or not the message could be delivered. The same rows are written and the same cookie is set on every path, and delivery is forked off the request path, so the branches are indistinguishable in body, in status and in time. The handle the code is answered against is set in the __Host-effect_auth.email_otp_handle cookie and is never in the body."
      })
    ),
    HttpApiEndpoint.post("verify", "/verify", {
      payload: EmailOtpVerifyPayload,
      success: [EmailOtpResult, MfaRequired],
      error: [InvalidCode, SignUpDisabled, PolicyRefused, RateLimited, OriginNotAllowed]
    }).annotateMerge(
      OpenApi.annotations({
        summary: "Answer a one-time code",
        description:
          "The handle comes from the cookie the send endpoint set, so an attempt costs the budget of the browser that asked for the code rather than of the address it names. InvalidCode is every way of being wrong — a wrong code, an expired one, one already answered, one issued under another purpose, and a budget that has run out — because telling them apart would say whether a code was ever issued. Success is a two-status union: 200 with what the code meant, or 202 with MfaRequired when a factor plugin owes a second factor, in which case the pending-authentication token is set in the __Host-effect_auth.pending cookie and no session cookie is written."
      })
    ),
    HttpApiEndpoint.get("link", "/link", {
      query: EmailOtpLinkQuery,
      success: Redirect,
      error: RateLimited
    }).annotateMerge(
      OpenApi.annotations({
        summary: "Follow the sign-in link sent beside a code",
        description:
          "The other half of the hybrid: one issuance mints a code and a link against the same row, and consuming either retires the other. Claims the single-use token, establishes the session, sets the cookie and redirects. Every failure is a redirect too — to the errorCallbackURL the link was minted with, carrying ?error=invalid_token or ?error=sign_up_disabled — because the person arrived here by a top-level browser navigation and has to land on a page. A sign-in a factor plugin challenges redirects carrying ?mfa=required with the pending-authentication cookie and no session cookie."
      })
    ),
    HttpApiEndpoint.post("stepUpSend", "/step-up/send", {
      success: Ok,
      error: RateLimited
    })
      .middleware(Authenticated)
      .annotate(AuthoritativeSession, true)
      .annotateMerge(
        OpenApi.annotations({
          summary: "Send a step-up code to the caller's own address",
          description:
            "The address is the account's, never one the caller names, so this endpoint cannot be used to mail anybody else. It carries no RequireAssurance of its own: this is one of the endpoints that satisfies them."
        })
      ),
    HttpApiEndpoint.post("stepUpVerify", "/step-up/verify", {
      payload: EmailOtpVerifyPayload,
      success: SessionWithUser,
      error: [InvalidCode, RateLimited]
    })
      .middleware(Authenticated)
      .annotate(AuthoritativeSession, true)
      .annotateMerge(
        OpenApi.annotations({
          summary: "Answer a step-up code, raising the session's assurance",
          description:
            "Appends an emailOtp possession entry to the session's methods, recomputes its level, re-stamps authenticatedAt and rotates the opaque token — the session id is kept, so open tabs and the session list survive, while a token captured before the step-up does not inherit it. The cookie is re-set with the new token. A code issued under the sign-in purpose is never accepted here."
        })
      ),
    HttpApiEndpoint.post("changeEmailSend", "/change-email/send", {
      payload: EmailOtpChangeEmailPayload,
      success: Ok,
      error: [EmailUnchanged, RateLimited]
    })
      .middleware(Authenticated)
      .annotate(AuthoritativeSession, true)
      .annotate(RequireAssurance, freshSession)
      .annotateMerge(
        OpenApi.annotations({
          summary: "Send a code to the address an account is to be moved to",
          description:
            "One hop rather than the core flow's two, because the caller has already proved they hold this session recently enough — that is what the freshness requirement stands in for. Answers 200 whether or not the new address is already taken, and writes nothing to it; the occupied case is settled by the unique index when the code is answered."
        })
      ),
    HttpApiEndpoint.post("changeEmailVerify", "/change-email/verify", {
      payload: EmailOtpVerifyPayload,
      success: Ok,
      error: [InvalidCode, UserAlreadyExists, RateLimited]
    })
      .middleware(Authenticated)
      .annotate(AuthoritativeSession, true)
      .annotate(RequireAssurance, freshSession)
      .annotateMerge(
        OpenApi.annotations({
          summary: "Answer a change-of-address code",
          description:
            "Moves the account to the address the code was sent to and marks it verified — the code was delivered there and came back, which is the whole of what verification proves. Other sessions are not revoked: no credential changed."
        })
      )
  )
  .prefix(emailOtpPrefix)
  .annotateMerge(
    OpenApi.annotations({
      title: "E-mail one-time code",
      description:
        "Sign-in, address verification, password reset, step-up and change-of-address by a short code mailed to an address — with a single-use link beside it, backed by the same row."
    })
  ) {}

/**
 * The e-mail one-time-code endpoints as a standalone `HttpApi`.
 *
 * **When to use**
 *
 * As the client's declaration — `EmailOtpClient.make` builds against this — and
 * as a compact way to serve the plugin on its own. An application that composes
 * its own API adds the *group* to it instead:
 *
 * **Example**
 *
 * ```ts
 * import { HttpApi } from "effect/unstable/httpapi"
 * import { AuthApi, EmailOtp } from "effect-auth"
 *
 * const AppApi = HttpApi.make("app").addHttpApi(AuthApi).add(EmailOtp.EmailOtpApiGroup)
 * ```
 *
 * @category models
 * @since 0.2.0
 */
export const EmailOtpApi = HttpApi.make("effect-auth-email-otp").add(EmailOtpApiGroup)
