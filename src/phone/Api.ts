/**
 * The HTTP contract of the phone plugin.
 *
 * Seven endpoints under `/auth/phone`, in three pairs and a management one:
 * prove a number belongs to the caller, sign in with one, and raise a live
 * session's assurance with one.
 *
 * **Details**
 *
 * The three pairs are three *capabilities*, and a deployment turns each on
 * separately — see `Phone.Config`. Every endpoint is declared whatever the
 * configuration says, exactly as this library's own `signInEmail` is: a
 * capability that is off answers `404`, so the document a client generates
 * against the group is the same document whoever serves it, and turning a
 * capability on is not a wire change.
 *
 * This module is import-safe from a browser, exactly as `http/AuthApi.ts` and
 * `email-otp/Api.ts` are: schemas and the group declaration, never a store, a
 * sender or a node builtin. It is what `PhoneClient` and the server
 * implementation share.
 *
 * **Gotchas**
 *
 * The code never travels in a request that also carries the number. The handle
 * a code was issued against rides in a `__Host-` cookie of this plugin's own
 * (`Phone.verifyCookieBaseName` and its two siblings), so a verify request is
 * `{ code }` and nothing else — which is what binds the attempt budget to the
 * browser that asked and stops anybody from spending a stranger's attempts.
 *
 * @since 0.2.0
 */
import { Schema } from "effect"
import { HttpApi, HttpApiEndpoint, HttpApiGroup, OpenApi } from "effect/unstable/httpapi"
import { InvalidCode, RateLimited } from "../domain/Errors.js"
import { PolicyRefused } from "../domain/Hooks.js"
import { SessionWithUser } from "../domain/Schema.js"
import { MfaRequired, Ok } from "../http/AuthApi.js"
import { Authenticated, AuthoritativeSession, freshSession, RequireAssurance } from "../http/Middleware.js"
import { OriginNotAllowed } from "../http/OriginCheck.js"
import { maxInputLength } from "./E164.js"

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/**
 * The number is not one this library can read as E.164.
 *
 * **Gotchas**
 *
 * Says nothing about whether the number exists, is reachable, or belongs to
 * anybody: it is a statement about the *string*, raised before any lookup and
 * before any message. `E164.normalize` is what decides it.
 *
 * @category errors
 * @since 0.2.0
 */
export class InvalidPhoneNumber extends Schema.TaggedError<InvalidPhoneNumber>("effect-auth/phone/InvalidPhoneNumber")(
  "InvalidPhoneNumber",
  {},
  {
    description: "The phone number is not a valid E.164 number",
    httpApiStatus: 400
  }
) {}

/**
 * The deployment does not send messages to this number's country.
 *
 * **Details**
 *
 * `Phone.Options.allowedCountries` defaults to the empty list, which refuses
 * everything: an SMS is the one thing this library does that costs money per
 * request, so where the messages may go is a decision a deployment makes rather
 * than one it inherits. This error is what an un-opted-in country looks like,
 * and it is raised before anything is sent, written or rate-limited against a
 * destination.
 *
 * @category errors
 * @since 0.2.0
 */
export class PhoneCountryNotAllowed extends Schema.TaggedError<PhoneCountryNotAllowed>(
  "effect-auth/phone/PhoneCountryNotAllowed"
)(
  "PhoneCountryNotAllowed",
  {},
  {
    description: "This deployment does not send messages to that country",
    httpApiStatus: 403
  }
) {}

/**
 * The number is already held by another account.
 *
 * **Gotchas**
 *
 * Raised only *after* the code has been answered correctly — the caller has
 * proved they hold the handset by then, so telling them it is registered
 * elsewhere reveals nothing they could not have found out by using it. Asking
 * for a code for a number somebody else holds is answered like every other ask.
 *
 * @category errors
 * @since 0.2.0
 */
export class PhoneAlreadyInUse extends Schema.TaggedError<PhoneAlreadyInUse>("effect-auth/phone/PhoneAlreadyInUse")(
  "PhoneAlreadyInUse",
  {},
  {
    description: "That number already belongs to another account",
    httpApiStatus: 409
  }
) {}

/**
 * The caller has no verified number, so there is nothing to send a code to.
 *
 * **Gotchas**
 *
 * Only ever raised on the two authenticated endpoints, about the caller's own
 * account, so it discloses nothing about anybody else.
 *
 * @category errors
 * @since 0.2.0
 */
export class PhoneNotVerified extends Schema.TaggedError<PhoneNotVerified>("effect-auth/phone/PhoneNotVerified")(
  "PhoneNotVerified",
  {},
  {
    description: "The caller has no verified phone number",
    httpApiStatus: 403
  }
) {}

/**
 * A number would have become this person's only second factor, and the
 * deployment does not permit that.
 *
 * **Details**
 *
 * NIST 800-63B §3.2.9: SMS is a *restricted* authenticator, and a subscriber
 * whose only second factor is a restricted one has no fallback when the
 * restriction bites. `Phone.Options.requireAlternateSecondFactor` turns the
 * rule on; the check reads the `Authenticators` seam, so what counts as an
 * alternative is whatever other factor plugins the deployment installed.
 *
 * @category errors
 * @since 0.2.0
 */
export class RestrictedFactorNotAllowed extends Schema.TaggedError<RestrictedFactorNotAllowed>(
  "effect-auth/phone/RestrictedFactorNotAllowed"
)(
  "RestrictedFactorNotAllowed",
  {},
  {
    description: "A restricted factor may not be this account's only second factor",
    httpApiStatus: 403
  }
) {}

// -----------------------------------------------------------------------------
// Payloads
// -----------------------------------------------------------------------------

/**
 * A phone number as it arrives on the wire: any spelling, bounded in length.
 *
 * **Gotchas**
 *
 * The schema bounds the string and nothing else. Whether it is a *number* is
 * decided by `E164.normalize` inside the service, which answers
 * {@link InvalidPhoneNumber} — a typed refusal a client can act on, rather than
 * a decode error, and the same answer whichever entry point was used.
 *
 * @category models
 * @since 0.2.0
 */
export const InputPhoneNumber = Schema.String.pipe(
  Schema.check(Schema.isMinLength(1), Schema.isMaxLength(maxInputLength))
)

/**
 * A code as it arrives on the wire.
 *
 * @category models
 * @since 0.2.0
 */
export const InputCode = Schema.String.pipe(Schema.check(Schema.isMinLength(1), Schema.isMaxLength(16)))

/**
 * The body of the two endpoints that name a number.
 *
 * @category models
 * @since 0.2.0
 */
export const PhoneNumberPayload = Schema.Struct({
  phoneNumber: InputPhoneNumber
})

/**
 * The type of a {@link PhoneNumberPayload}.
 *
 * @category models
 * @since 0.2.0
 */
export type PhoneNumberPayload = typeof PhoneNumberPayload.Type

/**
 * The body of every endpoint that answers a code.
 *
 * **Gotchas**
 *
 * No number and no handle: the handle is in the cookie the matching `send`
 * endpoint set, which is what binds the code to the browser that asked for it.
 *
 * @category models
 * @since 0.2.0
 */
export const PhoneCodePayload = Schema.Struct({
  code: InputCode
})

/**
 * The type of a {@link PhoneCodePayload}.
 *
 * @category models
 * @since 0.2.0
 */
export type PhoneCodePayload = typeof PhoneCodePayload.Type

/**
 * The body of `POST /auth/phone/sign-in/verify`.
 *
 * **Details**
 *
 * {@link PhoneCodePayload} plus the one answer only a sign-in has to give: how
 * long the session it mints should outlive the browser. Every other door into
 * this library that mints a session takes it — `signInEmail`, the username
 * sign-in, the passkey ceremony — and a code answered on a shared handset is
 * exactly the sign-in somebody would want to say `false` to.
 *
 * The two `verify` endpoints beside it do not take it: they raise or attach to
 * a session that already made that choice.
 *
 * @category models
 * @since 0.2.0
 */
export const PhoneSignInPayload = Schema.Struct({
  code: InputCode,
  rememberMe: Schema.optional(Schema.Boolean)
})

/**
 * The type of a {@link PhoneSignInPayload}.
 *
 * @category models
 * @since 0.2.0
 */
export type PhoneSignInPayload = typeof PhoneSignInPayload.Type

/**
 * The empty body of `POST /auth/phone/step-up/send`.
 *
 * The number is the caller's own, read off their record; naming one here would
 * be a second, unproved number on a step-up path.
 *
 * @category models
 * @since 0.2.0
 */
export const EmptyPayload = Schema.Struct({})

/**
 * The type of an {@link EmptyPayload}.
 *
 * @category models
 * @since 0.2.0
 */
export type EmptyPayload = typeof EmptyPayload.Type

/**
 * What `POST /auth/phone/verify` answers: the number as it is now stored, and
 * when it was proved.
 *
 * **Gotchas**
 *
 * The *canonical* number, which is the useful half: a caller that typed
 * `+1 (555) 010-0000` gets `+15550100000` back and can show what was actually
 * recorded. It is the caller's own number, proved a moment ago, so there is
 * nothing here they did not just supply.
 *
 * @category models
 * @since 0.2.0
 */
export const VerifiedPhone = Schema.Struct({
  phoneNumber: Schema.String,
  verifiedAt: Schema.DateTimeUtcFromString
})

/**
 * The type of a {@link VerifiedPhone}.
 *
 * @category models
 * @since 0.2.0
 */
export type VerifiedPhone = typeof VerifiedPhone.Type

// -----------------------------------------------------------------------------
// Group
// -----------------------------------------------------------------------------

/**
 * The path every endpoint of this plugin is served under.
 *
 * **Gotchas**
 *
 * Baked into the group and not changeable with `HttpApi.prefix`, for the reason
 * `emailOtpPrefix` gives: rewriting the paths in the type produces a group
 * that no longer satisfies the `groups.phone` constraint the handlers and the
 * client check against.
 *
 * @category constructors
 * @since 0.2.0
 */
export const phonePrefix = "/auth/phone"

/**
 * The seven endpoints the phone plugin serves.
 *
 * **Details**
 *
 * A class, for the two reasons `AuthApiGroup` is one: it is the shape a
 * consumer's `groups.phone` constraint names, and it keeps the inferred group
 * behind a single named declaration in the emitted types. Non-generic, and it
 * answers the base user projection — a plugin group is not multiplied by a
 * deployment's custom user fields.
 *
 * The middleware is applied per endpoint rather than to the group: four of the
 * seven are about the caller's own account and carry `Authenticated`, and three
 * are how somebody with no session at all gets one.
 *
 * @category models
 * @since 0.2.0
 */
export class PhoneApiGroup extends HttpApiGroup.make("phone")
  .add(
    HttpApiEndpoint.post("sendVerification", "/send-verification", {
      payload: PhoneNumberPayload,
      success: Ok,
      error: [InvalidPhoneNumber, PhoneCountryNotAllowed, RestrictedFactorNotAllowed, RateLimited]
    })
      .middleware(Authenticated)
      // Attaching a number is factor enrolment: it must be decided against the
      // session row rather than a snapshot, and it must cost a recent
      // authentication.
      .annotate(AuthoritativeSession, true)
      .annotate(RequireAssurance, freshSession)
      .annotateMerge(
        OpenApi.annotations({
          summary: "Send a code to a number the caller wants to attach",
          description:
            "Sets the phone-verification handle in a __Host- cookie and sends a code by SMS. The number is normalised to E.164 before anything else happens, and refused outright when its country is not in the deployment's allowedCountries — which is empty by default. Answers the same whether or not the number already belongs to somebody else: that is settled at verify time, once possession has been proved."
        })
      ),
    HttpApiEndpoint.post("verify", "/verify", {
      payload: PhoneCodePayload,
      success: VerifiedPhone,
      error: [InvalidCode, PhoneAlreadyInUse, RestrictedFactorNotAllowed, RateLimited]
    })
      .middleware(Authenticated)
      .annotate(AuthoritativeSession, true)
      .annotate(RequireAssurance, freshSession)
      .annotateMerge(
        OpenApi.annotations({
          summary: "Attach a number by answering its code",
          description:
            "Consumes the handle from the __Host- cookie and the code from the body, atomically and once. On success the number replaces whatever the caller held before. PhoneAlreadyInUse is raised only after the code was right, so it never tells an unproven caller who holds a number."
        })
      ),
    HttpApiEndpoint.post("remove", "/remove", {
      payload: EmptyPayload,
      success: Ok,
      error: RateLimited
    })
      .middleware(Authenticated)
      .annotate(AuthoritativeSession, true)
      .annotate(RequireAssurance, freshSession)
      .annotateMerge(
        OpenApi.annotations({
          summary: "Detach the caller's number",
          description:
            "Removing a factor is a factor-management operation and costs a recent authentication, exactly as attaching one does. Succeeds whether or not there was a number to remove."
        })
      ),
    HttpApiEndpoint.post("signInSend", "/sign-in/send", {
      payload: PhoneNumberPayload,
      success: Ok,
      error: [InvalidPhoneNumber, PhoneCountryNotAllowed, OriginNotAllowed, RateLimited]
    }).annotateMerge(
      OpenApi.annotations({
        summary: "Send a sign-in code to a number",
        description:
          "Answers 200 for a well-formed, permitted number whether or not anybody holds it, and takes the same time to do it — a message is only actually sent for a number that names an account, and it is sent off the request path. Unauthenticated, so it checks a present Origin or Referer against trustedOrigins."
      })
    ),
    HttpApiEndpoint.post("signInVerify", "/sign-in/verify", {
      payload: PhoneSignInPayload,
      success: [SessionWithUser, MfaRequired],
      error: [InvalidCode, OriginNotAllowed, PolicyRefused, RateLimited]
    }).annotateMerge(
      OpenApi.annotations({
        summary: "Sign in by answering a code",
        description:
          "Consumes the handle from the __Host- cookie and the code from the body, and completes the sign-in through the same choke point every other credential goes through. Success is the two-status union: 200 with the session and its user, or 202 with MfaRequired when a factor plugin owes a second factor, in which case the pending-authentication token is set and no session cookie is written. A code for a number with no account is InvalidCode, which is also what a wrong code is. Unauthenticated and it mints a session, so — like the send beside it — a present Origin or Referer is checked against trustedOrigins: a cross-site post that already knew a code would otherwise sign a visitor's browser into somebody else's account."
      })
    ),
    HttpApiEndpoint.post("stepUpSend", "/step-up/send", {
      payload: EmptyPayload,
      success: Ok,
      error: [PhoneNotVerified, RateLimited]
    })
      .middleware(Authenticated)
      .annotate(AuthoritativeSession, true)
      .annotateMerge(
        OpenApi.annotations({
          summary: "Send a step-up code to the caller's own number",
          description:
            "Takes no number: it goes to the one on the caller's record, which they have already proved they hold. Carries no RequireAssurance of its own — this is one of the endpoints that satisfies them."
        })
      ),
    HttpApiEndpoint.post("stepUpVerify", "/step-up/verify", {
      payload: PhoneCodePayload,
      success: SessionWithUser,
      error: [InvalidCode, RateLimited]
    })
      .middleware(Authenticated)
      .annotate(AuthoritativeSession, true)
      .annotateMerge(
        OpenApi.annotations({
          summary: "Raise the caller's session by answering a code",
          description:
            "Appends an sms entry to the session's methods, recomputes its level, re-stamps authenticatedAt and rotates the opaque token — the session id is kept, so open tabs and the session list survive, while a token captured before the step-up does not inherit it. The cookie is re-set with the new token. SMS is a restricted channel, so the entry it records is marked restricted and is never phishing-resistant."
        })
      )
  )
  .prefix(phonePrefix)
  .annotateMerge(
    OpenApi.annotations({
      title: "Phone",
      description:
        "A verified phone number: as a contact detail, as a way to sign in, and as a way to raise a live session's assurance."
    })
  ) {}

/**
 * The phone endpoints as a standalone `HttpApi`.
 *
 * **When to use**
 *
 * As the client's declaration — `PhoneClient.make` builds against this — and as
 * a compact way to serve the plugin on its own. An application that composes
 * its own API adds the *group* to it instead.
 *
 * @category models
 * @since 0.2.0
 */
export const PhoneApi = HttpApi.make("effect-auth-phone").add(PhoneApiGroup)
