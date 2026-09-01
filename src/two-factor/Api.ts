/**
 * The HTTP contract of the two-factor plugin.
 *
 * Nine endpoints under `/auth/two-factor`: enrol an authenticator app and prove
 * it, answer a second factor with a code or a recovery code, turn it off,
 * regenerate the recovery set, and manage the browsers that may skip the
 * prompt.
 *
 * This module is import-safe from a browser, exactly as `http/AuthApi.ts` is:
 * schemas and the group declaration, never a store, a cipher or a node builtin.
 * It is what `TwoFactorClient` and the server implementation share.
 *
 * **Gotchas — the two endpoints with no middleware**
 *
 * `totp/verify` and `recovery/verify` deliberately do **not** carry
 * `Authenticated`. Each answers two subjects: a *pending* authentication, which
 * by construction has no session yet — the whole point of a second factor is
 * that the first one did not mint one — and a live session being raised to a
 * higher assurance. A middleware that demanded a session would make the first
 * of those unreachable, so the handler discriminates the two itself and the
 * endpoint declares `Unauthorized` for a caller that presents neither.
 *
 * @since 0.2.0
 */
import { Schema } from "effect"
import { HttpApi, HttpApiEndpoint, HttpApiGroup, OpenApi } from "effect/unstable/httpapi"
import { InvalidCode, InvalidToken, NotFound, RateLimited, Unauthorized } from "../domain/Errors.js"
import { PolicyRefused } from "../domain/Hooks.js"
import { OriginNotAllowed } from "../http/OriginCheck.js"
import { SessionWithUser } from "../domain/Schema.js"
import { recoveryCodeMethod } from "../domain/Sessions.js"
import { Ok, Secret } from "../http/AuthApi.js"
import { Authenticated, AuthoritativeSession, freshSession, RequireAssurance } from "../http/Middleware.js"
import { totpMethod } from "./Schema.js"

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/**
 * There is already an authenticator-app enrolment this person has proved.
 *
 * **Details**
 *
 * Enrolling again would replace a second factor with one the caller chose,
 * which is a takeover dressed as a convenience. A *pending* enrolment — one
 * that was started and never confirmed — is not this: starting again abandons
 * it and hands back a fresh secret, because a half-finished enrolment protects
 * nothing.
 *
 * @category errors
 * @since 0.2.0
 */
export class TotpAlreadyEnrolled extends Schema.TaggedError<TotpAlreadyEnrolled>(
  "effect-auth/two-factor/TotpAlreadyEnrolled"
)(
  "TotpAlreadyEnrolled",
  {},
  {
    description: "This account already has a confirmed authenticator-app enrolment",
    httpApiStatus: 409
  }
) {}

/**
 * There is no authenticator-app enrolment to act on.
 *
 * **Gotchas**
 *
 * Reachable only from endpoints that already carry a session, so it tells the
 * caller about their own account and is not an enumeration oracle. The two
 * *verify* endpoints never answer this: to somebody presenting a code, "you
 * have no second factor" and "that code is wrong" are one answer,
 * `InvalidCode`.
 *
 * @category errors
 * @since 0.2.0
 */
export class TotpNotEnrolled extends Schema.TaggedError<TotpNotEnrolled>("effect-auth/two-factor/TotpNotEnrolled")(
  "TotpNotEnrolled",
  {},
  {
    description: "This account has no authenticator-app enrolment",
    httpApiStatus: 409
  }
) {}

// -----------------------------------------------------------------------------
// Payloads
// -----------------------------------------------------------------------------

/**
 * The body of `POST /auth/two-factor/totp/confirm`.
 *
 * @category models
 * @since 0.2.0
 */
export const TotpConfirmPayload = Schema.Struct({
  /** The six digits the authenticator app is showing. */
  code: Secret
})

/**
 * The type of a {@link TotpConfirmPayload}.
 *
 * @category models
 * @since 0.2.0
 */
export type TotpConfirmPayload = typeof TotpConfirmPayload.Type

/**
 * The body of `POST /auth/two-factor/totp/verify`.
 *
 * @category models
 * @since 0.2.0
 */
export const TotpVerifyPayload = Schema.Struct({
  /** The six digits the authenticator app is showing. */
  code: Secret,
  /**
   * Remember this browser, so it is not asked for a second factor again until
   * the trust expires. Defaults to `false`: it is a thing the person asks for.
   */
  trustDevice: Schema.optional(Schema.Boolean),
  /** What to call the remembered browser in the device list. */
  label: Schema.optional(Schema.String.pipe(Schema.check(Schema.isMinLength(1), Schema.isMaxLength(64))))
})

/**
 * The type of a {@link TotpVerifyPayload}.
 *
 * @category models
 * @since 0.2.0
 */
export type TotpVerifyPayload = typeof TotpVerifyPayload.Type

/**
 * The body of `POST /auth/two-factor/recovery/verify`.
 *
 * **Gotchas**
 *
 * There is no `trustDevice` here, and that is not an omission: spending a
 * recovery code means the authenticator is gone, so this is the moment every
 * remembered browser is forgotten rather than a new one added.
 *
 * @category models
 * @since 0.2.0
 */
export const RecoveryVerifyPayload = Schema.Struct({
  /** The printed code, in any spelling — case and dashes are normalised. */
  code: Secret
})

/**
 * The type of a {@link RecoveryVerifyPayload}.
 *
 * @category models
 * @since 0.2.0
 */
export type RecoveryVerifyPayload = typeof RecoveryVerifyPayload.Type

/**
 * The body of `POST /auth/two-factor/devices/revoke`.
 *
 * @category models
 * @since 0.2.0
 */
export const DeviceRevokePayload = Schema.Struct({
  deviceId: Schema.String
})

/**
 * The type of a {@link DeviceRevokePayload}.
 *
 * @category models
 * @since 0.2.0
 */
export type DeviceRevokePayload = typeof DeviceRevokePayload.Type

// -----------------------------------------------------------------------------
// Responses
// -----------------------------------------------------------------------------

/**
 * What `POST /auth/two-factor/totp/enroll` answers: a secret to put into an
 * authenticator app, and how long there is to do it.
 *
 * **Gotchas**
 *
 * The only response in this library that carries a long-lived secret, and it
 * carries it exactly once — the ciphertext is what the database holds, and
 * there is no endpoint that reads it back. Both fields are `Redacted` so
 * nothing between here and the page can log them, and both contain the same
 * secret: `otpauthUri` is what a QR code encodes, `secret` is the
 * "type it in by hand" fallback.
 *
 * @category models
 * @since 0.2.0
 */
export const TotpEnrolmentStarted = Schema.Struct({
  /** The shared secret, RFC 4648 base32, uppercase and unpadded. */
  secret: Schema.Redacted(Schema.String),
  /** The `otpauth://totp/…` URI an authenticator app scans. */
  otpauthUri: Schema.Redacted(Schema.String),
  /** When an unconfirmed enrolment stops being confirmable. */
  expiresAt: Schema.DateTimeUtcFromString
})

/**
 * The type of a {@link TotpEnrolmentStarted}.
 *
 * @category models
 * @since 0.2.0
 */
export type TotpEnrolmentStarted = typeof TotpEnrolmentStarted.Type

/**
 * A freshly minted set of recovery codes, shown once.
 *
 * **Gotchas**
 *
 * There is no endpoint that lists these again, by design: only a keyed digest
 * of each is stored, so this response is the one time they exist. A person who
 * loses them regenerates the set, which invalidates the old one.
 *
 * @category models
 * @since 0.2.0
 */
export const RecoveryCodeSet = Schema.Struct({
  codes: Schema.Array(Schema.Redacted(Schema.String))
})

/**
 * The type of a {@link RecoveryCodeSet}.
 *
 * @category models
 * @since 0.2.0
 */
export type RecoveryCodeSet = typeof RecoveryCodeSet.Type

/**
 * One remembered browser, as its owner sees it.
 *
 * **Gotchas**
 *
 * No token and no digest: this is a list a person reads to decide what to
 * revoke, not a way to reconstruct a credential.
 *
 * @category models
 * @since 0.2.0
 */
export const TrustedDeviceView = Schema.Struct({
  id: Schema.String,
  label: Schema.NullOr(Schema.String),
  userAgent: Schema.NullOr(Schema.String),
  ipAddress: Schema.NullOr(Schema.String),
  createdAt: Schema.DateTimeUtcFromString,
  lastUsedAt: Schema.DateTimeUtcFromString,
  /** Absolute, and never extended by use. */
  expiresAt: Schema.DateTimeUtcFromString,
  /** Whether this is the browser making the request. */
  current: Schema.Boolean
})

/**
 * The type of a {@link TrustedDeviceView}.
 *
 * @category models
 * @since 0.2.0
 */
export type TrustedDeviceView = typeof TrustedDeviceView.Type

// -----------------------------------------------------------------------------
// Group
// -----------------------------------------------------------------------------

/**
 * The path every endpoint of this plugin is served under.
 *
 * **Gotchas**
 *
 * Baked into the group, and not changeable with `HttpApi.prefix` — see
 * `EmailOtp`'s note: re-prefixing rewrites the endpoint paths in the type, so
 * the result no longer satisfies the `groups.twoFactor` constraint the handlers
 * and the client check against.
 *
 * @category constructors
 * @since 0.2.0
 */
export const twoFactorPrefix = "/auth/two-factor"

/**
 * The assurance the two endpoints that take a second factor away demand: that
 * one of *this plugin's own* factors was proved on the session making the
 * request, recently.
 *
 * **Details**
 *
 * The obvious spelling is `{ aal: "aal2" }`, and it is wrong. `aal2` is
 * derived from *two distinct factor kinds*, so an account whose only first
 * factor is possession — OAuth-only, email-otp-only, SMS, a passkey the
 * authenticator did not verify a person for — never reaches it: the first
 * factor is possession, a TOTP code is possession, and `Assurance.deriveAal`
 * correctly reads that pair as one factor kind and answers `aal1`. Such an
 * account could enrol an authenticator app and then never disable it and never
 * regenerate its recovery codes, because no sequence of calls this library
 * serves would satisfy the guard. That is a permanent trap, and it is set for
 * the commonest kind of account there is.
 *
 * Naming the methods says what the endpoint actually means — *prove you still
 * hold the thing you are about to remove* — and it says it for every account
 * shape. It is no weaker against the threat these endpoints exist for: a
 * stolen session may only turn the second factor off if the second factor was
 * answered on that session, which was the whole content of `aal2` here.
 *
 * **Gotchas**
 *
 * It states no `maxAge`, so the middleware resolves one from
 * `session.freshAge` rather than from `assurance.stepUpWindow` — the
 * `stepUpWindow` default is reserved for a policy that names `aal2`. A
 * deployment wanting the tighter window states a `maxAge` of its own.
 *
 * `allowRecovery` is deliberately left unstated, so a printed recovery code is
 * one of the two answers: somebody whose authenticator is gone is exactly who
 * needs to disable the enrolment and enrol again.
 *
 * @category models
 * @since 0.2.0
 */
export const provedSecondFactor = { methods: [totpMethod, recoveryCodeMethod] } as const

/**
 * The nine endpoints the two-factor plugin serves.
 *
 * **Details**
 *
 * Every endpoint that adds, removes or replaces a factor carries
 * `AuthoritativeSession` — the decision must be made against the row, never a
 * cookie-cache snapshot — and a `RequireAssurance` policy:
 *
 * - enrolling and confirming ask only for a *recent* session
 *   (`freshSession`), because a person with no second factor yet cannot be
 *   asked for one;
 * - disabling and regenerating ask for {@link provedSecondFactor} — that this
 *   plugin's own factor was answered on this session, recently — because both
 *   are exactly what somebody who has stolen a session would do next.
 *
 * @category models
 * @since 0.2.0
 */
export class TwoFactorApiGroup extends HttpApiGroup.make("twoFactor")
  .add(
    HttpApiEndpoint.post("totpEnroll", "/totp/enroll", {
      success: TotpEnrolmentStarted,
      error: TotpAlreadyEnrolled
    })
      .middleware(Authenticated)
      .annotate(AuthoritativeSession, true)
      .annotate(RequireAssurance, freshSession)
      .annotateMerge(
        OpenApi.annotations({
          summary: "Start an authenticator-app enrolment",
          description:
            "Answers a fresh shared secret and the otpauth:// URI a QR code encodes. The enrolment is pending until a code proves it, and a pending enrolment is never accepted for authentication. Starting again abandons a pending enrolment and mints a new secret; an enrolment that has already been confirmed is not replaced — disable it first."
        })
      ),
    HttpApiEndpoint.post("totpConfirm", "/totp/confirm", {
      payload: TotpConfirmPayload,
      success: RecoveryCodeSet,
      error: [InvalidCode, TotpAlreadyEnrolled, TotpNotEnrolled, RateLimited]
    })
      .middleware(Authenticated)
      .annotate(AuthoritativeSession, true)
      .annotate(RequireAssurance, freshSession)
      .annotateMerge(
        OpenApi.annotations({
          summary: "Prove a pending enrolment and receive the recovery codes",
          description:
            "The recovery codes are generated at this moment — not at enrolment — and returned once. Only a keyed digest of each is stored, so there is no endpoint that lists them again. The step the confirming code belongs to is recorded, so that code cannot be replayed."
        })
      ),
    HttpApiEndpoint.post("totpVerify", "/totp/verify", {
      payload: TotpVerifyPayload,
      success: SessionWithUser,
      error: [InvalidCode, InvalidToken, Unauthorized, OriginNotAllowed, PolicyRefused, RateLimited]
    }).annotateMerge(
      OpenApi.annotations({
        summary: "Answer a second factor with an authenticator-app code",
        description:
          "Serves two subjects. With the pending-authentication cookie set — a sign-in that was interrupted for a second factor — it completes that sign-in and sets the session cookie; the pending cookie is cleared either way, and a wrong code leaves the pending authentication alive until it expires. With a session instead, it raises that session's assurance in place and re-sets its cookie with the rotated token. A caller presenting neither is Unauthorized."
      })
    ),
    HttpApiEndpoint.post("totpDisable", "/totp/disable", {
      success: Ok,
      error: TotpNotEnrolled
    })
      .middleware(Authenticated)
      .annotate(AuthoritativeSession, true)
      .annotate(RequireAssurance, provedSecondFactor)
      .annotateMerge(
        OpenApi.annotations({
          summary: "Remove the authenticator-app enrolment",
          description:
            "Deletes the enrolment, every recovery code and every remembered browser. Requires a session that answered this plugin's own factor — an authenticator code or a recovery code — recently, because turning the second factor off is the first thing a stolen session would do."
        })
      ),
    HttpApiEndpoint.post("recoveryVerify", "/recovery/verify", {
      payload: RecoveryVerifyPayload,
      success: SessionWithUser,
      error: [InvalidCode, InvalidToken, Unauthorized, OriginNotAllowed, PolicyRefused, RateLimited]
    }).annotateMerge(
      OpenApi.annotations({
        summary: "Answer a second factor with a recovery code",
        description:
          "The same two subjects as totp/verify, with the code spent atomically so it can never be used twice. Every remembered browser is forgotten and a notification is sent, because spending one of these means the authenticator is gone. The session it produces records that a recovery code was used, so a policy may refuse it where it would accept a real factor."
      })
    ),
    HttpApiEndpoint.post("recoveryRegenerate", "/recovery/regenerate", {
      success: RecoveryCodeSet,
      error: TotpNotEnrolled
    })
      .middleware(Authenticated)
      .annotate(AuthoritativeSession, true)
      .annotate(RequireAssurance, provedSecondFactor)
      .annotateMerge(
        OpenApi.annotations({
          summary: "Replace the recovery codes",
          description:
            "Every previous code — spent or not — stops working, and every remembered browser is forgotten. Requires a recently answered second factor for the same reason disabling does."
        })
      ),
    HttpApiEndpoint.get("devices", "/devices", {
      success: Schema.Array(TrustedDeviceView)
    })
      .middleware(Authenticated)
      .annotateMerge(
        OpenApi.annotations({
          summary: "List the browsers that may skip the second factor",
          description: "Expired devices are not listed. current marks the browser making the request."
        })
      ),
    HttpApiEndpoint.post("devicesRevoke", "/devices/revoke", {
      payload: DeviceRevokePayload,
      success: Ok,
      error: NotFound
    })
      .middleware(Authenticated)
      .annotate(AuthoritativeSession, true)
      .annotateMerge(
        OpenApi.annotations({
          summary: "Forget one remembered browser",
          description: "Ownership is enforced in the statement, so this cannot revoke somebody else's device."
        })
      ),
    HttpApiEndpoint.post("devicesRevokeAll", "/devices/revoke-all", {
      success: Ok
    })
      .middleware(Authenticated)
      .annotate(AuthoritativeSession, true)
      .annotateMerge(
        OpenApi.annotations({
          summary: "Forget every remembered browser",
          description:
            "The one clearing path that does not require turning the second factor off, and the thing to do from a device you still trust when one you do not is out there."
        })
      )
  )
  .prefix(twoFactorPrefix)
  .annotateMerge(
    OpenApi.annotations({
      title: "Two-factor authentication",
      description:
        "Time-based one-time codes, recovery codes and remembered browsers. A person with a confirmed enrolment is asked for a second factor by every sign-in path this library serves, because the interposition point is the sign-in pipeline rather than a list of routes."
    })
  ) {}

/**
 * The two-factor endpoints as a standalone `HttpApi`.
 *
 * **When to use**
 *
 * As the client's declaration — `TwoFactorClient.make` builds against this —
 * and as a compact way to serve the plugin on its own. An application that
 * composes its own API adds the *group* to it instead.
 *
 * **Example**
 *
 * ```ts
 * import { HttpApi } from "effect/unstable/httpapi"
 * import { AuthApi, TwoFactor } from "effect-auth"
 *
 * const AppApi = HttpApi.make("app").addHttpApi(AuthApi).add(TwoFactor.TwoFactorApiGroup)
 * ```
 *
 * @category models
 * @since 0.2.0
 */
export const TwoFactorApi = HttpApi.make("effect-auth-two-factor").add(TwoFactorApiGroup)
