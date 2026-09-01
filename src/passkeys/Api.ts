/**
 * The HTTP contract of the passkeys plugin.
 *
 * Seven endpoints under `/auth/passkeys`: two halves of a registration
 * ceremony, two halves of an authentication ceremony, and the three things a
 * person does to their own credentials.
 *
 * This module is import-safe from a browser, exactly as `http/AuthApi.ts` is: it
 * pulls in schemas and the group declaration, never a store, a verifier or a
 * node builtin — and never `@simplewebauthn/server`, which only
 * `WebAuthn.layerSimple` names. It is what `PasskeysClient` and the server
 * implementation share.
 *
 * **Gotchas — which endpoints are guarded, and why**
 *
 * Registering a credential *adds a way into the account*, so both halves of
 * that ceremony carry `Authenticated`, `AuthoritativeSession` and
 * `RequireAssurance(freshSession)`: a stolen but stale cookie must not be enough
 * to make a session takeover permanent. Deleting one carries the same, because
 * removing somebody's second factor is how an attacker keeps what they took.
 *
 * The two authentication halves carry none of it. A passkey *is* the credential:
 * requiring a session to present one would defeat the flow, and the sign-in page
 * has to be reachable by somebody who cannot sign in at all.
 *
 * @since 0.2.0
 */
import { Schema } from "effect"
import { HttpApi, HttpApiEndpoint, HttpApiGroup, OpenApi } from "effect/unstable/httpapi"
import { NotFound, RateLimited } from "../domain/Errors.js"
import { PolicyRefused } from "../domain/Hooks.js"
import { Email, SessionWithUser } from "../domain/Schema.js"
import { MfaRequired, Ok } from "../http/AuthApi.js"
import { Authenticated, AuthoritativeSession, freshSession, RequireAssurance } from "../http/Middleware.js"
import { OriginNotAllowed } from "../http/OriginCheck.js"
import { CannotRemoveLastAuthenticator, ChallengeExpired, PasskeyVerificationFailed } from "./Errors.js"
import { PasskeyId } from "./Schema.js"
import {
  AuthenticationOptions,
  AuthenticationResponse,
  AuthenticatorAttachment,
  AuthenticatorTransports,
  RegistrationOptions,
  RegistrationResponse
} from "./Wire.js"

// -----------------------------------------------------------------------------
// Payloads
// -----------------------------------------------------------------------------

/**
 * The longest name a person may give one of their own credentials — the
 * `varchar(64)` the column is.
 *
 * @category constructors
 * @since 0.2.0
 */
export const maxPasskeyNameLength = 64

const PasskeyName = Schema.String.pipe(Schema.check(Schema.isMinLength(1), Schema.isMaxLength(maxPasskeyNameLength)))

/**
 * The body of `POST /auth/passkeys/register/options`.
 *
 * @category models
 * @since 0.2.0
 */
export const RegisterOptionsPayload = Schema.Struct({
  /**
   * Ask for a platform authenticator (this device) or a roaming one (a security
   * key). Omit it and the browser offers both, which is what most deployments
   * want.
   */
  authenticatorAttachment: Schema.optional(AuthenticatorAttachment)
})

/**
 * The type of a {@link RegisterOptionsPayload}.
 *
 * @category models
 * @since 0.2.0
 */
export type RegisterOptionsPayload = typeof RegisterOptionsPayload.Type

/**
 * The body of `POST /auth/passkeys/register/verify`.
 *
 * **Gotchas**
 *
 * There is no user id in it, and there never will be: whose credential this is
 * comes from the session, and the ceremony was minted for that same person.
 *
 * @category models
 * @since 0.2.0
 */
export const RegisterVerifyPayload = Schema.Struct({
  response: RegistrationResponse,
  /** What to call it in the credential list. */
  name: Schema.optional(PasskeyName)
})

/**
 * The type of a {@link RegisterVerifyPayload}.
 *
 * @category models
 * @since 0.2.0
 */
export type RegisterVerifyPayload = typeof RegisterVerifyPayload.Type

/**
 * The body of `POST /auth/passkeys/authenticate/options`.
 *
 * @category models
 * @since 0.2.0
 */
export const AuthenticateOptionsPayload = Schema.Struct({
  /**
   * An address to scope `allowCredentials` to, for a deployment that asks for
   * one before offering the passkey prompt.
   *
   * **Gotchas**
   *
   * Optional, and omitting it is the better flow: a discoverable credential
   * needs no address at all. An address with no account is answered with decoy
   * descriptors rather than an empty list, so this endpoint tells a caller
   * nothing about who is registered.
   */
  email: Schema.optional(Email)
})

/**
 * The type of an {@link AuthenticateOptionsPayload}.
 *
 * @category models
 * @since 0.2.0
 */
export type AuthenticateOptionsPayload = typeof AuthenticateOptionsPayload.Type

/**
 * The body of `POST /auth/passkeys/authenticate/verify`.
 *
 * @category models
 * @since 0.2.0
 */
export const AuthenticateVerifyPayload = Schema.Struct({
  response: AuthenticationResponse,
  /**
   * When `false` the session this ceremony establishes expires in a day rather
   * than at the deployment's full `session.expiresIn`. Ignored when the
   * ceremony raises an existing session instead of minting one — that session's
   * own choice stands.
   */
  rememberMe: Schema.optional(Schema.Boolean)
})

/**
 * The type of an {@link AuthenticateVerifyPayload}.
 *
 * @category models
 * @since 0.2.0
 */
export type AuthenticateVerifyPayload = typeof AuthenticateVerifyPayload.Type

/**
 * The body of `POST /auth/passkeys/rename`.
 *
 * @category models
 * @since 0.2.0
 */
export const RenamePasskeyPayload = Schema.Struct({
  id: PasskeyId,
  /** `null` clears the name. */
  name: Schema.NullOr(PasskeyName)
})

/**
 * The type of a {@link RenamePasskeyPayload}.
 *
 * @category models
 * @since 0.2.0
 */
export type RenamePasskeyPayload = typeof RenamePasskeyPayload.Type

/**
 * The body of `POST /auth/passkeys/delete`.
 *
 * @category models
 * @since 0.2.0
 */
export const DeletePasskeyPayload = Schema.Struct({
  id: PasskeyId
})

/**
 * The type of a {@link DeletePasskeyPayload}.
 *
 * @category models
 * @since 0.2.0
 */
export type DeletePasskeyPayload = typeof DeletePasskeyPayload.Type

// -----------------------------------------------------------------------------
// Responses
// -----------------------------------------------------------------------------

/**
 * One of a person's credentials, as they are shown it.
 *
 * **Gotchas**
 *
 * No credential id and no public key. Neither is a secret, and neither is any
 * of a browser's business once the credential is registered: the id a person's
 * own management endpoints name a credential by is this row's own
 * {@link PasskeyId}.
 *
 * @category models
 * @since 0.2.0
 */
export const PasskeySummary = Schema.Struct({
  id: PasskeyId,
  /** Whatever the person called it, or `null`. */
  name: Schema.NullOr(Schema.String),
  /** The authenticator model, for showing an icon. */
  aaguid: Schema.String,
  transports: AuthenticatorTransports,
  /** Whether the credential is synced, so a person can tell a device apart from a key. */
  backedUp: Schema.Boolean,
  createdAt: Schema.DateTimeUtcFromString,
  lastUsedAt: Schema.NullOr(Schema.DateTimeUtcFromString)
})

/**
 * The type of a {@link PasskeySummary}.
 *
 * @category models
 * @since 0.2.0
 */
export type PasskeySummary = typeof PasskeySummary.Type

/**
 * A person's credentials, oldest first.
 *
 * @category models
 * @since 0.2.0
 */
export const PasskeySummaries: Schema.$Array<typeof PasskeySummary> = Schema.Array(PasskeySummary)

// -----------------------------------------------------------------------------
// Group
// -----------------------------------------------------------------------------

/**
 * The path every endpoint of this plugin is served under.
 *
 * **Gotchas**
 *
 * Baked into the group, and not changeable with `HttpApi.prefix` — see
 * `EmailOtp.emailOtpPrefix` for why. A deployment serving the API elsewhere
 * sets `AuthConfig.basePath`.
 *
 * @category constructors
 * @since 0.2.0
 */
export const passkeysPrefix = "/auth/passkeys"

/**
 * The seven endpoints the passkeys plugin serves.
 *
 * **Details**
 *
 * A class, for the same reasons `AuthApiGroup` and `EmailOtpApiGroup` are: it
 * is the shape a consumer's `groups.passkeys` constraint names, and it keeps the
 * inferred group type behind one named declaration in the emitted types.
 *
 * Non-generic, and it answers the base user projection — a plugin group never
 * takes a deployment's user model, so `SessionWithUser` here is the base one.
 *
 * @category models
 * @since 0.2.0
 */
export class PasskeysApiGroup extends HttpApiGroup.make("passkeys")
  .add(
    HttpApiEndpoint.post("registerOptions", "/register/options", {
      payload: RegisterOptionsPayload,
      success: RegistrationOptions,
      error: RateLimited
    })
      .middleware(Authenticated)
      // Registering a credential adds a way into the account, so the decision is
      // made against the row rather than a snapshot…
      .annotate(AuthoritativeSession, true)
      // …and a session that has not authenticated recently may not make it.
      .annotate(RequireAssurance, freshSession)
      .annotateMerge(
        OpenApi.annotations({
          summary: "Begin registering a passkey",
          description:
            "Answers the PublicKeyCredentialCreationOptions to hand navigator.credentials.create, and sets the single-use ceremony cookie __Host-effect_auth.passkey. excludeCredentials lists the caller's existing credentials so the browser refuses to enrol the same authenticator twice. Requires a session that authenticated within the deployment's session.freshAge."
        })
      ),
    HttpApiEndpoint.post("registerVerify", "/register/verify", {
      payload: RegisterVerifyPayload,
      success: PasskeySummary,
      error: [ChallengeExpired, PasskeyVerificationFailed, RateLimited]
    })
      .middleware(Authenticated)
      .annotate(AuthoritativeSession, true)
      .annotate(RequireAssurance, freshSession)
      .annotateMerge(
        OpenApi.annotations({
          summary: "Finish registering a passkey",
          description:
            "Claims the ceremony cookie, checks the attestation against the deployment's configured rpId and origins, and stores the credential. The challenge is spent whichever way this goes. PasskeyVerificationFailed covers a bad attestation, a ceremony minted for somebody else, and a credential id already registered — the three are one answer on purpose."
        })
      ),
    HttpApiEndpoint.post("authenticateOptions", "/authenticate/options", {
      payload: AuthenticateOptionsPayload,
      success: AuthenticationOptions,
      error: [OriginNotAllowed, RateLimited]
    }).annotateMerge(
      OpenApi.annotations({
        summary: "Begin signing in with a passkey",
        description:
          "Answers the PublicKeyCredentialRequestOptions to hand navigator.credentials.get, and sets the single-use ceremony cookie. With no email the list is empty and the browser offers whatever discoverable credential it holds, which is the flow to prefer. With an email that has no account the list is decoy descriptors derived from the address, so the answer is indistinguishable from a real one. Unauthenticated, and guarded by an Origin/Referer check."
      })
    ),
    HttpApiEndpoint.post("authenticateVerify", "/authenticate/verify", {
      payload: AuthenticateVerifyPayload,
      success: [SessionWithUser, MfaRequired],
      error: [ChallengeExpired, PasskeyVerificationFailed, PolicyRefused, RateLimited]
    }).annotateMerge(
      OpenApi.annotations({
        summary: "Finish signing in with a passkey",
        description:
          "Claims the ceremony cookie, verifies the assertion, and either signs the caller in or — when the ceremony was minted by that same person's own live session — raises that session's assurance in place, keeping its id and rotating its token. A UV=1 ceremony reaches aal2 in one step. 202 MfaRequired when a factor plugin still owes something; that response sets the pending cookie and never a session cookie."
      })
    ),
    HttpApiEndpoint.get("listPasskeys", "/", {
      success: PasskeySummaries
    })
      .middleware(Authenticated)
      .annotateMerge(
        OpenApi.annotations({
          summary: "List the caller's passkeys",
          description: "Oldest first. Carries no credential id and no public key."
        })
      ),
    HttpApiEndpoint.post("renamePasskey", "/rename", {
      payload: RenamePasskeyPayload,
      success: PasskeySummary,
      error: NotFound
    })
      .middleware(Authenticated)
      .annotate(AuthoritativeSession, true)
      .annotateMerge(
        OpenApi.annotations({
          summary: "Rename one of the caller's passkeys",
          description:
            "Ownership is enforced inside the statement, so a credential belonging to somebody else is NotFound rather than a refusal — it is not the caller's to know about."
        })
      ),
    HttpApiEndpoint.post("deletePasskey", "/delete", {
      payload: DeletePasskeyPayload,
      success: Ok,
      error: [NotFound, CannotRemoveLastAuthenticator]
    })
      .middleware(Authenticated)
      .annotate(AuthoritativeSession, true)
      // Removing a factor is how an attacker makes a session takeover permanent.
      .annotate(RequireAssurance, freshSession)
      .annotateMerge(
        OpenApi.annotations({
          summary: "Remove one of the caller's passkeys",
          description:
            "Ownership is enforced inside the statement. Requires a session that authenticated within the deployment's session.freshAge. Refuses CannotRemoveLastAuthenticator when this credential is the account's only way in, which is the mirror of the guard on unlinking the last account."
        })
      )
  )
  .prefix(passkeysPrefix)
  .annotateMerge(
    OpenApi.annotations({
      title: "Passkeys",
      description: "WebAuthn credentials: registration, sign-in, step-up and management."
    })
  ) {}

/**
 * The passkey endpoints as a standalone `HttpApi`.
 *
 * **When to use**
 *
 * As the client's declaration — `PasskeysClient.make` builds against this — and
 * as a compact way to serve the plugin on its own. An application that composes
 * its own API adds the *group* to it instead:
 *
 * **Example**
 *
 * ```ts skip-type-checking
 * import { HttpApi } from "effect/unstable/httpapi"
 * import { AuthApi } from "effect-auth"
 * import { PasskeysApiGroup } from "effect-auth/passkeys"
 *
 * const AppApi = HttpApi.make("app").addHttpApi(AuthApi).add(PasskeysApiGroup)
 * ```
 *
 * @category models
 * @since 0.2.0
 */
export const PasskeysApi = HttpApi.make("effect-auth-passkeys").add(PasskeysApiGroup)
