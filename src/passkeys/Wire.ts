/**
 * The WebAuthn ceremony JSON, as schemas.
 *
 * **Details**
 *
 * These are the four shapes that cross the wire between a browser's
 * `navigator.credentials` and this library: the two option documents the server
 * produces, and the two responses the authenticator produces. They are written
 * as `effect` schemas rather than borrowed from the optional dependency's
 * TypeScript types for three reasons — the OpenAPI document has to describe
 * them, the request bodies have to be *bounded* before anything parses them,
 * and `effect-auth` owns its own wire whether or not
 * `@simplewebauthn/server` is installed.
 *
 * This module is browser-safe and dependency-free: `Api.ts`, the client, the
 * `WebAuthn` seam and the test authenticator all import it.
 *
 * **Gotchas**
 *
 * Every binary field is a base64url string, which is what
 * `PublicKeyCredential.toJSON()` and `@simplewebauthn/browser` both produce.
 * Nothing here is decoded by this module — the bounds are a size limit, not a
 * validation — because the only thing entitled to interpret authenticator bytes
 * is the verifier behind {@link WebAuthn}.
 *
 * Unknown members are dropped rather than refused: `clientExtensionResults` in
 * particular is browser-controlled, open-ended and not consulted by this
 * library, so accepting and discarding it is the honest treatment. A ceremony
 * this library did not ask for an extension in is not one whose extension
 * output it will act on.
 *
 * @since 0.2.0
 */
import { Schema } from "effect"

// -----------------------------------------------------------------------------
// Bounds
// -----------------------------------------------------------------------------

const bounded = (maxLength: number) =>
  Schema.String.pipe(Schema.check(Schema.isMinLength(1), Schema.isMaxLength(maxLength)))

/**
 * The longest credential id this library will store or accept.
 *
 * **Details**
 *
 * WebAuthn L3 §6.5.1 bounds a credential id at 1023 *bytes*; base64url of that
 * is 1364 characters. The column is `varchar(1024)`, and this bound is the
 * column's, so a credential that could not be stored is refused at the edge
 * rather than by a driver error halfway through a ceremony. Every authenticator
 * in the field emits 16–64 bytes.
 *
 * @category constructors
 * @since 0.2.0
 */
export const maxCredentialIdLength = 1024

/** The bound on the collected client data, which is a small JSON document. */
const maxClientDataLength = 4096

/** The bound on an attestation object. `none` attestation is a few hundred bytes. */
const maxAttestationLength = 32768

/** The bound on authenticator data and on a signature. */
const maxAuthenticatorDataLength = 8192

// -----------------------------------------------------------------------------
// Enumerations
// -----------------------------------------------------------------------------

/**
 * How a credential travels to the authenticator, as the browser reports it.
 *
 * **Gotchas**
 *
 * A closed set on purpose, even though WebAuthn's registry grows: an unknown
 * transport is a hint this library would store and hand back to a browser that
 * did not ask for it. A response naming one is refused, which costs a
 * registration on an authenticator this library has not been taught about and
 * is the safe direction.
 *
 * @category models
 * @since 0.2.0
 */
export const AuthenticatorTransport: Schema.Literals<
  ["ble", "cable", "hybrid", "internal", "nfc", "smart-card", "usb"]
> = Schema.Literals(["ble", "cable", "hybrid", "internal", "nfc", "smart-card", "usb"])

/**
 * The type of an {@link AuthenticatorTransport}.
 *
 * @category models
 * @since 0.2.0
 */
export type AuthenticatorTransport = typeof AuthenticatorTransport.Type

/**
 * The transports of one credential.
 *
 * **Gotchas**
 *
 * No length bound on the schema, and none is needed: the element schema is a
 * closed set of seven literals and the store deduplicates before it writes, so
 * a client repeating `"usb"` ten thousand times stores one entry.
 *
 * @category models
 * @since 0.2.0
 */
export const AuthenticatorTransports: Schema.$Array<typeof AuthenticatorTransport> =
  Schema.Array(AuthenticatorTransport)

/**
 * {@link AuthenticatorTransports} as the plugin's table stores them: a JSON
 * array in a `text` column, the `accounts.scope` precedent.
 *
 * @category models
 * @since 0.2.0
 */
export const AuthenticatorTransportsJson: Schema.fromJsonString<typeof AuthenticatorTransports> =
  Schema.fromJsonString(AuthenticatorTransports)

/**
 * Whether the authenticator has to verify the *person*, not merely their
 * possession of it.
 *
 * @category models
 * @since 0.2.0
 */
export const UserVerificationRequirement: Schema.Literals<["required", "preferred", "discouraged"]> = Schema.Literals([
  "required",
  "preferred",
  "discouraged"
])

/**
 * The type of a {@link UserVerificationRequirement}.
 *
 * @category models
 * @since 0.2.0
 */
export type UserVerificationRequirement = typeof UserVerificationRequirement.Type

/**
 * Whether the credential has to be discoverable — resident on the
 * authenticator, so that a sign-in needs no username first.
 *
 * @category models
 * @since 0.2.0
 */
export const ResidentKeyRequirement: Schema.Literals<["required", "preferred", "discouraged"]> = Schema.Literals([
  "required",
  "preferred",
  "discouraged"
])

/**
 * The type of a {@link ResidentKeyRequirement}.
 *
 * @category models
 * @since 0.2.0
 */
export type ResidentKeyRequirement = typeof ResidentKeyRequirement.Type

/**
 * Where the authenticator lives: on this device, or on something the person
 * carries.
 *
 * @category models
 * @since 0.2.0
 */
export const AuthenticatorAttachment: Schema.Literals<["platform", "cross-platform"]> = Schema.Literals([
  "platform",
  "cross-platform"
])

/**
 * The type of an {@link AuthenticatorAttachment}.
 *
 * @category models
 * @since 0.2.0
 */
export type AuthenticatorAttachment = typeof AuthenticatorAttachment.Type

// -----------------------------------------------------------------------------
// Descriptors
// -----------------------------------------------------------------------------

/**
 * One credential named to a browser — in `excludeCredentials` on registration,
 * in `allowCredentials` on authentication.
 *
 * @category models
 * @since 0.2.0
 */
export const CredentialDescriptor = Schema.Struct({
  id: bounded(maxCredentialIdLength),
  type: Schema.Literal("public-key"),
  transports: Schema.optionalKey(AuthenticatorTransports)
})

/**
 * The type of a {@link CredentialDescriptor}.
 *
 * @category models
 * @since 0.2.0
 */
export type CredentialDescriptor = typeof CredentialDescriptor.Type

// -----------------------------------------------------------------------------
// Options documents
// -----------------------------------------------------------------------------

/**
 * What `navigator.credentials.create()` is called with — the
 * `PublicKeyCredentialCreationOptionsJSON` of WebAuthn L3, as this library
 * emits it.
 *
 * **Gotchas**
 *
 * `user.id` is the per-user WebAuthn handle, never the user id: the handle is
 * random, opaque and specific to this deployment, and a database key is not
 * opaque in the privacy sense — an authenticator syncs it and a relying party
 * that ever sees it learns a stable identifier.
 *
 * @category models
 * @since 0.2.0
 */
export const RegistrationOptions = Schema.Struct({
  rp: Schema.Struct({ id: Schema.String, name: Schema.String }),
  user: Schema.Struct({ id: Schema.String, name: Schema.String, displayName: Schema.String }),
  challenge: Schema.String,
  pubKeyCredParams: Schema.Array(Schema.Struct({ type: Schema.Literal("public-key"), alg: Schema.Finite })),
  timeout: Schema.Finite,
  excludeCredentials: Schema.Array(CredentialDescriptor),
  authenticatorSelection: Schema.Struct({
    residentKey: ResidentKeyRequirement,
    requireResidentKey: Schema.Boolean,
    userVerification: UserVerificationRequirement,
    authenticatorAttachment: Schema.optionalKey(AuthenticatorAttachment)
  }),
  attestation: Schema.Literal("none")
})

/**
 * The type of a {@link RegistrationOptions}.
 *
 * @category models
 * @since 0.2.0
 */
export type RegistrationOptions = typeof RegistrationOptions.Type

/**
 * What `navigator.credentials.get()` is called with — the
 * `PublicKeyCredentialRequestOptionsJSON` of WebAuthn L3.
 *
 * **Gotchas**
 *
 * `allowCredentials` is empty for a discoverable sign-in and *plausible* for an
 * address this deployment has never seen: the dummy descriptors are derived
 * from the address by HMAC, so the shape of the answer is the same either way.
 * See `Passkeys.authenticationOptions`.
 *
 * @category models
 * @since 0.2.0
 */
export const AuthenticationOptions = Schema.Struct({
  challenge: Schema.String,
  timeout: Schema.Finite,
  rpId: Schema.String,
  allowCredentials: Schema.Array(CredentialDescriptor),
  userVerification: UserVerificationRequirement
})

/**
 * The type of an {@link AuthenticationOptions}.
 *
 * @category models
 * @since 0.2.0
 */
export type AuthenticationOptions = typeof AuthenticationOptions.Type

// -----------------------------------------------------------------------------
// Authenticator responses
// -----------------------------------------------------------------------------

/**
 * What `navigator.credentials.create()` resolved to, serialized.
 *
 * @category models
 * @since 0.2.0
 */
export const RegistrationResponse = Schema.Struct({
  id: bounded(maxCredentialIdLength),
  rawId: bounded(maxCredentialIdLength),
  type: Schema.Literal("public-key"),
  authenticatorAttachment: Schema.optionalKey(AuthenticatorAttachment),
  response: Schema.Struct({
    clientDataJSON: bounded(maxClientDataLength),
    attestationObject: bounded(maxAttestationLength),
    transports: Schema.optionalKey(AuthenticatorTransports)
  })
})

/**
 * The type of a {@link RegistrationResponse}.
 *
 * @category models
 * @since 0.2.0
 */
export type RegistrationResponse = typeof RegistrationResponse.Type

/**
 * What `navigator.credentials.get()` resolved to, serialized.
 *
 * **Gotchas**
 *
 * `userHandle` is present exactly when the credential was discoverable, and it
 * is the one field a discoverable sign-in is *identified* by — which is why
 * `Passkeys.verifyAuthentication` refuses a response whose handle is not the
 * one this deployment issued for the credential's owner.
 *
 * @category models
 * @since 0.2.0
 */
export const AuthenticationResponse = Schema.Struct({
  id: bounded(maxCredentialIdLength),
  rawId: bounded(maxCredentialIdLength),
  type: Schema.Literal("public-key"),
  authenticatorAttachment: Schema.optionalKey(AuthenticatorAttachment),
  response: Schema.Struct({
    clientDataJSON: bounded(maxClientDataLength),
    authenticatorData: bounded(maxAuthenticatorDataLength),
    signature: bounded(maxAuthenticatorDataLength),
    userHandle: Schema.optionalKey(bounded(maxCredentialIdLength))
  })
})

/**
 * The type of an {@link AuthenticationResponse}.
 *
 * @category models
 * @since 0.2.0
 */
export type AuthenticationResponse = typeof AuthenticationResponse.Type
