/**
 * The WebAuthn ceremony seam: four operations, owned by `effect-auth`,
 * implemented by whatever verifier a deployment installs.
 *
 * **Details**
 *
 * Verifying a WebAuthn assertion is bounds-checked CBOR, `authData` parsing,
 * COSE-to-JWK for three key types, DER-to-raw ECDSA, and a ceremony-validation
 * checklist that WebAuthn L3 keeps extending. It is five to nine hundred lines
 * of security-critical parsing that cannot be tested without a fixture corpus
 * this project cannot mint. So it is delegated — to `@simplewebauthn/server`, an
 * **optional peer dependency**, loaded by {@link layerSimple} and by nothing
 * else, so that installing `effect-auth` without passkeys still installs one
 * runtime dependency.
 *
 * What is *not* delegated is the policy. Which origins count, which RP id, which
 * algorithms, whether user verification is required, which credential belongs to
 * whom, and what a counter regression means are all decided in `Passkeys.ts` and
 * handed to this seam as arguments. That division is the reason the seam exists:
 * a different verifier changes the parsing and changes none of the rules.
 *
 * **Gotchas**
 *
 * Every failure of a verify is one {@link PasskeyVerificationFailed}. The
 * underlying library distinguishes a dozen — bad signature, wrong origin, wrong
 * type, absent user-presence bit, unsupported algorithm — and telling them apart
 * would tell an unauthenticated caller which of their guesses was closest. The
 * cause is kept for logs by the failure itself and never reaches the caller.
 *
 * The dependency is imported once, when {@link layerSimple} is built, not once
 * per request: a deployment either has it or does not, and a missing optional
 * peer dependency should stop the process from starting rather than turn every
 * ceremony into a `500`. That is why the layer has an error channel.
 *
 * @since 0.2.0
 */
import { Context, Effect, Layer, Schema } from "effect"
import { annotateAuthLogs } from "../internal/effects.js"
import { PasskeyVerificationFailed } from "./Errors.js"
import type {
  AuthenticationOptions,
  AuthenticationResponse,
  AuthenticatorAttachment,
  AuthenticatorTransport,
  CredentialDescriptor,
  RegistrationOptions,
  RegistrationResponse,
  ResidentKeyRequirement,
  UserVerificationRequirement
} from "./Wire.js"

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/**
 * The verifier this deployment asked for could not be loaded.
 *
 * **Details**
 *
 * A start-up failure, in the shape `DiscoveryError` already has: it is raised
 * while {@link layerSimple} is being built, so a deployment that composed the
 * passkeys plugin without installing `@simplewebauthn/server` fails to boot
 * rather than serving endpoints that answer `500`. It reaches no endpoint's
 * error union.
 *
 * @category errors
 * @since 0.2.0
 */
export class WebAuthnUnavailable extends Schema.TaggedError<WebAuthnUnavailable>("effect-auth/WebAuthnUnavailable")(
  "WebAuthnUnavailable",
  {
    cause: Schema.optional(Schema.Defect())
  },
  {
    description: "The WebAuthn verifier could not be loaded; install @simplewebauthn/server",
    httpApiStatus: 500
  }
) {}

// -----------------------------------------------------------------------------
// Requests
// -----------------------------------------------------------------------------

/**
 * Everything a registration ceremony's option document is built from.
 *
 * **Gotchas**
 *
 * `challenge` is supplied rather than generated. The server has to remember what
 * it asked for, and the row that remembers it is written before the document is
 * handed out — so the challenge is minted by `Passkeys`, not here.
 *
 * @category models
 * @since 0.2.0
 */
export interface RegistrationRequest {
  readonly rpId: string
  readonly rpName: string
  /** The user's opaque WebAuthn handle, base64url. Never their user id. */
  readonly userHandle: string
  readonly userName: string
  readonly userDisplayName: string
  /** Base64url, minted by the caller. */
  readonly challenge: string
  /** Milliseconds. */
  readonly timeout: number
  /** Credentials this person already registered, so the browser refuses a duplicate. */
  readonly excludeCredentials: ReadonlyArray<CredentialDescriptor>
  readonly userVerification: UserVerificationRequirement
  readonly residentKey: ResidentKeyRequirement
  /** COSE algorithm identifiers, most preferred first. */
  readonly algorithms: ReadonlyArray<number>
  readonly authenticatorAttachment?: AuthenticatorAttachment | undefined
}

/**
 * Everything an authentication ceremony's option document is built from.
 *
 * @category models
 * @since 0.2.0
 */
export interface AuthenticationRequest {
  readonly rpId: string
  /** Base64url, minted by the caller. */
  readonly challenge: string
  /** Milliseconds. */
  readonly timeout: number
  /** Empty for a discoverable sign-in. */
  readonly allowCredentials: ReadonlyArray<CredentialDescriptor>
  readonly userVerification: UserVerificationRequirement
}

/**
 * What the verifier is asked to check about an attestation.
 *
 * @category models
 * @since 0.2.0
 */
export interface VerifyRegistrationRequest {
  readonly response: RegistrationResponse
  /** The challenge the ceremony was minted with, base64url. */
  readonly challenge: string
  readonly rpId: string
  /** Every origin this deployment serves. Configured, never read off a header. */
  readonly origins: ReadonlyArray<string>
  readonly requireUserVerification: boolean
  readonly algorithms: ReadonlyArray<number>
}

/**
 * The stored half of an authentication check: what this library already knows
 * about the credential being presented.
 *
 * @category models
 * @since 0.2.0
 */
export interface StoredCredential {
  readonly credentialId: string
  readonly publicKey: Uint8Array
  readonly signCount: number
  readonly transports: ReadonlyArray<AuthenticatorTransport>
}

/**
 * What the verifier is asked to check about an assertion.
 *
 * @category models
 * @since 0.2.0
 */
export interface VerifyAuthenticationRequest {
  readonly response: AuthenticationResponse
  readonly challenge: string
  readonly rpId: string
  readonly origins: ReadonlyArray<string>
  readonly requireUserVerification: boolean
  readonly credential: StoredCredential
}

// -----------------------------------------------------------------------------
// Results
// -----------------------------------------------------------------------------

/**
 * What a verified attestation established.
 *
 * **Gotchas**
 *
 * `userVerified` is the authenticator's own UV bit as it came back, never the
 * `userVerification` the request asked for. It is the whole of what makes a
 * passkey a multi-factor ceremony, so it is read off the evidence and nothing
 * else — see `Assurance.deriveAal`.
 *
 * @category models
 * @since 0.2.0
 */
export interface RegistrationVerification {
  readonly credentialId: string
  readonly publicKey: Uint8Array
  readonly signCount: number
  readonly transports: ReadonlyArray<AuthenticatorTransport>
  readonly aaguid: string
  readonly backupEligible: boolean
  readonly backedUp: boolean
  readonly userVerified: boolean
}

/**
 * What a verified assertion established.
 *
 * @category models
 * @since 0.2.0
 */
export interface AuthenticationVerification {
  readonly signCount: number
  readonly userVerified: boolean
  readonly backedUp: boolean
}

// -----------------------------------------------------------------------------
// Service
// -----------------------------------------------------------------------------

/**
 * The {@link WebAuthn} service definition.
 *
 * @category models
 * @since 0.2.0
 */
export interface WebAuthnService {
  /** Builds the document `navigator.credentials.create()` is called with. */
  readonly generateRegistrationOptions: (request: RegistrationRequest) => Effect.Effect<RegistrationOptions>

  /** Checks an attestation, or fails. */
  readonly verifyRegistration: (
    request: VerifyRegistrationRequest
  ) => Effect.Effect<RegistrationVerification, PasskeyVerificationFailed>

  /** Builds the document `navigator.credentials.get()` is called with. */
  readonly generateAuthenticationOptions: (request: AuthenticationRequest) => Effect.Effect<AuthenticationOptions>

  /** Checks an assertion against a stored credential, or fails. */
  readonly verifyAuthentication: (
    request: VerifyAuthenticationRequest
  ) => Effect.Effect<AuthenticationVerification, PasskeyVerificationFailed>
}

/**
 * Builds and checks WebAuthn ceremonies. See {@link WebAuthnService}.
 *
 * @category services
 * @since 0.2.0
 */
export class WebAuthn extends Context.Service<WebAuthn, WebAuthnService>()("effect-auth/passkeys/WebAuthn") {}

// -----------------------------------------------------------------------------
// The @simplewebauthn/server implementation
// -----------------------------------------------------------------------------

/**
 * What the verifier said, on its way to being forgotten.
 *
 * Not exported and never on the wire: it exists so the rejection travels as a
 * *typed* failure between the `tryPromise` and {@link refuse}, which is where
 * the cause is logged and dropped. The caller sees
 * {@link PasskeyVerificationFailed} and nothing else.
 */
class VerifierRejected extends Schema.TaggedError<VerifierRejected>("effect-auth/passkeys/VerifierRejected")(
  "VerifierRejected",
  { cause: Schema.optional(Schema.Defect()) }
) {}

/**
 * Every way a verification can fail, collapsed into the one answer — with the
 * verifier's own account of it logged at `Debug` on the way past, because an
 * operator debugging a broken deployment needs what the caller must not be
 * told.
 */
const refuse = <A>(effect: Effect.Effect<A, VerifierRejected>): Effect.Effect<A, PasskeyVerificationFailed> =>
  effect.pipe(
    Effect.tapError((rejected) =>
      annotateAuthLogs(Effect.logDebug("a WebAuthn ceremony did not verify", rejected.cause))
    ),
    Effect.mapError(() => PasskeyVerificationFailed.make())
  )

/** The `pubKeyCredParams` a list of COSE algorithm identifiers spells out. */
const credentialParamsFor = (
  algorithms: ReadonlyArray<number>
): ReadonlyArray<{ readonly type: "public-key"; readonly alg: number }> =>
  algorithms.map((alg) => ({ type: "public-key" as const, alg }))

/** The `authenticatorSelection` a request's preferences spell out. */
const selectionFor = (request: RegistrationRequest) => ({
  residentKey: request.residentKey,
  requireResidentKey: request.residentKey === "required",
  userVerification: request.userVerification,
  ...(request.authenticatorAttachment === undefined ? {} : { authenticatorAttachment: request.authenticatorAttachment })
})

/**
 * Loads `@simplewebauthn/server` and builds a {@link WebAuthnService} over it.
 *
 * **Gotchas**
 *
 * The dynamic `import` is what keeps the dependency optional: nothing in the
 * default entry point mentions the package, and the only module that names it is
 * this one, reached only through `effect-auth/passkeys`.
 *
 * @category constructors
 * @since 0.2.0
 */
export const makeSimple: Effect.Effect<WebAuthnService, WebAuthnUnavailable> = Effect.gen(function* () {
  const webauthn = yield* Effect.tryPromise({
    try: () => import("@simplewebauthn/server"),
    catch: (cause) => WebAuthnUnavailable.make({ cause })
  })

  return WebAuthn.of({
    // Built here rather than delegated. The document is data this library owns
    // end to end: the challenge is minted and stored by `Passkeys` before the
    // document exists, the exclusion list comes out of this deployment's own
    // table, and every other member is configuration. Handing all of that to
    // the dependency only to discard what it answered would be ceremony. What
    // is genuinely hard — bounded CBOR, COSE, signature verification and the
    // ceremony checklist — is what the two verifications below delegate.
    generateRegistrationOptions: (request) =>
      Effect.succeed({
        rp: { id: request.rpId, name: request.rpName },
        // The person's opaque handle, never their user id.
        user: { id: request.userHandle, name: request.userName, displayName: request.userDisplayName },
        challenge: request.challenge,
        pubKeyCredParams: credentialParamsFor(request.algorithms),
        timeout: request.timeout,
        excludeCredentials: request.excludeCredentials,
        authenticatorSelection: selectionFor(request),
        attestation: "none" as const
      }),

    verifyRegistration: (request) =>
      Effect.flatMap(
        refuse(
          Effect.tryPromise({
            try: () =>
              webauthn.verifyRegistrationResponse({
                response: {
                  id: request.response.id,
                  rawId: request.response.rawId,
                  type: request.response.type,
                  // This library asks for no extension, so it acts on none. A
                  // browser's extension output is dropped rather than forwarded.
                  clientExtensionResults: {},
                  ...(request.response.authenticatorAttachment === undefined
                    ? {}
                    : { authenticatorAttachment: request.response.authenticatorAttachment }),
                  response: {
                    clientDataJSON: request.response.response.clientDataJSON,
                    attestationObject: request.response.response.attestationObject,
                    ...(request.response.response.transports === undefined
                      ? {}
                      : { transports: [...request.response.response.transports] })
                  }
                },
                expectedChallenge: request.challenge,
                // Configured origins, never the request's own `Origin` header:
                // an RP origin read off the request is attacker-controlled, and
                // the whole phishing resistance of WebAuthn rests on it.
                expectedOrigin: [...request.origins],
                expectedRPID: request.rpId,
                requireUserPresence: true,
                requireUserVerification: request.requireUserVerification,
                supportedAlgorithmIDs: [...request.algorithms]
              }),
            catch: (cause) => VerifierRejected.make({ cause })
          })
        ),
        (verified): Effect.Effect<RegistrationVerification, PasskeyVerificationFailed> =>
          verified.verified
            ? Effect.succeed({
                credentialId: verified.registrationInfo.credential.id,
                publicKey: verified.registrationInfo.credential.publicKey,
                signCount: verified.registrationInfo.credential.counter,
                transports: verified.registrationInfo.credential.transports ?? [],
                aaguid: verified.registrationInfo.aaguid,
                // `multiDevice` is the backup-eligibility bit of `authData`,
                // named for what it means rather than for where it lives.
                backupEligible: verified.registrationInfo.credentialDeviceType === "multiDevice",
                backedUp: verified.registrationInfo.credentialBackedUp,
                userVerified: verified.registrationInfo.userVerified
              })
            : Effect.fail(PasskeyVerificationFailed.make())
      ),

    generateAuthenticationOptions: (request) =>
      Effect.succeed({
        challenge: request.challenge,
        timeout: request.timeout,
        rpId: request.rpId,
        allowCredentials: request.allowCredentials,
        userVerification: request.userVerification
      }),

    verifyAuthentication: (request) =>
      Effect.flatMap(
        refuse(
          Effect.tryPromise({
            try: () =>
              webauthn.verifyAuthenticationResponse({
                response: {
                  id: request.response.id,
                  rawId: request.response.rawId,
                  type: request.response.type,
                  clientExtensionResults: {},
                  ...(request.response.authenticatorAttachment === undefined
                    ? {}
                    : { authenticatorAttachment: request.response.authenticatorAttachment }),
                  response: {
                    clientDataJSON: request.response.response.clientDataJSON,
                    authenticatorData: request.response.response.authenticatorData,
                    signature: request.response.response.signature,
                    ...(request.response.response.userHandle === undefined
                      ? {}
                      : { userHandle: request.response.response.userHandle })
                  }
                },
                expectedChallenge: request.challenge,
                expectedOrigin: [...request.origins],
                expectedRPID: request.rpId,
                requireUserVerification: request.requireUserVerification,
                credential: {
                  id: request.credential.credentialId,
                  // Copied into a fresh buffer: the dependency's `Uint8Array_`
                  // is the `ArrayBuffer`-backed form, and a copy is how that is
                  // reached without an assertion.
                  publicKey: new Uint8Array(request.credential.publicKey),
                  // Deliberately zero, and this is the one place this
                  // implementation does not simply relay what it was told.
                  // `@simplewebauthn/server` applies a counter policy of its own
                  // — any non-advancing counter is a hard failure — and that
                  // policy is not this library's: a regression is published as
                  // `PasskeyCounterRegression` and refused only when the
                  // deployment asked for it, because a perfectly healthy synced
                  // passkey on a second device looks exactly like a clone. Zero
                  // is how the dependency is told "the counter is not yours to
                  // judge"; `Passkeys.verifyAuthentication` judges it, against
                  // the value actually stored.
                  counter: 0,
                  transports: [...request.credential.transports]
                }
              }),
            catch: (cause) => VerifierRejected.make({ cause })
          })
        ),
        (verified): Effect.Effect<AuthenticationVerification, PasskeyVerificationFailed> =>
          verified.verified
            ? Effect.succeed({
                signCount: verified.authenticationInfo.newCounter,
                userVerified: verified.authenticationInfo.userVerified,
                backedUp: verified.authenticationInfo.credentialBackedUp
              })
            : Effect.fail(PasskeyVerificationFailed.make())
      )
  })
})

/**
 * Provides {@link WebAuthn} over `@simplewebauthn/server`.
 *
 * **When to use**
 *
 * In any deployment serving passkeys, unless it has a verifier of its own.
 *
 * ```ts skip-type-checking
 * import { Layer } from "effect"
 * import { Passkeys, PasskeyStore, WebAuthn } from "effect-auth/passkeys"
 *
 * const PasskeysLive = Passkeys.layer({ rpId: "example.com", origin: "https://example.com" }).pipe(
 *   Layer.provide(WebAuthn.layerSimple),
 *   Layer.provide(PasskeyStore.layer)
 * )
 * ```
 *
 * **Gotchas**
 *
 * `@simplewebauthn/server` must be installed. It is declared as an optional peer
 * dependency, so a deployment that does not serve passkeys never installs it —
 * and one that does gets a build-time failure here rather than a runtime one at
 * the first ceremony.
 *
 * @category layers
 * @since 0.2.0
 */
export const layerSimple: Layer.Layer<WebAuthn, WebAuthnUnavailable> = Layer.effect(WebAuthn, makeSimple)
