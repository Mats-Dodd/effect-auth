/**
 * The browser half of a WebAuthn ceremony, behind a service.
 *
 * **Details**
 *
 * `navigator.credentials.create` and `.get` are the two calls a passkey flow
 * cannot avoid, and they are also the two things a test cannot run. So they are
 * a `Context.Service` with one browser implementation ({@link layerBrowser}) and
 * an interface small enough that a test — or a React Native shim, or a
 * `@simplewebauthn/browser` wrapper — can implement it in a dozen lines.
 *
 * The conversion between the wire's base64url and the DOM's `ArrayBuffer`s
 * happens here and nowhere else. It is written out rather than delegated to
 * `PublicKeyCredential.parseCreationOptionsFromJSON`, which is still missing on
 * enough shipped browsers that a library depending on it would fail on them.
 *
 * **Gotchas**
 *
 * Everything a browser can refuse is one {@link WebAuthnClientError} with a
 * `reason`: `"Unsupported"` when there is no WebAuthn at all, `"Cancelled"`
 * when the person dismissed the prompt or the ceremony was aborted, and
 * `"Failed"` for everything else. The distinction matters to a UI — a
 * cancellation is not an error to show — and it is entirely client-side, so
 * nothing here can leak anything about an account.
 *
 * @since 0.2.0
 */
import { Context, Effect, Encoding, Layer, Result, Schema } from "effect"
import type {
  AuthenticationOptions,
  AuthenticationResponse,
  AuthenticatorAttachment,
  AuthenticatorTransport,
  RegistrationOptions,
  RegistrationResponse
} from "../../passkeys/Wire.js"

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/**
 * Why a browser did not produce a credential.
 *
 * @category models
 * @since 0.2.0
 */
export const WebAuthnClientFailure: Schema.Literals<["Unsupported", "Cancelled", "Failed"]> = Schema.Literals([
  /** This runtime has no WebAuthn, or no platform authenticator for it. */
  "Unsupported",
  /** The person dismissed the prompt, or the ceremony was aborted. */
  "Cancelled",
  /** Anything else the browser said. */
  "Failed"
])

/**
 * The type of a {@link WebAuthnClientFailure}.
 *
 * @category models
 * @since 0.2.0
 */
export type WebAuthnClientFailure = typeof WebAuthnClientFailure.Type

/**
 * The browser did not produce a credential.
 *
 * **Gotchas**
 *
 * Client-side only. It never crosses the network and it never carries anything
 * the browser said about an account, because the browser was never told about
 * one.
 *
 * @category errors
 * @since 0.2.0
 */
export class WebAuthnClientError extends Schema.TaggedError<WebAuthnClientError>(
  "effect-auth/passkeys/WebAuthnClientError"
)("WebAuthnClientError", {
  reason: WebAuthnClientFailure
}) {}

// -----------------------------------------------------------------------------
// Service
// -----------------------------------------------------------------------------

/**
 * How a passkey ceremony asks the browser to do its half.
 *
 * @category models
 * @since 0.2.0
 */
export interface WebAuthnClientService {
  /** Whether this runtime can do WebAuthn at all. */
  readonly isSupported: Effect.Effect<boolean>

  /**
   * Whether the browser will offer a passkey from an autofill dropdown.
   *
   * **When to use**
   *
   * Before starting a conditional-UI ceremony. A browser that answers `false`
   * would simply never resolve it.
   */
  readonly isConditionalMediationAvailable: Effect.Effect<boolean>

  /** `navigator.credentials.create`, in the wire's own shapes. */
  readonly create: (
    options: RegistrationOptions,
    signal?: AbortSignal
  ) => Effect.Effect<RegistrationResponse, WebAuthnClientError>

  /**
   * `navigator.credentials.get`, in the wire's own shapes.
   *
   * `mediation: "conditional"` is the autofill flow: the browser offers a
   * passkey from the username field rather than opening a modal, and the promise
   * stays pending until the person picks one.
   */
  readonly get: (
    options: AuthenticationOptions,
    request?: { readonly mediation?: CredentialMediationRequirement | undefined; readonly signal?: AbortSignal }
  ) => Effect.Effect<AuthenticationResponse, WebAuthnClientError>
}

/**
 * The browser's half of a WebAuthn ceremony. See {@link WebAuthnClientService}.
 *
 * @category services
 * @since 0.2.0
 */
export class WebAuthnClient extends Context.Service<WebAuthnClient, WebAuthnClientService>()(
  "effect-auth/client/internal/webauthn/WebAuthnClient"
) {}

// -----------------------------------------------------------------------------
// Conversions
// -----------------------------------------------------------------------------

const transports: ReadonlyArray<AuthenticatorTransport> = [
  "ble",
  "cable",
  "hybrid",
  "internal",
  "nfc",
  "smart-card",
  "usb"
]

const isTransport = (value: string): value is AuthenticatorTransport => transports.some((known) => known === value)

const attachments: ReadonlyArray<AuthenticatorAttachment> = ["platform", "cross-platform"]

const isAttachment = (value: string): value is AuthenticatorAttachment => attachments.some((known) => known === value)

const failed = (reason: WebAuthnClientFailure) => WebAuthnClientError.make({ reason })

/**
 * Base64url in, bytes out. A value this deployment's own server produced, so a
 * malformed one is a bug rather than something a person can act on.
 */
const bytes = (value: string): Effect.Effect<Uint8Array<ArrayBuffer>, WebAuthnClientError> => {
  const decoded = Encoding.decodeBase64Url(value)
  // Copied into a fresh buffer: `BufferSource` is the `ArrayBuffer`-backed
  // form, and a copy is how that is reached without an assertion.
  return Result.isFailure(decoded) ? Effect.fail(failed("Failed")) : Effect.succeed(new Uint8Array(decoded.success))
}

/**
 * The transports the DOM's own descriptor type admits, intersected with what
 * the server recorded.
 *
 * The two sets are not the same — WebAuthn's registry grows faster than
 * `lib.dom` does — and a hint the browser has never heard of is a hint it would
 * refuse the whole descriptor over. Written as a filter of the *known* list so
 * that neither side needs an assertion.
 */
const domTransports = (
  values: ReadonlyArray<AuthenticatorTransport>
): NonNullable<PublicKeyCredentialDescriptor["transports"]> => {
  const known: NonNullable<PublicKeyCredentialDescriptor["transports"]> = ["ble", "hybrid", "internal", "nfc", "usb"]
  return known.filter((transport) => values.some((value) => value === transport))
}

const base64Url = (buffer: ArrayBuffer): string => Encoding.encodeBase64Url(new Uint8Array(buffer))

/**
 * What the browser said, classified. `NotAllowedError` is what every browser
 * raises for a dismissed prompt, an aborted ceremony and a timeout alike;
 * `AbortError` for an explicit abort.
 */
const classify = (cause: unknown): WebAuthnClientFailure => {
  if (cause instanceof globalThis.DOMException) {
    return cause.name === "NotAllowedError" || cause.name === "AbortError" ? "Cancelled" : "Failed"
  }
  return "Failed"
}

const credentials = (): Effect.Effect<CredentialsContainer, WebAuthnClientError> =>
  typeof globalThis.navigator === "undefined" ||
  globalThis.navigator.credentials === undefined ||
  typeof globalThis.PublicKeyCredential === "undefined"
    ? Effect.fail(failed("Unsupported"))
    : Effect.succeed(globalThis.navigator.credentials)

// -----------------------------------------------------------------------------
// The browser implementation
// -----------------------------------------------------------------------------

/**
 * A {@link WebAuthnClientService} over `navigator.credentials`.
 *
 * **When to use**
 *
 * As a plain value, which is what `PasskeysClient.make` defaults to: a client
 * built in a page has nowhere to provide a layer, and a test replaces it by
 * passing its own implementation rather than by composing one.
 * {@link layerBrowser} is the same value behind the service key, for a program
 * that would rather compose.
 *
 * @category constructors
 * @since 0.2.0
 */
export const browser: WebAuthnClientService = WebAuthnClient.of({
  isSupported: Effect.sync(
    () =>
      typeof globalThis.navigator !== "undefined" &&
      globalThis.navigator.credentials !== undefined &&
      typeof globalThis.PublicKeyCredential !== "undefined"
  ),

  isConditionalMediationAvailable: Effect.orElseSucceed(
    Effect.flatMap(credentials(), () =>
      Effect.promise(() =>
        globalThis.PublicKeyCredential.isConditionalMediationAvailable === undefined
          ? Promise.resolve(false)
          : globalThis.PublicKeyCredential.isConditionalMediationAvailable()
      )
    ),
    () => false
  ),

  create: (options, signal) =>
    Effect.gen(function* () {
      const container = yield* credentials()
      const challenge = yield* bytes(options.challenge)
      const userId = yield* bytes(options.user.id)
      const exclude = yield* Effect.forEach(options.excludeCredentials, (descriptor) =>
        Effect.map(bytes(descriptor.id), (id) => ({
          id,
          type: "public-key" as const,
          ...(descriptor.transports === undefined ? {} : { transports: domTransports(descriptor.transports) })
        }))
      )

      const credential = yield* Effect.tryPromise({
        try: () =>
          container.create({
            ...(signal === undefined ? {} : { signal }),
            publicKey: {
              rp: options.rp,
              user: { id: userId, name: options.user.name, displayName: options.user.displayName },
              challenge,
              pubKeyCredParams: options.pubKeyCredParams.map((param) => ({ type: param.type, alg: param.alg })),
              timeout: options.timeout,
              excludeCredentials: exclude,
              authenticatorSelection: { ...options.authenticatorSelection },
              attestation: options.attestation
            }
          }),
        catch: (cause) => failed(classify(cause))
      })

      if (
        !(credential instanceof globalThis.PublicKeyCredential) ||
        !(credential.response instanceof globalThis.AuthenticatorAttestationResponse)
      ) {
        return yield* failed("Failed")
      }
      const response = credential.response
      const reported = typeof response.getTransports === "function" ? response.getTransports().filter(isTransport) : []
      const attachment = credential.authenticatorAttachment
      return {
        id: credential.id,
        rawId: base64Url(credential.rawId),
        type: "public-key" as const,
        ...(attachment !== null && isAttachment(attachment) ? { authenticatorAttachment: attachment } : {}),
        response: {
          clientDataJSON: base64Url(response.clientDataJSON),
          attestationObject: base64Url(response.attestationObject),
          ...(reported.length === 0 ? {} : { transports: reported })
        }
      } satisfies RegistrationResponse
    }),

  get: (options, request) =>
    Effect.gen(function* () {
      const container = yield* credentials()
      const challenge = yield* bytes(options.challenge)
      const allow = yield* Effect.forEach(options.allowCredentials, (descriptor) =>
        Effect.map(bytes(descriptor.id), (id) => ({
          id,
          type: "public-key" as const,
          ...(descriptor.transports === undefined ? {} : { transports: domTransports(descriptor.transports) })
        }))
      )

      const credential = yield* Effect.tryPromise({
        try: () =>
          container.get({
            ...(request?.mediation === undefined ? {} : { mediation: request.mediation }),
            ...(request?.signal === undefined ? {} : { signal: request.signal }),
            publicKey: {
              challenge,
              timeout: options.timeout,
              rpId: options.rpId,
              allowCredentials: allow,
              userVerification: options.userVerification
            }
          }),
        catch: (cause) => failed(classify(cause))
      })

      if (
        !(credential instanceof globalThis.PublicKeyCredential) ||
        !(credential.response instanceof globalThis.AuthenticatorAssertionResponse)
      ) {
        return yield* failed("Failed")
      }
      const response = credential.response
      const attachment = credential.authenticatorAttachment
      return {
        id: credential.id,
        rawId: base64Url(credential.rawId),
        type: "public-key" as const,
        ...(attachment !== null && isAttachment(attachment) ? { authenticatorAttachment: attachment } : {}),
        response: {
          clientDataJSON: base64Url(response.clientDataJSON),
          authenticatorData: base64Url(response.authenticatorData),
          signature: base64Url(response.signature),
          ...(response.userHandle === null ? {} : { userHandle: base64Url(response.userHandle) })
        }
      } satisfies AuthenticationResponse
    })
})

/**
 * {@link browser}, as an `Effect`.
 *
 * @category constructors
 * @since 0.2.0
 */
export const makeBrowser: Effect.Effect<WebAuthnClientService> = Effect.succeed(browser)

/**
 * Provides {@link WebAuthnClient} over the ambient `navigator.credentials`.
 *
 * **Gotchas**
 *
 * Safe to build outside a browser: nothing is touched until a ceremony runs, and
 * one that runs there fails `Unsupported` rather than throwing on a missing
 * global. That is what lets a server-rendered page hold the client.
 *
 * @category layers
 * @since 0.2.0
 */
export const layerBrowser: Layer.Layer<WebAuthnClient> = Layer.succeed(WebAuthnClient)(browser)
