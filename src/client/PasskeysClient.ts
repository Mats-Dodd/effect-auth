/**
 * The browser-facing client for the passkeys plugin.
 *
 * **Details**
 *
 * The first client in this package with real logic in it. Every other atom is
 * one request; a passkey ceremony is three steps that must not be separable —
 * ask for options, hand them to `navigator.credentials`, send back what it
 * produced — so {@link PasskeysClient.register} and
 * {@link PasskeysClient.authenticate} are *composite* mutation atoms whose body
 * is one `Effect`. An application writes an argument to the atom and gets a
 * result; there is no intermediate state for it to hold, drop or leak.
 *
 * `authenticate` carries the same `"auth.session"` reactivity key `AuthClient`'s
 * own sign-in does, so an application holding both clients sees its session atom
 * refetch by itself.
 *
 * This module is browser-safe, exactly as `AuthClient` is: it reaches the
 * plugin's `Api.ts` and `Wire.ts` and nothing else of it — no store, no
 * verifier, and never `@simplewebauthn/server`.
 *
 * **Gotchas**
 *
 * A person dismissing the passkey prompt is a {@link WebAuthnClientError} with
 * `reason: "Cancelled"`, and it is not a failure worth showing. Match on it
 * before rendering anything.
 *
 * @since 0.2.0
 */
import type { Layer } from "effect"
import { Effect } from "effect"
import type { HttpClient } from "effect/unstable/http"
import { type AsyncResult, type Atom, AtomHttpApi } from "effect/unstable/reactivity"
import type { NotFound, RateLimited, StepUpRequired, Unauthorized } from "../domain/Errors.js"
import type { PolicyRefused } from "../domain/Hooks.js"
import type { OriginNotAllowed } from "../http/OriginCheck.js"
import type { SessionWithUser } from "../domain/Schema.js"
import type { MfaRequired, Ok } from "../http/AuthApi.js"
import {
  type AuthenticateOptionsPayload,
  type DeletePasskeyPayload,
  PasskeysApi,
  type PasskeysApiGroup,
  type PasskeySummary,
  type RegisterOptionsPayload,
  type RenamePasskeyPayload
} from "../passkeys/Api.js"
import type { CannotRemoveLastAuthenticator, ChallengeExpired, PasskeyVerificationFailed } from "../passkeys/Errors.js"
import { sessionKey, sessionsKey } from "./AuthClient.js"
import { layerFetch, withPayload } from "./Atoms.js"
import type { WebAuthnClientError, WebAuthnClientService } from "./internal/webauthn.js"
import { browser } from "./internal/webauthn.js"

export {
  /**
   * The browser's half of a ceremony, as a service — for a program that would
   * rather compose a layer than pass a value.
   *
   * @since 0.2.0
   */
  browser as browserWebAuthnClient,
  layerBrowser as layerWebAuthnClient,
  makeBrowser as makeWebAuthnClient,
  WebAuthnClient,
  WebAuthnClientError,
  type WebAuthnClientFailure,
  type WebAuthnClientService
} from "./internal/webauthn.js"

/**
 * The reactivity key the passkey list is held under.
 *
 * @category constructors
 * @since 0.2.0
 */
export const passkeysKey = "auth.passkeys"

/**
 * The argument of {@link PasskeysClient.register}.
 *
 * @category models
 * @since 0.2.0
 */
export interface Register extends RegisterOptionsPayload {
  /** What to call the credential in the list. */
  readonly name?: string | undefined
  /** Abort the browser prompt from the outside. */
  readonly signal?: AbortSignal | undefined
}

/**
 * The argument of {@link PasskeysClient.authenticate}.
 *
 * @category models
 * @since 0.2.0
 */
export interface Authenticate extends AuthenticateOptionsPayload {
  /** When `false` the session this establishes expires in a day. */
  readonly rememberMe?: boolean | undefined
  /**
   * `"conditional"` is the autofill flow: the browser offers a passkey from the
   * username field instead of opening a modal, and the ceremony stays pending
   * until the person picks one. Pair it with `autocomplete="username webauthn"`
   * on the field.
   */
  readonly mediation?: CredentialMediationRequirement | undefined
  /** Abort the browser prompt from the outside. */
  readonly signal?: AbortSignal | undefined
}

/**
 * What a passkey sign-in came to: a session, or the second factor still owed.
 *
 * @category models
 * @since 0.2.0
 */
export type AuthenticateResult = SessionWithUser | MfaRequired

/**
 * Everything {@link PasskeysClient.register} can fail with.
 *
 * @category models
 * @since 0.2.0
 */
export type RegisterError =
  | WebAuthnClientError
  | ChallengeExpired
  | PasskeyVerificationFailed
  | RateLimited
  | Unauthorized
  | StepUpRequired

/**
 * Everything {@link PasskeysClient.authenticate} can fail with.
 *
 * @category models
 * @since 0.2.0
 */
export type AuthenticateError =
  | WebAuthnClientError
  | ChallengeExpired
  | PasskeyVerificationFailed
  | PolicyRefused
  | OriginNotAllowed
  | RateLimited

/**
 * The options of {@link make}.
 *
 * @category models
 * @since 0.2.0
 */
export interface Options {
  /**
   * Where the server is. Omit it when the auth endpoints are served from the
   * same origin as the page, which is the common — and the safest — case.
   */
  readonly baseUrl?: string | URL | undefined
  /**
   * The browser's half of a ceremony. Defaults to `navigator.credentials`.
   *
   * **When to use**
   *
   * In a test, or on a runtime whose WebAuthn is not the DOM's — this is the
   * seam the ceremony is faked at.
   */
  readonly webauthn?: WebAuthnClientService | undefined
  /** The transport. Defaults to `fetch` with {@link Options.credentials} applied. */
  readonly httpClient?: Layer.Layer<HttpClient.HttpClient> | undefined
  /**
   * The `fetch` credentials mode, defaulting to `"include"` so that the session
   * cookie a ceremony sets is kept on a cross-origin deployment.
   */
  readonly credentials?: RequestCredentials | undefined
  /** Wraps the underlying `HttpClient` — retries, logging, a timeout. */
  readonly transformClient?: ((client: HttpClient.HttpClient) => HttpClient.HttpClient) | undefined
  /** The atom runtime factory. Defaults to `Atom.runtime`. */
  readonly runtime?: Atom.RuntimeFactory | undefined
}

/**
 * The atoms and helpers returned by {@link make}.
 *
 * @category models
 * @since 0.2.0
 */
export interface PasskeysClient {
  /** The underlying `AtomHttpApi` service class, for anything this interface does not wrap. */
  readonly service: AtomHttpApi.AtomHttpApiClient<PasskeysApiClient, typeof serviceId, typeof PasskeysApiGroup>
  /** The atom runtime the client's atoms run in. */
  readonly runtime: Atom.AtomRuntime<PasskeysApiClient>

  /**
   * Registers a passkey: options, `navigator.credentials.create`, verify — one
   * `Effect`, one atom. Invalidates {@link passkeysKey}.
   *
   * **Gotchas**
   *
   * The endpoints behind it require a session that authenticated recently, so a
   * `StepUpRequired` here means "re-authenticate first", not "you cannot".
   */
  readonly register: Atom.AtomResultFn<Register, PasskeySummary, RegisterError>

  /**
   * Signs in with a passkey — or, when the page already holds that person's own
   * session, raises its assurance in place. Invalidates {@link sessionKey} and
   * {@link sessionsKey}.
   *
   * **Gotchas**
   *
   * Branch on `"_tag" in result`: a `MfaRequired` means the credential was
   * accepted and a further factor is owed.
   */
  readonly authenticate: Atom.AtomResultFn<Authenticate, AuthenticateResult, AuthenticateError>

  /** The caller's credentials, oldest first, keyed on {@link passkeysKey}. */
  readonly passkeys: Atom.Atom<AsyncResult.AsyncResult<ReadonlyArray<PasskeySummary>, Unauthorized | StepUpRequired>>

  /** Renames one of the caller's credentials. Invalidates {@link passkeysKey}. */
  readonly rename: Atom.AtomResultFn<RenamePasskeyPayload, PasskeySummary, NotFound | Unauthorized | StepUpRequired>

  /**
   * Removes one of the caller's credentials. Invalidates {@link passkeysKey}.
   *
   * **Gotchas**
   *
   * Refuses `CannotRemoveLastAuthenticator` when this credential is the
   * account's only way in — render it as "add another way to sign in first",
   * not as a failure.
   */
  readonly remove: Atom.AtomResultFn<
    DeletePasskeyPayload,
    Ok,
    NotFound | CannotRemoveLastAuthenticator | Unauthorized | StepUpRequired
  >

  /** Whether this runtime can do WebAuthn at all. */
  readonly isSupported: Effect.Effect<boolean>

  /**
   * Whether the browser will offer a passkey from an autofill dropdown.
   *
   * **When to use**
   *
   * Before setting `mediation: "conditional"`. A browser that answers `false`
   * would leave the ceremony pending for ever.
   */
  readonly isConditionalMediationAvailable: Effect.Effect<boolean>
}

/**
 * The identity of the generated client's service key.
 *
 * **Gotchas**
 *
 * A phantom: `AtomHttpApi.Service` takes a `Self` type purely to name the key,
 * and the composite atoms below run on `service.runtime`, whose requirements
 * channel is that `Self`. Leaving it `unknown` — as a client with no composite
 * atom can — would put `unknown` in a requirements channel, which is exactly
 * what the requirements channel must never hold.
 *
 * @category models
 * @since 0.2.0
 */
export interface PasskeysApiClient {
  readonly _: "effect-auth/PasskeysClient"
}

const serviceId = "effect-auth/PasskeysClient"

/**
 * Transport and decoding failures become defects, exactly as `AtomHttpApi`'s own
 * mutation atoms make them.
 *
 * The composite atoms below drive the generated client directly rather than
 * through `service.mutation`, so this is where that discipline is kept: a
 * network blip and a response this client cannot decode are not outcomes an
 * application branches on, and they must not appear in one atom's error union
 * and nowhere else in the package.
 */
const asDefect = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
  Effect.catchTags(effect, { HttpClientError: Effect.die, SchemaError: Effect.die })

/**
 * Builds a {@link PasskeysClient}.
 *
 * **Example**
 *
 * ```ts
 * import { AtomRegistry } from "effect/unstable/reactivity"
 * import { PasskeysClient } from "effect-auth/client"
 *
 * const passkeys = PasskeysClient.make({ baseUrl: "http://localhost:3000" })
 * const registry = AtomRegistry.make()
 *
 * registry.set(passkeys.authenticate, {})
 * ```
 *
 * @category constructors
 * @since 0.2.0
 */
export const make = (options?: Options): PasskeysClient => {
  const webauthn = options?.webauthn ?? browser

  const service = AtomHttpApi.Service<PasskeysApiClient>()(serviceId, {
    // No cast, and no `api` option to make one necessary: the group carries its
    // own prefix, so this declaration's paths are the ones a consumer's composed
    // API serves.
    api: PasskeysApi,
    httpClient: options?.httpClient ?? layerFetch(options?.credentials ?? "include"),
    baseUrl: options?.baseUrl,
    transformClient: options?.transformClient,
    runtime: options?.runtime
  })

  const register = service.runtime.fn<Register>()(
    (argument) =>
      Effect.gen(function* () {
        const client = yield* service
        const document = yield* client.passkeys.registerOptions({
          payload:
            argument.authenticatorAttachment === undefined
              ? {}
              : { authenticatorAttachment: argument.authenticatorAttachment }
        })
        const response = yield* webauthn.create(document, argument.signal)
        return yield* client.passkeys.registerVerify({
          payload: { response, ...(argument.name === undefined ? {} : { name: argument.name }) }
        })
      }).pipe(asDefect),
    { reactivityKeys: [passkeysKey] }
  )

  const authenticate = service.runtime.fn<Authenticate>()(
    (argument) =>
      Effect.gen(function* () {
        const client = yield* service
        const document = yield* client.passkeys.authenticateOptions({
          payload: argument.email === undefined ? {} : { email: argument.email }
        })
        const response = yield* webauthn.get(document, {
          ...(argument.mediation === undefined ? {} : { mediation: argument.mediation }),
          ...(argument.signal === undefined ? {} : { signal: argument.signal })
        })
        return yield* client.passkeys.authenticateVerify({
          payload: { response, ...(argument.rememberMe === undefined ? {} : { rememberMe: argument.rememberMe }) }
        })
      }).pipe(asDefect),
    // Signing in changes who is signed in, and the device list has a new entry.
    { reactivityKeys: [sessionKey, sessionsKey] }
  )

  return {
    service,
    runtime: service.runtime,
    register,
    authenticate,
    passkeys: service.query("passkeys", "listPasskeys", { reactivityKeys: [passkeysKey] }),
    rename: withPayload<RenamePasskeyPayload>()(service.mutation("passkeys", "renamePasskey"), [passkeysKey]),
    remove: withPayload<DeletePasskeyPayload>()(service.mutation("passkeys", "deletePasskey"), [passkeysKey]),
    isSupported: webauthn.isSupported,
    isConditionalMediationAvailable: webauthn.isConditionalMediationAvailable
  }
}
