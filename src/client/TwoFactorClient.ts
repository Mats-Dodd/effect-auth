/**
 * The browser-facing client for the two-factor plugin.
 *
 * {@link make} builds an `AtomHttpApi` service around {@link TwoFactorApi} and
 * hands back one query and eight mutations. The two that establish or raise a
 * session — `verify` and `verifyRecoveryCode` — carry the same
 * `"auth.session"` reactivity key `AuthClient`'s own sign-in does, so an
 * application holding both clients sees its session atom refetch by itself.
 *
 * This module is browser-safe, exactly as `AuthClient` is.
 *
 * **Details**
 *
 * Like `EmailOtpClient`, this takes no `api` option: the group's
 * `/auth/two-factor` prefix is baked into its declaration, so the paths this
 * client calls are the ones a consumer's composed API serves whatever else that
 * API contains — and building against the plugin's own `HttpApi` is what keeps
 * this module free of a boundary cast.
 *
 * **Gotchas**
 *
 * Nothing here ever sees the pending-authentication cookie or the
 * trusted-device cookie: both are `__Host-` and `HttpOnly`, the browser
 * attaches them, and `credentials: "include"` is what makes that work on a
 * cross-origin deployment. An application that has just been answered
 * `MfaRequired` by `AuthClient.signIn` calls {@link TwoFactorClient.verify}
 * with the code and nothing else.
 *
 * @since 0.2.0
 */
import type { Layer } from "effect"
import type { HttpClient } from "effect/unstable/http"
import { type AsyncResult, type Atom, AtomHttpApi } from "effect/unstable/reactivity"
import type {
  InvalidCode,
  InvalidToken,
  NotFound,
  RateLimited,
  StepUpRequired,
  Unauthorized
} from "../domain/Errors.js"
import type { PolicyRefused } from "../domain/Hooks.js"
import type { SessionWithUser } from "../domain/Schema.js"
import type { Ok } from "../http/AuthApi.js"
import type { OriginNotAllowed } from "../http/OriginCheck.js"
import type {
  DeviceRevokePayload,
  RecoveryCodeSet,
  RecoveryVerifyPayload,
  TotpAlreadyEnrolled,
  TotpConfirmPayload,
  TotpEnrolmentStarted,
  TotpNotEnrolled,
  TotpVerifyPayload,
  TrustedDeviceView,
  TwoFactorApiGroup
} from "../two-factor/Api.js"
import { TwoFactorApi } from "../two-factor/Api.js"
import { sessionKey, sessionsKey } from "./AuthClient.js"
import { layerFetch, withoutPayload, withPayload } from "./Atoms.js"

/**
 * The reactivity key the device list is held under.
 *
 * **Details**
 *
 * Every mutation that can change it carries it, including the two that spend a
 * factor: confirming an enrolment, spending a recovery code, regenerating the
 * set and disabling the second factor all forget every remembered browser, so
 * a list held on screen is stale the moment any of them returns.
 *
 * @category constructors
 * @since 0.2.0
 */
export const devicesKey = "auth.two-factor.devices"

/**
 * The argument of {@link TwoFactorClient.confirm}.
 *
 * @category models
 * @since 0.2.0
 */
export type Confirm = TotpConfirmPayload

/**
 * The argument of {@link TwoFactorClient.verify}.
 *
 * @category models
 * @since 0.2.0
 */
export type Verify = TotpVerifyPayload

/**
 * The argument of {@link TwoFactorClient.verifyRecoveryCode}.
 *
 * @category models
 * @since 0.2.0
 */
export type VerifyRecoveryCode = RecoveryVerifyPayload

/**
 * The argument of {@link TwoFactorClient.revokeDevice}.
 *
 * @category models
 * @since 0.2.0
 */
export type RevokeDevice = DeviceRevokePayload

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
   * The transport. Defaults to `fetch` with the {@link Options.credentials}
   * setting applied.
   */
  readonly httpClient?: Layer.Layer<HttpClient.HttpClient> | undefined
  /**
   * The `fetch` credentials mode, defaulting to `"include"` so that the
   * `__Host-` cookies this flow rides on travel to a cross-origin deployment.
   * Ignored when {@link Options.httpClient} is supplied.
   */
  readonly credentials?: RequestCredentials | undefined
  /** Wraps the underlying `HttpClient` — retries, logging, a timeout. */
  readonly transformClient?: ((client: HttpClient.HttpClient) => HttpClient.HttpClient) | undefined
  /** The atom runtime factory. Defaults to `Atom.runtime`. */
  readonly runtime?: Atom.RuntimeFactory | undefined
}

/**
 * The errors every authenticated member of this client can answer, whatever
 * else it declares: no session, or one that has not proved enough.
 */
type Guarded = Unauthorized | StepUpRequired

/**
 * The errors both verify members can answer.
 *
 * `Unauthorized` is "you presented neither a pending authentication nor a
 * session"; `InvalidToken` is "the pending authentication is gone";
 * `InvalidCode` is every way of getting the code wrong.
 */
type VerifyError = InvalidCode | InvalidToken | Unauthorized | OriginNotAllowed | PolicyRefused | RateLimited

/**
 * The atoms returned by {@link make}.
 *
 * **Details**
 *
 * Run a mutation by writing its argument to it
 * (`registry.set(client.verify, { code })`), or with `AuthClient.run` from an
 * `Effect` — it takes any mutation atom, this one included.
 *
 * @category models
 * @since 0.2.0
 */
export interface TwoFactorClient {
  /**
   * The underlying `AtomHttpApi` service class, for anything this interface
   * does not wrap.
   */
  readonly service: AtomHttpApi.AtomHttpApiClient<unknown, typeof serviceId, typeof TwoFactorApiGroup>
  /**
   * The atom runtime the client's atoms run in.
   *
   * **Gotchas**
   *
   * Its own, not `AuthClient`'s. The two clients share reactivity *keys*
   * rather than a runtime, which is what makes `verify` refetch the session
   * atom of an `AuthClient` built beside it.
   */
  readonly runtime: Atom.AtomRuntime<unknown>

  /**
   * The browsers that may skip the second factor, keyed on {@link devicesKey}.
   *
   * A read, so it refetches by itself whenever a mutation carrying that key
   * settles — including the ones that forget every device at once.
   */
  readonly devices: Atom.Atom<AsyncResult.AsyncResult<ReadonlyArray<TrustedDeviceView>, Guarded>>

  /**
   * Starts an enrolment and answers the secret, once. Show it as a QR code
   * from `otpauthUri`, and offer `secret` for manual entry.
   */
  readonly enroll: Atom.AtomResultFn<void, TotpEnrolmentStarted, TotpAlreadyEnrolled | Guarded>

  /**
   * Proves the enrolment and answers the recovery codes, once. Invalidates
   * {@link devicesKey}: confirming a factor forgets every remembered browser.
   */
  readonly confirm: Atom.AtomResultFn<
    Confirm,
    RecoveryCodeSet,
    InvalidCode | TotpAlreadyEnrolled | TotpNotEnrolled | RateLimited | Guarded
  >

  /**
   * Answers a second factor with an authenticator-app code — completing a
   * sign-in that was interrupted, or raising the session in hand. Invalidates
   * {@link sessionKey}, {@link sessionsKey} and {@link devicesKey}.
   */
  readonly verify: Atom.AtomResultFn<Verify, SessionWithUser, VerifyError>

  /**
   * The same, with a recovery code. Invalidates the same keys — spending one
   * forgets every remembered browser.
   */
  readonly verifyRecoveryCode: Atom.AtomResultFn<VerifyRecoveryCode, SessionWithUser, VerifyError>

  /**
   * Removes the enrolment, the recovery codes and every remembered browser.
   * Requires a session that has proved a second factor.
   */
  readonly disable: Atom.AtomResultFn<void, Ok, TotpNotEnrolled | Guarded>

  /**
   * Replaces the recovery codes and answers the new set, once. Requires a
   * session that has proved a second factor.
   */
  readonly regenerateRecoveryCodes: Atom.AtomResultFn<void, RecoveryCodeSet, TotpNotEnrolled | Guarded>

  /** Forgets one remembered browser. Invalidates {@link devicesKey}. */
  readonly revokeDevice: Atom.AtomResultFn<RevokeDevice, Ok, NotFound | Guarded>

  /** Forgets every remembered browser. Invalidates {@link devicesKey}. */
  readonly revokeDevices: Atom.AtomResultFn<void, Ok, Guarded>
}

const serviceId = "effect-auth/TwoFactorClient"

/**
 * Builds a {@link TwoFactorClient}.
 *
 * **Example**
 *
 * ```ts
 * import { Redacted } from "effect"
 * import { AtomRegistry } from "effect/unstable/reactivity"
 * import { TwoFactorClient } from "effect-auth/client"
 *
 * const twoFactor = TwoFactorClient.make({ baseUrl: "http://localhost:3000" })
 * const registry = AtomRegistry.make()
 *
 * registry.set(twoFactor.verify, { code: Redacted.make("123456"), trustDevice: true })
 * ```
 *
 * @category constructors
 * @since 0.2.0
 */
export const make = (options?: Options): TwoFactorClient => {
  const service = AtomHttpApi.Service()(serviceId, {
    // No cast, and no `api` option to make one necessary: the group carries its
    // own prefix, so this declaration's paths are the ones a consumer's
    // composed API serves.
    api: TwoFactorApi,
    httpClient: options?.httpClient ?? layerFetch(options?.credentials ?? "include"),
    baseUrl: options?.baseUrl,
    transformClient: options?.transformClient,
    runtime: options?.runtime
  })

  // Answering a second factor is a sign-in or a step-up: whatever an
  // application derives from "who is signed in" has to refetch, and the device
  // list may have gained an entry or lost all of them.
  const settled = [sessionKey, sessionsKey, devicesKey]

  return {
    service,
    runtime: service.runtime,

    devices: service.query("twoFactor", "devices", { reactivityKeys: [devicesKey] }),
    enroll: withoutPayload(service.mutation("twoFactor", "totpEnroll"), undefined),
    confirm: withPayload<Confirm>()(service.mutation("twoFactor", "totpConfirm"), [devicesKey]),
    verify: withPayload<Verify>()(service.mutation("twoFactor", "totpVerify"), settled),
    verifyRecoveryCode: withPayload<VerifyRecoveryCode>()(service.mutation("twoFactor", "recoveryVerify"), settled),
    disable: withoutPayload(service.mutation("twoFactor", "totpDisable"), [devicesKey]),
    regenerateRecoveryCodes: withoutPayload(service.mutation("twoFactor", "recoveryRegenerate"), [devicesKey]),
    revokeDevice: withPayload<RevokeDevice>()(service.mutation("twoFactor", "devicesRevoke"), [devicesKey]),
    revokeDevices: withoutPayload(service.mutation("twoFactor", "devicesRevokeAll"), [devicesKey])
  }
}
