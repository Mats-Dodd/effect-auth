/**
 * The browser-facing client for the phone plugin.
 *
 * {@link make} builds an `AtomHttpApi` service around `PhoneApi` and hands back
 * one mutation atom per endpoint. The three that change who is signed in — the
 * sign-in verify and the step-up verify — carry `AuthClient`'s own
 * `"auth.session"` and `"auth.sessions"` reactivity keys, so an application
 * holding both clients sees its session atom refetch by itself.
 *
 * This module is browser-safe, exactly as `AuthClient` is.
 *
 * **Details**
 *
 * Unlike `AuthClient.make` this takes no `api` option: the group's
 * `/auth/phone` prefix is baked into its declaration, so the paths this client
 * calls are the ones a consumer's composed API serves whatever else that API
 * contains — and building against the plugin's own `HttpApi` is what keeps this
 * module free of a boundary cast.
 *
 * **Gotchas**
 *
 * No atom takes a handle. The handle a code was issued against rides in a
 * `__Host-` cookie the browser sends by itself, so every verify is `{ code }`
 * and a page never holds the value that binds the attempt budget to it. That is
 * also why {@link Options.credentials} defaults to `"include"`.
 *
 * @since 0.2.0
 */
import type { Layer } from "effect"
import type { HttpClient } from "effect/unstable/http"
import { type Atom, AtomHttpApi } from "effect/unstable/reactivity"
import type { InvalidCode, RateLimited, StepUpRequired, Unauthorized } from "../domain/Errors.js"
import type { PolicyRefused } from "../domain/Hooks.js"
import type { SessionWithUser } from "../domain/Schema.js"
import type { MfaRequired, Ok } from "../http/AuthApi.js"
import type { OriginNotAllowed } from "../http/OriginCheck.js"
import type {
  EmptyPayload,
  InvalidPhoneNumber,
  PhoneAlreadyInUse,
  PhoneApiGroup,
  PhoneCodePayload,
  PhoneSignInPayload,
  PhoneCountryNotAllowed,
  PhoneNotVerified,
  PhoneNumberPayload,
  RestrictedFactorNotAllowed,
  VerifiedPhone
} from "../phone/Api.js"
import { PhoneApi } from "../phone/Api.js"
import { sessionKey, sessionsKey } from "./AuthClient.js"
import { layerFetch, withPayload } from "./Atoms.js"

/**
 * The argument of the two atoms that name a number.
 *
 * @category models
 * @since 0.2.0
 */
export type SendCode = PhoneNumberPayload

/**
 * The argument of every atom that answers a code.
 *
 * @category models
 * @since 0.2.0
 */
export type AnswerCode = PhoneCodePayload

/**
 * The argument of {@link PhoneClient.signInVerify}: a code, and how long the
 * session it mints should outlive the browser.
 *
 * @category models
 * @since 0.2.0
 */
export type AnswerSignInCode = PhoneSignInPayload

/**
 * The argument of the two atoms that take nothing.
 *
 * @category models
 * @since 0.2.0
 */
export type NoArgument = EmptyPayload

/**
 * What {@link PhoneClient.signInVerify} answers: a session, or the news that a
 * second factor is owed.
 *
 * **Gotchas**
 *
 * A real union, discriminated on `_tag` — `"_tag" in result` narrows it. The
 * `MfaRequired` member arrives on `202` and carries no session cookie; the
 * pending-authentication token is in the `__Host-effect_auth.pending` cookie,
 * where a script cannot read it.
 *
 * @category models
 * @since 0.2.0
 */
export type SignInResult = SessionWithUser | MfaRequired

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
   * The `fetch` credentials mode, defaulting to `"include"`.
   *
   * **Gotchas**
   *
   * Every flow here is two requests and the second one only works because the
   * first one's cookie came back. `"omit"` breaks all three.
   */
  readonly credentials?: RequestCredentials | undefined
  /** Wraps the underlying `HttpClient` — retries, logging, a timeout. */
  readonly transformClient?: ((client: HttpClient.HttpClient) => HttpClient.HttpClient) | undefined
  /** The atom runtime factory. Defaults to `Atom.runtime`. */
  readonly runtime?: Atom.RuntimeFactory | undefined
}

/**
 * The atoms returned by {@link make}.
 *
 * **Details**
 *
 * Run a mutation by writing its argument to it
 * (`registry.set(phone.signInSend, { phoneNumber })`), or with `AuthClient.run`
 * from an `Effect` — it takes any mutation atom, these included.
 *
 * @category models
 * @since 0.2.0
 */
export interface PhoneClient {
  /** The underlying `AtomHttpApi` service class, for anything this interface does not wrap. */
  readonly service: AtomHttpApi.AtomHttpApiClient<unknown, typeof serviceId, typeof PhoneApiGroup>
  /** The atom runtime the client's atoms run in. */
  readonly runtime: Atom.AtomRuntime<unknown>

  /** Sends a code to a number the signed-in caller wants to attach. */
  readonly sendVerification: Atom.AtomResultFn<
    SendCode,
    Ok,
    InvalidPhoneNumber | PhoneCountryNotAllowed | RestrictedFactorNotAllowed | RateLimited | Authenticate
  >
  /** Attaches the number by answering its code. */
  readonly verify: Atom.AtomResultFn<
    AnswerCode,
    VerifiedPhone,
    InvalidCode | PhoneAlreadyInUse | RestrictedFactorNotAllowed | RateLimited | Authenticate
  >
  /** Detaches the caller's number. */
  readonly remove: Atom.AtomResultFn<NoArgument, Ok, RateLimited | Authenticate>

  /** Sends a sign-in code. Answers the same whether or not anybody holds the number. */
  readonly signInSend: Atom.AtomResultFn<
    SendCode,
    Ok,
    InvalidPhoneNumber | PhoneCountryNotAllowed | OriginNotAllowed | RateLimited
  >
  /**
   * Signs in by answering a code, and sets the session cookie. Invalidates
   * `"auth.session"` and `"auth.sessions"`.
   */
  readonly signInVerify: Atom.AtomResultFn<
    AnswerSignInCode,
    SignInResult,
    InvalidCode | OriginNotAllowed | PolicyRefused | RateLimited
  >

  /** Sends a step-up code to the number on the caller's own record. */
  readonly stepUpSend: Atom.AtomResultFn<NoArgument, Ok, PhoneNotVerified | RateLimited | Authenticate>
  /**
   * Raises the caller's session by answering a code, and re-sets the cookie
   * with the rotated token. Invalidates `"auth.session"` and `"auth.sessions"`.
   */
  readonly stepUpVerify: Atom.AtomResultFn<AnswerCode, SessionWithUser, InvalidCode | RateLimited | Authenticate>
}

/**
 * What every authenticated endpoint can fail with before its own errors are
 * reached: no session, or one whose assurance the endpoint's policy refuses.
 *
 * **Gotchas**
 *
 * Declared on the `Authenticated` middleware rather than on any endpoint, so it
 * is on all four of the atoms that carry it whether or not they say so. Recover
 * from `StepUpRequired` with `AuthClient.withStepUp`.
 *
 * @category models
 * @since 0.2.0
 */
export type Authenticate = Unauthorized | StepUpRequired

const serviceId = "effect-auth/PhoneClient"

/**
 * Builds a {@link PhoneClient}.
 *
 * **Example**
 *
 * ```ts
 * import { AtomRegistry } from "effect/unstable/reactivity"
 * import { PhoneClient } from "effect-auth/client"
 *
 * const phone = PhoneClient.make({ baseUrl: "http://localhost:3000" })
 * const registry = AtomRegistry.make()
 *
 * registry.set(phone.signInSend, { phoneNumber: "+1 555 010 0000" })
 * ```
 *
 * @category constructors
 * @since 0.2.0
 */
export const make = (options?: Options): PhoneClient => {
  const service = AtomHttpApi.Service()(serviceId, {
    // No cast, and no `api` option to make one necessary: the group carries its
    // own prefix, so this declaration's paths are the ones a consumer's composed
    // API serves.
    api: PhoneApi,
    httpClient: options?.httpClient ?? layerFetch(options?.credentials ?? "include"),
    baseUrl: options?.baseUrl,
    transformClient: options?.transformClient,
    runtime: options?.runtime
  })

  return {
    service,
    runtime: service.runtime,

    sendVerification: withPayload<SendCode>()(service.mutation("phone", "sendVerification"), undefined),
    // Attaching or detaching a number changes what the account's authenticator
    // list says, which is part of what a session view shows.
    verify: withPayload<AnswerCode>()(service.mutation("phone", "verify"), [sessionKey]),
    remove: withPayload<NoArgument>()(service.mutation("phone", "remove"), [sessionKey]),

    signInSend: withPayload<SendCode>()(service.mutation("phone", "signInSend"), undefined),
    // A sign-in: whatever an application derives from "who is signed in" has to
    // refetch, and the device list has a new entry in it.
    signInVerify: withPayload<AnswerCode>()(service.mutation("phone", "signInVerify"), [sessionKey, sessionsKey]),

    stepUpSend: withPayload<NoArgument>()(service.mutation("phone", "stepUpSend"), undefined),
    // The session's own level and its token both moved.
    stepUpVerify: withPayload<AnswerCode>()(service.mutation("phone", "stepUpVerify"), [sessionKey, sessionsKey])
  }
}
