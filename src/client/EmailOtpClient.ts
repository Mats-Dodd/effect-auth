/**
 * The browser-facing client for the e-mail one-time-code plugin.
 *
 * {@link make} builds an `AtomHttpApi` service around {@link EmailOtpApi} and
 * hands back the six mutation atoms — ask for a code, answer one, and the two
 * authenticated pairs — plus the helper that builds a link's URL. The three
 * atoms that establish or change a session carry the same `"auth.session"`
 * reactivity key `AuthClient`'s own sign-in does, so an application holding both
 * clients sees its session atom refetch by itself.
 *
 * This module is browser-safe, exactly as `AuthClient` is.
 *
 * **Details**
 *
 * Unlike `AuthClient.make`, this takes no `api` option: the group's
 * `/auth/email-otp` prefix is baked into its declaration, so the paths this
 * client calls are the ones a consumer's composed API serves whatever else that
 * API contains — and building against the plugin's own `HttpApi` is what keeps
 * this module free of a boundary cast. An application that would rather drive
 * its *own* composed API needs no client from this library at all:
 *
 * ```ts skip-type-checking
 * import { HttpApiClient } from "effect/unstable/httpapi"
 *
 * const emailOtp = yield* HttpApiClient.group(AppApi, { group: "emailOtp" })
 * ```
 *
 * **Gotchas**
 *
 * The handle a code is answered against is in an `HttpOnly` cookie, so every
 * call has to carry cookies: leave {@link Options.credentials} at its default,
 * or supply an `httpClient` that sends them.
 *
 * @since 0.2.0
 */
import type { Layer } from "effect"
import type { HttpClient } from "effect/unstable/http"
import { type Atom, AtomHttpApi } from "effect/unstable/reactivity"
import type {
  EmailUnchanged,
  InvalidCode,
  RateLimited,
  StepUpRequired,
  Unauthorized,
  UserAlreadyExists
} from "../domain/Errors.js"
import type { PolicyRefused } from "../domain/Hooks.js"
import type { SessionWithUser } from "../domain/Schema.js"
import {
  type EmailOtpApiGroup,
  EmailOtpApi,
  type EmailOtpChangeEmailPayload,
  emailOtpLinkPath,
  type EmailOtpResult,
  type EmailOtpSendPayload,
  type EmailOtpVerifyPayload,
  type SignUpDisabled
} from "../email-otp/Api.js"
import type { MfaRequired, Ok } from "../http/AuthApi.js"
import type { OriginNotAllowed } from "../http/OriginCheck.js"
import { sessionKey, sessionsKey } from "./AuthClient.js"
import { layerFetch, withPayload, withoutPayload } from "./Atoms.js"

/**
 * The path the e-mailed link points at, as `EmailOtpApiGroup` serves it.
 *
 * @category constructors
 * @since 0.2.0
 */
export const linkPath = emailOtpLinkPath

/**
 * The argument of {@link EmailOtpClient.send}.
 *
 * @category models
 * @since 0.2.0
 */
export type Send = EmailOtpSendPayload

/**
 * The argument of every endpoint that answers a code.
 *
 * `code` is a `Redacted<string>` — wrap what the person typed with
 * `Redacted.make`.
 *
 * @category models
 * @since 0.2.0
 */
export type Verify = EmailOtpVerifyPayload

/**
 * The argument of {@link EmailOtpClient.changeEmailSend}.
 *
 * @category models
 * @since 0.2.0
 */
export type ChangeEmail = EmailOtpChangeEmailPayload

/**
 * What {@link EmailOtpClient.verify} answers: what the code meant, or the news
 * that a second factor is owed.
 *
 * Branch on `_tag`.
 *
 * @category models
 * @since 0.2.0
 */
export type VerifyResult = EmailOtpResult | MfaRequired

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
   * The `fetch` credentials mode, defaulting to `"include"` so that the handle
   * cookie the send endpoint sets is kept — and sent back — on a cross-origin
   * deployment. Ignored when {@link Options.httpClient} is supplied.
   */
  readonly credentials?: RequestCredentials | undefined
  /**
   * Wraps the underlying `HttpClient` — retries, logging, a timeout.
   */
  readonly transformClient?: ((client: HttpClient.HttpClient) => HttpClient.HttpClient) | undefined
  /**
   * The atom runtime factory. Defaults to `Atom.runtime`.
   */
  readonly runtime?: Atom.RuntimeFactory | undefined
}

/**
 * The atoms and helpers returned by {@link make}.
 *
 * **Details**
 *
 * Run a mutation by writing its argument to it (`registry.set(client.send, {...})`),
 * or with `AuthClient.run` from an `Effect` — it takes any mutation atom, this
 * one included.
 *
 * @category models
 * @since 0.2.0
 */
export interface EmailOtpClient {
  /**
   * The underlying `AtomHttpApi` service class, for anything this interface does
   * not wrap.
   */
  readonly service: AtomHttpApi.AtomHttpApiClient<unknown, typeof serviceId, typeof EmailOtpApiGroup>
  /**
   * The atom runtime the client's atoms run in.
   *
   * **Gotchas**
   *
   * Its own, not `AuthClient`'s. The two clients share reactivity *keys* rather
   * than a runtime, which is what makes `verify` refetch the session atom of an
   * `AuthClient` built beside it.
   */
  readonly runtime: Atom.AtomRuntime<unknown>

  /**
   * Asks for a code. Succeeds whether or not the address has an account, and
   * whether or not the message could be delivered.
   */
  readonly send: Atom.AtomResultFn<Send, Ok, RateLimited | OriginNotAllowed>

  /**
   * Answers a code, against the handle in the cookie `send` set. Invalidates
   * `"auth.session"` and `"auth.sessions"`, because one of the things it can do
   * is sign somebody in.
   */
  readonly verify: Atom.AtomResultFn<
    Verify,
    VerifyResult,
    InvalidCode | SignUpDisabled | PolicyRefused | RateLimited | OriginNotAllowed
  >

  /** Asks for a step-up code, sent to the signed-in person's own address. */
  readonly stepUpSend: Atom.AtomResultFn<void, Ok, RateLimited | StepUpRequired | Unauthorized>

  /**
   * Answers a step-up code, raising the session's assurance and rotating its
   * token. Invalidates `"auth.session"`.
   */
  readonly stepUpVerify: Atom.AtomResultFn<
    Verify,
    SessionWithUser,
    InvalidCode | RateLimited | StepUpRequired | Unauthorized
  >

  /** Asks for a code at the address the account is to be moved to. */
  readonly changeEmailSend: Atom.AtomResultFn<
    ChangeEmail,
    Ok,
    EmailUnchanged | RateLimited | StepUpRequired | Unauthorized
  >

  /**
   * Answers a change-of-address code. Invalidates `"auth.session"`: the user
   * behind it has a new address.
   */
  readonly changeEmailVerify: Atom.AtomResultFn<
    Verify,
    Ok,
    InvalidCode | RateLimited | StepUpRequired | Unauthorized | UserAlreadyExists
  >

  /**
   * The URL of the link a token belongs to.
   *
   * **When to use**
   *
   * Rarely: the server builds this URL itself and puts it in the message. It is
   * here for an application that mails its own template from a token it was
   * handed, and for tests.
   *
   * **Gotchas**
   *
   * Path-relative when no {@link Options.baseUrl} was given, which is what a
   * same-origin page wants.
   */
  readonly linkUrl: (token: string) => string
}

const serviceId = "effect-auth/EmailOtpClient"

/**
 * Builds an {@link EmailOtpClient}.
 *
 * **Example**
 *
 * ```ts
 * import { AtomRegistry } from "effect/unstable/reactivity"
 * import { EmailOtpClient } from "effect-auth/client"
 *
 * const emailOtp = EmailOtpClient.make({ baseUrl: "http://localhost:3000" })
 * const registry = AtomRegistry.make()
 *
 * registry.set(emailOtp.send, { email: "ada@example.com", purpose: "signIn" })
 * ```
 *
 * @category constructors
 * @since 0.2.0
 */
export const make = (options?: Options): EmailOtpClient => {
  const service = AtomHttpApi.Service()(serviceId, {
    // No cast, and no `api` option to make one necessary: the group carries its
    // own prefix, so this declaration's paths are the ones a consumer's composed
    // API serves.
    api: EmailOtpApi,
    httpClient: options?.httpClient ?? layerFetch(options?.credentials ?? "include"),
    baseUrl: options?.baseUrl,
    transformClient: options?.transformClient,
    runtime: options?.runtime
  })

  return {
    service,
    runtime: service.runtime,

    send: withPayload<Send>()(service.mutation("emailOtp", "send"), undefined),
    // Answering a code can be a sign-in: whatever an application derives from
    // "who is signed in" has to refetch, and the device list has a new entry.
    verify: withPayload<Verify>()(service.mutation("emailOtp", "verify"), [sessionKey, sessionsKey]),

    stepUpSend: withoutPayload(service.mutation("emailOtp", "stepUpSend"), undefined),
    // The session's level and its token both moved.
    stepUpVerify: withPayload<Verify>()(service.mutation("emailOtp", "stepUpVerify"), [sessionKey]),

    changeEmailSend: withPayload<ChangeEmail>()(service.mutation("emailOtp", "changeEmailSend"), undefined),
    changeEmailVerify: withPayload<Verify>()(service.mutation("emailOtp", "changeEmailVerify"), [sessionKey]),

    linkUrl: (token) => {
      const path = `${linkPath}?token=${encodeURIComponent(token)}`
      return options?.baseUrl === undefined ? path : new URL(path, options.baseUrl.toString()).toString()
    }
  }
}
