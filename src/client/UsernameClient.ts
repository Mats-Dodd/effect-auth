/**
 * The browser-facing client for the username plugin.
 *
 * {@link make} builds an `AtomHttpApi` service around `UsernameApi` and hands
 * back three mutation atoms — sign in, choose a username, ask whether one is
 * free. `signIn` and `set` carry the same `"auth.session"` reactivity key
 * `AuthClient`'s own sign-in does, so an application holding both clients sees
 * its session atom refetch by itself.
 *
 * This module is browser-safe, exactly as `AuthClient` is.
 *
 * **Details**
 *
 * Like `EmailOtpClient`, it takes no `api` option: the group's
 * `/auth/username` prefix is baked into its declaration, so the paths this
 * client calls are the ones a consumer's composed API serves — and building
 * against the plugin's own `HttpApi` is what keeps this module free of a
 * boundary cast.
 *
 * @since 0.2.0
 */
import type { Layer } from "effect"
import type { HttpClient } from "effect/unstable/http"
import { type Atom, AtomHttpApi } from "effect/unstable/reactivity"
import type {
  EmailNotVerified,
  InvalidCredentials,
  RateLimited,
  StepUpRequired,
  Unauthorized
} from "../domain/Errors.js"
import type { PolicyRefused } from "../domain/Hooks.js"
import type { SessionWithUser } from "../domain/Schema.js"
import type { MfaRequired } from "../http/AuthApi.js"
import type { OriginNotAllowed } from "../http/OriginCheck.js"
import {
  type AvailabilityResponse,
  UsernameApi,
  type UsernameApiGroup,
  type UsernameInvalid,
  type UsernamePayload,
  type UsernameResponse,
  type UsernameSignInPayload,
  type UsernameTaken
} from "../username/Api.js"
import { sessionKey, sessionsKey } from "./AuthClient.js"
import { layerFetch, withPayload } from "./Atoms.js"

/**
 * The argument of {@link UsernameClient.signIn}.
 *
 * @category models
 * @since 0.2.0
 */
export type SignIn = UsernameSignInPayload

/**
 * The argument of {@link UsernameClient.set} and {@link UsernameClient.available}.
 *
 * @category models
 * @since 0.2.0
 */
export type Username = UsernamePayload

/**
 * What {@link UsernameClient.signIn} answers with.
 *
 * **Gotchas**
 *
 * A union, exactly as `AuthClient.signIn`'s is: branch on `"_tag" in result`.
 * `MfaRequired` means the sign-in was correct and a second factor is owed — the
 * pending-authentication token is in a `__Host-` cookie and no session exists
 * yet.
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
   * same origin as the page.
   */
  readonly baseUrl?: string | URL | undefined
  /** The transport. Defaults to `fetch` with the {@link Options.credentials} setting applied. */
  readonly httpClient?: Layer.Layer<HttpClient.HttpClient> | undefined
  /**
   * The `fetch` credentials mode, defaulting to `"include"` so the session
   * cookie `signIn` sets is kept on a cross-origin deployment. Ignored when
   * {@link Options.httpClient} is supplied.
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
 * @category models
 * @since 0.2.0
 */
export interface UsernameClient {
  /** The underlying `AtomHttpApi` service class, for anything this interface does not wrap. */
  readonly service: AtomHttpApi.AtomHttpApiClient<unknown, typeof serviceId, typeof UsernameApiGroup>
  /**
   * The atom runtime the client's atoms run in.
   *
   * Its own, not `AuthClient`'s: the two clients share reactivity *keys* rather
   * than a runtime, which is what makes `signIn` refetch the session atom of an
   * `AuthClient` built beside it.
   */
  readonly runtime: Atom.AtomRuntime<unknown>

  /**
   * Signs in with a username and password, and sets the session cookie.
   * Invalidates `"auth.session"` and `"auth.sessions"`.
   */
  readonly signIn: Atom.AtomResultFn<
    SignIn,
    SignInResult,
    InvalidCredentials | EmailNotVerified | PolicyRefused | OriginNotAllowed | RateLimited
  >

  /**
   * Chooses or changes the caller's username. Requires a session that
   * authenticated within `session.freshAge`.
   */
  readonly set: Atom.AtomResultFn<
    Username,
    UsernameResponse,
    UsernameInvalid | UsernameTaken | Unauthorized | StepUpRequired
  >

  /**
   * Asks whether a username is free. Served only where the deployment switched
   * it on.
   */
  readonly available: Atom.AtomResultFn<
    Username,
    AvailabilityResponse,
    UsernameInvalid | OriginNotAllowed | RateLimited
  >
}

const serviceId = "effect-auth/UsernameClient"

/**
 * Builds a {@link UsernameClient}.
 *
 * **Example**
 *
 * ```ts
 * import { Redacted } from "effect"
 * import { AtomRegistry } from "effect/unstable/reactivity"
 * import { UsernameClient } from "effect-auth/client"
 *
 * const username = UsernameClient.make({ baseUrl: "http://localhost:3000" })
 * const registry = AtomRegistry.make()
 *
 * registry.set(username.signIn, { username: "ada", password: Redacted.make("correct horse battery staple") })
 * ```
 *
 * @category constructors
 * @since 0.2.0
 */
export const make = (options?: Options): UsernameClient => {
  const service = AtomHttpApi.Service()(serviceId, {
    api: UsernameApi,
    httpClient: options?.httpClient ?? layerFetch(options?.credentials ?? "include"),
    baseUrl: options?.baseUrl,
    transformClient: options?.transformClient,
    runtime: options?.runtime
  })

  return {
    service,
    runtime: service.runtime,

    // A sign-in: whatever an application derives from "who is signed in" has to
    // refetch, and the device list has a new entry in it.
    signIn: withPayload<SignIn>()(service.mutation("username", "signIn"), [sessionKey, sessionsKey]),
    // The name is part of the session's user, so the session atom is stale the
    // moment this returns.
    set: withPayload<Username>()(service.mutation("username", "set"), [sessionKey]),
    available: withPayload<Username>()(service.mutation("username", "available"), undefined)
  }
}
