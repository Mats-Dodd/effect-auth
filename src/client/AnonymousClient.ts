/**
 * The browser-facing client for the anonymous plugin.
 *
 * Two mutation atoms — become a visitor, and discard one. Both carry the same
 * `"auth.session"` reactivity key `AuthClient`'s own sign-in does, so an
 * application holding both clients sees its session atom refetch by itself.
 *
 * This module is browser-safe, exactly as `AuthClient` is.
 *
 * @since 0.2.0
 */
import type { Layer } from "effect"
import type { HttpClient } from "effect/unstable/http"
import { type Atom, AtomHttpApi } from "effect/unstable/reactivity"
import type { RateLimited, StepUpRequired, Unauthorized } from "../domain/Errors.js"
import type { PolicyRefused } from "../domain/Hooks.js"
import type { SessionWithUser } from "../domain/Schema.js"
import { AnonymousApi, type AnonymousApiGroup, type NotAnonymous } from "../anonymous/Api.js"
import type { Ok } from "../http/AuthApi.js"
import type { OriginNotAllowed } from "../http/OriginCheck.js"
import { sessionKey, sessionsKey } from "./AuthClient.js"
import { layerFetch, withoutPayload } from "./Atoms.js"

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
   * cookie `signIn` sets is kept on a cross-origin deployment.
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
export interface AnonymousClient {
  /** The underlying `AtomHttpApi` service class, for anything this interface does not wrap. */
  readonly service: AtomHttpApi.AtomHttpApiClient<unknown, typeof serviceId, typeof AnonymousApiGroup>
  /** The atom runtime the client's atoms run in. Its own, not `AuthClient`'s. */
  readonly runtime: Atom.AtomRuntime<unknown>

  /**
   * Becomes an anonymous visitor and sets the session cookie. Takes no
   * argument. Invalidates `"auth.session"` and `"auth.sessions"`.
   */
  readonly signIn: Atom.AtomResultFn<void, SessionWithUser, PolicyRefused | OriginNotAllowed | RateLimited>

  /**
   * Discards the caller's anonymous account and clears the cookies. Refuses
   * with `NotAnonymous` once the account has been adopted.
   */
  readonly delete: Atom.AtomResultFn<void, Ok, NotAnonymous | Unauthorized | StepUpRequired>
}

const serviceId = "effect-auth/AnonymousClient"

/**
 * Builds an {@link AnonymousClient}.
 *
 * **Example**
 *
 * ```ts
 * import { AtomRegistry } from "effect/unstable/reactivity"
 * import { AnonymousClient } from "effect-auth/client"
 *
 * const anonymous = AnonymousClient.make({ baseUrl: "http://localhost:3000" })
 * const registry = AtomRegistry.make()
 *
 * registry.set(anonymous.signIn, undefined)
 * ```
 *
 * @category constructors
 * @since 0.2.0
 */
export const make = (options?: Options): AnonymousClient => {
  const service = AtomHttpApi.Service()(serviceId, {
    api: AnonymousApi,
    httpClient: options?.httpClient ?? layerFetch(options?.credentials ?? "include"),
    baseUrl: options?.baseUrl,
    transformClient: options?.transformClient,
    runtime: options?.runtime
  })

  return {
    service,
    runtime: service.runtime,

    signIn: withoutPayload(service.mutation("anonymous", "signIn"), [sessionKey, sessionsKey]),
    // The account is gone, so anything derived from "who is signed in" is wrong
    // until it refetches.
    delete: withoutPayload(service.mutation("anonymous", "delete"), [sessionKey, sessionsKey])
  }
}
