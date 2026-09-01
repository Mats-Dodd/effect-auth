/**
 * The browser-facing client for the magic link plugin.
 *
 * {@link make} builds an `AtomHttpApi` service around {@link MagicLinkApi} and
 * hands back two mutation atoms — ask for a link, exchange one for a session —
 * plus the helper that builds a link's URL. `exchange` carries the same
 * `"auth.session"` reactivity key `AuthClient`'s own sign-in does, so an
 * application holding both clients sees its session atom refetch by itself.
 *
 * This module is browser-safe, exactly as `AuthClient` is.
 *
 * **Details**
 *
 * Unlike `AuthClient.make`, this takes no `api` option: the group's `/auth/magic-link`
 * prefix is baked into its declaration, so the paths this client calls are the
 * ones a consumer's composed API serves whatever else that API contains — and
 * building against the plugin's own `HttpApi` is what keeps this module free of a
 * boundary cast. An application that would rather drive its *own* composed API
 * needs no client from this library at all:
 *
 * ```ts skip-type-checking
 * import { HttpApiClient } from "effect/unstable/httpapi"
 *
 * const magicLink = yield* HttpApiClient.group(AppApi, { group: "magicLink" })
 * ```
 *
 * @since 1.0.0
 */
import type { Layer } from "effect"
import type { HttpClient } from "effect/unstable/http"
import { type Atom, AtomHttpApi } from "effect/unstable/reactivity"
import type { InvalidToken, RateLimited } from "../domain/Errors.js"
import type { PolicyRefused } from "../domain/Hooks.js"
import type { SessionWithUser } from "../domain/Schema.js"
import type { Ok } from "../http/AuthApi.js"
import {
  magicLinkPrefix,
  MagicLinkApi,
  type MagicLinkApiGroup,
  type MagicLinkExchangePayload,
  type MagicLinkSignInPayload,
  type SignUpDisabled
} from "../magic-link/Api.js"
import { sessionKey, sessionsKey } from "./AuthClient.js"
import { layerFetch, withPayload } from "./internal/atoms.js"

/**
 * The path the e-mailed link points at, as {@link MagicLinkApiGroup} serves it.
 *
 * @category constructors
 * @since 1.0.0
 */
export const verifyPath = `${magicLinkPrefix}/verify`

/**
 * The argument of {@link MagicLinkClient.signIn}.
 *
 * @category models
 * @since 1.0.0
 */
export type SignIn = MagicLinkSignInPayload

/**
 * The argument of {@link MagicLinkClient.exchange}. `token` is a
 * `Redacted<string>` — wrap the value out of the link with `Redacted.make`.
 *
 * @category models
 * @since 1.0.0
 */
export type Exchange = MagicLinkExchangePayload

/**
 * The options of {@link make}.
 *
 * @category models
 * @since 1.0.0
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
   * The `fetch` credentials mode, defaulting to `"include"` so that the session
   * cookie `exchange` sets is kept on a cross-origin deployment. Ignored when
   * {@link Options.httpClient} is supplied.
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
 * Run a mutation by writing its argument to it (`registry.set(client.signIn, {...})`),
 * or with `AuthClient.run` from an `Effect` — it takes any mutation atom, this
 * one included.
 *
 * @category models
 * @since 1.0.0
 */
export interface MagicLinkClient {
  /**
   * The underlying `AtomHttpApi` service class, for anything this interface does
   * not wrap.
   */
  readonly service: AtomHttpApi.AtomHttpApiClient<unknown, typeof serviceId, typeof MagicLinkApiGroup>
  /**
   * The atom runtime the client's atoms run in.
   *
   * **Gotchas**
   *
   * Its own, not `AuthClient`'s. The two clients share reactivity *keys* rather
   * than a runtime, which is what makes `exchange` refetch the session atom of an
   * `AuthClient` built beside it.
   */
  readonly runtime: Atom.AtomRuntime<unknown>

  /**
   * Asks for a link. Succeeds whether or not the address has an account, and
   * whether or not the message could be delivered.
   */
  readonly signIn: Atom.AtomResultFn<SignIn, Ok, RateLimited>

  /**
   * Exchanges a link's token for a session, and sets the session cookie.
   * Invalidates `"auth.session"` and `"auth.sessions"`.
   */
  readonly exchange: Atom.AtomResultFn<
    Exchange,
    SessionWithUser,
    InvalidToken | SignUpDisabled | PolicyRefused | RateLimited
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
  readonly verifyUrl: (token: string) => string
}

const serviceId = "effect-auth/MagicLinkClient"

/**
 * Builds a {@link MagicLinkClient}.
 *
 * **Example**
 *
 * ```ts
 * import { AtomRegistry } from "effect/unstable/reactivity"
 * import { MagicLinkClient } from "effect-auth/client"
 *
 * const magicLink = MagicLinkClient.make({ baseUrl: "http://localhost:3000" })
 * const registry = AtomRegistry.make()
 *
 * registry.set(magicLink.signIn, { email: "ada@example.com" })
 * ```
 *
 * @category constructors
 * @since 1.0.0
 */
export const make = (options?: Options): MagicLinkClient => {
  const service = AtomHttpApi.Service()(serviceId, {
    // No cast, and no `api` option to make one necessary: the group carries its
    // own prefix, so this declaration's paths are the ones a consumer's composed
    // API serves.
    api: MagicLinkApi,
    httpClient: options?.httpClient ?? layerFetch(options?.credentials ?? "include"),
    baseUrl: options?.baseUrl,
    transformClient: options?.transformClient,
    runtime: options?.runtime
  })

  return {
    service,
    runtime: service.runtime,

    signIn: withPayload<SignIn>()(service.mutation("magicLink", "signIn"), undefined),
    // Spending a link is a sign-in: whatever an application derives from "who is
    // signed in" has to refetch, and the device list has a new entry in it.
    exchange: withPayload<Exchange>()(service.mutation("magicLink", "exchange"), [sessionKey, sessionsKey]),

    verifyUrl: (token) => {
      const path = `${verifyPath}?token=${encodeURIComponent(token)}`
      return options?.baseUrl === undefined ? path : new URL(path, options.baseUrl.toString()).toString()
    }
  }
}
