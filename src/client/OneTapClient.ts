/**
 * The browser-facing client for Google One Tap.
 *
 * **Details**
 *
 * More than a pair of atoms, because One Tap is more than a pair of requests:
 * Google's `gsi/client` script has to be on the page, initialised with a nonce
 * this server minted, and its credential handed back. {@link make} wraps all of
 * it — {@link OneTapClient.start} loads the script once, asks for a nonce, and
 * initialises the library with the callback that posts the credential.
 *
 * **Gotchas — FedCM, since August 2025**
 *
 * `use_fedcm_for_prompt` is *ignored*: the browser-mediated flow is the only
 * flow, and this client does not pass the option. Two consequences follow that
 * no library can paper over. A page inside an iframe needs
 * `allow="identity-credentials-get"` on that iframe or the prompt never
 * appears. And the moment-notification API — `isNotDisplayed`,
 * `getNotDisplayedReason` and the rest — is gone: `prompt()` takes no listener
 * here because there is nothing left for one to observe, so a page that needs a
 * fallback shows its own button rather than reacting to a reason.
 *
 * `client_id` is written **last** in the object handed to
 * `google.accounts.id.initialize`, after {@link StartOptions.additionalOptions}
 * has been spread. A page that passes a `client_id` of its own in that bag is
 * therefore ignored rather than obeyed — it is the one field whose value has to
 * be the one the server will check the audience against.
 *
 * This module is browser-safe, exactly as `AuthClient` is, and it touches the
 * DOM only inside the functions that are documented as doing so.
 *
 * @since 0.2.0
 */
import type { Layer } from "effect"
import { Effect, Option, Result, Schema } from "effect"
import type { HttpClient } from "effect/unstable/http"
import { type Atom, AtomHttpApi } from "effect/unstable/reactivity"
import type { AccountAlreadyLinked, OAuthProviderError, RateLimited, UserNotFound } from "../domain/Errors.js"
import type { PolicyRefused } from "../domain/Hooks.js"
import type { SessionWithUser } from "../domain/Schema.js"
import type { MfaRequired } from "../http/AuthApi.js"
import type { OriginNotAllowed } from "../http/OriginCheck.js"
import type { OneTapApiGroup, OneTapCallbackPayload, OneTapNonce, OneTapRejected } from "../one-tap/Api.js"
import { OneTapApi } from "../one-tap/Api.js"
import { sessionKey, sessionsKey } from "./AuthClient.js"
import { layerFetch, withoutPayload, withPayload } from "./Atoms.js"

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/**
 * Google's script is not on the page, or would not load.
 *
 * **Gotchas**
 *
 * A client-side condition and never a response: it carries no
 * `httpApiStatus` and appears in no endpoint's error union. A page seeing it
 * has no network to Google, a content-security policy that refuses
 * `accounts.google.com`, or an extension that removed the script.
 *
 * @category errors
 * @since 0.2.0
 */
export class OneTapUnavailable extends Schema.TaggedError<OneTapUnavailable>("effect-auth/one-tap/OneTapUnavailable")(
  "OneTapUnavailable",
  {
    reason: Schema.String
  },
  { description: "Google's One Tap script could not be loaded or is not present" }
) {}

// -----------------------------------------------------------------------------
// The script
// -----------------------------------------------------------------------------

/**
 * Where Google publishes the One Tap library.
 *
 * @category constructors
 * @since 0.2.0
 */
export const scriptUrl = "https://accounts.google.com/gsi/client"

const isRecord = (value: unknown): value is { readonly [key: string]: unknown } =>
  typeof value === "object" && value !== null

const isFunction = (value: unknown): value is (...args: ReadonlyArray<unknown>) => unknown =>
  typeof value === "function"

/**
 * The four functions this client calls on Google's global, narrowed off it
 * rather than declared over it.
 *
 * **Gotchas**
 *
 * Read through `Reflect.get` and narrowed with predicates, so that no part of
 * this module asserts a shape onto a global somebody else's script wrote. A
 * page where the script has not loaded, or where something has replaced it,
 * produces {@link OneTapUnavailable} instead of a `TypeError` three frames
 * down.
 *
 * @category models
 * @since 0.2.0
 */
export interface GoogleIdentity {
  readonly initialize: (config: { readonly [key: string]: unknown }) => void
  readonly prompt: () => void
  readonly cancel: () => void
  readonly disableAutoSelect: () => void
}

/**
 * Google's `google.accounts.id`, if it is there.
 *
 * @category combinators
 * @since 0.2.0
 */
export const identity: Effect.Effect<GoogleIdentity, OneTapUnavailable> = Effect.suspend(() => {
  const global: unknown = Reflect.get(globalThis, "google")
  const accounts = isRecord(global) ? global.accounts : undefined
  const id = isRecord(accounts) ? accounts.id : undefined
  if (!isRecord(id) || !isFunction(id.initialize) || !isFunction(id.prompt)) {
    return OneTapUnavailable.make({ reason: "google.accounts.id is not present on this page" })
  }
  const initialize = id.initialize
  const prompt = id.prompt
  const cancel = id.cancel
  const disableAutoSelect = id.disableAutoSelect
  return Effect.succeed({
    initialize: (config) => {
      initialize(config)
    },
    prompt: () => {
      prompt()
    },
    cancel: () => {
      if (isFunction(cancel)) cancel()
    },
    disableAutoSelect: () => {
      if (isFunction(disableAutoSelect)) disableAutoSelect()
    }
  })
})

/** The document, narrowed to the three things loading a script needs. */
interface Host {
  readonly find: (selector: string) => unknown
  readonly create: () => unknown
  readonly append: (element: unknown) => void
  readonly listen: (element: unknown, event: string, handler: () => void) => void
}

const host = (): Option.Option<Host> => {
  const document: unknown = Reflect.get(globalThis, "document")
  const querySelector = isRecord(document) ? document.querySelector : undefined
  const createElement = isRecord(document) ? document.createElement : undefined
  const head = isRecord(document) ? document.head : undefined
  const appendChild = isRecord(head) ? head.appendChild : undefined
  if (!isFunction(querySelector) || !isFunction(createElement) || !isFunction(appendChild)) return Option.none()
  return Option.some({
    find: (selector) => querySelector.call(document, selector),
    create: () => createElement.call(document, "script"),
    append: (element) => {
      appendChild.call(head, element)
    },
    listen: (element, event, handler) => {
      const addEventListener = isRecord(element) ? element.addEventListener : undefined
      if (isFunction(addEventListener)) addEventListener.call(element, event, handler)
    }
  })
}

/**
 * Puts Google's script on the page, once however many times this is called.
 *
 * **Details**
 *
 * Three states, and the DOM itself is what holds them: the library is already
 * present and there is nothing to do; a `<script>` for it is already in the
 * document and this waits on *that* element's own events; or there is neither,
 * and one is appended. That is why there is no module-level promise here — the
 * page is the shared state, and two clients built side by side do not race to
 * append two scripts.
 *
 * **Gotchas**
 *
 * Touches the DOM. Calling it outside a browser is {@link OneTapUnavailable},
 * not a crash.
 *
 * @category combinators
 * @since 0.2.0
 */
export const loadScript: Effect.Effect<void, OneTapUnavailable> = Effect.flatMap(Effect.result(identity), (found) =>
  Result.isSuccess(found)
    ? Effect.void
    : Effect.suspend(() =>
        Option.match(host(), {
          onNone: () => OneTapUnavailable.make({ reason: "there is no document to load the script into" }),
          onSome: (page) =>
            Effect.callback<void, OneTapUnavailable>((resume) => {
              const failure = () => resume(OneTapUnavailable.make({ reason: `${scriptUrl} could not be loaded` }))
              const existing = page.find(`script[src="${scriptUrl}"]`)
              if (isRecord(existing)) {
                page.listen(existing, "load", () => resume(Effect.void))
                page.listen(existing, "error", failure)
                return
              }
              const element = page.create()
              if (!isRecord(element)) {
                resume(OneTapUnavailable.make({ reason: "document.createElement did not answer an element" }))
                return
              }
              Reflect.set(element, "src", scriptUrl)
              Reflect.set(element, "async", true)
              Reflect.set(element, "defer", true)
              page.listen(element, "load", () => resume(Effect.void))
              page.listen(element, "error", failure)
              page.append(element)
            })
        })
      )
)

// -----------------------------------------------------------------------------
// Models
// -----------------------------------------------------------------------------

/**
 * The argument of {@link OneTapClient.callback}.
 *
 * @category models
 * @since 0.2.0
 */
export type Callback = OneTapCallbackPayload

/**
 * What {@link OneTapClient.callback} answers: a session, or the news that a
 * second factor is owed.
 *
 * @category models
 * @since 0.2.0
 */
export type SignInResult = SessionWithUser | MfaRequired

/**
 * What {@link OneTapClient.start} takes.
 *
 * @category models
 * @since 0.2.0
 */
export interface StartOptions {
  /** The Google client id, which must be the one the server's provider carries. */
  readonly clientId: string
  /**
   * The nonce this ceremony runs under — the `nonce` field of what
   * {@link OneTapClient.nonce} answered.
   *
   * **Gotchas**
   *
   * It is passed in rather than fetched here so that this function is the DOM
   * half and nothing else: the request that mints it also sets the cookie the
   * server compares against, and a page that has not made that request has
   * nothing for the server to compare with.
   */
  readonly nonce: string
  /** What to do with the credential Google produces. */
  readonly onCredential: (credential: string) => void
  /**
   * Anything else `google.accounts.id.initialize` accepts — `auto_select`,
   * `cancel_on_tap_outside`, `context`, `ux_mode`, `login_uri`.
   *
   * **Gotchas**
   *
   * `client_id`, `nonce` and `callback` in here are overwritten: they are the
   * three fields whose values have to be the ones the server will check
   * against.
   */
  readonly additionalOptions?: { readonly [key: string]: unknown } | undefined
  /** Whether to show the prompt immediately. Defaults to `true`. */
  readonly prompt?: boolean | undefined
}

/**
 * The options of {@link make}.
 *
 * @category models
 * @since 0.2.0
 */
export interface Options {
  /** Where the server is. Omit it for a same-origin deployment. */
  readonly baseUrl?: string | URL | undefined
  /** The transport. Defaults to `fetch` with the {@link Options.credentials} setting applied. */
  readonly httpClient?: Layer.Layer<HttpClient.HttpClient> | undefined
  /**
   * The `fetch` credentials mode, defaulting to `"include"`.
   *
   * **Gotchas**
   *
   * The nonce the callback is checked against is in a cookie the first request
   * set. `"omit"` makes every ceremony fail the binding check.
   */
  readonly credentials?: RequestCredentials | undefined
  /** Wraps the underlying `HttpClient`. */
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
export interface OneTapClient {
  /** The underlying `AtomHttpApi` service class. */
  readonly service: AtomHttpApi.AtomHttpApiClient<unknown, typeof serviceId, typeof OneTapApiGroup>
  /** The atom runtime the client's atoms run in. */
  readonly runtime: Atom.AtomRuntime<unknown>

  /** Asks the server for a nonce, which it also sets in a `__Host-` cookie. */
  readonly nonce: Atom.AtomResultFn<void, OneTapNonce, RateLimited>

  /**
   * Hands a credential back and, on success, sets the session cookie.
   * Invalidates `"auth.session"` and `"auth.sessions"`.
   */
  readonly callback: Atom.AtomResultFn<
    Callback,
    SignInResult,
    | OneTapRejected
    | OAuthProviderError
    | AccountAlreadyLinked
    | UserNotFound
    | PolicyRefused
    | OriginNotAllowed
    | RateLimited
  >

  /**
   * The whole ceremony's front half: load the script, take a nonce, initialise
   * Google's library with it.
   *
   * **Details**
   *
   * `onCredential` is handed the raw `credential`, which is what a page passes
   * to {@link OneTapClient.callback} beside the nonce it started with. Google
   * delivers a credential through a callback rather than a promise, so this is
   * where the two shapes meet, and it is deliberately the *only* place in this
   * module that does.
   *
   * @example
   * ```ts skip-type-checking
   * const { nonce } = yield* AuthClient.run(oneTap.nonce, undefined)
   * yield* oneTap.start({
   *   clientId,
   *   nonce,
   *   onCredential: (credential) => registry.set(oneTap.callback, { credential, nonce })
   * })
   * ```
   */
  readonly start: (options: StartOptions) => Effect.Effect<void, OneTapUnavailable>

  /**
   * Ends automatic sign-in for this browser. Call it when somebody signs out.
   *
   * **Details**
   *
   * `google.accounts.id.disableAutoSelect()` plus, where the browser has it,
   * `navigator.credentials.preventSilentAccess()` — the FedCM-era half, which
   * is what actually stops the mediation layer from re-offering the account.
   * Absent either one, the other still runs.
   */
  readonly preventSilentAccess: Effect.Effect<void>
}

const serviceId = "effect-auth/OneTapClient"

/**
 * Builds a {@link OneTapClient}.
 *
 * @category constructors
 * @since 0.2.0
 */
export const make = (options?: Options): OneTapClient => {
  const service = AtomHttpApi.Service()(serviceId, {
    api: OneTapApi,
    httpClient: options?.httpClient ?? layerFetch(options?.credentials ?? "include"),
    baseUrl: options?.baseUrl,
    transformClient: options?.transformClient,
    runtime: options?.runtime
  })

  const nonce = withoutPayload(service.mutation("oneTap", "nonce"), undefined)

  const start = (start: StartOptions): Effect.Effect<void, OneTapUnavailable> =>
    Effect.gen(function* () {
      yield* loadScript
      const google = yield* identity
      google.initialize({
        ...start.additionalOptions,
        nonce: start.nonce,
        callback: (response: unknown) => {
          const credential = isRecord(response) ? response.credential : undefined
          if (typeof credential === "string") start.onCredential(credential)
        },
        // Last, deliberately: whatever `additionalOptions` said about the client
        // id is overwritten, because this is the value the server will check the
        // token's audience against and a page that disagrees with it is a page
        // whose credentials will all be refused.
        client_id: start.clientId
      })
      if (start.prompt !== false) google.prompt()
    })

  const preventSilentAccess = Effect.gen(function* () {
    const google = yield* Effect.result(identity)
    if (Result.isSuccess(google)) google.success.disableAutoSelect()
    const navigator: unknown = Reflect.get(globalThis, "navigator")
    const credentials = isRecord(navigator) ? navigator.credentials : undefined
    const prevent = isRecord(credentials) ? credentials.preventSilentAccess : undefined
    if (isFunction(prevent)) {
      yield* Effect.ignore(Effect.promise(() => Promise.resolve(prevent.call(credentials))))
    }
  })

  return {
    service,
    runtime: service.runtime,
    nonce,
    // A sign-in: whatever an application derives from "who is signed in" has to
    // refetch, and the device list has a new entry in it.
    callback: withPayload<Callback>()(service.mutation("oneTap", "callback"), [sessionKey, sessionsKey]),
    start,
    preventSilentAccess
  }
}
