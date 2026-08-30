/**
 * The browser-facing client for `effect-auth`.
 *
 * {@link make} builds an [`AtomHttpApi`](https://effect.website) service around
 * the {@link AuthApi} declaration and hands back the atoms an application
 * actually wants: one `session` query, and one mutation per endpoint. The
 * mutations that change who is signed in carry the `"auth.session"` reactivity
 * key, so signing in, signing up, signing out or resetting a password refetches
 * the session atom by itself — no manual invalidation, no stale user in the
 * corner of the screen.
 *
 * This module is browser-safe: it imports schemas, the middleware *declaration*
 * and `fetch`, never a store, a hasher or a node builtin.
 *
 * **Reading a result**
 *
 * Every atom here holds an `AsyncResult`. `AtomHttpApi` turns transport
 * failures (a dead network, a CORS refusal) and decode failures into
 * **defects**, not typed errors — the typed error channel is exactly the
 * endpoint's declared error union. So match with `AsyncResult.matchWithError`,
 * which splits the failure case into `onError` (a `RateLimited`, an
 * `InvalidCredentials` — something the UI has a sentence for) and `onDefect`
 * (something went wrong that the contract never promised):
 *
 * ```ts
 * import { AsyncResult } from "effect/unstable/reactivity"
 * import { AuthClient } from "effect-auth/client"
 *
 * declare const registry: import("effect/unstable/reactivity").AtomRegistry.AtomRegistry
 * const client = AuthClient.make({ baseUrl: "http://localhost:3000" })
 *
 * const render = AsyncResult.matchWithError(registry.get(client.session), {
 *   onInitial: () => "loading…",
 *   onSuccess: (_) => `signed in as ${_.value.user.email}`,
 *   onError: (error) => error._tag === "Unauthorized" ? "signed out" : "unavailable",
 *   onDefect: () => "something went wrong"
 * })
 * ```
 *
 * @since 1.0.0
 */
import type { Layer as LayerType, Record, Redacted } from "effect"
import { Effect, Layer } from "effect"
import type { HttpClient } from "effect/unstable/http"
import { FetchHttpClient, HttpClientRequest } from "effect/unstable/http"
import type { HttpApi, HttpApiGroup } from "effect/unstable/httpapi"
import { HttpApiMiddleware } from "effect/unstable/httpapi"
import type { AsyncResult, AtomRegistry } from "effect/unstable/reactivity"
import { Atom, AtomHttpApi } from "effect/unstable/reactivity"
import type {
  CannotUnlinkLastAccount,
  EmailNotVerified,
  InvalidCredentials,
  InvalidToken,
  NotFound,
  OAuthProviderError,
  PasswordPolicyViolation,
  RateLimited,
  SessionNotFresh,
  Unauthorized,
  UserAlreadyExists
} from "../domain/Errors.js"
import type { AccountPublic, SessionPublic, SessionWithUser, SignUpResponse } from "../domain/Schema.js"
import type { OAuthRedirect, Ok } from "../http/AuthApi.js"
import {
  AuthApi,
  type AuthApiGroup,
  ChangePasswordPayload,
  LinkSocialPayload,
  RequestPasswordResetPayload,
  ResetPasswordPayload,
  RevokeSessionPayload,
  SendVerificationEmailPayload,
  SignInEmailPayload,
  SignInSocialPayload,
  SignUpEmailPayload,
  UnlinkAccountPayload,
  VerifyEmailQuery
} from "../http/AuthApi.js"
import { Authenticated } from "../http/Middleware.js"

// -----------------------------------------------------------------------------
// Reactivity keys
// -----------------------------------------------------------------------------

/**
 * The reactivity key of the current session.
 *
 * **Details**
 *
 * The `session` atom is registered under it, and every mutation that can change
 * who the caller is invalidates it. Application atoms that derive from "who is
 * signed in" — a profile query, a permissions query — should carry it too, so
 * that one sign-out refreshes all of them at once.
 *
 * @category constructors
 * @since 1.0.0
 */
export const sessionKey = "auth.session"

/**
 * The reactivity key of the caller's list of sessions (the "active devices"
 * view). Invalidated by every revoke, and by a password change.
 *
 * @category constructors
 * @since 1.0.0
 */
export const sessionsKey = "auth.sessions"

/**
 * The reactivity key of the caller's list of linked sign-in methods.
 * Invalidated by `unlinkAccount`.
 *
 * @category constructors
 * @since 1.0.0
 */
export const accountsKey = "auth.accounts"

/**
 * The shape `Atom` accepts for invalidation keys.
 *
 * @category models
 * @since 1.0.0
 */
export type ReactivityKeys =
  | ReadonlyArray<unknown>
  | Record.ReadonlyRecord<string, ReadonlyArray<unknown>>

// -----------------------------------------------------------------------------
// Payload types
// -----------------------------------------------------------------------------

/**
 * The argument of {@link AuthClient.signUp}. `password` is a `Redacted<string>`
 * — wrap the plaintext with `Redacted.make` at the input boundary.
 *
 * @category models
 * @since 1.0.0
 */
export type SignUpEmail = typeof SignUpEmailPayload.Type

/**
 * The argument of {@link AuthClient.signIn}.
 *
 * @category models
 * @since 1.0.0
 */
export type SignInEmail = typeof SignInEmailPayload.Type

/**
 * The argument of {@link AuthClient.revokeSession}.
 *
 * @category models
 * @since 1.0.0
 */
export type RevokeSession = typeof RevokeSessionPayload.Type

/**
 * The argument of {@link AuthClient.requestPasswordReset}.
 *
 * @category models
 * @since 1.0.0
 */
export type RequestPasswordReset = typeof RequestPasswordResetPayload.Type

/**
 * The argument of {@link AuthClient.resetPassword}.
 *
 * @category models
 * @since 1.0.0
 */
export type ResetPassword = typeof ResetPasswordPayload.Type

/**
 * The argument of {@link AuthClient.changePassword}.
 *
 * @category models
 * @since 1.0.0
 */
export type ChangePassword = typeof ChangePasswordPayload.Type

/**
 * The argument of {@link AuthClient.sendVerificationEmail}.
 *
 * @category models
 * @since 1.0.0
 */
export type SendVerificationEmail = typeof SendVerificationEmailPayload.Type

/**
 * The argument of {@link AuthClient.verifyEmail}.
 *
 * @category models
 * @since 1.0.0
 */
export type VerifyEmail = typeof VerifyEmailQuery.Type

/**
 * The argument of {@link AuthClient.signInSocial}.
 *
 * @category models
 * @since 1.0.0
 */
export type SignInSocial = typeof SignInSocialPayload.Type

/**
 * The argument of {@link AuthClient.linkSocial}.
 *
 * @category models
 * @since 1.0.0
 */
export type LinkSocial = typeof LinkSocialPayload.Type

/**
 * The argument of {@link AuthClient.unlinkAccount}.
 *
 * @category models
 * @since 1.0.0
 */
export type UnlinkAccount = typeof UnlinkAccountPayload.Type

// -----------------------------------------------------------------------------
// Options
// -----------------------------------------------------------------------------

/**
 * The options of {@link make}.
 *
 * @category models
 * @since 1.0.0
 */
export interface Options<
  ApiId extends string = string,
  Groups extends HttpApiGroup.Constraint = typeof AuthApiGroup
> {
  /**
   * Where the server is. Omit it when the auth endpoints are served from the
   * same origin as the page, which is the common — and the safest — case.
   */
  readonly baseUrl?: string | URL | undefined
  /**
   * The API to generate the client from. Defaults to {@link AuthApi}. Supply
   * the application's own composed API when it re-prefixed the auth group, or
   * simply to keep one API value in the codebase — the paths this client calls
   * must be the ones the server serves.
   *
   * **Gotchas**
   *
   * `HttpApi` is invariant in its groups, so a composed API — `HttpApi.make("app")
   * .addHttpApi(AuthApi).add(TodosGroup)` — is not assignable to a parameter
   * fixed at `AuthApi`'s groups. Which is why this option is generic, exactly
   * as `AuthHandlers.layer` is on the server: the group set is inferred from
   * what is passed, and only the `auth` group is required to be present. The
   * atoms below stay typed by `effect-auth`'s own group either way.
   */
  readonly api?:
    | (
      & HttpApi.HttpApi<ApiId, Groups>
      & { readonly groups: { readonly auth: HttpApiGroup.Constraint } }
    )
    | undefined
  /**
   * The transport. Defaults to `fetch` with the {@link Options.credentials}
   * setting applied. Replace it in tests, or to add retries and tracing.
   */
  readonly httpClient?: LayerType.Layer<HttpClient.HttpClient> | undefined
  /**
   * The `fetch` credentials mode, defaulting to `"include"` so that the session
   * cookie is sent on cross-origin requests too. Ignored when
   * {@link Options.httpClient} is supplied.
   */
  readonly credentials?: RequestCredentials | undefined
  /**
   * Returns the opaque session token to send as `Authorization: Bearer …`.
   *
   * **When to use**
   *
   * Only outside a browser — a mobile app, a CLI, a test — where there is no
   * cookie jar. In a browser leave it unset: the cookie is `httpOnly`, so
   * script cannot read it, which is the point.
   */
  readonly bearerToken?: (() => string | Redacted.Redacted<string> | undefined) | undefined
  /**
   * Wraps the underlying `HttpClient` — retries, logging, a timeout.
   */
  readonly transformClient?: ((client: HttpClient.HttpClient) => HttpClient.HttpClient) | undefined
  /**
   * The atom runtime factory. Defaults to `Atom.runtime`.
   */
  readonly runtime?: Atom.RuntimeFactory | undefined
}

// -----------------------------------------------------------------------------
// The client
// -----------------------------------------------------------------------------

/**
 * The atoms and helpers returned by {@link make}.
 *
 * **Details**
 *
 * Every member is an atom, so nothing here runs until something reads it. Read
 * a query with `registry.get` / a framework binding; run a mutation by writing
 * its argument to it (`registry.set(client.signIn, {...})`), or with
 * {@link run} from an `Effect`.
 *
 * @category models
 * @since 1.0.0
 */
export interface AuthClient {
  /**
   * The underlying `AtomHttpApi` service class. Use it to reach an endpoint
   * this interface does not wrap, or to build a query with a different
   * time-to-live: `client.service.query("auth", "listSessions", {...})`.
   */
  readonly service: AtomHttpApi.AtomHttpApiClient<unknown, typeof serviceId, typeof AuthApiGroup>
  /**
   * The atom runtime the client's atoms run in.
   */
  readonly runtime: Atom.AtomRuntime<unknown>

  /**
   * The current session and its user, keyed on {@link sessionKey}.
   *
   * **Gotchas**
   *
   * A signed-out visitor is an `Unauthorized` *failure*, not an empty success:
   * `AsyncResult.matchWithError`'s `onError` is where "show the sign-in form"
   * lives.
   */
  readonly session: Atom.Atom<AsyncResult.AsyncResult<SessionWithUser, Unauthorized>>
  /**
   * The caller's unexpired sessions, keyed on {@link sessionsKey}.
   */
  readonly sessions: Atom.Atom<AsyncResult.AsyncResult<ReadonlyArray<SessionPublic>, Unauthorized>>
  /**
   * The caller's linked sign-in methods, keyed on {@link accountsKey}.
   */
  readonly accounts: Atom.Atom<AsyncResult.AsyncResult<ReadonlyArray<AccountPublic>, Unauthorized>>

  /** Creates an account. Invalidates {@link sessionKey}. */
  readonly signUp: Atom.AtomResultFn<
    SignUpEmail,
    SignUpResponse,
    UserAlreadyExists | PasswordPolicyViolation | RateLimited
  >
  /** Signs in with an e-mail address and password. Invalidates {@link sessionKey}. */
  readonly signIn: Atom.AtomResultFn<
    SignInEmail,
    SessionWithUser,
    InvalidCredentials | EmailNotVerified | RateLimited
  >
  /** Revokes the current session. Invalidates {@link sessionKey} and {@link sessionsKey}. */
  readonly signOut: Atom.AtomResultFn<void, Ok, Unauthorized>
  /** Revokes one of the caller's other sessions. Invalidates {@link sessionsKey}. */
  readonly revokeSession: Atom.AtomResultFn<RevokeSession, Ok, NotFound | Unauthorized>
  /** Revokes every session of the caller, this one included. */
  readonly revokeSessions: Atom.AtomResultFn<void, Ok, Unauthorized>
  /** Revokes every session of the caller except this one. */
  readonly revokeOtherSessions: Atom.AtomResultFn<void, Ok, Unauthorized>
  /** Asks for a reset link. Succeeds whether or not the address has an account. */
  readonly requestPasswordReset: Atom.AtomResultFn<RequestPasswordReset, Ok, RateLimited>
  /** Sets a new password from a reset token. Every session is revoked, so this invalidates {@link sessionKey}. */
  readonly resetPassword: Atom.AtomResultFn<
    ResetPassword,
    Ok,
    InvalidToken | PasswordPolicyViolation
  >
  /** Changes the caller's password. Requires a fresh session. */
  readonly changePassword: Atom.AtomResultFn<
    ChangePassword,
    Ok,
    InvalidCredentials | SessionNotFresh | PasswordPolicyViolation | Unauthorized
  >
  /** Asks for a verification link. Succeeds whether or not the address has an account. */
  readonly sendVerificationEmail: Atom.AtomResultFn<SendVerificationEmail, Ok, RateLimited>
  /** Consumes a verification token. `emailVerified` changes, so this invalidates {@link sessionKey}. */
  readonly verifyEmail: Atom.AtomResultFn<VerifyEmail, Ok, InvalidToken>
  /** Begins an OAuth sign-in; succeeds with the URL to navigate to. See {@link AuthClient.signInSocialUrl}. */
  readonly signInSocial: Atom.AtomResultFn<SignInSocial, OAuthRedirect, OAuthProviderError | RateLimited>
  /** Begins linking a provider to the signed-in account. */
  readonly linkSocial: Atom.AtomResultFn<LinkSocial, OAuthRedirect, OAuthProviderError | Unauthorized>
  /** Removes one of the caller's sign-in methods. Invalidates {@link accountsKey}. */
  readonly unlinkAccount: Atom.AtomResultFn<
    UnlinkAccount,
    Ok,
    CannotUnlinkLastAccount | NotFound | SessionNotFresh | Unauthorized
  >

  /**
   * Starts an OAuth sign-in and answers the authorization URL to send the
   * browser to.
   *
   * **Example**
   *
   * ```ts
   * import { Effect } from "effect"
   * import { AuthClient } from "effect-auth/client"
   *
   * const client = AuthClient.make({ baseUrl: "http://localhost:3000" })
   *
   * const github = client.signInSocialUrl({ providerId: "github" }).pipe(
   *   Effect.flatMap(AuthClient.navigate)
   * )
   * ```
   */
  readonly signInSocialUrl: (
    payload: SignInSocial
  ) => Effect.Effect<string, OAuthProviderError | RateLimited, AtomRegistry.AtomRegistry>
  /**
   * Starts an account link and answers the authorization URL to send the
   * browser to.
   */
  readonly linkSocialUrl: (
    payload: LinkSocial
  ) => Effect.Effect<string, OAuthProviderError | Unauthorized, AtomRegistry.AtomRegistry>
}

const serviceId = "effect-auth/AuthClient"

/**
 * Builds an {@link AuthClient}.
 *
 * **Details**
 *
 * One client per application: it owns an atom runtime, and two clients would
 * mean two independent session atoms disagreeing about who is signed in.
 * Create it at module scope and import it where it is needed.
 *
 * **Example**
 *
 * ```ts
 * import { Redacted } from "effect"
 * import { AtomRegistry } from "effect/unstable/reactivity"
 * import { AuthClient } from "effect-auth/client"
 *
 * const client = AuthClient.make({ baseUrl: "http://localhost:3000" })
 * const registry = AtomRegistry.make()
 *
 * registry.mount(client.session)
 * registry.set(client.signIn, {
 *   email: "ada@example.com",
 *   password: Redacted.make("correct horse battery staple")
 * })
 * // the session atom refetches by itself: signIn carries the "auth.session" key
 * ```
 *
 * @category constructors
 * @since 1.0.0
 */
export const make = <
  ApiId extends string = string,
  Groups extends HttpApiGroup.Constraint = typeof AuthApiGroup
>(options?: Options<ApiId, Groups> | undefined): AuthClient => {
  const getToken = options?.bearerToken
  const httpClient = options?.httpClient ?? layerFetch(options?.credentials ?? "include")
  const forClient = HttpApiMiddleware.layerClient(Authenticated, ({ next, request }) => {
    const token = getToken?.()
    return next(token === undefined ? request : HttpClientRequest.bearerToken(request, token))
  })

  const service = AtomHttpApi.Service()(serviceId, {
    // The generic parameter above admits any API that carries an `auth` group;
    // the atoms this module publishes describe that one group, and reaching a
    // consumer's other groups is what `client.service` is for.
    api: (options?.api ?? AuthApi) as unknown as HttpApi.HttpApi<string, typeof AuthApiGroup>,
    httpClient: Layer.merge(httpClient, forClient),
    baseUrl: options?.baseUrl,
    transformClient: options?.transformClient,
    runtime: options?.runtime
  })

  const signInSocial = withPayload<SignInSocial>()(service.mutation("auth", "signInSocial"), undefined)
  const linkSocial = withPayload<LinkSocial>()(service.mutation("auth", "linkSocial"), undefined)

  return {
    service,
    runtime: service.runtime,

    session: service.query("auth", "getSession", { reactivityKeys: [sessionKey] }),
    sessions: service.query("auth", "listSessions", { reactivityKeys: [sessionKey, sessionsKey] }),
    accounts: service.query("auth", "listAccounts", { reactivityKeys: [sessionKey, accountsKey] }),

    signUp: withPayload<SignUpEmail>()(service.mutation("auth", "signUpEmail"), [sessionKey]),
    signIn: withPayload<SignInEmail>()(service.mutation("auth", "signInEmail"), [sessionKey]),
    signOut: withoutPayload(service.mutation("auth", "signOut"), [sessionKey, sessionsKey]),
    revokeSession: withPayload<RevokeSession>()(service.mutation("auth", "revokeSession"), [sessionsKey]),
    revokeSessions: withoutPayload(service.mutation("auth", "revokeSessions"), [sessionKey, sessionsKey]),
    revokeOtherSessions: withoutPayload(service.mutation("auth", "revokeOtherSessions"), [sessionsKey]),
    requestPasswordReset: withPayload<RequestPasswordReset>()(
      service.mutation("auth", "requestPasswordReset"),
      undefined
    ),
    resetPassword: withPayload<ResetPassword>()(
      service.mutation("auth", "resetPassword"),
      [sessionKey, sessionsKey]
    ),
    changePassword: withPayload<ChangePassword>()(
      service.mutation("auth", "changePassword"),
      [sessionKey, sessionsKey]
    ),
    sendVerificationEmail: withPayload<SendVerificationEmail>()(
      service.mutation("auth", "sendVerificationEmail"),
      undefined
    ),
    verifyEmail: withQuery<VerifyEmail>()(service.mutation("auth", "verifyEmail"), [sessionKey]),
    signInSocial,
    linkSocial,
    unlinkAccount: withPayload<UnlinkAccount>()(service.mutation("auth", "unlinkAccount"), [accountsKey]),

    signInSocialUrl: (payload) => Effect.map(run(signInSocial, payload), (_) => _.url),
    linkSocialUrl: (payload) => Effect.map(run(linkSocial, payload), (_) => _.url)
  }
}

// -----------------------------------------------------------------------------
// Running a mutation from an Effect
// -----------------------------------------------------------------------------

/**
 * Runs a mutation atom and waits for its result.
 *
 * **Details**
 *
 * Writing to a mutation atom is fire-and-forget: the write returns immediately
 * and the atom's `AsyncResult` moves to waiting. This waits for the write to
 * settle and rethrows the typed error, which is what an `Effect`-shaped caller
 * — a form submit handler, a test — wants.
 *
 * **Gotchas**
 *
 * The failure channel carries only the endpoint's declared errors. A transport
 * or decode failure arrives as a *defect*, so catch it with `Effect.result` /
 * `Effect.catchCause`, not `Effect.catchTag`.
 *
 * **Example**
 *
 * ```ts
 * import { Effect, Redacted } from "effect"
 * import { AuthClient } from "effect-auth/client"
 *
 * const client = AuthClient.make()
 *
 * const program = AuthClient.run(client.signIn, {
 *   email: "ada@example.com",
 *   password: Redacted.make("correct horse battery staple")
 * })
 * ```
 *
 * @category combinators
 * @since 1.0.0
 */
export const run = <Arg, A, E>(
  self: Atom.AtomResultFn<Arg, A, E>,
  arg: Arg
): Effect.Effect<A, E, AtomRegistry.AtomRegistry> =>
  Effect.flatMap(
    Atom.set(self, arg),
    () => Atom.getResult(self, { suspendOnWaiting: true })
  )

/**
 * Sends the browser to a URL.
 *
 * **Gotchas**
 *
 * A no-op where there is no `location` — a node test, a server render. Pair it
 * with {@link AuthClient.signInSocialUrl}, whose URL is produced by the server
 * and therefore needs no validation here.
 *
 * @category combinators
 * @since 1.0.0
 */
export const navigate = (url: string): Effect.Effect<void> =>
  Effect.sync(() => {
    globalThis.location?.assign(url)
  })

// -----------------------------------------------------------------------------
// internal
// -----------------------------------------------------------------------------

const layerFetch = (credentials: RequestCredentials): LayerType.Layer<HttpClient.HttpClient> =>
  Layer.provide(
    FetchHttpClient.layer,
    Layer.succeed(FetchHttpClient.RequestInit, { credentials })
  )

const isControl = (u: unknown): u is Atom.Reset | Atom.Interrupt => u === Atom.Reset || u === Atom.Interrupt

/**
 * Rewrites a mutation atom's argument.
 *
 * `AtomHttpApi.mutation` takes the whole client request plus the reactivity
 * keys; a caller should pass the payload and nothing else, with the keys of the
 * endpoint baked in. The wrapper reads the underlying atom — so it holds the
 * same `AsyncResult` — and translates writes.
 *
 * The underlying atom is typed `any` on purpose: `AtomHttpApi` computes the
 * argument as `Simplify<ClientRequest<…> & { reactivityKeys?: … }>`, which does
 * not spell out to anything nameable here. The three wrappers below are the
 * only callers, and each one's public signature is exact.
 */
const rewrite = <Arg, A, E>(
  self: Atom.AtomResultFn<any, A, E>,
  encode: (arg: Arg) => unknown
): Atom.AtomResultFn<Arg, A, E> =>
  Atom.writable<AsyncResult.AsyncResult<A, E>, Arg | Atom.Reset | Atom.Interrupt>(
    (get) => get(self),
    (ctx, value) => {
      ctx.set(self, isControl(value) ? value : encode(value))
    }
  )

const withPayload = <P>() =>
<A, E>(
  self: Atom.AtomResultFn<any, A, E>,
  reactivityKeys: ReactivityKeys | undefined
): Atom.AtomResultFn<P, A, E> => rewrite<P, A, E>(self, (payload) => ({ payload, reactivityKeys }))

const withQuery = <Q>() =>
<A, E>(
  self: Atom.AtomResultFn<any, A, E>,
  reactivityKeys: ReactivityKeys | undefined
): Atom.AtomResultFn<Q, A, E> => rewrite<Q, A, E>(self, (query) => ({ query, reactivityKeys }))

const withoutPayload = <A, E>(
  self: Atom.AtomResultFn<any, A, E>,
  reactivityKeys: ReactivityKeys | undefined
): Atom.AtomResultFn<void, A, E> => rewrite<void, A, E>(self, () => ({ reactivityKeys }))
