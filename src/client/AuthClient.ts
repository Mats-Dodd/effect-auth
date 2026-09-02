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
 * import { Predicate } from "effect"
 * import { AsyncResult } from "effect/unstable/reactivity"
 * import { AuthClient } from "effect-auth/client"
 *
 * declare const registry: import("effect/unstable/reactivity").AtomRegistry.AtomRegistry
 * const client = AuthClient.make({ baseUrl: "http://localhost:3000" })
 *
 * const render = AsyncResult.matchWithError(registry.get(client.session), {
 *   onInitial: () => "loading…",
 *   onSuccess: (_) => `signed in as ${_.value.user.email}`,
 *   onError: (error) => Predicate.isTagged(error, "Unauthorized") ? "signed out" : "unavailable",
 *   onDefect: () => "something went wrong"
 * })
 * ```
 *
 * @since 0.1.0
 */
import type { Redacted, Types } from "effect"
import { Effect, Layer, Predicate } from "effect"
import type { HttpClient } from "effect/unstable/http"
import { HttpClientRequest } from "effect/unstable/http"
import type { HttpApi, HttpApiGroup } from "effect/unstable/httpapi"
import { HttpApiMiddleware } from "effect/unstable/httpapi"
import type { AsyncResult, AtomRegistry } from "effect/unstable/reactivity"
import { Atom, AtomHttpApi } from "effect/unstable/reactivity"
import type {
  CannotUnlinkLastAccount,
  EmailNotVerified,
  EmailUnchanged,
  InvalidCredentials,
  InvalidToken,
  NotFound,
  OAuthProviderError,
  PasswordAlreadySet,
  PasswordPolicyViolation,
  RateLimited,
  StepUpRequired,
  TokenRefreshFailed,
  Unauthorized,
  UserAlreadyExists,
  UserNotFound
} from "../domain/Errors.js"
import type { PolicyRefused } from "../domain/Hooks.js"
import type {
  AccountPublic,
  SessionPublic,
  SessionWithUserOf,
  SignUpResponseOf,
  UserFields,
  UserModel,
  UserPublicOf
} from "../domain/Schema.js"
import {
  type AccessTokenResponse,
  type AccountSelection,
  AuthApi,
  type AuthApiGroupOf,
  type ChangeEmailPayload,
  type ChangePasswordPayload,
  type DeleteUserPayload,
  type DeleteUserResponse,
  type LinkSocialPayload,
  type OAuthRedirect,
  type MfaRequired,
  type Ok,
  type ReauthenticatePayload,
  type RefreshTokenResponse,
  type RequestPasswordResetPayload,
  type ResetPasswordPayload,
  type RevokeSessionPayload,
  type SendVerificationEmailPayload,
  type SetPasswordPayload,
  type SignInEmailPayload,
  type SignInSocialPayload,
  type SignUpEmailOf,
  type SignUpEmailPayload,
  type TokenQuery,
  type UnlinkAccountPayload,
  type UpdateUserOf,
  type VerifyEmailQuery
} from "../http/AuthApi.js"
import { Authenticated } from "../http/Middleware.js"
import type { OriginNotAllowed } from "../http/OriginCheck.js"
import type { PayloadRequest, ReactivityKeys as AtomReactivityKeys } from "./Atoms.js"
import { layerFetch, withoutPayload, withPayload, withQuery } from "./Atoms.js"

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
 * @since 0.1.0
 */
export const sessionKey = "auth.session"

/**
 * The reactivity key of the caller's list of sessions (the "active devices"
 * view). Invalidated by every revoke, and by a password change.
 *
 * @category constructors
 * @since 0.1.0
 */
export const sessionsKey = "auth.sessions"

/**
 * The reactivity key of the caller's list of linked sign-in methods.
 * Invalidated by `unlinkAccount`.
 *
 * @category constructors
 * @since 0.1.0
 */
export const accountsKey = "auth.accounts"

/**
 * The shape `Atom` accepts for invalidation keys.
 *
 * @category models
 * @since 0.1.0
 */
export type ReactivityKeys = AtomReactivityKeys

// -----------------------------------------------------------------------------
// Payload types
// -----------------------------------------------------------------------------

/**
 * The argument of {@link AuthClient.signUp}. `password` is a `Redacted<string>`
 * — wrap the plaintext with `Redacted.make` at the input boundary.
 *
 * **Details**
 *
 * The base half. A client built with a model carries
 * `SignUpEmailOf<F>` instead — the same fields, plus whichever of the
 * deployment's own a client may state.
 *
 * @category models
 * @since 0.1.0
 */
export type SignUpEmail = typeof SignUpEmailPayload.Type

/**
 * The argument of {@link AuthClient.signIn}.
 *
 * @category models
 * @since 0.1.0
 */
export type SignInEmail = typeof SignInEmailPayload.Type

/**
 * The argument of {@link AuthClient.revokeSession}.
 *
 * @category models
 * @since 0.1.0
 */
export type RevokeSession = typeof RevokeSessionPayload.Type

/**
 * The argument of {@link AuthClient.requestPasswordReset}.
 *
 * @category models
 * @since 0.1.0
 */
export type RequestPasswordReset = typeof RequestPasswordResetPayload.Type

/**
 * The argument of {@link AuthClient.resetPassword}.
 *
 * @category models
 * @since 0.1.0
 */
export type ResetPassword = typeof ResetPasswordPayload.Type

/**
 * The argument of {@link AuthClient.changePassword}.
 *
 * @category models
 * @since 0.1.0
 */
export type ChangePassword = typeof ChangePasswordPayload.Type

/**
 * The argument of {@link AuthClient.reauthenticate}.
 *
 * @category models
 * @since 0.2.0
 */
export type Reauthenticate = typeof ReauthenticatePayload.Type

/**
 * What a sign-in answers: a session, or the news that a second factor is owed.
 *
 * **Details**
 *
 * The `MfaRequired` member arrives on `202` and carries no user id, no address
 * and no token — the pending-authentication token is in a `__Host-` cookie the
 * browser attaches by itself. Discriminate on `_tag`: a `SessionWithUser` has
 * none, so `"_tag" in result` narrows both ways.
 *
 * @category models
 * @since 0.2.0
 */
export type SignInResult<F extends UserFields = {}> = SessionWithUserOf<F> | MfaRequired

/**
 * The argument of {@link AuthClient.sendVerificationEmail}.
 *
 * @category models
 * @since 0.1.0
 */
export type SendVerificationEmail = typeof SendVerificationEmailPayload.Type

/**
 * The argument of {@link AuthClient.verifyEmail}.
 *
 * @category models
 * @since 0.1.0
 */
export type VerifyEmail = typeof VerifyEmailQuery.Type

/**
 * The argument of {@link AuthClient.signInSocial}.
 *
 * @category models
 * @since 0.1.0
 */
export type SignInSocial = typeof SignInSocialPayload.Type

/**
 * The argument of {@link AuthClient.linkSocial}.
 *
 * @category models
 * @since 0.1.0
 */
export type LinkSocial = typeof LinkSocialPayload.Type

/**
 * The argument of {@link AuthClient.unlinkAccount}.
 *
 * @category models
 * @since 0.1.0
 */
export type UnlinkAccount = typeof UnlinkAccountPayload.Type

/**
 * The argument of {@link AuthClient.changeEmail}.
 *
 * @category models
 * @since 0.1.0
 */
export type ChangeEmail = typeof ChangeEmailPayload.Type

/**
 * The argument of {@link AuthClient.confirmEmailChange} and
 * {@link AuthClient.verifyEmailChange} — the token out of a mailed link.
 *
 * @category models
 * @since 0.1.0
 */
export type TokenArgument = typeof TokenQuery.Type

/**
 * The argument of {@link AuthClient.deleteUser}.
 *
 * @category models
 * @since 0.1.0
 */
export type DeleteUser = typeof DeleteUserPayload.Type

/**
 * The argument of {@link AuthClient.setPassword}.
 *
 * @category models
 * @since 0.1.0
 */
export type SetPassword = typeof SetPasswordPayload.Type

/**
 * The argument of {@link AuthClient.getAccessToken} and
 * {@link AuthClient.refreshToken}.
 *
 * @category models
 * @since 0.1.0
 */
export type SelectAccount = typeof AccountSelection.Type

// -----------------------------------------------------------------------------
// Options
// -----------------------------------------------------------------------------

/**
 * The options of {@link make}.
 *
 * @category models
 * @since 0.1.0
 */
export interface Options<
  ApiId extends string = string,
  Groups extends HttpApiGroup.Constraint = AuthApiGroupOf,
  F extends UserFields = {}
> {
  /**
   * Where the server is. Omit it when the auth endpoints are served from the
   * same origin as the page, which is the common — and the safest — case.
   */
  readonly baseUrl?: string | URL | undefined
  /**
   * The API to generate the client from. Defaults to {@link AuthApi}. Supply
   * the application's own composed API to keep one API value in the codebase —
   * the paths this client calls must be the ones the server serves.
   *
   * **Gotchas**
   *
   * `HttpApi` is invariant in its groups, so a composed API — `HttpApi.make("app")
   * .addHttpApi(AuthApi).add(TodosGroup)` — is not assignable to a parameter
   * fixed at `AuthApi`'s groups. Which is why this option is generic, exactly
   * as `AuthHandlers.layer` is on the server: the group set is inferred from
   * what is passed, and only `groups.auth` is constrained. It is constrained to
   * `effect-auth`'s own group, though, not merely to *a* group under that name,
   * so an API that re-declares `auth` — or one whose auth group carries a
   * different prefix, since `HttpApi.prefix` rewrites the endpoint paths in the
   * type — is rejected here rather than at the first mismatched request. The
   * atoms below stay typed by that group either way.
   */
  readonly api?:
    | (HttpApi.HttpApi<ApiId, Groups> & { readonly groups: { readonly auth: NoInfer<AuthApiGroupOf<F>> } })
    | undefined
  /**
   * The user model the API was declared with — `makeAuthApi(model)`'s.
   *
   * **When to use**
   *
   * Whenever {@link Options.api} was built from a model with custom user
   * fields. It is what types `session.user`, `signUp` and `signIn` with them.
   *
   * **Gotchas**
   *
   * Required in that case, not optional: the model cannot be recovered from the
   * API's type, so leaving it out makes the compiler read the API as the base
   * one and reject it. Leaving *both* out is the ordinary base-model client.
   */
  readonly model?: UserModel<F> | undefined
  /**
   * The transport. Defaults to `fetch` with the {@link Options.credentials}
   * setting applied. Replace it in tests, or to add retries and tracing.
   */
  readonly httpClient?: Layer.Layer<HttpClient.HttpClient> | undefined
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
  readonly bearerToken?: (() => string | Redacted.Redacted | undefined) | undefined
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
 * @since 0.1.0
 */
export interface AuthClient<F extends UserFields = {}> {
  /**
   * The underlying `AtomHttpApi` service class. Use it to reach an endpoint
   * this interface does not wrap, or to build a query with a different
   * time-to-live: `client.service.query("auth", "listSessions", {...})`.
   */
  readonly service: AtomHttpApi.AtomHttpApiClient<unknown, typeof serviceId, AuthApiGroupOf<F>>
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
  readonly session: Atom.Atom<AsyncResult.AsyncResult<SessionWithUserOf<F>, StepUpRequired | Unauthorized>>
  /**
   * The caller's unexpired sessions, keyed on {@link sessionsKey}.
   */
  readonly sessions: Atom.Atom<AsyncResult.AsyncResult<ReadonlyArray<SessionPublic>, StepUpRequired | Unauthorized>>
  /**
   * The caller's linked sign-in methods, keyed on {@link accountsKey}.
   */
  readonly accounts: Atom.Atom<AsyncResult.AsyncResult<ReadonlyArray<AccountPublic>, StepUpRequired | Unauthorized>>

  /** Creates an account. Invalidates {@link sessionKey}. */
  readonly signUp: Atom.AtomResultFn<
    SignUpEmailOf<F>,
    SignUpResponseOf<F>,
    UserAlreadyExists | PasswordPolicyViolation | PolicyRefused | RateLimited | OriginNotAllowed
  >
  /**
   * Signs in with an e-mail address and password. Invalidates
   * {@link sessionKey}.
   *
   * **Gotchas**
   *
   * The success is a union: a `SessionWithUser` when the sign-in completed, and
   * an `MfaRequired` — `202` — when a factor plugin owes a second factor and no
   * session was minted. Branch on `"_tag" in result` before reading `user`.
   */
  readonly signIn: Atom.AtomResultFn<
    SignInEmail,
    SignInResult<F>,
    InvalidCredentials | EmailNotVerified | PolicyRefused | RateLimited | OriginNotAllowed
  >
  /**
   * Proves the caller's password again, raising the session's assurance so an
   * endpoint that answered {@link StepUpRequired} will accept the next attempt.
   *
   * **Details**
   *
   * The session id survives — open tabs keep working — while its opaque token
   * is rotated and the cookie re-set. Invalidates {@link sessionKey}, because
   * the session it answers with is a new revision of the one every atom is
   * holding. See {@link withStepUp}, which runs it for you.
   */
  readonly reauthenticate: Atom.AtomResultFn<
    Reauthenticate,
    SessionWithUserOf<F>,
    InvalidCredentials | RateLimited | StepUpRequired | Unauthorized
  >
  /** Revokes the current session. Invalidates {@link sessionKey} and {@link sessionsKey}. */
  readonly signOut: Atom.AtomResultFn<void, Ok, StepUpRequired | Unauthorized>
  /** Revokes one of the caller's other sessions. Invalidates {@link sessionsKey}. */
  readonly revokeSession: Atom.AtomResultFn<RevokeSession, Ok, NotFound | StepUpRequired | Unauthorized>
  /** Revokes every session of the caller, this one included. */
  readonly revokeSessions: Atom.AtomResultFn<void, Ok, StepUpRequired | Unauthorized>
  /** Revokes every session of the caller except this one. */
  readonly revokeOtherSessions: Atom.AtomResultFn<void, Ok, StepUpRequired | Unauthorized>
  /** Asks for a reset link. Succeeds whether or not the address has an account. */
  readonly requestPasswordReset: Atom.AtomResultFn<RequestPasswordReset, Ok, RateLimited | OriginNotAllowed>
  /** Sets a new password from a reset token. Every session is revoked, so this invalidates {@link sessionKey}. */
  readonly resetPassword: Atom.AtomResultFn<ResetPassword, Ok, InvalidToken | PasswordPolicyViolation>
  /** Changes the caller's password. Requires a fresh session. */
  readonly changePassword: Atom.AtomResultFn<
    ChangePassword,
    Ok,
    InvalidCredentials | PasswordPolicyViolation | StepUpRequired | Unauthorized
  >
  /** Asks for a verification link. Succeeds whether or not the address has an account. */
  readonly sendVerificationEmail: Atom.AtomResultFn<SendVerificationEmail, Ok, RateLimited | OriginNotAllowed>
  /** Consumes a verification token. `emailVerified` changes, so this invalidates {@link sessionKey}. */
  readonly verifyEmail: Atom.AtomResultFn<VerifyEmail, Ok, InvalidToken>
  /** Begins an OAuth sign-in; succeeds with the URL to navigate to. See {@link AuthClient.signInSocialUrl}. */
  readonly signInSocial: Atom.AtomResultFn<
    SignInSocial,
    OAuthRedirect,
    OAuthProviderError | PolicyRefused | RateLimited
  >
  /** Begins linking a provider to the signed-in account. */
  readonly linkSocial: Atom.AtomResultFn<
    LinkSocial,
    OAuthRedirect,
    OAuthProviderError | PolicyRefused | StepUpRequired | Unauthorized
  >
  /** Removes one of the caller's sign-in methods. Invalidates {@link accountsKey}. */
  readonly unlinkAccount: Atom.AtomResultFn<
    UnlinkAccount,
    Ok,
    CannotUnlinkLastAccount | NotFound | StepUpRequired | Unauthorized
  >
  /**
   * Edits the caller's own profile. The session atom carries the user, so this
   * invalidates {@link sessionKey}.
   */
  readonly updateUser: Atom.AtomResultFn<
    UpdateUserOf<F>,
    { readonly user: UserPublicOf<F> },
    UserNotFound | StepUpRequired | Unauthorized
  >
  /**
   * Starts moving the account to another address. Succeeds whether or not the
   * address is free — see the endpoint. Nothing has changed when it returns, so
   * nothing is invalidated.
   */
  readonly changeEmail: Atom.AtomResultFn<
    ChangeEmail,
    Ok,
    EmailUnchanged | PolicyRefused | RateLimited | StepUpRequired | Unauthorized
  >
  /** Consumes the first-hop token, from the current address. */
  readonly confirmEmailChange: Atom.AtomResultFn<TokenArgument, Ok, InvalidToken>
  /** Consumes the second-hop token, from the new address. The address changes, so this invalidates {@link sessionKey}. */
  readonly verifyEmailChange: Atom.AtomResultFn<TokenArgument, Ok, InvalidToken | UserAlreadyExists>
  /**
   * Deletes the caller's own account, or asks for the confirmation mail that
   * will. Read `status` to tell the two apart — and invalidate either way, since
   * a `"Deleted"` answer means every atom below is now unauthorized.
   */
  readonly deleteUser: Atom.AtomResultFn<
    DeleteUser,
    DeleteUserResponse,
    InvalidCredentials | PolicyRefused | RateLimited | StepUpRequired | Unauthorized
  >
  /** Gives an account without one its first password. Invalidates {@link accountsKey}. */
  readonly setPassword: Atom.AtomResultFn<
    SetPassword,
    Ok,
    PasswordAlreadySet | PasswordPolicyViolation | RateLimited | StepUpRequired | Unauthorized
  >
  /** A usable provider access token for one of the caller's linked accounts. */
  readonly getAccessToken: Atom.AtomResultFn<
    SelectAccount,
    AccessTokenResponse,
    NotFound | TokenRefreshFailed | StepUpRequired | Unauthorized
  >
  /** Spends one of the caller's refresh tokens. */
  readonly refreshToken: Atom.AtomResultFn<
    SelectAccount,
    RefreshTokenResponse,
    NotFound | TokenRefreshFailed | StepUpRequired | Unauthorized
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
  ) => Effect.Effect<string, OAuthProviderError | PolicyRefused | RateLimited, AtomRegistry.AtomRegistry>
  /**
   * Starts an account link and answers the authorization URL to send the
   * browser to.
   */
  readonly linkSocialUrl: (
    payload: LinkSocial
  ) => Effect.Effect<
    string,
    OAuthProviderError | PolicyRefused | StepUpRequired | Unauthorized,
    AtomRegistry.AtomRegistry
  >
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
 * @since 0.1.0
 */
export const make = <
  ApiId extends string = string,
  Groups extends HttpApiGroup.Constraint = AuthApiGroupOf,
  F extends UserFields = {}
>(
  options?: Options<ApiId, Groups, F>
): AuthClient<F> => {
  const getToken = options?.bearerToken
  const httpClient = options?.httpClient ?? layerFetch(options?.credentials ?? "include")
  const forClient = HttpApiMiddleware.layerClient(Authenticated, ({ next, request }) => {
    const token = getToken?.()
    return next(token === undefined ? request : HttpClientRequest.bearerToken(request, token))
  })

  const service = AtomHttpApi.Service()(serviceId, {
    // The only cast in this module, and the boundary the `Options.api` signature
    // exists to make safe. `HttpApi` is invariant in its group union, so a
    // consumer's composed API is not assignable to `HttpApi<string, typeof
    // AuthApiGroup>` even though `Options.api` has already forced the compiler
    // to prove that its `groups.auth` *is* `typeof AuthApiGroup`. Narrowing the
    // union to that one group only removes groups this module never names: every
    // `service.query`/`service.mutation` call below asks for `"auth"`, and
    // `AtomHttpApi` derives its paths from `api.groups[group]`, so the requests
    // issued are the ones the consumer's own auth group declares, prefix
    // included. A consumer reaching its *other* groups builds its own client;
    // that is what `AuthClient.service` documents.
    //
    // (It goes via `unknown` because a one-step conversion is refused:
    // `HttpApi.prefix`'s return type makes the two sides non-overlapping to the
    // compiler's comparability check.)
    // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- REFACTOR.md §5 boundary cast
    api: (options?.api ?? AuthApi) as unknown as HttpApi.HttpApi<string, AuthApiGroupOf<F>>,
    httpClient: Layer.merge(httpClient, forClient),
    baseUrl: options?.baseUrl,
    transformClient: options?.transformClient,
    runtime: options?.runtime
  })

  const signInSocial = withPayload<SignInSocial>()(service.mutation("auth", "signInSocial"), undefined)
  const linkSocial = withPayload<LinkSocial>()(service.mutation("auth", "linkSocial"), undefined)

  // The second cast in this module, and the only one the custom-field
  // parameterization adds. `signUpEmail` is the one endpoint whose *payload*
  // type mentions `F`, and `HttpApiEndpoint.ClientRequest` branches on the
  // payload type to decide the request shape — a conditional over an `F` that is
  // still a type parameter stays deferred, so inside this function the mutation
  // atom's argument type has no writable form at all. At a call site, where `F`
  // is a concrete field map, that same type resolves to exactly what is stated
  // here; the success type needs no help, because it is a struct rather than a
  // conditional. Only the *argument* is being named: the atom, the request it
  // issues and the schema it encodes through are the ones `AtomHttpApi` built
  // from the API that was passed in.
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- REFACTOR.md §5 boundary cast
  const signUpMutation = service.mutation("auth", "signUpEmail") as unknown as Atom.AtomResultFn<
    PayloadRequest<SignUpEmailOf<F>>,
    SignUpResponseOf<F>,
    UserAlreadyExists | PasswordPolicyViolation | PolicyRefused | RateLimited | OriginNotAllowed
  >

  // The same cast, for the same reason, on the other endpoint whose *payload*
  // type mentions `F`. See the comment above: `HttpApiEndpoint.ClientRequest`
  // branches on the payload type, and a conditional over an unresolved `F` has no
  // writable form inside this function — while at a call site, where `F` is a
  // concrete field map, it resolves to exactly what is stated here.
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- REFACTOR.md §5 boundary cast
  const updateUserMutation = service.mutation("auth", "updateUser") as unknown as Atom.AtomResultFn<
    PayloadRequest<UpdateUserOf<F>>,
    { readonly user: UserPublicOf<F> },
    UserNotFound | Unauthorized
  >

  return {
    service,
    runtime: service.runtime,

    session: service.query("auth", "getSession", { reactivityKeys: [sessionKey] }),
    sessions: service.query("auth", "listSessions", { reactivityKeys: [sessionKey, sessionsKey] }),
    accounts: service.query("auth", "listAccounts", { reactivityKeys: [sessionKey, accountsKey] }),

    signUp: withPayload<SignUpEmailOf<F>>()(signUpMutation, [sessionKey]),
    signIn: withPayload<SignInEmail>()(service.mutation("auth", "signInEmail"), [sessionKey]),
    reauthenticate: withPayload<Reauthenticate>()(service.mutation("auth", "reauthenticate"), [sessionKey]),
    signOut: withoutPayload(service.mutation("auth", "signOut"), [sessionKey, sessionsKey]),
    revokeSession: withPayload<RevokeSession>()(service.mutation("auth", "revokeSession"), [sessionsKey]),
    revokeSessions: withoutPayload(service.mutation("auth", "revokeSessions"), [sessionKey, sessionsKey]),
    revokeOtherSessions: withoutPayload(service.mutation("auth", "revokeOtherSessions"), [sessionsKey]),
    requestPasswordReset: withPayload<RequestPasswordReset>()(
      service.mutation("auth", "requestPasswordReset"),
      undefined
    ),
    resetPassword: withPayload<ResetPassword>()(service.mutation("auth", "resetPassword"), [sessionKey, sessionsKey]),
    changePassword: withPayload<ChangePassword>()(service.mutation("auth", "changePassword"), [
      sessionKey,
      sessionsKey
    ]),
    sendVerificationEmail: withPayload<SendVerificationEmail>()(
      service.mutation("auth", "sendVerificationEmail"),
      undefined
    ),
    verifyEmail: withQuery<VerifyEmail>()(service.mutation("auth", "verifyEmail"), [sessionKey]),
    signInSocial,
    linkSocial,
    unlinkAccount: withPayload<UnlinkAccount>()(service.mutation("auth", "unlinkAccount"), [accountsKey]),

    updateUser: withPayload<UpdateUserOf<F>>()(updateUserMutation, [sessionKey]),
    changeEmail: withPayload<ChangeEmail>()(service.mutation("auth", "changeEmail"), undefined),
    confirmEmailChange: withQuery<TokenArgument>()(service.mutation("auth", "confirmEmailChange"), [sessionKey]),
    verifyEmailChange: withQuery<TokenArgument>()(service.mutation("auth", "verifyEmailChange"), [sessionKey]),
    // A `"Deleted"` answer leaves nothing behind, so every atom that reads the
    // caller goes with it. A `"ConfirmationSent"` one invalidates three atoms
    // that had not changed, which costs three refetches and no correctness.
    deleteUser: withPayload<DeleteUser>()(service.mutation("auth", "deleteUser"), [
      sessionKey,
      sessionsKey,
      accountsKey
    ]),
    setPassword: withPayload<SetPassword>()(service.mutation("auth", "setPassword"), [accountsKey]),
    getAccessToken: withPayload<SelectAccount>()(service.mutation("auth", "getAccessToken"), undefined),
    refreshToken: withPayload<SelectAccount>()(service.mutation("auth", "refreshToken"), undefined),

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
 * @since 0.1.0
 */
export const run = <Arg, A, E>(
  self: Atom.AtomResultFn<Arg, A, E>,
  arg: Arg
): Effect.Effect<A, E, AtomRegistry.AtomRegistry> =>
  Effect.flatMap(Atom.set(self, arg), () => Atom.getResult(self, { suspendOnWaiting: true }))

/**
 * Runs an effect, and when it is refused for want of assurance, steps up once
 * and runs it again.
 *
 * **When to use**
 *
 * Around any call to an endpoint that can answer `StepUpRequired` — changing a
 * password, unlinking a sign-in method, moving the address, deleting the
 * account. `onStepUp` is handed the refusal, so the prompt it puts up can name
 * the level that was wanted and offer exactly the factors
 * `error.current.available` lists; its job is to satisfy the requirement —
 * `AuthClient.run(client.reauthenticate, { password })` is the one this library
 * ships — and to fail if the person declines.
 *
 * **Details**
 *
 * Exactly one retry. A second `StepUpRequired` is returned to the caller rather
 * than looped on: if stepping up did not satisfy the policy, asking again will
 * not either, and a client that retried forever would be a way to make a person
 * approve a prompt they did not read.
 *
 * **Example**
 *
 * ```ts
 * import { Effect, Redacted } from "effect"
 * import { AuthClient } from "effect-auth/client"
 *
 * declare const client: AuthClient.AuthClient
 * declare const askForPassword: (available: ReadonlyArray<string>) => Effect.Effect<string>
 *
 * const change = AuthClient.withStepUp(
 *   AuthClient.run(client.changePassword, {
 *     currentPassword: Redacted.make("old"),
 *     newPassword: Redacted.make("new")
 *   }),
 *   (error) =>
 *     askForPassword(error.current.available).pipe(
 *       Effect.flatMap((password) =>
 *         AuthClient.run(client.reauthenticate, { password: Redacted.make(password) })
 *       )
 *     )
 * )
 * ```
 *
 * @category combinators
 * @since 0.2.0
 */
export const withStepUp = <A, E extends { readonly _tag: string }, R, E2, R2>(
  effect: Effect.Effect<A, E, R>,
  onStepUp: (error: Types.ExtractTag<E, "StepUpRequired">) => Effect.Effect<unknown, E2, R2>
): Effect.Effect<A, E | E2, R | R2> =>
  // `catchIf` with a named refinement rather than `catchTag`: `catchTag`'s tag
  // parameter is constrained by `Types.Tags<E>`, which TypeScript leaves
  // unresolved while `E` is a type parameter, so no literal satisfies it. The
  // refinement is built from `Predicate.isTagged` — the same test `catchTag`
  // runs underneath — and widened to the member of `E` that carries the tag, so
  // the handler still sees the refusal's own `current` field. The retry re-runs
  // `effect`, so the refusal is back in the error channel and the result is
  // `E | E2` however the first attempt failed.
  Effect.catchIf(
    effect,
    (error: E): error is Types.ExtractTag<E, "StepUpRequired"> => Predicate.isTagged(error, "StepUpRequired"),
    (error) => Effect.flatMap(onStepUp(error), () => effect)
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
 * @since 0.1.0
 */
export const navigate = (url: string): Effect.Effect<void> =>
  Effect.sync(() => {
    globalThis.location?.assign(url)
  })
