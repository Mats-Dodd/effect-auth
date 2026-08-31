/**
 * The server implementation of {@link AuthApiGroup}.
 *
 * Every handler here is deliberately thin: read the decoded request, call one
 * domain or OAuth service, translate the result into the endpoint's declared
 * response, and set or clear the session cookie. There is no policy in this
 * module — no freshness rule, no linking decision, no token arithmetic — because
 * all of that belongs to services that a non-HTTP transport could reuse
 * unchanged.
 *
 * **Details**
 *
 * {@link layer} is a factory rather than a prebuilt layer. The service a group
 * implementation provides is typed by the *consuming* API's identifier, so a
 * layer built against a fixed `HttpApi` could never satisfy
 * `HttpApiBuilder.layer` for somebody else's API. Passing the API in lets the
 * identifier infer, and — because the group carries its own routes — means the
 * routes registered are the ones that API actually declares, prefix included.
 *
 * **Gotchas**
 *
 * Two error tags never reach a caller. `PersistenceError` and
 * `PasswordHashError` are server faults: they are turned into defects here, so
 * they render as `500` and stay out of every endpoint's error union.
 *
 * @since 1.0.0
 */
import type { Layer } from "effect"
import { Effect, Option, Redacted } from "effect"
import type { HttpServerRequest } from "effect/unstable/http"
import { HttpServerResponse } from "effect/unstable/http"
import { RateLimiter } from "effect/unstable/persistence"
import type { HttpApi, HttpApiGroup } from "effect/unstable/httpapi"
import { HttpApiBuilder, HttpApiSchema } from "effect/unstable/httpapi"
import type { AuthConfigService } from "../config/AuthConfig.js"
import { AuthConfig } from "../config/AuthConfig.js"
import { Accounts } from "../domain/Accounts.js"
import { OAuthProviderError, PasswordHashError } from "../domain/Errors.js"
import { Passwords, passwordsOf } from "../domain/Passwords.js"
import type { UserFields, UserModel } from "../domain/Schema.js"
import { baseUserModel } from "../domain/Schema.js"
import { Sessions, sessionsOf } from "../domain/Sessions.js"
import { PersistenceError } from "../domain/Stores.js"
import { OAuthFlow, withErrorCode } from "../oauth/Flow.js"
import type { AuthApiGroupOf } from "./AuthApi.js"
import { AuthApiGroup } from "./AuthApi.js"
import type { Authenticated } from "./Middleware.js"
import { CurrentSession, currentUserOf } from "./Middleware.js"
import { clearSessionCookie, setSessionCookie } from "./MiddlewareLive.js"
import { resolveUrl, validateUrl } from "./OriginCheck.js"
import type { Bucket } from "./RateLimits.js"
import { clientAddress, consumeWith, credentials, email as emailBucket } from "./RateLimits.js"

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/** Everything a caller is allowed to see — see {@link serverFault}. */
const isCallerError = <E>(error: E): error is Exclude<E, PasswordHashError | PersistenceError> =>
  !(error instanceof PasswordHashError) && !(error instanceof PersistenceError)

/**
 * Turns the two server-fault errors into defects.
 *
 * **Details**
 *
 * `PersistenceError` and `PasswordHashError` mean the deployment is broken, not
 * that the caller did anything wrong: neither appears in an endpoint's declared
 * error union, and both must render as an opaque `500` with the cause in the
 * logs. Every handler that calls a domain service therefore ends in this, which
 * is the one place that translation happens — and the return type is what makes
 * the compiler agree that no endpoint declares them.
 *
 * @category combinators
 * @since 1.0.0
 */
export const serverFault = <A, E, R>(
  effect: Effect.Effect<A, E, R>
): Effect.Effect<A, Exclude<E, PasswordHashError | PersistenceError>, R> =>
  Effect.catch(effect, (error) => isCallerError(error) ? Effect.fail(error) : Effect.die(error))

/**
 * What the session row records about the client that created it.
 *
 * **Gotchas**
 *
 * The address is derived from the same configurable header chain the rate
 * limiter uses, and is therefore only as trustworthy as the proxy in front of
 * this process. It is recorded so a person can recognise their own devices in a
 * session list; nothing authorizes on it.
 *
 * @category combinators
 * @since 1.0.0
 */
export const clientMeta = (
  config: AuthConfigService,
  request: HttpServerRequest.HttpServerRequest
): { readonly ipAddress: string | null; readonly userAgent: string | null } => ({
  ipAddress: Option.getOrNull(clientAddress(config, request)),
  userAgent: request.headers["user-agent"] ?? null
})

/**
 * The response for an endpoint whose feature is switched off.
 *
 * **Details**
 *
 * `emailPassword.enabled` decides whether the credential endpoints are served
 * at all, but the endpoints are *declared* unconditionally — a schema-driven API
 * has one shape, not one per configuration. A disabled endpoint therefore
 * answers `404`, which is what "this deployment does not serve that" means over
 * HTTP, rather than inventing an error the contract does not mention.
 *
 * @category constructors
 * @since 1.0.0
 */
export const notServed: HttpServerResponse.HttpServerResponse = HttpServerResponse.empty({ status: 404 })

/**
 * The body-less `302` the OAuth callback answers with.
 *
 * @category constructors
 * @since 1.0.0
 */
export const redirectTo = (location: string) =>
  HttpApiSchema.withHeaders({
    body: undefined,
    headers: { location }
  })

/**
 * The `{ success: true }` body shared by every acknowledged endpoint.
 *
 * @category constructors
 * @since 1.0.0
 */
export const acknowledged = { success: true } as const

// -----------------------------------------------------------------------------
// Layer
// -----------------------------------------------------------------------------

/**
 * The services the handlers need.
 *
 * **Gotchas**
 *
 * `OAuthFlow` is deliberately absent. It is looked up with
 * `Effect.serviceOption`, so a deployment that configures no OAuth provider
 * neither provides it nor needs an `HttpClient`; the three OAuth endpoints then
 * answer `UnknownProvider` instead of failing to build.
 *
 * @category models
 * @since 1.0.0
 */
export type HandlerServices =
  | AuthConfig
  | Sessions
  | Passwords
  | Accounts
  | Authenticated
  | RateLimiter.RateLimiter

/**
 * Implements the `auth` group of an `HttpApi` that contains it.
 *
 * **Example**
 *
 * ```ts
 * import { HttpApi } from "effect/unstable/httpapi"
 * import { AuthApi, AuthHandlers } from "effect-auth"
 *
 * const MyApi = HttpApi.make("app").addHttpApi(AuthApi)
 * const HandlersLive = AuthHandlers.layer(MyApi)
 * ```
 *
 * **Example** (a deployment with its own user fields)
 *
 * ```ts
 * import { HttpApi } from "effect/unstable/httpapi"
 * import { AuthHandlers, makeAuthApi, makeUserModel } from "effect-auth"
 *
 * const model = makeUserModel({})
 * const MyApi = HttpApi.make("app").addHttpApi(makeAuthApi(model))
 * const HandlersLive = AuthHandlers.layer(MyApi, model)
 * ```
 *
 * **Details**
 *
 * The second parameter is the model the API was declared with. It is what makes
 * sign-up accept a deployment's own fields and the three user-bearing endpoints
 * answer with them; the layer's *type* does not move, because the model reaches
 * the services through typed views of the keys they already occupy.
 *
 * **Gotchas**
 *
 * The API passed here must be the same value passed to `HttpApiBuilder.layer`.
 * The routes are read off the group *it* carries, so an API whose prefix was
 * changed after this call would serve the old paths.
 *
 * Its `auth` group must be this library's own — {@link AuthApiGroup} when no
 * model is passed, `makeAuthApiGroup(model)`'s when one is. Any group set is
 * accepted around it, but a group merely *named* `auth`, one built from a
 * *different* model, or `AuthApiGroup` re-prefixed with `HttpApi.prefix` (which
 * rewrites the endpoint paths in the type), is rejected here rather than
 * mis-served at runtime.
 *
 * @category layers
 * @since 1.0.0
 */
export const layer = <ApiId extends string, Groups extends HttpApiGroup.Constraint, F extends UserFields = {}>(
  // `NoInfer`, so that `F` comes from the model alone and the API is *checked*
  // against the group that model declares. It is what makes both mistakes a
  // compile error rather than a silent one: a parameterized API served by
  // handlers built without its model (`F` falls back to `{}`, and the API's
  // group is not `AuthApiGroupOf<{}>`), and the base API served with somebody's
  // model. Without it the compiler would also read `F` off the group's own inner
  // types, where it appears as `BaseUserFields & F`, and report the mismatch
  // between two spellings of the same thing.
  api:
    & HttpApi.HttpApi<ApiId, Groups>
    & { readonly groups: { readonly auth: NoInfer<AuthApiGroupOf<F>> } },
  model?: UserModel<F>
): Layer.Layer<
  HttpApiGroup.Service<ApiId, "auth">,
  never,
  HandlerServices
> =>
  // Two branches because `UserModel<F>` and `UserModel<{}>` are different types:
  // "the model, or the base one" is a choice that has to be made before anything
  // is built with it.
  model === undefined ? build(api, baseUserModel) : build(api, model)

const build = <ApiId extends string, Groups extends HttpApiGroup.Constraint, F extends UserFields>(
  api: HttpApi.HttpApi<ApiId, Groups>,
  model: UserModel<F>
): Layer.Layer<
  HttpApiGroup.Service<ApiId, "auth">,
  never,
  HandlerServices
> => {
  const CurrentUser = currentUserOf(model)
  return HttpApiBuilder.group(
    // The only cast in this module, and the boundary the whole signature exists
    // to make safe. `HttpApi` is invariant in its group union, so a consumer's
    // composed API — `HttpApi.make("app").addHttpApi(AuthApi).add(TodosGroup)` —
    // is not assignable to `HttpApi<ApiId, typeof AuthApiGroup>`, even though it
    // demonstrably contains that exact group: `layer`'s parameter requires
    // `groups.auth` to *be* the group the model passed alongside it declares,
    // checked by the compiler at every call site. `HttpApiBuilder.group` reads
    // nothing but `api.groups["auth"]` (see its implementation), so narrowing
    // the union it sees to the one group named here cannot change what runs, and
    // the routes still come off the consumer's own group value.
    //
    // It narrows to the *base* group rather than to `AuthApiGroupOf<F>`, which
    // is what lets the nineteen handlers below be type-checked once instead of
    // once per deployment. An endpoint whose payload type mentions `F` has a
    // request shape TypeScript cannot resolve — `HttpApiEndpoint`'s
    // `RequestFromParts` branches on the payload type, and a conditional over an
    // unresolved `F` stays deferred, so `payload` would have no readable
    // properties at all. The difference between the two groups is confined to
    // three endpoints, and in both directions it is a widening this module
    // honours: sign-up *receives* a payload with the model's extra fields on it
    // (recovered, typed, through `model.extrasOf`) and the three user-bearing
    // endpoints *answer* with a user that has them (produced by
    // `model.toPublic`). Encoding and decoding are done by the consumer's own
    // group either way, so the extras are on the wire whatever this narrowing
    // says.
    //
    // (It goes via `unknown` because a one-step conversion is refused:
    // `HttpApi.prefix`'s return type makes the two sides non-overlapping to the
    // compiler's comparability check.)
    api as unknown as HttpApi.HttpApi<ApiId, typeof AuthApiGroup>,
    "auth",
    (handlers) =>
      Effect.gen(function*() {
        const config = yield* AuthConfig
        // The two services that answer with users are read through the model's
        // typed view of their key: the same slot, a shape that carries the
        // deployment's own fields.
        const sessions = yield* sessionsOf(model)
        const passwords = yield* passwordsOf(model)
        const accounts = yield* Accounts
        const limiter = yield* RateLimiter.RateLimiter
        // Resolved once, and optional: see `HandlerServices`.
        const flow = yield* Effect.serviceOption(OAuthFlow)

        // Every service is resolved here, when the layer is built, so that no
        // handler carries a request-time requirement: anything left in a
        // handler's environment becomes a router-scoped service the consumer
        // would have to provide per request.
        const rateLimit = (bucket: Bucket, request: HttpServerRequest.HttpServerRequest) =>
          consumeWith({ config, limiter, bucket, request })

        const unknownProvider = (providerId: string) =>
          new OAuthProviderError({ providerId, reason: "UnknownProvider" })

        return handlers
          .handle("signUpEmail", ({ payload, request }) =>
            Effect.gen(function*() {
              yield* rateLimit(credentials, request)
              if (!config.emailPassword.enabled) return notServed
              // `payload` carries whatever custom fields the deployment's model
              // declared — this handler is checked against the base group, so
              // the model is what recovers them, at the type level as well as at
              // run time. A deployment that declared none contributes `{}`.
              const result = yield* passwords.signUp({
                ...payload,
                ...model.extrasOf(payload, "jsonCreate"),
                callbackURL: Option.getOrUndefined(validateUrl(config, payload.callbackURL)),
                ...clientMeta(config, request)
              }).pipe(serverFault)

              if (Option.isNone(result.session)) {
                // Verification is required, or auto sign-in is off: the user
                // exists but has no session, and no cookie is written.
                return { user: model.toPublic(result.user), session: null }
              }
              const { session, token } = result.session.value
              yield* setSessionCookie(config, session, token, { persistent: payload.rememberMe !== false })
              return { user: model.toPublic(result.user), session }
            }))
          .handle("signInEmail", ({ payload, request }) =>
            Effect.gen(function*() {
              yield* rateLimit(credentials, request)
              if (!config.emailPassword.enabled) return notServed
              const result = yield* passwords.signIn({
                email: payload.email,
                password: payload.password,
                rememberMe: payload.rememberMe,
                ...clientMeta(config, request)
              }).pipe(serverFault)

              yield* setSessionCookie(config, result.session, result.token, {
                persistent: payload.rememberMe !== false
              })
              return { user: model.toPublic(result.user), session: result.session }
            }))
          .handle("signOut", () =>
            Effect.gen(function*() {
              const session = yield* CurrentSession
              yield* sessions.signOut(session).pipe(serverFault)
              yield* clearSessionCookie(config)
              return acknowledged
            }))
          .handle("getSession", () =>
            Effect.gen(function*() {
              // The middleware has already verified, refreshed and — when the
              // expiry moved — re-set the cookie.
              const user = yield* CurrentUser
              const session = yield* CurrentSession
              return { user: model.toPublic(user), session }
            }))
          .handle("listSessions", () =>
            Effect.gen(function*() {
              const user = yield* CurrentUser
              return yield* sessions.list(user.id).pipe(serverFault)
            }))
          .handle("revokeSession", ({ payload }) =>
            Effect.gen(function*() {
              const user = yield* CurrentUser
              yield* sessions.revoke(payload.sessionId, user.id).pipe(serverFault)
              return acknowledged
            }))
          .handle("revokeSessions", () =>
            Effect.gen(function*() {
              const user = yield* CurrentUser
              yield* sessions.revokeAll(user.id).pipe(serverFault)
              // This one revoked the caller's own session too.
              yield* clearSessionCookie(config)
              return acknowledged
            }))
          .handle("revokeOtherSessions", () =>
            Effect.gen(function*() {
              const user = yield* CurrentUser
              const session = yield* CurrentSession
              yield* sessions.revokeOthers(user.id, session.id).pipe(serverFault)
              return acknowledged
            }))
          .handle("requestPasswordReset", ({ payload, request }) =>
            Effect.gen(function*() {
              yield* rateLimit(emailBucket, request)
              if (!config.emailPassword.enabled) return notServed
              // Answers the same whether or not the address has an account.
              yield* passwords.requestReset({
                email: payload.email,
                redirectTo: Option.getOrUndefined(validateUrl(config, payload.redirectTo))
              }).pipe(serverFault)
              return acknowledged
            }))
          .handle("resetPassword", ({ payload }) =>
            Effect.gen(function*() {
              if (!config.emailPassword.enabled) return notServed
              yield* passwords.resetPassword({
                token: payload.token,
                newPassword: payload.newPassword
              }).pipe(serverFault)
              // Every session was revoked, this browser's included.
              yield* clearSessionCookie(config)
              return acknowledged
            }))
          .handle("changePassword", ({ payload }) =>
            Effect.gen(function*() {
              if (!config.emailPassword.enabled) return notServed
              const user = yield* CurrentUser
              const session = yield* CurrentSession
              // A stolen but stale cookie must not be enough to take the
              // account over permanently: the caller has to have signed in
              // recently, as well as knowing the current password.
              yield* sessions.requireFresh(session)
              yield* passwords.changePassword({
                userId: user.id,
                currentPassword: payload.currentPassword,
                newPassword: payload.newPassword,
                revokeOtherSessions: payload.revokeOtherSessions,
                currentSessionId: session.id
              }).pipe(serverFault)
              return acknowledged
            }))
          .handle("sendVerificationEmail", ({ payload, request }) =>
            Effect.gen(function*() {
              yield* rateLimit(emailBucket, request)
              if (!config.emailPassword.enabled) return notServed
              yield* passwords.sendVerificationEmail({
                email: payload.email,
                callbackURL: Option.getOrUndefined(validateUrl(config, payload.callbackURL))
              }).pipe(serverFault)
              return acknowledged
            }))
          .handle("verifyEmail", ({ query }) =>
            Effect.gen(function*() {
              if (!config.emailPassword.enabled) return notServed
              // A query parameter is decoded as a plain string — query strings
              // do not go through the JSON codec — so it is redacted here,
              // before anything can log it. `query.callbackURL` is accepted and
              // ignored: the link an e-mail carries has one appended to it, and
              // this endpoint answers JSON rather than a redirect.
              yield* passwords.verifyEmail(Redacted.make(query.token)).pipe(serverFault)
              return acknowledged
            }))
          .handle("signInSocial", ({ payload, request }) =>
            Effect.gen(function*() {
              // Unauthenticated, and every call writes a state row. Without a
              // counter it is a free way to grow the verifications table — and
              // therefore to slow the indexed lookup every callback and reset
              // depends on. It shares the credentials policy, not its counter:
              // the key carries the path.
              yield* rateLimit(credentials, request)
              if (Option.isNone(flow)) {
                return yield* Effect.fail(unknownProvider(payload.providerId))
              }
              const started = yield* flow.value.start({
                providerId: payload.providerId,
                callbackURL: payload.callbackURL,
                errorCallbackURL: payload.errorCallbackURL,
                scopes: payload.scopes,
                rememberMe: payload.rememberMe
              }).pipe(serverFault)
              return { url: started.url, redirect: true }
            }))
          .handle("oauthCallback", ({ params, query, request }) =>
            Effect.gen(function*() {
              if (Option.isNone(flow)) {
                return redirectTo(withErrorCode(resolveUrl(config, null), "unknown_provider"))
              }
              // `complete` resolves every failure into a validated redirect: the
              // browser arrived here by a top-level navigation and must leave by
              // one, whatever happened.
              const outcome = yield* flow.value.complete({
                providerId: params.providerId,
                code: query.code,
                state: query.state,
                error: query.error,
                ...clientMeta(config, request)
              }).pipe(serverFault)

              if (outcome._tag === "Success" && outcome.session !== null && outcome.token !== null) {
                // Null for a link flow: the person was already signed in, and a
                // second session would be a silent session upgrade.
                // `rememberMe` travelled in the state row, so the choice made
                // when the flow started decides the cookie's persistence here,
                // exactly as it does on the password path.
                yield* setSessionCookie(config, outcome.session, outcome.token, {
                  persistent: outcome.rememberMe
                })
              }
              return redirectTo(outcome.redirectTo)
            }))
          .handle("listAccounts", () =>
            Effect.gen(function*() {
              const user = yield* CurrentUser
              return yield* accounts.listForUser(user.id).pipe(serverFault)
            }))
          .handle("linkSocial", ({ payload }) =>
            Effect.gen(function*() {
              if (Option.isNone(flow)) {
                return yield* Effect.fail(unknownProvider(payload.providerId))
              }
              const user = yield* CurrentUser
              const started = yield* flow.value.start({
                providerId: payload.providerId,
                callbackURL: payload.callbackURL,
                errorCallbackURL: payload.errorCallbackURL,
                scopes: payload.scopes,
                linkUserId: user.id
              }).pipe(serverFault)
              return { url: started.url, redirect: true }
            }))
          .handle("unlinkAccount", ({ payload }) =>
            Effect.gen(function*() {
              const user = yield* CurrentUser
              const session = yield* CurrentSession
              yield* sessions.requireFresh(session)
              yield* accounts.unlink(payload.accountId, user.id).pipe(serverFault)
              return acknowledged
            }))
      })
  )
}
