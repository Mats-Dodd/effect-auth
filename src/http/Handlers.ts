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
import { OAuthProviderError } from "../domain/Errors.js"
import { Passwords } from "../domain/Passwords.js"
import { Sessions } from "../domain/Sessions.js"
import { OAuthFlow, withErrorCode } from "../oauth/Flow.js"
import { AuthApiGroup } from "./AuthApi.js"
import type { Authenticated } from "./Middleware.js"
import { CurrentSession, CurrentUser } from "./Middleware.js"
import { clearSessionCookie, setSessionCookie } from "./MiddlewareLive.js"
import { resolveUrl, validateUrl } from "./OriginCheck.js"
import type { Bucket } from "./RateLimits.js"
import { clientAddress, consumeWith, credentials, email as emailBucket } from "./RateLimits.js"

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

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
 * **Gotchas**
 *
 * The API passed here must be the same value passed to `HttpApiBuilder.layer`.
 * The routes are read off the group *it* carries, so an API whose prefix was
 * changed after this call would serve the old paths.
 *
 * Its `auth` group must be {@link AuthApiGroup} itself. Any group set is
 * accepted around it — that is what the generic is for — but a group merely
 * *named* `auth`, or `AuthApiGroup` re-prefixed with `HttpApi.prefix` (which
 * rewrites the endpoint paths in the type), is rejected here rather than
 * mis-served at runtime.
 *
 * @category layers
 * @since 1.0.0
 */
export const layer = <ApiId extends string, Groups extends HttpApiGroup.Constraint>(
  api:
    & HttpApi.HttpApi<ApiId, Groups>
    & { readonly groups: { readonly auth: typeof AuthApiGroup } }
): Layer.Layer<
  HttpApiGroup.Service<ApiId, "auth">,
  never,
  HandlerServices
> =>
  HttpApiBuilder.group(
    // The only cast in this module, and the boundary the whole signature exists
    // to make safe. `HttpApi` is invariant in its group union, so a consumer's
    // composed API — `HttpApi.make("app").addHttpApi(AuthApi).add(TodosGroup)` —
    // is not assignable to `HttpApi<ApiId, typeof AuthApiGroup>`, even though it
    // demonstrably contains that exact group: the parameter's intersection
    // requires `groups.auth` to *be* `typeof AuthApiGroup`, checked by the
    // compiler at every call site. `HttpApiBuilder.group` reads nothing but
    // `api.groups["auth"]` (see its implementation), so narrowing the union it
    // sees to the one group named here cannot change what runs, and the routes
    // still come off the consumer's own group value.
    // (It goes via `unknown` because a one-step conversion is refused:
    // `HttpApi.prefix`'s return type makes the two sides non-overlapping to the
    // compiler's comparability check.)
    api as unknown as HttpApi.HttpApi<ApiId, typeof AuthApiGroup>,
    "auth",
    (handlers) =>
      Effect.gen(function*() {
        const config = yield* AuthConfig
        const sessions = yield* Sessions
        const passwords = yield* Passwords
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
              const result = yield* passwords.signUp({
                name: payload.name,
                email: payload.email,
                password: payload.password,
                image: payload.image,
                callbackURL: Option.getOrUndefined(validateUrl(config, payload.callbackURL)),
                rememberMe: payload.rememberMe,
                ...clientMeta(config, request)
              }).pipe(Effect.catchTag(["PasswordHashError", "PersistenceError"], Effect.die))

              if (Option.isNone(result.session)) {
                // Verification is required, or auto sign-in is off: the user
                // exists but has no session, and no cookie is written.
                return { user: result.user, session: null }
              }
              const { session, token } = result.session.value
              yield* setSessionCookie(config, session, token, { persistent: payload.rememberMe !== false })
              return { user: result.user, session }
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
              }).pipe(Effect.catchTag(["PasswordHashError", "PersistenceError"], Effect.die))

              yield* setSessionCookie(config, result.session, result.token, {
                persistent: payload.rememberMe !== false
              })
              return { user: result.user, session: result.session }
            }))
          .handle("signOut", () =>
            Effect.gen(function*() {
              const session = yield* CurrentSession
              yield* sessions.signOut(session).pipe(Effect.catchTag("PersistenceError", Effect.die))
              yield* clearSessionCookie(config)
              return acknowledged
            }))
          .handle("getSession", () =>
            Effect.gen(function*() {
              // The middleware has already verified, refreshed and — when the
              // expiry moved — re-set the cookie.
              const user = yield* CurrentUser
              const session = yield* CurrentSession
              return { user, session }
            }))
          .handle("listSessions", () =>
            Effect.gen(function*() {
              const user = yield* CurrentUser
              return yield* sessions.list(user.id).pipe(Effect.catchTag("PersistenceError", Effect.die))
            }))
          .handle("revokeSession", ({ payload }) =>
            Effect.gen(function*() {
              const user = yield* CurrentUser
              yield* sessions.revoke(payload.sessionId, user.id).pipe(
                Effect.catchTag("PersistenceError", Effect.die)
              )
              return acknowledged
            }))
          .handle("revokeSessions", () =>
            Effect.gen(function*() {
              const user = yield* CurrentUser
              yield* sessions.revokeAll(user.id).pipe(Effect.catchTag("PersistenceError", Effect.die))
              // This one revoked the caller's own session too.
              yield* clearSessionCookie(config)
              return acknowledged
            }))
          .handle("revokeOtherSessions", () =>
            Effect.gen(function*() {
              const user = yield* CurrentUser
              const session = yield* CurrentSession
              yield* sessions.revokeOthers(user.id, session.id).pipe(
                Effect.catchTag("PersistenceError", Effect.die)
              )
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
              }).pipe(Effect.catchTag("PersistenceError", Effect.die))
              return acknowledged
            }))
          .handle("resetPassword", ({ payload }) =>
            Effect.gen(function*() {
              if (!config.emailPassword.enabled) return notServed
              yield* passwords.resetPassword({
                token: payload.token,
                newPassword: payload.newPassword
              }).pipe(Effect.catchTag(["PasswordHashError", "PersistenceError"], Effect.die))
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
              }).pipe(Effect.catchTag(["PasswordHashError", "PersistenceError"], Effect.die))
              return acknowledged
            }))
          .handle("sendVerificationEmail", ({ payload, request }) =>
            Effect.gen(function*() {
              yield* rateLimit(emailBucket, request)
              if (!config.emailPassword.enabled) return notServed
              yield* passwords.sendVerificationEmail({
                email: payload.email,
                callbackURL: Option.getOrUndefined(validateUrl(config, payload.callbackURL))
              }).pipe(Effect.catchTag("PersistenceError", Effect.die))
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
              yield* passwords.verifyEmail(Redacted.make(query.token)).pipe(
                Effect.catchTag("PersistenceError", Effect.die)
              )
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
              }).pipe(Effect.catchTag("PersistenceError", Effect.die))
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
              }).pipe(Effect.catchTag("PersistenceError", Effect.die))

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
              return yield* accounts.listForUser(user.id).pipe(
                Effect.catchTag("PersistenceError", Effect.die)
              )
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
              }).pipe(Effect.catchTag("PersistenceError", Effect.die))
              return { url: started.url, redirect: true }
            }))
          .handle("unlinkAccount", ({ payload }) =>
            Effect.gen(function*() {
              const user = yield* CurrentUser
              const session = yield* CurrentSession
              yield* sessions.requireFresh(session)
              yield* accounts.unlink(payload.accountId, user.id).pipe(
                Effect.catchTag("PersistenceError", Effect.die)
              )
              return acknowledged
            }))
      })
  )
