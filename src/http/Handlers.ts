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
 * Three of the exports here belong to a plugin rather than to this group.
 * {@link forGroup} is the same boundary {@link layer} is built on, offered to a
 * module that serves endpoints of its own; {@link dieOn} is how it keeps its own
 * infrastructural failures out of its endpoints' error unions; and
 * {@link clearSessionCookies} is what any handler that ends a session must call.
 *
 * **Gotchas**
 *
 * Two error tags never reach a caller. `PersistenceError` and
 * `PasswordHashError` are server faults: they are turned into defects here, so
 * they render as `500` and stay out of every endpoint's error union.
 *
 * @since 0.1.0
 */
import type { Layer, Scope } from "effect"
import { DateTime, Duration, Effect, Option, Redacted } from "effect"
import type { HttpServerRequest } from "effect/unstable/http"
import { HttpServerResponse } from "effect/unstable/http"
import { RateLimiter } from "effect/unstable/persistence"
import { type HttpApi, HttpApiBuilder, type HttpApiGroup, HttpApiSchema } from "effect/unstable/httpapi"
import type { AuthConfigService } from "../config/AuthConfig.js"
import { AuthConfig } from "../config/AuthConfig.js"
import { Accounts } from "../domain/Accounts.js"
import { InvalidCredentials, NotFound, OAuthProviderError } from "../domain/Errors.js"
import { type Passwords, passwordsOf } from "../domain/Passwords.js"
import type { UserFields, UserModel } from "../domain/Schema.js"
import { baseUserModel } from "../domain/Schema.js"
import { type Sessions, sessionsOf } from "../domain/Sessions.js"
import { type Users, usersOf } from "../domain/Users.js"
import { OAuthFlow } from "../oauth/Flow.js"
import type { AuthApiGroupOf } from "./AuthApi.js"
import { AuthApiGroup } from "./AuthApi.js"
import type { Authenticated } from "./Middleware.js"
import { CurrentSession, currentUserOf } from "./Middleware.js"
import type { PluginCookie } from "./Cookies.js"
import { oauthStateCookieName, pluginCookieFor } from "./Cookies.js"
import {
  clearOAuthStateCookie,
  clearSessionCookie,
  optionalSession,
  setOAuthStateCookie,
  setSessionCookie
} from "./MiddlewareLive.js"
import { policyRefusedTarget, requireTrustedIfPresent, resolveUrl, validateUrl, withErrorCode } from "./OriginCheck.js"
import type { Bucket } from "./RateLimits.js"
import { clientAddress, consumeWith, credentials, email as emailBucket } from "./RateLimits.js"
import type { SessionCacheService } from "./SessionCache.js"
import { SessionCache } from "./SessionCache.js"

// -----------------------------------------------------------------------------
// Failures
// -----------------------------------------------------------------------------

/** A tagged error — everything {@link dieOn} can be pointed at. */
interface Tagged {
  readonly _tag: string
}

/**
 * Whether an error is one the fault filter turns into a defect, stated as the
 * narrowing the compiler cannot derive from a membership test.
 */
const isNamedFault =
  <E extends Tagged, Tags extends ReadonlyArray<string>>(
    tags: Tags
  ): ((error: E) => error is Extract<E, { readonly _tag: Tags[number] }>) =>
  (error): error is Extract<E, { readonly _tag: Tags[number] }> =>
    tags.includes(error._tag)

/**
 * Turns the failures whose tags are named into defects, and takes them out of
 * the error channel.
 *
 * **When to use**
 *
 * For the errors that mean *the deployment is broken* rather than *the caller
 * did something wrong*: they must render as an opaque `500` with the cause in
 * the logs, and they must not appear in an endpoint's declared error union. A
 * plugin whose services can fail its own infrastructural way names those tags
 * here, exactly as this library names its two in {@link serverFaultTags}.
 *
 * **Example**
 *
 * ```ts
 * import { AuthHandlers } from "effect-auth"
 *
 * const mailerFault = AuthHandlers.dieOn(["EmailDeliveryError"])
 * ```
 *
 * **Gotchas**
 *
 * The tags are matched by string. Pass the array `as const` (or a
 * `ReadonlyArray` constant like {@link serverFaultTags}) so the return type
 * names the tags rather than widening to `string` — with a widened `Tags` the
 * whole error channel disappears from the type while the runtime keeps failing.
 *
 * @category combinators
 * @since 0.1.0
 */
export const dieOn =
  <const Tags extends ReadonlyArray<string>>(tags: Tags) =>
  <A, E extends Tagged, R>(
    effect: Effect.Effect<A, E, R>
  ): Effect.Effect<A, Exclude<E, Extract<E, { readonly _tag: Tags[number] }>>, R> =>
    // `catchIf` rather than `Effect.catch` + `Effect.fail`: on the pass-through
    // branch it re-fails the *original* Cause, keeping its annotations and any
    // sibling reasons, where a fresh `Effect.fail(error)` would drop them. The
    // price is the explicit type arguments — inference cannot recover them from
    // the refinement — and the `Exclude<E, Extract<E, …>>` spelling, which is
    // what `catchIf` computes and which TS cannot equate with `Exclude<E, …>`
    // for a generic `E`. For a tagged union they name the same set either way.
    Effect.catchIf<A, E, R, Extract<E, { readonly _tag: Tags[number] }>, never, never, never>(
      effect,
      isNamedFault<E, Tags>(tags),
      Effect.die
    )

/**
 * The two failures no endpoint of this library declares: a storage fault and a
 * hashing fault. Both mean the deployment is broken.
 *
 * @category constructors
 * @since 0.1.0
 */
export const serverFaultTags = ["PasswordHashError", "PersistenceError"] as const

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
 * @since 0.1.0
 */
export const serverFault: <A, E extends Tagged, R>(
  effect: Effect.Effect<A, E, R>
) => Effect.Effect<A, Exclude<E, Extract<E, { readonly _tag: "PasswordHashError" | "PersistenceError" }>>, R> =
  dieOn(serverFaultTags)

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
 * @since 0.1.0
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
 * @since 0.1.0
 */
export const notServed: HttpServerResponse.HttpServerResponse = HttpServerResponse.empty({ status: 404 })

/**
 * The body-less `302` the OAuth callback answers with.
 *
 * @category constructors
 * @since 0.1.0
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
 * @since 0.1.0
 */
export const acknowledged = { success: true } as const

/**
 * Ends this browser's session on the response being built: the session cookie
 * *and* whatever the cookie cache left beside it.
 *
 * **When to use**
 *
 * Wherever a handler signs the caller out — sign-out, revoking every session, a
 * completed password reset, a deleted account. Clearing only the session cookie
 * would leave a snapshot behind, and a snapshot is served without a database
 * read: the person would stay signed in until it expired.
 *
 * @category combinators
 * @since 0.1.0
 */
export const clearSessionCookies = (
  config: AuthConfigService,
  cache: SessionCacheService
): Effect.Effect<void, never, HttpServerRequest.HttpServerRequest> =>
  Effect.andThen(clearSessionCookie(config), cache.clear)

/**
 * The name, before any prefix, of the cookie a pending authentication rides in.
 *
 * **Details**
 *
 * `__Host-effect_auth.pending` on a TLS deployment, the bare name on plain
 * HTTP — {@link pendingCookie} makes that decision. It is the *only* place the
 * pending-authentication token is ever written: a body a script can read is not
 * where a credential belongs, and a response that carries this cookie never
 * carries a session cookie.
 *
 * @category constructors
 * @since 0.2.0
 */
export const pendingCookieBaseName = "effect_auth.pending"

/**
 * The pending-authentication cookie for this deployment.
 *
 * **When to use**
 *
 * From a factor plugin that has to read the cookie's *name* — to pull the token
 * off the incoming request — rather than write it. {@link setPendingCookie} and
 * {@link clearPendingCookie} are the write side.
 *
 * @category combinators
 * @since 0.2.0
 */
export const pendingCookie = (config: AuthConfigService, maxAge: Duration.Duration): PluginCookie =>
  pluginCookieFor(config, { baseName: pendingCookieBaseName, hostOnly: true, maxAge })

/**
 * Attaches the pending-authentication cookie to the response being built.
 *
 * **When to use**
 *
 * From any sign-in path whose result is a `Challenge`: the token travels here
 * and nowhere else, browser-bound exactly as the OAuth `state` cookie is.
 *
 * **Gotchas**
 *
 * A response that sets this must not also set a session cookie. That is not an
 * assertion this function can make — it is the caller's, and it is what the
 * `getSetCookie()` test pins.
 *
 * @category combinators
 * @since 0.2.0
 */
export const setPendingCookie = (
  config: AuthConfigService,
  token: Redacted.Redacted,
  options: { readonly maxAge: Duration.Duration }
): Effect.Effect<void, never, HttpServerRequest.HttpServerRequest> => {
  const cookie = pendingCookie(config, options.maxAge)
  return HttpApiBuilder.securitySetCookie(cookie.security, token, cookie.options)
}

/**
 * Expires the pending-authentication cookie on the response being built.
 *
 * **When to use**
 *
 * The moment the pending token is spent or refused — success or failure — so a
 * single-use value never rides a second request. Repeats `path` and `domain`,
 * as every expiry in this library does.
 *
 * @category combinators
 * @since 0.2.0
 */
export const clearPendingCookie = (
  config: AuthConfigService
): Effect.Effect<void, never, HttpServerRequest.HttpServerRequest> => {
  const cookie = pendingCookie(config, Duration.zero)
  return HttpApiBuilder.securitySetCookie(cookie.security, Redacted.make(""), cookie.expiredOptions)
}

/**
 * The query parameter a redirect-shaped sign-in sets when a second factor is
 * still owed.
 *
 * **Details**
 *
 * `?mfa=required` on the flow's own validated `redirectTo`. A browser that
 * arrived by a top-level navigation has to leave by one, so an OAuth callback
 * cannot answer a `202` — this is the same shape `?error=` already uses to tell
 * the landing page what happened. The pending-authentication token is not in
 * it: that is in the `__Host-` cookie, where a credential belongs.
 *
 * @category constructors
 * @since 0.2.0
 */
export const mfaRequiredParam = "mfa"

/**
 * Marks a redirect target as "signed in, but a second factor is owed".
 *
 * **Gotchas**
 *
 * The URL must already have been through `OriginCheck.resolveUrl`: this
 * appends a parameter and validates nothing, exactly as
 * `OriginCheck.withErrorCode` does.
 *
 * @category combinators
 * @since 0.2.0
 */
export const withMfaRequired = (url: string): string => {
  const parsed = new URL(url)
  parsed.searchParams.set(mfaRequiredParam, "required")
  return parsed.toString()
}

/**
 * The `GET` callback this deployment serves, carrying everything a `form_post`
 * provider sent in its body as a query string.
 *
 * **Details**
 *
 * Built from `baseUrl` and `basePath` rather than from the incoming request, so
 * the browser is sent to this deployment's own callback and nowhere else — a
 * `Host` header is attacker-controllable and a `Location` built from one is an
 * open redirect. Absent fields are simply not written.
 *
 * @category combinators
 * @since 0.1.0
 */
export const callbackFormTarget = (
  config: AuthConfigService,
  providerId: string,
  form: {
    readonly code?: string | undefined
    readonly state?: string | undefined
    readonly error?: string | undefined
    readonly error_description?: string | undefined
    readonly user?: string | undefined
  }
): string => {
  const url = new URL(`${config.basePath}/callback/${encodeURIComponent(providerId)}`, config.baseUrl)
  for (const [key, value] of Object.entries(form)) {
    if (value !== undefined) url.searchParams.set(key, value)
  }
  return url.toString()
}

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
 * @since 0.1.0
 */
export type HandlerServices =
  | AuthConfig
  | Sessions
  | Passwords
  | Users
  | Accounts
  | SessionCache
  | Authenticated
  | RateLimiter.RateLimiter

// -----------------------------------------------------------------------------
// Groups
// -----------------------------------------------------------------------------

/**
 * Implements one `HttpApiGroup` inside whatever `HttpApi` a consumer composed it
 * into.
 *
 * **When to use**
 *
 * In every plugin that serves endpoints. `HttpApiBuilder.group` takes the API
 * the group was *added to*, and a library cannot name that API — so a plugin
 * that called it directly would either force its consumers onto a fixed API or
 * repeat this module's boundary cast. `forGroup` is that boundary, written once:
 * hand it your group and your handlers, and what comes back is the function a
 * consumer applies to their own API.
 *
 * **Example**
 *
 * ```ts
 * import { Effect, Schema } from "effect"
 * import { HttpApiEndpoint, HttpApiGroup } from "effect/unstable/httpapi"
 * import { AuthHandlers } from "effect-auth"
 *
 * const PingGroup = HttpApiGroup.make("ping").add(
 *   HttpApiEndpoint.get("ping", "/ping", { success: Schema.String })
 * )
 *
 * export const layer = AuthHandlers.forGroup(PingGroup, (handlers) =>
 *   Effect.succeed(handlers.handle("ping", () => Effect.succeed("pong"))))
 * ```
 *
 * **Gotchas**
 *
 * The API passed to the result must be the one passed to `HttpApiBuilder.layer`:
 * the routes are read off the group *it* carries, so an API whose prefix was
 * changed after the call would serve the old paths. A group merely *named* the
 * same thing, or the group re-prefixed with `HttpApi.prefix` (which rewrites the
 * endpoint paths in the type), is rejected rather than mis-served.
 *
 * @category combinators
 * @since 0.1.0
 */
export const forGroup =
  <const Id extends string, Group extends HttpApiGroup.Constraint, Return>(
    // `Id` is inferred from the value's own `identifier`, which is what makes the
    // key of the mapped type below a literal rather than `string`.
    group: Group & { readonly identifier: Id },
    build: (handlers: HttpApiBuilder.Handlers.FromGroup<Group>) => HttpApiBuilder.Handlers.ValidateReturn<Return>
  ) =>
  <ApiId extends string, Groups extends HttpApiGroup.Constraint>(
    api: HttpApi.HttpApi<ApiId, Groups> & { readonly groups: { readonly [K in Id]: Group } }
  ): Layer.Layer<
    HttpApiGroup.Service<ApiId, Id>,
    HttpApiBuilder.Handlers.Error<Return>,
    Exclude<HttpApiBuilder.Handlers.Context<Return>, Scope.Scope>
  > =>
    buildGroup(api, group, build)

/**
 * `HttpApiBuilder.group`, restated for one named group of a composed API.
 *
 * **Details**
 *
 * The only cast in this module, and the boundary both {@link forGroup} and
 * {@link layer} exist to make safe. Two things about `HttpApiBuilder.group`'s
 * signature make it unusable from a library:
 *
 * `HttpApi` is invariant in its group union, so a consumer's composed API —
 * `HttpApi.make("app").addHttpApi(AuthApi).add(Todos)` — is not assignable to
 * `HttpApi<ApiId, typeof AuthApiGroup>`, even though it demonstrably contains
 * that exact group.
 *
 * And its group identifier is constrained by `HttpApiGroup.Identifier<Groups>`,
 * a conditional type that stays deferred while `Groups` is a type parameter — so
 * no generic caller can name the group it is implementing, whatever it casts the
 * API to.
 *
 * What is cast is therefore the *function*, not the API, and the function being
 * cast is the two-line wrapper right here: it reads the identifier off the group
 * value and passes the API through untouched. That is sound because
 * `HttpApiBuilder.group` reads nothing but `api.groups[identifier]` (see its
 * implementation), so the routes registered are the consumer's own group's,
 * whatever the types above say. What the callers add is the check the types can
 * no longer make: each of them pins `groups[id]` to the group it was given, at
 * every call site.
 *
 * `layer` passes the *base* auth group rather than `AuthApiGroupOf<F>`, which is
 * what lets its twenty-nine handlers be type-checked once instead of once per
 * deployment. An endpoint whose payload type mentions `F` has a request shape
 * TypeScript cannot resolve — `HttpApiEndpoint`'s `RequestFromParts` branches on
 * the payload type, and a conditional over an unresolved `F` stays deferred, so
 * `payload` would have no readable properties at all. The difference between the
 * two groups is confined to three endpoints, and in both directions it is a
 * widening that module honours: sign-up *receives* a payload with the model's
 * extra fields on it (recovered, typed, through `model.extrasOf`) and the three
 * user-bearing endpoints *answer* with a user that has them (produced by
 * `model.toPublic`). Encoding and decoding are done by the consumer's own group
 * either way, so the extras are on the wire whatever this says.
 *
 * (It goes via `unknown` because the two signatures are not comparable in either
 * direction — which is the whole point of restating one as the other.)
 */
// oxlint-disable-next-line typescript/no-unsafe-type-assertion -- REFACTOR.md §5 boundary cast
const buildGroup = (<Return>(
  api: HttpApi.HttpApi<string, HttpApiGroup.Constraint>,
  group: HttpApiGroup.Constraint,
  build: (
    handlers: HttpApiBuilder.Handlers.FromGroup<HttpApiGroup.Constraint>
  ) => HttpApiBuilder.Handlers.ValidateReturn<Return>
) => HttpApiBuilder.group(api, group.identifier, build)) as unknown as <
  ApiId extends string,
  Groups extends HttpApiGroup.Constraint,
  const Id extends string,
  Group extends HttpApiGroup.Constraint & { readonly identifier: Id },
  Return
>(
  api: HttpApi.HttpApi<ApiId, Groups>,
  group: Group,
  build: (handlers: HttpApiBuilder.Handlers.FromGroup<Group>) => HttpApiBuilder.Handlers.ValidateReturn<Return>
) => Layer.Layer<
  HttpApiGroup.Service<ApiId, Id>,
  HttpApiBuilder.Handlers.Error<Return>,
  Exclude<HttpApiBuilder.Handlers.Context<Return>, Scope.Scope>
>

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
 * @since 0.1.0
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
  api: HttpApi.HttpApi<ApiId, Groups> & { readonly groups: { readonly auth: NoInfer<AuthApiGroupOf<F>> } },
  model?: UserModel<F>
): Layer.Layer<HttpApiGroup.Service<ApiId, "auth">, never, HandlerServices> =>
  // Two branches because `UserModel<F>` and `UserModel<{}>` are different types:
  // "the model, or the base one" is a choice that has to be made before anything
  // is built with it.
  model === undefined ? build(api, baseUserModel) : build(api, model)

const build = <ApiId extends string, Groups extends HttpApiGroup.Constraint, F extends UserFields>(
  api: HttpApi.HttpApi<ApiId, Groups>,
  model: UserModel<F>
): Layer.Layer<HttpApiGroup.Service<ApiId, "auth">, never, HandlerServices> => {
  const CurrentUser = currentUserOf(model)
  return buildGroup(api, AuthApiGroup, (handlers) =>
    Effect.gen(function* () {
      const config = yield* AuthConfig
      // The two services that answer with users are read through the model's
      // typed view of their key: the same slot, a shape that carries the
      // deployment's own fields.
      const sessions = yield* sessionsOf(model)
      const passwords = yield* passwordsOf(model)
      const users = yield* usersOf(model)
      const accounts = yield* Accounts
      const cache = yield* SessionCache
      const limiter = yield* RateLimiter.RateLimiter
      // Resolved once, and optional: see `HandlerServices`.
      const flow = yield* Effect.serviceOption(OAuthFlow)

      // Every service is resolved here, when the layer is built, so that no
      // handler carries a request-time requirement: anything left in a
      // handler's environment becomes a router-scoped service the consumer
      // would have to provide per request.
      const rateLimit = (bucket: Bucket, request: HttpServerRequest.HttpServerRequest) =>
        consumeWith({ config, limiter, bucket, request })

      /**
       * `OriginCheck.requireTrustedIfPresent`, with this layer's configuration
       * provided into it at build time so that no handler carries a
       * request-time `AuthConfig` requirement.
       *
       * On the unauthenticated doors: an `Origin` or `Referer` that is present
       * and untrusted is refused, and a request claiming neither — a server, a
       * script — passes. Every plugin's unauthenticated POST already does this;
       * the library's own were the half that did not, and a rule the plugins
       * enforce and the core does not is not a rule.
       *
       * On `signInEmail` it closes login CSRF: a cross-site form post
       * otherwise signs a visitor's browser into an account the attacker
       * controls, and everything that person then does — a password saved, an
       * address added, a purchase — happens in it. On the two mail-sending
       * doors it is the same reach a plugin's send endpoint is guarded against.
       */
      const trustedOrigin = Effect.provideService(requireTrustedIfPresent, AuthConfig, config)

      /**
       * Who the browser already was, on a door that does not require anybody.
       *
       * A sign-in that arrives carrying a session is an *upgrade* — the
       * anonymous visitor with a basket who now signs in to the account they
       * had all along — and `AuthHooks.beforeSessionMint` is where a deployment
       * acts on it. Nothing is required and nothing is refused: a caller with
       * no credential, or a stale one, is the ordinary case and reads `None`.
       */
      const current = (request: HttpServerRequest.HttpServerRequest) => optionalSession({ config, sessions, request })

      const unknownProvider = (providerId: string) => OAuthProviderError.make({ providerId, reason: "UnknownProvider" })

      return handlers
        .handle("signUpEmail", ({ payload, request }) =>
          Effect.gen(function* () {
            yield* trustedOrigin
            yield* rateLimit(credentials, request)
            if (!config.emailPassword.enabled) return notServed
            // `payload` carries whatever custom fields the deployment's model
            // declared — this handler is checked against the base group, so
            // the model is what recovers them, at the type level as well as at
            // run time. A deployment that declared none contributes `{}`.
            const result = yield* passwords
              .signUp({
                ...payload,
                ...model.extrasOf(payload, "jsonCreate"),
                callbackURL: Option.getOrUndefined(validateUrl(config, payload.callbackURL)),
                ...clientMeta(config, request)
              })
              .pipe(serverFault)

            if (Option.isNone(result.session)) {
              // Verification is required, or auto sign-in is off: the user
              // exists but has no session, and no cookie is written.
              return { user: model.toPublic(result.user), session: null }
            }
            const { session, token } = result.session.value
            yield* setSessionCookie(config, session, token, { persistent: payload.rememberMe !== false })
            return { user: model.toPublic(result.user), session }
          })
        )
        .handle("signInEmail", ({ payload, request }) =>
          Effect.gen(function* () {
            yield* trustedOrigin
            yield* rateLimit(credentials, request)
            if (!config.emailPassword.enabled) return notServed
            const result = yield* passwords
              .signIn({
                email: payload.email,
                password: payload.password,
                rememberMe: payload.rememberMe,
                current: Option.getOrUndefined(yield* current(request)),
                ...clientMeta(config, request)
              })
              .pipe(serverFault)

            if (result._tag === "Challenge") {
              // The pending token, and only the pending token: no session was
              // minted, so no session cookie may be written here. A response
              // that carried both would be a half-authenticated credential the
              // second factor no longer gates.
              const now = yield* DateTime.now
              yield* setPendingCookie(config, result.token, {
                maxAge: Duration.max(Duration.zero, DateTime.distance(now, result.expiresAt))
              })
              return { _tag: "MfaRequired" as const, available: result.available, expiresAt: result.expiresAt }
            }

            yield* setSessionCookie(config, result.session, result.token, {
              persistent: payload.rememberMe !== false
            })
            return { user: model.toPublic(result.user), session: result.session }
          })
        )
        .handle("reauthenticate", ({ payload, request }) =>
          Effect.gen(function* () {
            yield* rateLimit(credentials, request)
            if (!config.emailPassword.enabled) return notServed
            const user = yield* CurrentUser
            const session = yield* CurrentSession
            // Exactly one hash verification runs whether or not this account
            // has a password, so a wrong answer costs what a right one does —
            // the same discipline `signIn` runs, through the same function.
            const matches = yield* passwords.verifyPassword(user.id, payload.password).pipe(serverFault)
            if (!matches) {
              return yield* InvalidCredentials.make()
            }
            const elevated = yield* sessions
              .elevate(session, {
                method: "password",
                factor: "knowledge",
                phishingResistant: false,
                restricted: false
              })
              .pipe(serverFault)
            // `elevate` rotates the token, so the cookie has to carry the new
            // one — the old one stops resolving the instant this returns.
            yield* setSessionCookie(config, elevated.session, elevated.token, {
              persistent: elevated.session.rememberMe
            })
            // And the snapshot beside it names the old token and the old
            // level. Rewriting it is what keeps the very next request a hit;
            // `write` is a no-op unless this request presented the cookie.
            yield* cache.write(elevated.session, user)
            return { user: model.toPublic(user), session: elevated.session }
          })
        )
        .handle("signOut", () =>
          Effect.gen(function* () {
            const session = yield* CurrentSession
            yield* sessions.signOut(session).pipe(serverFault)
            yield* clearSessionCookies(config, cache)
            return acknowledged
          })
        )
        .handle("getSession", () =>
          Effect.gen(function* () {
            // The middleware has already verified, refreshed and — when the
            // expiry moved — re-set the cookie.
            const user = yield* CurrentUser
            const session = yield* CurrentSession
            return { user: model.toPublic(user), session }
          })
        )
        .handle("listSessions", () =>
          Effect.gen(function* () {
            const user = yield* CurrentUser
            return yield* sessions.list(user.id).pipe(serverFault)
          })
        )
        .handle("revokeSession", ({ payload }) =>
          Effect.gen(function* () {
            const user = yield* CurrentUser
            const session = yield* CurrentSession
            yield* sessions.revoke(payload.sessionId, user.id).pipe(serverFault)
            // Revoking one's own session ends this browser's too: clear the
            // cookies, or the cookie cache would keep serving this browser
            // behind its snapshot until it aged out — the row is already gone.
            if (payload.sessionId === session.id) {
              yield* clearSessionCookies(config, cache)
            }
            return acknowledged
          })
        )
        .handle("revokeSessions", () =>
          Effect.gen(function* () {
            const user = yield* CurrentUser
            yield* sessions.revokeAll(user.id).pipe(serverFault)
            // This one revoked the caller's own session too.
            yield* clearSessionCookies(config, cache)
            return acknowledged
          })
        )
        .handle("revokeOtherSessions", () =>
          Effect.gen(function* () {
            const user = yield* CurrentUser
            const session = yield* CurrentSession
            yield* sessions.revokeOthers(user.id, session.id).pipe(serverFault)
            return acknowledged
          })
        )
        .handle("requestPasswordReset", ({ payload, request }) =>
          Effect.gen(function* () {
            yield* trustedOrigin
            yield* rateLimit(emailBucket, request)
            if (!config.emailPassword.enabled) return notServed
            // Answers the same whether or not the address has an account.
            yield* passwords
              .requestReset({
                email: payload.email,
                redirectTo: Option.getOrUndefined(validateUrl(config, payload.redirectTo))
              })
              .pipe(serverFault)
            return acknowledged
          })
        )
        .handle("resetPassword", ({ payload }) =>
          Effect.gen(function* () {
            if (!config.emailPassword.enabled) return notServed
            yield* passwords
              .resetPassword({
                token: payload.token,
                newPassword: payload.newPassword
              })
              .pipe(serverFault)
            // Every session was revoked, this browser's included.
            yield* clearSessionCookies(config, cache)
            return acknowledged
          })
        )
        .handle("changePassword", ({ payload }) =>
          Effect.gen(function* () {
            if (!config.emailPassword.enabled) return notServed
            const user = yield* CurrentUser
            const session = yield* CurrentSession
            yield* passwords
              .changePassword({
                userId: user.id,
                currentPassword: payload.currentPassword,
                newPassword: payload.newPassword,
                revokeOtherSessions: payload.revokeOtherSessions,
                currentSessionId: session.id
              })
              .pipe(serverFault)
            return acknowledged
          })
        )
        .handle("sendVerificationEmail", ({ payload, request }) =>
          Effect.gen(function* () {
            yield* trustedOrigin
            yield* rateLimit(emailBucket, request)
            if (!config.emailPassword.enabled) return notServed
            yield* passwords
              .sendVerificationEmail({
                email: payload.email,
                callbackURL: Option.getOrUndefined(validateUrl(config, payload.callbackURL))
              })
              .pipe(serverFault)
            return acknowledged
          })
        )
        .handle("verifyEmail", ({ query }) =>
          Effect.gen(function* () {
            if (!config.emailPassword.enabled) return notServed
            // A query parameter is decoded as a plain string — query strings
            // do not go through the JSON codec — so it is redacted here,
            // before anything can log it. `query.callbackURL` is accepted and
            // ignored: the link an e-mail carries has one appended to it, and
            // this endpoint answers JSON rather than a redirect.
            yield* passwords.verifyEmail(Redacted.make(query.token)).pipe(serverFault)
            return acknowledged
          })
        )
        .handle("signInSocial", ({ payload, request }) =>
          Effect.gen(function* () {
            // Unauthenticated, and every call writes a state row. Without a
            // counter it is a free way to grow the verifications table — and
            // therefore to slow the indexed lookup every callback and reset
            // depends on. It shares the credentials policy, not its counter:
            // the key carries the path.
            yield* rateLimit(credentials, request)
            if (Option.isNone(flow)) {
              return yield* unknownProvider(payload.providerId)
            }
            const started = yield* flow.value
              .start({
                providerId: payload.providerId,
                callbackURL: payload.callbackURL,
                errorCallbackURL: payload.errorCallbackURL,
                scopes: payload.scopes,
                rememberMe: payload.rememberMe
              })
              .pipe(serverFault)
            // Bind the flow to this browser: the callback requires the state
            // it comes back with to equal this cookie, which an attacker who
            // merely obtained a valid state cannot plant in the victim's jar.
            yield* setOAuthStateCookie(config, started.state, { maxAge: config.tokens.oauthStateTtl })
            return { url: started.url, redirect: true }
          })
        )
        .handle("oauthCallback", ({ params, query, request }) =>
          Effect.gen(function* () {
            // The state cookie is single-use — cleared on every exit from this
            // handler, the `unknown_provider` early return included, so
            // "cleared whatever the outcome" is literally true.
            yield* clearOAuthStateCookie(config)
            if (Option.isNone(flow)) {
              return redirectTo(withErrorCode(resolveUrl(config, null), "unknown_provider"))
            }
            // Browser binding, before the state is even consumed: the flow set
            // a cookie holding the raw `state` when it started, and the value
            // the provider echoed back must equal it. A browser lured to a
            // callback for a `state` it never started holds no such cookie and
            // is turned away with the same safe `state_mismatch` code an
            // unissued state gets.
            const bound = request.cookies[oauthStateCookieName(config)]
            if (query.state === undefined || bound === undefined || bound.length === 0 || bound !== query.state) {
              // The same closed-set code `errorCode(OAuthStateMismatch)` and
              // `complete` produce for an unissued state, written as the
              // literal it resolves to — as the `unknown_provider` branch above is.
              return redirectTo(withErrorCode(resolveUrl(config, null), "state_mismatch"))
            }
            // `complete` resolves every failure into a validated redirect: the
            // browser arrived here by a top-level navigation and must leave by
            // one, whatever happened.
            const outcome = yield* flow.value
              .complete({
                providerId: params.providerId,
                code: query.code,
                state: query.state,
                error: query.error,
                // Apple's one-shot display name: it is posted to
                // `oauthCallbackForm`, which puts it on this GET's query string,
                // and `userInfo` is the only thing that reads it. Unsigned and
                // attacker-controllable — carried, never trusted.
                ...(query.user === undefined ? {} : { params: { user: query.user } }),
                // The same upgrade seam `signInEmail` carries: a callback that
                // arrives in a browser already holding a session is somebody
                // signing in to the account they had all along.
                current: Option.getOrUndefined(yield* current(request)),
                ...clientMeta(config, request)
              })
              .pipe(serverFault)

            if (outcome._tag === "Success" && outcome.challenge !== null) {
              // A challenge and a session cookie are mutually exclusive, and
              // the flow has already made `session` and `token` null to say so.
              // The browser leaves by the navigation it arrived on, carrying
              // the pending token in its own `__Host-` cookie and a marker on
              // the query string so the landing page knows to ask.
              const now = yield* DateTime.now
              yield* setPendingCookie(config, outcome.challenge.token, {
                maxAge: Duration.max(Duration.zero, DateTime.distance(now, outcome.challenge.expiresAt))
              })
              return redirectTo(withMfaRequired(outcome.redirectTo))
            }
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
          })
        )
        .handle("listAccounts", () =>
          Effect.gen(function* () {
            const user = yield* CurrentUser
            return yield* accounts.listForUser(user.id).pipe(serverFault)
          })
        )
        .handle("linkSocial", ({ payload }) =>
          Effect.gen(function* () {
            if (Option.isNone(flow)) {
              return yield* unknownProvider(payload.providerId)
            }
            const user = yield* CurrentUser
            const started = yield* flow.value
              .start({
                providerId: payload.providerId,
                callbackURL: payload.callbackURL,
                errorCallbackURL: payload.errorCallbackURL,
                scopes: payload.scopes,
                linkUserId: user.id
              })
              .pipe(serverFault)
            // Bind the link flow to this browser too: the callback attaches
            // the returned identity to `user.id`, so a forged callback must
            // not be able to drive it — see `signInSocial`.
            yield* setOAuthStateCookie(config, started.state, { maxAge: config.tokens.oauthStateTtl })
            return { url: started.url, redirect: true }
          })
        )
        .handle("unlinkAccount", ({ payload }) =>
          Effect.gen(function* () {
            const user = yield* CurrentUser
            yield* accounts.unlink(payload.accountId, user.id).pipe(serverFault)
            return acknowledged
          })
        )
        .handle("updateUser", ({ payload }) =>
          Effect.gen(function* () {
            const user = yield* CurrentUser
            const session = yield* CurrentSession
            const updated = yield* users
              .update({
                userId: user.id,
                name: payload.name,
                image: payload.image,
                // The deployment's own writable fields, recovered from the model
                // — this handler is checked against the base group, so the
                // payload's custom half is invisible to it otherwise.
                ...model.extrasOf(payload, "jsonUpdate")
              })
              .pipe(serverFault)
            // The snapshot in this browser's cookie now names the old profile.
            // Rewriting it here is cheaper than invalidating it, and keeps the
            // very next request a cache hit. Unconditional because it is not:
            // `write` is a no-op unless the request presented the session
            // cookie, so a bearer client is handed nothing.
            yield* cache.write(session, updated)
            return { user: model.toPublic(updated) }
          })
        )
        .handle("changeEmail", ({ payload, request }) =>
          Effect.gen(function* () {
            yield* rateLimit(credentials, request)
            if (!config.user.changeEmail.enabled) return notServed
            const user = yield* CurrentUser
            yield* users
              .requestEmailChange({
                user,
                newEmail: payload.newEmail,
                callbackURL: Option.getOrUndefined(validateUrl(config, payload.callbackURL))
              })
              .pipe(serverFault)
            // The same answer whichever branch ran, taken address included.
            return acknowledged
          })
        )
        .handle("confirmEmailChange", ({ query }) =>
          Effect.gen(function* () {
            if (!config.user.changeEmail.enabled) return notServed
            yield* users.confirmEmailChange(Redacted.make(query.token)).pipe(serverFault)
            return acknowledged
          })
        )
        .handle("verifyEmailChange", ({ query }) =>
          Effect.gen(function* () {
            if (!config.user.changeEmail.enabled) return notServed
            yield* users.verifyEmailChange(Redacted.make(query.token)).pipe(serverFault)
            // Unauthenticated: this link may be opened in a browser that holds
            // nobody's session, or the account owner's, and there is no
            // `CurrentSession` here to rewrite a snapshot from. Dropping
            // whatever this browser had costs one database read and is the
            // only way a stale address cannot survive the change.
            yield* cache.clear
            return acknowledged
          })
        )
        .handle("deleteUser", ({ payload, request }) =>
          Effect.gen(function* () {
            yield* rateLimit(credentials, request)
            if (!config.user.deleteUser.enabled) return notServed
            const user = yield* CurrentUser
            const session = yield* CurrentSession
            const outcome = yield* users
              .requestDeletion({
                user,
                session,
                password: payload.password,
                callbackURL: Option.getOrUndefined(validateUrl(config, payload.callbackURL))
              })
              .pipe(serverFault)

            if (outcome === "Deleted") {
              // The row and every session of it have gone; the credential in
              // this browser is dead and must not look alive.
              yield* clearSessionCookies(config, cache)
            }
            return { success: true, status: outcome }
          })
        )
        .handle("deleteUserCallback", ({ query }) =>
          Effect.gen(function* () {
            if (!config.user.deleteUser.enabled) return notServed
            const user = yield* CurrentUser
            const deleted = yield* users
              .confirmDeletion({
                token: Redacted.make(query.token),
                userId: user.id
              })
              .pipe(serverFault)
            yield* clearSessionCookies(config, cache)
            return redirectTo(deleted.redirectTo)
          }).pipe(
            // A refusal is a caller-visible outcome, never a fault — but this
            // endpoint is a top-level navigation, so it leaves by one too. The
            // token was claimed before the hook was asked, so the link is
            // spent whichever way this went, and no cookie is cleared: nothing
            // was deleted.
            Effect.catchTag(
              "PolicyRefused",
              // `baseUrl`, and deliberately: the only URL this link carries is
              // where to land once the account is *gone*, and sending somebody
              // whose deletion was refused to "your account has been deleted"
              // would be a lie. Unlike a magic link, this payload has no error
              // URL to honour.
              (refused) => Effect.succeed(redirectTo(policyRefusedTarget(config, null, refused.code)))
            )
          )
        )
        .handle("setPassword", ({ payload, request }) =>
          Effect.gen(function* () {
            yield* rateLimit(credentials, request)
            if (!config.emailPassword.enabled) return notServed
            const user = yield* CurrentUser
            yield* passwords
              .setPassword({
                userId: user.id,
                newPassword: payload.newPassword
              })
              .pipe(serverFault)
            return acknowledged
          })
        )
        .handle("getAccessToken", ({ payload }) =>
          Effect.gen(function* () {
            const user = yield* CurrentUser
            if (Option.isNone(flow)) {
              // No provider is configured, so no account can be one of theirs.
              return yield* NotFound.make()
            }
            return yield* flow.value
              .accessToken({
                userId: user.id,
                accountId: payload.accountId
              })
              .pipe(serverFault)
          })
        )
        .handle("refreshToken", ({ payload }) =>
          Effect.gen(function* () {
            const user = yield* CurrentUser
            if (Option.isNone(flow)) {
              return yield* NotFound.make()
            }
            return yield* flow.value
              .refreshTokens({
                userId: user.id,
                accountId: payload.accountId
              })
              .pipe(serverFault)
          })
        )
        .handle("oauthCallbackForm", ({ params, payload }) =>
          // No session, no state, no store: the whole endpoint is a hop. A
          // provider using `response_mode=form_post` posts here cross-site,
          // and a cross-site POST carries no `SameSite=Lax` cookie — so
          // completing the flow here could neither read the caller's session
          // nor write one that the browser would keep. The 302 turns it into
          // the top-level GET navigation the rest of the flow is built for.
          Effect.succeed(redirectTo(callbackFormTarget(config, params.providerId, payload)))
        )
    })
  )
}
