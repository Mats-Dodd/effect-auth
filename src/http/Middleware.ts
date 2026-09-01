/**
 * The authentication middleware contract.
 *
 * This module *declares* the shape of authentication: which context keys an
 * authenticated request carries, which credentials the API accepts, and which
 * error an unauthenticated request receives. It contains no verification logic
 * — the implementation layer (`src/http/MiddlewareLive.ts`) supplies that — which is
 * what keeps the declaration importable from a browser client without dragging
 * the session store along with it.
 *
 * @since 0.1.0
 */
import { Context, DateTime, Duration, Effect } from "effect"
import { HttpApiMiddleware } from "effect/unstable/httpapi"
import { AuthConfig } from "../config/AuthConfig.js"
import { SessionNotFresh, Unauthorized } from "../domain/Errors.js"
import type { Session, User, UserFields, UserModel, UserOf } from "../domain/Schema.js"
import { bearerSecurity, insecureSessionCookieSecurity, secureSessionCookieSecurity } from "./Cookies.js"

// -----------------------------------------------------------------------------
// Principal
// -----------------------------------------------------------------------------

/**
 * The session behind the request being handled.
 *
 * **Details**
 *
 * Provided by {@link Authenticated} to every endpoint that declares it. This is
 * the persisted session row, so `id`, `userId`, `createdAt` and `expiresAt` are
 * all available — enough for the freshness guard and for "revoke every session
 * but this one".
 *
 * The interface-split convention is already satisfied without a
 * `CurrentSessionService` alias: the shape is the exported `Session` model, so
 * the class here is nothing but the key.
 *
 * @category services
 * @since 0.1.0
 */
export class CurrentSession extends Context.Service<CurrentSession, Session>()(
  "effect-auth/http/Middleware/CurrentSession"
) {}

/**
 * The user behind the request being handled.
 *
 * **Details**
 *
 * Provided by {@link Authenticated} alongside {@link CurrentSession}; the two
 * are read in one query. A future authorization middleware can `require` these
 * two keys as its principal without `effect-auth` growing a policy concept.
 *
 * As with {@link CurrentSession}, the shape is the exported `User` model rather
 * than an inline one, so there is nothing to extract.
 *
 * @category services
 * @since 0.1.0
 */
export class CurrentUser extends Context.Service<CurrentUser, User>()("effect-auth/http/Middleware/CurrentUser") {}

/**
 * {@link CurrentUser}, seen through a model's custom fields.
 *
 * **Details**
 *
 * This is how a deployment's own columns reach a handler: the same key, the same
 * slot, a narrower shape. `MiddlewareLive` provides the authenticated user
 * through this view, and a handler — or an application's own endpoint — reads it
 * back through the same view to see the fields it declared.
 *
 * **Example**
 *
 * ```ts skip-type-checking
 * const plan = Effect.map(currentUserOf(model), (user) => user.plan)
 * ```
 *
 * @category services
 * @since 0.1.0
 */
export const currentUserOf = <F extends UserFields>(_model: UserModel<F>): Context.Service<CurrentUser, UserOf<F>> =>
  Context.Service<CurrentUser, UserOf<F>>("effect-auth/http/Middleware/CurrentUser")

// -----------------------------------------------------------------------------
// Middleware
// -----------------------------------------------------------------------------

/**
 * Requires a valid session, and provides {@link CurrentUser} and
 * {@link CurrentSession} to the endpoint.
 *
 * **Details**
 *
 * Three credential transports are declared, and the builder tries them in
 * order until one authenticates:
 *
 * - `secureSessionCookie` — `__Secure-effect_auth.session`, what a TLS
 *   deployment writes.
 * - `sessionCookie` — `effect_auth.session`, what a plain-HTTP deployment (a
 *   local dev server) writes.
 * - `bearer` — the same opaque session token as `Authorization: Bearer <token>`,
 *   for clients that have no cookie jar.
 *
 * Both cookie names are declared because a security scheme's key is fixed when
 * this class is created, while the `__Secure-` prefix is decided at runtime
 * from `baseUrl`. Only one of the two is ever *honoured*, though: the
 * implementation refuses whichever name this deployment does not write, so a
 * TLS deployment accepts `__Secure-effect_auth.session` alone. Accepting the
 * un-prefixed name there would undo the prefix, which exists precisely because
 * an attacker on a plain-HTTP sibling origin can set the plain name and not the
 * prefixed one.
 *
 * The implementation verifies the token through `Sessions.verify`, which
 * performs the rolling refresh, and re-sets the cookie when the expiry moved.
 * On the cookie transport it additionally applies the `Origin` check, which is
 * why cookie and bearer are separate schemes rather than one.
 *
 * **Gotchas**
 *
 * `requiredForClient` is `true`: a generated client must supply its own
 * middleware implementation (`HttpApiMiddleware.layerClient`) that attaches the
 * credential. A browser client whose cookies are attached by the browser still
 * needs to provide one — it just passes the request through.
 *
 * The three leaking requirements are not this module's to discharge. An
 * `HttpApiMiddleware` wraps the endpoint's own effect, so whatever that effect
 * requires appears on the middleware's signature, and `HttpServerRequest`,
 * `ParsedSearchParams` and `RouteContext` are precisely the per-request services
 * the router provides while it is dispatching — there is no layer-creation time
 * at which they could be resolved, and resolving them would mean serving every
 * request from one request's context. They are declared here rather than
 * silenced so the pass-through is stated instead of assumed.
 *
 * @effect-expect-leaking HttpServerRequest | ParsedSearchParams | RouteContext
 *
 * @category services
 * @since 0.1.0
 */
export class Authenticated extends HttpApiMiddleware.Service<
  Authenticated,
  {
    provides: CurrentUser | CurrentSession
    requires: never
  }
>()("effect-auth/Authenticated", {
  requiredForClient: true,
  security: {
    secureSessionCookie: secureSessionCookieSecurity,
    sessionCookie: insecureSessionCookieSecurity,
    bearer: bearerSecurity
  },
  error: Unauthorized
}) {}

// -----------------------------------------------------------------------------
// Annotations
// -----------------------------------------------------------------------------

/**
 * Marks an endpoint that must see the session as the *database* has it.
 *
 * **When to use**
 *
 * On every endpoint whose decision depends on the current state of the
 * credential or the identity behind it: changing a password, unlinking a sign-in
 * method, changing an address, deleting an account. Annotate it, and the session
 * cookie cache is bypassed for that endpoint — neither read nor written — so the
 * handler cannot act on a snapshot taken up to `cookieCache.maxAge` ago.
 *
 * It is an endpoint annotation rather than a second middleware because the
 * `Authenticated` middleware can read the annotations of the endpoint it is
 * wrapping, and because a plugin then opts in by declaring one line on its own
 * endpoint rather than by composing a different middleware.
 *
 * **Example**
 *
 * ```ts
 * import { Schema } from "effect"
 * import { HttpApiEndpoint } from "effect/unstable/httpapi"
 * import { Authenticated, AuthoritativeSession } from "effect-auth"
 *
 * const rotateKeys = HttpApiEndpoint.post("rotateKeys", "/rotate-keys", {
 *   success: Schema.Struct({ success: Schema.Boolean })
 * })
 *   .middleware(Authenticated)
 *   .annotate(AuthoritativeSession, true)
 * ```
 *
 * **Gotchas**
 *
 * The default is `false`, so an endpoint that says nothing is cacheable. That is
 * the right default — the vast majority of authenticated endpoints only need to
 * know *who* is calling — but it means a new credential-changing endpoint has to
 * remember this line.
 *
 * @category services
 * @since 0.1.0
 */
export const AuthoritativeSession: Context.Reference<boolean> = Context.Reference<boolean>(
  "effect-auth/AuthoritativeSession",
  { defaultValue: () => false }
)

// -----------------------------------------------------------------------------
// Guards
// -----------------------------------------------------------------------------

/**
 * Fails with `SessionNotFresh` unless the current session was established
 * within `session.freshAge`.
 *
 * **When to use**
 *
 * Run it first in any handler whose effect would let a session takeover become
 * permanent: changing a password, unlinking the last-but-one sign-in method.
 * An attacker holding a stolen but stale cookie is then forced to produce the
 * current password, which they do not have.
 *
 * It is a plain `Effect` rather than a second middleware because freshness is a
 * property of a handful of operations, not of a transport.
 *
 * **Example**
 *
 * ```ts
 * import { Effect } from "effect"
 * import { CurrentSession, requireFresh } from "effect-auth"
 *
 * const changePassword = Effect.gen(function*() {
 *   yield* requireFresh
 *   const session = yield* CurrentSession
 *   return session.userId
 * })
 * ```
 *
 * @category combinators
 * @since 0.1.0
 */
export const requireFresh: Effect.Effect<void, SessionNotFresh, CurrentSession | AuthConfig> = Effect.gen(function* () {
  const session = yield* CurrentSession
  const config = yield* AuthConfig
  const freshUntil = DateTime.addDuration(session.createdAt, config.session.freshAge)
  if (yield* DateTime.isFuture(freshUntil)) return
  return yield* SessionNotFresh.make({
    freshAgeSeconds: Duration.toSeconds(config.session.freshAge)
  })
})
