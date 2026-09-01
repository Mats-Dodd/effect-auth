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
import { Context } from "effect"
import { HttpApiMiddleware } from "effect/unstable/httpapi"
import type { AssurancePolicy } from "../domain/Assurance.js"
import { StepUpRequired, Unauthorized } from "../domain/Errors.js"
import type { User, UserFields, UserModel, UserOf } from "../domain/Schema.js"
import { CurrentSession } from "../domain/Sessions.js"
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
 * all available — enough for an assurance guard and for "revoke every session
 * but this one".
 *
 * Declared in `domain/Sessions.ts` and re-exported here, which is where a
 * handler imports it from. A principal is a domain concept —
 * `Sessions.requireAssurance` reads it — and `domain` does not name `http`,
 * even in a type position, so the declaration lives on the domain side and the
 * transport that provides it re-exports it.
 *
 * @category services
 * @since 0.1.0
 */
export { CurrentSession }

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
  error: [Unauthorized, StepUpRequired]
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

/**
 * The assurance an endpoint requires of the session behind the request.
 *
 * **When to use**
 *
 * On every endpoint whose effect would let a session takeover become permanent
 * or would add a way into the account: changing or setting a password,
 * unlinking a sign-in method, moving the address, deleting the account,
 * enrolling or removing a second factor. Annotate it, and the `Authenticated`
 * middleware refuses the request with `StepUpRequired` unless the session meets
 * the policy — before the handler runs, and without the handler having to
 * remember a guard.
 *
 * It is an endpoint annotation rather than a second middleware for the same two
 * reasons {@link AuthoritativeSession} is one: the middleware can read the
 * annotations of the endpoint it wraps, and a plugin opts in with one line on
 * its own endpoint instead of composing a different middleware. That is also
 * why `StepUpRequired` is declared on {@link Authenticated} itself and appears
 * in every authenticated endpoint's error union — an annotation is erased from
 * the endpoint's *type*, so the error has nowhere else to be declared.
 *
 * **Details**
 *
 * A policy that states no `maxAge` is measured against the deployment's
 * `session.freshAge`, which is what the library's own credential-changing
 * endpoints ask for — see {@link freshSession}. An endpoint that wants a level
 * and no age bound at all states `maxAge: Duration.infinity` explicitly.
 *
 * An endpoint carrying this annotation is **never** served from the session
 * cookie cache, whether or not it also carries {@link AuthoritativeSession}: a
 * snapshot records the assurance the session had when it was written, and an
 * elevation that happened since would be invisible to it. The decision is made
 * against the row every time.
 *
 * **Example**
 *
 * ```ts
 * import { Duration, Schema } from "effect"
 * import { HttpApiEndpoint } from "effect/unstable/httpapi"
 * import { Authenticated, AuthoritativeSession, RequireAssurance } from "effect-auth"
 *
 * const removeFactor = HttpApiEndpoint.post("removeFactor", "/factors/remove", {
 *   success: Schema.Struct({ success: Schema.Boolean })
 * })
 *   .middleware(Authenticated)
 *   .annotate(AuthoritativeSession, true)
 *   .annotate(RequireAssurance, { aal: "aal2", maxAge: Duration.minutes(5) })
 * ```
 *
 * **Gotchas**
 *
 * The default is `undefined`, so an endpoint that says nothing requires
 * nothing. As with {@link AuthoritativeSession}, that is the right default and
 * it means a new sensitive endpoint has to remember this line.
 *
 * @category services
 * @since 0.2.0
 */
export const RequireAssurance: Context.Reference<AssurancePolicy | undefined> = Context.Reference<
  AssurancePolicy | undefined
>("effect-auth/RequireAssurance", { defaultValue: () => undefined })

/**
 * The policy the library's own credential-changing endpoints carry: "signed in
 * recently enough", where "enough" is the deployment's `session.freshAge`.
 *
 * **Details**
 *
 * The empty policy, and deliberately so: {@link RequireAssurance} resolves an
 * absent `maxAge` against `session.freshAge`, so this is the whole of the rule
 * `requireFresh` used to state — measured, since `0.2.0`, from
 * `session.authenticatedAt` rather than from `session.createdAt`, so that a
 * re-authentication satisfies it and a rolling refresh does not.
 *
 * @category constructors
 * @since 0.2.0
 */
export const freshSession: AssurancePolicy = {}
