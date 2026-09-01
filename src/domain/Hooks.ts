/**
 * Typed policy points a deployment or a plugin hangs its own rules on.
 *
 * **Details**
 *
 * Six semantic moments — provisioning a user, minting a session for one,
 * changing an address, deleting an account, attaching a provider identity — at
 * which core asks whoever installed hooks whether to proceed, and, for
 * {@link AuthHooksOf.beforeUserCreate}, what the row should say. Every member is
 * optional and the default is that none are installed, so a deployment that
 * wants none configures nothing.
 *
 * This is deliberately *not* a request-level `before`/`after` pair — an
 * `HttpApiMiddleware` already does that — and deliberately not a CRUD hook on
 * every store method: the store decorator seams (`Extras.sessionStore`) do that.
 * What it adds is the handful of places where a *policy* belongs and where
 * decorating a service would be whack-a-mole, users being created from three
 * different flows.
 *
 * **Gotchas — hooks are short and local**
 *
 * Every hook runs inside whichever transaction the calling flow holds, so a
 * refusal or a failure aborts the whole operation atomically — which is exactly
 * why a hook must not make a network call or sleep: it is holding a database
 * transaction open. Side effects that may fail, be slow, or be retried belong on
 * `Auth.events`, which is fire-and-forget and runs after the commit.
 *
 * {@link PolicyRefused} is the only failure a hook may raise. Anything else it
 * throws or dies with is a defect and renders as an opaque `500`, which is the
 * correct answer for a broken policy.
 *
 * A ban enforced by `beforeSessionCreate` refuses *new* sessions; it does not
 * touch the live ones. Pair it with revocation, or with a `cookieCache.version`
 * keyed on a public field.
 *
 * **Example**
 *
 * ```ts skip-type-checking
 * import { Effect, Layer } from "effect"
 * import { Auth, Hooks } from "effect-auth"
 *
 * const AcmeOnly = Hooks.layer({
 *   beforeUserCreate: ({ candidate }) =>
 *     candidate.email.endsWith("@acme.com")
 *       ? Effect.succeed(candidate)
 *       : Effect.fail(new Hooks.PolicyRefused({ code: "domain_not_allowed" }))
 * })
 *
 * const AuthLive = Auth.layer(options).pipe(Layer.provide(AcmeOnly))
 * ```
 *
 * @since 0.1.0
 */
import type { Option } from "effect"
import { Context, Effect, Layer, Schema } from "effect"
import { omitUndefined } from "../internal/records.js"
import type { OAuthUserInfo } from "../oauth/Provider.js"
import type { UserFields, UserInsertOf, UserModel, UserOf } from "./Schema.js"
import type { SessionWithUser } from "./Stores.js"

// -----------------------------------------------------------------------------
// Models
// -----------------------------------------------------------------------------

/**
 * Where the person a hook is being consulted about came from.
 *
 * **Details**
 *
 * `OAuth` carries the verified profile the provider returned, so one
 * `beforeUserCreate` covers every provider a deployment serves without the hook
 * having to know which of them is which. `Plugin` is how a plugin names itself,
 * and it is what every plugin this package ships now uses — `email-otp`,
 * `anonymous`, `passkeys`, `username` — rather than each adding a member here.
 *
 * @category models
 * @since 0.1.0
 */
export type ProvisionSource =
  /** A sign-up with an e-mail address and a password. */
  | { readonly _tag: "EmailPassword" }
  /** A first sign-in through an OAuth or OIDC provider. */
  | { readonly _tag: "OAuth"; readonly providerId: string; readonly info: OAuthUserInfo }
  /**
   * A first sign-in through a mailed magic link.
   *
   * Nothing this package ships produces it any more: the magic link plugin was
   * absorbed into `email-otp`, whose link half provisions under
   * `Plugin("email-otp")`. Kept because a deployment's own link plugin may
   * still name itself with it, and because removing a member is a breaking
   * change to every exhaustive match over this union for no gain.
   */
  | { readonly _tag: "MagicLink" }
  /** A plugin that provisions users of its own, naming itself. */
  | { readonly _tag: "Plugin"; readonly plugin: string }

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/**
 * A deployment's own policy refused the operation.
 *
 * **Details**
 *
 * The one failure a hook may raise, and the one this library translates into a
 * `403`. Every operation a hook guards declares it, and the redirect-shaped
 * completions — the OAuth callback, a magic link, the delete-account link —
 * encode it as `?error=policy_refused&code=<code>` instead.
 *
 * **Gotchas**
 *
 * `code` is written by the deployment and is shown to the caller verbatim, in a
 * response body and in a URL a browser is sent to. It is a short, stable
 * classification a client can branch on — `"domain_not_allowed"`, `"banned"` —
 * never a message, never anything derived from a secret, another person's data,
 * or the internals of the policy. `detail` is subject to the same rule.
 *
 * @category errors
 * @since 0.1.0
 */
export class PolicyRefused extends Schema.TaggedError<PolicyRefused>("effect-auth/PolicyRefused")(
  "PolicyRefused",
  {
    code: Schema.String,
    detail: Schema.optional(Schema.String)
  },
  {
    description: "A deployment policy refused the operation",
    httpApiStatus: 403
  }
) {}

// -----------------------------------------------------------------------------
// Service
// -----------------------------------------------------------------------------

/**
 * The hooks a deployment installed, for a model parameterized by `F`.
 *
 * **Details**
 *
 * Every member is optional, and an absent one means "allow, unchanged". All of
 * them run inside whichever transaction the calling flow holds — see the module
 * header for what that forbids.
 *
 * @category models
 * @since 0.1.0
 */
export interface AuthHooksOf<F extends UserFields> {
  /**
   * Consulted before any user row is written, whatever created it.
   *
   * **Details**
   *
   * The one choke point every provisioning flow passes through. It may answer
   * with a *rewritten* candidate — setting a role off the OAuth profile, forcing
   * a display name — or refuse. A rewrite is re-validated through the model's
   * own `insert` variant before it is stored, so a hook cannot smuggle a row the
   * schema would have rejected past it.
   */
  readonly beforeUserCreate?: (options: {
    readonly candidate: UserInsertOf<F>
    readonly source: ProvisionSource
  }) => Effect.Effect<UserInsertOf<F>, PolicyRefused>

  /**
   * Consulted after the row exists, in the same transaction.
   *
   * **When to use**
   *
   * For the rows that have to exist alongside a user and cannot be written
   * before it — a tenant, a membership, anything with a foreign key onto
   * `users.id`. A failure here aborts the sign-up that created the user, so
   * there is no half-provisioned account to reconcile later.
   */
  readonly afterUserCreate?: (options: {
    readonly user: UserOf<F>
    readonly source: ProvisionSource
  }) => Effect.Effect<void, PolicyRefused>

  /**
   * Consulted before a session is minted for a user the store already knows —
   * a suspended account, a deployment that has withdrawn access.
   *
   * **Gotchas**
   *
   * It runs *after* the credential has been verified, so a refusal reveals
   * nothing that a correct password would not already have revealed, and the
   * constant-work timing defence of the sign-in path is not skipped.
   *
   * It governs new sessions only: the ones already issued keep working until
   * they are revoked or expire.
   */
  readonly beforeSessionCreate?: (options: {
    readonly user: UserOf<F>
    readonly source: ProvisionSource
    /**
     * The session the request already carried, if it carried one.
     *
     * **Details**
     *
     * The request arrived as user A and a session is about to be minted for
     * user B. A policy that acts on that — an "upgrade an anonymous visitor"
     * merge — belongs in {@link AuthHooksService.beforeSessionMint} rather than
     * here, because here the sign-in may still be challenged and never happen.
     *
     * `None` on every unauthenticated sign-in, which is the ordinary case.
     */
    readonly current: Option.Option<SessionWithUser>
  }) => Effect.Effect<void, PolicyRefused>

  /**
   * Consulted once the sign-in is *going to happen*: after
   * {@link AuthHooksService.beforeSessionCreate} admitted it and after the
   * sign-in pipeline said `Proceed`, immediately before the session row is
   * written.
   *
   * **When to use**
   *
   * For the work that must not happen for a sign-in that is never completed.
   * The two hook points answer two different questions, and the difference is
   * the whole reason there are two:
   *
   * - `beforeSessionCreate` asks *may this person sign in at all*. It runs
   *   first, so a deployment that has withdrawn access refuses before a factor
   *   plugin issues a pending row, sends an SMS or writes anything on that
   *   person's behalf.
   * - `beforeSessionMint` asks *what has to happen as this session is minted*.
   *   A second factor may still be owed when the first runs, and a challenged
   *   sign-in mints nothing — so a merge, a migration of somebody's data, a
   *   `DELETE` of the account being merged away, run here or they run for a
   *   sign-in that never completed.
   *
   * This is the seam the anonymous plugin's merge hangs on, and it is why that
   * plugin does not use `beforeSessionCreate`: a visitor deleted at the earlier
   * point is deleted even when the person then abandons the second-factor
   * prompt, mistypes their codes, or is refused.
   *
   * **Gotchas**
   *
   * A `PolicyRefused` here aborts the mint, and nothing has been published yet
   * — but the credential the caller presented is already spent, because it was
   * checked before either hook ran. Refuse here only for something the caller
   * genuinely cannot retry past.
   *
   * It is not run inside the same transaction as the write of the session row:
   * `SignIn` holds no transaction runner. A hook that must be atomic with
   * something opens its own, as the anonymous plugin does; the residue is that
   * a storage failure in the mint itself, after this hook committed, leaves the
   * hook's work done and no session issued.
   */
  readonly beforeSessionMint?: (options: {
    readonly user: UserOf<F>
    readonly source: ProvisionSource
    /** The session the request already carried, if it carried one. */
    readonly current: Option.Option<SessionWithUser>
  }) => Effect.Effect<void, PolicyRefused>

  /**
   * Consulted before an e-mail change is started, ahead of any token being
   * minted and ahead of the lookup that decides which hop is sent — so the
   * enumeration posture of that flow is exactly what it was.
   */
  readonly beforeEmailChange?: (options: {
    readonly user: UserOf<F>
    readonly newEmail: string
  }) => Effect.Effect<void, PolicyRefused>

  /**
   * Consulted before an account is deleted, on both shapes of the flow.
   *
   * **Gotchas**
   *
   * On the mail-confirmed shape it is consulted twice — once when the link is
   * asked for and once when it is followed — and the second consultation happens
   * *after* the token has been claimed, so a refused link is spent rather than
   * left replayable.
   */
  readonly beforeUserDelete?: (options: { readonly user: UserOf<F> }) => Effect.Effect<void, PolicyRefused>

  /**
   * Consulted before a provider identity is attached to a user that already
   * exists — implicit linking on a matching address, and `linkSocial` alike.
   *
   * First provisioning is not a link: that is `beforeUserCreate`'s job.
   */
  readonly beforeAccountLink?: (options: {
    readonly user: UserOf<F>
    readonly providerId: string
    readonly info: OAuthUserInfo
  }) => Effect.Effect<void, PolicyRefused>
}

/**
 * The hooks a deployment installed. See {@link AuthHooksOf}.
 *
 * @category models
 * @since 0.1.0
 */
export interface AuthHooksService extends AuthHooksOf<{}> {}

/**
 * The hooks this deployment installed, or none.
 *
 * **Details**
 *
 * A `Context.Reference` rather than a service: its default is "no hooks at
 * all", so `Auth.layer` needs nothing provided to it and every existing
 * deployment keeps working unchanged. {@link layer} sets it; {@link append}
 * adds to whatever is already there.
 *
 * **Gotchas**
 *
 * It is read when the layer that consults it is *built*, not per request. A
 * deployment therefore provides its hooks underneath `Auth.layer`
 * (`Layer.provide`), and cannot swap them for one request.
 *
 * @category services
 * @since 0.1.0
 */
export const AuthHooks: Context.Reference<AuthHooksService> = Context.Reference<AuthHooksService>(
  "effect-auth/AuthHooks",
  { defaultValue: () => ({}) }
)

/**
 * {@link AuthHooks}, seen through a model's custom fields.
 *
 * **Details**
 *
 * The same key with a narrower shape — the candidate a hook rewrites and the
 * user it inspects carry the deployment's own columns. See `userStoreOf` in
 * `domain/Stores.ts` for what a typed view is and why it is sound: core reads
 * the base-typed key, hands it a row that really does carry the extra columns,
 * and re-validates whatever a rewrite answers with through the model itself.
 *
 * **Example**
 *
 * ```ts skip-type-checking
 * const Hooks = Layer.succeed(hooksOf(model))({
 *   beforeUserCreate: ({ candidate }) => Effect.succeed({ ...candidate, plan: "free" })
 * })
 * ```
 *
 * @category services
 * @since 0.1.0
 */
export const hooksOf = <F extends UserFields>(_model: UserModel<F>): Context.Reference<AuthHooksOf<F>> =>
  Context.Reference<AuthHooksOf<F>>("effect-auth/AuthHooks", { defaultValue: () => ({}) })

// -----------------------------------------------------------------------------
// Composition
// -----------------------------------------------------------------------------

/**
 * Runs `first` and then `second`, and stops at the first refusal.
 *
 * Absent on either side is the identity, so a set with no member of this kind
 * contributes no wrapper at all — which is what keeps `{}` a true identity for
 * {@link combine}.
 */
const sequence = <O>(
  first: ((options: O) => Effect.Effect<void, PolicyRefused>) | undefined,
  second: ((options: O) => Effect.Effect<void, PolicyRefused>) | undefined
): ((options: O) => Effect.Effect<void, PolicyRefused>) | undefined => {
  if (first === undefined) return second
  if (second === undefined) return first
  // `second` is applied inside `flatMap` rather than beside it, so a hook
  // written as a plain function with a body is not entered at all when the one
  // before it refused.
  return (options) => Effect.flatMap(first(options), () => second(options))
}

/**
 * Two hook sets as one: `before*` chain left to right, each seeing what the one
 * before it answered, and the first refusal wins.
 *
 * **Details**
 *
 * This is the monoid `append` is written in terms of, with `{}` — the
 * {@link AuthHooks} default — as its identity. `beforeUserCreate` threads the
 * candidate through: `second` is handed the row `first` rewrote, not the
 * original. The rest sequence, and a refusal short-circuits whatever would have
 * followed.
 *
 * @category combinators
 * @since 0.1.0
 */
export const combine = (first: AuthHooksService, second: AuthHooksService): AuthHooksService => {
  const firstCreate = first.beforeUserCreate
  const secondCreate = second.beforeUserCreate
  const beforeUserCreate =
    firstCreate === undefined
      ? secondCreate
      : secondCreate === undefined
        ? firstCreate
        : (options: { readonly candidate: UserInsertOf<{}>; readonly source: ProvisionSource }) =>
            Effect.flatMap(firstCreate(options), (candidate) => secondCreate({ ...options, candidate }))

  const afterUserCreate = sequence(first.afterUserCreate, second.afterUserCreate)
  const beforeSessionCreate = sequence(first.beforeSessionCreate, second.beforeSessionCreate)
  const beforeSessionMint = sequence(first.beforeSessionMint, second.beforeSessionMint)
  const beforeEmailChange = sequence(first.beforeEmailChange, second.beforeEmailChange)
  const beforeUserDelete = sequence(first.beforeUserDelete, second.beforeUserDelete)
  const beforeAccountLink = sequence(first.beforeAccountLink, second.beforeAccountLink)

  // Only the members at least one side actually declared: a combined set that
  // named all seven would turn "no hook here" into "a hook that does nothing",
  // which is observably different to a caller that branches on absence.
  return {
    ...omitUndefined({
      beforeUserCreate,
      afterUserCreate,
      beforeSessionCreate,
      beforeSessionMint,
      beforeEmailChange,
      beforeUserDelete,
      beforeAccountLink
    })
  }
}

// -----------------------------------------------------------------------------
// Layers
// -----------------------------------------------------------------------------

/**
 * Installs `hooks`, replacing whatever was there.
 *
 * **When to use**
 *
 * In an application, which knows what it installed. Provide it underneath
 * `Auth.layer` — the reference is read when the services that consult it are
 * built.
 *
 * **Example**
 *
 * ```ts skip-type-checking
 * const AuthLive = Auth.layer(options).pipe(Layer.provide(Hooks.layer(myHooks)))
 * ```
 *
 * @category layers
 * @since 0.1.0
 */
export const layer = (hooks: AuthHooksService): Layer.Layer<never> => Layer.succeed(AuthHooks)(hooks)

/**
 * Adds `hooks` after whatever is already installed, rather than replacing it.
 *
 * **When to use**
 *
 * In a plugin, which cannot know what else the deployment installed. Whatever
 * was there runs first and this runs after it, on the same terms as
 * {@link combine} — so an application's refusal short-circuits the plugin's
 * hook, and a plugin never silently disables an application's policy.
 *
 * **Details**
 *
 * This is exactly what `Layer.updateService` does, written as the layer it
 * builds from: reading {@link AuthHooks} here resolves the reference's default
 * when nothing provided one, so appending to an empty deployment works without
 * the deployment having to install an empty set first.
 *
 * **Example**
 *
 * ```ts skip-type-checking
 * const AuthLive = Auth.layer(options).pipe(
 *   Layer.provide(Hooks.append(pluginHooks)),
 *   Layer.provide(Hooks.layer(applicationHooks))
 * )
 * ```
 *
 * @category layers
 * @since 0.1.0
 */
export const append = (hooks: AuthHooksService): Layer.Layer<never> =>
  Layer.effect(
    AuthHooks,
    Effect.map(AuthHooks, (installed) => combine(installed, hooks))
  )
