/**
 * The one place a sign-in becomes a session.
 *
 * **Details**
 *
 * Four flows in this library establish sessions — a password sign-up, a
 * password sign-in, an OAuth callback and a mailed link — and every one of them
 * used to run its own `beforeSessionCreate`, mint its own row and publish its
 * own `SignedIn`. What a *sign-in* is, though, is a property of all four at
 * once: which factors were proved, what assurance that reaches, and whether
 * something still has to happen before a session may exist at all. There was
 * nowhere to write that down, so this module is that place, and the four flows
 * are now four callers of {@link SignInService.complete}.
 *
 * `complete` does three things in a fixed order:
 *
 * 1. asks `AuthHooks.beforeSessionCreate` whether this person may start a
 *    session — now carrying `current`, the session the request arrived with, so
 *    a policy can adopt or merge an anonymous visitor inside the mint;
 * 2. asks the {@link SignInPipeline} whether anything is still owed. A factor
 *    plugin installs a decider here, and a decider is the *only* interposition
 *    point: there is no path list, so a plugin cannot forget one of the four
 *    flows the way a route matcher does;
 * 3. on `Proceed`, mints the session with the evidence as its log and publishes
 *    `SignedIn`.
 *
 * **Gotchas**
 *
 * A `Challenge` mints **nothing** — no session row, no token, no event. The
 * pending state lives in whatever the decider issued (a `Verifications` row,
 * carried in a `__Host-` cookie), never in a half-authenticated session, because
 * a `sessions` row is a working credential everywhere in this library and one
 * that had cleared only the first factor would be a total bypass for every
 * endpoint that forgot to check its level.
 *
 * @since 0.2.0
 */
import { Context, type DateTime, Effect, Layer, type Option, type Redacted } from "effect"
import { omitUndefined } from "../internal/records.js"
import { AuthEvents, oauthMethod, passwordMethod, publishSafely } from "./Events.js"
import type { PolicyRefused, ProvisionSource } from "./Hooks.js"
import { hooksOf } from "./Hooks.js"
import type { Session, UserFields, UserModel, UserOf } from "./Schema.js"
import { baseUserModel } from "./Schema.js"
import type { Evidence, Sessions } from "./Sessions.js"
import { sessionsOf } from "./Sessions.js"
import type { PersistenceError, SessionWithUser } from "./Stores.js"

// -----------------------------------------------------------------------------
// Models
// -----------------------------------------------------------------------------

/**
 * What the request said, as far as a session is concerned.
 *
 * @category models
 * @since 0.2.0
 */
export interface SignInRequest {
  /** `false` shortens the session's lifetime. Defaults to `true`. */
  readonly rememberMe?: boolean | undefined
  /** Recorded on the row so a person can recognise their own devices. */
  readonly ipAddress: string | null
  /** Recorded for the same reason. */
  readonly userAgent: string | null
}

/**
 * Everything {@link SignInService.complete} needs to decide whether a session
 * may exist, and to mint it if it may.
 *
 * @category models
 * @since 0.2.0
 */
export interface CompleteOptions<F extends UserFields = {}> {
  /** Whose sign-in this is. The credential has already been verified. */
  readonly user: UserOf<F>
  /** Which flow verified it. */
  readonly source: ProvisionSource
  /**
   * What was proved, in the order it was proved.
   *
   * A flow that has just finished one ceremony passes one entry and lets the
   * mint stamp it. A flow completing a *pending* sign-in passes the evidence it
   * accumulated — the first factor, with the moment it originally completed —
   * followed by its own.
   */
  readonly evidence: ReadonlyArray<Evidence>
  /**
   * The session the request already carried, if any: the seam an anonymous
   * account is adopted or merged through. `None` on an ordinary sign-in.
   */
  readonly current: Option.Option<SessionWithUser>
  readonly request: SignInRequest
}

/**
 * A challenge that must be answered before a session exists.
 *
 * **Details**
 *
 * `kind` names what the client is being asked for (`"mfa"`), and `available`
 * the factor types this person can answer it with, so a client can render the
 * right prompt. `token` addresses the pending state and travels **only** in a
 * `__Host-` cookie — never in a response body, never in a URL. Neither member
 * carries an address, an identifier or a secret beyond that token.
 *
 * @category models
 * @since 0.2.0
 */
export interface SignInChallenge {
  readonly _tag: "Challenge"
  readonly kind: string
  readonly available: ReadonlyArray<string>
  readonly token: Redacted.Redacted
  readonly expiresAt: DateTime.Utc
}

/**
 * What the pipeline decided: mint the session, or ask for something first.
 *
 * @category models
 * @since 0.2.0
 */
export type SignInDecision = { readonly _tag: "Proceed" } | SignInChallenge

/**
 * The decision that mints a session, as a value — a decider with nothing to say
 * answers this rather than building one per call.
 *
 * @category constructors
 * @since 0.2.0
 */
export const proceed: SignInDecision = { _tag: "Proceed" }

/**
 * What a sign-in came to: a session, or a challenge that owes one.
 *
 * **Gotchas**
 *
 * The two are mutually exclusive by construction, which is what the HTTP layer
 * relies on when it refuses to write a session cookie beside a challenge.
 *
 * @category models
 * @since 0.2.0
 */
export type SignInResult<F extends UserFields = {}> =
  | {
      readonly _tag: "Complete"
      readonly session: Session
      readonly user: UserOf<F>
      readonly token: Redacted.Redacted
    }
  | SignInChallenge

// -----------------------------------------------------------------------------
// Pipeline
// -----------------------------------------------------------------------------

/**
 * The deciders installed on sign-in, for a model parameterized by `F`.
 *
 * **Details**
 *
 * One optional member, and an absent one means "nothing is owed". It runs
 * inside whichever transaction the calling flow holds and after the credential
 * has been verified, so the same rules as `AuthHooks` apply: short and local,
 * no network call, no sleep. Issuing the pending-auth row it returns a token for
 * is a database write, which is exactly what it may do.
 *
 * **Gotchas**
 *
 * A decider must answer `Proceed` for `source._tag === "EmailPassword"` on a
 * *sign-up*. An account created a millisecond ago holds no second factor, so a
 * challenge there asks for something nobody can answer: `Passwords.signUp`
 * answers `{ user, session: None }` — the shape `autoSignIn: false` already
 * produces — logs a warning, and whatever the decider issued on the way is
 * stranded. A plugin that wants a factor enrolled at registration enrols it
 * after the account exists, and challenges the *next* sign-in.
 *
 * @category models
 * @since 0.2.0
 */
export interface SignInPipelineOf<F extends UserFields> {
  readonly decide?: (options: CompleteOptions<F>) => Effect.Effect<SignInDecision, PolicyRefused | PersistenceError>
}

/**
 * The deciders installed on sign-in. See {@link SignInPipelineOf}.
 *
 * @category models
 * @since 0.2.0
 */
export interface SignInPipelineService extends SignInPipelineOf<{}> {}

/**
 * The sign-in deciders this deployment installed, or none.
 *
 * **Details**
 *
 * A `Context.Reference` rather than a service, on exactly the terms `AuthHooks`
 * is: its default contributes nothing, so a deployment with no factor plugins
 * provides nothing and every verified credential proceeds. It is read when the
 * services that consult it are built, so it is provided *underneath*
 * `Auth.layer` and cannot be swapped per request.
 *
 * @category services
 * @since 0.2.0
 */
export const SignInPipeline: Context.Reference<SignInPipelineService> = Context.Reference<SignInPipelineService>(
  "effect-auth/domain/SignIn/SignInPipeline",
  { defaultValue: () => ({}) }
)

/**
 * {@link SignInPipeline}, seen through a model's custom fields — the same key
 * with a narrower shape. See `hooksOf` in `domain/Hooks.ts`.
 *
 * @category services
 * @since 0.2.0
 */
export const pipelineOf = <F extends UserFields>(_model: UserModel<F>): Context.Reference<SignInPipelineOf<F>> =>
  Context.Reference<SignInPipelineOf<F>>("effect-auth/domain/SignIn/SignInPipeline", { defaultValue: () => ({}) })

/**
 * Two pipelines as one: `first` decides, and `second` is asked only if `first`
 * had nothing to ask for.
 *
 * **Details**
 *
 * The monoid {@link append} is written in terms of, with `{}` — the
 * {@link SignInPipeline} default — as its identity. The **first challenge
 * wins**: a second decider is not even entered once one has interrupted the
 * sign-in, so two factor plugins cannot both issue a pending row for one
 * ceremony and leave the second one orphaned. A refusal short-circuits the same
 * way.
 *
 * @category combinators
 * @since 0.2.0
 */
export const combine = (first: SignInPipelineService, second: SignInPipelineService): SignInPipelineService => {
  const firstDecide = first.decide
  const secondDecide = second.decide
  const decide =
    firstDecide === undefined
      ? secondDecide
      : secondDecide === undefined
        ? firstDecide
        : (options: CompleteOptions) =>
            Effect.flatMap(
              firstDecide(options),
              (decision): Effect.Effect<SignInDecision, PolicyRefused | PersistenceError> =>
                decision._tag === "Challenge" ? Effect.succeed(decision) : secondDecide(options)
            )
  // Only the member at least one side declared, so that "no decider" stays
  // distinguishable from "a decider that always proceeds".
  return { ...omitUndefined({ decide }) }
}

/**
 * Installs `pipeline`, replacing whatever was there.
 *
 * @category layers
 * @since 0.2.0
 */
export const layerPipeline = (pipeline: SignInPipelineService): Layer.Layer<never> =>
  Layer.succeed(SignInPipeline)(pipeline)

/**
 * Adds `pipeline` after whatever is already installed, rather than replacing
 * it — what a plugin uses, since it cannot know what else the deployment
 * installed.
 *
 * @category layers
 * @since 0.2.0
 */
export const appendPipeline = (pipeline: SignInPipelineService): Layer.Layer<never> =>
  Layer.effect(
    SignInPipeline,
    Effect.map(SignInPipeline, (installed) => combine(installed, pipeline))
  )

// -----------------------------------------------------------------------------
// Service
// -----------------------------------------------------------------------------

/**
 * The {@link SignIn} service definition.
 *
 * @category models
 * @since 0.2.0
 */
export interface SignInService<F extends UserFields = {}> {
  /**
   * Turns a verified credential into a session, or into the challenge that owes
   * one.
   *
   * **Gotchas**
   *
   * Call it *after* the credential has been verified and after any
   * constant-cost timing defence has run, so that a `PolicyRefused` or a
   * challenge is only ever shown to somebody who already proved something.
   */
  readonly complete: (options: CompleteOptions<F>) => Effect.Effect<SignInResult<F>, PolicyRefused | PersistenceError>
}

/**
 * The sign-in choke point.
 *
 * @category services
 * @since 0.2.0
 */
export class SignIn extends Context.Service<SignIn, SignInService>()("effect-auth/domain/SignIn/SignIn") {}

/**
 * {@link SignIn}, seen through a model's custom fields. See `sessionsOf` in
 * `domain/Sessions.ts` for what a typed view is and why it is sound.
 *
 * @category services
 * @since 0.2.0
 */
export const signInOf = <F extends UserFields>(_model: UserModel<F>): Context.Service<SignIn, SignInService<F>> =>
  Context.Service<SignIn, SignInService<F>>("effect-auth/domain/SignIn/SignIn")

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

/**
 * The `method` a `SignedIn` event carries for a sign-in from `source`.
 *
 * **Details**
 *
 * The entry point, not the evidence: `"password"` for both halves of the
 * e-mail-and-password flow, `oauth:<providerId>` for a callback, the plugin's
 * own name for a plugin. The evidence travels beside it, on the event's
 * `methods`.
 *
 * @category combinators
 * @since 0.2.0
 */
export const methodOf = (source: ProvisionSource): string => {
  switch (source._tag) {
    case "EmailPassword":
      return passwordMethod
    case "OAuth":
      return oauthMethod(source.providerId)
    case "MagicLink":
      return "magic-link"
    case "Plugin":
      return source.plugin
  }
}

/**
 * Builds the {@link SignIn} implementation from the session service, the event
 * hub, and whatever hooks and deciders were installed.
 *
 * @category constructors
 * @since 0.2.0
 */
export const make: <F extends UserFields>(
  model: UserModel<F>
) => Effect.Effect<SignInService<F>, never, Sessions | AuthEvents> = Effect.fnUntraced(function* <F extends UserFields>(
  model: UserModel<F>
) {
  const sessions = yield* sessionsOf(model)
  const events = yield* AuthEvents
  const hooks = yield* hooksOf(model)
  const pipeline = yield* pipelineOf(model)

  const complete = Effect.fnUntraced(function* (options: CompleteOptions<F>) {
    // First, because a deployment that has withdrawn access decides whether
    // this person may start a session at all — before anything is issued on
    // their behalf.
    const beforeSession = hooks.beforeSessionCreate
    if (beforeSession !== undefined) {
      yield* beforeSession({ user: options.user, source: options.source, current: options.current })
    }

    const decide = pipeline.decide
    const decision = decide === undefined ? proceed : yield* decide(options)
    if (decision._tag === "Challenge") {
      // Nothing is minted and nothing is published: as far as every other part
      // of this library is concerned, no sign-in has happened yet — which is
      // exactly why `beforeSessionMint` has not run.
      return decision satisfies SignInResult<F>
    }

    // The sign-in is going to happen. Anything that must not happen for one
    // that does not — a merge, a deletion of the account being merged away —
    // runs here rather than above the decision.
    const beforeMint = hooks.beforeSessionMint
    if (beforeMint !== undefined) {
      yield* beforeMint({ user: options.user, source: options.source, current: options.current })
    }

    const created = yield* sessions.createUnchecked({
      userId: options.user.id,
      ipAddress: options.request.ipAddress,
      userAgent: options.request.userAgent,
      rememberMe: options.request.rememberMe,
      methods: options.evidence
    })
    yield* publishSafely(events, {
      _tag: "SignedIn",
      userId: options.user.id,
      sessionId: created.session.id,
      method: methodOf(options.source),
      // The stamped log the row carries, not the caller's unstamped evidence,
      // so a subscriber and the session agree on what happened and when.
      methods: created.session.methods
    })
    return {
      _tag: "Complete",
      session: created.session,
      user: options.user,
      token: created.token
    } satisfies SignInResult<F>
  })

  return signInOf(model).of({ complete })
})

/**
 * Provides {@link SignIn} for the user model given.
 *
 * @category layers
 * @since 0.2.0
 */
export const layerFor = <F extends UserFields>(
  model: UserModel<F>
): Layer.Layer<SignIn, never, Sessions | AuthEvents> => Layer.effect(signInOf(model), make(model))

/**
 * {@link layerFor}, for a deployment that added no user fields of its own.
 *
 * @category layers
 * @since 0.2.0
 */
export const layer: Layer.Layer<SignIn, never, Sessions | AuthEvents> = layerFor(baseUserModel)
