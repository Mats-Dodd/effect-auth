/**
 * Anonymous accounts: signing in as nobody, and turning that visitor into
 * somebody later.
 *
 * **Details**
 *
 * An anonymous visitor is a **real** `users` row. `users.email` is `NOT NULL`,
 * unique, and has to contain an `@`, and every lookup in this library goes
 * through it — `findByEmail`, `normalizeEmail`, the OAuth linking algorithm —
 * so making it nullable would be a change to five flows in order to describe a
 * sixth. Instead the address is synthetic:
 * `anon-<uuidv7>@anonymous.invalid`, in the domain RFC 2606 reserves so that
 * nothing can ever be delivered to it. {@link isSyntheticEmail} is how anything
 * that composes a message can tell.
 *
 * What makes the row anonymous is a marker in the plugin's own table, never an
 * `is_anonymous` column on `users`. Adoption is that marker's deletion.
 *
 * **Gotchas — the three rules that shape this module**
 *
 * *An anonymous session is `aal0`.* Its evidence is the empty array, so
 * `Assurance.deriveAal` gives it `aal0` and `requireAssurance({ aal: "aal1" })`
 * is the one guard that excludes every anonymous visitor. No endpoint needs an
 * `isAnonymous` check of its own, and none should grow one.
 *
 * *Conversion is driven by the pipeline, not by a path list.* better-auth
 * matched request paths and forgot two of them, silently. Here it is
 * {@link layerHooks}: a `beforeSessionCreate` that sees the request arrived as
 * user A and a session is about to be minted for user B, runs the deployment's
 * `onMerge` and deletes A. It runs before the mint, so a failing `onMerge`
 * means no session at all — better-auth awaited theirs *after* setting the
 * cookie, leaving a valid session beside an error response.
 *
 * *Adoption is checked, not asserted.* {@link AnonymousService.adopt} clears
 * the marker only once the account really does hold a way in — a credential
 * with a hash, a provider identity, or an authenticator some factor plugin
 * contributed. A plugin that calls it too early gets `"NoCredential"` and the
 * person stays anonymous, which is the answer that cannot lock anybody out.
 *
 * @since 0.2.0
 */
import type { Redacted } from "effect"
import { Context, DateTime, Duration, Effect, Layer, Option } from "effect"
import type { AssurancePolicy } from "../domain/Assurance.js"
import { Authenticators, list as listAuthenticators } from "../domain/Authenticators.js"
import type { StepUpRequired } from "../domain/Errors.js"
import { AuthEvents, PluginEvent, publishSafely } from "../domain/Events.js"
import type { AuthHooksService, PolicyRefused } from "../domain/Hooks.js"
import {
  AuthHooks,
  combine as combineHooks,
  PolicyRefused as PolicyRefusedError,
  ProvisionSource
} from "../domain/Hooks.js"
import { credentialProviderId } from "../domain/Passwords.js"
import type { Session, User, UserId } from "../domain/Schema.js"
import { CredentialIssuer, normalizeEmail, User as UserModel } from "../domain/Schema.js"
import { requireAssuranceFor } from "../domain/Sessions.js"
import { SignIn, SignInResult } from "../domain/SignIn.js"
import type { PersistenceError } from "../domain/Stores.js"
import { AccountStore, UserStore, WithAuthTransaction } from "../domain/Stores.js"
import { Users } from "../domain/Users.js"
import { annotateAuthLogs, insertRow } from "../internal/effects.js"
import { withDefaults } from "../internal/records.js"
import type { AnonymousStoreService } from "./Store.js"
import { AnonymousStore, makeAnonymousStore } from "./Store.js"
import { SqlClient } from "effect/unstable/sql"
import { NotAnonymous } from "./Api.js"

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/**
 * The name this plugin provisions and publishes under.
 *
 * @category constructors
 * @since 0.2.0
 */
export const anonymousPlugin = "anonymous"

/**
 * What every user this plugin provisions, and every session it mints, came
 * from.
 *
 * @category constructors
 * @since 0.2.0
 */
export const anonymousSource: ProvisionSource = ProvisionSource.Plugin({ plugin: anonymousPlugin })

/**
 * The domain synthetic addresses are minted in.
 *
 * RFC 2606 reserves `.invalid` precisely so that it can never resolve, so a
 * mailer handed one of these fails to deliver rather than reaching a stranger.
 *
 * @category constructors
 * @since 0.2.0
 */
export const anonymousDomain = "anonymous.invalid"

/**
 * The `PolicyRefused.code` an anonymous sign-in a factor plugin challenged
 * leaves by.
 *
 * **Details**
 *
 * A brand-new visitor has no second factor to answer with, so a pipeline that
 * challenges here has refused rather than deferred, and there is nowhere for a
 * pending-authentication ceremony to go. Fail closed, with no session minted —
 * the same shape the email-otp flow uses for the same reason.
 *
 * @category constructors
 * @since 0.2.0
 */
export const mfaRequiredCode = "mfa_required"

/**
 * The policy that excludes every anonymous visitor: "you are somebody".
 *
 * **When to use**
 *
 * As the `RequireAssurance` annotation on any endpoint an anonymous session
 * must not reach. It is the whole of what phase 1 promised — one guard instead
 * of an `isAnonymous` check scattered over the endpoints — because an anonymous
 * session's `methods` are empty and `aal0` is what `deriveAal` gives an empty
 * log.
 *
 * @category constructors
 * @since 0.2.0
 */
export const identifiedPolicy: AssurancePolicy = { aal: "aal1" }

/**
 * The endpoints an anonymous visitor is allowed to reach at `aal0` out of the
 * box: every way this library ships of acquiring a real credential without
 * leaving the account already in hand.
 *
 * **Details**
 *
 * The four flows phase 1 named — `setPassword`, `linkSocial`, passkey
 * registration and the email-OTP address change — spelled as the endpoint names
 * that serve them, which is why registration and the address change each appear
 * twice: both are two halves of one ceremony and an anonymous visitor has to
 * reach both.
 *
 * **Gotchas**
 *
 * A name here permits nothing on its own. An endpoint is reachable at `aal0`
 * unless a deployment annotates it {@link identifiedPolicy}, and this list is
 * only ever consulted by {@link AnonymousService.requireAdoptable}, which an
 * endpoint calls for itself. Adding a name is therefore a *narrowing* of what a
 * deployment tightened, never a widening of what this library serves.
 *
 * @category constructors
 * @since 0.2.0
 */
export const defaultAdoptEndpoints: ReadonlySet<string> = new Set([
  // The password this library owns.
  "setPassword",
  // A provider identity.
  "linkSocial",
  // A passkey, whose registration is two halves.
  "registerOptions",
  "registerVerify",
  // A real, verified address, whose change is two halves as well.
  "changeEmailSend",
  "changeEmailVerify"
])

/**
 * A synthetic address for a fresh anonymous visitor.
 *
 * @category combinators
 * @since 0.2.0
 */
export const syntheticEmail = (id: string): string => `anon-${id}@${anonymousDomain}`

/**
 * The address the throwaway first construction of a visitor's row carries. It
 * is replaced before anything is written; see `Anonymous.signIn`.
 */
const seedEmail = `anon@${anonymousDomain}`

/**
 * Whether an address is one this plugin minted.
 *
 * **When to use**
 *
 * In a mailer, or anywhere a message is composed: a synthetic address is not
 * deliverable, and sending to one is a bounce and a reputational cost rather
 * than a mail. The plugin's own tests assert that no message this library sends
 * ever names one.
 *
 * @category guards
 * @since 0.2.0
 */
export const isSyntheticEmail = (email: string): boolean => normalizeEmail(email).endsWith(`@${anonymousDomain}`)

// -----------------------------------------------------------------------------
// Options
// -----------------------------------------------------------------------------

/**
 * What merging an anonymous visitor into an account they are signing in to is
 * told.
 *
 * @category models
 * @since 0.2.0
 */
export interface MergeOptions {
  /** The anonymous user the request arrived as. About to be deleted. */
  readonly anonymous: User
  /** The account they are signing in to. */
  readonly target: User
}

/**
 * What a deployment may vary about anonymous accounts.
 *
 * @category models
 * @since 0.2.0
 */
export interface Config {
  /** The display name a fresh visitor is given. Defaults to `"Anonymous"`. */
  readonly name: string
  /**
   * Which `Authenticated` endpoints an anonymous visitor may reach at `aal0`.
   *
   * **Details**
   *
   * Names of endpoints, checked by {@link AnonymousService.requireAdoptable},
   * which the endpoint calls for itself. It is deliberately not a path matcher:
   * an endpoint states its own name, exactly as it states its own
   * `RequireAssurance` annotation, so there is no regex to forget a route in.
   *
   * Defaults to {@link defaultAdoptEndpoints}. The library's own endpoints all
   * admit `aal0` today, because `freshSession` states no level — this list is
   * what a deployment tightens *with*, by annotating everything else
   * {@link identifiedPolicy} and letting the adopt list back through.
   */
  readonly adoptEndpoints: ReadonlySet<string>
  /** How long a visitor may be idle before {@link AnonymousService.sweep} removes them. Defaults to 30 days. */
  readonly idleFor: Duration.Duration
  /** How many visitors one {@link AnonymousService.sweep} may remove. Defaults to `1000`. */
  readonly sweepLimit: number
  /**
   * What to do with an anonymous visitor's work when they sign in to an account
   * that already exists.
   *
   * **Details**
   *
   * Runs inside the merge transaction, *before* the anonymous row is deleted
   * and before any session is minted, so a `PolicyRefused` or a defect leaves
   * both accounts untouched and produces no session at all. The default is
   * absent, which means the default behaviour is "delete A".
   *
   * **Gotchas**
   *
   * It has no requirements channel, because a hook is installed underneath
   * `Auth.layer` where the deployment's own services are not yet in context.
   * Close over whatever it needs — a repository the application already holds —
   * when building the layer.
   *
   * A hook holds a database transaction open: no network call, no sleep.
   */
  readonly onMerge?: ((options: MergeOptions) => Effect.Effect<void, PolicyRefused>) | undefined
}

/**
 * {@link Config}, with every field optional and the adopt list accepted as
 * anything iterable.
 *
 * @category models
 * @since 0.2.0
 */
export interface Options {
  readonly name?: string | undefined
  readonly adoptEndpoints?: Iterable<string> | undefined
  readonly idleFor?: Duration.Duration | undefined
  readonly sweepLimit?: number | undefined
  readonly onMerge?: ((options: MergeOptions) => Effect.Effect<void, PolicyRefused>) | undefined
}

/**
 * The defaults every unstated {@link Options} field resolves to.
 *
 * @category constructors
 * @since 0.2.0
 */
export const defaults: Config = {
  name: "Anonymous",
  adoptEndpoints: defaultAdoptEndpoints,
  // Firebase's own default for the same feature, and the number a deployment
  // that has thought about it will change.
  idleFor: Duration.days(30),
  sweepLimit: 1000
}

/**
 * Resolves {@link Options} against {@link defaults}.
 *
 * @category constructors
 * @since 0.2.0
 */
export const makeConfig = (options?: Options): Config =>
  withDefaults(defaults, {
    name: options?.name,
    idleFor: options?.idleFor,
    sweepLimit: options?.sweepLimit,
    onMerge: options?.onMerge,
    adoptEndpoints: options?.adoptEndpoints === undefined ? undefined : new Set(options.adoptEndpoints)
  })

// -----------------------------------------------------------------------------
// Models
// -----------------------------------------------------------------------------

/**
 * What {@link AnonymousService.signIn} takes.
 *
 * @category models
 * @since 0.2.0
 */
export interface SignInOptions {
  readonly ipAddress?: string | null | undefined
  readonly userAgent?: string | null | undefined
  readonly rememberMe?: boolean | undefined
}

/**
 * What {@link AnonymousService.signIn} answers with.
 *
 * @category models
 * @since 0.2.0
 */
export interface AnonymousSession {
  readonly user: User
  readonly session: Session
  /** The raw session token, for the cookie the handler sets. */
  readonly token: Redacted.Redacted
}

/**
 * What {@link AnonymousService.adopt} did.
 *
 * @category models
 * @since 0.2.0
 */
export type AdoptOutcome =
  /** The marker is gone; this person is somebody now. */
  | "Adopted"
  /** There was no marker: they were already somebody, and nothing changed. */
  | "NotAnonymous"
  /**
   * They hold no way into the account yet, so the marker stays. The answer that
   * cannot lock anybody out.
   */
  | "NoCredential"

/**
 * What {@link AnonymousService.adopt} takes.
 *
 * @category models
 * @since 0.2.0
 */
export interface AdoptOptions {
  readonly userId: UserId
  /**
   * A real address to move the account to, replacing the synthetic one.
   *
   * **Gotchas**
   *
   * Only pass one this deployment has *proved* — a verified e-mail OTP, an
   * OAuth identity's verified address. The plugin writes it verbatim and marks
   * it verified unless told otherwise; it cannot check what a caller proved.
   */
  readonly email?: string | undefined
  /** Whether that address is verified. Defaults to `true`, since it should be proved. */
  readonly emailVerified?: boolean | undefined
}

// -----------------------------------------------------------------------------
// Service
// -----------------------------------------------------------------------------

/**
 * The {@link Anonymous} service definition.
 *
 * @category models
 * @since 0.2.0
 */
export interface AnonymousService {
  /** The resolved configuration this instance was built with. */
  readonly config: Config

  /**
   * Provisions an anonymous visitor and establishes their session.
   *
   * **Details**
   *
   * The user row, the marker and the deployment's `afterUserCreate` all commit
   * together; the session is minted afterwards through `SignIn.complete`, so a
   * hook that refuses the account leaves nothing behind.
   *
   * Fails `PolicyRefused` when the pipeline challenges — see
   * {@link mfaRequiredCode} — because a visitor who has just been invented has
   * no second factor to answer with.
   */
  readonly signIn: (options?: SignInOptions) => Effect.Effect<AnonymousSession, PolicyRefused | PersistenceError>

  /** Whether a user is still an anonymous visitor. */
  readonly isAnonymous: (userId: UserId) => Effect.Effect<boolean, PersistenceError>

  /** Moves a visitor's `last_seen_at` to now, so the sweep leaves them alone. */
  readonly touch: (userId: UserId) => Effect.Effect<boolean, PersistenceError>

  /**
   * Clears the marker — and, when handed a proved address, replaces the
   * synthetic one — once the account really does hold a way in.
   *
   * **When to use**
   *
   * This is the adoption seam. A plugin that has just given this person a
   * credential (`setPassword`, `linkSocial`, a passkey, a verified e-mail OTP)
   * calls it; nothing happens automatically, because only the caller knows that
   * its own write committed.
   */
  readonly adopt: (options: AdoptOptions) => Effect.Effect<AdoptOutcome, PersistenceError>

  /**
   * Refuses `endpoint` for an anonymous session unless the deployment put it on
   * the adopt list.
   *
   * **When to use**
   *
   * From a handler whose endpoint an anonymous visitor may only reach in order
   * to *stop* being one. The endpoint names itself, so there is no path matcher
   * to forget a route in, and the refusal is the ordinary `StepUpRequired`
   * every other assurance failure produces.
   */
  readonly requireAdoptable: (
    session: Session,
    endpoint: string
  ) => Effect.Effect<void, StepUpRequired | PersistenceError>

  /**
   * Deletes an anonymous visitor outright — the row, its sessions and its
   * accounts.
   *
   * Fails {@link NotAnonymous} for a user who has been adopted: destroying a
   * real account is `Users.requestDeletion`'s job.
   */
  readonly discard: (user: User) => Effect.Effect<void, NotAnonymous | PersistenceError>

  /**
   * Removes the anonymous visitors who have been idle for longer than
   * `idleFor` and hold no live session.
   *
   * **When to use**
   *
   * From the deployment's own scheduler. It is an `Effect` rather than a
   * running fibre on purpose: how often a sweep runs, and whether it runs on
   * this instance at all, is not a library decision.
   *
   * Answers how many were removed, and never removes more than `sweepLimit` in
   * one call, so one run cannot hold a connection for an unbounded time.
   */
  readonly sweep: (options?: {
    readonly idleFor?: Duration.Duration | undefined
    readonly limit?: number | undefined
  }) => Effect.Effect<number, PersistenceError>
}

/**
 * Anonymous accounts. See {@link AnonymousService}.
 *
 * @category services
 * @since 0.2.0
 */
export class Anonymous extends Context.Service<Anonymous, AnonymousService>()("effect-auth/anonymous/Anonymous") {}

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

/**
 * What {@link make} needs.
 *
 * @category models
 * @since 0.2.0
 */
export type Requirements = AnonymousStore | AuthEvents | SignIn | Users | UserStore | AccountStore | WithAuthTransaction

/**
 * Builds the {@link Anonymous} implementation.
 *
 * @category constructors
 * @since 0.2.0
 */
export const make: (options?: Options) => Effect.Effect<AnonymousService, never, Requirements> = Effect.fnUntraced(
  function* (options?: Options) {
    const settings = makeConfig(options)
    const store = yield* AnonymousStore
    const events = yield* AuthEvents
    const { complete: completeSignIn } = yield* SignIn
    const domain = yield* Users
    const users = yield* UserStore
    const accounts = yield* AccountStore
    const transaction = yield* WithAuthTransaction
    // Read here rather than per request, exactly as the email-otp plugin reads
    // it: the set of factor plugins is fixed when the layer is built.
    const authenticators = yield* Authenticators

    const signIn = Effect.fnUntraced(
      function* (request?: SignInOptions) {
        // The row, the marker and the session are one transaction. An
        // unauthenticated caller is what reaches this, so a refusal after the
        // row was committed would let anybody write users into the database at
        // the endpoint's rate limit and leave them for the sweep — and the
        // service's own promise is that a hook which refuses this visitor
        // leaves nothing behind.
        const result = yield* transaction.run(
          Effect.gen(function* () {
            // The address has to name the row, and the row's id is the model's
            // own UUIDv7 — so the row is built twice: once to learn the id, and
            // once to carry the address that id implies. Both constructions are
            // pure, and only the second is ever written. Reaching for a second
            // id generator instead would put a `Crypto` requirement on every
            // consumer of this plugin for no gain.
            const seed = yield* insertRow(UserModel.insert, {
              name: settings.name,
              email: seedEmail,
              emailVerified: false,
              image: null
            })
            const candidate = yield* insertRow(UserModel.insert, {
              id: seed.id,
              name: settings.name,
              email: syntheticEmail(seed.id),
              // Never: nothing has been proved, and the address is not one
              // anything could prove.
              emailVerified: false,
              image: null
            })
            // Through `Users.provision`, so `beforeUserCreate` may rewrite or
            // refuse this visitor exactly as it may any other person.
            const created = yield* domain.provision({ candidate, source: anonymousSource })
            // In the same transaction: a marker without a user, or a user
            // without a marker, is a person nobody can classify.
            yield* store.create(created.id)

            const completed = yield* completeSignIn({
              user: created,
              source: anonymousSource,
              // Empty on purpose. `deriveAal([])` is `aal0`, which is the whole
              // of how an anonymous session is told apart from a real one.
              evidence: [],
              current: Option.none(),
              request: {
                ipAddress: request?.ipAddress ?? null,
                userAgent: request?.userAgent ?? null,
                rememberMe: request?.rememberMe
              }
            })

            if (SignInResult.$is("Challenge")(completed)) {
              // Nothing was minted, and nothing here can answer a challenge: a
              // visitor invented a millisecond ago holds no second factor, so a
              // challenge is a refusal rather than something to defer. Failing
              // inside the transaction takes the row and the marker with it.
              yield* annotateAuthLogs(
                Effect.logDebug("the sign-in pipeline challenged an anonymous sign-in", { kind: completed.kind })
              )
              return yield* PolicyRefusedError.make({ code: mfaRequiredCode })
            }
            return completed
          })
        )

        return { user: result.user, session: result.session, token: result.token } satisfies AnonymousSession
      },
      (effect) => Effect.withSpan(effect, "Anonymous.signIn")
    )

    const isAnonymous = (userId: UserId) => Effect.map(store.find(userId), Option.isSome)

    /** How many ways into this account there are, counted the way `Accounts.unlink` counts them. */
    const waysIn = Effect.fnUntraced(function* (userId: UserId) {
      const rows = yield* accounts.listByUserId(userId)
      const credentials = rows.filter(
        (account) =>
          // A provider identity is a way in; a credential row with no hash is
          // not one, and a synthetic account never has one until something
          // gives it one.
          account.issuer !== CredentialIssuer ||
          account.providerId !== credentialProviderId ||
          account.passwordHash !== null
      ).length
      const contributed = yield* listAuthenticators(authenticators, userId)
      return credentials + contributed.filter((authenticator) => authenticator.signIn).length
    })

    /**
     * Whether this account holds a way in — a credential, an authenticator, or
     * a verified address of its own.
     *
     * **Details**
     *
     * A verified address that is not the synthetic one counts, because with a
     * code-by-e-mail plugin installed it *is* a way in: the person can sign in
     * at that mailbox, and nothing else about the account has to exist for that
     * to be true. Part D's rule is "a real credential **or verified
     * identifier**", and `waysIn` alone only counts the first half.
     *
     * This is what separates "a visitor" from "somebody who arrived as a
     * visitor and has since become a person". Only the first may be swept, and
     * only the first may be merged away.
     */
    const settled = Effect.fnUntraced(function* (userId: UserId) {
      if ((yield* waysIn(userId)) > 0) return true
      const found = yield* users.findById(userId)
      if (Option.isNone(found)) return false
      return found.value.emailVerified && !isSyntheticEmail(found.value.email)
    })

    const adopt = Effect.fnUntraced(function* (request: AdoptOptions) {
      const marker = yield* store.find(request.userId)
      if (Option.isNone(marker)) return "NotAnonymous" satisfies AdoptOutcome

      const email = request.email === undefined ? undefined : normalizeEmail(request.email)

      // Checked, not asserted: a plugin that calls this before its own write
      // committed gets the answer that cannot lock anybody out.
      //
      // A proved address the caller is handing over counts as a way in, and is
      // looked at *before* the refusal — otherwise the documented "adopt on a
      // verified e-mail" path could never adopt, because a visitor who verified
      // a real address holds no `accounts` row and contributes no authenticator,
      // while the address they just proved is a way in the moment a code-by-mail
      // plugin is installed.
      if (email === undefined && !(yield* settled(request.userId))) {
        return "NoCredential" satisfies AdoptOutcome
      }
      yield* transaction.run(
        Effect.gen(function* () {
          if (email !== undefined) {
            yield* users.update(request.userId, {
              email,
              emailVerified: request.emailVerified ?? true
            })
          }
          yield* store.clear(request.userId)
        })
      )

      yield* publishSafely(
        events,
        PluginEvent.make({
          plugin: anonymousPlugin,
          event: "AnonymousAdopted",
          userId: request.userId,
          // The address is not a secret and is what a subscriber needs to know
          // the account moved; nothing else about the person is recorded.
          data: email === undefined ? {} : { email }
        })
      )
      return "Adopted" satisfies AdoptOutcome
    })

    const requireAdoptable = Effect.fnUntraced(function* (session: Session, endpoint: string) {
      if (settings.adoptEndpoints.has(endpoint)) return
      // One rule, written once, in the core: an anonymous session's log is
      // empty, so `aal1` is exactly "you have proved something".
      yield* requireAssuranceFor(session, identifiedPolicy, [])
    })

    const discard = Effect.fnUntraced(function* (user: User) {
      if (!(yield* isAnonymous(user.id))) {
        return yield* NotAnonymous.make()
      }
      // Sessions, accounts and the marker cascade with the row, and `UserDeleted`
      // is published by the domain rather than by this plugin.
      yield* domain.delete(user)
    })

    const sweep = Effect.fnUntraced(
      function* (request?: { readonly idleFor?: Duration.Duration | undefined; readonly limit?: number | undefined }) {
        const now = yield* DateTime.now
        const idleFor = request?.idleFor ?? settings.idleFor
        const before = DateTime.subtractDuration(now, idleFor)
        const idle = yield* store.listIdle({ before, now, limit: request?.limit ?? settings.sweepLimit })

        let removed = 0
        for (const userId of idle) {
          const found = yield* users.findById(userId)
          if (Option.isNone(found)) continue
          // The marker says "arrived as a visitor", not "is disposable".
          // Nothing in this library clears it on its own — `setPassword`,
          // `linkSocial` and a passkey registration are all reachable at aal0
          // by design, and none of them can call a plugin — so a person who
          // acquired a real credential and then stopped visiting for a month
          // still carries it. Deleting them would destroy an account with a
          // password in it.
          if (yield* settled(userId)) continue
          yield* domain.delete(found.value)
          removed++
        }
        return removed
      },
      (effect) => Effect.withSpan(effect, "Anonymous.sweep")
    )

    return Anonymous.of({
      config: settings,
      signIn,
      isAnonymous,
      touch: (userId) => store.touch(userId),
      adopt,
      requireAdoptable,
      discard,
      sweep
    })
  }
)

/**
 * Provides {@link Anonymous}.
 *
 * @category layers
 * @since 0.2.0
 */
export const layer = (options?: Options): Layer.Layer<Anonymous, never, Requirements> =>
  Layer.effect(Anonymous, make(options))

// -----------------------------------------------------------------------------
// Merge on sign-in
// -----------------------------------------------------------------------------

/**
 * The merge hook: whenever a session is about to be minted for somebody other
 * than the anonymous visitor the request arrived as, the deployment's `onMerge`
 * runs and the visitor is deleted.
 *
 * **When to use**
 *
 * Provided *underneath* `Auth.layer`, which is where `AuthHooks` is read:
 *
 * ```ts skip-type-checking
 * const AuthLive = Auth.layer(options).pipe(
 *   Layer.provide(Anonymous.layerHooks({ onMerge })),
 *   Layer.provide(PgLive)
 * )
 * ```
 *
 * **Details**
 *
 * It appends rather than replaces — `Hooks.combine`'s monoid — so an
 * application's own `beforeSessionCreate` still runs, and still runs first: a
 * deployment's refusal short-circuits this, and this never silently disables a
 * deployment's policy.
 *
 * The merge and the deletion are one transaction, and they run at
 * `beforeSessionMint` — after the sign-in pipeline has said `Proceed` and
 * immediately before the session row is written — not at
 * `beforeSessionCreate`. The difference is the whole correctness of this hook:
 * at the earlier point a second factor may still be owed, and a challenged
 * sign-in mints nothing, so a visitor deleted there is deleted even when the
 * person abandons the prompt or runs out of attempts. Their data would be gone
 * and they would be signed in as nobody.
 *
 * A `PolicyRefused` from `onMerge` aborts the mint with both accounts intact; a
 * storage failure is a defect, which aborts it too.
 *
 * **Gotchas**
 *
 * It reads the marker table directly through a `SqlClient`, because the core
 * stores do not exist underneath `Auth.layer` — see `Store.ts`. The deletion is
 * `Users.delete`'s cascade written as one statement, so no `UserDeleted` is
 * published for a merged-away visitor; a subscriber that needs to know watches
 * `SignedIn`, which names the account that survived.
 *
 * @category layers
 * @since 0.2.0
 */
export const layerHooks = (options?: Options): Layer.Layer<never, never, SqlClient.SqlClient> =>
  Layer.effect(
    AuthHooks,
    Effect.gen(function* () {
      const installed = yield* AuthHooks
      const sql = yield* SqlClient.SqlClient
      const store = yield* makeAnonymousStore
      const settings = makeConfig(options)
      return combineHooks(installed, mergeHooks(sql, store, settings))
    })
  )

/** The hook set {@link layerHooks} appends. Separate so it can be tested on its own. */
const mergeHooks = (sql: SqlClient.SqlClient, store: AnonymousStoreService, settings: Config): AuthHooksService => ({
  beforeSessionMint: ({ current, user }) =>
    Effect.gen(function* () {
      if (Option.isNone(current)) return
      const visitor = current.value.user
      // Signing in again as oneself is not a merge.
      if (visitor.id === user.id) return
      if (Option.isNone(yield* store.find(visitor.id))) return

      yield* sql.withTransaction(
        Effect.gen(function* () {
          // Claim the marker first, and let the statement pick the winner. Two
          // sign-ins from one browser — a double submit, a retry — would
          // otherwise both read the marker, both run `onMerge`, and copy
          // somebody's data across twice; `onMerge` is a deployment's own
          // callback and carries no idempotency contract. Only the request
          // whose `DELETE` returned a row goes on.
          const claimed = yield* sql<{
            readonly user_id: string
          }>`DELETE FROM effect_auth_anonymous WHERE user_id = ${visitor.id} RETURNING user_id`
          if (claimed.length === 0) return

          // The marker says "arrived as a visitor", not "is disposable". A
          // visitor who has since set a password, linked a provider or proved a
          // real address is a person, and merging them away would destroy an
          // account somebody can sign in to. Nothing in this library clears the
          // marker on its own, so this is checked rather than assumed.
          //
          // Read here in SQL rather than through `Accounts` and `Users`,
          // because this hook is provided *underneath* `Auth.layer` and the
          // core stores do not exist yet — the same reason `Store.ts` exists.
          // Contributed authenticators cannot be counted for that reason: a
          // visitor whose only way in is a passkey is not seen here. Their
          // deployment should call `Anonymous.adopt` when the passkey is
          // registered, which is what clears the marker for good.
          const ways = yield* sql<{
            readonly id: string
          }>`SELECT id FROM accounts
             WHERE user_id = ${visitor.id}
               AND (issuer <> ${CredentialIssuer}
                 OR provider_id <> ${credentialProviderId}
                 OR password_hash IS NOT NULL)
             LIMIT 1`
          const rows = yield* sql<{
            readonly email: string
            readonly email_verified: boolean | number
          }>`SELECT email, email_verified FROM users WHERE id = ${visitor.id}`
          const row = rows[0]
          const provenAddress = row !== undefined && Boolean(row.email_verified) && !isSyntheticEmail(row.email)
          if (ways.length > 0 || provenAddress) return

          const merge = settings.onMerge
          if (merge !== undefined) yield* merge({ anonymous: visitor, target: user })
          yield* sql`DELETE FROM users WHERE id = ${visitor.id}`
        })
      )
    }).pipe(
      // A hook may fail `PolicyRefused` and nothing else; a storage failure
      // here is a broken deployment, and a defect aborts the mint exactly as a
      // refusal does. Fail closed either way. The tags are named rather than
      // the refusal excluded, so that a failure this hook grows later has to be
      // classified here instead of silently becoming a defect.
      Effect.catchTag(["PersistenceError", "SqlError"], Effect.die)
    )
})
