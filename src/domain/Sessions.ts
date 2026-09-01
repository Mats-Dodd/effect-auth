/**
 * The session lifecycle.
 *
 * `Sessions` owns everything that happens between "a token was minted" and "a
 * token no longer works": creation, resolution, the rolling refresh, freshness,
 * and revocation. It is the only module that ever holds a raw session token,
 * and it hands one out exactly once — from `Sessions.create` — because
 * only the SHA-256 digest is written to `sessions.token_hash`.
 *
 * **Details**
 *
 * Three lifetimes, all configured under `AuthConfig.session`:
 *
 * - `expiresIn` (default 7 days) — how long a new session lives.
 * - `updateAge` (default 1 day) — how much of that must elapse before a
 *   verified session has its expiry rolled forward. This throttles the write:
 *   without it every authenticated request would `UPDATE sessions`.
 * - `freshAge` (default 1 day) — how recently a session must have been
 *   *interactively authenticated* to authorize a sensitive operation such as
 *   changing a password. Freshness tracks `authenticatedAt`, which only
 *   {@link SessionsService.create} and {@link SessionsService.elevate} write: a
 *   session kept alive for a month by ordinary browsing is no evidence that the
 *   person at the keyboard is still the account's owner, and the rolling
 *   refresh must never restore it.
 *
 * A session also records *how* it was authenticated — the append-only
 * `methods` log and the `aal` derived from it — and can be raised to a higher
 * assurance in place through {@link SessionsService.elevate}, which rotates the
 * token so a copy captured at the lower level does not inherit the higher one.
 * {@link requireAssurance} is the guard that reads it.
 *
 * @since 0.1.0
 */
import { Context, DateTime, Duration, Effect, Layer, type Redacted } from "effect"
import { Model } from "effect/unstable/schema"
import type { AuthConfigService } from "../config/AuthConfig.js"
import { AuthConfig } from "../config/AuthConfig.js"
import { Token } from "../crypto/Token.js"
import { insertRow } from "../internal/effects.js"
import type { Aal, AssurancePolicy, AuthenticationFactor, AuthenticationMethod } from "./Assurance.js"
import { deriveAal, policyToJson } from "./Assurance.js"
import { NotFound, SessionExpired, StepUpRequired, Unauthorized } from "./Errors.js"
import { AuthEvents, publishSafely } from "./Events.js"
import type { Session, SessionId, UserFields, UserId, UserModel, UserOf } from "./Schema.js"
import { baseUserModel, Session as SessionModel } from "./Schema.js"
import { PersistenceError, type SessionStore, sessionStoreOf } from "./Stores.js"

// -----------------------------------------------------------------------------
// Models
// -----------------------------------------------------------------------------

/**
 * What {@link Sessions.create} needs to know.
 *
 * @category models
 * @since 0.1.0
 */
export interface CreateOptions {
  readonly userId: UserId
  /**
   * The client address, recorded on the row so a user can recognise their own
   * sessions in a device list. Never used for authorization.
   */
  readonly ipAddress?: string | null | undefined
  /**
   * The client's `User-Agent`, recorded for the same reason.
   */
  readonly userAgent?: string | null | undefined
  /**
   * When explicitly `false` the session is given
   * `session.rememberMeDisabledExpiresIn` (default 1 day) instead of
   * `session.expiresIn`. Defaults to `true`.
   */
  readonly rememberMe?: boolean | undefined
  /**
   * What the person proved to get this session, in the order they proved it.
   *
   * **Gotchas**
   *
   * Defaults to *nothing*, which derives `aal0` — a session that recorded no
   * evidence is honest about it and fails every {@link requireAssurance} that
   * asks for a level. The mint that knows how the person authenticated is
   * `SignIn.complete`, and it is the one every sign-in path in this library
   * goes through.
   */
  readonly methods?: ReadonlyArray<Evidence> | undefined
  /**
   * When the person interactively authenticated. Defaults to now, which is
   * what a mint means.
   */
  readonly authenticatedAt?: DateTime.Utc | undefined
}

/**
 * One thing a person proved, before it is stamped with the moment it
 * completed.
 *
 * **Details**
 *
 * An `Assurance.AuthenticationMethod` with `completedAt` optional. A ceremony
 * that has just finished leaves it out and the mint stamps it from the clock,
 * so there is one clock read per sign-in and no call site can misreport when
 * something happened. Evidence being *replayed* — the password step carried
 * through a pending second factor — states the moment it originally completed,
 * and keeps it.
 *
 * @category models
 * @since 0.2.0
 */
export interface Evidence {
  /** How the person authenticated. An open set — see `Assurance`. */
  readonly method: string
  /** What kind of thing it proved. */
  readonly factor: AuthenticationFactor
  /** Whether the ceremony is bound to an origin, as WebAuthn is. */
  readonly phishingResistant: boolean
  /** Whether NIST 800-63B restricts the channel it used (SMS, PSTN). */
  readonly restricted: boolean
  /** The WebAuthn user-verification bit, where the ceremony reports one. */
  readonly userVerified?: boolean
  /** When it completed. Absent means "just now". */
  readonly completedAt?: DateTime.Utc
}

/**
 * {@link Evidence} with the moment it completed filled in.
 *
 * @category combinators
 * @since 0.2.0
 */
export const stampEvidence = (evidence: Evidence, now: DateTime.Utc): AuthenticationMethod => ({
  ...evidence,
  completedAt: evidence.completedAt ?? now
})

/**
 * A newly minted session and its raw token.
 *
 * **Gotchas**
 *
 * `token` is the only copy that will ever exist — the database holds its
 * digest. Put it in a `Set-Cookie` or a response body and drop it; there is no
 * way to recover it afterwards.
 *
 * @category models
 * @since 0.1.0
 */
export interface CreatedSession {
  readonly session: Session
  readonly token: Redacted.Redacted
}

/**
 * A session that was raised to a higher assurance, and the token that now
 * addresses it.
 *
 * **Gotchas**
 *
 * `session.id` is the one it always had, so the device list and every open tab
 * still name the same row — but `token` is a *new* secret and the previous one
 * stops resolving the instant the elevation commits. Whoever holds the old copy
 * has to sign in again, which is the point: a token captured at `aal1` must not
 * become an `aal2` credential.
 *
 * @category models
 * @since 0.2.0
 */
export interface ElevatedSession {
  readonly session: Session
  readonly token: Redacted.Redacted
}

/**
 * A resolved session.
 *
 * @category models
 * @since 0.1.0
 */
export interface VerifiedSession<F extends UserFields = {}> {
  readonly session: Session
  readonly user: UserOf<F>
  /**
   * `true` when this verification rolled the expiry forward, which is the HTTP
   * layer's signal to re-send the session cookie with a new `Max-Age`.
   */
  readonly refreshed: boolean
}

// -----------------------------------------------------------------------------
// Lifetime arithmetic
// -----------------------------------------------------------------------------

/**
 * The lifetime a session was last granted: the distance between the expiry it
 * currently carries and the moment that expiry was written.
 *
 * **Details**
 *
 * `updatedAt` is set both by the insert and by every `SessionStore.touch`, so
 * `expiresAt - updatedAt` recovers the TTL the session was created or last
 * refreshed with. For an ordinary session that is exactly
 * `session.expiresIn`, which makes {@link refreshDueAt} identical to the
 * specified `expiresAt - expiresIn + updateAge`.
 *
 * **Gotchas**
 *
 * Deriving the lifetime rather than assuming `expiresIn` is what keeps a
 * `rememberMe: false` session short. Assuming the configured value would make
 * the refresh test true the instant a one-day session was created, and every
 * such session would be silently promoted to a seven-day one on its first
 * authenticated request.
 *
 * @category combinators
 * @since 0.1.0
 */
export const grantedLifetime = (session: Session, config: AuthConfigService): Duration.Duration => {
  const lifetime = DateTime.distance(session.updatedAt, session.expiresAt)
  return Duration.isPositive(lifetime) ? lifetime : config.session.expiresIn
}

/**
 * The instant a session becomes due for a rolling refresh:
 * `expiresAt - lifetime + updateAge`.
 *
 * @category combinators
 * @since 0.1.0
 */
export const refreshDueAt = (session: Session, config: AuthConfigService): DateTime.Utc =>
  DateTime.addDuration(
    DateTime.subtractDuration(session.expiresAt, grantedLifetime(session, config)),
    config.session.updateAge
  )

/**
 * Whether a session's expiry is due to be rolled forward at `now`.
 *
 * @category guards
 * @since 0.1.0
 */
export const isRefreshDue = (session: Session, config: AuthConfigService, now: DateTime.Utc): boolean =>
  DateTime.isLessThanOrEqualTo(refreshDueAt(session, config), now)

/**
 * Whether a session has expired at `now`.
 *
 * @category guards
 * @since 0.1.0
 */
export const isExpired = (session: Session, now: DateTime.Utc): boolean =>
  DateTime.isLessThanOrEqualTo(session.expiresAt, now)

/**
 * Whether a session is fresh enough for a sensitive operation at `now`.
 *
 * **Details**
 *
 * Measured from `authenticatedAt` — the last time somebody actually proved
 * something — and never from `createdAt` or the rolling refresh. This is the
 * one function that answers the question; the HTTP layer reads it rather than
 * repeating the arithmetic.
 *
 * @category guards
 * @since 0.1.0
 */
export const isFreshAt = (session: Session, config: AuthConfigService, now: DateTime.Utc): boolean =>
  DateTime.isGreaterThan(DateTime.addDuration(session.authenticatedAt, config.session.freshAge), now)

// -----------------------------------------------------------------------------
// Assurance
// -----------------------------------------------------------------------------

/**
 * The `method` name a recovery code is recorded under, and the one
 * `AssurancePolicy.allowRecovery: false` strikes from the log before it judges
 * it.
 *
 * @category constructors
 * @since 0.2.0
 */
export const recoveryCodeMethod = "recoveryCode"

/**
 * The frozen ordering `aal0 < aal1 < aal2`, as a rank a comparison can use.
 */
const rankOf: { readonly [Level in Aal]: number } = { aal0: 0, aal1: 1, aal2: 2 }

/**
 * The evidence a policy is willing to look at: everything the session recorded,
 * less the recovery codes when the policy refuses them.
 */
const considered = (
  methods: ReadonlyArray<AuthenticationMethod>,
  policy: AssurancePolicy
): ReadonlyArray<AuthenticationMethod> =>
  policy.allowRecovery === false ? methods.filter((entry) => entry.method !== recoveryCodeMethod) : methods

/**
 * Whether a session satisfies an {@link AssurancePolicy} at `now`.
 *
 * **Details**
 *
 * The members are conjunctive and a policy that states nothing admits every
 * session. `allowRecovery: false` is applied *first*, by striking recovery-code
 * entries out of the log, so a level and a method list are both judged on the
 * evidence that is left rather than each carrying its own exception. `aal` is
 * therefore re-derived through `Assurance.deriveAal` rather than read off the
 * row — the row's own level is what the session has, which is what the refusal
 * reports, and this is what it has *under this policy*.
 *
 * `maxAge` is measured from `authenticatedAt`, and `methods` is satisfied by
 * any one entry that proved something (an entry whose factor is `none` — a
 * trusted-device skip — never satisfies a method requirement).
 *
 * @category guards
 * @since 0.2.0
 */
export const meetsAssurance = (session: Session, policy: AssurancePolicy, now: DateTime.Utc): boolean => {
  const evidence = considered(session.methods, policy)
  if (policy.aal !== undefined && rankOf[deriveAal(evidence)] < rankOf[policy.aal]) return false
  if (policy.maxAge !== undefined) {
    const until = DateTime.addDuration(session.authenticatedAt, policy.maxAge)
    if (!DateTime.isGreaterThan(until, now)) return false
  }
  if (policy.methods !== undefined) {
    const wanted = new Set(policy.methods)
    if (!evidence.some((entry) => entry.factor !== "none" && wanted.has(entry.method))) return false
  }
  return true
}

/**
 * Fails {@link StepUpRequired} unless `session` satisfies `policy`.
 *
 * **Details**
 *
 * `available` is the method names this person could step up with — the answer
 * `Authenticators.list` gives, projected to its `type`s. It carries no
 * identifier and no secret, and it is what lets a client offer the right prompt
 * instead of guessing, or degrade gracefully when the answer is empty.
 *
 * **Gotchas**
 *
 * The refusal deliberately does **not** carry a challenge. Pre-issuing one here
 * would mean that every guarded request a stale session made sent an SMS.
 *
 * @category guards
 * @since 0.2.0
 */
export const requireAssuranceFor = (
  session: Session,
  policy: AssurancePolicy,
  available: ReadonlyArray<string>
): Effect.Effect<void, StepUpRequired> =>
  Effect.flatMap(DateTime.now, (now) =>
    meetsAssurance(session, policy, now)
      ? Effect.void
      : StepUpRequired.make({
          required: policyToJson(policy),
          current: { aal: session.aal, authenticatedAt: session.authenticatedAt, available }
        })
  )

/**
 * The session behind the request being handled.
 *
 * **Details**
 *
 * Declared here rather than in `http/Middleware.ts`, where it used to be, so
 * that `domain` does not name `http` even in a type position. A principal is a
 * domain concept: `requireAssurance` reads it, and so does any handler stricter
 * than its endpoint's annotation. `http/Middleware` re-exports it, which is
 * where a handler still imports it from, and `Authenticated` is still what
 * provides it.
 *
 * **Gotchas**
 *
 * The key string still says `http/Middleware` because the string *is* the
 * identity: two `Context.Service` values agree only if their strings do, so
 * changing it is a runtime change and not a rename. It stays as it is.
 *
 * @category services
 * @since 0.2.0
 */
export class CurrentSession extends Context.Service<CurrentSession, Session>()(
  "effect-auth/http/Middleware/CurrentSession"
) {}

/**
 * {@link requireAssuranceFor} against the session behind the request being
 * handled.
 *
 * **When to use**
 *
 * In a handler — core's or a plugin's — that is stricter than the endpoint's
 * own `RequireAssurance` annotation, or that computes its policy from the
 * request. It replaces the old `requireFresh`, whose behaviour is
 * `requireAssurance({ maxAge: config.session.freshAge }, available)`.
 *
 * **Example**
 *
 * ```ts skip-type-checking
 * import { Effect } from "effect"
 * import { Sessions } from "effect-auth"
 *
 * const handler = Effect.gen(function*() {
 *   yield* Sessions.requireAssurance({ aal: "aal2" }, ["totp"])
 * })
 * ```
 *
 * @category guards
 * @since 0.2.0
 */
export const requireAssurance = (
  policy: AssurancePolicy,
  available: ReadonlyArray<string>
): Effect.Effect<void, StepUpRequired, CurrentSession> =>
  Effect.flatMap(CurrentSession, (session) => requireAssuranceFor(session, policy, available))

// -----------------------------------------------------------------------------
// Service
// -----------------------------------------------------------------------------

/**
 * The {@link Sessions} service definition.
 *
 * @category models
 * @since 0.1.0
 */
export interface SessionsService<F extends UserFields = {}> {
  /**
   * Mints a session for a user and returns it together with its raw token,
   * consulting nothing.
   *
   * **When to use**
   *
   * Almost never. `SignIn.complete` is the choke point every sign-in in this
   * library goes through, and it is the only sanctioned caller of this method:
   * it runs `beforeSessionCreate`, consults the `SignInPipeline` — which is
   * where a second factor interposes — and publishes `SignedIn`. A plugin that
   * mints here instead is a sign-in door with no policy on it, and a person
   * with a second factor enrolled walks straight through it. That is the
   * three-path bypass this wave exists to make unrepresentable, so the name
   * says what it is rather than letting it read like the ordinary way in.
   *
   * A test asserts that `src/` calls it in exactly one place.
   *
   * **Gotchas**
   *
   * No event is published here and no policy is consulted. Evidence the caller
   * does not state is not invented: the session records an empty log and
   * derives `aal0`, which meets no assurance policy that asks for a level.
   */
  readonly createUnchecked: (options: CreateOptions) => Effect.Effect<CreatedSession, PersistenceError>

  /**
   * Records that the person behind a live session proved one more thing, and
   * rotates its token.
   *
   * **Details**
   *
   * Appends `evidence` to the session's log, recomputes `aal` through
   * `Assurance.deriveAal`, re-stamps `authenticatedAt`, and replaces the
   * token — all under a lock on the row, in one transaction with the read that
   * produced the log, so no reader ever sees a level that disagrees with the
   * log it came from. The row keeps its id, so the device list and every open
   * tab survive; the previous token stops resolving, so a copy captured at the
   * lower level does not inherit the higher one. The caller is responsible for
   * writing the new token back to the client.
   *
   * `session` names the row and is *not* the log that is appended to: the
   * stored one is, whatever the caller was holding. A `Session` that came from
   * the cookie-cache snapshot, or one that raced another elevation, would
   * otherwise overwrite the row with a log missing whatever it had learned in
   * between.
   *
   * **Gotchas**
   *
   * A session revoked between the request and this call fails
   * `PersistenceError`, not `NotFound`. The store answers `None` for it — the
   * same shape `touch` uses — and it is folded here deliberately: every caller
   * is a step-up endpoint whose session was resolved microseconds ago, so the
   * only way to see it is a revocation mid-flight, and there is nothing for the
   * caller to do about it that it would not already do for a failed write.
   * Widening four plugins' error channels to say so would buy nothing.
   *
   * Publishes `SessionElevated`.
   */
  readonly elevate: (session: Session, evidence: Evidence) => Effect.Effect<ElevatedSession, PersistenceError>

  /**
   * Resolves a presented token to its session and user, rolling the expiry
   * forward when it is due.
   *
   * **Details**
   *
   * One relational read (`SessionStore.findByTokenHash`) plus, at most once per
   * `updateAge`, one `UPDATE`. An expired row fails `SessionExpired` and is
   * deleted on the way out; an unknown token fails `Unauthorized`. The two stay
   * distinct so a client can tell "sign in again" from "you were never signed
   * in", and neither reveals anything about another account.
   */
  readonly verify: (
    token: Redacted.Redacted
  ) => Effect.Effect<VerifiedSession<F>, Unauthorized | SessionExpired | PersistenceError>

  /**
   * Ends the session the caller presented — the sign-out path.
   *
   * **Details**
   *
   * Emits `SignedOut` rather than `SessionRevoked`: a person closing their own
   * session is a different signal from an administrator or a password reset
   * cutting one off, and a security pipeline wants to tell them apart. It
   * succeeds even when the row has already gone, because signing out twice is
   * not an error the caller can act on.
   */
  readonly signOut: (session: Session) => Effect.Effect<void, PersistenceError>

  /**
   * Revokes one session belonging to `userId`, failing `NotFound` when no such
   * session exists. Ownership is enforced inside the delete statement, so this
   * cannot end somebody else's session.
   */
  readonly revoke: (sessionId: SessionId, userId: UserId) => Effect.Effect<void, NotFound | PersistenceError>

  /**
   * Revokes every session of a user and answers how many were removed. Used by
   * the password reset flow, which must sign every device out.
   */
  readonly revokeAll: (userId: UserId) => Effect.Effect<number, PersistenceError>

  /**
   * Revokes every session of a user except the one given.
   */
  readonly revokeOthers: (userId: UserId, currentSessionId: SessionId) => Effect.Effect<number, PersistenceError>

  /**
   * The user's live sessions, newest first. Expired rows are not listed.
   */
  readonly list: (userId: UserId) => Effect.Effect<ReadonlyArray<Session>, PersistenceError>

  /**
   * Whether the session was interactively authenticated within
   * `session.freshAge`.
   *
   * **Gotchas**
   *
   * The rolling refresh does not restore this. To *fail* on a stale session,
   * use {@link requireAssuranceFor} with `{ maxAge: config.session.freshAge }`,
   * which says the same thing and can also say more.
   */
  readonly isFresh: (session: Session) => Effect.Effect<boolean>
}

/**
 * The session lifecycle service.
 *
 * @category services
 * @since 0.1.0
 */
export class Sessions extends Context.Service<Sessions, SessionsService>()("effect-auth/domain/Sessions") {}

/**
 * {@link Sessions}, seen through a model's custom fields.
 *
 * The same key with a narrower shape: `verify` is the one method whose result
 * carries a user, so it is the one place `F` shows. See `userStoreOf` in
 * `domain/Stores.ts` for what a typed view is and why it is sound.
 *
 * @category services
 * @since 0.1.0
 */
export const sessionsOf = <F extends UserFields>(_model: UserModel<F>): Context.Service<Sessions, SessionsService<F>> =>
  Context.Service<Sessions, SessionsService<F>>("effect-auth/domain/Sessions")

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

/**
 * Builds the {@link Sessions} implementation from the ambient configuration,
 * token service, session store and event hub.
 *
 * @category constructors
 * @since 0.1.0
 */
export const make: <F extends UserFields>(
  model: UserModel<F>
) => Effect.Effect<SessionsService<F>, never, AuthConfig | Token | SessionStore | AuthEvents> = Effect.fnUntraced(
  function* <F extends UserFields>(model: UserModel<F>) {
    const config = yield* AuthConfig
    const tokens = yield* Token
    const store = yield* sessionStoreOf(model)
    const events = yield* AuthEvents

    const create = Effect.fnUntraced(function* (options: CreateOptions) {
      const token = yield* tokens.generateToken
      const tokenHash = yield* tokens.hashToken(token)
      const now = yield* DateTime.now
      // `rememberMe` defaults to `true`: only an explicit `false` shortens the
      // lifetime. The flag is stored as well as consumed here, so the rolling
      // refresh can rebuild the same short TTL and the HTTP layer can re-issue a
      // cookie with the matching `Max-Age`.
      const rememberMe = options.rememberMe !== false
      const ttl = rememberMe ? config.session.expiresIn : config.session.rememberMeDisabledExpiresIn
      // One clock read stamps the log, the interactive-authentication time and
      // the expiry, so the three cannot disagree with each other.
      const methods = (options.methods ?? []).map((evidence) => stampEvidence(evidence, now))
      const row = yield* insertRow(SessionModel.insert, {
        tokenHash,
        userId: options.userId,
        expiresAt: DateTime.addDuration(now, ttl),
        ipAddress: options.ipAddress ?? null,
        userAgent: options.userAgent ?? null,
        rememberMe,
        methods,
        // Not an option a caller may state. `deriveAal` is the only thing in
        // this library that computes a level, and a row whose `aal` disagreed
        // with its own `methods` would be a lie every reader repeats —
        // `GET /auth/session`, the cookie-cache snapshot,
        // `StepUpRequired.current.aal`, a future `acr` claim — while
        // `meetsAssurance` re-derives and quietly disagrees with all of them.
        aal: deriveAal(methods),
        // `Model.Override`, because the field defaults to the insert's own
        // clock and this is the caller stating a different moment — the one the
        // ceremony actually completed at.
        authenticatedAt: Model.Override(options.authenticatedAt ?? now)
      })
      const session = yield* store.create(row)
      return { session, token } satisfies CreatedSession
    })

    const elevate = Effect.fnUntraced(function* (session: Session, evidence: Evidence) {
      const now = yield* DateTime.now
      const stamped = stampEvidence(evidence, now)
      const token = yield* tokens.generateToken
      const tokenHash = yield* tokens.hashToken(token)
      const updated = yield* store.elevate(session.id, {
        // Append-only, onto the log the row actually holds — which is why this
        // is a function and not an array. The level is re-derived from the
        // whole of the result rather than raised by hand, and this is the one
        // place that happens for a step-up.
        append: (stored) => {
          const methods = [...stored, stamped]
          return { methods, aal: deriveAal(methods) }
        },
        authenticatedAt: now,
        tokenHash
      })
      const elevated = yield* Effect.fromOption(updated, () =>
        PersistenceError.make({
          operation: "Sessions.elevate",
          cause: "the session was revoked while it was being elevated"
        })
      )
      yield* publishSafely(events, {
        _tag: "SessionElevated",
        userId: elevated.userId,
        sessionId: elevated.id,
        method: evidence.method
      })
      return { session: elevated, token } satisfies ElevatedSession
    })

    const verify = Effect.fnUntraced(function* (token: Redacted.Redacted) {
      const tokenHash = yield* tokens.hashToken(token)
      const found = yield* store.findByTokenHash(tokenHash)
      const { session, user } = yield* Effect.fromOption(found, () => Unauthorized.make())
      const now = yield* DateTime.now

      if (isExpired(session, now)) {
        // The row is dead weight and the presented token is already useless, so
        // dropping it is safe; a storage failure here must not change the answer.
        yield* Effect.ignore(store.deleteById(session.id, session.userId))
        return yield* SessionExpired.make()
      }

      if (!isRefreshDue(session, config, now)) {
        return { session, user, refreshed: false } satisfies VerifiedSession<F>
      }

      const expiresAt = DateTime.addDuration(now, grantedLifetime(session, config))
      const touched = yield* store.touch(session.id, expiresAt)
      // A `None` means the session was revoked between the read and the update.
      const refreshed = yield* Effect.fromOption(touched, () => Unauthorized.make())
      return { session: refreshed, user, refreshed: true } satisfies VerifiedSession<F>
    })

    const signOut = Effect.fnUntraced(function* (session: Session) {
      const removed = yield* store.deleteById(session.id, session.userId)
      if (!removed) return
      yield* publishSafely(events, { _tag: "SignedOut", userId: session.userId, sessionId: session.id })
    })

    const revoke = Effect.fnUntraced(function* (sessionId: SessionId, userId: UserId) {
      const removed = yield* store.deleteById(sessionId, userId)
      if (!removed) {
        return yield* NotFound.make()
      }
      yield* publishSafely(events, { _tag: "SessionRevoked", userId, sessionId, scope: "single", count: 1 })
    })

    const revokeAll = Effect.fnUntraced(function* (userId: UserId) {
      const count = yield* store.deleteByUserId(userId)
      yield* publishSafely(events, { _tag: "SessionRevoked", userId, sessionId: null, scope: "all", count })
      return count
    })

    const revokeOthers = Effect.fnUntraced(function* (userId: UserId, currentSessionId: SessionId) {
      const count = yield* store.deleteByUserIdExcept(userId, currentSessionId)
      yield* publishSafely(events, { _tag: "SessionRevoked", userId, sessionId: null, scope: "others", count })
      return count
    })

    const isFresh = (session: Session): Effect.Effect<boolean> =>
      Effect.map(DateTime.now, (now) => isFreshAt(session, config, now))

    return sessionsOf(model).of({
      createUnchecked: create,
      elevate,
      verify,
      signOut,
      revoke,
      revokeAll,
      revokeOthers,
      list: (userId) => store.listByUserId(userId),
      isFresh
    })
  }
)

/**
 * Provides {@link Sessions} for the user model given: `verify` answers with that
 * model's user, while the layer's own type stays the base one.
 *
 * @category layers
 * @since 0.1.0
 */
export const layerFor = <F extends UserFields>(
  model: UserModel<F>
): Layer.Layer<Sessions, never, AuthConfig | Token | SessionStore | AuthEvents> =>
  Layer.effect(sessionsOf(model), make(model))

/**
 * {@link layerFor}, for a deployment that added no user fields of its own.
 *
 * @category layers
 * @since 0.1.0
 */
export const layer: Layer.Layer<Sessions, never, AuthConfig | Token | SessionStore | AuthEvents> =
  layerFor(baseUserModel)
