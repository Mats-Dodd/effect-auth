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
 *   *created* to authorize a sensitive operation such as changing a password.
 *   Freshness deliberately tracks `createdAt`, not the rolling refresh: a
 *   session kept alive for a month by ordinary browsing is no evidence that the
 *   person at the keyboard is still the account's owner.
 *
 * @since 1.0.0
 */
import { Context, DateTime, Duration, Effect, Layer, Option, Redacted } from "effect"
import type { AuthConfigService } from "../config/AuthConfig.js"
import { AuthConfig } from "../config/AuthConfig.js"
import { Token } from "../crypto/Token.js"
import { NotFound, SessionExpired, SessionNotFresh, Unauthorized } from "./Errors.js"
import { AuthEvents, publishSafely } from "./Events.js"
import type { Session, SessionId, User, UserId } from "./Schema.js"
import { Session as SessionModel } from "./Schema.js"
import type { PersistenceError } from "./Stores.js"
import { SessionStore } from "./Stores.js"

// -----------------------------------------------------------------------------
// Models
// -----------------------------------------------------------------------------

/**
 * What {@link Sessions.create} needs to know.
 *
 * @category models
 * @since 1.0.0
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
}

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
 * @since 1.0.0
 */
export interface CreatedSession {
  readonly session: Session
  readonly token: Redacted.Redacted<string>
}

/**
 * A resolved session.
 *
 * @category models
 * @since 1.0.0
 */
export interface VerifiedSession {
  readonly session: Session
  readonly user: User
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
 * @since 1.0.0
 */
export const grantedLifetime = (session: Session, config: AuthConfigService): Duration.Duration => {
  const millis = DateTime.toEpochMillis(session.expiresAt) - DateTime.toEpochMillis(session.updatedAt)
  return millis > 0 ? Duration.millis(millis) : config.session.expiresIn
}

/**
 * The instant a session becomes due for a rolling refresh:
 * `expiresAt - lifetime + updateAge`.
 *
 * @category combinators
 * @since 1.0.0
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
 * @since 1.0.0
 */
export const isRefreshDue = (session: Session, config: AuthConfigService, now: DateTime.Utc): boolean =>
  DateTime.isLessThanOrEqualTo(refreshDueAt(session, config), now)

/**
 * Whether a session has expired at `now`.
 *
 * @category guards
 * @since 1.0.0
 */
export const isExpired = (session: Session, now: DateTime.Utc): boolean =>
  DateTime.isLessThanOrEqualTo(session.expiresAt, now)

/**
 * Whether a session is fresh enough for a sensitive operation at `now`.
 *
 * @category guards
 * @since 1.0.0
 */
export const isFreshAt = (session: Session, config: AuthConfigService, now: DateTime.Utc): boolean =>
  DateTime.isGreaterThan(DateTime.addDuration(session.createdAt, config.session.freshAge), now)

// -----------------------------------------------------------------------------
// Service
// -----------------------------------------------------------------------------

/**
 * The {@link Sessions} service definition.
 *
 * @category models
 * @since 1.0.0
 */
export interface SessionsService {
  /**
   * Mints a session for a user and returns it together with its raw token.
   *
   * **Gotchas**
   *
   * No event is published here. Only the caller knows *how* the user
   * authenticated, so `SignedIn` is emitted by `Passwords` or by the OAuth
   * flow, which pass the method along.
   */
  readonly create: (options: CreateOptions) => Effect.Effect<CreatedSession, PersistenceError>

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
    token: Redacted.Redacted<string>
  ) => Effect.Effect<VerifiedSession, Unauthorized | SessionExpired | PersistenceError>

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
  readonly revoke: (
    sessionId: SessionId,
    userId: UserId
  ) => Effect.Effect<void, NotFound | PersistenceError>

  /**
   * Revokes every session of a user and answers how many were removed. Used by
   * the password reset flow, which must sign every device out.
   */
  readonly revokeAll: (userId: UserId) => Effect.Effect<number, PersistenceError>

  /**
   * Revokes every session of a user except the one given.
   */
  readonly revokeOthers: (
    userId: UserId,
    currentSessionId: SessionId
  ) => Effect.Effect<number, PersistenceError>

  /**
   * The user's live sessions, newest first. Expired rows are not listed.
   */
  readonly list: (userId: UserId) => Effect.Effect<ReadonlyArray<Session>, PersistenceError>

  /**
   * Whether the session was created within `session.freshAge`.
   */
  readonly isFresh: (session: Session) => Effect.Effect<boolean>

  /**
   * Fails with `SessionNotFresh` unless `isFresh` holds. This is
   * the guard behind change-password and account unlinking.
   */
  readonly requireFresh: (session: Session) => Effect.Effect<void, SessionNotFresh>
}

/**
 * The session lifecycle service.
 *
 * @category services
 * @since 1.0.0
 */
export class Sessions extends Context.Service<Sessions, SessionsService>()("effect-auth/Sessions") {}

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

/**
 * Builds the {@link Sessions} implementation from the ambient configuration,
 * token service, session store and event hub.
 *
 * @category constructors
 * @since 1.0.0
 */
export const make: () => Effect.Effect<
  SessionsService,
  never,
  AuthConfig | Token | SessionStore | AuthEvents
> = Effect.fnUntraced(function*() {
  const config = yield* AuthConfig
  const tokens = yield* Token
  const store = yield* SessionStore
  const events = yield* AuthEvents

  const create = Effect.fnUntraced(function*(options: CreateOptions) {
    const token = yield* tokens.generateToken
    const tokenHash = yield* tokens.hashToken(token)
    const now = yield* DateTime.now
    const ttl = options.rememberMe === false
      ? config.session.rememberMeDisabledExpiresIn
      : config.session.expiresIn
    const row = yield* Effect.orDie(SessionModel.insert.makeEffect({
      tokenHash,
      userId: options.userId,
      expiresAt: DateTime.addDuration(now, ttl),
      ipAddress: options.ipAddress ?? null,
      userAgent: options.userAgent ?? null
    }))
    const session = yield* store.create(row)
    return { session, token } satisfies CreatedSession
  })

  const verify = Effect.fnUntraced(function*(token: Redacted.Redacted<string>) {
    const tokenHash = yield* tokens.hashToken(token)
    const found = yield* store.findByTokenHash(tokenHash)
    if (Option.isNone(found)) {
      return yield* Effect.fail(new Unauthorized())
    }
    const { session, user } = found.value
    const now = yield* DateTime.now

    if (isExpired(session, now)) {
      // The row is dead weight and the presented token is already useless, so
      // dropping it is safe; a storage failure here must not change the answer.
      yield* Effect.ignore(store.deleteById(session.id, session.userId))
      return yield* Effect.fail(new SessionExpired())
    }

    if (!isRefreshDue(session, config, now)) {
      return { session, user, refreshed: false } satisfies VerifiedSession
    }

    const expiresAt = DateTime.addDuration(now, grantedLifetime(session, config))
    const touched = yield* store.touch(session.id, expiresAt)
    if (Option.isNone(touched)) {
      // Revoked between the read and the update.
      return yield* Effect.fail(new Unauthorized())
    }
    return { session: touched.value, user, refreshed: true } satisfies VerifiedSession
  })

  const signOut = Effect.fnUntraced(function*(session: Session) {
    const removed = yield* store.deleteById(session.id, session.userId)
    if (!removed) return
    yield* publishSafely(events, { _tag: "SignedOut", userId: session.userId, sessionId: session.id })
  })

  const revoke = Effect.fnUntraced(function*(sessionId: SessionId, userId: UserId) {
    const removed = yield* store.deleteById(sessionId, userId)
    if (!removed) {
      return yield* Effect.fail(new NotFound())
    }
    yield* publishSafely(events, { _tag: "SessionRevoked", userId, sessionId, scope: "single", count: 1 })
  })

  const revokeAll = Effect.fnUntraced(function*(userId: UserId) {
    const count = yield* store.deleteByUserId(userId)
    yield* publishSafely(events, { _tag: "SessionRevoked", userId, sessionId: null, scope: "all", count })
    return count
  })

  const revokeOthers = Effect.fnUntraced(function*(userId: UserId, currentSessionId: SessionId) {
    const count = yield* store.deleteByUserIdExcept(userId, currentSessionId)
    yield* publishSafely(events, { _tag: "SessionRevoked", userId, sessionId: null, scope: "others", count })
    return count
  })

  const isFresh = (session: Session): Effect.Effect<boolean> =>
    Effect.map(DateTime.now, (now) => isFreshAt(session, config, now))

  const requireFresh = Effect.fnUntraced(function*(session: Session) {
    const fresh = yield* isFresh(session)
    if (!fresh) {
      return yield* Effect.fail(
        new SessionNotFresh({ freshAgeSeconds: Duration.toSeconds(config.session.freshAge) })
      )
    }
  })

  return Sessions.of({
    create,
    verify,
    signOut,
    revoke,
    revokeAll,
    revokeOthers,
    list: (userId) => store.listByUserId(userId),
    isFresh,
    requireFresh
  })
})

/**
 * Provides {@link Sessions}.
 *
 * @category layers
 * @since 1.0.0
 */
export const layer: Layer.Layer<Sessions, never, AuthConfig | Token | SessionStore | AuthEvents> = Layer.effect(
  Sessions,
  make()
)
