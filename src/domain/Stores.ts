/**
 * The persistence seam of `effect-auth`.
 *
 * Four stores plus a transaction runner. Domain logic depends on nothing else
 * for storage: swap `SqlStores.layer` for an in-memory or bespoke
 * implementation and every flow keeps working. Implementations must translate
 * their driver failures into {@link PersistenceError} — an `SqlError` must never
 * reach the domain services or an endpoint's error union.
 *
 * **Details**
 *
 * Conventions across the four services:
 *
 * - a lookup that may find nothing returns `Option`, never `null`
 * - a write that addresses a row by id is also scoped by `userId` where the row
 *   belongs to a user, so ownership is enforced by the statement itself rather
 *   than by a read followed by a write
 * - inserts take the model's `insert` variant, built with
 *   `User.insert.make({ ... })`, which fills in the generated UUIDv7 id and the
 *   `createdAt` / `updatedAt` timestamps from the current clock
 *
 * @since 1.0.0
 */
import type { DateTime, Effect, Option } from "effect"
import { Context, Schema } from "effect"
import type {
  Account,
  AccountId,
  BaseUserPatch,
  Session,
  SessionId,
  UserExtras,
  UserFields,
  UserId,
  UserInsertOf,
  UserModel,
  UserOf,
  Verification
} from "./Schema.js"

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/**
 * How a storage failure is classified, where the implementation can tell.
 *
 * **Details**
 *
 * Only the distinction the domain acts on is modelled: a unique-index
 * rejection, which is what a lost race to create a row looks like. Everything
 * else is `"Unknown"`, and an implementation that classifies nothing simply
 * omits the field. Keeping the classification here rather than in a domain
 * module is what stops `SqlError` leaking upward through the seam.
 *
 * @category models
 * @since 1.0.0
 */
export const PersistenceFailureKind = Schema.Literals(["UniqueViolation", "Unknown"])

/**
 * The type of a {@link PersistenceFailureKind}.
 *
 * @category models
 * @since 1.0.0
 */
export type PersistenceFailureKind = typeof PersistenceFailureKind.Type

/**
 * A storage operation failed.
 *
 * **Details**
 *
 * The tagged wrapper every store implementation reports. `operation` names the
 * store method (`"SessionStore.findByTokenHash"`) and `cause` carries the
 * underlying driver failure as a defect for logging. Neither is part of any
 * endpoint contract: the HTTP layer renders this as an opaque `500`.
 *
 * @category errors
 * @since 1.0.0
 */
export class PersistenceError
  extends Schema.TaggedError<PersistenceError>("effect-auth/PersistenceError")("PersistenceError", {
    operation: Schema.String,
    kind: Schema.optional(PersistenceFailureKind),
    cause: Schema.optional(Schema.Defect())
  }, {
    description: "A storage operation failed",
    httpApiStatus: 500
  })
{}

/**
 * Whether a storage failure was a unique-index rejection.
 *
 * **When to use**
 *
 * Where the losing side of a concurrent write has a graceful answer: a second
 * sign-up for one address is `UserAlreadyExists`, and a second OAuth callback
 * for one new identity is simply a sign-in.
 *
 * **Gotchas**
 *
 * A store implementation that does not classify its failures never matches
 * here, so a caller must keep whatever pre-flight lookup it already had; this
 * only closes the race the lookup cannot.
 *
 * @category guards
 * @since 1.0.0
 */
export const isUniqueViolation = (error: PersistenceError): boolean => error.kind === "UniqueViolation"

// -----------------------------------------------------------------------------
// UserStore
// -----------------------------------------------------------------------------

/**
 * The mutable fields of a user, for a model parameterized by `F`.
 *
 * **Details**
 *
 * Everything the `update` variant carries except the primary key and the
 * timestamp the store maintains itself, each of them optional: an absent key is
 * a column the statement does not touch.
 *
 * **Gotchas**
 *
 * `email` must already be normalized by {@link normalizeEmail} from
 * `domain/Schema.ts`; the store does not normalize on the caller's behalf.
 *
 * @category models
 * @since 1.0.0
 */
export type UserPatch<F extends UserFields = {}> = BaseUserPatch & Partial<UserExtras<F, "update">>

/**
 * The {@link UserStore} service definition, for a model parameterized by `F`.
 *
 * @category models
 * @since 1.0.0
 */
export interface UserStoreService<F extends UserFields = {}> {
  /**
   * Inserts a user and returns the stored row.
   *
   * Fails with {@link PersistenceError} when the unique index on `email`
   * rejects the insert; the sign-up flow translates that into
   * `UserAlreadyExists`.
   *
   * **Gotchas**
   *
   * A caller holding this service through the base-typed {@link UserStore} key
   * hands in a row built from the base fields alone. An implementation must fill
   * the model's custom fields in itself — `UserModel.completeInsert` is what the
   * SQL store uses — which the provisionability rule on `makeUserModel`
   * guarantees is always possible.
   */
  readonly create: (user: UserInsertOf<F>) => Effect.Effect<UserOf<F>, PersistenceError>

  /**
   * Looks a user up by primary key.
   */
  readonly findById: (id: UserId) => Effect.Effect<Option.Option<UserOf<F>>, PersistenceError>

  /**
   * Looks a user up by normalized e-mail address.
   */
  readonly findByEmail: (email: string) => Effect.Effect<Option.Option<UserOf<F>>, PersistenceError>

  /**
   * Applies a partial update and returns the stored row, or `None` when no user
   * has that id.
   */
  readonly update: (id: UserId, patch: UserPatch<F>) => Effect.Effect<Option.Option<UserOf<F>>, PersistenceError>

  /**
   * Deletes a user. Sessions and accounts cascade. Returns whether a row was
   * removed.
   */
  readonly delete: (id: UserId) => Effect.Effect<boolean, PersistenceError>

  /**
   * Takes a row lock on one user, so that a transaction which then reads or
   * reclaims that user's accounts cannot race a concurrent one doing the same.
   *
   * **Details**
   *
   * `SELECT id FROM users WHERE id = <id> FOR UPDATE` on the dialects that have
   * row-level locking; on SQLite, whose writers are already serialized, it is a
   * plain read and the same guarantee. It answers nothing — it is called for the
   * lock, not the row — and must be run inside a {@link WithAuthTransaction} for
   * the lock to be held for any useful span.
   */
  readonly lockUserRow: (id: UserId) => Effect.Effect<void, PersistenceError>
}

/**
 * Storage for user rows.
 *
 * @category services
 * @since 1.0.0
 */
export class UserStore extends Context.Service<UserStore, UserStoreService>()("effect-auth/UserStore") {}

/**
 * {@link UserStore}, seen through a model's custom fields.
 *
 * **Details**
 *
 * The same key — same string, same `Identifier`, same slot in the context — with
 * a narrower `Shape`. Yielding this gives a `UserStoreService<F>` whose reads
 * carry the deployment's own columns, while every layer that *provides* the
 * store still publishes it under the plain `UserStore` key, so no signature in
 * the library becomes generic.
 *
 * **Gotchas**
 *
 * Reading through the base key stays sound: `UserOf<{}>` is what every user has
 * in common, and a row with more columns than that is still one of them. Writing
 * is the direction that needs care, and only this library's own layers write —
 * see {@link UserStoreService.create}.
 *
 * @category services
 * @since 1.0.0
 */
export const userStoreOf = <F extends UserFields>(
  _model: UserModel<F>
): Context.Service<UserStore, UserStoreService<F>> =>
  Context.Service<UserStore, UserStoreService<F>>("effect-auth/UserStore")

// -----------------------------------------------------------------------------
// SessionStore
// -----------------------------------------------------------------------------

/**
 * A session together with the user it belongs to.
 *
 * @category models
 * @since 1.0.0
 */
export interface SessionWithUser<F extends UserFields = {}> {
  readonly session: Session
  readonly user: UserOf<F>
}

/**
 * The {@link SessionStore} service definition, for a model parameterized by `F`.
 *
 * **Details**
 *
 * `F` reaches exactly one method: the joined read is the only place a session
 * store hands a user back.
 *
 * @category models
 * @since 1.0.0
 */
export interface SessionStoreService<F extends UserFields = {}> {
  /**
   * Inserts a session and returns the stored row.
   */
  readonly create: (session: typeof Session.insert.Type) => Effect.Effect<Session, PersistenceError>

  /**
   * Resolves a presented session token, hashed by the caller, to its session
   * and its user in a single relational read.
   *
   * **Details**
   *
   * Returns rows regardless of expiry: `Sessions.verify` decides what an
   * expired row means, so that an expired session can be distinguished from an
   * unknown one and cleaned up.
   */
  readonly findByTokenHash: (
    tokenHash: string
  ) => Effect.Effect<Option.Option<SessionWithUser<F>>, PersistenceError>

  /**
   * Extends a session's expiry (the rolling refresh) and returns the updated
   * row, or `None` when the session was concurrently revoked.
   */
  readonly touch: (
    id: SessionId,
    expiresAt: DateTime.Utc
  ) => Effect.Effect<Option.Option<Session>, PersistenceError>

  /**
   * Deletes one session belonging to `userId`. Returns whether a row was
   * removed.
   *
   * **Gotchas**
   *
   * The `userId` is part of the statement rather than checked beforehand, so a
   * caller cannot revoke a session that is not theirs and there is no
   * check-then-act race.
   */
  readonly deleteById: (id: SessionId, userId: UserId) => Effect.Effect<boolean, PersistenceError>

  /**
   * Deletes every session of a user. Returns the number of rows removed.
   */
  readonly deleteByUserId: (userId: UserId) => Effect.Effect<number, PersistenceError>

  /**
   * Deletes every session of a user except the one given. Returns the number of
   * rows removed.
   */
  readonly deleteByUserIdExcept: (userId: UserId, sessionId: SessionId) => Effect.Effect<number, PersistenceError>

  /**
   * Lists the user's sessions that have not expired, newest first.
   */
  readonly listByUserId: (userId: UserId) => Effect.Effect<ReadonlyArray<Session>, PersistenceError>

  /**
   * Deletes every session whose expiry has passed. Returns the number of rows
   * removed.
   */
  readonly deleteExpired: Effect.Effect<number, PersistenceError>
}

/**
 * Storage for {@link Session} rows.
 *
 * @category services
 * @since 1.0.0
 */
export class SessionStore extends Context.Service<SessionStore, SessionStoreService>()("effect-auth/SessionStore") {}

/**
 * {@link SessionStore}, seen through a model's custom fields.
 *
 * The same key with a narrower shape — see {@link userStoreOf} for what that
 * means and why it is sound.
 *
 * @category services
 * @since 1.0.0
 */
export const sessionStoreOf = <F extends UserFields>(
  _model: UserModel<F>
): Context.Service<SessionStore, SessionStoreService<F>> =>
  Context.Service<SessionStore, SessionStoreService<F>>("effect-auth/SessionStore")

// -----------------------------------------------------------------------------
// AccountStore
// -----------------------------------------------------------------------------

/**
 * The provider credentials of an {@link Account} that are refreshed on every
 * sign-in.
 *
 * @category models
 * @since 1.0.0
 */
export interface AccountTokens {
  readonly accessToken?: string | null
  readonly refreshToken?: string | null
  readonly idToken?: string | null
  readonly accessTokenExpiresAt?: DateTime.Utc | null
  readonly refreshTokenExpiresAt?: DateTime.Utc | null
  readonly scope?: string | null
}

/**
 * The {@link AccountStore} service definition.
 *
 * @category models
 * @since 1.0.0
 */
export interface AccountStoreService {
  /**
   * Inserts an account and returns the stored row.
   *
   * Fails with {@link PersistenceError} when the unique index on
   * `(issuer, account_id)` rejects the insert.
   */
  readonly create: (account: typeof Account.insert.Type) => Effect.Effect<Account, PersistenceError>

  /**
   * Looks an account up by its provider identity — the compound unique key, and
   * the only identity an OAuth sign-in is matched on.
   */
  readonly findByIssuerAccountId: (
    issuer: string,
    accountId: string
  ) => Effect.Effect<Option.Option<Account>, PersistenceError>

  /**
   * Looks an account up by its primary key, scoped to the user it must belong
   * to.
   *
   * **When to use**
   *
   * Wherever a caller names one of *their own* accounts — asking for its access
   * token, refreshing it. The ownership predicate is part of the statement, so
   * there is no read-then-check window and no branch that could be skipped.
   *
   * **Gotchas**
   *
   * `None` covers "no such account" and "not yours" alike, and deliberately so:
   * telling them apart would let a signed-in caller probe which account ids
   * exist.
   */
  readonly findByIdAndUserId: (
    id: AccountId,
    userId: UserId
  ) => Effect.Effect<Option.Option<Account>, PersistenceError>

  /**
   * Looks up a user's account for one provider — including the synthetic
   * `local:credential` provider that holds the password hash.
   */
  readonly findByUserIdAndProviderId: (
    userId: UserId,
    providerId: string
  ) => Effect.Effect<Option.Option<Account>, PersistenceError>

  /**
   * Lists every sign-in method of a user.
   */
  readonly listByUserId: (userId: UserId) => Effect.Effect<ReadonlyArray<Account>, PersistenceError>

  /**
   * Lists every sign-in method of a user, holding a write lock on the rows
   * until the surrounding transaction ends.
   *
   * **When to use**
   *
   * Before a check-then-act on the *set* of a user's sign-in methods — which in
   * practice means `Accounts.unlink`, whose `CannotUnlinkLastAccount` guard is
   * only as good as the isolation it counts under.
   *
   * **Gotchas**
   *
   * `sql.withTransaction` issues a plain `BEGIN`, which on PostgreSQL is READ
   * COMMITTED: two concurrent unlinks would otherwise each see two methods,
   * each delete a different one, and both commit, leaving a user who cannot
   * sign in. On PostgreSQL this is `SELECT ... FOR UPDATE`; a store whose
   * writes are already serialized (SQLite) may implement it as an ordinary
   * read.
   */
  readonly listByUserIdForUpdate: (userId: UserId) => Effect.Effect<ReadonlyArray<Account>, PersistenceError>

  /**
   * Replaces the provider tokens of an account. Absent keys are left unchanged.
   * Returns `None` when no account has that id.
   */
  readonly updateTokens: (
    id: AccountId,
    tokens: AccountTokens
  ) => Effect.Effect<Option.Option<Account>, PersistenceError>

  /**
   * Sets the password hash of a user's `local:credential` account, returning
   * `None` when the user has no credential account yet — an OAuth-only user
   * resetting a password, for instance, which the domain answers by creating
   * one.
   */
  readonly updatePasswordHash: (
    userId: UserId,
    passwordHash: string
  ) => Effect.Effect<Option.Option<Account>, PersistenceError>

  /**
   * Deletes one account belonging to `userId`. Returns whether a row was
   * removed. Ownership is enforced by the statement.
   */
  readonly deleteById: (id: AccountId, userId: UserId) => Effect.Effect<boolean, PersistenceError>

  /**
   * Deletes every sign-in method of a user. Returns the number of rows removed.
   *
   * **When to use**
   *
   * Where the *set* of credentials has to go without the user going with it —
   * proving ownership of an address that somebody else had registered against
   * it, for instance, which revokes whatever they had linked. Deleting the user
   * cascades instead, and needs none of this.
   *
   * **Gotchas**
   *
   * This bypasses the "never unlink the last method" guard by design: it is the
   * whole set, and the caller is expected to be establishing a new one in the
   * same transaction.
   */
  readonly deleteByUserId: (userId: UserId) => Effect.Effect<number, PersistenceError>

  /**
   * Counts a user's sign-in methods. Used to refuse unlinking the last one.
   */
  readonly countByUserId: (userId: UserId) => Effect.Effect<number, PersistenceError>
}

/**
 * Storage for {@link Account} rows — the sign-in methods of a user.
 *
 * @category services
 * @since 1.0.0
 */
export class AccountStore extends Context.Service<AccountStore, AccountStoreService>()("effect-auth/AccountStore") {}

// -----------------------------------------------------------------------------
// VerificationStore
// -----------------------------------------------------------------------------

/**
 * The {@link VerificationStore} service definition.
 *
 * @category models
 * @since 1.0.0
 */
export interface VerificationStoreService {
  /**
   * Inserts a verification row and returns it.
   */
  readonly create: (verification: typeof Verification.insert.Type) => Effect.Effect<Verification, PersistenceError>

  /**
   * Atomically claims a verification value: the row is deleted and returned in
   * one statement, and only when it has not expired.
   *
   * **Details**
   *
   * `DELETE FROM verifications WHERE identifier = ? AND value_hash = ? AND
   * expires_at > ? RETURNING *`. This single statement is the entire
   * race-safety story for password reset tokens, e-mail verification links and
   * OAuth state: two concurrent callers cannot both receive the row.
   *
   * **Gotchas**
   *
   * `None` covers unknown, already-consumed, and expired alike. Distinguishing
   * "expired" from "never existed" would require a second read and would leak
   * whether a token was ever issued, so callers report `InvalidToken` and only
   * use `TokenExpired` where they hold the row already.
   */
  readonly consume: (
    identifier: string,
    valueHash: string
  ) => Effect.Effect<Option.Option<Verification>, PersistenceError>

  /**
   * Deletes every row under one identifier, whether expired or not. Returns the
   * number of rows removed.
   *
   * **When to use**
   *
   * To retire the *siblings* of a value that was just claimed. Asking for a
   * password reset twice mints two independent tokens; once one of them has
   * reset the password, the other must not still work — somebody with transient
   * mailbox access would otherwise hold a key to an account its owner believes
   * they have just re-secured.
   */
  readonly deleteByIdentifier: (identifier: string) => Effect.Effect<number, PersistenceError>

  /**
   * Deletes every row whose expiry has passed. Returns the number of rows
   * removed.
   */
  readonly deleteExpired: Effect.Effect<number, PersistenceError>
}

/**
 * Storage for {@link Verification} rows — e-mail verification tokens, password
 * reset tokens, and pending OAuth state.
 *
 * @category services
 * @since 1.0.0
 */
export class VerificationStore
  extends Context.Service<VerificationStore, VerificationStoreService>()("effect-auth/VerificationStore")
{}

// -----------------------------------------------------------------------------
// Transactions
// -----------------------------------------------------------------------------

/**
 * The {@link WithAuthTransaction} service definition.
 *
 * @category models
 * @since 1.0.0
 */
export interface WithAuthTransactionService {
  /**
   * Runs `effect` in a transaction, rolling back on failure or interruption.
   */
  readonly run: <A, E, R>(effect: Effect.Effect<A, E, R>) => Effect.Effect<A, E | PersistenceError, R>
}

/**
 * Runs a domain effect inside one storage transaction.
 *
 * **When to use**
 *
 * Wrap multi-store writes that must not be observable half-applied: OAuth
 * sign-up creates a user, an account and a session; password reset updates a
 * hash and revokes every session.
 *
 * **Details**
 *
 * The SQL layer implements this with `sql.withTransaction`. An in-memory or
 * test implementation may be the identity function. Events are published after
 * the transaction has committed, never inside it.
 *
 * @category services
 * @since 1.0.0
 */
export class WithAuthTransaction
  extends Context.Service<WithAuthTransaction, WithAuthTransactionService>()("effect-auth/WithAuthTransaction")
{}

/**
 * Every service the storage seam is made of. `SqlStores.layer` provides exactly
 * this set.
 *
 * @category services
 * @since 1.0.0
 */
export type AuthStores =
  | UserStore
  | SessionStore
  | AccountStore
  | VerificationStore
  | WithAuthTransaction
