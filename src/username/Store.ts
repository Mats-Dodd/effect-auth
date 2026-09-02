/**
 * Where usernames are stored.
 *
 * A seam of the plugin's own, in the shape of this library's four core stores:
 * an interface, a `Context.Service` key, and one SQL implementation. A
 * deployment that keeps its rows somewhere else replaces {@link layer} and
 * nothing above it changes.
 *
 * **Details**
 *
 * {@link UsernameStoreService.claim} is the interesting one. Choosing a name is
 * two writes — release whatever the caller held, take the new one — and both
 * have to commit together or a failed change costs somebody their name. It is
 * one transaction containing one `DELETE` and one conditional upsert
 * (`Mutations.upsertAndRead`), so the "somebody else already holds it" case is
 * the conditional update matching nothing rather than a read taken beforehand,
 * which two callers racing for one name could both have passed.
 *
 * The release runs first, and on MySQL that ordering is what makes the upsert
 * safe: `ON DUPLICATE KEY UPDATE` fires on any unique key the insert collides
 * with, and this table is unique on the holder as well as on the name.
 *
 * @since 0.2.0
 */
import type { Option } from "effect"
import { Context, DateTime, Effect, Layer, Predicate, Schema } from "effect"
import { SqlClient, SqlError, SqlSchema } from "effect/unstable/sql"
import { UserId } from "../domain/Schema.js"
import type { PersistenceError as PersistenceErrorType } from "../domain/Stores.js"
import { PersistenceError, persistenceFailureKind } from "../domain/Stores.js"
import { dialectOf, identifier } from "../sql/Dialect.js"
import * as Mutations from "../sql/Mutations.js"
import { UsernameTaken } from "./Api.js"

// -----------------------------------------------------------------------------
// Model
// -----------------------------------------------------------------------------

/**
 * One row of `effect_auth_usernames`.
 *
 * @category models
 * @since 0.2.0
 */
export const UsernameRecord = Schema.Struct({
  /** The `UsernameCaseMapped` form. The primary key, and the uniqueness rule. */
  usernameKey: Schema.String,
  /** What the person typed, and what a profile shows. */
  username: Schema.String,
  userId: UserId,
  createdAt: Schema.DateTimeUtcFromString
})

/**
 * The type of a {@link UsernameRecord}.
 *
 * @category models
 * @since 0.2.0
 */
export type UsernameRecord = typeof UsernameRecord.Type

// -----------------------------------------------------------------------------
// Service
// -----------------------------------------------------------------------------

/**
 * The {@link UsernameStore} service definition.
 *
 * @category models
 * @since 0.2.0
 */
export interface UsernameStoreService {
  /** Resolves a normalized username to the row that holds it. */
  readonly findByKey: (usernameKey: string) => Effect.Effect<Option.Option<UsernameRecord>, PersistenceErrorType>
  /** The username a person holds, if they hold one. */
  readonly findByUserId: (userId: UserId) => Effect.Effect<Option.Option<UsernameRecord>, PersistenceErrorType>
  /**
   * Gives `userId` this username, releasing whatever it held, in one
   * transaction.
   *
   * Fails {@link UsernameTaken} when the key belongs to somebody else — the
   * conditional update matching nothing, not a read beforehand — and the
   * release is rolled back with it.
   */
  readonly claim: (record: {
    readonly usernameKey: string
    readonly username: string
    readonly userId: UserId
  }) => Effect.Effect<UsernameRecord, UsernameTaken | PersistenceErrorType>
  /** Releases whatever username a person holds. Answers whether one was released. */
  readonly release: (userId: UserId) => Effect.Effect<boolean, PersistenceErrorType>
}

/**
 * Storage for usernames. See {@link UsernameStoreService}.
 *
 * @category services
 * @since 0.2.0
 */
export class UsernameStore extends Context.Service<UsernameStore, UsernameStoreService>()(
  "effect-auth/username/Store/UsernameStore"
) {}

// -----------------------------------------------------------------------------
// SQL implementation
// -----------------------------------------------------------------------------

const columns = `username_key AS "usernameKey", username, user_id AS "userId", created_at AS "createdAt"`

/** The table the rows live in. Its schema is `./Migrations.ts`. */
const usernames = "effect_auth_usernames"

/** The key a claim re-addresses its row by, and what a release counts. */
const key: ReadonlyArray<string> = ["username_key"]

/**
 * Whether the database rolled the transaction back because two of them wanted
 * each other's locks.
 *
 * **Details**
 *
 * MySQL only, and it is this statement pair that provokes it. A claim is a
 * `DELETE` for whatever the caller held followed by an `INSERT`, and under
 * InnoDB's default REPEATABLE READ a `DELETE` whose predicate matches nothing
 * still takes a next-key lock on the gap the row would have been in. This
 * library's ids are time-ordered, so every new holder's gap is the *same* one —
 * the supremum of the holder index — and two first-time claims therefore both
 * hold a gap lock there and then both ask for the insert-intention lock the
 * other's gap lock refuses. InnoDB picks a victim and rolls it back with
 * ER_LOCK_DEADLOCK, whose message is literally "try restarting transaction".
 *
 * So it is restarted — see {@link deadlockRetries}. The rolled-back transaction
 * wrote nothing and the winner has already committed, so a restart is a fresh
 * attempt against a table that has moved on rather than a repeat of the same
 * collision. PostgreSQL and SQLite never match this predicate: neither takes a
 * gap lock, and SQLite serialises writers outright.
 */
const isDeadlock = (error: unknown): error is SqlError.SqlError =>
  SqlError.isSqlError(error) && Predicate.isTagged(error.reason, "DeadlockError")

/**
 * How many restarts a lost lock race is allowed.
 *
 * Immediate, with no back-off: the victim's transaction is already rolled back
 * and the winner has committed, so there is nothing left to wait for — and a
 * `sleep` here would hang under the test clock every `layer()` block installs.
 * Three, rather than one, because contention is between *claimants* and not
 * between two fixed parties: a claim that loses to one neighbour can lose to the
 * next, and a run of three suites against one MySQL server reproduced exactly
 * that. Four attempts is enough for the concurrency a single account's claims
 * can actually reach.
 */
const deadlockRetries = 3

const ClaimRequest = Schema.Struct({
  usernameKey: Schema.String,
  username: Schema.String,
  userId: UserId,
  createdAt: Schema.DateTimeUtcFromString
})

/**
 * Builds the SQL implementation over the ambient `SqlClient`.
 *
 * @category constructors
 * @since 0.2.0
 */
export const makeUsernameStore: Effect.Effect<UsernameStoreService, never, SqlClient.SqlClient> = Effect.gen(
  function* () {
    const sql = yield* SqlClient.SqlClient
    const dialect = yield* dialectOf(sql)
    const cols = sql.literal(columns)
    const table = identifier(sql, usernames)

    const fail = (operation: string) => (cause: unknown) =>
      PersistenceError.make({ operation, kind: persistenceFailureKind(cause), cause })

    const mapErrors =
      (operation: string) =>
      <A, E, R>(effect: Effect.Effect<A, E, R>): Effect.Effect<A, PersistenceErrorType, R> =>
        Effect.mapError(effect, fail(operation))

    const selectByKey = SqlSchema.findOneOption({
      Request: Schema.String,
      Result: UsernameRecord,
      execute: (usernameKey) => sql`SELECT ${cols} FROM ${table} WHERE username_key = ${usernameKey}`
    })

    const selectByUserId = SqlSchema.findOneOption({
      Request: Schema.String,
      Result: UsernameRecord,
      execute: (userId) => sql`SELECT ${cols} FROM ${table} WHERE user_id = ${userId}`
    })

    /**
     * Releases the caller's previous name, when it is not the one being claimed.
     *
     * It runs *before* the claim, inside the same transaction, and that ordering
     * is load-bearing on MySQL: `ON DUPLICATE KEY UPDATE` fires on any unique
     * key the insert collides with, and this table is unique on `user_id` as
     * well as on `username_key`. With the caller's other row already gone the
     * only key left to collide on is the name.
     */
    const releaseOther = (userId: string, usernameKey: string) =>
      Mutations.deleteAndCount({
        sql,
        dialect,
        table: usernames,
        key,
        where: sql`user_id = ${userId} AND username_key <> ${usernameKey}`
      })

    /**
     * Takes the name, or matches nothing.
     *
     * The condition is the whole of the ownership rule: the row is rewritten
     * when the caller already holds this key, and nothing comes back when
     * somebody else does. An unconditional update here would hand one person's
     * name to another. On PostgreSQL and SQLite that is `DO UPDATE … WHERE
     * user_id = excluded.user_id` and an empty `RETURNING`; on MySQL it is the
     * `IF(…)` assignment and a read-back that finds no row the caller owns.
     */
    const takeName = SqlSchema.findAll({
      Request: ClaimRequest,
      Result: UsernameRecord,
      execute: (row) =>
        Mutations.upsertAndRead({
          sql,
          dialect,
          table: usernames,
          record: {
            username_key: row.usernameKey,
            username: row.username,
            user_id: row.userId,
            created_at: row.createdAt
          },
          conflict: key,
          update: ["username"],
          condition: (current, incoming) => sql`${current("user_id")} = ${incoming("user_id")}`,
          columns: cols,
          readBack: sql`username_key = ${row.usernameKey} AND user_id = ${row.userId}`
        })
    })

    const deleteByUserId = (userId: string) =>
      Mutations.deleteAndCount({ sql, dialect, table: usernames, key, where: sql`user_id = ${userId}` })

    const claim = Effect.fnUntraced(function* (record: {
      readonly usernameKey: string
      readonly username: string
      readonly userId: UserId
    }) {
      const createdAt = yield* DateTime.now
      type Attempt = Effect.Effect<UsernameRecord, UsernameTaken | SqlError.SqlError | Schema.SchemaError>

      const attempt: Attempt = sql.withTransaction(
        Effect.gen(function* () {
          yield* releaseOther(record.userId, record.usernameKey)
          const rows = yield* takeName({ ...record, createdAt })
          const row = rows[0]
          // Failing rather than answering `None`: the release above has to be
          // rolled back with it, and only a failure does that.
          if (row === undefined) return yield* UsernameTaken.make()
          return row
        })
      )

      // Annotated because `Effect.catchTag` reads its tags off this channel and
      // `Effect.retry` answers with a conditional type it cannot see into. A
      // refusal is not retried: `UsernameTaken` is an answer, not a lost race.
      const guarded: Attempt = Effect.retry(attempt, { while: isDeadlock, times: deadlockRetries })

      const claimed = yield* Effect.catchTag(
        guarded,
        // The plugin's own refusal is re-failed as itself; everything the
        // driver or the decoder can raise takes the `orElse` branch and becomes
        // the persistence failure every other store reports. Data-first,
        // because the tag list cannot be checked against an error channel the
        // pipe has not produced yet.
        ["UsernameTaken"],
        (taken) => taken,
        (cause) => fail("UsernameStore.claim")(cause)
      )
      return claimed
    })

    return UsernameStore.of({
      findByKey: (usernameKey) => mapErrors("UsernameStore.findByKey")(selectByKey(usernameKey)),
      findByUserId: (userId) => mapErrors("UsernameStore.findByUserId")(selectByUserId(userId)),
      claim,
      release: (userId) => mapErrors("UsernameStore.release")(Effect.map(deleteByUserId(userId), (count) => count > 0))
    })
  }
)

/**
 * Provides {@link UsernameStore} over the ambient `SqlClient`.
 *
 * **Gotchas**
 *
 * Named for the thing it provides rather than `layer`, because a plugin's
 * barrel is flat: `Username.layer` is the plugin's own, and two `layer`s in one
 * namespace is an ambiguity a consumer would have to resolve by importing a
 * file path.
 *
 * @category layers
 * @since 0.2.0
 */
export const layerUsernameStore: Layer.Layer<UsernameStore, never, SqlClient.SqlClient> = Layer.effect(
  UsernameStore,
  makeUsernameStore
)
