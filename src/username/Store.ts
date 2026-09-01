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
 * one transaction containing one `DELETE` and one `INSERT … ON CONFLICT … DO
 * UPDATE … WHERE`, so the "somebody else already holds it" case is the
 * conditional update matching nothing rather than a read taken beforehand,
 * which two callers racing for one name could both have passed.
 *
 * @since 0.2.0
 */
import type { Option } from "effect"
import { Context, DateTime, Effect, Layer, Schema } from "effect"
import { SqlClient, SqlError, SqlSchema } from "effect/unstable/sql"
import { UserId } from "../domain/Schema.js"
import type { PersistenceError as PersistenceErrorType } from "../domain/Stores.js"
import { PersistenceError } from "../domain/Stores.js"
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

const kindOf = (cause: unknown) =>
  SqlError.isSqlError(cause) && cause.reason._tag === "UniqueViolation" ? "UniqueViolation" : "Unknown"

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
    const cols = sql.literal(columns)

    const fail = (operation: string) => (cause: unknown) =>
      PersistenceError.make({ operation, kind: kindOf(cause), cause })

    const mapErrors =
      (operation: string) =>
      <A, E, R>(effect: Effect.Effect<A, E, R>): Effect.Effect<A, PersistenceErrorType, R> =>
        Effect.mapError(effect, fail(operation))

    const selectByKey = SqlSchema.findOneOption({
      Request: Schema.String,
      Result: UsernameRecord,
      execute: (usernameKey) => sql`SELECT ${cols} FROM effect_auth_usernames WHERE username_key = ${usernameKey}`
    })

    const selectByUserId = SqlSchema.findOneOption({
      Request: Schema.String,
      Result: UsernameRecord,
      execute: (userId) => sql`SELECT ${cols} FROM effect_auth_usernames WHERE user_id = ${userId}`
    })

    /** Releases the caller's previous name, when it is not the one being claimed. */
    const releaseOther = SqlSchema.findAll({
      Request: Schema.Struct({ userId: Schema.String, usernameKey: Schema.String }),
      Result: Schema.Struct({ username_key: Schema.String }),
      execute: (row) =>
        sql`DELETE FROM effect_auth_usernames
        WHERE user_id = ${row.userId} AND username_key <> ${row.usernameKey}
        RETURNING username_key`
    })

    /**
     * Takes the name, or matches nothing.
     *
     * `DO UPDATE … WHERE user_id = excluded.user_id` is the whole of the
     * ownership rule: the row is rewritten when the caller already holds this
     * key, and the statement returns no row when somebody else does. An
     * unconditional `DO UPDATE` here would hand one person's name to another.
     */
    const takeName = SqlSchema.findAll({
      Request: ClaimRequest,
      Result: UsernameRecord,
      execute: (row) =>
        sql`INSERT INTO effect_auth_usernames (username_key, username, user_id, created_at)
        VALUES (${row.usernameKey}, ${row.username}, ${row.userId}, ${row.createdAt})
        ON CONFLICT (username_key) DO UPDATE SET username = excluded.username
        WHERE effect_auth_usernames.user_id = excluded.user_id
        RETURNING ${cols}`
    })

    const deleteByUserId = SqlSchema.findAll({
      Request: Schema.String,
      Result: Schema.Struct({ username_key: Schema.String }),
      execute: (userId) => sql`DELETE FROM effect_auth_usernames WHERE user_id = ${userId} RETURNING username_key`
    })

    const claim = Effect.fnUntraced(function* (record: {
      readonly usernameKey: string
      readonly username: string
      readonly userId: UserId
    }) {
      const createdAt = yield* DateTime.now
      const claimed = yield* sql
        .withTransaction(
          Effect.gen(function* () {
            yield* releaseOther({ userId: record.userId, usernameKey: record.usernameKey })
            const rows = yield* takeName({ ...record, createdAt })
            const row = rows[0]
            // Failing rather than answering `None`: the release above has to be
            // rolled back with it, and only a failure does that.
            if (row === undefined) return yield* UsernameTaken.make()
            return row
          })
        )
        .pipe(
          // The plugin's own refusal passes through; everything the driver or the
          // decoder can raise becomes the persistence failure every other store
          // reports.
          Effect.mapError((error) => (error._tag === "UsernameTaken" ? error : fail("UsernameStore.claim")(error)))
        )
      return claimed
    })

    return UsernameStore.of({
      findByKey: (usernameKey) => mapErrors("UsernameStore.findByKey")(selectByKey(usernameKey)),
      findByUserId: (userId) => mapErrors("UsernameStore.findByUserId")(selectByUserId(userId)),
      claim,
      release: (userId) =>
        mapErrors("UsernameStore.release")(Effect.map(deleteByUserId(userId), (rows) => rows.length > 0))
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
