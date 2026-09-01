/**
 * Where the anonymous marker rows live.
 *
 * A seam of the plugin's own, in the shape of this library's four core stores.
 * It requires nothing but a `SqlClient`, which is deliberate: the merge hook
 * ({@link Anonymous.layerHooks}) has to be provided *underneath* `Auth.layer`,
 * where the core stores do not exist yet, and it reads this one.
 *
 * @since 0.2.0
 */
import type { Option } from "effect"
import { Context, DateTime, Effect, Layer, Schema } from "effect"
import { SqlClient, SqlError, SqlSchema } from "effect/unstable/sql"
import { UserId } from "../domain/Schema.js"
import type { PersistenceError as PersistenceErrorType } from "../domain/Stores.js"
import { PersistenceError } from "../domain/Stores.js"

// -----------------------------------------------------------------------------
// Model
// -----------------------------------------------------------------------------

/**
 * One row of `effect_auth_anonymous`.
 *
 * @category models
 * @since 0.2.0
 */
export const AnonymousRecord = Schema.Struct({
  userId: UserId,
  createdAt: Schema.DateTimeUtcFromString,
  /** What the sweep measures idleness by. Starts equal to `createdAt`. */
  lastSeenAt: Schema.DateTimeUtcFromString
})

/**
 * The type of an {@link AnonymousRecord}.
 *
 * @category models
 * @since 0.2.0
 */
export type AnonymousRecord = typeof AnonymousRecord.Type

// -----------------------------------------------------------------------------
// Service
// -----------------------------------------------------------------------------

/**
 * The {@link AnonymousStore} service definition.
 *
 * @category models
 * @since 0.2.0
 */
export interface AnonymousStoreService {
  /** The marker for a user, if they have one. Its presence is what "anonymous" means. */
  readonly find: (userId: UserId) => Effect.Effect<Option.Option<AnonymousRecord>, PersistenceErrorType>
  /** Marks a user anonymous. Called inside the transaction that created them. */
  readonly create: (userId: UserId) => Effect.Effect<AnonymousRecord, PersistenceErrorType>
  /** Moves `last_seen_at` to now. Answers whether a marker was there to move. */
  readonly touch: (userId: UserId) => Effect.Effect<boolean, PersistenceErrorType>
  /** Removes the marker — what adoption is. Answers whether one was there. */
  readonly clear: (userId: UserId) => Effect.Effect<boolean, PersistenceErrorType>
  /**
   * The anonymous users idle since `before` that hold no live session.
   *
   * **Gotchas**
   *
   * The live-session clause is what keeps a visitor who is still using the site
   * out of the sweep whatever `last_seen_at` says: a session's rolling refresh
   * moves its expiry, and a person with one has not gone away.
   */
  readonly listIdle: (options: {
    readonly before: DateTime.Utc
    readonly now: DateTime.Utc
    readonly limit: number
  }) => Effect.Effect<ReadonlyArray<UserId>, PersistenceErrorType>
}

/**
 * Storage for the anonymous marker. See {@link AnonymousStoreService}.
 *
 * @category services
 * @since 0.2.0
 */
export class AnonymousStore extends Context.Service<AnonymousStore, AnonymousStoreService>()(
  "effect-auth/anonymous/Store/AnonymousStore"
) {}

// -----------------------------------------------------------------------------
// SQL implementation
// -----------------------------------------------------------------------------

const columns = `user_id AS "userId", created_at AS "createdAt", last_seen_at AS "lastSeenAt"`

const kindOf = (cause: unknown) =>
  SqlError.isSqlError(cause) && cause.reason._tag === "UniqueViolation" ? "UniqueViolation" : "Unknown"

const StampRequest = Schema.Struct({ userId: UserId, now: Schema.DateTimeUtcFromString })

const IdleRequest = Schema.Struct({
  before: Schema.DateTimeUtcFromString,
  now: Schema.DateTimeUtcFromString,
  limit: Schema.Finite
})

/**
 * Builds the SQL implementation over the ambient `SqlClient`.
 *
 * @category constructors
 * @since 0.2.0
 */
export const makeAnonymousStore: Effect.Effect<AnonymousStoreService, never, SqlClient.SqlClient> = Effect.gen(
  function* () {
    const sql = yield* SqlClient.SqlClient
    const cols = sql.literal(columns)

    const mapErrors =
      (operation: string) =>
      <A, E, R>(effect: Effect.Effect<A, E, R>): Effect.Effect<A, PersistenceErrorType, R> =>
        Effect.mapError(effect, (cause) => PersistenceError.make({ operation, kind: kindOf(cause), cause }))

    const selectByUserId = SqlSchema.findOneOption({
      Request: UserId,
      Result: AnonymousRecord,
      execute: (userId) => sql`SELECT ${cols} FROM effect_auth_anonymous WHERE user_id = ${userId}`
    })

    const insertMarker = SqlSchema.findOne({
      Request: StampRequest,
      Result: AnonymousRecord,
      execute: (row) =>
        sql`INSERT INTO effect_auth_anonymous (user_id, created_at, last_seen_at)
        VALUES (${row.userId}, ${row.now}, ${row.now})
        RETURNING ${cols}`
    })

    const stamp = SqlSchema.findAll({
      Request: StampRequest,
      Result: Schema.Struct({ user_id: Schema.String }),
      execute: (row) =>
        sql`UPDATE effect_auth_anonymous SET last_seen_at = ${row.now} WHERE user_id = ${row.userId} RETURNING user_id`
    })

    const deleteMarker = SqlSchema.findAll({
      Request: UserId,
      Result: Schema.Struct({ user_id: Schema.String }),
      execute: (userId) => sql`DELETE FROM effect_auth_anonymous WHERE user_id = ${userId} RETURNING user_id`
    })

    const selectIdle = SqlSchema.findAll({
      Request: IdleRequest,
      Result: Schema.Struct({ userId: UserId }),
      execute: (row) =>
        sql`SELECT a.user_id AS "userId" FROM effect_auth_anonymous a
        WHERE a.last_seen_at <= ${row.before}
          AND NOT EXISTS (
            SELECT 1 FROM sessions s WHERE s.user_id = a.user_id AND s.expires_at > ${row.now}
          )
        ORDER BY a.last_seen_at
        LIMIT ${row.limit}`
    })

    return AnonymousStore.of({
      find: (userId) => mapErrors("AnonymousStore.find")(selectByUserId(userId)),
      create: (userId) =>
        mapErrors("AnonymousStore.create")(Effect.flatMap(DateTime.now, (now) => insertMarker({ userId, now }))),
      touch: (userId) =>
        mapErrors("AnonymousStore.touch")(
          Effect.flatMap(DateTime.now, (now) => Effect.map(stamp({ userId, now }), (rows) => rows.length > 0))
        ),
      clear: (userId) => mapErrors("AnonymousStore.clear")(Effect.map(deleteMarker(userId), (rows) => rows.length > 0)),
      listIdle: (options) =>
        mapErrors("AnonymousStore.listIdle")(Effect.map(selectIdle(options), (rows) => rows.map((row) => row.userId)))
    })
  }
)

/**
 * Provides {@link AnonymousStore} over the ambient `SqlClient`.
 *
 * **Gotchas**
 *
 * Named for the thing it provides rather than `layer`, because a plugin's
 * barrel is flat and `Anonymous.layer` is the plugin's own.
 *
 * @category layers
 * @since 0.2.0
 */
export const layerAnonymousStore: Layer.Layer<AnonymousStore, never, SqlClient.SqlClient> = Layer.effect(
  AnonymousStore,
  makeAnonymousStore
)
