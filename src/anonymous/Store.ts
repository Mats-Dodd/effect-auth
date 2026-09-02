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
import { SqlClient, SqlSchema } from "effect/unstable/sql"
import { UserId } from "../domain/Schema.js"
import type { PersistenceError as PersistenceErrorType } from "../domain/Stores.js"
import { PersistenceError, persistenceFailureKind } from "../domain/Stores.js"
import { dialectOf, identifier } from "../sql/Dialect.js"
import * as Mutations from "../sql/Mutations.js"

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

/** The marker table. Its schema is `./Migrations.ts`. */
const anonymous = "effect_auth_anonymous"

/** The holder is the primary key, so it is what every mutation re-addresses its row by. */
const key: ReadonlyArray<string> = ["user_id"]

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
    const dialect = yield* dialectOf(sql)
    const cols = sql.literal(columns)
    const table = identifier(sql, anonymous)
    /** The holder alone — what `touch` counts, rather than reading the row back. */
    const holder = sql`${identifier(sql, "user_id")}`

    const mapErrors =
      (operation: string) =>
      <A, E, R>(effect: Effect.Effect<A, E, R>): Effect.Effect<A, PersistenceErrorType, R> =>
        Effect.mapError(effect, (cause) =>
          PersistenceError.make({ operation, kind: persistenceFailureKind(cause), cause })
        )

    const selectByUserId = SqlSchema.findOneOption({
      Request: UserId,
      Result: AnonymousRecord,
      execute: (userId) => sql`SELECT ${cols} FROM ${table} WHERE user_id = ${userId}`
    })

    const insertMarker = SqlSchema.findOne({
      Request: StampRequest,
      Result: AnonymousRecord,
      execute: (row) =>
        Mutations.insertAndRead({
          sql,
          dialect,
          table: anonymous,
          key,
          record: { user_id: row.userId, created_at: row.now, last_seen_at: row.now },
          columns: cols
        })
    })

    /**
     * Moves the clock, answering with the holder of every row it moved.
     *
     * The projection is the key rather than the row: `touch` only asks whether a
     * marker was there, and reading the row back would be a second thing for
     * MySQL's write-then-read to keep in step with.
     */
    const stamp = SqlSchema.findAll({
      Request: StampRequest,
      Result: Schema.Struct({ user_id: Schema.String }),
      execute: (row) =>
        Mutations.updateAndRead({
          sql,
          dialect,
          table: anonymous,
          key,
          set: { last_seen_at: row.now },
          where: sql`user_id = ${row.userId}`,
          columns: holder
        })
    })

    const deleteMarker = (userId: UserId) =>
      Mutations.deleteAndCount({ sql, dialect, table: anonymous, key, where: sql`user_id = ${userId}` })

    const selectIdle = SqlSchema.findAll({
      Request: IdleRequest,
      Result: Schema.Struct({ userId: UserId }),
      execute: (row) =>
        sql`SELECT a.user_id AS "userId" FROM ${table} a
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
      clear: (userId) => mapErrors("AnonymousStore.clear")(Effect.map(deleteMarker(userId), (count) => count > 0)),
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
