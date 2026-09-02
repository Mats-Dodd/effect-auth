/**
 * The SQL `SessionStore`.
 *
 * **Details**
 *
 * `findByTokenHash` resolves a presented token to its session **and** its user
 * in a single joined read, so the hot path of every authenticated request is
 * one round trip — one statement on every dialect, because nothing about a
 * `SELECT` needs a dialect's opinion. The user half of that row is the model's,
 * so its projection is derived from the model's field map exactly as the user
 * store's is; the session half is fixed and spelled out.
 *
 * Every write goes through `src/sql/Mutations.ts`. `elevate` is the one that is
 * more than a write: it reads the stored row under a lock, lets the caller's
 * `append` decide the new log, and writes the result — so it holds the
 * transaction and the lock itself, through `Mutations.atomically` like every
 * other multi-statement sequence, and hands only the write to the helper, which
 * on MySQL re-takes the same row's lock inside the same transaction and is
 * therefore the same single guarded write it is on PostgreSQL.
 *
 * Not exported from the package: `SqlStores.layerFor` is the public door.
 *
 * @internal
 */
import { Array, DateTime, Effect, Option, Schema } from "effect"
import { SqlClient } from "effect/unstable/sql"
import type { SessionStoreService, SessionWithUser } from "../../domain/Stores.js"
import { PersistenceError, sessionStoreOf } from "../../domain/Stores.js"
import { AuthenticationMethodsJson } from "../../domain/Assurance.js"
import type { UserFields, UserModel, UserRow } from "../../domain/Schema.js"
import { Session } from "../../domain/Schema.js"
import { booleanCodec, dialectOf, lockClause } from "../Dialect.js"
import { atomically, deleteAndCount, insertAndRead, updateAndRead } from "../Mutations.js"
import { joinedProjectionOf, persist, userColumnsOf, userReaderOf } from "./internal.js"

// -----------------------------------------------------------------------------
// Column projections
// -----------------------------------------------------------------------------

const sessionColumns = `id, token_hash AS "tokenHash", user_id AS "userId", expires_at AS "expiresAt", ip_address AS "ipAddress", user_agent AS "userAgent", authenticated_at AS "authenticatedAt", aal, methods, remember_me AS "rememberMe", created_at AS "createdAt", updated_at AS "updatedAt"`

const sessionJoinColumns = `s.id AS "s_id", s.token_hash AS "s_tokenHash", s.user_id AS "s_userId", s.expires_at AS "s_expiresAt", s.ip_address AS "s_ipAddress", s.user_agent AS "s_userAgent", s.authenticated_at AS "s_authenticatedAt", s.aal AS "s_aal", s.methods AS "s_methods", s.remember_me AS "s_rememberMe", s.created_at AS "s_createdAt", s.updated_at AS "s_updatedAt"`

/** The table this store owns. */
const table = "sessions"

/** The unique key a mutation re-addresses a row by where the dialect needs one. */
const key = ["id"]

/** @internal */
export const make: <F extends UserFields>(
  model: UserModel<F>
) => Effect.Effect<SessionStoreService<F>, never, SqlClient.SqlClient> = Effect.fnUntraced(function* <
  F extends UserFields
>(model: UserModel<F>) {
  const sql = yield* SqlClient.SqlClient
  const dialect = yield* dialectOf(sql)
  const sessionCols = sql.literal(sessionColumns)
  const columns = userColumnsOf(model.selectFields)
  const sessionWithUserCols = sql.csv([sql.literal(sessionJoinColumns), joinedProjectionOf(sql, columns, "u", "u_")])
  const boolean = booleanCodec(dialect)
  // The joined user half may carry a deployment's own nullable flag, so an
  // absent value stays absent there; `sessions.remember_me` is `NOT NULL` on
  // every dialect and is read as the flag it is.
  const readUser = userReaderOf(columns, boolean.decodeNullable)

  const decodeSession = Schema.decodeUnknownEffect(Session)
  const encodeInsert = Schema.encodeUnknownEffect(Session.insert)
  const encodeMethods = Schema.encodeUnknownEffect(AuthenticationMethodsJson)

  /**
   * `sessions.remember_me` is the one boolean the session table stores, so —
   * exactly as the user store does for its own flags — the dialect's stored
   * form is brought back to a `boolean` before the row is decoded, rather than
   * letting SQLite's or MySQL's integer reach a `Schema.Boolean`.
   */
  const readSession = (row: UserRow): Effect.Effect<Session, Schema.SchemaError> =>
    decodeSession({ ...row, rememberMe: boolean.decode(row["rememberMe"]) })

  /** `elevate`'s own row lock: the read it takes before it decides what to write. */
  const lock = lockClause(sql, dialect)

  const firstSession = (rows: ReadonlyArray<UserRow>): Effect.Effect<Option.Option<Session>, Schema.SchemaError> =>
    Option.match(Array.head(rows), {
      onNone: () => Effect.succeedNone,
      onSome: (row) => Effect.asSome(readSession(row))
    })

  const sessionFromRow = (row: UserRow) => ({
    id: row["s_id"],
    tokenHash: row["s_tokenHash"],
    userId: row["s_userId"],
    expiresAt: row["s_expiresAt"],
    ipAddress: row["s_ipAddress"],
    userAgent: row["s_userAgent"],
    authenticatedAt: row["s_authenticatedAt"],
    aal: row["s_aal"],
    methods: row["s_methods"],
    rememberMe: boolean.decode(row["s_rememberMe"]),
    createdAt: row["s_createdAt"],
    updatedAt: row["s_updatedAt"]
  })

  /**
   * The two halves of the joined row are decoded separately rather than
   * through one composite schema: only the user half is the model's, and
   * keeping it that way is what stops the model's field map leaking into the
   * session store's own types.
   */
  const decodeJoined = (row: UserRow): Effect.Effect<SessionWithUser<F>, PersistenceError> =>
    Effect.mapError(
      Effect.all({
        session: decodeSession(sessionFromRow(row)),
        user: model.decodeRow(readUser(row, "u_"))
      }),
      (cause) => PersistenceError.make({ operation: "SessionStore.findByTokenHash", cause })
    )

  const insertSession = (session: typeof Session.insert.Type): Effect.Effect<Session, PersistenceError> =>
    persist("SessionStore.create")(
      Effect.gen(function* () {
        // Encoding a well-formed insert row is the model's own doing, so a
        // failure here is a defect rather than something a caller can act on.
        const row = yield* Effect.orDie(encodeInsert(session))
        const rows = yield* insertAndRead<UserRow>({
          sql,
          dialect,
          table,
          key,
          record: {
            id: row.id,
            token_hash: row.tokenHash,
            user_id: row.userId,
            expires_at: row.expiresAt,
            ip_address: row.ipAddress,
            user_agent: row.userAgent,
            authenticated_at: row.authenticatedAt,
            aal: row.aal,
            methods: row.methods,
            remember_me: boolean.encode(row.rememberMe),
            created_at: row.createdAt,
            updated_at: row.updatedAt
          },
          columns: sessionCols
        })
        return yield* Option.match(Array.head(rows), {
          onNone: () =>
            Effect.fail(
              PersistenceError.make({ operation: "SessionStore.create", cause: "the statement returned no row" })
            ),
          onSome: readSession
        })
      })
    )

  const selectSessionWithUser = (
    tokenHash: string
  ): Effect.Effect<Option.Option<SessionWithUser<F>>, PersistenceError> =>
    Effect.flatMap(
      persist("SessionStore.findByTokenHash")(
        sql<UserRow>`SELECT ${sessionWithUserCols}
          FROM sessions s
          INNER JOIN users u ON u.id = s.user_id
          WHERE s.token_hash = ${tokenHash}`
      ),
      (rows) =>
        Option.match(Array.head(rows), {
          onNone: (): Effect.Effect<Option.Option<SessionWithUser<F>>, PersistenceError> => Effect.succeedNone,
          onSome: (row) => Effect.asSome(decodeJoined(row))
        })
    )

  return sessionStoreOf(model).of({
    create: (session) => insertSession(session),

    findByTokenHash: (tokenHash) => selectSessionWithUser(tokenHash),

    // The rolling refresh moves only the expiry and the update stamp; the
    // stored `remember_me` is deliberately left as it was, so a short session
    // kept alive by browsing never has its lifetime silently promoted.
    touch: (id, expiresAt) =>
      persist("SessionStore.touch")(
        Effect.gen(function* () {
          const now = yield* DateTime.now
          const rows = yield* updateAndRead<UserRow>({
            sql,
            dialect,
            table,
            key,
            set: { expires_at: DateTime.formatIso(expiresAt), updated_at: DateTime.formatIso(now) },
            where: sql`id = ${id}`,
            columns: sessionCols
          })
          return yield* firstSession(rows)
        })
      ),

    // A step-up as a read-modify-write, under a lock on the row and inside one
    // transaction: the stored log is read, the caller's `append` decides what
    // the new log and level are, and the log, the level, the stamp and the
    // digest of the new token are written together. No reader can observe a row
    // whose `aal` disagrees with its `methods`, the old token stops resolving
    // at the same instant the new one starts, and — because the log appended to
    // is the one in the row rather than the one the caller was holding — a
    // stale `Session` value or a concurrent elevation cannot silently drop what
    // the session had already proved.
    elevate: (id, patch) =>
      persist("SessionStore.elevate")(
        atomically(
          sql,
          dialect,
          Effect.gen(function* () {
            const now = yield* DateTime.now
            const locked = yield* sql<UserRow>`SELECT ${sessionCols} FROM sessions WHERE id = ${id}${lock}`
            const current = Array.head(locked)
            // Concurrently revoked. `None` rather than a failure, exactly as
            // `touch` answers for the same situation.
            if (Option.isNone(current)) return Option.none<Session>()

            const stored = yield* readSession(current.value)
            const next = patch.append(stored.methods)
            // The array is derived from the row's own, already typed; a failure
            // to encode it is this library's bug rather than something a caller
            // can act on.
            const methods = yield* Effect.orDie(encodeMethods(next.methods))
            const rows = yield* updateAndRead<UserRow>({
              sql,
              dialect,
              table,
              key,
              set: {
                methods,
                aal: next.aal,
                authenticated_at: DateTime.formatIso(patch.authenticatedAt),
                token_hash: patch.tokenHash,
                updated_at: DateTime.formatIso(now)
              },
              where: sql`id = ${id}`,
              columns: sessionCols
            })
            return yield* firstSession(rows)
          })
        )
      ),

    deleteById: (id, userId) =>
      persist("SessionStore.deleteById")(
        Effect.map(
          deleteAndCount({ sql, dialect, table, key, where: sql`id = ${id} AND user_id = ${userId}` }),
          (count) => count > 0
        )
      ),

    deleteByUserId: (userId) =>
      persist("SessionStore.deleteByUserId")(
        deleteAndCount({ sql, dialect, table, key, where: sql`user_id = ${userId}` })
      ),

    deleteByUserIdExcept: (userId, sessionId) =>
      persist("SessionStore.deleteByUserIdExcept")(
        deleteAndCount({ sql, dialect, table, key, where: sql`user_id = ${userId} AND id <> ${sessionId}` })
      ),

    listByUserId: (userId) =>
      persist("SessionStore.listByUserId")(
        Effect.gen(function* () {
          const now = yield* DateTime.now
          const rows = yield* sql<UserRow>`SELECT ${sessionCols} FROM sessions
          WHERE user_id = ${userId} AND expires_at > ${DateTime.formatIso(now)}
          ORDER BY created_at DESC, id DESC`
          return yield* Effect.forEach(rows, readSession)
        })
      ),

    deleteExpired: persist("SessionStore.deleteExpired")(
      Effect.flatMap(DateTime.now, (now) =>
        deleteAndCount({ sql, dialect, table, key, where: sql`expires_at <= ${DateTime.formatIso(now)}` })
      )
    )
  })
})
