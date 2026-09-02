/**
 * The SQL `UserStore`.
 *
 * **Details**
 *
 * The user model is the one table a deployment may add columns to, so this
 * store spells nothing out: its projection, its `INSERT` and its `UPDATE` are
 * all derived from the model's own field map when {@link make} builds the
 * service. Which of its columns is a boolean — the one thing the dialects
 * genuinely disagree about — is read off the field's encoded schema rather than
 * off its name.
 *
 * Every write goes through `src/sql/Mutations.ts`, which is where the three
 * dialects' spellings of "write a row and hand it back" live. This module reads
 * the dialect once, when the service is built, and holds nothing dialect-shaped
 * of its own beyond the boolean codec its columns are written through.
 *
 * Not exported from the package: `SqlStores.layerFor` is the public door.
 *
 * @internal
 */
import { Array, DateTime, Effect, Option, Schema } from "effect"
import { SqlClient } from "effect/unstable/sql"
import { omitUndefined } from "../../internal/records.js"
import type { UserPatch, UserStoreService } from "../../domain/Stores.js"
import { PersistenceError, userStoreOf } from "../../domain/Stores.js"
import type { UserFields, UserModel, UserOf, UserRow } from "../../domain/Schema.js"
import { booleanCodec, dialectOf, lockClause } from "../Dialect.js"
import { deleteAndCount, insertAndRead, updateAndRead } from "../Mutations.js"
import { columnWriterOf, persist, projectionOf, type RawIdRow, userColumnsOf, userReaderOf } from "./internal.js"

/** The table this store owns. */
const table = "users"

/** The unique key a mutation re-addresses a row by where the dialect needs one. */
const key = ["id"]

/** @internal */
export const make: <F extends UserFields>(
  model: UserModel<F>
) => Effect.Effect<UserStoreService<F>, never, SqlClient.SqlClient> = Effect.fnUntraced(function* <
  F extends UserFields
>(model: UserModel<F>) {
  const sql = yield* SqlClient.SqlClient
  const dialect = yield* dialectOf(sql)
  const columns = userColumnsOf(model.selectFields)
  const userCols = sql.literal(projectionOf(columns))
  const boolean = booleanCodec(dialect)
  // A custom field may be a nullable flag, so a stored `null` stays `null`
  // rather than being read as "declined".
  const readUser = userReaderOf(columns, boolean.decodeNullable)
  const toColumns = columnWriterOf(columns, boolean.encode)
  const lock = lockClause(sql, dialect)

  const encodeInsert = Schema.encodeUnknownEffect(model.rows.insert)
  const encodePatch = Schema.encodeUnknownEffect(model.rows.patch)

  /** A decoding failure means the columns and the model have drifted apart. */
  const decoded = (operation: string, row: UserRow): Effect.Effect<UserOf<F>, PersistenceError> =>
    Effect.mapError(model.decodeRow(readUser(row, "")), (cause) => PersistenceError.make({ operation, cause }))

  const one =
    (operation: string) =>
    (rows: ReadonlyArray<UserRow>): Effect.Effect<UserOf<F>, PersistenceError> =>
      Option.match(Array.head(rows), {
        onNone: () => Effect.fail(PersistenceError.make({ operation, cause: "the statement returned no row" })),
        onSome: (row) => decoded(operation, row)
      })

  const first =
    (operation: string) =>
    (rows: ReadonlyArray<UserRow>): Effect.Effect<Option.Option<UserOf<F>>, PersistenceError> =>
      Option.match(Array.head(rows), {
        onNone: () => Effect.succeedNone,
        onSome: (row) => Effect.asSome(decoded(operation, row))
      })

  return userStoreOf(model).of({
    create: (user) =>
      Effect.gen(function* () {
        // A caller holding the base-typed key builds rows out of base fields
        // alone; the model's own defaults are what makes such a row storable.
        const complete = yield* model.completeInsert(user)
        const encoded = yield* Effect.orDie(encodeInsert(complete))
        const rows = yield* persist("UserStore.create")(
          insertAndRead<UserRow>({ sql, dialect, table, key, record: toColumns(encoded), columns: userCols })
        )
        return yield* one("UserStore.create")(rows)
      }),

    findById: (id) =>
      Effect.flatMap(
        persist("UserStore.findById")(sql<UserRow>`SELECT ${userCols} FROM users WHERE id = ${id}`),
        first("UserStore.findById")
      ),

    findByEmail: (email) =>
      Effect.flatMap(
        persist("UserStore.findByEmail")(sql<UserRow>`SELECT ${userCols} FROM users WHERE email = ${email}`),
        first("UserStore.findByEmail")
      ),

    update: (id, patch: UserPatch<F>) =>
      Effect.gen(function* () {
        const now = yield* DateTime.now
        // The patch is already typed by the model, so an encoding failure here
        // is a bug rather than something a caller can act on.
        const encoded = yield* Effect.orDie(encodePatch(patch))
        const set = omitUndefined({ ...toColumns(encoded), updated_at: DateTime.formatIso(now) })
        const rows = yield* persist("UserStore.update")(
          updateAndRead<UserRow>({ sql, dialect, table, key, set, where: sql`id = ${id}`, columns: userCols })
        )
        return yield* first("UserStore.update")(rows)
      }),

    delete: (id) =>
      persist("UserStore.delete")(
        Effect.map(deleteAndCount({ sql, dialect, table, key, where: sql`id = ${id}` }), (count) => count > 0)
      ),

    // Called for the lock, not the row: a transaction takes it before reading
    // a user's accounts so a concurrent reclaim of the same user cannot
    // interleave. The id is a bound parameter; the only interpolated fragment
    // is the dialect's own `FOR UPDATE` (empty on SQLite).
    lockUserRow: (id) =>
      persist("UserStore.lockUserRow")(Effect.asVoid(sql<RawIdRow>`SELECT id FROM users WHERE id = ${id}${lock}`))
  })
})
