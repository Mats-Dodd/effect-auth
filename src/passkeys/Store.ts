/**
 * The persistence seam for registered passkeys.
 *
 * **Details**
 *
 * A service of the plugin's own, implemented over the ambient `SqlClient` by
 * {@link layer}, on exactly the terms `SqlStores` implements this library's four
 * core stores: statements written with the tagged-template constructor, columns
 * `snake_case` in the database and aliased back to the model's `camelCase`, and
 * every driver failure classified as a `PersistenceError` with `kind:
 * "UniqueViolation"` where the driver said so.
 *
 * It is separate from {@link Passkeys} for the reason `SqlStores` is separate
 * from `Sessions`: the policy — which credential may be used by whom, what a
 * counter regression means, what evidence a ceremony produced — belongs to the
 * service, and a deployment that keeps its credentials somewhere other than the
 * deployment's SQL database replaces this and keeps that.
 *
 * **Gotchas — ownership lives here**
 *
 * `rename`, `remove` and `findByIdAndUser` all carry the user id into the
 * `WHERE` clause. A caller cannot read a row, check it, and then act on it: the
 * check and the act are one statement. That is the shape the IDOR in
 * better-auth's passkey plugin (`bd9bd58f8`) did not have.
 *
 * SQLite and MySQL have no boolean type, so the three flags are stored as
 * `1`/`0` there and as real booleans on PostgreSQL. That difference is
 * `Dialect.booleanCodec`'s and nothing else's, exactly as
 * `users.email_verified`'s is. Every mutation that has to answer with the row
 * it wrote goes through `Mutations`, which is where MySQL's missing `RETURNING`
 * is dealt with — once, rather than per statement.
 *
 * @since 0.2.0
 */
import { Array, Context, DateTime, Effect, Layer, Option, Schema } from "effect"
import { SqlClient } from "effect/unstable/sql"
import { UserId } from "../domain/Schema.js"
import { persistenceFailureKind, PersistenceError } from "../domain/Stores.js"
import { booleanCodec, dialectOf } from "../sql/Dialect.js"
import * as Mutations from "../sql/Mutations.js"
import type { PasskeyId } from "./Schema.js"
import { Passkey } from "./Schema.js"

// -----------------------------------------------------------------------------
// Models
// -----------------------------------------------------------------------------

/**
 * What one completed ceremony changes about a stored credential.
 *
 * **Details**
 *
 * Four columns, and no more: `backupEligible` is a property of the credential
 * rather than of this ceremony, and `publicKey`, `credentialId` and `aaguid`
 * are what the credential *is*. A row's identity never moves.
 *
 * @category models
 * @since 0.2.0
 */
export interface PasskeyUse {
  /** The counter the authenticator reported. */
  readonly signCount: number
  /** Whether the credential is currently backed up. */
  readonly backedUp: boolean
  /** Whether the authenticator has now verified the person to itself at least once. */
  readonly uvInitialised: boolean
  /** When the ceremony completed. */
  readonly lastUsedAt: DateTime.Utc
}

/**
 * The {@link PasskeyStore} service definition.
 *
 * @category models
 * @since 0.2.0
 */
export interface PasskeyStoreService {
  /**
   * Inserts a credential.
   *
   * Fails with a `UniqueViolation` `PersistenceError` when the credential id is
   * already registered — to this user or to anybody else. That is the whole of
   * the "a credential is registered once" rule: it is an index, not a lookup.
   */
  readonly create: (passkey: typeof Passkey.insert.Type) => Effect.Effect<Passkey, PersistenceError>

  /**
   * Looks a credential up by the id the authenticator chose.
   *
   * **Gotchas**
   *
   * Not scoped to a user, and it cannot be: a discoverable sign-in presents a
   * credential id and nothing else, and the account is what this read
   * *discovers*. Everything downstream of it re-checks ownership.
   */
  readonly findByCredentialId: (credentialId: string) => Effect.Effect<Option.Option<Passkey>, PersistenceError>

  /** Looks one of a user's own credentials up by row id. */
  readonly findByIdAndUser: (id: PasskeyId, userId: UserId) => Effect.Effect<Option.Option<Passkey>, PersistenceError>

  /** Every credential a user has registered, oldest first. */
  readonly listByUserId: (userId: UserId) => Effect.Effect<ReadonlyArray<Passkey>, PersistenceError>

  /** Records a completed ceremony, or `None` when the row has gone. */
  readonly recordUse: (id: PasskeyId, use: PasskeyUse) => Effect.Effect<Option.Option<Passkey>, PersistenceError>

  /** Renames one of a user's own credentials, or `None` when they have no such row. */
  readonly rename: (
    id: PasskeyId,
    userId: UserId,
    name: string | null
  ) => Effect.Effect<Option.Option<Passkey>, PersistenceError>

  /** Removes one of a user's own credentials, answering whether a row went. */
  readonly remove: (id: PasskeyId, userId: UserId) => Effect.Effect<boolean, PersistenceError>

  /** Removes every credential a user holds, answering how many went. */
  readonly removeByUserId: (userId: UserId) => Effect.Effect<number, PersistenceError>

  /** The user's WebAuthn handle, or `None` when they have never been issued one. */
  readonly findHandle: (userId: UserId) => Effect.Effect<Option.Option<string>, PersistenceError>

  /**
   * Issues a user's WebAuthn handle.
   *
   * **Gotchas**
   *
   * Fails with a `UniqueViolation` when one already exists, rather than
   * overwriting it: a handle that changed would orphan every credential already
   * registered under the old one. The caller resolves the race by reading
   * again — see `Passkeys`.
   */
  readonly createHandle: (userId: UserId, handle: string) => Effect.Effect<string, PersistenceError>

  /** The user a handle belongs to, or `None`. */
  readonly findUserIdByHandle: (handle: string) => Effect.Effect<Option.Option<UserId>, PersistenceError>
}

/**
 * Where registered passkeys live. See {@link PasskeyStoreService}.
 *
 * @category services
 * @since 0.2.0
 */
export class PasskeyStore extends Context.Service<PasskeyStore, PasskeyStoreService>()(
  "effect-auth/passkeys/Store/PasskeyStore"
) {}

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

interface Row {
  readonly [column: string]: unknown
}

const persist =
  (operation: string) =>
  <A, E, R>(effect: Effect.Effect<A, E, R>): Effect.Effect<A, PersistenceError, R> =>
    Effect.mapError(effect, (cause) => PersistenceError.make({ operation, kind: persistenceFailureKind(cause), cause }))

const noRow = (operation: string) =>
  Effect.fail(PersistenceError.make({ operation, cause: "the statement returned no row" }))

const passkeyColumns = [
  "id",
  `user_id AS "userId"`,
  `credential_id AS "credentialId"`,
  `public_key AS "publicKey"`,
  `sign_count AS "signCount"`,
  "transports",
  "aaguid",
  `backup_eligible AS "backupEligible"`,
  `backed_up AS "backedUp"`,
  `uv_initialised AS "uvInitialised"`,
  "name",
  `created_at AS "createdAt"`,
  `last_used_at AS "lastUsedAt"`
].join(", ")

/** The one table a credential lives in. */
const passkeys = "effect_auth_passkeys"

/** The one table a WebAuthn user handle lives in. */
const passkeyUsers = "effect_auth_passkey_users"

/** What names a credential row again after it has been written. */
const passkeyKey = ["id"]

/**
 * `bigint` reaches this library as a `number` under PGlite and SQLite and as a
 * `string` under drivers that refuse to narrow it — PostgreSQL's among them.
 * `sign_count` holds a WebAuthn signature counter, a uint32, so the conversion
 * is lossless. The same normalisation lives on `last_used_step` in
 * `two-factor/Store.ts`.
 */
const readSignCount = (value: unknown): unknown => (typeof value === "string" ? Number(value) : value)

/**
 * Builds the SQL implementation over the ambient `SqlClient`.
 *
 * @category constructors
 * @since 0.2.0
 */
export const make: Effect.Effect<PasskeyStoreService, never, SqlClient.SqlClient> = Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient
  const dialect = yield* dialectOf(sql)
  const cols = sql.literal(passkeyColumns)
  const boolean = booleanCodec(dialect)

  const decodePasskey = Schema.decodeUnknownEffect(Passkey)
  const encodeInsert = Schema.encodeUnknownEffect(Passkey.insert)

  /** The driver's stored flags and counter brought back before the model sees them. */
  const readPasskey = (row: Row) =>
    decodePasskey({
      ...row,
      signCount: readSignCount(row["signCount"]),
      backupEligible: boolean.decode(row["backupEligible"]),
      backedUp: boolean.decode(row["backedUp"]),
      uvInitialised: boolean.decode(row["uvInitialised"])
    })

  const first = (operation: string) => (rows: ReadonlyArray<Row>) =>
    Option.match(Array.head(rows), {
      onNone: () => Effect.succeedNone,
      onSome: (row) => Effect.asSome(persist(operation)(readPasskey(row)))
    })

  const all = (operation: string) => (rows: ReadonlyArray<Row>) => persist(operation)(Effect.forEach(rows, readPasskey))

  return PasskeyStore.of({
    create: (passkey) =>
      Effect.gen(function* () {
        // Encoding a row this library built is its own doing: a failure here is
        // a defect, not something a caller can act on.
        const row = yield* Effect.orDie(encodeInsert(passkey))
        const rows = yield* persist("PasskeyStore.create")(
          Mutations.insertAndRead<Row>({
            sql,
            dialect,
            table: passkeys,
            key: passkeyKey,
            record: {
              id: row.id,
              user_id: row.userId,
              credential_id: row.credentialId,
              public_key: row.publicKey,
              sign_count: row.signCount,
              transports: row.transports,
              aaguid: row.aaguid,
              backup_eligible: boolean.encode(row.backupEligible),
              backed_up: boolean.encode(row.backedUp),
              uv_initialised: boolean.encode(row.uvInitialised),
              name: row.name,
              created_at: row.createdAt,
              last_used_at: row.lastUsedAt
            },
            columns: cols
          })
        )
        return yield* Option.match(Array.head(rows), {
          onNone: () => noRow("PasskeyStore.create"),
          onSome: (created) => persist("PasskeyStore.create")(readPasskey(created))
        })
      }),

    findByCredentialId: (credentialId) =>
      Effect.flatMap(
        persist("PasskeyStore.findByCredentialId")(
          sql<Row>`SELECT ${cols} FROM effect_auth_passkeys WHERE credential_id = ${credentialId}`
        ),
        first("PasskeyStore.findByCredentialId")
      ),

    findByIdAndUser: (id, userId) =>
      Effect.flatMap(
        persist("PasskeyStore.findByIdAndUser")(
          sql<Row>`SELECT ${cols} FROM effect_auth_passkeys WHERE id = ${id} AND user_id = ${userId}`
        ),
        first("PasskeyStore.findByIdAndUser")
      ),

    listByUserId: (userId) =>
      Effect.flatMap(
        persist("PasskeyStore.listByUserId")(
          sql<Row>`SELECT ${cols} FROM effect_auth_passkeys
            WHERE user_id = ${userId}
            ORDER BY created_at ASC, id ASC`
        ),
        all("PasskeyStore.listByUserId")
      ),

    // One statement on PostgreSQL and SQLite, one locked read-modify-read on
    // MySQL: either way the counter, the backup state, the user-verification
    // history and the stamp move together, so a reader never sees a row whose
    // counter has advanced past a ceremony it does not record.
    recordUse: (id, use) =>
      Effect.flatMap(
        persist("PasskeyStore.recordUse")(
          Mutations.updateAndRead<Row>({
            sql,
            dialect,
            table: passkeys,
            key: passkeyKey,
            set: {
              sign_count: use.signCount,
              backed_up: boolean.encode(use.backedUp),
              uv_initialised: boolean.encode(use.uvInitialised),
              last_used_at: DateTime.formatIso(use.lastUsedAt)
            },
            where: sql`id = ${id}`,
            columns: cols
          })
        ),
        first("PasskeyStore.recordUse")
      ),

    rename: (id, userId, name) =>
      Effect.flatMap(
        persist("PasskeyStore.rename")(
          Mutations.updateAndRead<Row>({
            sql,
            dialect,
            table: passkeys,
            key: passkeyKey,
            set: { name },
            where: sql`id = ${id} AND user_id = ${userId}`,
            columns: cols
          })
        ),
        first("PasskeyStore.rename")
      ),

    remove: (id, userId) =>
      persist("PasskeyStore.remove")(
        Effect.map(
          Mutations.deleteAndCount({
            sql,
            dialect,
            table: passkeys,
            key: passkeyKey,
            where: sql`id = ${id} AND user_id = ${userId}`
          }),
          (count) => count > 0
        )
      ),

    removeByUserId: (userId) =>
      persist("PasskeyStore.removeByUserId")(
        Mutations.deleteAndCount({
          sql,
          dialect,
          table: passkeys,
          key: passkeyKey,
          where: sql`user_id = ${userId}`
        })
      ),

    findHandle: (userId) =>
      persist("PasskeyStore.findHandle")(
        Effect.map(sql<Row>`SELECT handle FROM effect_auth_passkey_users WHERE user_id = ${userId}`, (rows) =>
          Option.map(Array.head(rows), (row) => String(row["handle"]))
        )
      ),

    createHandle: (userId, handle) =>
      Effect.flatMap(
        persist("PasskeyStore.createHandle")(
          Mutations.insertAndRead<Row>({
            sql,
            dialect,
            table: passkeyUsers,
            key: ["user_id"],
            record: { user_id: userId, handle },
            columns: sql.literal("handle")
          })
        ),
        (rows) =>
          Option.match(Array.head(rows), {
            onNone: () => noRow("PasskeyStore.createHandle"),
            onSome: (row) => Effect.succeed(String(row["handle"]))
          })
      ),

    findUserIdByHandle: (handle) =>
      persist("PasskeyStore.findUserIdByHandle")(
        Effect.map(
          sql<Row>`SELECT user_id AS "userId" FROM effect_auth_passkey_users WHERE handle = ${handle}`,
          (rows) => Option.map(Array.head(rows), (row) => UserId.make(String(row["userId"])))
        )
      )
  })
})

/**
 * Provides {@link PasskeyStore} over the ambient `SqlClient`.
 *
 * **When to use**
 *
 * Below `Passkeys.layer`, and — since the `Authenticators` contribution reads
 * it too — usually beside `SqlStores.layer` over the same client.
 *
 * @category layers
 * @since 0.2.0
 */
export const layer: Layer.Layer<PasskeyStore, never, SqlClient.SqlClient> = Layer.effect(PasskeyStore, make)
