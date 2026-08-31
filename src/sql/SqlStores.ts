/**
 * The SQL implementation of the `effect-auth` persistence seam.
 *
 * One layer, {@link layer}, provides all four stores plus the transaction
 * runner over an ambient `SqlClient`. Statements are written with the
 * tagged-template constructor and decoded into the domain models with
 * `SqlSchema`, so a row never reaches the domain services as a bag of `unknown`.
 *
 * **Details**
 *
 * Columns are `snake_case` in the database and aliased back to the models'
 * `camelCase` field names in every projection (`token_hash AS "tokenHash"`),
 * which keeps the schema idiomatic on PostgreSQL without depending on a
 * client-level name transform the application may not have configured.
 *
 * The three fixed models spell their projections out. The user model does not:
 * a deployment may add columns to it, so its projection, its `INSERT` and its
 * `UPDATE` are all derived from the model's own field map when
 * {@link layerFor} builds the layer. Which of its columns is a boolean — the one
 * thing PostgreSQL and SQLite genuinely disagree about — is read off the field's
 * encoded schema rather than off its name.
 *
 * Two behaviours are worth calling out because the security of the library
 * rests on them:
 *
 * - `SessionStore.findByTokenHash` resolves a presented token to its session
 *   **and** its user in a single joined read, so the hot path of every
 *   authenticated request is one round trip.
 * - `VerificationStore.consume` is a single `DELETE ... RETURNING` guarded by
 *   the expiry, which is what makes password-reset tokens, e-mail verification
 *   links and OAuth state genuinely single-use: two concurrent callers cannot
 *   both be handed the row.
 *
 * **Gotchas**
 *
 * Every failure — a driver error, a decoding error, an unexpectedly missing
 * `RETURNING` row — is reported as {@link PersistenceError}, with `kind` set to
 * `"UniqueViolation"` where the driver said so, which is the one distinction
 * the domain acts on. The underlying `SqlError` is kept in `cause` for logs;
 * nothing above the seam inspects it.
 *
 * @since 1.0.0
 */
import { Array, DateTime, Effect, Layer, Option, Predicate, Schema, SchemaAST } from "effect"
import { SqlClient, SqlError, SqlSchema } from "effect/unstable/sql"
import { camelToSnake, omitUndefined } from "../internal/records.js"
import type {
  AccountStoreService,
  AccountTokens,
  AuthStores,
  PersistenceFailureKind,
  SessionStoreService,
  SessionWithUser,
  UserPatch,
  UserStoreService,
  VerificationStoreService,
  WithAuthTransactionService
} from "../domain/Stores.js"
import {
  AccountStore,
  PersistenceError,
  sessionStoreOf,
  userStoreOf,
  VerificationStore,
  WithAuthTransaction
} from "../domain/Stores.js"
import type { AccountId, UserFields, UserModel, UserOf, UserRow } from "../domain/Schema.js"
import { Account, baseUserModel, CredentialIssuer, Session, Verification } from "../domain/Schema.js"

// -----------------------------------------------------------------------------
// Column projections
// -----------------------------------------------------------------------------

const sessionColumns =
  `id, token_hash AS "tokenHash", user_id AS "userId", expires_at AS "expiresAt", ip_address AS "ipAddress", user_agent AS "userAgent", created_at AS "createdAt", updated_at AS "updatedAt"`

const accountColumns =
  `id, issuer, account_id AS "accountId", provider_id AS "providerId", user_id AS "userId", access_token AS "accessToken", refresh_token AS "refreshToken", id_token AS "idToken", access_token_expires_at AS "accessTokenExpiresAt", refresh_token_expires_at AS "refreshTokenExpiresAt", scope, password_hash AS "passwordHash", created_at AS "createdAt", updated_at AS "updatedAt"`

const verificationColumns =
  `id, identifier, value_hash AS "valueHash", payload, expires_at AS "expiresAt", created_at AS "createdAt", updated_at AS "updatedAt"`

const sessionJoinColumns =
  `s.id AS "s_id", s.token_hash AS "s_tokenHash", s.user_id AS "s_userId", s.expires_at AS "s_expiresAt", s.ip_address AS "s_ipAddress", s.user_agent AS "s_userAgent", s.created_at AS "s_createdAt", s.updated_at AS "s_updatedAt"`

// -----------------------------------------------------------------------------
// User columns, derived from the model
// -----------------------------------------------------------------------------

/**
 * One stored column of the user model.
 *
 * **Details**
 *
 * `field` is what the model calls it, `column` is what the database calls it,
 * and `boolean` is whether the stored value is one — the single dialect-sensitive
 * property a column has here, and the reason it is read off the schema rather
 * than off a hard-coded list of names.
 */
interface UserColumn {
  readonly field: string
  readonly column: string
  readonly boolean: boolean
}

/**
 * Whether a field's *stored* form is a boolean.
 *
 * **Gotchas**
 *
 * The encoded side is what matters: `Schema.DateTimeUtcFromString` decodes to a
 * `DateTime` and stores a string, and a `Schema.Literals` of strings stores one
 * too. A nullable boolean is a union, so its members are looked at as well.
 */
const storesBoolean = (schema: Schema.Top): boolean => {
  const ast = SchemaAST.toEncoded(schema.ast)
  return SchemaAST.isBoolean(ast) ||
    (SchemaAST.isUnion(ast) && ast.types.some((member) => SchemaAST.isBoolean(member)))
}

const userColumnsOf = (fields: { readonly [key: string]: Schema.Top }): ReadonlyArray<UserColumn> =>
  Object.entries(fields).map(([field, schema]) => ({
    field,
    column: camelToSnake(field),
    boolean: storesBoolean(schema)
  }))

/** `id, email_verified AS "emailVerified", …` — the projection of a plain read. */
const projectionOf = (columns: ReadonlyArray<UserColumn>): string =>
  columns.map(({ column, field }) => column === field ? column : `${column} AS "${field}"`).join(", ")

/** `u.email_verified AS "u_emailVerified", …` — the projection of the joined read. */
const joinedProjectionOf = (columns: ReadonlyArray<UserColumn>, alias: string, prefix: string): string =>
  columns.map(({ column, field }) => `${alias}.${column} AS "${prefix}${field}"`).join(", ")

interface RawCountRow {
  readonly count: unknown
}

interface RawIdRow {
  readonly id: unknown
}

// -----------------------------------------------------------------------------
// Request schemas
// -----------------------------------------------------------------------------

const IsoString = Schema.DateTimeUtcFromString

const SessionListRequest = Schema.Struct({ userId: Schema.String, now: IsoString })

const SessionTouchRequest = Schema.Struct({
  id: Schema.String,
  expiresAt: IsoString,
  updatedAt: IsoString
})

const IssuerAccountRequest = Schema.Struct({ issuer: Schema.String, accountId: Schema.String })

const UserProviderRequest = Schema.Struct({ userId: Schema.String, providerId: Schema.String })

const ConsumeRequest = Schema.Struct({
  identifier: Schema.String,
  valueHash: Schema.String,
  now: IsoString
})

const NowRequest = Schema.Struct({ now: IsoString })

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/**
 * Classifies a driver failure for the domain, which acts on exactly one
 * distinction: a lost race to create a row.
 */
const kindOf = (cause: unknown): PersistenceFailureKind =>
  SqlError.isSqlError(cause) && cause.reason._tag === "UniqueViolation" ? "UniqueViolation" : "Unknown"

const fail = (operation: string) => (cause: unknown) =>
  new PersistenceError({ operation, kind: kindOf(cause), cause })

const persist =
  (operation: string) =>
  <A, E, R>(effect: Effect.Effect<A, E, R>): Effect.Effect<A, PersistenceError, R> =>
    Effect.mapError(effect, fail(operation))

const decodeAccount = Schema.decodeUnknownEffect(Account)

/**
 * The one row an `UPDATE … RETURNING` produced, decoded — or `None` when the
 * statement matched nothing, which every caller reads as "no such row".
 */
const decodeFirst =
  <A, E, R>(decode: (row: unknown) => Effect.Effect<A, E, R>) =>
  (rows: ReadonlyArray<unknown>): Effect.Effect<Option.Option<A>, E, R> =>
    Option.match(Array.head(rows), {
      onNone: () => Effect.succeedNone,
      onSome: (row) => Effect.asSome(decode(row))
    })

const firstAccount = decodeFirst(decodeAccount)

/**
 * SQLite has no boolean type: `users.email_verified` is an integer flag there
 * and a real boolean on PostgreSQL. These two adapters are the only dialect
 * divergence in the store implementations.
 */
const booleanCodec = (sql: SqlClient.SqlClient) => ({
  encode: sql.onDialectOrElse({
    orElse: () => (value: boolean): boolean | number => value,
    sqlite: () => (value: boolean): boolean | number => value ? 1 : 0
  }),
  decode: sql.onDialectOrElse({
    orElse: () => (value: unknown): unknown => value,
    sqlite: () => (value: unknown): unknown => value === 1 || value === true
  })
})

/**
 * Reads the user half out of a result row: the columns the model declares,
 * un-prefixed, with the boolean ones brought back from whatever the dialect
 * stores them as.
 */
const userReaderOf = (
  columns: ReadonlyArray<UserColumn>,
  decodeBoolean: (value: unknown) => unknown
) =>
(row: UserRow, prefix: string): UserRow => {
  const user: Record<string, unknown> = Object.create(null)
  for (const { boolean, field } of columns) {
    const value = row[`${prefix}${field}`]
    user[field] = boolean ? decodeBoolean(value) : value
  }
  return user
}

/**
 * Turns an encoded model row into the columns a statement writes: `camelCase`
 * becomes `snake_case`, and a boolean becomes whatever this dialect stores one
 * as.
 */
const columnWriterOf = (
  columns: ReadonlyArray<UserColumn>,
  encodeBoolean: (value: boolean) => boolean | number
) => {
  const byField = new Map(columns.map((column) => [column.field, column]))
  return (row: UserRow): Record<string, unknown> => {
    const record: Record<string, unknown> = Object.create(null)
    for (const [field, value] of Object.entries(row)) {
      const column = byField.get(field)
      record[column?.column ?? camelToSnake(field)] =
        column?.boolean === true && Predicate.isBoolean(value) ? encodeBoolean(value) : value
    }
    return record
  }
}

const countRows = (rows: ReadonlyArray<RawCountRow>): number => rows.length === 0 ? 0 : Number(rows[0]!.count)

const encodeExpiry = (value: DateTime.Utc | null | undefined): string | null =>
  value === null || value === undefined ? null : DateTime.formatIso(value)

// -----------------------------------------------------------------------------
// UserStore
// -----------------------------------------------------------------------------

const makeUserStore: <F extends UserFields>(
  model: UserModel<F>
) => Effect.Effect<UserStoreService<F>, never, SqlClient.SqlClient> = Effect.fnUntraced(
  function*<F extends UserFields>(model: UserModel<F>) {
    const sql = yield* SqlClient.SqlClient
    const columns = userColumnsOf(model.selectFields)
    const userCols = sql.literal(projectionOf(columns))
    const boolean = booleanCodec(sql)
    const readUser = userReaderOf(columns, boolean.decode)
    const toColumns = columnWriterOf(columns, boolean.encode)

    const encodeInsert = Schema.encodeUnknownEffect(model.rows.insert)
    const encodePatch = Schema.encodeUnknownEffect(model.rows.patch)

    /** A decoding failure means the columns and the model have drifted apart. */
    const decoded = (operation: string, row: UserRow): Effect.Effect<UserOf<F>, PersistenceError> =>
      Effect.mapError(
        model.decodeRow(readUser(row, "")),
        (cause) => new PersistenceError({ operation, cause })
      )

    const one = (operation: string) => (rows: ReadonlyArray<UserRow>): Effect.Effect<UserOf<F>, PersistenceError> =>
      Option.match(Array.head(rows), {
        onNone: () =>
          Effect.fail(
            new PersistenceError({ operation, cause: "the statement returned no row" })
          ),
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
        Effect.gen(function*() {
          // A caller holding the base-typed key builds rows out of base fields
          // alone; the model's own defaults are what makes such a row storable.
          const complete = yield* model.completeInsert(user)
          const encoded = yield* Effect.orDie(encodeInsert(complete))
          const rows = yield* persist("UserStore.create")(
            sql<UserRow>`INSERT INTO users ${sql.insert(toColumns(encoded))} RETURNING ${userCols}`
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
        Effect.gen(function*() {
          const now = yield* DateTime.now
          // The patch is already typed by the model, so an encoding failure here
          // is a bug rather than something a caller can act on.
          const encoded = yield* Effect.orDie(encodePatch(patch))
          const set = omitUndefined({ ...toColumns(encoded), updated_at: DateTime.formatIso(now) })
          const rows = yield* persist("UserStore.update")(
            sql<UserRow>`UPDATE users SET ${sql.update(set)} WHERE id = ${id} RETURNING ${userCols}`
          )
          return yield* first("UserStore.update")(rows)
        }),

      delete: (id) =>
        persist("UserStore.delete")(
          Effect.map(sql<RawIdRow>`DELETE FROM users WHERE id = ${id} RETURNING id`, (rows) => rows.length > 0)
        )
    })
  }
)

// -----------------------------------------------------------------------------
// SessionStore
// -----------------------------------------------------------------------------

const makeSessionStore: <F extends UserFields>(
  model: UserModel<F>
) => Effect.Effect<SessionStoreService<F>, never, SqlClient.SqlClient> = Effect.fnUntraced(
  function*<F extends UserFields>(model: UserModel<F>) {
    const sql = yield* SqlClient.SqlClient
    const sessionCols = sql.literal(sessionColumns)
    const columns = userColumnsOf(model.selectFields)
    const sessionWithUserCols = sql.literal(
      `${sessionJoinColumns}, ${joinedProjectionOf(columns, "u", "u_")}`
    )
    const decodeBoolean = booleanCodec(sql).decode
    const readUser = userReaderOf(columns, decodeBoolean)

    const decodeSession = Schema.decodeUnknownEffect(Session)

    const sessionFromRow = (row: UserRow) => ({
      id: row["s_id"],
      tokenHash: row["s_tokenHash"],
      userId: row["s_userId"],
      expiresAt: row["s_expiresAt"],
      ipAddress: row["s_ipAddress"],
      userAgent: row["s_userAgent"],
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
        (cause) => new PersistenceError({ operation: "SessionStore.findByTokenHash", cause })
      )

    const insertSession = SqlSchema.findOne({
      Request: Session.insert,
      Result: Session,
      execute: (row) =>
        sql`INSERT INTO sessions (id, token_hash, user_id, expires_at, ip_address, user_agent, created_at, updated_at)
        VALUES (${row.id}, ${row.tokenHash}, ${row.userId}, ${row.expiresAt}, ${row.ipAddress}, ${row.userAgent}, ${row.createdAt}, ${row.updatedAt})
        RETURNING ${sessionCols}`
    })

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

    const touchSession = SqlSchema.findOneOption({
      Request: SessionTouchRequest,
      Result: Session,
      execute: (row) =>
        sql`UPDATE sessions SET expires_at = ${row.expiresAt}, updated_at = ${row.updatedAt}
        WHERE id = ${row.id}
        RETURNING ${sessionCols}`
    })

    const listSessions = SqlSchema.findAll({
      Request: SessionListRequest,
      Result: Session,
      execute: (row) =>
        sql`SELECT ${sessionCols} FROM sessions
        WHERE user_id = ${row.userId} AND expires_at > ${row.now}
        ORDER BY created_at DESC, id DESC`
    })

    return sessionStoreOf(model).of({
      create: (session) => persist("SessionStore.create")(insertSession(session)),

      findByTokenHash: (tokenHash) => selectSessionWithUser(tokenHash),

      touch: (id, expiresAt) =>
        persist("SessionStore.touch")(Effect.flatMap(
          DateTime.now,
          (now) => touchSession({ id, expiresAt, updatedAt: now })
        )),

      deleteById: (id, userId) =>
        persist("SessionStore.deleteById")(
          Effect.map(
            sql<RawIdRow>`DELETE FROM sessions WHERE id = ${id} AND user_id = ${userId} RETURNING id`,
            (rows) => rows.length > 0
          )
        ),

      deleteByUserId: (userId) =>
        persist("SessionStore.deleteByUserId")(
          Effect.map(
            sql<RawIdRow>`DELETE FROM sessions WHERE user_id = ${userId} RETURNING id`,
            (rows) => rows.length
          )
        ),

      deleteByUserIdExcept: (userId, sessionId) =>
        persist("SessionStore.deleteByUserIdExcept")(
          Effect.map(
            sql<RawIdRow>`DELETE FROM sessions WHERE user_id = ${userId} AND id <> ${sessionId} RETURNING id`,
            (rows) => rows.length
          )
        ),

      listByUserId: (userId) =>
        persist("SessionStore.listByUserId")(Effect.flatMap(
          DateTime.now,
          (now) => listSessions({ userId, now })
        )),

      deleteExpired: persist("SessionStore.deleteExpired")(Effect.flatMap(
        DateTime.now,
        (now) =>
          Effect.map(
            sql<RawIdRow>`DELETE FROM sessions WHERE expires_at <= ${DateTime.formatIso(now)} RETURNING id`,
            (rows) => rows.length
          )
      ))
    })
  }
)

// -----------------------------------------------------------------------------
// AccountStore
// -----------------------------------------------------------------------------

const makeAccountStore: () => Effect.Effect<AccountStoreService, never, SqlClient.SqlClient> = Effect
  .fnUntraced(function*() {
    const sql = yield* SqlClient.SqlClient
    const accountCols = sql.literal(accountColumns)

    const insertAccount = SqlSchema.findOne({
      Request: Account.insert,
      Result: Account,
      execute: (row) =>
        sql`INSERT INTO accounts (
          id, issuer, account_id, provider_id, user_id,
          access_token, refresh_token, id_token,
          access_token_expires_at, refresh_token_expires_at,
          scope, password_hash, created_at, updated_at
        ) VALUES (
          ${row.id}, ${row.issuer}, ${row.accountId}, ${row.providerId}, ${row.userId},
          ${row.accessToken}, ${row.refreshToken}, ${row.idToken},
          ${row.accessTokenExpiresAt}, ${row.refreshTokenExpiresAt},
          ${row.scope}, ${row.passwordHash}, ${row.createdAt}, ${row.updatedAt}
        ) RETURNING ${accountCols}`
    })

    const selectAccountByIssuer = SqlSchema.findOneOption({
      Request: IssuerAccountRequest,
      Result: Account,
      execute: (row) =>
        sql`SELECT ${accountCols} FROM accounts
        WHERE issuer = ${row.issuer} AND account_id = ${row.accountId}`
    })

    const selectAccountByProvider = SqlSchema.findOneOption({
      Request: UserProviderRequest,
      Result: Account,
      execute: (row) =>
        sql`SELECT ${accountCols} FROM accounts
        WHERE user_id = ${row.userId} AND provider_id = ${row.providerId}`
    })

    const listAccounts = SqlSchema.findAll({
      Request: Schema.String,
      Result: Account,
      execute: (userId) =>
        sql`SELECT ${accountCols} FROM accounts WHERE user_id = ${userId} ORDER BY created_at ASC, id ASC`
    })

    /**
     * `FOR UPDATE` on the dialects that have it. SQLite serializes writers
     * already, so the plain read is the same guarantee there.
     */
    const lockClause = sql.onDialectOrElse({
      orElse: () => sql.literal(" FOR UPDATE"),
      sqlite: () => sql.literal("")
    })

    const listAccountsForUpdate = SqlSchema.findAll({
      Request: Schema.String,
      Result: Account,
      execute: (userId) =>
        sql`SELECT ${accountCols} FROM accounts WHERE user_id = ${userId} ORDER BY created_at ASC, id ASC${lockClause}`
    })

    const updateAccountRow = (operation: string, id: AccountId, set: Record<string, unknown>) =>
      persist(operation)(Effect.gen(function*() {
        const rows = yield* sql`UPDATE accounts SET ${sql.update(set)} WHERE id = ${id} RETURNING ${accountCols}`
        return yield* firstAccount(rows)
      }))

    return AccountStore.of({
      create: (account) => persist("AccountStore.create")(insertAccount(account)),

      findByIssuerAccountId: (issuer, accountId) =>
        persist("AccountStore.findByIssuerAccountId")(selectAccountByIssuer({ issuer, accountId })),

      findByUserIdAndProviderId: (userId, providerId) =>
        persist("AccountStore.findByUserIdAndProviderId")(selectAccountByProvider({ userId, providerId })),

      listByUserId: (userId) => persist("AccountStore.listByUserId")(listAccounts(userId)),

      listByUserIdForUpdate: (userId) =>
        persist("AccountStore.listByUserIdForUpdate")(listAccountsForUpdate(userId)),

      updateTokens: (id, tokens: AccountTokens) =>
        Effect.flatMap(DateTime.now, (now) =>
          updateAccountRow(
            "AccountStore.updateTokens",
            id,
            omitUndefined({
              access_token: tokens.accessToken,
              refresh_token: tokens.refreshToken,
              id_token: tokens.idToken,
              access_token_expires_at: tokens.accessTokenExpiresAt === undefined
                ? undefined
                : encodeExpiry(tokens.accessTokenExpiresAt),
              refresh_token_expires_at: tokens.refreshTokenExpiresAt === undefined
                ? undefined
                : encodeExpiry(tokens.refreshTokenExpiresAt),
              scope: tokens.scope,
              updated_at: DateTime.formatIso(now)
            })
          )),

      updatePasswordHash: (userId, passwordHash) =>
        persist("AccountStore.updatePasswordHash")(Effect.gen(function*() {
          const now = yield* DateTime.now
          const rows = yield* sql`UPDATE accounts
          SET password_hash = ${passwordHash}, updated_at = ${DateTime.formatIso(now)}
          WHERE user_id = ${userId} AND issuer = ${CredentialIssuer}
          RETURNING ${accountCols}`
          return yield* firstAccount(rows)
        })),

      deleteById: (id, userId) =>
        persist("AccountStore.deleteById")(
          Effect.map(
            sql<RawIdRow>`DELETE FROM accounts WHERE id = ${id} AND user_id = ${userId} RETURNING id`,
            (rows) => rows.length > 0
          )
        ),

      deleteByUserId: (userId) =>
        persist("AccountStore.deleteByUserId")(
          Effect.map(
            sql<RawIdRow>`DELETE FROM accounts WHERE user_id = ${userId} RETURNING id`,
            (rows) => rows.length
          )
        ),

      countByUserId: (userId) =>
        persist("AccountStore.countByUserId")(
          Effect.map(
            sql<RawCountRow>`SELECT COUNT(*) AS "count" FROM accounts WHERE user_id = ${userId}`,
            countRows
          )
        )
    })
  })

// -----------------------------------------------------------------------------
// VerificationStore
// -----------------------------------------------------------------------------

const makeVerificationStore: () => Effect.Effect<VerificationStoreService, never, SqlClient.SqlClient> = Effect
  .fnUntraced(function*() {
    const sql = yield* SqlClient.SqlClient
    const verificationCols = sql.literal(verificationColumns)

    const insertVerification = SqlSchema.findOne({
      Request: Verification.insert,
      Result: Verification,
      execute: (row) =>
        sql`INSERT INTO verifications (id, identifier, value_hash, payload, expires_at, created_at, updated_at)
        VALUES (${row.id}, ${row.identifier}, ${row.valueHash}, ${row.payload}, ${row.expiresAt}, ${row.createdAt}, ${row.updatedAt})
        RETURNING ${verificationCols}`
    })

    /**
     * The whole race-safety story: one statement claims the row, guarded by the
     * expiry, and hands it to exactly one caller.
     */
    const consumeVerification = SqlSchema.findOneOption({
      Request: ConsumeRequest,
      Result: Verification,
      execute: (row) =>
        sql`DELETE FROM verifications
        WHERE identifier = ${row.identifier}
          AND value_hash = ${row.valueHash}
          AND expires_at > ${row.now}
        RETURNING ${verificationCols}`
    })

    const deleteVerificationsByIdentifier = SqlSchema.findAll({
      Request: Schema.String,
      Result: Schema.Struct({ id: Schema.String }),
      execute: (identifier) => sql`DELETE FROM verifications WHERE identifier = ${identifier} RETURNING id`
    })

    const deleteExpiredVerifications = SqlSchema.findAll({
      Request: NowRequest,
      Result: Schema.Struct({ id: Schema.String }),
      execute: (row) => sql`DELETE FROM verifications WHERE expires_at <= ${row.now} RETURNING id`
    })

    return VerificationStore.of({
      create: (verification) => persist("VerificationStore.create")(insertVerification(verification)),

      consume: (identifier, valueHash) =>
        persist("VerificationStore.consume")(Effect.flatMap(
          DateTime.now,
          (now) => consumeVerification({ identifier, valueHash, now })
        )),

      deleteByIdentifier: (identifier) =>
        persist("VerificationStore.deleteByIdentifier")(
          Effect.map(deleteVerificationsByIdentifier(identifier), (rows) => rows.length)
        ),

      deleteExpired: persist("VerificationStore.deleteExpired")(Effect.flatMap(
        DateTime.now,
        (now) => Effect.map(deleteExpiredVerifications({ now }), (rows) => rows.length)
      ))
    })
  })

// -----------------------------------------------------------------------------
// WithAuthTransaction
// -----------------------------------------------------------------------------

const makeTransaction: () => Effect.Effect<WithAuthTransactionService, never, SqlClient.SqlClient> = Effect
  .fnUntraced(function*() {
    const sql = yield* SqlClient.SqlClient
    return WithAuthTransaction.of({
      run: <A, E, R>(effect: Effect.Effect<A, E, R>): Effect.Effect<A, E | PersistenceError, R> =>
        Effect.mapError(
          sql.withTransaction(effect),
          (error): E | PersistenceError =>
            SqlError.isSqlError(error)
              ? new PersistenceError({ operation: "WithAuthTransaction.run", cause: error })
              : error
        )
    })
  })

// -----------------------------------------------------------------------------
// The layer
// -----------------------------------------------------------------------------

/**
 * Implements the whole persistence seam — `UserStore`, `SessionStore`,
 * `AccountStore`, `VerificationStore` and `WithAuthTransaction` — over an
 * ambient `SqlClient`, for the user model given.
 *
 * **Details**
 *
 * One layer per store, merged. Each of them takes the same `SqlClient` — which
 * its own layer memoizes, so this is one client and five sets of prepared
 * statements, not five clients — and a deployment that wants to replace exactly
 * one store can merge its own over this.
 *
 * The user store's columns are read off `model` once, when the layer is built:
 * the projection, the `INSERT` and the `UPDATE` are all derived from the field
 * map, so a deployment's own columns are stored and read back without a line of
 * SQL being written for them. The two stores are published under the plain
 * `UserStore` / `SessionStore` keys, so this layer's type is the same whatever
 * the model is.
 *
 * **When to use**
 *
 * Provide it below `Auth.layer` together with a driver layer (`PgClient.layer`,
 * `PgliteClient.layer`, a SQLite client, …). The tables it reads are created by
 * `Migrations.layerFor(model)` or by the application's own migrator.
 *
 * **Example**
 *
 * ```ts skip-type-checking
 * const StoresLive = SqlStores.layerFor(model).pipe(
 *   Layer.provideMerge(Migrations.layerFor(model)),
 *   Layer.provide(PgLive)
 * )
 * ```
 *
 * @category layers
 * @since 1.0.0
 */
export const layerFor = <F extends UserFields>(
  model: UserModel<F>
): Layer.Layer<AuthStores, never, SqlClient.SqlClient> =>
  Layer.mergeAll(
    Layer.effect(userStoreOf(model), makeUserStore(model)),
    Layer.effect(sessionStoreOf(model), makeSessionStore(model)),
    Layer.effect(AccountStore, makeAccountStore()),
    Layer.effect(VerificationStore, makeVerificationStore()),
    Layer.effect(WithAuthTransaction, makeTransaction())
  )

/**
 * {@link layerFor}, for a deployment that added no user fields of its own.
 *
 * @category layers
 * @since 1.0.0
 */
export const layer: Layer.Layer<AuthStores, never, SqlClient.SqlClient> = layerFor(baseUserModel)
