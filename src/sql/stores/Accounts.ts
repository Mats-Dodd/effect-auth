/**
 * The SQL `AccountStore`.
 *
 * **Details**
 *
 * OAuth access, refresh and ID tokens are encrypted with AES-256-GCM before
 * they reach SQL. The account id and token kind are associated data, so a
 * ciphertext cannot be moved between rows or columns.
 *
 * Not exported from the package: `SqlStores.layerFor` is the public door.
 *
 * @internal
 */
import { Array, DateTime, Effect, Option, Schema } from "effect"
import type { Statement } from "effect/unstable/sql"
import { SqlClient, SqlSchema } from "effect/unstable/sql"
import { AuthConfig } from "../../config/AuthConfig.js"
import { omitUndefined } from "../../internal/records.js"
import { make as makeProviderTokenCipher } from "../../internal/providerTokenCipher.js"
import type { ProviderTokenCipher, ProviderTokenField } from "../../internal/providerTokenCipher.js"
import type { AccountStoreService, AccountTokens } from "../../domain/Stores.js"
import { AccountStore, PersistenceError } from "../../domain/Stores.js"
import type { AccountId } from "../../domain/Schema.js"
import { Account, CredentialIssuer } from "../../domain/Schema.js"
import { dialectOf, identifier, lockClause } from "../Dialect.js"
import { deleteAndCount, insertAndRead, updateAndRead } from "../Mutations.js"
import { persist, type RawCountRow } from "./internal.js"

// -----------------------------------------------------------------------------
// The table
// -----------------------------------------------------------------------------

const accountsTable = "accounts"

/** The primary key: how a mutation helper names a row again on MySQL. */
const accountKey: ReadonlyArray<string> = ["id"]

// -----------------------------------------------------------------------------
// Column projections
// -----------------------------------------------------------------------------

const accountColumns = `id, issuer, account_id AS "accountId", provider_id AS "providerId", user_id AS "userId", access_token AS "accessToken", refresh_token AS "refreshToken", id_token AS "idToken", access_token_expires_at AS "accessTokenExpiresAt", refresh_token_expires_at AS "refreshTokenExpiresAt", scope, password_hash AS "passwordHash", created_at AS "createdAt", updated_at AS "updatedAt"`

// -----------------------------------------------------------------------------
// Request schemas
// -----------------------------------------------------------------------------

const IssuerAccountRequest = Schema.Struct({ issuer: Schema.String, accountId: Schema.String })

const UserProviderRequest = Schema.Struct({ userId: Schema.String, providerId: Schema.String })

const IdUserRequest = Schema.Struct({ id: Schema.String, userId: Schema.String })

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

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

const countRows = (rows: ReadonlyArray<RawCountRow>): number => (rows.length === 0 ? 0 : Number(rows[0]!.count))

const encodeExpiry = (value: DateTime.Utc | null | undefined): string | null =>
  value === null || value === undefined ? null : DateTime.formatIso(value)

/** @internal */
export const make: Effect.Effect<AccountStoreService, never, SqlClient.SqlClient | AuthConfig> = Effect.gen(
  function* () {
    const sql = yield* SqlClient.SqlClient
    const dialect = yield* dialectOf(sql)
    const config = yield* AuthConfig
    const cipher = yield* makeProviderTokenCipher(config.secret)
    const accountCols = sql.literal(accountColumns)

    const providerFields = ["access_token", "refresh_token", "id_token"] as const
    // A total map rather than a `switch`: exhaustiveness is checked by the
    // `satisfies`, and there is no unreachable fall-through to account for.
    const modelFields = {
      access_token: "accessToken",
      refresh_token: "refreshToken",
      id_token: "idToken"
    } as const satisfies Record<ProviderTokenField, "accessToken" | "refreshToken" | "idToken">
    const modelField = (field: ProviderTokenField): "accessToken" | "refreshToken" | "idToken" => modelFields[field]
    const cryptoFailure = (operation: string) => (cause: unknown) => PersistenceError.make({ operation, cause })
    const protect = <A>(operation: string, effect: Effect.Effect<A>): Effect.Effect<A, PersistenceError> =>
      effect.pipe(Effect.catchDefect((cause) => Effect.fail(cryptoFailure(operation)(cause))))
    const transformTokens = <
      A extends {
        readonly id: string
        readonly accessToken: string | null
        readonly refreshToken: string | null
        readonly idToken: string | null
      }
    >(
      account: A,
      transform: ProviderTokenCipher["encrypt"] | ProviderTokenCipher["decrypt"]
    ): Effect.Effect<A> =>
      Effect.gen(function* () {
        const patch: Partial<Record<"accessToken" | "refreshToken" | "idToken", string | null>> = {}
        for (const field of providerFields) {
          const property = modelField(field)
          const value = account[property]
          patch[property] = value === null ? null : yield* transform(account.id, field, value)
        }
        return { ...account, ...patch }
      })
    const encryptAccount = <A extends Parameters<typeof transformTokens>[0]>(account: A) =>
      transformTokens(account, cipher.encrypt)
    const decryptAccount = (account: Account) => transformTokens(account, cipher.decrypt)
    const decryptOption = (operation: string, value: Option.Option<Account>) =>
      Option.isNone(value)
        ? Effect.succeedNone
        : Effect.map(protect(operation, decryptAccount(value.value)), Option.some)
    const decryptAll = (operation: string, values: ReadonlyArray<Account>) =>
      protect(operation, Effect.forEach(values, decryptAccount))

    const encryptPatch = (id: AccountId, tokens: AccountTokens) =>
      protect(
        "AccountStore.updateTokens",
        Effect.gen(function* () {
          return {
            ...tokens,
            ...(tokens.accessToken === undefined || tokens.accessToken === null
              ? {}
              : { accessToken: yield* cipher.encrypt(id, "access_token", tokens.accessToken) }),
            ...(tokens.refreshToken === undefined || tokens.refreshToken === null
              ? {}
              : { refreshToken: yield* cipher.encrypt(id, "refresh_token", tokens.refreshToken) }),
            ...(tokens.idToken === undefined || tokens.idToken === null
              ? {}
              : { idToken: yield* cipher.encrypt(id, "id_token", tokens.idToken) })
          } satisfies AccountTokens
        })
      )

    const insertAccount = SqlSchema.findOne({
      Request: Account.insert,
      Result: Account,
      execute: (row) =>
        insertAndRead({
          sql,
          dialect,
          table: accountsTable,
          key: accountKey,
          columns: accountCols,
          record: {
            id: row.id,
            issuer: row.issuer,
            account_id: row.accountId,
            provider_id: row.providerId,
            user_id: row.userId,
            access_token: row.accessToken,
            refresh_token: row.refreshToken,
            id_token: row.idToken,
            access_token_expires_at: row.accessTokenExpiresAt,
            refresh_token_expires_at: row.refreshTokenExpiresAt,
            scope: row.scope,
            password_hash: row.passwordHash,
            created_at: row.createdAt,
            updated_at: row.updatedAt
          }
        })
    })

    const selectAccountByIssuer = SqlSchema.findOneOption({
      Request: IssuerAccountRequest,
      Result: Account,
      execute: (row) =>
        sql`SELECT ${accountCols} FROM accounts
        WHERE issuer = ${row.issuer} AND account_id = ${row.accountId}`
    })

    const selectAccountByIdAndUser = SqlSchema.findOneOption({
      Request: IdUserRequest,
      Result: Account,
      execute: (row) =>
        sql`SELECT ${accountCols} FROM accounts
        WHERE id = ${row.id} AND user_id = ${row.userId}`
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
     * `FOR UPDATE` on the dialects that have it, empty on SQLite — which
     * serialises its writers already, so the plain read is the same guarantee
     * there. This is the reclaim lock: `Accounts.unlink`'s last-method guard is
     * only sound while two transactions cannot both read the same user's
     * accounts and both believe they were alone.
     */
    const lock = lockClause(sql, dialect)

    const listAccountsForUpdate = SqlSchema.findAll({
      Request: Schema.String,
      Result: Account,
      execute: (userId) =>
        sql`SELECT ${accountCols} FROM accounts WHERE user_id = ${userId} ORDER BY created_at ASC, id ASC${lock}`
    })

    /** The rows matching `where`, deleted, counted. */
    const deleteAccounts = (operation: string, where: Statement.Fragment): Effect.Effect<number, PersistenceError> =>
      persist(operation)(deleteAndCount({ sql, dialect, table: accountsTable, key: accountKey, where }))

    /** One account, updated and read back — `None` when the predicate matched nothing. */
    const updateAccountRow = (operation: string, where: Statement.Fragment, set: Record<string, unknown>) =>
      persist(operation)(
        Effect.gen(function* () {
          const rows = yield* updateAndRead({
            sql,
            dialect,
            table: accountsTable,
            key: accountKey,
            columns: accountCols,
            set,
            where
          })
          return yield* firstAccount(rows)
        })
      )

    return AccountStore.of({
      create: (account) =>
        Effect.gen(function* () {
          const encrypted = yield* protect("AccountStore.create", encryptAccount(account))
          const stored = yield* persist("AccountStore.create")(insertAccount(encrypted))
          return yield* protect("AccountStore.create", decryptAccount(stored))
        }),

      findByIssuerAccountId: (issuer, accountId) =>
        Effect.flatMap(
          persist("AccountStore.findByIssuerAccountId")(selectAccountByIssuer({ issuer, accountId })),
          (value) => decryptOption("AccountStore.findByIssuerAccountId", value)
        ),

      findByIdAndUserId: (id, userId) =>
        Effect.flatMap(persist("AccountStore.findByIdAndUserId")(selectAccountByIdAndUser({ id, userId })), (value) =>
          decryptOption("AccountStore.findByIdAndUserId", value)
        ),

      findByUserIdAndProviderId: (userId, providerId) =>
        Effect.flatMap(
          persist("AccountStore.findByUserIdAndProviderId")(selectAccountByProvider({ userId, providerId })),
          (value) => decryptOption("AccountStore.findByUserIdAndProviderId", value)
        ),

      listByUserId: (userId) =>
        Effect.flatMap(persist("AccountStore.listByUserId")(listAccounts(userId)), (values) =>
          decryptAll("AccountStore.listByUserId", values)
        ),

      listByUserIdForUpdate: (userId) =>
        Effect.flatMap(persist("AccountStore.listByUserIdForUpdate")(listAccountsForUpdate(userId)), (values) =>
          decryptAll("AccountStore.listByUserIdForUpdate", values)
        ),

      updateTokens: (id, tokens: AccountTokens) =>
        Effect.gen(function* () {
          const now = yield* DateTime.now
          const encrypted = yield* encryptPatch(id, tokens)
          const updated = yield* updateAccountRow(
            "AccountStore.updateTokens",
            sql`id = ${id}`,
            omitUndefined({
              access_token: encrypted.accessToken,
              refresh_token: encrypted.refreshToken,
              id_token: encrypted.idToken,
              access_token_expires_at:
                encrypted.accessTokenExpiresAt === undefined ? undefined : encodeExpiry(encrypted.accessTokenExpiresAt),
              refresh_token_expires_at:
                encrypted.refreshTokenExpiresAt === undefined
                  ? undefined
                  : encodeExpiry(encrypted.refreshTokenExpiresAt),
              scope: encrypted.scope,
              updated_at: DateTime.formatIso(now)
            })
          )
          return yield* decryptOption("AccountStore.updateTokens", updated)
        }),

      updatePasswordHash: (userId, passwordHash) =>
        Effect.gen(function* () {
          const now = yield* DateTime.now
          const updated = yield* updateAccountRow(
            "AccountStore.updatePasswordHash",
            sql`user_id = ${userId} AND issuer = ${CredentialIssuer}`,
            { password_hash: passwordHash, updated_at: DateTime.formatIso(now) }
          )
          return yield* decryptOption("AccountStore.updatePasswordHash", updated)
        }),

      deleteById: (id, userId) =>
        Effect.map(
          deleteAccounts("AccountStore.deleteById", sql`id = ${id} AND user_id = ${userId}`),
          (count) => count > 0
        ),

      deleteByUserId: (userId) => deleteAccounts("AccountStore.deleteByUserId", sql`user_id = ${userId}`),

      countByUserId: (userId) =>
        persist("AccountStore.countByUserId")(
          Effect.map(
            sql<RawCountRow>`SELECT COUNT(*) AS ${identifier(sql, "count")} FROM accounts WHERE user_id = ${userId}`,
            countRows
          )
        )
    })
  }
)
