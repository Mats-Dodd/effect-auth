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
import { SqlClient, SqlSchema } from "effect/unstable/sql"
import { AuthConfig } from "../../config/AuthConfig.js"
import { omitUndefined } from "../../internal/records.js"
import { make as makeProviderTokenCipher } from "../../internal/providerTokenCipher.js"
import type { ProviderTokenCipher, ProviderTokenField } from "../../internal/providerTokenCipher.js"
import type { AccountStoreService, AccountTokens } from "../../domain/Stores.js"
import { AccountStore, PersistenceError } from "../../domain/Stores.js"
import type { AccountId } from "../../domain/Schema.js"
import { Account, CredentialIssuer } from "../../domain/Schema.js"
import { persist, type RawCountRow, type RawIdRow } from "./internal.js"

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
      persist(operation)(
        Effect.gen(function* () {
          const rows = yield* sql`UPDATE accounts SET ${sql.update(set)} WHERE id = ${id} RETURNING ${accountCols}`
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
            id,
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
        persist("AccountStore.updatePasswordHash")(
          Effect.gen(function* () {
            const now = yield* DateTime.now
            const rows = yield* sql`UPDATE accounts
          SET password_hash = ${passwordHash}, updated_at = ${DateTime.formatIso(now)}
          WHERE user_id = ${userId} AND issuer = ${CredentialIssuer}
          RETURNING ${accountCols}`
            return yield* Effect.flatMap(firstAccount(rows), (value) =>
              decryptOption("AccountStore.updatePasswordHash", value)
            )
          })
        ),

      deleteById: (id, userId) =>
        persist("AccountStore.deleteById")(
          Effect.map(
            sql<RawIdRow>`DELETE FROM accounts WHERE id = ${id} AND user_id = ${userId} RETURNING id`,
            (rows) => rows.length > 0
          )
        ),

      deleteByUserId: (userId) =>
        persist("AccountStore.deleteByUserId")(
          Effect.map(sql<RawIdRow>`DELETE FROM accounts WHERE user_id = ${userId} RETURNING id`, (rows) => rows.length)
        ),

      countByUserId: (userId) =>
        persist("AccountStore.countByUserId")(
          Effect.map(sql<RawCountRow>`SELECT COUNT(*) AS "count" FROM accounts WHERE user_id = ${userId}`, countRows)
        )
    })
  }
)
