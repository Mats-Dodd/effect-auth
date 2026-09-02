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
 * - OAuth access, refresh and ID tokens are encrypted with AES-256-GCM before
 *   they reach SQL. The account id and token kind are associated data, so a
 *   ciphertext cannot be moved between rows or columns.
 *
 * **Gotchas**
 *
 * Every failure — a driver error, a decoding error, an unexpectedly missing
 * `RETURNING` row — is reported as {@link PersistenceError}, with `kind` set to
 * `"UniqueViolation"` where the driver said so, which is the one distinction
 * the domain acts on. The underlying `SqlError` is kept in `cause` for logs;
 * nothing above the seam inspects it.
 *
 * @since 0.1.0
 */
import { Layer } from "effect"
import type { SqlClient } from "effect/unstable/sql"
import type { AuthConfig } from "../config/AuthConfig.js"
import type { AuthStores } from "../domain/Stores.js"
import { AccountStore, sessionStoreOf, userStoreOf, VerificationStore, WithAuthTransaction } from "../domain/Stores.js"
import type { UserFields, UserModel } from "../domain/Schema.js"
import { baseUserModel } from "../domain/Schema.js"
import * as Accounts from "./stores/Accounts.js"
import * as internal from "./stores/internal.js"
import * as Sessions from "./stores/Sessions.js"
import * as Transaction from "./stores/Transaction.js"
import * as Users from "./stores/Users.js"
import * as Verifications from "./stores/Verifications.js"

/**
 * Reads SQLite's integer flag back as a boolean, leaving an absent value
 * absent.
 *
 * **Gotchas**
 *
 * `null` and `undefined` pass through untouched. A custom field may be
 * `NullOr(Schema.Boolean)` — a nullable flag whose column is nullable on both
 * dialects — and turning its `null` into `false` would be a silent rewrite of
 * "not asked yet" into "declined" on every read, which the model would accept
 * because `false` decodes just as well.
 *
 * @category combinators
 * @since 0.1.0
 */
export const decodeSqliteBoolean: (value: unknown) => unknown = internal.decodeSqliteBoolean

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
 * @since 0.1.0
 */
export const layerFor = <F extends UserFields>(
  model: UserModel<F>
): Layer.Layer<AuthStores, never, SqlClient.SqlClient | AuthConfig> =>
  Layer.mergeAll(
    Layer.effect(userStoreOf(model), Users.make(model)),
    Layer.effect(sessionStoreOf(model), Sessions.make(model)),
    Layer.effect(AccountStore, Accounts.make),
    Layer.effect(VerificationStore, Verifications.make),
    Layer.effect(WithAuthTransaction, Transaction.make)
  )

/**
 * {@link layerFor}, for a deployment that added no user fields of its own.
 *
 * @category layers
 * @since 0.1.0
 */
export const layer: Layer.Layer<AuthStores, never, SqlClient.SqlClient | AuthConfig> = layerFor(baseUserModel)
