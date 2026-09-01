/**
 * The parameterized deployment every test under `test/fields/` runs against.
 *
 * **Details**
 *
 * Three fields, one of each kind, chosen so that every rule the kernel enforces
 * is visible somewhere:
 *
 * - `plan` is {@link UserField.withDefault} — a client may state it at sign-up
 *   and the model fills it in when it does not, so it exercises both the
 *   defaulting path and the "custom column round-trips" path.
 * - `apiSecret` is {@link UserField.hidden} — it must be present in every
 *   database variant and absent from every JSON one, which is what keeps it out
 *   of a response body, a generated client and the cookie cache.
 * - `role` is {@link UserField.readOnly} — readable everywhere, never settable
 *   through a payload.
 *
 * `layerDatabase` and `layerStores` are module-level constants for the same
 * reason `AuthTest`'s are: `layer()` memoises by object identity, so every block
 * in this directory shares one PGlite rather than booting its own.
 *
 * @since 0.1.0
 */
import type { PgliteClient } from "@effect/sql-pglite"
import { Schema } from "effect"
import type { Layer } from "effect"
import { HttpApi } from "effect/unstable/httpapi"
import type { Migrator, SqlClient, SqlError } from "effect/unstable/sql"
import { makeUserModel, UserField } from "../../src/domain/Schema.js"
import type { AuthStores } from "../../src/domain/Stores.js"
import { makeAuthApi } from "../../src/http/AuthApi.js"
import { AuthTest } from "../../src/testing/index.js"

/**
 * The user model under test.
 */
export const model = makeUserModel({
  plan: UserField.withDefault(Schema.Literals(["free", "pro"]), () => "free" as const),
  apiSecret: UserField.hidden(Schema.NullOr(Schema.String), () => null),
  role: UserField.readOnly(Schema.Literals(["user", "admin"]), () => "user" as const)
})

/**
 * The fields of {@link model}, for the type-level assertions.
 */
export type Fields = typeof model.fields

/**
 * The API an application composes when it declares its own user fields — and
 * therefore what `AuthHandlers.layer` and `AuthClient.make` are checked against
 * here.
 */
export const FieldsApi = HttpApi.make("fields-app").addHttpApi(makeAuthApi(model))

/**
 * A fresh in-memory PGlite with the base tables *and* {@link model}'s columns.
 *
 * Memoised on the model by `AuthTest`, so every block in this directory shares
 * one database — including the ones that reach it through `AuthTest.layer`.
 */
export const layerDatabase: Layer.Layer<
  SqlClient.SqlClient | PgliteClient.PgliteClient,
  Migrator.MigrationError | SqlError.SqlError
> = AuthTest.layerDatabaseFor(model)

/**
 * The whole persistence tier of {@link model} over {@link layerDatabase}.
 */
export const layerStores: Layer.Layer<
  AuthStores | SqlClient.SqlClient | PgliteClient.PgliteClient,
  Migrator.MigrationError | SqlError.SqlError
> = AuthTest.layerStoresFor(model)
