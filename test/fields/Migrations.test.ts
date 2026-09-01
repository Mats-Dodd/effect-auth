/**
 * The columns a deployment's custom user fields need.
 *
 * **Details**
 *
 * `forUserFields` is the only part of the kernel that writes DDL, and it has to
 * get three things right: the column type each field stores as, a default that
 * lets the statement run against a table that already has rows, and idempotence,
 * because the layer runs it on every boot. A field that stores as something no
 * column can hold has to say so at migration time rather than at the first
 * insert, and that is the fourth test.
 */
import { assert, layer } from "@effect/vitest"
import { Effect, Schema } from "effect"
import { Migrator, SqlClient } from "effect/unstable/sql"
import { makeUserModel, UserField } from "../../src/domain/Schema.js"
import * as Migrations from "../../src/sql/Migrations.js"
import { testName, uniqueEmail } from "../fixtures.js"
import { layerDatabase, model } from "./model.js"

interface ColumnRow {
  readonly column_name: string
  readonly data_type: string
  readonly is_nullable: string
  readonly column_default: string | null
}

const describeUsers = Effect.gen(function*() {
  const sql = yield* SqlClient.SqlClient
  const rows = yield* sql<ColumnRow>`SELECT column_name, data_type, is_nullable, column_default
    FROM information_schema.columns
    WHERE table_name = 'users'`
  return new Map(rows.map((row) => [row.column_name, row]))
})

layer(layerDatabase)("fields/Migrations", (it) => {
  it.effect("adds a column for every custom field, typed and defaulted", () =>
    Effect.gen(function*() {
      const columns = yield* describeUsers

      const plan = columns.get("plan")
      assert.isDefined(plan)
      assert.strictEqual(plan?.data_type, "text")
      assert.strictEqual(plan?.is_nullable, "NO")
      assert.include(plan?.column_default ?? "", "'free'")

      const role = columns.get("role")
      assert.isDefined(role)
      assert.strictEqual(role?.data_type, "text")
      assert.strictEqual(role?.is_nullable, "NO")
      assert.include(role?.column_default ?? "", "'user'")

      // A nullable field keeps its column nullable, and takes no default: `null`
      // is what an absent value already means.
      const apiSecret = columns.get("api_secret")
      assert.isDefined(apiSecret)
      assert.strictEqual(apiSecret?.data_type, "text")
      assert.strictEqual(apiSecret?.is_nullable, "YES")
    }))

  it.effect("names the column in snake_case", () =>
    Effect.map(describeUsers, (columns) => {
      assert.isTrue(columns.has("api_secret"))
      assert.isFalse(columns.has("apiSecret"))
    }))

  it.effect("is idempotent", () =>
    Effect.gen(function*() {
      // The layer already ran it once; running it again must be a no-op rather
      // than a duplicate-column failure.
      yield* Migrations.forUserFields(model)
      yield* Migrations.forUserFields(model)
      const columns = yield* describeUsers
      assert.isTrue(columns.has("plan"))
    }))

  it.effect("adds a column a later model declares", () =>
    Effect.gen(function*() {
      const extended = makeUserModel({
        ...model.fields,
        seats: UserField.withDefault(Schema.Number, () => 1),
        trial: UserField.withDefault(Schema.Boolean, () => false)
      })
      yield* Migrations.forUserFields(extended)

      const columns = yield* describeUsers
      assert.strictEqual(columns.get("seats")?.data_type, "double precision")
      assert.include(columns.get("seats")?.column_default ?? "", "1")
      assert.strictEqual(columns.get("trial")?.data_type, "boolean")
      assert.include(columns.get("trial")?.column_default ?? "", "false")
    }))

  it.effect("refuses a field no column can hold", () =>
    Effect.gen(function*() {
      const unstorable = makeUserModel({
        preferences: UserField.hidden(
          Schema.Struct({ theme: Schema.String }),
          () => ({ theme: "dark" })
        )
      })
      const result = yield* Effect.result(Migrations.forUserFields(unstorable))
      assert.isTrue(result._tag === "Failure")
      if (result._tag === "Failure") {
        assert.isTrue(result.failure instanceof Migrator.MigrationError)
        assert.include(String(result.failure), "preferences")
      }
    }))

  it.effect("refuses a table name that is not an identifier", () =>
    Effect.gen(function*() {
      const result = yield* Effect.result(
        Migrations.forUserFields(model, { table: "users; DROP TABLE users" })
      )
      assert.isTrue(result._tag === "Failure")
    }))

  it.effect("leaves the base migrations to the migrator", () =>
    Effect.gen(function*() {
      const sql = yield* SqlClient.SqlClient
      const rows = yield* sql<{ readonly name: string }>`SELECT name FROM effect_auth_migrations ORDER BY migration_id`
      assert.deepStrictEqual(
        rows.map((row) => row.name),
        ["create_users", "create_sessions", "create_accounts", "create_verifications", "session_remember_me"]
      )
    }))

  it.effect("adds nothing for a model with no custom fields", () =>
    Effect.gen(function*() {
      const empty = makeUserModel({})
      assert.deepStrictEqual(empty.extraKeys, [])
      // Running it is a no-op rather than a failure. Asserting on the *set* of
      // columns would race the sibling that adds two of its own: the block runs
      // concurrently and shares one database.
      yield* Migrations.forUserFields(empty)
    }))

  it.effect("stores and reads a row through the columns it created", () =>
    Effect.gen(function*() {
      const sql = yield* SqlClient.SqlClient
      const row = yield* model.makeInsert({
        name: testName,
        email: uniqueEmail("ddl"),
        emailVerified: false,
        image: null
      })
      const encoded = yield* Schema.encodeEffect(model.rows.insert)(row)
      yield* sql`INSERT INTO users ${sql.insert({
        id: encoded["id"],
        name: encoded["name"],
        email: encoded["email"],
        email_verified: encoded["emailVerified"],
        image: encoded["image"],
        created_at: encoded["createdAt"],
        updated_at: encoded["updatedAt"]
      })}`

      const stored = yield* sql<
        { readonly plan: string; readonly role: string; readonly api_secret: string | null }
      >`SELECT plan, role, api_secret FROM users WHERE id = ${String(encoded["id"])}`
      assert.deepStrictEqual([...stored], [{ plan: "free", role: "user", api_secret: null }])
    }))
})
