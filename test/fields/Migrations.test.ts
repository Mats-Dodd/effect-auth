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
 *
 * **Gotchas**
 *
 * Nothing here reads a catalog. Which column names exist comes from
 * {@link Database.TestDatabase}; what type, default and nullability they carry
 * is asserted by writing and reading rows, because `text`, `double precision`
 * and `boolean` are three different words on three databases and only the
 * behaviour is the same on all of them.
 */
import { assert, layer } from "@effect/vitest"
import { Effect, Schema } from "effect"
import { Migrator, SqlClient } from "effect/unstable/sql"
import { makeUserModel, UserField } from "../../src/domain/Schema.js"
import { booleanCodec } from "../../src/sql/Dialect.js"
import * as Migrations from "../../src/sql/Migrations.js"
import * as Database from "../../src/testing/Database.js"
import { testName, uniqueEmail } from "../fixtures.js"
import { layerDatabase, model } from "./model.js"

/** The custom columns `users` carries, by name. */
const userColumns = Effect.flatMap(Database.TestDatabase, (database) => database.columnNames("users"))

/**
 * Inserts a base user row — the shape a caller that knows nothing about the
 * custom fields can build — and hands back its id.
 *
 * Every default and every nullability assertion in this file is a statement
 * about what this row reads back as.
 */
const insertBaseUser = Effect.fnUntraced(function* (label: string) {
  const sql = yield* SqlClient.SqlClient
  const dialect = yield* Database.dialect
  const row = yield* model.makeInsert({
    name: testName,
    email: uniqueEmail(label),
    emailVerified: false,
    image: null
  })
  const encoded = yield* Schema.encodeEffect(model.rows.insert)(row)
  yield* sql`INSERT INTO users ${sql.insert({
    id: encoded["id"],
    name: encoded["name"],
    email: encoded["email"],
    // `node:sqlite` binds no booleans, so the flag goes in the way the store
    // would write it rather than the way the schema encoded it.
    email_verified: booleanCodec(dialect).encode(row.emailVerified),
    image: encoded["image"],
    created_at: encoded["createdAt"],
    updated_at: encoded["updatedAt"]
  })}`
  return String(encoded["id"])
})

layer(layerDatabase)("fields/Migrations", (it) => {
  it.effect("adds a column for every custom field, defaulted as the field declares", () =>
    Effect.gen(function* () {
      const sql = yield* SqlClient.SqlClient
      const columns = yield* userColumns
      assert.include(columns, "plan")
      assert.include(columns, "role")
      assert.include(columns, "api_secret")

      const id = yield* insertBaseUser("defaults")
      const stored = yield* sql<{
        readonly plan: string
        readonly role: string
        readonly api_secret: string | null
      }>`SELECT plan, role, api_secret FROM users WHERE id = ${id}`

      // A defaulted field's default is written by the column, not by the store:
      // that is what lets `forUserFields` run against a table that already has
      // rows. A nullable field takes no default — `null` is what an absent
      // value already means.
      assert.deepStrictEqual([...stored], [{ plan: "free", role: "user", api_secret: null }])
    })
  )

  it.effect("keeps a non-nullable custom column non-nullable, and a nullable one nullable", () =>
    Effect.gen(function* () {
      const sql = yield* SqlClient.SqlClient
      const id = yield* insertBaseUser("nullability")

      const clearPlan = yield* Effect.result(sql`UPDATE users SET plan = ${null} WHERE id = ${id}`)
      assert.strictEqual(clearPlan._tag, "Failure")

      const clearRole = yield* Effect.result(sql`UPDATE users SET role = ${null} WHERE id = ${id}`)
      assert.strictEqual(clearRole._tag, "Failure")

      // `apiSecret` is `NullOr`, so its column has to hold a null.
      const clearSecret = yield* Effect.result(sql`UPDATE users SET api_secret = ${null} WHERE id = ${id}`)
      assert.strictEqual(clearSecret._tag, "Success")
    })
  )

  it.effect("names the column in snake_case", () =>
    Effect.map(userColumns, (columns) => {
      assert.include(columns, "api_secret")
      assert.notInclude(columns, "apiSecret")
    })
  )

  it.effect("is idempotent", () =>
    Effect.gen(function* () {
      // The layer already ran it once; running it again must be a no-op rather
      // than a duplicate-column failure.
      yield* Migrations.forUserFields(model)
      yield* Migrations.forUserFields(model)
      assert.include(yield* userColumns, "plan")
    })
  )

  it.effect("adds a column a later model declares", () =>
    Effect.gen(function* () {
      const sql = yield* SqlClient.SqlClient
      const dialect = yield* Database.dialect
      const extended = makeUserModel({
        ...model.fields,
        seats: UserField.withDefault(Schema.Finite, () => 1),
        trial: UserField.withDefault(Schema.Boolean, () => false)
      })
      yield* Migrations.forUserFields(extended)

      const columns = yield* userColumns
      assert.include(columns, "seats")
      assert.include(columns, "trial")

      // A number field stores as a number and a boolean field as whatever the
      // dialect calls a boolean, and both carry the model's default — which is
      // what a row written before the column existed will read back as.
      const id = yield* insertBaseUser("later-model")
      const stored = yield* sql<{
        readonly seats: number
        readonly trial: unknown
      }>`SELECT seats, trial FROM users WHERE id = ${id}`
      assert.strictEqual(stored[0]?.seats, 1)
      assert.strictEqual(booleanCodec(dialect).decode(stored[0]?.trial), false)
    })
  )

  it.effect("refuses a field no column can hold", () =>
    Effect.gen(function* () {
      const unstorable = makeUserModel({
        preferences: UserField.hidden(Schema.Struct({ theme: Schema.String }), () => ({ theme: "dark" }))
      })
      const result = yield* Effect.result(Migrations.forUserFields(unstorable))
      assert.isTrue(result._tag === "Failure")
      if (result._tag === "Failure") {
        assert.isTrue(result.failure instanceof Migrator.MigrationError)
        assert.include(String(result.failure), "preferences")
      }
    })
  )

  it.effect("refuses a table name that is not an identifier", () =>
    Effect.gen(function* () {
      const result = yield* Effect.result(Migrations.forUserFields(model, { table: "users; DROP TABLE users" }))
      assert.isTrue(result._tag === "Failure")
    })
  )

  it.effect("leaves the base migrations to the migrator", () =>
    Effect.gen(function* () {
      const sql = yield* SqlClient.SqlClient
      const rows = yield* sql<{ readonly name: string }>`SELECT name FROM effect_auth_migrations ORDER BY migration_id`
      assert.deepStrictEqual(
        rows.map((row) => row.name),
        [
          "create_users",
          "create_sessions",
          "create_accounts",
          "create_verifications",
          "session_remember_me",
          "session_assurance"
        ]
      )
    })
  )

  it.effect("adds nothing for a model with no custom fields", () =>
    Effect.gen(function* () {
      const empty = makeUserModel({})
      assert.deepStrictEqual(empty.extraKeys, [])
      // Running it is a no-op rather than a failure. Asserting on the *set* of
      // columns would race the sibling that adds two of its own: the block runs
      // concurrently and shares one database.
      yield* Migrations.forUserFields(empty)
    })
  )

  it.effect("stores and reads a row through the columns it created", () =>
    Effect.gen(function* () {
      const sql = yield* SqlClient.SqlClient
      const id = yield* insertBaseUser("ddl")
      const stored = yield* sql<{
        readonly plan: string
        readonly role: string
        readonly api_secret: string | null
      }>`SELECT plan, role, api_secret FROM users WHERE id = ${id}`
      assert.deepStrictEqual([...stored], [{ plan: "free", role: "user", api_secret: null }])
    })
  )
})
