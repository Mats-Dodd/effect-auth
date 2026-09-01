/**
 * The base instance is the parameterized one.
 *
 * **Details**
 *
 * Everything the library exports without a model — `User.json`, `UserPublic`,
 * `SessionWithUser`, `SqlStores.layer` — is `makeUserModel({})`'s. These tests
 * are what says so: the six variants of the empty model carry the same fields
 * and the same schema identifiers as the ones `Model.Class` generated, so a
 * deployment that adds no fields publishes byte-identical OpenAPI and every
 * existing test keeps passing for a reason rather than by luck.
 *
 * The guard rails around `makeUserModel` are here too, because both of them fire
 * at construction time and neither has anything to run against.
 */
import { assert, describe, it } from "@effect/vitest"
import { Effect, Option, Schema } from "effect"
import { Model } from "effect/unstable/schema"
import {
  baseUserModel,
  makeUserModel,
  SessionWithUser,
  SignUpResponse,
  User,
  UserField,
  UserModelRef,
  UserPublic
} from "../../src/domain/Schema.js"

const variants = ["select", "insert", "update", "json", "jsonCreate", "jsonUpdate"] as const

const annotationsOf = (schema: Schema.Top): unknown => schema.ast.annotations

/**
 * The own enumerable fields of a decoded row, as plain data.
 *
 * The two sides of the round-trip assertion below come from different schema
 * variants — one of them a `Model.Class` instance — so the prototypes must stay
 * out of the comparison. `Object.entries` copies exactly what a spread would.
 */
const fieldsOf = (value: object): Record<string, unknown> => Object.fromEntries(Object.entries(value))

describe("fields/Default", () => {
  it("derives the same fields as the base model, variant for variant", () => {
    const struct = Model.Struct(Model.fields(User))
    for (const variant of variants) {
      assert.deepStrictEqual(
        Object.keys(baseUserModel[variant].fields),
        Object.keys(Model.extract(struct, variant).fields),
        `variant ${variant}`
      )
    }
  })

  it("annotates every variant the way `Model.Class` does", () => {
    for (const variant of variants) {
      assert.deepStrictEqual(
        annotationsOf(baseUserModel[variant]),
        { id: `effect-auth/User.${variant}`, title: `effect-auth/User.${variant}` },
        `variant ${variant}`
      )
    }
    // The exported projection is this model's, so the OpenAPI component it names
    // is the one a base deployment has always published.
    assert.deepStrictEqual(annotationsOf(UserPublic), annotationsOf(User.json))
  })

  it.effect("round-trips a user through the empty model exactly as `User` does", () =>
    Effect.gen(function* () {
      const row = {
        id: "01930000-0000-7000-8000-000000000001",
        name: "Ada",
        email: "ada@example.com",
        emailVerified: true,
        image: null,
        createdAt: "2024-01-01T00:00:00.000Z",
        updatedAt: "2024-01-02T00:00:00.000Z"
      }
      const throughModel = yield* baseUserModel.decodeRow(row)
      const throughClass = yield* Schema.decodeEffect(User)(row)
      assert.deepStrictEqual(fieldsOf(throughModel), fieldsOf(throughClass))

      const encoded = yield* Schema.encodeEffect(baseUserModel.json)(throughModel)
      assert.deepStrictEqual(encoded, row)
    })
  )

  it("keeps the two response payloads on the base model's projection", () => {
    assert.strictEqual(SessionWithUser.fields.user, baseUserModel.json)
    assert.strictEqual(SignUpResponse.fields.user, baseUserModel.json)
  })

  it.effect("carries no custom fields and needs no defaults", () =>
    Effect.gen(function* () {
      assert.deepStrictEqual(baseUserModel.extraKeys, [])
      assert.deepStrictEqual(yield* baseUserModel.extraDefaults, {})
    })
  )

  it.effect("defaults the ambient model reference to the base model", () =>
    Effect.map(UserModelRef, (model) => {
      assert.strictEqual(model, baseUserModel)
    })
  )

  it("refuses a custom field that cannot be provisioned", () => {
    assert.throws(() => makeUserModel({ nickname: Schema.String }), /not provisionable/)
  })

  it("refuses custom fields whose columns collide", () => {
    // Columns are the snake_case of the key: `email_verified` would land on the
    // base `emailVerified` column, and `fooBar` / `foo_bar` on one shared column.
    assert.throws(
      () => makeUserModel({ email_verified: UserField.withDefault(Schema.Boolean, () => false) }),
      /column email_verified, also emailVerified/
    )
    assert.throws(
      () =>
        makeUserModel({
          fooBar: UserField.withDefault(Schema.String, () => ""),
          foo_bar: UserField.withDefault(Schema.String, () => "")
        }),
      /column foo_bar, also fooBar/
    )
  })

  it("refuses a custom field that redeclares a base one", () => {
    assert.throws(() => makeUserModel({ email: UserField.withDefault(Schema.String, () => "") }), /redeclare/)
  })

  it("accepts a `required` field whose schema defaults itself", () => {
    const model = makeUserModel({
      nickname: UserField.required(Schema.String.pipe(Schema.withConstructorDefault(Effect.succeed("anonymous"))))
    })
    assert.deepStrictEqual(model.extraKeys, ["nickname"])
    assert.isTrue(
      Option.isSome(
        model.insert.makeOption({ name: "Ada", email: "ada@example.com", emailVerified: false, image: null })
      )
    )
  })
})
