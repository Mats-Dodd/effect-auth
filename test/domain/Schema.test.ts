/**
 * `makeUserModel` — the public key lists a mass-assignment guard filters against.
 *
 * **Details**
 *
 * A create or update payload may only set the custom fields a client is allowed
 * to state, which is exactly the ones the `jsonCreate` / `jsonUpdate` variants
 * carry. A field declared `readOnly` or `hidden` is in neither variant, so it is
 * absent from these lists and a client that sends it has it dropped rather than
 * applied. The model computes the lists once; these tests pin what it publishes.
 */
import { assert, describe, it } from "@effect/vitest"
import { Schema } from "effect"
import { baseUserModel, makeUserModel, UserField } from "../../src/domain/Schema.js"

const model = makeUserModel({
  plan: UserField.withDefault(Schema.Literals(["free", "pro"]), () => "free" as const),
  role: UserField.readOnly(Schema.Literals(["user", "admin"]), () => "user" as const),
  apiSecret: UserField.hidden(Schema.NullOr(Schema.String), () => null)
})

describe("domain/Schema makeUserModel", () => {
  it("exposes only the client-settable custom fields per JSON variant", () => {
    assert.deepStrictEqual(model.extraKeys, ["plan", "role", "apiSecret"])

    // `withDefault` is settable through both payloads; `readOnly` and `hidden`
    // through neither.
    assert.deepStrictEqual(model.jsonCreateExtraKeys, ["plan"])
    assert.deepStrictEqual(model.jsonUpdateExtraKeys, ["plan"])
  })

  it("publishes empty lists for a deployment that added no fields", () => {
    assert.deepStrictEqual(baseUserModel.jsonCreateExtraKeys, [])
    assert.deepStrictEqual(baseUserModel.jsonUpdateExtraKeys, [])
  })
})
