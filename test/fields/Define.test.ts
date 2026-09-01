/**
 * `Auth.define` — the whole parameterized surface derived from one declaration.
 *
 * **Details**
 *
 * The bundle adds no capability: every member is what the corresponding
 * per-module function returns for the same model. What it removes is the one
 * mistake nothing else can catch cheaply — an API, a stack, handlers and a
 * client built from *different* models. So the test is an end-to-end one:
 * declare the fields once, serve the API the definition carries with the
 * handlers the definition carries, and read a custom field back out.
 *
 * `AuthTest.layer` supplies the database and the mailer; `auth.layer` is
 * exercised for its type in `Fields.types.ts`, where building it for real would
 * mean a second PGlite.
 */
import { assert, layer } from "@effect/vitest"
import { Effect, Layer, Schema } from "effect"
import { HttpApi } from "effect/unstable/httpapi"
import { UserField } from "../../src/domain/Schema.js"
import { Auth } from "../../src/index.js"
import { AuthTest, TestHttpClient } from "../../src/testing/index.js"
import { testName, testPassword, uniqueEmail } from "../fixtures.js"

const auth = Auth.define({
  user: {
    fields: {
      tier: UserField.withDefault(Schema.Literals(["bronze", "gold"]), () => "bronze" as const)
    }
  }
})

const DefineApi = HttpApi.make("define-app").addHttpApi(auth.Api)

const layerDefine = auth
  .handlers(DefineApi)
  .pipe(Layer.provideMerge(AuthTest.layer({ user: { model: auth.model } })), Layer.merge(AuthTest.layerPlatform))

layer(layerDefine)("fields/Define", (it) => {
  it.effect("serves the fields it declared", () =>
    Effect.gen(function* () {
      const { client } = yield* TestHttpClient.makeClient(DefineApi)
      const email = uniqueEmail("defined")

      const registered = yield* client.auth.signUpEmail({
        payload: { name: testName, email, password: testPassword, tier: "gold" }
      })
      assert.strictEqual(registered.user.tier, "gold")

      const current = yield* client.auth.getSession()
      assert.strictEqual(current.user.tier, "gold")
    })
  )

  it.effect("reads the same field back through its own store view", () =>
    Effect.gen(function* () {
      const store = yield* auth.UserStore
      const email = uniqueEmail("defined-store")
      const created = yield* store.create(
        yield* auth.model.makeInsert({ name: testName, email, emailVerified: true, image: null })
      )
      assert.strictEqual(created.tier, "bronze")
    })
  )

  it("derives one model, and everything from it", () => {
    assert.deepStrictEqual(auth.model.extraKeys, ["tier"])
    assert.strictEqual(auth.ApiGroup.identifier, "auth")
    assert.strictEqual(auth.Api.identifier, "effect-auth")
  })
})
