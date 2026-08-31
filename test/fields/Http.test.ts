/**
 * A deployment's own user fields, end to end over HTTP.
 *
 * **Details**
 *
 * The store tests prove the columns exist and round-trip. What is left is the
 * seam this wave built: an endpoint declaration that carries the fields, a
 * handler that forwards what a client stated about them, a response that carries
 * the ones a client may see and *not* the ones it may not, and an application's
 * own endpoint reading one off `CurrentUser`.
 *
 * The generated client is the point of the last two: it decodes every response
 * through the API's own schemas, so a field missing from the declaration would
 * fail the request rather than quietly go unasserted.
 */
import { assert, layer } from "@effect/vitest"
import { Effect, Layer, Schema } from "effect"
import { HttpApiBuilder, HttpApiEndpoint, HttpApiGroup } from "effect/unstable/httpapi"
import { Authenticated, currentUserOf } from "../../src/http/Middleware.js"
import { AuthTest, TestHttpClient } from "../../src/testing/index.js"
import { testName, testPassword, uniqueEmail } from "../fixtures.js"
import { FieldsApi, model } from "./model.js"

/**
 * An application's own endpoint, reading a custom field off the authenticated
 * user. `currentUserOf(model)` is the whole story: the same key the middleware
 * fills, seen through the model, so `user.plan` is a `"free" | "pro"` here
 * without anything in the middleware's own signature having moved.
 */
const ProfileGroup = HttpApiGroup.make("profile").add(
  HttpApiEndpoint.get("plan", "/profile/plan", { success: Schema.String })
    .middleware(Authenticated)
)

const ProfileApi = FieldsApi.add(ProfileGroup)

const ProfileHandlers = HttpApiBuilder.group(ProfileApi, "profile", (handlers) =>
  Effect.succeed(
    handlers.handle("plan", () => Effect.map(currentUserOf(model), (user) => user.plan))
  ))

const layerFields = ProfileHandlers.pipe(
  Layer.provideMerge(AuthTest.layerHttpApi(ProfileApi, { user: { model } }))
)

const makeClient = () => TestHttpClient.makeClient(ProfileApi)

layer(layerFields)("fields/Http", (it) => {
  it.effect("takes a custom field at sign-up and answers with it", () =>
    Effect.gen(function*() {
      const email = uniqueEmail("signup-pro")
      const { client } = yield* makeClient()

      const registered = yield* client.auth.signUpEmail({
        payload: { name: testName, email, password: testPassword, plan: "pro" }
      })

      assert.strictEqual(registered.user.plan, "pro")
      // `role` is the application's, never a client's, and it is on the wire
      // because it is readable — just not settable.
      assert.strictEqual(registered.user.role, "user")
      // `apiSecret` is hidden: absent from the JSON variant, and therefore from
      // the response body and from the type the client decoded.
      assert.isFalse(Object.hasOwn(registered.user, "apiSecret"))
    }))

  it.effect("fills a custom field in when the client states nothing", () =>
    Effect.gen(function*() {
      const email = uniqueEmail("signup-default")
      const { client } = yield* makeClient()

      const registered = yield* client.auth.signUpEmail({
        payload: { name: testName, email, password: testPassword }
      })

      assert.strictEqual(registered.user.plan, "free")
    }))

  it.effect("carries the custom fields through sign-in and GET /session", () =>
    Effect.gen(function*() {
      const email = uniqueEmail("session")
      const { client } = yield* makeClient()

      yield* client.auth.signUpEmail({
        payload: { name: testName, email, password: testPassword, plan: "pro" }
      })
      yield* client.auth.signOut()

      const signedIn = yield* client.auth.signInEmail({ payload: { email, password: testPassword } })
      assert.strictEqual(signedIn.user.plan, "pro")

      const current = yield* client.auth.getSession()
      assert.strictEqual(current.user.plan, "pro")
      assert.strictEqual(current.user.role, "user")
      assert.isFalse(Object.hasOwn(current.user, "apiSecret"))
    }))

  it.effect("never puts a hidden field on the wire", () =>
    Effect.gen(function*() {
      const email = uniqueEmail("hidden-http")
      const { client } = yield* makeClient()

      // The value is written by the model's default, so nothing in the request
      // carries it — what is being asserted is that nothing in a *response*
      // does either, on the endpoint that returns the most user.
      const registered = yield* client.auth.signUpEmail({
        payload: { name: testName, email, password: testPassword }
      })
      const current = yield* client.auth.getSession()

      assert.notInclude(JSON.stringify(registered), "apiSecret")
      assert.notInclude(JSON.stringify(current), "apiSecret")
    }))

  it.effect("patches a custom field through update-user, and leaves the rest alone", () =>
    Effect.gen(function*() {
      const email = uniqueEmail("update-plan")
      const { client } = yield* makeClient()

      yield* client.auth.signUpEmail({
        payload: { name: testName, email, password: testPassword, plan: "pro" }
      })

      // The base half and the deployment's own half of the body are patched by
      // the same statement …
      const updated = yield* client.auth.updateUser({ payload: { name: "Ada Byron", plan: "free" } })
      assert.strictEqual(updated.user.name, "Ada Byron")
      assert.strictEqual(updated.user.plan, "free")
      // … and the two fields a client may not write are where they were.
      assert.strictEqual(updated.user.role, "user")
      assert.isFalse(Object.hasOwn(updated.user, "apiSecret"))

      // A custom field the body does not name is a column the statement does
      // not touch — not one reset to the model's default.
      yield* client.auth.updateUser({ payload: { plan: "pro" } })
      const renamed = yield* client.auth.updateUser({ payload: { name: "Ada Lovelace" } })
      assert.strictEqual(renamed.user.plan, "pro")

      // And the write landed: the application's own endpoint reads it back off
      // `CurrentUser` on the next request.
      assert.strictEqual(yield* client.profile.plan(), "pro")
    }))

  it.effect("lets an application's own endpoint read a custom field", () =>
    Effect.gen(function*() {
      const email = uniqueEmail("own-endpoint")
      const { client } = yield* makeClient()

      yield* client.auth.signUpEmail({
        payload: { name: testName, email, password: testPassword, plan: "pro" }
      })

      // Through the same cookie jar: the middleware verified the session, read
      // the user through the model, and provided it under the key this handler
      // reads.
      assert.strictEqual(yield* client.profile.plan(), "pro")
    }))
})
