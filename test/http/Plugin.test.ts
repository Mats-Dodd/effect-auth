import { assert, layer } from "@effect/vitest"
import { Effect, Schema } from "effect"
import { HttpApi, HttpApiEndpoint, HttpApiGroup } from "effect/unstable/httpapi"
import { AuthApi } from "../../src/http/AuthApi.js"
import * as AuthHandlers from "../../src/http/Handlers.js"
import { Authenticated, CurrentUser } from "../../src/http/Middleware.js"
import { AuthTest, TestHttpClient } from "../../src/testing/index.js"
import { testName, testPassword, uniqueEmail } from "../fixtures.js"

/**
 * A plugin, in the shape the SDK asks for: a group of its own, handlers built
 * with `AuthHandlers.forGroup`, and a layer a consumer composes.
 *
 * It exists to prove three things at once — that `forGroup` registers routes on
 * somebody else's composed API, that a plugin may declare this library's own
 * middleware and read `CurrentUser` behind it, and that `AuthTest.layerHttpApi`'s
 * third parameter provides a plugin the *same* deployment the auth handlers got.
 */
const WhoAmIGroup = HttpApiGroup.make("whoami")
  .add(
    HttpApiEndpoint.get("whoami", "/whoami", { success: Schema.Struct({ email: Schema.String }) })
      .middleware(Authenticated)
  )
  .prefix("/auth/whoami")

const PluginApi = HttpApi.make("plugin-app").addHttpApi(AuthApi).add(WhoAmIGroup)

const whoamiHandlers = AuthHandlers.forGroup(WhoAmIGroup, (handlers) =>
  Effect.succeed(
    handlers.handle("whoami", () => Effect.map(CurrentUser, (user) => ({ email: user.email })))
  ))

layer(AuthTest.layerHttpApi(PluginApi, undefined, whoamiHandlers(PluginApi)))("http/plugin seam", (it) => {
  it.effect("serves a plugin's group beside the auth group, on one deployment", () =>
    Effect.gen(function*() {
      const email = uniqueEmail("plugin")
      const { client } = yield* TestHttpClient.makeClient(PluginApi)

      yield* client.auth.signUpEmail({
        payload: { name: testName, email, password: testPassword }
      })

      // The plugin's endpoint is behind this library's middleware, reading the
      // `CurrentUser` the deployment's own `Authenticated` provided.
      const answer = yield* client.whoami.whoami()
      assert.strictEqual(answer.email, email)

      // And the auth group is still served, from the same stack.
      const session = yield* client.auth.getSession()
      assert.strictEqual(session.user.email, email)
    }))

  it.effect("refuses the plugin's endpoint without a session", () =>
    Effect.gen(function*() {
      const { client } = yield* TestHttpClient.makeClient(PluginApi)
      const error = yield* Effect.flip(client.whoami.whoami())
      assert.strictEqual(error._tag, "Unauthorized")
    }))
})
