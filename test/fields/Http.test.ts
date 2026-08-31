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
import { Effect, Layer, Option, Ref, Schema } from "effect"
import type { HttpServerResponse as HttpServerResponseType } from "effect/unstable/http"
import {
  HttpClientRequest,
  HttpEffect,
  HttpRouter,
  HttpServerRequest,
  HttpServerResponse
} from "effect/unstable/http"
import { HttpApiBuilder, HttpApiEndpoint, HttpApiGroup } from "effect/unstable/httpapi"
import { userStoreOf } from "../../src/domain/Stores.js"
import { insecureSessionCookieName } from "../../src/http/Cookies.js"
import { Authenticated, currentUserOf } from "../../src/http/Middleware.js"
import { AuthTest, TestHttpClient } from "../../src/testing/index.js"
import { expectSome, testName, testPassword, testPasswordText, uniqueEmail } from "../fixtures.js"
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

/** The user rows of this deployment's model, for reading a column back. */
const users = userStoreOf(model)

/**
 * A request the generated client cannot make: a body naming keys the endpoint's
 * payload schema does not declare.
 *
 * **Details**
 *
 * The typed client encodes every payload through that schema, so it strips
 * `role` and `apiSecret` before the bytes are written — which is exactly why it
 * cannot be the witness here. What is under test is the *server*, and two
 * independent facts hold it up: `Schema.Struct` discards excess keys on decode,
 * and `model.extrasOf` picks only the `jsonCreate`/`jsonUpdate` variants' keys
 * before the spread into the store. A regression in either — an
 * `onExcessProperty` annotation on the payload, `extrasOf` widening to
 * `extraKeys` — would let a client write an application-owned column while every
 * typed test in this file stayed green.
 *
 * The router is built the same way `TestHttpClient.makeClient` builds it, from
 * the services this block already provides.
 */
const rawPost = Effect.fnUntraced(function*(
  path: string,
  body: Record<string, unknown>,
  headers?: Record<string, string>
) {
  const handler = yield* HttpRouter.toHttpEffect(HttpApiBuilder.layer(ProfileApi))
  const request = HttpClientRequest.post(`${AuthTest.testBaseUrl}${path}`, { headers }).pipe(
    HttpClientRequest.bodyJsonUnsafe(body)
  )

  const sent = yield* Ref.make(Option.none<HttpServerResponseType.HttpServerResponse>())
  yield* HttpEffect.toHandled(handler, (_request, response) => Ref.set(sent, Option.some(response))).pipe(
    Effect.provideService(HttpServerRequest.HttpServerRequest, HttpServerRequest.fromClientRequest(request))
  )

  const response = yield* expectSome(yield* Ref.get(sent), `no response for POST ${path}`)
  const client = HttpServerResponse.toClientResponse(response)
  return { status: client.status, body: yield* client.json }
})

/** The `user` half of a raw response body, as a plain record. */
const userOf = (body: unknown): Record<string, unknown> =>
  (body as { readonly user: Record<string, unknown> }).user

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

  it.effect("drops an application-owned field a raw sign-up body tries to set", () =>
    Effect.gen(function*() {
      const email = uniqueEmail("signup-raw-role")

      const { body, status } = yield* rawPost("/auth/sign-up/email", {
        name: testName,
        email,
        password: testPasswordText,
        plan: "pro",
        // Neither of these is on the sign-up payload: `role` is readOnly and
        // `apiSecret` is hidden, so both are the application's to write.
        role: "admin",
        apiSecret: "the-client-picked-this"
      })

      assert.strictEqual(status, 200)
      // The field a client *may* state was taken …
      assert.strictEqual(userOf(body)["plan"], "pro")
      // … and the two it may not were not: the response says the defaults.
      assert.strictEqual(userOf(body)["role"], "user")
      assert.isFalse(Object.hasOwn(userOf(body), "apiSecret"))

      // And the row agrees, which is the assertion the response alone cannot
      // make: `apiSecret` is hidden from every JSON variant, so a written value
      // would be invisible in a body either way.
      const store = yield* users
      const stored = yield* expectSome(yield* store.findByEmail(email), "the account was not created")
      assert.strictEqual(stored.role, "user")
      assert.strictEqual(stored.apiSecret, null)
    }))

  it.effect("drops an application-owned field a raw update-user body tries to set", () =>
    Effect.gen(function*() {
      const email = uniqueEmail("update-raw-role")
      const { client, cookies } = yield* makeClient()
      yield* client.auth.signUpEmail({
        payload: { name: testName, email, password: testPassword }
      })

      // The same browser, hand-writing the body the typed client would have
      // stripped.
      const token = yield* TestHttpClient.sessionCookieValue(cookies)
      const { body, status } = yield* rawPost(
        "/auth/update-user",
        { name: "Ada Byron", plan: "pro", role: "admin", apiSecret: "the-client-picked-this" },
        { cookie: `${insecureSessionCookieName}=${token}` }
      )

      assert.strictEqual(status, 200)
      assert.strictEqual(userOf(body)["name"], "Ada Byron")
      assert.strictEqual(userOf(body)["plan"], "pro")
      assert.strictEqual(userOf(body)["role"], "user")

      const store = yield* users
      const stored = yield* expectSome(yield* store.findByEmail(email), "the account went missing")
      assert.strictEqual(stored.role, "user")
      assert.strictEqual(stored.apiSecret, null)
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
