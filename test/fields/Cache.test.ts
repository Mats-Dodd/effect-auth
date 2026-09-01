/**
 * A deployment's own user fields, through the session cookie cache.
 *
 * **Details**
 *
 * The snapshot is the model's `json` projection, so the two rules the kernel
 * promises have to hold here as well as in a response body: a field a client
 * may see is carried, and a `UserField.hidden` one is not — not in the value,
 * not in the encoded payload, and therefore not in a cookie that leaves the
 * server signed but unencrypted.
 *
 * Because a hidden field cannot be carried without disclosing it, the presence
 * of one disables request-path cache reads for the model. The codec remains
 * testable, but middleware will always resolve the authoritative database row.
 */
import { assert, layer } from "@effect/vitest"
import { DateTime, Duration, Effect, Encoding, Result, Schema } from "effect"
import { passwordsOf } from "../../src/domain/Passwords.js"
import { userStoreOf } from "../../src/domain/Stores.js"
import { cacheCookieSeparator, sessionCacheOf } from "../../src/http/SessionCache.js"
import { AuthTest } from "../../src/testing/index.js"
import { expectSome, testName, testPassword, uniqueEmail } from "../fixtures.js"
import { model } from "./model.js"

const cache = sessionCacheOf(model)
const passwords = passwordsOf(model)
const users = userStoreOf(model)

/**
 * The JSON half of a cookie value, read as a value rather than asserted onto
 * one: only `user` is claimed, and only as the open record it actually is.
 */
const WrittenPayload = Schema.Struct({ user: Schema.Record(Schema.String, Schema.Unknown) })
const readWritten = Schema.decodeEffect(Schema.fromJsonString(WrittenPayload))

/** The JSON half of a cookie value, as it goes on the wire. */
const payloadText = (value: string): string => {
  const decoded = Encoding.decodeBase64UrlString(value.slice(0, value.indexOf(cacheCookieSeparator)))
  return Result.isSuccess(decoded) ? decoded.success : ""
}

layer(AuthTest.layer({ cookieCache: { enabled: true }, user: { model } }))("fields/Cache", (it) => {
  it.effect("carries a deployment's own field, and never a hidden one", () =>
    Effect.gen(function* () {
      const service = yield* cache
      assert.isFalse(service.enabled)
      const store = yield* users
      const email = uniqueEmail("cache-fields")

      const result = yield* (yield* passwords).signUp({
        name: testName,
        email,
        password: testPassword,
        plan: "pro"
      })
      const established = yield* expectSome(result.session, "sign-up should establish a session")
      // A hidden field with something worth hiding in it.
      const user = yield* expectSome(
        yield* store.update(result.user.id, { apiSecret: "s3cret-api-key" }),
        "the update matched no row"
      )
      assert.strictEqual(user.plan, "pro")
      assert.strictEqual(user.apiSecret, "s3cret-api-key")

      const now = yield* DateTime.now
      const value = yield* service.encode({
        version: "",
        tokenHash: established.session.tokenHash,
        expiresAt: DateTime.addDuration(now, Duration.minutes(5)),
        session: established.session,
        user
      })

      // What the browser is actually handed: signed, not encrypted, so this is
      // the assertion that matters.
      const json = payloadText(value)
      const written = yield* readWritten(json)
      assert.strictEqual(written.user["plan"], "pro")
      assert.strictEqual(written.user["role"], "user")
      assert.isFalse("apiSecret" in written.user, "a hidden field must not reach the cookie")
      assert.isFalse(json.includes("s3cret-api-key"))

      const read = yield* expectSome(yield* service.decode(value), "the value it just signed should decode")
      assert.strictEqual(read.user.plan, "pro")
      assert.strictEqual(read.user.role, "user")
      assert.strictEqual(read.user.email, email)
      // Decoding can only reconstruct the declared default, which is why the
      // service is disabled for request-path reads above.
      assert.strictEqual(read.user.apiSecret, null)
    })
  )
})
