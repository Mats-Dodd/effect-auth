import { assert, describe, layer } from "@effect/vitest"
import { Duration, Effect, Layer, Option, Redacted } from "effect"
import { TestClock } from "effect/testing"
import * as UsernameTest from "../../src/testing/UsernameTest.js"
import * as TestHttpClient from "../../src/testing/TestHttpClient.js"
import { testName, testPassword, testPasswordText, uniqueEmail } from "../fixtures.js"

/**
 * The completed half of a sign-in's two-status success.
 *
 * A local copy of `test/http/helpers.ts`'s: that module reaches this library's
 * own test API through `src/testing/index.ts`, which this suite does not need
 * and which a sibling bucket is currently mid-edit on.
 */
const completeSignIn = <S, U>(
  result: { readonly _tag: "MfaRequired" } | { readonly user: U; readonly session: S }
): { readonly user: U; readonly session: S } => {
  if ("_tag" in result) {
    throw new Error("expected a completed sign-in; the deployment answered MfaRequired")
  }
  return result
}

/** A browser addressing this block's deployment, with a jar the test can read. */
const makeClient = (options?: TestHttpClient.ClientOptions) => TestHttpClient.makeClient(UsernameTest.TestApi, options)

/** A name no other test in this file will take. */
let counter = 0
const uniqueName = (label: string) => `${label}-${(counter += 1)}-${globalThis.crypto.randomUUID().slice(0, 8)}`

/** Registers an account through the composed API and hands back the browser it signed up on. */
const signedUp = Effect.fnUntraced(function* (email: string, options?: TestHttpClient.ClientOptions) {
  const created = yield* makeClient(options)
  const result = yield* created.client.auth.signUpEmail({
    payload: { name: testName, email, password: testPassword }
  })
  return { ...created, user: result.user }
})

/**
 * {@link UsernameTest.layerHttp} on a `TestClock` of its own, which a test may
 * move — the hand-built twin of `AuthTest.layerHttpMovingClock`, which serves
 * this library's own API rather than the composed one.
 */
const layerMovingClock = (options?: UsernameTest.Options) =>
  UsernameTest.layerHttp(options).pipe(Layer.provideMerge(Layer.fresh(TestClock.layer())))

describe.sequential("username/Handlers", () => {
  layer(UsernameTest.layerHttp())("the endpoints", (it) => {
    it.effect("signs a browser in by username and sets the session cookie", () =>
      Effect.gen(function* () {
        const email = uniqueEmail("http-signin")
        const name = uniqueName("http")
        const { client } = yield* signedUp(email)
        yield* client.username.set({ payload: { username: name } })

        const { client: browser, cookies } = yield* makeClient()
        const result = completeSignIn(
          yield* browser.username.signIn({ payload: { username: name.toUpperCase(), password: testPassword } })
        )
        assert.strictEqual(result.user.email, email)
        assert.isTrue(Option.isSome(yield* TestHttpClient.sessionCookie(cookies)))

        // The cookie it wrote is a working session.
        const session = yield* browser.auth.getSession()
        assert.strictEqual(session.user.email, email)
      })
    )

    it.effect("answers InvalidCredentials for an unknown name and for a wrong password alike", () =>
      Effect.gen(function* () {
        const name = uniqueName("http-refuse")
        const { client } = yield* signedUp(uniqueEmail("http-refuse"))
        yield* client.username.set({ payload: { username: name } })

        const { client: browser } = yield* makeClient()
        const unknown = yield* Effect.flip(
          browser.username.signIn({ payload: { username: uniqueName("nobody"), password: testPassword } })
        )
        assert.strictEqual(unknown._tag, "InvalidCredentials")

        const wrong = yield* Effect.flip(
          browser.username.signIn({ payload: { username: name, password: Redacted.make("nope") } })
        )
        assert.strictEqual(wrong._tag, "InvalidCredentials")
      })
    )

    it.effect("requires a session to set a username, and refuses a name somebody else holds", () =>
      Effect.gen(function* () {
        const first = yield* signedUp(uniqueEmail("http-set-a"))
        const second = yield* signedUp(uniqueEmail("http-set-b"))
        const name = uniqueName("contended")

        const stored = yield* first.client.username.set({ payload: { username: name } })
        assert.strictEqual(stored.username, name)
        assert.strictEqual(stored.usernameKey, name.toLowerCase())

        const taken = yield* Effect.flip(second.client.username.set({ payload: { username: name } }))
        assert.strictEqual(taken._tag, "UsernameTaken")

        const { client: stranger } = yield* makeClient()
        const unauthorized = yield* Effect.flip(stranger.username.set({ payload: { username: uniqueName("x") } }))
        assert.strictEqual(unauthorized._tag, "Unauthorized")
      })
    )

    it.effect("refuses a name this deployment does not allow, naming why", () =>
      Effect.gen(function* () {
        const { client } = yield* signedUp(uniqueEmail("http-invalid"))
        const failure = yield* Effect.flip(client.username.set({ payload: { username: "admin" } }))
        assert.strictEqual(failure._tag, "UsernameInvalid")
        assert.strictEqual(failure._tag === "UsernameInvalid" ? failure.reason : null, "reserved")
      })
    )

    it.effect("does not serve the availability oracle unless the deployment opted in", () =>
      Effect.gen(function* () {
        const { client } = yield* makeClient()
        const status = yield* TestHttpClient.refusedStatus(
          client.username.available({ payload: { username: uniqueName("free") } })
        )
        assert.strictEqual(status, 404)
      })
    )

    it.effect("refuses a cross-origin sign-in that names an untrusted origin", () =>
      Effect.gen(function* () {
        const name = uniqueName("origin")
        const { client } = yield* signedUp(uniqueEmail("http-origin"))
        yield* client.username.set({ payload: { username: name } })

        // A cross-origin form post arrives with no cookie at all, which is
        // exactly what the Authenticated middleware's own origin check cannot
        // see — so the handler asks for itself.
        const { client: attacker } = yield* makeClient({ headers: { origin: "https://evil.test" } })
        const failure = yield* Effect.flip(
          attacker.username.signIn({ payload: { username: name, password: testPassword } })
        )
        assert.strictEqual(failure._tag, "OriginNotAllowed")
      })
    )
  })

  layer(UsernameTest.layerHttp({ username: { availability: true } }))("with the oracle switched on", (it) => {
    it.effect("answers whether a name is free, and refuses one nobody may have", () =>
      Effect.gen(function* () {
        const name = uniqueName("oracle")
        const { client } = yield* makeClient()

        assert.deepStrictEqual(yield* client.username.available({ payload: { username: name } }), { available: true })

        const owner = yield* signedUp(uniqueEmail("http-oracle"))
        yield* owner.client.username.set({ payload: { username: name } })
        assert.deepStrictEqual(yield* client.username.available({ payload: { username: name } }), { available: false })

        const refused = yield* Effect.flip(client.username.available({ payload: { username: "admin" } }))
        assert.strictEqual(refused._tag, "UsernameInvalid")
      })
    )
  })

  layer(
    UsernameTest.layerHttp({
      username: { availability: true },
      rateLimit: { enabled: true, ipHeaders: ["x-forwarded-for"] }
    })
  )("with rate limiting on", (it) => {
    it.effect("limits the oracle on a bucket of its own, leaving sign-in alone", () =>
      Effect.gen(function* () {
        const { client } = yield* makeClient({ headers: { "x-forwarded-for": "203.0.113.77" } })
        // Ten a minute; the eleventh is refused.
        for (let attempt = 0; attempt < 10; attempt++) {
          yield* client.username.available({ payload: { username: uniqueName("burn") } })
        }
        const limited = yield* Effect.flip(client.username.available({ payload: { username: uniqueName("burn") } }))
        assert.strictEqual(limited._tag, "RateLimited")

        // The credential bucket is untouched: a spent oracle must not lock
        // anybody out of signing in. `credentials` is three per ten seconds, so
        // one attempt is well inside it.
        const signIn = yield* Effect.flip(
          client.username.signIn({ payload: { username: uniqueName("nobody"), password: testPassword } })
        )
        assert.strictEqual(signIn._tag, "InvalidCredentials")
      })
    )
  })

  layer(layerMovingClock())("as time passes", (it) => {
    it.effect("refuses to set a username from a session that authenticated too long ago", () =>
      Effect.gen(function* () {
        const { client } = yield* signedUp(uniqueEmail("http-stale"))

        // `freshSession` resolves to session.freshAge, one day by default.
        yield* TestClock.adjust(Duration.days(2))

        const failure = yield* Effect.flip(client.username.set({ payload: { username: uniqueName("stale") } }))
        assert.strictEqual(failure._tag, "StepUpRequired")

        // Re-authenticating takes the refusal away again, which is the whole
        // point of measuring freshness from `authenticatedAt`.
        yield* client.auth.reauthenticate({ payload: { password: Redacted.make(testPasswordText) } })
        const name = uniqueName("fresh")
        const stored = yield* client.username.set({ payload: { username: name } })
        assert.strictEqual(stored.username, name)
      })
    )
  })
})
