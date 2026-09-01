/**
 * The username client's atoms against a stubbed transport.
 *
 * **Details**
 *
 * The point is the *generated* client's real encoding and decoding without a
 * socket: which path each atom calls, what it puts in the body, that the
 * two-status sign-in union narrows on the wire, and that the reactivity keys
 * are the ones an `AuthClient` built beside this one already watches.
 */
import { assert, describe, it } from "@effect/vitest"
import { Effect, Layer, Redacted } from "effect"
import type { HttpClientError } from "effect/unstable/http"
import { HttpClient, HttpClientResponse } from "effect/unstable/http"
import type { Atom } from "effect/unstable/reactivity"
import { AsyncResult, AtomRegistry } from "effect/unstable/reactivity"
import * as AuthClient from "../../src/client/AuthClient.js"
import * as UsernameClient from "../../src/client/UsernameClient.js"

const now = "2024-01-01T00:00:00.000Z"

const sessionWithUserJson = {
  user: {
    id: "0192e5a0-0000-7000-8000-000000000002",
    name: "Ada Lovelace",
    email: "ada@example.com",
    emailVerified: true,
    image: null,
    createdAt: now,
    updatedAt: now
  },
  session: {
    id: "0192e5a0-0000-7000-8000-000000000003",
    userId: "0192e5a0-0000-7000-8000-000000000002",
    expiresAt: "2024-01-08T00:00:00.000Z",
    ipAddress: null,
    userAgent: null,
    authenticatedAt: now,
    aal: "aal1",
    methods: "[]",
    rememberMe: true,
    createdAt: now,
    updatedAt: now
  }
}

const json = (status: number, body: unknown): Response =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } })

const preprocess: HttpClient.HttpClient.Preprocess<HttpClientError.HttpClientError, never> = Effect.succeed

/** A transport that answers the three endpoints and records what it was asked. */
const stub = (routes: Record<string, () => Response>) => {
  const calls: Array<string> = []
  const bodies: Array<unknown> = []
  const client = HttpClient.makeWith(
    Effect.fnUntraced(function* (requestEffect) {
      const request = yield* requestEffect
      const path = new URL(request.url, "http://auth.test").pathname
      const key = `${request.method} ${path}`
      calls.push(key)
      const body = request.body
      bodies.push(body._tag === "Uint8Array" ? JSON.parse(new TextDecoder().decode(body.body)) : null)
      const route = Object.hasOwn(routes, key) ? routes[key] : undefined
      return HttpClientResponse.fromWeb(request, route?.() ?? json(404, { _tag: "NotFound" }))
    }),
    preprocess
  )
  return { layer: Layer.succeed(HttpClient.HttpClient, client), calls, bodies }
}

/**
 * Waits until an atom's value satisfies a predicate, resolving immediately when
 * it already does. Refetches settle on the registry's scheduler, so a test
 * cannot read one straight after writing — it waits, as a rendered view does.
 */
const waitFor = <A>(
  reg: AtomRegistry.AtomRegistry,
  atom: Atom.Atom<A>,
  predicate: (value: A) => boolean
): Effect.Effect<A> =>
  Effect.callback<A>((resume) => {
    let cancel: (() => void) | undefined
    let done = false
    const finish = (value: A): void => {
      if (done) return
      done = true
      resume(Effect.succeed(value))
      cancel?.()
    }
    const current = reg.get(atom)
    if (predicate(current)) {
      finish(current)
      return Effect.void
    }
    cancel = reg.subscribe(atom, (value) => {
      if (predicate(value)) finish(value)
    })
    return Effect.sync(() => cancel?.())
  })

const registry = Effect.acquireRelease(
  Effect.sync(() => AtomRegistry.make()),
  (made) => Effect.sync(() => made.dispose())
)

describe("UsernameClient", () => {
  it.effect("signs in by username and decodes the 200 as a session", () =>
    Effect.gen(function* () {
      const transport = stub({ "POST /auth/username/sign-in": () => json(200, sessionWithUserJson) })
      const client = UsernameClient.make({ httpClient: transport.layer })
      const reg = yield* registry

      const result = yield* AuthClient.run(client.signIn, {
        username: "Ada_Lovelace",
        password: Redacted.make("correct horse battery staple")
      }).pipe(Effect.provideService(AtomRegistry.AtomRegistry, reg))

      assert.isFalse("_tag" in result, "nothing was owed, so this is a session")
      assert.deepStrictEqual(transport.calls, ["POST /auth/username/sign-in"])
      // The name goes up as it was typed: the server folds it, and a client
      // that folded it first would be a second, drifting copy of the rule.
      assert.deepStrictEqual(transport.bodies[0], {
        username: "Ada_Lovelace",
        password: "correct horse battery staple"
      })
    })
  )

  it.effect("decodes the 202 as MfaRequired, which is the same union AuthClient answers", () =>
    Effect.gen(function* () {
      const transport = stub({
        "POST /auth/username/sign-in": () =>
          json(202, { _tag: "MfaRequired", available: ["totp"], expiresAt: "2024-01-01T00:10:00.000Z" })
      })
      const client = UsernameClient.make({ httpClient: transport.layer })
      const reg = yield* registry

      const result = yield* AuthClient.run(client.signIn, {
        username: "ada",
        password: Redacted.make("correct horse battery staple")
      }).pipe(Effect.provideService(AtomRegistry.AtomRegistry, reg))

      // The status is what selects the member, so a client never has to guess
      // from the shape of a body.
      assert.isTrue("_tag" in result)
      if (!("_tag" in result)) return
      assert.strictEqual(result._tag, "MfaRequired")
      assert.deepStrictEqual([...result.available], ["totp"])
      // A 202 carries no session, so nothing here could be mistaken for one.
      assert.isFalse("session" in result)
    })
  )

  it.effect("chooses a name and answers both forms of it", () =>
    Effect.gen(function* () {
      const transport = stub({
        "POST /auth/username/set": () => json(200, { username: "Ada_Lovelace", usernameKey: "ada_lovelace" })
      })
      const client = UsernameClient.make({ httpClient: transport.layer })
      const reg = yield* registry

      const record = yield* AuthClient.run(client.set, { username: "Ada_Lovelace" }).pipe(
        Effect.provideService(AtomRegistry.AtomRegistry, reg)
      )

      assert.strictEqual(record.username, "Ada_Lovelace")
      assert.strictEqual(record.usernameKey, "ada_lovelace")
      assert.deepStrictEqual(transport.calls, ["POST /auth/username/set"])
    })
  )

  it.effect("surfaces the refusal a deployment's rules produce", () =>
    Effect.gen(function* () {
      const transport = stub({
        "POST /auth/username/set": () => json(400, { _tag: "UsernameInvalid", reason: "reserved" })
      })
      const client = UsernameClient.make({ httpClient: transport.layer })
      const reg = yield* registry

      const failure = yield* Effect.flip(
        AuthClient.run(client.set, { username: "admin" }).pipe(Effect.provideService(AtomRegistry.AtomRegistry, reg))
      )

      assert.strictEqual(failure._tag, "UsernameInvalid")
      // A closed set, so a client can say what is wrong without parsing prose.
      assert.strictEqual(failure._tag === "UsernameInvalid" ? failure.reason : null, "reserved")
    })
  )

  it.effect("asks whether a name is free without asking who holds it", () =>
    Effect.gen(function* () {
      const transport = stub({ "POST /auth/username/available": () => json(200, { available: false }) })
      const client = UsernameClient.make({ httpClient: transport.layer })
      const reg = yield* registry

      const answer = yield* AuthClient.run(client.available, { username: "ada" }).pipe(
        Effect.provideService(AtomRegistry.AtomRegistry, reg)
      )

      assert.isFalse(answer.available)
      // No identifier comes back, only the one bit that was asked for.
      assert.deepStrictEqual(Object.keys(answer), ["available"])
    })
  )

  it.effect("refetches the session atom of an AuthClient built beside it", () =>
    Effect.gen(function* () {
      let signedIn = false
      const transport = stub({
        "GET /auth/session": () => (signedIn ? json(200, sessionWithUserJson) : json(401, { _tag: "Unauthorized" })),
        "POST /auth/username/sign-in": () => {
          signedIn = true
          return json(200, sessionWithUserJson)
        }
      })
      // Two clients, two runtimes, one transport — exactly what an application
      // holding both writes.
      const auth = AuthClient.make({ httpClient: transport.layer })
      const client = UsernameClient.make({ httpClient: transport.layer })
      const reg = yield* registry

      yield* AtomRegistry.mount(reg, auth.session)
      const before = yield* waitFor(reg, auth.session, AsyncResult.isFailure)
      assert.isTrue(AsyncResult.isFailure(before))

      yield* AuthClient.run(client.signIn, {
        username: "ada",
        password: Redacted.make("correct horse battery staple")
      }).pipe(Effect.provideService(AtomRegistry.AtomRegistry, reg))

      // Nothing refreshed it by hand: the "auth.session" reactivity key the
      // plugin's client shares with AuthClient did it.
      const after = yield* waitFor(reg, auth.session, AsyncResult.isSuccess)
      assert.isTrue(AsyncResult.isSuccess(after))
      if (AsyncResult.isSuccess(after)) {
        assert.strictEqual(after.value.user.email, "ada@example.com")
      }
      assert.deepStrictEqual(transport.calls, ["GET /auth/session", "POST /auth/username/sign-in", "GET /auth/session"])
    })
  )
})
