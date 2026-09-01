/**
 * The anonymous client's two atoms against a stubbed transport.
 *
 * The point is the generated client's real encoding and decoding without a
 * socket: that becoming a visitor sends an empty body — there is no field a
 * caller could put a user id in — that discarding one surfaces the refusal a
 * real account gets, and that both refetch the session an `AuthClient` built
 * beside this one holds.
 */
import { assert, describe, it } from "@effect/vitest"
import { Effect, Layer } from "effect"
import type { HttpClientError } from "effect/unstable/http"
import { HttpClient, HttpClientResponse } from "effect/unstable/http"
import type { Atom } from "effect/unstable/reactivity"
import { AsyncResult, AtomRegistry } from "effect/unstable/reactivity"
import * as AnonymousClient from "../../src/client/AnonymousClient.js"
import * as AuthClient from "../../src/client/AuthClient.js"

const now = "2024-01-01T00:00:00.000Z"

const sessionWithUserJson = {
  user: {
    id: "0192e5a0-0000-7000-8000-000000000002",
    name: "Anonymous",
    email: "anon-0192e5a0-0000-7000-8000-000000000002@anonymous.invalid",
    emailVerified: false,
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
    // The whole of how a visitor is told apart from a person.
    aal: "aal0",
    methods: "[]",
    rememberMe: false,
    createdAt: now,
    updatedAt: now
  }
}

const json = (status: number, body: unknown): Response =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } })

const preprocess: HttpClient.HttpClient.Preprocess<HttpClientError.HttpClientError, never> = Effect.succeed

const stub = (routes: Record<string, () => Response>) => {
  const calls: Array<string> = []
  const bodies: Array<string> = []
  const client = HttpClient.makeWith(
    Effect.fnUntraced(function* (requestEffect) {
      const request = yield* requestEffect
      const path = new URL(request.url, "http://auth.test").pathname
      const key = `${request.method} ${path}`
      calls.push(key)
      const body = request.body
      bodies.push(body._tag === "Uint8Array" ? new TextDecoder().decode(body.body) : "")
      const route = Object.hasOwn(routes, key) ? routes[key] : undefined
      return HttpClientResponse.fromWeb(request, route?.() ?? json(404, { _tag: "NotFound" }))
    }),
    preprocess
  )
  return { layer: Layer.succeed(HttpClient.HttpClient, client), calls, bodies }
}

const registry = Effect.acquireRelease(
  Effect.sync(() => AtomRegistry.make()),
  (made) => Effect.sync(() => made.dispose())
)

/** See `test/username/Client.test.ts`. */
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

describe("AnonymousClient", () => {
  it.effect("becomes a visitor with an empty body and an aal0 session", () =>
    Effect.gen(function* () {
      const transport = stub({ "POST /auth/anonymous/sign-in": () => json(200, sessionWithUserJson) })
      const client = AnonymousClient.make({ httpClient: transport.layer })
      const reg = yield* registry

      const result = yield* AuthClient.run(client.signIn, undefined).pipe(
        Effect.provideService(AtomRegistry.AtomRegistry, reg)
      )

      assert.strictEqual(result.session.aal, "aal0")
      assert.strictEqual(result.user.emailVerified, false)
      assert.deepStrictEqual(transport.calls, ["POST /auth/anonymous/sign-in"])
      // Nothing goes up. There is no field a caller could name somebody in,
      // which is what closes better-auth's `anonymousUserId` injection at the
      // client as well as at the endpoint.
      assert.strictEqual(transport.bodies[0], "")
    })
  )

  it.effect("discards a visitor", () =>
    Effect.gen(function* () {
      const transport = stub({ "POST /auth/anonymous/delete": () => json(200, { success: true }) })
      const client = AnonymousClient.make({ httpClient: transport.layer })
      const reg = yield* registry

      const ok = yield* AuthClient.run(client.delete, undefined).pipe(
        Effect.provideService(AtomRegistry.AtomRegistry, reg)
      )
      assert.isTrue(ok.success)
    })
  )

  it.effect("refuses to destroy an account that has since been adopted", () =>
    Effect.gen(function* () {
      const transport = stub({ "POST /auth/anonymous/delete": () => json(403, { _tag: "NotAnonymous" }) })
      const client = AnonymousClient.make({ httpClient: transport.layer })
      const reg = yield* registry

      const failure = yield* Effect.flip(
        AuthClient.run(client.delete, undefined).pipe(Effect.provideService(AtomRegistry.AtomRegistry, reg))
      )
      // Destroying a real account is /auth/delete-user's job, with the
      // confirmation that endpoint requires.
      assert.strictEqual(failure._tag, "NotAnonymous")
    })
  )

  it.effect("refetches the session atom of an AuthClient built beside it", () =>
    Effect.gen(function* () {
      let signedIn = false
      const transport = stub({
        "GET /auth/session": () => (signedIn ? json(200, sessionWithUserJson) : json(401, { _tag: "Unauthorized" })),
        "POST /auth/anonymous/sign-in": () => {
          signedIn = true
          return json(200, sessionWithUserJson)
        },
        "POST /auth/anonymous/delete": () => {
          signedIn = false
          return json(200, { success: true })
        }
      })
      const auth = AuthClient.make({ httpClient: transport.layer })
      const client = AnonymousClient.make({ httpClient: transport.layer })
      const reg = yield* registry

      yield* AtomRegistry.mount(reg, auth.session)
      yield* waitFor(reg, auth.session, AsyncResult.isFailure)

      yield* AuthClient.run(client.signIn, undefined).pipe(Effect.provideService(AtomRegistry.AtomRegistry, reg))
      const after = yield* waitFor(reg, auth.session, AsyncResult.isSuccess)
      assert.isTrue(AsyncResult.isSuccess(after))

      // And discarding the visitor puts it back: the account is gone, so
      // anything derived from "who is signed in" is wrong until it refetches.
      yield* AuthClient.run(client.delete, undefined).pipe(Effect.provideService(AtomRegistry.AtomRegistry, reg))
      const gone = yield* waitFor(reg, auth.session, AsyncResult.isFailure)
      assert.isTrue(AsyncResult.isFailure(gone))

      assert.deepStrictEqual(transport.calls, [
        "GET /auth/session",
        "POST /auth/anonymous/sign-in",
        "GET /auth/session",
        "POST /auth/anonymous/delete",
        "GET /auth/session"
      ])
    })
  )
})
