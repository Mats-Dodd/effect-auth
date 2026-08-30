import { assert, describe, it } from "@effect/vitest"
import { Effect, Redacted, Result } from "effect"
import { AsyncResult, Atom, AtomRegistry } from "effect/unstable/reactivity"
import { AuthClient } from "../../src/client/index.js"
import * as Stub from "./stub.js"

/**
 * A registry that is disposed when the test's scope closes.
 */
const registry = Effect.acquireRelease(
  Effect.sync(() => AtomRegistry.make()),
  (_) => Effect.sync(() => _.dispose())
)

/**
 * Waits until an atom's value satisfies a predicate, resolving immediately when
 * it already does.
 *
 * Mutation results and query refetches settle on the registry's scheduler, so a
 * test cannot read them straight after writing: it has to wait for the value it
 * expects, which is also what a rendered view does.
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
      return
    }
    cancel = reg.subscribe(atom, (value) => {
      if (predicate(value)) finish(value)
    })
    if (done) cancel()
    return Effect.sync(() => cancel?.())
  })

const settled = <A, E>(result: AsyncResult.AsyncResult<A, E>): boolean =>
  result._tag !== "Initial" && !result.waiting

const password = Redacted.make("correct horse battery staple")

describe("AuthClient", () => {
  it.effect("the session query resolves for a signed-in caller", () =>
    Effect.gen(function*() {
      const stub = Stub.make({ signedIn: true })
      const client = AuthClient.make({ httpClient: stub.layer })
      const reg = yield* registry

      const session = yield* Atom.getResult(client.session).pipe(
        Effect.provideService(AtomRegistry.AtomRegistry, reg)
      )

      assert.strictEqual(session.user.email, "ada@example.com")
      assert.strictEqual(session.session.userId, session.user.id)
      assert.deepStrictEqual(stub.calls, ["GET /auth/session"])
      // `tokenHash` is Model.Sensitive: it is absent from the wire and from the type.
      assert.isFalse(Object.hasOwn(session.session, "tokenHash"))
    }))

  it.effect("the session query fails with Unauthorized when signed out", () =>
    Effect.gen(function*() {
      const stub = Stub.make()
      const client = AuthClient.make({ httpClient: stub.layer })
      const reg = yield* registry

      const result = yield* Atom.getResult(client.session).pipe(
        Effect.result,
        Effect.provideService(AtomRegistry.AtomRegistry, reg)
      )

      assert.isTrue(Result.isFailure(result))
      if (Result.isFailure(result)) {
        assert.strictEqual(result.failure._tag, "Unauthorized")
      }
    }))

  it.effect("signIn invalidates the session atom, which refetches", () =>
    Effect.gen(function*() {
      const stub = Stub.make()
      const client = AuthClient.make({ httpClient: stub.layer })
      const reg = yield* registry
      yield* AtomRegistry.mount(reg, client.session)

      // The visitor arrives signed out.
      const before = yield* waitFor(reg, client.session, settled)
      assert.isTrue(AsyncResult.isFailure(before))
      assert.strictEqual(stub.countOf("GET /auth/session"), 1)

      const signedIn = yield* AuthClient.run(client.signIn, {
        email: "ada@example.com",
        password
      }).pipe(Effect.provideService(AtomRegistry.AtomRegistry, reg))
      assert.strictEqual(signedIn.user.email, "ada@example.com")

      // Nothing refreshed the session atom by hand: the "auth.session"
      // reactivity key on the mutation did it.
      const after = yield* waitFor(reg, client.session, AsyncResult.isSuccess)
      assert.isTrue(AsyncResult.isSuccess(after))
      if (AsyncResult.isSuccess(after)) {
        assert.strictEqual(after.value.user.email, "ada@example.com")
      }
      assert.strictEqual(stub.countOf("GET /auth/session"), 2)
      assert.deepStrictEqual(stub.calls, [
        "GET /auth/session",
        "POST /auth/sign-in/email",
        "GET /auth/session"
      ])
    }))

  it.effect("signOut invalidates the session atom, which refetches as Unauthorized", () =>
    Effect.gen(function*() {
      const stub = Stub.make({ signedIn: true })
      const client = AuthClient.make({ httpClient: stub.layer })
      const reg = yield* registry
      yield* AtomRegistry.mount(reg, client.session)

      const before = yield* waitFor(reg, client.session, AsyncResult.isSuccess)
      assert.isTrue(AsyncResult.isSuccess(before))

      const ok = yield* AuthClient.run(client.signOut, undefined).pipe(
        Effect.provideService(AtomRegistry.AtomRegistry, reg)
      )
      assert.isTrue(ok.success)

      const after = yield* waitFor(reg, client.session, AsyncResult.isFailure)
      assert.isTrue(AsyncResult.isFailure(after))
      assert.strictEqual(stub.countOf("GET /auth/session"), 2)
    }))

  it.effect("a query keyed on the session refetches too", () =>
    Effect.gen(function*() {
      const stub = Stub.make()
      const client = AuthClient.make({ httpClient: stub.layer })
      const reg = yield* registry
      yield* AtomRegistry.mount(reg, client.sessions)

      const before = yield* waitFor(reg, client.sessions, settled)
      assert.isTrue(AsyncResult.isFailure(before))

      yield* AuthClient.run(client.signIn, { email: "ada@example.com", password }).pipe(
        Effect.provideService(AtomRegistry.AtomRegistry, reg)
      )

      const after = yield* waitFor(reg, client.sessions, AsyncResult.isSuccess)
      assert.isTrue(AsyncResult.isSuccess(after))
      if (AsyncResult.isSuccess(after)) {
        assert.strictEqual(after.value.length, 1)
      }
      assert.strictEqual(stub.countOf("GET /auth/sessions"), 2)
    }))

  it.effect("a declared endpoint error stays a typed error", () =>
    Effect.gen(function*() {
      const stub = Stub.make()
      stub.rejectCredentials()
      const client = AuthClient.make({ httpClient: stub.layer })
      const reg = yield* registry

      const result = yield* AuthClient.run(client.signIn, {
        email: "ada@example.com",
        password
      }).pipe(Effect.result, Effect.provideService(AtomRegistry.AtomRegistry, reg))

      assert.isTrue(Result.isFailure(result))
      if (Result.isFailure(result)) {
        assert.strictEqual(result.failure._tag, "InvalidCredentials")
      }
    }))

  it.effect("a transport failure is a defect, and matchWithError separates it", () =>
    Effect.gen(function*() {
      const stub = Stub.make()
      stub.breakTransport()
      const client = AuthClient.make({ httpClient: stub.layer })
      const reg = yield* registry
      yield* AtomRegistry.mount(reg, client.session)

      const result = yield* waitFor(reg, client.session, settled)

      const rendered = AsyncResult.matchWithError(result, {
        onInitial: () => "loading",
        onSuccess: () => "signed in",
        onError: (error) => `error:${error._tag}`,
        onDefect: () => "defect"
      })
      assert.strictEqual(rendered, "defect")
    }))

  it.effect("signInSocialUrl answers the authorization URL", () =>
    Effect.gen(function*() {
      const stub = Stub.make()
      const client = AuthClient.make({ httpClient: stub.layer })
      const reg = yield* registry

      const url = yield* client.signInSocialUrl({ providerId: "github" }).pipe(
        Effect.provideService(AtomRegistry.AtomRegistry, reg)
      )

      assert.strictEqual(url, "https://github.test/login/oauth/authorize?state=abc")
      assert.deepStrictEqual(stub.calls, ["POST /auth/sign-in/social"])
    }))

  it.effect("the client middleware attaches a bearer token when one is configured", () =>
    Effect.gen(function*() {
      const stub = Stub.make({ signedIn: true })
      const client = AuthClient.make({
        httpClient: stub.layer,
        bearerToken: () => Redacted.make("opaque-session-token")
      })
      const reg = yield* registry

      yield* Atom.getResult(client.session).pipe(
        Effect.provideService(AtomRegistry.AtomRegistry, reg)
      )

      assert.strictEqual(stub.lastAuthorization(), "Bearer opaque-session-token")
    }))

  it.effect("no bearer token means no Authorization header — the cookie carries the session", () =>
    Effect.gen(function*() {
      const stub = Stub.make({ signedIn: true })
      const client = AuthClient.make({ httpClient: stub.layer })
      const reg = yield* registry

      yield* Atom.getResult(client.session).pipe(
        Effect.provideService(AtomRegistry.AtomRegistry, reg)
      )

      assert.strictEqual(stub.lastAuthorization(), undefined)
    }))

  it.effect("mutations are shared per client, so two reads see one in-flight request", () =>
    Effect.gen(function*() {
      const stub = Stub.make()
      const client = AuthClient.make({ httpClient: stub.layer })
      const reg = yield* registry

      yield* AuthClient.run(client.signUp, {
        name: "Ada Lovelace",
        email: "ada@example.com",
        password
      }).pipe(Effect.provideService(AtomRegistry.AtomRegistry, reg))

      const result = reg.get(client.signUp)
      assert.isTrue(AsyncResult.isSuccess(result))
      assert.strictEqual(stub.countOf("POST /auth/sign-up/email"), 1)
    }))
})
