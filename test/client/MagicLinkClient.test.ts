import { assert, describe, it } from "@effect/vitest"
import { Effect, Redacted, Result } from "effect"
import { AsyncResult, type Atom, AtomRegistry } from "effect/unstable/reactivity"
import { AuthClient, MagicLinkClient } from "../../src/client/index.js"
import * as Stub from "./stub.js"

/**
 * A registry that is disposed when the test's scope closes.
 */
const registry = Effect.acquireRelease(
  Effect.sync(() => AtomRegistry.make()),
  (_) => Effect.sync(() => _.dispose())
)

/**
 * A magic link client over a fresh stub transport, an `AuthClient` over the
 * *same* transport, and the registry both run in.
 *
 * The two clients are deliberately separate — they own separate atom runtimes,
 * exactly as an application's would — because the interesting claim is that they
 * share reactivity *keys*.
 */
const harness = () =>
  Effect.gen(function* () {
    const stub = Stub.make()
    const magicLink = MagicLinkClient.make({ httpClient: stub.layer })
    const auth = AuthClient.make({ httpClient: stub.layer })
    const reg = yield* registry
    return { stub, magicLink, auth, reg } as const
  })

/**
 * Waits until an atom's value satisfies a predicate, resolving immediately when
 * it already does. Mutation results and query refetches settle on the registry's
 * scheduler, so a test cannot read them straight after writing.
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
      // Nothing was subscribed, so there is nothing for the finalizer to undo.
      return Effect.void
    }
    cancel = reg.subscribe(atom, (value) => {
      if (predicate(value)) finish(value)
    })
    if (done) cancel()
    return Effect.sync(() => cancel?.())
  })

const settled = <A, E>(result: AsyncResult.AsyncResult<A, E>): boolean => result._tag !== "Initial" && !result.waiting

describe("MagicLinkClient", () => {
  it.effect("asks for a link with the payload alone", () =>
    Effect.gen(function* () {
      const { magicLink, reg, stub } = yield* harness()

      const answer = yield* AuthClient.run(magicLink.signIn, {
        email: "ada@example.com",
        callbackURL: "/welcome"
      }).pipe(Effect.provideService(AtomRegistry.AtomRegistry, reg))

      assert.deepStrictEqual(answer, { success: true })
      assert.deepStrictEqual(stub.calls, ["POST /auth/magic-link/sign-in"])
    })
  )

  it.effect("exchanges a token for a session", () =>
    Effect.gen(function* () {
      const { magicLink, reg } = yield* harness()

      const result = yield* AuthClient.run(magicLink.exchange, {
        token: Redacted.make("a-token")
      }).pipe(Effect.provideService(AtomRegistry.AtomRegistry, reg))

      assert.strictEqual(result.user.email, "ada@example.com")
      assert.strictEqual(result.session.userId, result.user.id)
      // `tokenHash` is Model.Sensitive: absent from the wire and from the type.
      assert.isFalse(Object.hasOwn(result.session, "tokenHash"))
    })
  )

  it.effect("reports a spent link as InvalidToken", () =>
    Effect.gen(function* () {
      const { magicLink, reg, stub } = yield* harness()
      stub.rejectMagicLink()

      const result = yield* AuthClient.run(magicLink.exchange, {
        token: Redacted.make("already-spent")
      }).pipe(Effect.result, Effect.provideService(AtomRegistry.AtomRegistry, reg))

      assert.isTrue(Result.isFailure(result))
      if (Result.isFailure(result)) {
        // The declared error union, decoded — not a defect.
        assert.strictEqual(result.failure._tag, "InvalidToken")
      }
    })
  )

  it.effect("refetches an AuthClient's session atom when a link is exchanged", () =>
    Effect.gen(function* () {
      const { auth, magicLink, reg, stub } = yield* harness()
      yield* AtomRegistry.mount(reg, auth.session)

      // The visitor arrives signed out.
      const before = yield* waitFor(reg, auth.session, settled)
      assert.isTrue(AsyncResult.isFailure(before))
      assert.strictEqual(stub.countOf("GET /auth/session"), 1)

      yield* AuthClient.run(magicLink.exchange, { token: Redacted.make("a-token") }).pipe(
        Effect.provideService(AtomRegistry.AtomRegistry, reg)
      )

      // Nothing refreshed the session atom by hand: the "auth.session"
      // reactivity key the two clients share did it, across two atom runtimes.
      const after = yield* waitFor(reg, auth.session, AsyncResult.isSuccess)
      assert.isTrue(AsyncResult.isSuccess(after))
      assert.strictEqual(stub.countOf("GET /auth/session"), 2)
    })
  )

  describe("verifyUrl", () => {
    it("is path-relative when the client has no baseUrl, and escapes the token", () => {
      const client = MagicLinkClient.make()
      // A subject token is `base64url(subject).secret`, so nothing here needs
      // escaping in practice — which is exactly why it is worth pinning that it
      // is escaped anyway.
      assert.strictEqual(client.verifyUrl("a token"), "/auth/magic-link/verify?token=a%20token")
    })

    it("is absolute against the baseUrl the client was given", () => {
      const client = MagicLinkClient.make({ baseUrl: "https://app.test" })
      assert.strictEqual(client.verifyUrl("a-token"), "https://app.test/auth/magic-link/verify?token=a-token")
    })
  })
})
