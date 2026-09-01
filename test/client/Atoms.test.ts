/**
 * The atom wrappers, as a plugin's client reaches them: through
 * `effect-auth/client`.
 *
 * **Details**
 *
 * The wrappers are a translation of an atom's *argument*, and that is all they
 * are: the underlying atom is read for its `AsyncResult`, and a write is encoded
 * into the whole client request before being passed on. So the assertions here
 * are about what the wrapped atom writes to the atom underneath it — with a
 * hand-made writable atom in place of `AtomHttpApi.mutation`'s, which is what
 * lets the test see the request rather than the response.
 *
 * The control symbols are the part worth pinning: an `AtomResultFn` accepts
 * `Atom.Reset` and `Atom.Interrupt` beside its argument, and a wrapper that
 * encoded those into a request would leave every wrapped atom unresettable.
 */
import { assert, describe, it } from "@effect/vitest"
import { AsyncResult, Atom, AtomRegistry } from "effect/unstable/reactivity"
import { AuthAtoms } from "../../src/client/index.js"

interface Credentials {
  readonly email: string
}

/**
 * An atom shaped like `AtomHttpApi.mutation`'s — an `AsyncResult` to read, and a
 * write channel that takes the whole client request — which records what it was
 * written rather than issuing it.
 */
const recording = <Req>(): {
  readonly atom: Atom.AtomResultFn<Req, string>
  readonly writes: Array<Req | Atom.Reset | Atom.Interrupt>
} => {
  const writes: Array<Req | Atom.Reset | Atom.Interrupt> = []
  const atom = Atom.writable<AsyncResult.AsyncResult<string>, Req | Atom.Reset | Atom.Interrupt>(
    () => AsyncResult.initial(),
    (_ctx, value) => {
      writes.push(value)
    }
  )
  return { atom, writes }
}

const registry = (): AtomRegistry.AtomRegistry => AtomRegistry.make()

describe("client/Atoms", () => {
  it("is reachable from the client entry point", () => {
    // The wave's actual deliverable: a plugin's client is written outside this
    // package and builds its atoms with exactly these.
    assert.isFunction(AuthAtoms.rewrite)
    assert.isFunction(AuthAtoms.withPayload)
    assert.isFunction(AuthAtoms.withQuery)
    assert.isFunction(AuthAtoms.withoutPayload)
    assert.isFunction(AuthAtoms.layerFetch)
  })

  it("withPayload writes the payload and the endpoint's keys", () => {
    const { atom, writes } = recording<AuthAtoms.PayloadRequest<Credentials>>()
    const wrapped = AuthAtoms.withPayload<Credentials>()(atom, ["session"])

    registry().set(wrapped, { email: "ada@example.com" })

    assert.deepStrictEqual(writes, [{ payload: { email: "ada@example.com" }, reactivityKeys: ["session"] }])
  })

  it("withQuery writes the query and the endpoint's keys", () => {
    const { atom, writes } = recording<AuthAtoms.QueryRequest<{ readonly token: string }>>()
    const wrapped = AuthAtoms.withQuery<{ readonly token: string }>()(atom, ["session"])

    registry().set(wrapped, { token: "abc" })

    assert.deepStrictEqual(writes, [{ query: { token: "abc" }, reactivityKeys: ["session"] }])
  })

  it("withoutPayload writes nothing but the keys", () => {
    const { atom, writes } = recording<AuthAtoms.Keyed>()
    const wrapped = AuthAtoms.withoutPayload(atom, { session: ["current"] })

    registry().set(wrapped, undefined)

    assert.deepStrictEqual(writes, [{ reactivityKeys: { session: ["current"] } }])
  })

  it("carries an endpoint that invalidates nothing", () => {
    const { atom, writes } = recording<AuthAtoms.PayloadRequest<Credentials>>()
    const wrapped = AuthAtoms.withPayload<Credentials>()(atom, undefined)

    registry().set(wrapped, { email: "ada@example.com" })

    assert.deepStrictEqual(writes, [{ payload: { email: "ada@example.com" }, reactivityKeys: undefined }])
  })

  it("passes the control symbols through untranslated", () => {
    const { atom, writes } = recording<AuthAtoms.PayloadRequest<Credentials>>()
    const wrapped = AuthAtoms.withPayload<Credentials>()(atom, ["session"])
    const reg = registry()

    reg.set(wrapped, Atom.Reset)
    reg.set(wrapped, Atom.Interrupt)

    // A wrapper that encoded these into a request would leave every wrapped
    // atom unresettable and uninterruptible.
    assert.deepStrictEqual(writes, [Atom.Reset, Atom.Interrupt])
  })

  it("reads the atom underneath, so it holds the same AsyncResult", () => {
    const { atom } = recording<AuthAtoms.PayloadRequest<Credentials>>()
    const wrapped = AuthAtoms.withPayload<Credentials>()(atom, ["session"])
    const reg = registry()

    assert.deepStrictEqual(reg.get(wrapped), reg.get(atom))
  })

  it("rewrite encodes an argument of any shape", () => {
    const { atom, writes } = recording<AuthAtoms.PayloadRequest<Credentials>>()
    const wrapped = AuthAtoms.rewrite<AuthAtoms.PayloadRequest<Credentials>, string, string, never>(atom, (email) => ({
      payload: { email },
      reactivityKeys: ["session"]
    }))

    registry().set(wrapped, "ada@example.com")

    assert.deepStrictEqual(writes, [{ payload: { email: "ada@example.com" }, reactivityKeys: ["session"] }])
  })
})
