/**
 * The wrappers every generated-client module in this package builds its atoms
 * with.
 *
 * **Details**
 *
 * `AtomHttpApi.mutation` hands back an atom whose argument is the *whole* client
 * request (`{ payload, query, params, headers, … }`) plus the reactivity keys to
 * invalidate. What an application wants to write is the payload alone, with the
 * keys of that endpoint already decided. These four combinators are that
 * translation, and they live here rather than in `AuthClient.ts` because the
 * magic link client — and every plugin client after it — needs exactly the same
 * three lines.
 *
 * Nothing here is exported from the package: it is shared internals, and the
 * shapes it names (`PayloadRequest`, `QueryRequest`) are re-exported by the
 * client modules that use them in a public signature.
 *
 * @internal
 */
import type { Record } from "effect"
import type { AsyncResult } from "effect/unstable/reactivity"
import { Atom } from "effect/unstable/reactivity"

/**
 * The shape `Atom` accepts for invalidation keys.
 *
 * @internal
 */
export type ReactivityKeys =
  | ReadonlyArray<unknown>
  | Record.ReadonlyRecord<string, ReadonlyArray<unknown>>

/**
 * The part of a mutation atom's argument every wrapper below writes.
 *
 * `AtomHttpApi.mutation` computes its argument as
 * `Simplify<ClientRequest<…> & { reactivityKeys?: … }>`, which names nothing
 * that can be written down here. It does not have to be: an `AtomResultFn` is
 * contravariant in its argument, so a wrapper that declares only the fields it
 * writes accepts exactly those atoms whose request those fields satisfy — an
 * endpoint with a required `params` or `query` is rejected at the call site
 * rather than at runtime, which is what the `any` this replaced gave away.
 *
 * @internal
 */
export interface Keyed {
  readonly reactivityKeys?: ReactivityKeys | undefined
}

/**
 * A mutation whose request carries a payload and nothing else required.
 *
 * @internal
 */
export interface PayloadRequest<P> extends Keyed {
  readonly payload: P
}

/**
 * A mutation whose request carries query parameters and nothing else required.
 *
 * @internal
 */
export interface QueryRequest<Q> extends Keyed {
  readonly query: Q
}

const isControl = (u: unknown): u is Atom.Reset | Atom.Interrupt => u === Atom.Reset || u === Atom.Interrupt

/**
 * Rewrites a mutation atom's argument.
 *
 * `AtomHttpApi.mutation` takes the whole client request plus the reactivity
 * keys; a caller should pass the payload and nothing else, with the keys of the
 * endpoint baked in. The wrapper reads the underlying atom — so it holds the
 * same `AsyncResult` — and translates writes.
 *
 * @internal
 */
export const rewrite = <Req, Arg, A, E>(
  self: Atom.AtomResultFn<Req, A, E>,
  encode: (arg: Arg) => Req
): Atom.AtomResultFn<Arg, A, E> =>
  Atom.writable<AsyncResult.AsyncResult<A, E>, Arg | Atom.Reset | Atom.Interrupt>(
    (get) => get(self),
    (ctx, value) => {
      ctx.set(self, isControl(value) ? value : encode(value))
    }
  )

/**
 * A mutation an application drives with the payload alone.
 *
 * @internal
 */
export const withPayload = <P>() =>
<A, E>(
  self: Atom.AtomResultFn<PayloadRequest<P>, A, E>,
  reactivityKeys: ReactivityKeys | undefined
): Atom.AtomResultFn<P, A, E> =>
  rewrite<PayloadRequest<P>, P, A, E>(self, (payload) => ({ payload, reactivityKeys }))

/**
 * A mutation an application drives with the query parameters alone.
 *
 * @internal
 */
export const withQuery = <Q>() =>
<A, E>(
  self: Atom.AtomResultFn<QueryRequest<Q>, A, E>,
  reactivityKeys: ReactivityKeys | undefined
): Atom.AtomResultFn<Q, A, E> =>
  rewrite<QueryRequest<Q>, Q, A, E>(self, (query) => ({ query, reactivityKeys }))

/**
 * A mutation with no request of its own.
 *
 * @internal
 */
export const withoutPayload = <A, E>(
  self: Atom.AtomResultFn<Keyed, A, E>,
  reactivityKeys: ReactivityKeys | undefined
): Atom.AtomResultFn<void, A, E> => rewrite<Keyed, void, A, E>(self, () => ({ reactivityKeys }))
