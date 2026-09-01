/**
 * The wrappers every generated-client module in this package builds its atoms
 * with, and the transport they are built on.
 *
 * **Details**
 *
 * `AtomHttpApi.mutation` hands back an atom whose argument is the *whole* client
 * request (`{ payload, query, params, headers, … }`) plus the reactivity keys to
 * invalidate. What an application wants to write is the payload alone, with the
 * keys of that endpoint already decided. These four combinators are that
 * translation, and they live here rather than in `AuthClient.ts` because the
 * email-otp client — and every plugin client after it — needs exactly the same
 * three lines.
 *
 * **When to use**
 *
 * From the client of a plugin outside this package, which is a generated client
 * of its own over the plugin's own `HttpApiGroup`. Building its atoms with
 * these is what makes it read like `AuthClient`'s at the call site —
 * `registry.set(client.verify, payload)` — and what makes the two agree about
 * cookies, because {@link layerFetch} is the transport under each of them.
 *
 * @since 0.1.0
 */
import type { Record } from "effect"
import { Layer } from "effect"
import type { HttpClient } from "effect/unstable/http"
import { FetchHttpClient } from "effect/unstable/http"
import type { AsyncResult } from "effect/unstable/reactivity"
import { Atom } from "effect/unstable/reactivity"

/**
 * The shape `Atom` accepts for invalidation keys.
 *
 * @category models
 * @since 0.1.0
 */
export type ReactivityKeys = ReadonlyArray<unknown> | Record.ReadonlyRecord<string, ReadonlyArray<unknown>>

/**
 * The part of a mutation atom's argument every wrapper below writes.
 *
 * **Details**
 *
 * `AtomHttpApi.mutation` computes its argument as
 * `Simplify<ClientRequest<…> & { reactivityKeys?: … }>`, which names nothing
 * that can be written down here. It does not have to be: an `AtomResultFn` is
 * contravariant in its argument, so a wrapper that declares only the fields it
 * writes accepts exactly those atoms whose request those fields satisfy — an
 * endpoint with a required `params` or `query` is rejected at the call site
 * rather than at runtime, which is what the `any` this replaced gave away.
 *
 * @category models
 * @since 0.1.0
 */
export interface Keyed {
  readonly reactivityKeys?: ReactivityKeys | undefined
}

/**
 * A mutation whose request carries a payload and nothing else required.
 *
 * @category models
 * @since 0.1.0
 */
export interface PayloadRequest<P> extends Keyed {
  readonly payload: P
}

/**
 * A mutation whose request carries query parameters and nothing else required.
 *
 * @category models
 * @since 0.1.0
 */
export interface QueryRequest<Q> extends Keyed {
  readonly query: Q
}

const isControl = (u: unknown): u is Atom.Reset | Atom.Interrupt => u === Atom.Reset || u === Atom.Interrupt

/**
 * Rewrites a mutation atom's argument.
 *
 * **Details**
 *
 * `AtomHttpApi.mutation` takes the whole client request plus the reactivity
 * keys; a caller should pass the payload and nothing else, with the keys of the
 * endpoint baked in. The wrapper reads the underlying atom — so it holds the
 * same `AsyncResult` — and translates writes.
 *
 * **When to use**
 *
 * Where neither {@link withPayload} nor {@link withQuery} fits: an endpoint
 * that takes path parameters, or one whose client-facing argument is a shape of
 * the plugin's own. `Atom.Reset` and `Atom.Interrupt` pass through
 * untranslated, so a wrapped atom is still resettable.
 *
 * @category combinators
 * @since 0.1.0
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
 * **Example**
 *
 * ```ts skip-type-checking
 * import { AuthAtoms } from "effect-auth/client"
 *
 * const verify = AuthAtoms.withPayload<VerifyPayload>()(client.mutation("otp", "verify"), ["session"])
 * ```
 *
 * @category combinators
 * @since 0.1.0
 */
export const withPayload =
  <P>() =>
  <A, E>(
    self: Atom.AtomResultFn<PayloadRequest<P>, A, E>,
    reactivityKeys: ReactivityKeys | undefined
  ): Atom.AtomResultFn<P, A, E> =>
    rewrite<PayloadRequest<P>, P, A, E>(self, (payload) => ({ payload, reactivityKeys }))

/**
 * A mutation an application drives with the query parameters alone.
 *
 * @category combinators
 * @since 0.1.0
 */
export const withQuery =
  <Q>() =>
  <A, E>(
    self: Atom.AtomResultFn<QueryRequest<Q>, A, E>,
    reactivityKeys: ReactivityKeys | undefined
  ): Atom.AtomResultFn<Q, A, E> =>
    rewrite<QueryRequest<Q>, Q, A, E>(self, (query) => ({ query, reactivityKeys }))

/**
 * A mutation with no request of its own.
 *
 * @category combinators
 * @since 0.1.0
 */
export const withoutPayload = <A, E>(
  self: Atom.AtomResultFn<Keyed, A, E>,
  reactivityKeys: ReactivityKeys | undefined
): Atom.AtomResultFn<void, A, E> => rewrite<Keyed, void, A, E>(self, () => ({ reactivityKeys }))

/**
 * The default transport a generated client is built on: `fetch`, told what to
 * do with cookies.
 *
 * **Details**
 *
 * `credentials: "include"` is what makes the session cookie travel to an API on
 * another origin, and it is the default every client in this package passes. It
 * lives here rather than in one of them because an application may hold two —
 * the auth client and a plugin's — and two transports that disagree about
 * cookies would be two different sign-in behaviours for endpoints of the same
 * deployment.
 *
 * @category layers
 * @since 0.1.0
 */
export const layerFetch = (credentials: RequestCredentials): Layer.Layer<HttpClient.HttpClient> =>
  Layer.provide(FetchHttpClient.layer, Layer.succeed(FetchHttpClient.RequestInit, { credentials }))
