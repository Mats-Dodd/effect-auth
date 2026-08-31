/**
 * `effect-auth/client` — the browser entry point.
 *
 * **Details**
 *
 * Nothing reachable from here imports a node builtin, a database driver or a
 * password hasher: the client is built from the API *declaration* plus `fetch`,
 * so bundling it into a page pulls in schemas and atoms only.
 *
 * **Example**
 *
 * ```ts
 * import { Redacted } from "effect"
 * import { AtomRegistry } from "effect/unstable/reactivity"
 * import { AuthClient } from "effect-auth/client"
 *
 * const client = AuthClient.make({ baseUrl: "http://localhost:3000" })
 * const registry = AtomRegistry.make()
 *
 * registry.mount(client.session)
 * registry.set(client.signIn, {
 *   email: "ada@example.com",
 *   password: Redacted.make("correct horse battery staple")
 * })
 * ```
 *
 * @since 1.0.0
 */

export * as AuthClient from "./AuthClient.js"

/**
 * The magic link plugin's client, for a deployment that serves
 * `MagicLink.MagicLinkApiGroup`.
 *
 * It is a client of its own rather than members on `AuthClient`, exactly as the
 * plugin is a module of its own on the server: an application that does not serve
 * magic links never imports it, and never ships it to a browser.
 *
 * @since 1.0.0
 */
export * as MagicLinkClient from "./MagicLinkClient.js"

/**
 * The reactivity primitives the client's atoms are built from, re-exported so
 * that an application reads results with exactly the version of `effect` the
 * atoms were created by.
 *
 * `AsyncResult.matchWithError` is the one to reach for: `AtomHttpApi` turns
 * transport and decode failures into defects, so a UI wants `onError` and
 * `onDefect` separated rather than the single `onFailure` of `AsyncResult.match`.
 *
 * @since 1.0.0
 */
export { AsyncResult, Atom, AtomRegistry } from "effect/unstable/reactivity"
