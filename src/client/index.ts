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
 * @since 0.1.0
 */

export * as AuthClient from "./AuthClient.js"

/**
 * The wrappers this package's own clients build their atoms with, and the
 * `fetch` transport under them.
 *
 * A plugin's client is a generated client of its own over the plugin's own
 * group, and these are what make it read like `AuthClient` at the call site:
 * `AuthAtoms.withPayload<P>()(client.mutation(…), keys)` turns an atom that
 * takes a whole client request into one an application drives with the payload
 * alone. `AuthAtoms.layerFetch` is the transport both clients share, so an
 * application holding two of them cannot end up with two different opinions
 * about cookies.
 *
 * @since 0.1.0
 */
export * as AuthAtoms from "./Atoms.js"

/**
 * A client per plugin, for a deployment that serves that plugin's group.
 *
 * Each is a client of its own rather than members on `AuthClient`, exactly as
 * the plugin is a module of its own on the server: an application that does not
 * serve passkeys never imports `PasskeysClient`, and never ships it to a
 * browser. They share `AuthClient`'s reactivity keys, so an application holding
 * two of them sees its session atom refetch by itself after a sign-in through
 * either.
 *
 * @since 0.2.0
 */
export * as AnonymousClient from "./AnonymousClient.js"
export * as EmailOtpClient from "./EmailOtpClient.js"
export * as OneTapClient from "./OneTapClient.js"
export * as PasskeysClient from "./PasskeysClient.js"
export * as PhoneClient from "./PhoneClient.js"
export * as TwoFactorClient from "./TwoFactorClient.js"
export * as UsernameClient from "./UsernameClient.js"

/**
 * The reactivity primitives the client's atoms are built from, re-exported so
 * that an application reads results with exactly the version of `effect` the
 * atoms were created by.
 *
 * `AsyncResult.matchWithError` is the one to reach for: `AtomHttpApi` turns
 * transport and decode failures into defects, so a UI wants `onError` and
 * `onDefect` separated rather than the single `onFailure` of `AsyncResult.match`.
 *
 * @since 0.1.0
 */
export { AsyncResult, Atom, AtomRegistry } from "effect/unstable/reactivity"
