/**
 * The anonymous plugin: a real account for somebody who has told you nothing,
 * and a way to turn that visitor into a person later.
 *
 * **Details**
 *
 * The shape every plugin in this library follows: a browser-safe API module
 * (`Api.ts`), a marker-table seam of its own (`Store.ts`), its own migrations
 * from `0001` (`Migrations.ts`), a domain service (`Anonymous.ts`), and
 * handlers built with `AuthHandlers.forGroup` (`Handlers.ts`).
 *
 * **Example**
 *
 * ```ts skip-type-checking
 * import { Layer } from "effect"
 * import { HttpApi } from "effect/unstable/httpapi"
 * import { Auth, AuthApi, AuthHandlers, Migrations } from "effect-auth"
 * import {
 *   Anonymous,
 *   AnonymousApiGroup,
 *   AnonymousMigrations,
 *   handlers,
 *   layerAnonymousStore,
 *   layerHooks
 * } from "effect-auth/anonymous"
 *
 * // The merge hook goes *underneath* the deployment, because that is where
 * // `AuthHooks` is read.
 * const AuthLive = Auth.layer(options).pipe(
 *   Layer.provide(layerHooks({ onMerge })),
 *   Layer.provide(PgLive),
 *   Layer.provide(MyMailer)
 * )
 *
 * const AnonymousLive = Anonymous.layer().pipe(
 *   Layer.provide(layerAnonymousStore),
 *   Layer.provide(AnonymousMigrations.layer.pipe(Layer.provide(Migrations.layer))),
 *   Layer.provideMerge(AuthLive)
 * )
 *
 * const AppApi = HttpApi.make("app").addHttpApi(AuthApi).add(AnonymousApiGroup)
 *
 * const HandlersLive = Layer.mergeAll(AuthHandlers.layer(AppApi), handlers(AppApi)).pipe(
 *   Layer.provide(AnonymousLive)
 * )
 * ```
 *
 * **Gotchas**
 *
 * Two layers, in two places. `Anonymous.layer` sits *above* the deployment and
 * serves the endpoints; `layerHooks` sits *below* it, because a hook is read
 * when `Auth.layer` is built. A deployment that installs only the first gets
 * anonymous sign-in with no merge-on-sign-in, which is a coherent
 * configuration and not an error — so nothing warns about it, and this is the
 * paragraph that says so.
 *
 * The garbage collection is an `Effect`, `Anonymous.sweep`, and not a running
 * fibre: how often it runs, and on which instance, is the deployment's call.
 *
 * @since 0.2.0
 */
export * from "./Anonymous.js"
export * from "./Api.js"
export * from "./Handlers.js"
export * as AnonymousMigrations from "./Migrations.js"
export * from "./Store.js"
