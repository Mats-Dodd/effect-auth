/**
 * The two-factor plugin: time-based one-time codes, recovery codes and
 * remembered browsers.
 *
 * **Details**
 *
 * The shape every plugin in this library follows — a browser-safe API module
 * (`Api.ts`), a service with its own configuration and its own mailer seam
 * (`TwoFactor.ts`), handlers built with `AuthHandlers.forGroup`
 * (`Handlers.ts`) — plus the two things a plugin that owns tables adds: its own
 * migration set, numbered from `0001` under a bookkeeping table of its own, and
 * its own persistence seam.
 *
 * **Gotchas — this plugin is installed in two places, and both are required**
 *
 * {@link layerSeams} goes **underneath** `Auth.layer`: it installs the
 * `SignInPipeline` decider that turns a first factor into a challenge and the
 * `Authenticators` contributor that stops `Accounts.unlink` and the reclaim
 * path from ignoring a second factor. Both are `Context.Reference`s, read when
 * the services that consult them are *built*, so one provided above the
 * deployment would never be seen.
 *
 * {@link layer} goes **over** it, like any other plugin: it is what the
 * endpoints call.
 *
 * **Example**
 *
 * ```ts skip-type-checking
 * import { Layer } from "effect"
 * import { HttpApi } from "effect/unstable/httpapi"
 * import { Auth, AuthApi, AuthHandlers, Migrations, TwoFactor } from "effect-auth"
 *
 * const options = { baseUrl, secret, emailPassword: { enabled: true } }
 *
 * // Underneath: the two seams, over the same configuration and the same database.
 * const Seams = TwoFactor.layerSeams().pipe(
 *   Layer.provide(Layer.merge(Auth.layerConfigOnly(options), PgLive))
 * )
 *
 * const AuthLive = Auth.layer(options).pipe(
 *   Layer.provide(Seams),
 *   Layer.provide(PgLive),
 *   Layer.provide(MyMailer)
 * )
 *
 * // Over the top: the service, its mailer, and its tables.
 * const TwoFactorLive = TwoFactor.layer().pipe(
 *   Layer.provideMerge(AuthLive),
 *   Layer.provide(MyTwoFactorMailer)
 * )
 *
 * const AppApi = HttpApi.make("app").addHttpApi(AuthApi).add(TwoFactor.TwoFactorApiGroup)
 * const HandlersLive = Layer.mergeAll(
 *   AuthHandlers.layer(AppApi),
 *   TwoFactor.handlers(AppApi)
 * ).pipe(Layer.provide(TwoFactorLive))
 *
 * // The tables, sequenced under this library's own.
 * const SchemaLive = TwoFactor.Migrations.layer.pipe(Layer.provide(Migrations.layer))
 * ```
 *
 * @since 0.2.0
 */
export * from "./Api.js"
export * from "./Handlers.js"
export * from "./Schema.js"
export * from "./TwoFactor.js"

/**
 * The three tables this plugin owns, as a migration set of its own. The
 * consumer composes it; nothing registers it globally.
 *
 * @since 0.2.0
 */
export * as Migrations from "./Migrations.js"

/**
 * What a recovery code looks like, and how one is read back.
 *
 * @since 0.2.0
 */
export * as RecoveryCodes from "./RecoveryCodes.js"

export { layer as layerStore, make as makeStore, TwoFactorStore, type TwoFactorStoreService } from "./Store.js"
