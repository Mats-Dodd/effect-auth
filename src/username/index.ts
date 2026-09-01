/**
 * The username plugin: signing in with a username and a password instead of an
 * e-mail address.
 *
 * **Details**
 *
 * The shape every plugin in this library follows: a browser-safe API module
 * (`Api.ts`), a storage seam of its own (`Store.ts`), its own migrations from
 * `0001` (`Migrations.ts`), a domain service (`Username.ts`), and handlers
 * built with `AuthHandlers.forGroup` (`Handlers.ts`). There is no plugin object
 * and no registration call — composition is plain layers.
 *
 * **Example**
 *
 * ```ts skip-type-checking
 * import { Layer } from "effect"
 * import { HttpApi } from "effect/unstable/httpapi"
 * import { Auth, AuthApi, AuthHandlers, Migrations } from "effect-auth"
 * import { handlers, layerUsernameStore, Username, UsernameApiGroup, UsernameMigrations } from "effect-auth/username"
 *
 * const AuthLive = Auth.layer(options).pipe(Layer.provide(PgLive), Layer.provide(MyMailer))
 *
 * const UsernameLive = Username.layer({ minLength: 2 }).pipe(
 *   Layer.provide(layerUsernameStore),
 *   // Sequenced after this library's own: the foreign key onto `users` needs
 *   // the table it points at.
 *   Layer.provide(UsernameMigrations.layer.pipe(Layer.provide(Migrations.layer))),
 *   Layer.provideMerge(AuthLive)
 * )
 *
 * const AppApi = HttpApi.make("app").addHttpApi(AuthApi).add(UsernameApiGroup)
 *
 * const HandlersLive = Layer.mergeAll(AuthHandlers.layer(AppApi), handlers(AppApi)).pipe(
 *   Layer.provide(UsernameLive)
 * )
 * ```
 *
 * **Gotchas**
 *
 * The plugin owns a table, so a deployment that adds it runs one more migration
 * set — recorded in a bookkeeping table of the plugin's own, never merged into
 * this library's. Register it nowhere global: the consumer composes it.
 *
 * @since 0.2.0
 */
export * from "./Api.js"
export * from "./Handlers.js"
export * as UsernameMigrations from "./Migrations.js"
export * from "./Store.js"
export * from "./Username.js"
