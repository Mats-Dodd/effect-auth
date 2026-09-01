/**
 * The magic link plugin: passwordless sign-in by a single-use link sent to an
 * e-mail address.
 *
 * **Details**
 *
 * The first plugin built on this library's extension seams, and the shape every
 * other one follows: a browser-safe API module (`Api.ts`), a domain service with
 * its own configuration and its own mailer seam (`MagicLink.ts`), and handlers
 * built with `AuthHandlers.forGroup` (`Handlers.ts`). There is no plugin object
 * and no registration call — composition is plain layers.
 *
 * **Example**
 *
 * ```ts skip-type-checking
 * import { Layer } from "effect"
 * import { HttpApi } from "effect/unstable/httpapi"
 * import { Auth, AuthApi, AuthHandlers, MagicLink } from "effect-auth"
 *
 * const AuthLive = Auth.layer(options).pipe(Layer.provide(PgLive), Layer.provide(MyMailer))
 * const MagicLinkLive = MagicLink.layer({ ttl: Duration.minutes(10) }).pipe(
 *   Layer.provideMerge(AuthLive),
 *   Layer.provide(MyMagicLinkMailer)
 * )
 *
 * const AppApi = HttpApi.make("app").addHttpApi(AuthApi).add(MagicLink.MagicLinkApiGroup)
 *
 * const HandlersLive = Layer.mergeAll(
 *   AuthHandlers.layer(AppApi),
 *   MagicLink.handlers(AppApi)
 * ).pipe(Layer.provide(MagicLinkLive))
 * ```
 *
 * **Gotchas**
 *
 * The plugin owns no table: a link is a `Verifications` token, so a deployment
 * that already ran this library's migrations needs no new ones. A plugin that
 * *does* need a table ships its own `Migrations.make` set under its own
 * bookkeeping table — never merged into this library's.
 *
 * @since 0.1.0
 */
export * from "./Api.js"
export * from "./Handlers.js"
export * from "./MagicLink.js"
