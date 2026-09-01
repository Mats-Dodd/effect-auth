/**
 * The phone plugin: a verified number as a contact detail, as a way to sign in,
 * and as a way to raise a live session's assurance.
 *
 * **Details**
 *
 * The plugin shape, unchanged: a browser-safe API module (`Api.ts`), a domain
 * service with its own configuration and its own sender seam (`Phone.ts`), a
 * table of its own behind a store (`Store.ts`) with migrations of its own
 * (`Migrations.ts`), handlers built with `AuthHandlers.forGroup`
 * (`Handlers.ts`), and one pure module for the thing everything else depends on
 * being right (`E164.ts`). There is no plugin object and no registration call —
 * composition is plain layers.
 *
 * **Example**
 *
 * ```ts skip-type-checking
 * import { Duration, Layer } from "effect"
 * import { HttpApi } from "effect/unstable/httpapi"
 * import { Auth, AuthApi, AuthHandlers, Migrations, Phone } from "effect-auth"
 *
 * // The table, and the migration that creates it after the core set.
 * const PhoneStoreLive = Phone.Store.layer.pipe(Layer.provide(PgLive))
 * const MigrationsLive = Phone.Migrations.layer.pipe(Layer.provide(Migrations.layer), Layer.provide(PgLive))
 *
 * // The seam goes *underneath* the deployment, so `Accounts.unlink` counts it.
 * const settings = { signIn: true, allowedCountries: ["1", "44"] }
 * const AuthLive = Auth.layer(options).pipe(
 *   Layer.provide(Phone.authenticators(settings).pipe(Layer.provide(PhoneStoreLive))),
 *   Layer.provide(PgLive)
 * )
 *
 * const PhoneLive = Phone.layer(settings).pipe(
 *   Layer.provideMerge(AuthLive),
 *   Layer.provide(PhoneStoreLive),
 *   Layer.provide(MyTwilioGateway)
 * )
 *
 * const AppApi = HttpApi.make("app").addHttpApi(AuthApi).add(Phone.PhoneApiGroup)
 * const HandlersLive = Layer.mergeAll(AuthHandlers.layer(AppApi), Phone.handlers(AppApi)).pipe(
 *   Layer.provide(PhoneLive)
 * )
 * ```
 *
 * **Gotchas**
 *
 * `allowedCountries` is empty by default and an empty list refuses every
 * number. A deployment that has not said where its messages may go sends none —
 * see `Phone.Config.allowedCountries` for why that is the default rather than
 * an oversight.
 *
 * The migrations are registered nowhere global: the consumer composes them, and
 * sequences them after this library's own because `user_id` references `users`.
 *
 * @since 0.2.0
 */
export * from "./Api.js"
export * as E164 from "./E164.js"
export * from "./Handlers.js"
export * as Migrations from "./Migrations.js"
export * from "./Phone.js"
export * as Store from "./Store.js"
