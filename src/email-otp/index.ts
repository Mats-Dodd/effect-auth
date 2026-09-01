/**
 * The e-mail one-time-code plugin: sign-in, address verification, password
 * reset, step-up and change-of-address by a short code mailed to an address —
 * with a single-use link beside it, backed by the same row.
 *
 * **Details**
 *
 * The reference plugin: a browser-safe API module (`Api.ts`), a domain service
 * with its own configuration and its own mailer seam (`EmailOtp.ts`), and
 * handlers built with `AuthHandlers.forGroup` (`Handlers.ts`). There is no
 * plugin object and no registration call — composition is plain layers.
 *
 * **Example**
 *
 * ```ts skip-type-checking
 * import { Duration, Layer } from "effect"
 * import { HttpApi } from "effect/unstable/httpapi"
 * import { Auth, AuthApi, AuthHandlers, EmailOtp } from "effect-auth"
 *
 * const AuthLive = Auth.layer(options).pipe(Layer.provide(PgLive), Layer.provide(MyMailer))
 * const EmailOtpLive = EmailOtp.layer({ ttl: Duration.minutes(10) }).pipe(
 *   Layer.provideMerge(AuthLive),
 *   Layer.provide(MyOtpMailer)
 * )
 *
 * const AppApi = HttpApi.make("app").addHttpApi(AuthApi).add(EmailOtp.EmailOtpApiGroup)
 *
 * const HandlersLive = Layer.mergeAll(
 *   AuthHandlers.layer(AppApi),
 *   EmailOtp.handlers(AppApi)
 * ).pipe(Layer.provide(EmailOtpLive))
 * ```
 *
 * **Gotchas**
 *
 * The plugin owns no table: a challenge is a `Verifications` row minted through
 * `Challenges`, so a deployment that already ran this library's migrations needs
 * no new ones. A plugin that *does* need a table ships its own `Migrations.make`
 * set under its own bookkeeping table — never merged into this library's.
 *
 * @since 0.2.0
 */
export * from "./Api.js"
export * from "./EmailOtp.js"
export * from "./Handlers.js"
