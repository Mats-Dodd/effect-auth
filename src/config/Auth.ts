/**
 * The batteries-included entry point.
 *
 * `Auth.layer` is the one call a consumer makes: it resolves the configuration
 * against the defaults, builds the crypto services, the SQL-backed stores, the
 * three domain services, the event hub, the `Authenticated` middleware
 * implementation and the rate limiter, and hands back a single `Layer` whose
 * only remaining requirements are the two seams an application must own — a
 * `SqlClient` and an `AuthEmails` — plus an `HttpClient` when OAuth providers
 * are configured.
 *
 * @since 1.0.0
 */
import type { Config, Redacted } from "effect"
import { Duration, Effect, Layer, Schedule, Stream } from "effect"
import type { HttpClient } from "effect/unstable/http"
import type { RateLimiter } from "effect/unstable/persistence"
import type { SqlClient } from "effect/unstable/sql"
import { Hmac, layer as hmacLayer } from "../crypto/Hmac.js"
import type { PasswordHasher } from "../crypto/PasswordHasher.js"
import { layerScrypt } from "../crypto/PasswordHasher.js"
import { layer as tokenLayer, Token } from "../crypto/Token.js"
import { Accounts, layer as accountsLayer } from "../domain/Accounts.js"
import type { AuthEvent } from "../domain/Events.js"
import { AuthEvents, layer as eventsLayer } from "../domain/Events.js"
import { layer as passwordsLayer, Passwords } from "../domain/Passwords.js"
import { layer as sessionsLayer, Sessions } from "../domain/Sessions.js"
import type { AuthStores, PersistenceError } from "../domain/Stores.js"
import { SessionStore, VerificationStore } from "../domain/Stores.js"
import * as AuthCookies from "../http/Cookies.js"
import type { Authenticated } from "../http/Middleware.js"
import { layer as middlewareLayer } from "../http/MiddlewareLive.js"
import * as RateLimits from "../http/RateLimits.js"
import { layer as flowLayer, OAuthFlow } from "../oauth/Flow.js"
import { layerEmpty, layerMerge, OAuthProviders } from "../oauth/Provider.js"
import * as SqlStores from "../sql/SqlStores.js"
import type {
  AuthConfigOptions,
  AuthConfigShape,
  CookieConfig,
  EmailPasswordConfig,
  EmailPathConfig,
  PartialOptions,
  RateLimitConfig,
  SessionConfig,
  TokenConfig
} from "./AuthConfig.js"
import { AuthConfig, layer as authConfigLayer, make as makeAuthConfig } from "./AuthConfig.js"
import type { AuthEmails } from "./AuthEmails.js"

// -----------------------------------------------------------------------------
// Options
// -----------------------------------------------------------------------------

/**
 * The shape of the `providers` list: each entry is a layer providing a
 * one-provider {@link OAuthProviders} registry, as every provider module's
 * `layer` / `layerConfig` returns.
 *
 * @category models
 * @since 1.0.0
 */
export type ProviderLayers = ReadonlyArray<Layer.Layer<OAuthProviders, any, any>>

/**
 * The knobs {@link layer} accepts on top of {@link AuthConfigOptions}.
 *
 * @category models
 * @since 1.0.0
 */
export interface Extras<Providers extends ProviderLayers> {
  /**
   * The OAuth providers to serve, as their own layers.
   *
   * **Details**
   *
   * They are merged with `layerMerge`, not `Layer.mergeAll`: every
   * provider layer carries the same service key, so merging them by hand would
   * make the last one win. Configuring at least one provider is what adds
   * `HttpClient` to this layer's requirements.
   */
  readonly providers?: Providers | undefined

  /**
   * The password hashing layer. Defaults to `PasswordHasher.layerScrypt()` with
   * the parameters from the specification.
   *
   * **When to use**
   *
   * Pass `PasswordHasher.layerPbkdf2()` on a runtime without `node:crypto`, or
   * `layerScrypt({ N: 1024, r: 8, p: 1 })` in a test suite. A hash records the
   * cost it was written at, so lowering it never invalidates existing hashes.
   */
  readonly passwordHasher?: Layer.Layer<PasswordHasher> | undefined

  /**
   * How many events the hub buffers before it starts dropping. Default 256.
   */
  readonly eventCapacity?: number | undefined

  /**
   * Extra request header names to redact from logs, in addition to the cookie
   * and authorization headers this library already registers.
   */
  readonly redactedHeaders?: ReadonlyArray<string | RegExp> | undefined
}

/**
 * Everything {@link layer} accepts.
 *
 * @category models
 * @since 1.0.0
 */
export interface Options<Providers extends ProviderLayers> extends AuthConfigOptions, Extras<Providers> {}

/**
 * Everything {@link layerConfig} accepts: the scalar settings as `Config`
 * values, the structured sections as plain objects.
 *
 * @category models
 * @since 1.0.0
 */
export interface ConfigOptions<Providers extends ProviderLayers> extends Extras<Providers> {
  readonly baseUrl: Config.Config<string>
  readonly secret: Config.Config<Redacted.Redacted<string>>
  readonly basePath?: Config.Config<string> | undefined
  readonly trustedOrigins?: Config.Config<ReadonlyArray<string>> | undefined
  readonly trustedProviders?: Config.Config<ReadonlyArray<string>> | undefined
  readonly session?: PartialOptions<SessionConfig> | undefined
  readonly emailPassword?: PartialOptions<EmailPasswordConfig> | undefined
  readonly cookie?: PartialOptions<CookieConfig> | undefined
  readonly tokens?: PartialOptions<TokenConfig> | undefined
  readonly rateLimit?: PartialOptions<RateLimitConfig> | undefined
  readonly emailPaths?: PartialOptions<EmailPathConfig> | undefined
}

// -----------------------------------------------------------------------------
// Layer shape
// -----------------------------------------------------------------------------

/**
 * Every service {@link layer} provides.
 *
 * **Details**
 *
 * `OAuthFlow` is present only when at least one provider is configured — the
 * handlers read it with `Effect.serviceOption`, so its absence turns the three
 * OAuth endpoints into `UnknownProvider` answers rather than a layer that
 * refuses to build.
 *
 * @category models
 * @since 1.0.0
 */
export type Services<Providers extends ProviderLayers> =
  | AuthConfig
  | AuthEvents
  | AuthStores
  | Token
  | Hmac
  | PasswordHasher
  | Sessions
  | Accounts
  | Passwords
  | Authenticated
  | RateLimiter.RateLimiter
  | OAuthProviders
  | (Providers extends readonly [] ? never : OAuthFlow)

/**
 * Everything {@link layer} still needs from the application: the database
 * client, the mailer, whatever the provider layers require, and — only when a
 * provider is configured — an `HttpClient`.
 *
 * @category models
 * @since 1.0.0
 */
export type Requirements<Providers extends ProviderLayers> =
  | SqlClient.SqlClient
  | AuthEmails
  | Layer.Services<Providers[number]>
  | (Providers extends readonly [] ? never : HttpClient.HttpClient)

// -----------------------------------------------------------------------------
// Composition
// -----------------------------------------------------------------------------

const compose = <Providers extends ProviderLayers>(
  config: AuthConfigShape,
  options: Extras<Providers>
): Layer.Layer<Services<Providers>, Layer.Error<Providers[number]>, Requirements<Providers>> => {
  const providers: ProviderLayers = options.providers ?? []

  // Everything that needs nothing but a `SqlClient` and the resolved config.
  const infrastructure = Layer.mergeAll(
    Layer.succeed(AuthConfig)(config),
    SqlStores.layer,
    tokenLayer,
    options.passwordHasher ?? layerScrypt(),
    eventsLayer(
      options.eventCapacity === undefined ? undefined : { capacity: options.eventCapacity }
    ),
    RateLimits.layer,
    // Checklist item 11: the cookie and authorization headers must never reach
    // a log line in the clear.
    AuthCookies.layerRedactedHeaders(options.redactedHeaders ?? [])
  )

  // `Hmac` keys itself from `AuthConfig.secret`, so it is built on top.
  const withHmac = hmacLayer.pipe(Layer.provideMerge(infrastructure))

  // `Passwords` needs `Sessions`, so the domain is two tiers.
  const domain = passwordsLayer.pipe(
    Layer.provideMerge(
      Layer.mergeAll(sessionsLayer, accountsLayer).pipe(Layer.provideMerge(withHmac))
    )
  )

  const registry = providers.length === 0
    ? layerEmpty
    : layerMerge(providers as ReadonlyArray<Layer.Layer<OAuthProviders, any, any>>)

  // The one branch in this file. With no provider configured the flow is not
  // built at all, which is precisely what keeps `HttpClient` out of the
  // requirements — see `Requirements`.
  const withOAuth: Layer.Layer<any, any, any> = providers.length === 0
    ? registry
    : flowLayer.pipe(Layer.provideMerge(registry))

  const stack = middlewareLayer.pipe(
    Layer.provideMerge(withOAuth.pipe(Layer.provideMerge(domain)))
  )

  // The branch above is invisible to the type checker; `Services` and
  // `Requirements` describe both of its arms, and the empty-provider arm is the
  // one that drops `OAuthFlow` and `HttpClient`.
  return stack as Layer.Layer<
    Services<Providers>,
    Layer.Error<Providers[number]>,
    Requirements<Providers>
  >
}

// -----------------------------------------------------------------------------
// Layers
// -----------------------------------------------------------------------------

/**
 * The batteries-included layer.
 *
 * **Example**
 *
 * ```ts
 * import { Layer, Redacted } from "effect"
 * import type { SqlClient } from "effect/unstable/sql"
 * import { Auth, AuthEmails, Github } from "effect-auth"
 *
 * // The two seams an application owns. Declaring them as the services they
 * // actually provide is what makes the `Layer.provide`s below discharge
 * // `AuthLive`'s requirements — see `Requirements`.
 * declare const PgLive: Layer.Layer<SqlClient.SqlClient>
 * declare const MyMailer: Layer.Layer<AuthEmails.AuthEmails>
 *
 * const AuthLive = Auth.layer({
 *   baseUrl: "http://localhost:3000",
 *   secret: Redacted.make("a-32-byte-or-longer-random-string"),
 *   emailPassword: { enabled: true },
 *   providers: [Github.layer({ clientId: "…", clientSecret: Redacted.make("…") })]
 * }).pipe(Layer.provide(PgLive), Layer.provide(MyMailer))
 * ```
 *
 * **Details**
 *
 * What it provides is listed by {@link Services}; what it still needs is listed
 * by {@link Requirements}. It does **not** run the migrations: schema changes
 * are the application's to sequence. Provide `Migrations.layer` under the
 * `SqlClient` for a quickstart, or merge `Migrations.migrations` into your own
 * migrator.
 *
 * @category layers
 * @since 1.0.0
 */
export const layer = <const Providers extends ProviderLayers = readonly []>(
  options: Options<Providers>
): Layer.Layer<Services<Providers>, Layer.Error<Providers[number]>, Requirements<Providers>> =>
  compose<Providers>(makeAuthConfig(options), options)

/**
 * {@link layer}, with the scalar settings read from `Config`.
 *
 * **Example**
 *
 * ```ts
 * import { Config } from "effect"
 * import { Auth } from "effect-auth"
 *
 * const AuthLive = Auth.layerConfig({
 *   baseUrl: Config.string("BASE_URL"),
 *   secret: Config.redacted("AUTH_SECRET"),
 *   emailPassword: { enabled: true }
 * })
 * ```
 *
 * **Gotchas**
 *
 * The secret must come from `Config.redacted`, so it is a `Redacted<string>`
 * from the moment it leaves the environment and can never be printed by a
 * `ConfigError`.
 *
 * @category layers
 * @since 1.0.0
 */
export const layerConfig = <const Providers extends ProviderLayers = readonly []>(
  options: ConfigOptions<Providers>
): Layer.Layer<
  Services<Providers>,
  Config.ConfigError | Layer.Error<Providers[number]>,
  Requirements<Providers>
> =>
  Layer.unwrap(
    Effect.gen(function*() {
      const config = makeAuthConfig({
        baseUrl: yield* options.baseUrl,
        secret: yield* options.secret,
        basePath: options.basePath === undefined ? undefined : yield* options.basePath,
        trustedOrigins: options.trustedOrigins === undefined ? undefined : yield* options.trustedOrigins,
        trustedProviders: options.trustedProviders === undefined ? undefined : yield* options.trustedProviders,
        session: options.session,
        emailPassword: options.emailPassword,
        cookie: options.cookie,
        tokens: options.tokens,
        rateLimit: options.rateLimit,
        emailPaths: options.emailPaths
      })
      return compose<Providers>(config, options)
    })
  )

/**
 * Provides only {@link AuthConfig}, for a process that needs the resolved
 * settings without the services — a migration script, or a second server that
 * only reads cookies.
 *
 * @category layers
 * @since 1.0.0
 */
export const layerConfigOnly: (options: AuthConfigOptions) => Layer.Layer<AuthConfig> = authConfigLayer

// -----------------------------------------------------------------------------
// Housekeeping
// -----------------------------------------------------------------------------

/**
 * Deletes every expired session and verification row, and reports how many of
 * each went.
 *
 * **When to use**
 *
 * Nothing in this library deletes an expired row on its own: a session is dead
 * the moment its `expires_at` passes, and a verification value is unclaimable
 * for the same reason, so correctness never depends on the row being gone. What
 * does depend on it is the size of the two tables — and `verifications` in
 * particular is written by unauthenticated callers (every `POST /sign-in/social`
 * mints one state row), so it grows faster than it is read.
 *
 * Run this on a schedule: a cron job that provides the stores, or
 * {@link layerCleanup} inside the server process.
 *
 * **Example**
 *
 * ```ts
 * import { Effect } from "effect"
 * import { Auth } from "effect-auth"
 *
 * const reap = Effect.flatMap(
 *   Auth.cleanupExpired,
 *   (removed) => Effect.log(`reaped ${removed.sessions} sessions, ${removed.verifications} verifications`)
 * )
 * ```
 *
 * @category combinators
 * @since 1.0.0
 */
export const cleanupExpired: Effect.Effect<
  { readonly sessions: number; readonly verifications: number },
  PersistenceError,
  SessionStore | VerificationStore
> = Effect.gen(function*() {
  const sessions = yield* SessionStore
  const verifications = yield* VerificationStore
  return {
    sessions: yield* sessions.deleteExpired,
    verifications: yield* verifications.deleteExpired
  }
})

/**
 * Runs {@link cleanupExpired} on an interval, in a fiber that lives as long as
 * the layer's scope.
 *
 * **When to use**
 *
 * In a single-process deployment, or wherever a separate cron job is more
 * ceremony than the problem deserves. Provide it alongside `Auth.layer` — it
 * needs the same stores.
 *
 * **Gotchas**
 *
 * Every instance that builds this layer reaps, so on many instances either
 * accept the duplicated work (the statements are idempotent) or run
 * {@link cleanupExpired} from one scheduled job instead. A failed sweep is
 * logged and the next one is attempted; it never fails the layer.
 *
 * @category layers
 * @since 1.0.0
 */
export const layerCleanup = (
  options?: { readonly interval?: Duration.Duration | undefined } | undefined
): Layer.Layer<never, never, SessionStore | VerificationStore> =>
  Layer.effectDiscard(
    Effect.forkScoped(
      Effect.repeat(
        Effect.ignore(cleanupExpired, {
          log: "Warn",
          message: "effect-auth: reaping expired sessions and verifications failed"
        }),
        Schedule.spaced(options?.interval ?? Duration.hours(1))
      )
    )
  )

// -----------------------------------------------------------------------------
// Events
// -----------------------------------------------------------------------------

/**
 * Every authentication event, from the moment the stream is run.
 *
 * **Example**
 *
 * ```ts
 * import { Effect, Stream } from "effect"
 * import { Auth } from "effect-auth"
 *
 * const audit = Stream.runForEach(Auth.events, (event) => Effect.log(event._tag))
 * ```
 *
 * **Gotchas**
 *
 * The hub drops rather than blocks, so a consumer that stops pulling costs
 * events, never a wedged sign-in. There is no replay: subscribe before the
 * traffic you want to observe.
 *
 * @category models
 * @since 1.0.0
 */
export const events: Stream.Stream<AuthEvent, never, AuthEvents> = Stream.unwrap(
  AuthEvents.use((hub) => Effect.succeed(hub.stream))
)
