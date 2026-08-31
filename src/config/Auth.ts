/**
 * The batteries-included entry point.
 *
 * `Auth.layer` is the one call a consumer makes: it resolves the configuration
 * against the defaults, builds the crypto services, the SQL-backed stores, the
 * three domain services, the event hub, the `Authenticated` middleware
 * implementation and the rate limiter, and hands back a single `Layer` whose
 * only remaining requirements are the two seams an application must own — a
 * `SqlClient` and an `AuthEmails`.
 *
 * **Details**
 *
 * OAuth is a second entry point rather than an option: {@link layerWithOAuth}
 * takes a non-empty list of provider *values* and adds exactly two things to
 * the result — `OAuthFlow` to what it provides, and an `HttpClient` to what it
 * needs. Nothing in this module inspects a list length or reshapes a type, so
 * what a call site reads is what the compiler checked.
 *
 * @since 1.0.0
 */
import type { Crypto, Redacted } from "effect"
import { Config, Duration, Effect, Layer, Schedule, Stream } from "effect"
import type { HttpClient } from "effect/unstable/http"
import type { RateLimiter } from "effect/unstable/persistence"
import type { SqlClient } from "effect/unstable/sql"
import type { PasswordHasher } from "../crypto/PasswordHasher.js"
import { layerScrypt } from "../crypto/PasswordHasher.js"
import type { Token } from "../crypto/Token.js"
import { layer as tokenLayer } from "../crypto/Token.js"
import { Accounts, layer as accountsLayer } from "../domain/Accounts.js"
import type { AuthEvent } from "../domain/Events.js"
import { AuthEvents, layer as eventsLayer } from "../domain/Events.js"
import { layer as passwordsLayer, Passwords } from "../domain/Passwords.js"
import { layer as sessionsLayer, Sessions } from "../domain/Sessions.js"
import type { AccountStore, AuthStores, PersistenceError, UserStore } from "../domain/Stores.js"
import { SessionStore, VerificationStore } from "../domain/Stores.js"
import * as AuthCookies from "../http/Cookies.js"
import type { Authenticated } from "../http/Middleware.js"
import { layer as middlewareLayer } from "../http/MiddlewareLive.js"
import * as RateLimits from "../http/RateLimits.js"
import { optionalConfig } from "../internal/config.js"
import { layerWebCrypto } from "../internal/crypto.js"
import { layer as flowLayer, OAuthFlow } from "../oauth/Flow.js"
import type { OAuthProviderConfig } from "../oauth/Provider.js"
import { OAuthProviders } from "../oauth/Provider.js"
import * as SqlStores from "../sql/SqlStores.js"
import type {
  AuthConfigOptions,
  AuthConfigService,
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
 * The OAuth providers a deployment serves, as the inert values
 * `Github.make` / `Google.make` return.
 *
 * **Details**
 *
 * Non-empty by construction: a deployment with no provider calls
 * {@link layer}, not {@link layerWithOAuth}, and gets a stack that needs no
 * `HttpClient`. Two entries with the same `id` are a configuration mistake and
 * the last one wins — see `OAuthProviders`.
 *
 * @category models
 * @since 1.0.0
 */
export type ProviderList = readonly [OAuthProviderConfig, ...Array<OAuthProviderConfig>]

/**
 * {@link ProviderList}, with each provider still to be read out of the
 * environment — the effects `Github.makeConfig` / `Google.makeConfig` return.
 *
 * @category models
 * @since 1.0.0
 */
export type ProviderConfigList = readonly [
  Effect.Effect<OAuthProviderConfig, Config.ConfigError>,
  ...Array<Effect.Effect<OAuthProviderConfig, Config.ConfigError>>
]

/**
 * The knobs every entry point in this module accepts on top of the settings.
 *
 * @category models
 * @since 1.0.0
 */
export interface Extras {
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
  readonly passwordHasher?: Layer.Layer<PasswordHasher, never, Crypto.Crypto> | undefined

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
export interface Options extends AuthConfigOptions, Extras {}

/**
 * Everything {@link layerWithOAuth} accepts: {@link Options} plus the providers
 * to serve.
 *
 * @category models
 * @since 1.0.0
 */
export interface OAuthOptions extends Options {
  /**
   * The providers this deployment serves, as values.
   *
   * **Example**
   *
   * ```ts
   * import { Redacted } from "effect"
   * import { Github, Google } from "effect-auth"
   *
   * const providers = [
   *   Github.make({ clientId: "…", clientSecret: Redacted.make("…") }),
   *   Google.make({ clientId: "…", clientSecret: Redacted.make("…") })
   * ] as const
   * ```
   */
  readonly providers: ProviderList
}

/**
 * Everything {@link layerConfig} accepts: the scalar settings as `Config`
 * values, the structured sections as plain objects.
 *
 * @category models
 * @since 1.0.0
 */
export interface ConfigOptions extends Extras {
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

/**
 * Everything {@link layerConfigWithOAuth} accepts: {@link ConfigOptions} plus
 * the providers, themselves read from the environment.
 *
 * @category models
 * @since 1.0.0
 */
export interface OAuthConfigOptions extends ConfigOptions {
  /**
   * The providers this deployment serves, each as an effect that reads its
   * credentials.
   *
   * **Example**
   *
   * ```ts
   * import { Config } from "effect"
   * import { Github } from "effect-auth"
   *
   * const providers = [
   *   Github.makeConfig({
   *     clientId: Config.string("GITHUB_CLIENT_ID"),
   *     clientSecret: Config.redacted("GITHUB_CLIENT_SECRET")
   *   })
   * ] as const
   * ```
   */
  readonly providers: ProviderConfigList
}

// -----------------------------------------------------------------------------
// Layer shape
// -----------------------------------------------------------------------------

/**
 * Every service {@link layer} provides.
 *
 * **Details**
 *
 * Exactly the services an application — or `AuthHandlers.layer` — has a reason
 * to reach: the resolved configuration, the event hub, the four stores, the
 * three domain services, the middleware implementation and the rate limiter.
 *
 * `Token`, `PasswordHasher` and `OAuthProviders` are deliberately absent. They
 * are implementation detail of this stack, provided *into* it and not out of
 * it, so replacing one is a change to the options here rather than a layer a
 * consumer can shadow. `Hmac` is not built at all — nothing in v1 reads it;
 * its module stays public for the v2 cookie cache.
 *
 * @category models
 * @since 1.0.0
 */
export type Services =
  | AuthConfig
  | AuthEvents
  | UserStore
  | SessionStore
  | AccountStore
  | VerificationStore
  | Sessions
  | Accounts
  | Passwords
  | Authenticated
  | RateLimiter.RateLimiter

/**
 * Every service {@link layerWithOAuth} provides: {@link Services} plus the
 * OAuth flow the three social endpoints run on.
 *
 * @category models
 * @since 1.0.0
 */
export type OAuthServices = Services | OAuthFlow

/**
 * Everything {@link layer} still needs from the application: the database
 * client and the mailer.
 *
 * @category models
 * @since 1.0.0
 */
export type Requirements = SqlClient.SqlClient | AuthEmails

/**
 * Everything {@link layerWithOAuth} still needs: {@link Requirements} plus a
 * transport, because talking to a provider is the one thing this library does
 * over the network.
 *
 * @category models
 * @since 1.0.0
 */
export type OAuthRequirements = Requirements | HttpClient.HttpClient

// -----------------------------------------------------------------------------
// Composition
// -----------------------------------------------------------------------------

/**
 * The two services that need random bytes and message digests, over the
 * WebCrypto-backed `Crypto` default.
 *
 * **Details**
 *
 * `Crypto` is provided *into* this tier and never surfaces, so it stays a
 * detail of this stack rather than something an application has to satisfy —
 * see `Requirements`. A deployment that wants a platform implementation hands
 * in a `passwordHasher` built over it, or provides `Crypto.Crypto` above these
 * two layers itself.
 */
const cryptoTier = (
  hasher: Layer.Layer<PasswordHasher, never, Crypto.Crypto> | undefined
): Layer.Layer<Token | PasswordHasher> =>
  Layer.mergeAll(tokenLayer, hasher ?? layerScrypt()).pipe(Layer.provide(layerWebCrypto))

/**
 * Everything below the domain services: the resolved settings, the stores, the
 * event hub and the rate limiter.
 */
const baseTier = (
  config: AuthConfigService,
  options: Extras
): Layer.Layer<AuthConfig | AuthStores | AuthEvents | RateLimiter.RateLimiter, never, SqlClient.SqlClient> =>
  Layer.mergeAll(
    Layer.succeed(AuthConfig)(config),
    SqlStores.layer,
    // `capacity` is optional and `undefined`-able, so an absent
    // `eventCapacity` is simply an absent capacity — no ternary needed.
    eventsLayer({ capacity: options.eventCapacity }),
    RateLimits.layer
  )

/**
 * The whole stack, over whichever services sit on the top tier alongside the
 * middleware.
 *
 * **Details**
 *
 * `top` is the one thing that differs between {@link layer} and
 * {@link layerWithOAuth} — `Passwords` alone, or `Passwords` plus the OAuth
 * flow. Everything else, down to the order the tiers are stacked in, is shared,
 * and the result type is computed from `top` rather than restated: the
 * non-OAuth call needs no `HttpClient` because nothing in its `top` asks for
 * one.
 */
const compose = <A, RIn>(
  config: AuthConfigService,
  options: Extras,
  top: Layer.Layer<A, never, RIn>
) =>
  middlewareLayer.pipe(
    Layer.provideMerge(top),
    Layer.provideMerge(Layer.mergeAll(sessionsLayer, accountsLayer)),
    Layer.provideMerge(baseTier(config, options)),
    Layer.provide(cryptoTier(options.passwordHasher)),
    // Checklist item 11: the cookie and authorization headers must never reach
    // a log line in the clear. `provideMerge`, not `provide`: this is a
    // `Context.Reference`, so the names have to survive into the context the
    // application runs on — `Headers` reads them from the *current* context
    // when a header set is logged, not from the one this stack was built with.
    // The layer's `ROut` is `never`, so merging it widens nothing.
    Layer.provideMerge(AuthCookies.layerRedactedHeaders(options.redactedHeaders ?? []))
  )

/**
 * The top tier {@link layerWithOAuth} composes over: the flow, with the
 * registry provided *into* it.
 *
 * The registry is inert data behind a service key and only the flow reads it,
 * so `provide` rather than `provideMerge` — it never becomes part of the
 * stack's surface.
 */
const oauthTop = (
  providers: ReadonlyArray<OAuthProviderConfig>
): Layer.Layer<
  Passwords | OAuthFlow,
  never,
  | AuthConfig
  | AuthStores
  | AuthEvents
  | AuthEmails
  | Accounts
  | Sessions
  | Token
  | PasswordHasher
  | HttpClient.HttpClient
> => Layer.mergeAll(passwordsLayer, flowLayer.pipe(Layer.provide(OAuthProviders.layer(providers))))

/** The settings {@link ConfigOptions} reads from the environment. */
interface ScalarSettings {
  readonly baseUrl: string
  readonly secret: Redacted.Redacted<string>
  readonly basePath: string | undefined
  readonly trustedOrigins: ReadonlyArray<string> | undefined
  readonly trustedProviders: ReadonlyArray<string> | undefined
}

const resolveConfig = (
  options: ConfigOptions
): Effect.Effect<AuthConfigService, Config.ConfigError> =>
  Effect.map(
    Config.unwrap<ScalarSettings>({
      baseUrl: options.baseUrl,
      secret: options.secret,
      basePath: optionalConfig(options.basePath),
      trustedOrigins: optionalConfig(options.trustedOrigins),
      trustedProviders: optionalConfig(options.trustedProviders)
    }),
    (settings) =>
      makeAuthConfig({
        ...settings,
        session: options.session,
        emailPassword: options.emailPassword,
        cookie: options.cookie,
        tokens: options.tokens,
        rateLimit: options.rateLimit,
        emailPaths: options.emailPaths
      })
  )

// -----------------------------------------------------------------------------
// Layers
// -----------------------------------------------------------------------------

/**
 * The batteries-included layer, without OAuth.
 *
 * **Example**
 *
 * ```ts
 * import { Layer, Redacted } from "effect"
 * import type { SqlClient } from "effect/unstable/sql"
 * import { Auth, AuthEmails } from "effect-auth"
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
 *   emailPassword: { enabled: true }
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
export const layer = (options: Options): Layer.Layer<Services, never, Requirements> =>
  compose(makeAuthConfig(options), options, passwordsLayer)

/**
 * {@link layer}, serving the OAuth providers it is given.
 *
 * **Example**
 *
 * ```ts
 * import { Layer, Redacted } from "effect"
 * import { FetchHttpClient } from "effect/unstable/http"
 * import type { SqlClient } from "effect/unstable/sql"
 * import { Auth, AuthEmails, Github, Google } from "effect-auth"
 *
 * declare const PgLive: Layer.Layer<SqlClient.SqlClient>
 * declare const MyMailer: Layer.Layer<AuthEmails.AuthEmails>
 *
 * const AuthLive = Auth.layerWithOAuth({
 *   baseUrl: "https://app.example.com",
 *   secret: Redacted.make("a-32-byte-or-longer-random-string"),
 *   emailPassword: { enabled: true },
 *   providers: [
 *     Github.make({ clientId: "…", clientSecret: Redacted.make("…") }),
 *     Google.make({ clientId: "…", clientSecret: Redacted.make("…") })
 *   ]
 * }).pipe(
 *   Layer.provide(PgLive),
 *   Layer.provide(MyMailer),
 *   Layer.provide(FetchHttpClient.layer)
 * )
 * ```
 *
 * **Gotchas**
 *
 * The `HttpClient` this needs must not follow redirects — the flow refuses them
 * twice over, but only one of the two locks applies to a client that followed a
 * redirect internally before answering. `FetchHttpClient.layer` is fine.
 *
 * @category layers
 * @since 1.0.0
 */
export const layerWithOAuth = (
  options: OAuthOptions
): Layer.Layer<OAuthServices, never, OAuthRequirements> =>
  compose(makeAuthConfig(options), options, oauthTop(options.providers))

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
export const layerConfig = (
  options: ConfigOptions
): Layer.Layer<Services, Config.ConfigError, Requirements> =>
  Layer.unwrap(Effect.map(resolveConfig(options), (config) => compose(config, options, passwordsLayer)))

/**
 * {@link layerWithOAuth}, with the settings *and* the provider credentials read
 * from `Config`.
 *
 * **Example**
 *
 * ```ts
 * import { Config } from "effect"
 * import { Auth, Github } from "effect-auth"
 *
 * const AuthLive = Auth.layerConfigWithOAuth({
 *   baseUrl: Config.string("BASE_URL"),
 *   secret: Config.redacted("AUTH_SECRET"),
 *   emailPassword: { enabled: true },
 *   providers: [
 *     Github.makeConfig({
 *       clientId: Config.string("GITHUB_CLIENT_ID"),
 *       clientSecret: Config.redacted("GITHUB_CLIENT_SECRET")
 *     })
 *   ]
 * })
 * ```
 *
 * **Details**
 *
 * Every provider is read before the stack is built, so a missing
 * `GITHUB_CLIENT_SECRET` is one `ConfigError` at start-up rather than a
 * provider that answers `UnknownProvider` in production.
 *
 * @category layers
 * @since 1.0.0
 */
export const layerConfigWithOAuth = (
  options: OAuthConfigOptions
): Layer.Layer<OAuthServices, Config.ConfigError, OAuthRequirements> =>
  Layer.unwrap(
    Effect.map(
      Effect.all([resolveConfig(options), Effect.all(options.providers)]),
      ([config, providers]) => compose(config, options, oauthTop(providers))
    )
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
