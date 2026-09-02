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
 * @since 0.1.0
 */
import type { Context, Crypto, Redacted } from "effect"
import { Config, Duration, Effect, Layer, Schedule, Stream } from "effect"
import type { HttpClient } from "effect/unstable/http"
import type { HttpApi, HttpApiGroup } from "effect/unstable/httpapi"
import type { RateLimiter } from "effect/unstable/persistence"
import type { Migrator, SqlClient, SqlError } from "effect/unstable/sql"
import type { AuthCipher } from "../crypto/Cipher.js"
import { layer as cipherLayer } from "../crypto/Cipher.js"
import type { Hmac } from "../crypto/Hmac.js"
import { layer as hmacLayer } from "../crypto/Hmac.js"
import type { PasswordHasher } from "../crypto/PasswordHasher.js"
import { layerScrypt } from "../crypto/PasswordHasher.js"
import type { Token } from "../crypto/Token.js"
import { layer as tokenLayer } from "../crypto/Token.js"
import { type Accounts, layer as accountsLayer } from "../domain/Accounts.js"
import { type Challenges, layer as challengesLayer } from "../domain/Challenges.js"
import type { DiscoveryError } from "../domain/Errors.js"
import type { AuthEvent } from "../domain/Events.js"
import { AuthEvents, layer as eventsLayer } from "../domain/Events.js"
import {
  layerFor as passwordsLayerFor,
  type Passwords,
  passwordsOf,
  type PasswordsService
} from "../domain/Passwords.js"
import type {
  SessionWithUserSchema,
  SignUpResponseSchema,
  UserFields,
  UserModel,
  UserOf,
  UserResponseSchema
} from "../domain/Schema.js"
import {
  baseUserModel,
  makeSessionWithUser,
  makeSignUpResponse,
  makeUserModel,
  makeUserResponse,
  UserModelRef
} from "../domain/Schema.js"
import { layerFor as signInLayerFor, type SignIn } from "../domain/SignIn.js"
import { layerFor as sessionsLayerFor, type Sessions, sessionsOf, type SessionsService } from "../domain/Sessions.js"
import {
  type AccountStore,
  type AuthStores,
  type PersistenceError,
  SessionStore,
  type UserStore,
  userStoreOf,
  type UserStoreService,
  VerificationStore,
  type WithAuthTransaction
} from "../domain/Stores.js"
import { layerFor as usersLayerFor, type Users, usersOf, type UsersService } from "../domain/Users.js"
import { layer as verificationsLayer, type Verifications } from "../domain/Verifications.js"
import type { AuthApiGroupOf } from "../http/AuthApi.js"
import { makeAuthApi, makeAuthApiGroup } from "../http/AuthApi.js"
import * as AuthCookies from "../http/Cookies.js"
import * as AuthHandlers from "../http/Handlers.js"
import type { Authenticated, CurrentUser } from "../http/Middleware.js"
import { currentUserOf } from "../http/Middleware.js"
import { layerFor as middlewareLayerFor } from "../http/MiddlewareLive.js"
import * as RateLimits from "../http/RateLimits.js"
import { layerFor as sessionCacheLayerFor, type SessionCache } from "../http/SessionCache.js"
import { optionalConfig } from "../internal/config.js"
import { layerWebCrypto } from "../internal/crypto.js"
import { layer as flowLayer, type OAuthFlow } from "../oauth/Flow.js"
import type { OAuthProviderConfig } from "../oauth/Provider.js"
import { OAuthProviders } from "../oauth/Provider.js"
import * as Migrations from "../sql/Migrations.js"
import * as SqlStores from "../sql/SqlStores.js"
import type {
  AssuranceConfig,
  AuthConfigOptions,
  AuthConfigService,
  CookieCacheConfig,
  CookieConfig,
  EmailPasswordConfig,
  EmailPathConfig,
  PartialOptions,
  RateLimitConfig,
  SessionConfig,
  TokenConfig,
  UserConfigOptions
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
 * @since 0.1.0
 */
export type ProviderList = readonly [OAuthProviderConfig, ...Array<OAuthProviderConfig>]

/**
 * {@link ProviderList}, with each provider still to be read out of the
 * environment — the effects `Github.makeConfig` / `Google.makeConfig` return.
 *
 * @category models
 * @since 0.1.0
 */
export type ProviderConfigList = readonly [ProviderConfigEffect, ...Array<ProviderConfigEffect>]

/**
 * One entry of a {@link ProviderConfigList}: a provider still to be resolved.
 *
 * **Details**
 *
 * Three things can happen while resolving one, and all three are in the type. It
 * may read credentials from the environment and fail `ConfigError`; it may fetch
 * an OIDC discovery document and fail `DiscoveryError`; and fetching one needs an
 * `HttpClient`, which a deployment serving providers supplies anyway. A provider
 * that does none of that — `Github.makeConfig` — simply uses less of it.
 *
 * @category models
 * @since 0.1.0
 */
export type ProviderConfigEffect = Effect.Effect<
  OAuthProviderConfig,
  Config.ConfigError | DiscoveryError,
  HttpClient.HttpClient
>

/**
 * The knobs every entry point in this module accepts on top of the settings.
 *
 * @category models
 * @since 0.1.0
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

  /**
   * A `SessionStore` laid over the SQL one.
   *
   * **When to use**
   *
   * To decorate the store the stack builds — a cache in front of
   * `findByTokenHash`, a counter, a metric — or to replace it outright with one
   * backed by something other than the `SqlClient`. The layer is *provided* the
   * SQL store and *merged over* it, so it may delegate to what it is given, and
   * whatever it publishes is what every service above sees.
   *
   * **Example**
   *
   * ```ts
   * import { Effect, Layer } from "effect"
   * import { Stores } from "effect-auth"
   *
   * const Counting = Layer.effect(
   *   Stores.SessionStore,
   *   Effect.map(Stores.SessionStore, (inner) => ({
   *     ...inner,
   *     findByTokenHash: (hash: string) => Effect.tap(inner.findByTokenHash(hash), () => Effect.logDebug("read"))
   *   }))
   * )
   * ```
   *
   * **Gotchas**
   *
   * This is the seam a distributed session store plugs into, and the one place
   * where "the store" and "the SQL store" can differ. The other three stores are
   * deliberately not decorable: nothing in this library reads them on a hot path.
   *
   * *The user a replacement answers with is part of its contract.* The slot is
   * typed with the base `User`, but every service above reads it through a
   * typed view built from the deployment's model — `findByTokenHash` is what
   * puts a user under `CurrentUser`, and what the cookie cache encodes through
   * `model.json`. A store that round-trips the joined user through the base
   * schema (`Schema.decodeUnknownEffect(User)`, `User.json`, `JSON.parse` of a
   * base projection) silently drops every custom column: an application
   * endpoint typed `user.plan` reads `undefined`, and a cache write of a model
   * whose custom field is required dies rather than encoding. A replacement
   * must carry the columns the model declares — decode rows with
   * `UserModelRef`'s `decodeRow`, which `Auth.compose` provides for exactly
   * this, or keep the row the SQL store handed it intact. A decorator that
   * passes the user through untouched, like the example above, is safe by
   * construction.
   */
  readonly sessionStore?: Layer.Layer<SessionStore, never, SessionStore> | undefined
}

/**
 * The user model a deployment's stack is built for.
 *
 * **Details**
 *
 * Present on every entry point in this module. Leaving it out is the same as
 * passing `baseUserModel`: the stack serves `User` as this library declares it.
 * Passing one built with `makeUserModel` is what makes a deployment's own
 * columns part of sign-up, of `GET /session` and of every user a store answers
 * with — and it costs the layer's *type* nothing, which is what the four
 * `Layer` signatures below are the proof of.
 *
 * **Gotchas**
 *
 * The same model value has to reach `makeAuthApi(model)`,
 * `AuthHandlers.layer(api, model)` and `AuthClient.make({ api, model })`. The
 * compiler enforces it — two models are two types even when their fields match —
 * but the error lands at the API, not here.
 *
 * @category models
 * @since 0.1.0
 */
export interface UserOptions<F extends UserFields> extends UserConfigOptions {
  /**
   * The model the stack's stores, sign-up and middleware are built for.
   *
   * **Gotchas**
   *
   * Optional because this section is also where the change-email and
   * delete-account policies live, and a deployment may want those without
   * declaring a field of its own. Leaving it out is `baseUserModel`.
   */
  readonly model?: UserModel<F> | undefined
}

/**
 * Everything {@link layer} accepts except the user model — the settings a
 * deployment that has already fixed its model still supplies. See
 * {@link Definition}.
 *
 * @category models
 * @since 0.1.0
 */
export interface Settings extends AuthConfigOptions, Extras {}

/**
 * Everything {@link layer} accepts.
 *
 * @category models
 * @since 0.1.0
 */
export interface Options<F extends UserFields = {}> extends Settings {
  /**
   * The deployment's user model. See {@link UserOptions}.
   */
  readonly user?: UserOptions<F> | undefined
}

/**
 * {@link Settings} plus the providers to serve.
 *
 * @category models
 * @since 0.1.0
 */
export interface OAuthSettings extends Settings {
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
 * Everything {@link layerWithOAuth} accepts: {@link Options} plus the providers
 * to serve.
 *
 * @category models
 * @since 0.1.0
 */
export interface OAuthOptions<F extends UserFields = {}> extends Options<F>, OAuthSettings {
  /** Restated so that the two supertypes agree on it. See {@link Options.user}. */
  readonly user?: UserOptions<F> | undefined
}

/**
 * Everything {@link layerConfig} accepts except the user model: the scalar
 * settings as `Config` values, the structured sections as plain objects.
 *
 * @category models
 * @since 0.1.0
 */
export interface ConfigSettings extends Extras {
  readonly baseUrl: Config.Config<string>
  readonly secret: Config.Config<Redacted.Redacted>
  readonly basePath?: Config.Config<string> | undefined
  readonly trustedOrigins?: Config.Config<ReadonlyArray<string>> | undefined
  readonly trustedProviders?: Config.Config<ReadonlyArray<string>> | undefined
  readonly session?: PartialOptions<SessionConfig> | undefined
  readonly assurance?: PartialOptions<AssuranceConfig> | undefined
  readonly emailPassword?: PartialOptions<EmailPasswordConfig> | undefined
  readonly cookie?: PartialOptions<CookieConfig> | undefined
  readonly tokens?: PartialOptions<TokenConfig> | undefined
  readonly rateLimit?: PartialOptions<RateLimitConfig> | undefined
  readonly emailPaths?: PartialOptions<EmailPathConfig> | undefined
  readonly cookieCache?: PartialOptions<CookieCacheConfig> | undefined
  readonly user?: UserConfigOptions | undefined
}

/**
 * Everything {@link layerConfig} accepts.
 *
 * @category models
 * @since 0.1.0
 */
export interface ConfigOptions<F extends UserFields = {}> extends ConfigSettings {
  /**
   * The deployment's user model. See {@link UserOptions}.
   */
  readonly user?: UserOptions<F> | undefined
}

/**
 * {@link ConfigSettings} plus the providers, themselves read from the
 * environment.
 *
 * @category models
 * @since 0.1.0
 */
export interface OAuthConfigSettings extends ConfigSettings {
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

/**
 * Everything {@link layerConfigWithOAuth} accepts: {@link ConfigOptions} plus
 * the providers, themselves read from the environment.
 *
 * @category models
 * @since 0.1.0
 */
export interface OAuthConfigOptions<F extends UserFields = {}> extends ConfigOptions<F>, OAuthConfigSettings {
  /** Restated so that the two supertypes agree on it. See {@link Options.user}. */
  readonly user?: UserOptions<F> | undefined
}

// -----------------------------------------------------------------------------
// Layer shape
// -----------------------------------------------------------------------------

/**
 * Every service {@link layer} provides.
 *
 * **Details**
 *
 * Exactly the services an application — or `AuthHandlers.layer`, or a plugin —
 * has a reason to reach: the resolved configuration, the event hub, the four
 * stores and the transaction runner, the two crypto services a plugin builds its
 * own tokens and signed values with (`Token`, `Hmac`), the domain services, the
 * session cookie cache, the middleware implementation and the rate limiter.
 *
 * `PasswordHasher` and `OAuthProviders` are deliberately absent. They are
 * implementation detail of this stack, provided *into* it and not out of it, so
 * replacing one is a change to the options here rather than a layer a consumer
 * can shadow.
 *
 * The widening is what makes the plugin convention work: a plugin's layer names
 * what it needs in its own `Requirements`, and a consumer discharges all of it
 * with one `Layer.provideMerge(AuthLive)`.
 *
 * @category models
 * @since 0.1.0
 */
export type Services =
  | AuthConfig
  | AuthEvents
  | UserStore
  | SessionStore
  | AccountStore
  | VerificationStore
  | WithAuthTransaction
  | Token
  | Hmac
  | Verifications
  | Challenges
  | AuthCipher
  | SessionCache
  | Sessions
  | SignIn
  | Accounts
  | Passwords
  | Users
  | Authenticated
  | RateLimiter.RateLimiter

/**
 * Every service {@link layerWithOAuth} provides: {@link Services} plus the
 * OAuth flow the three social endpoints run on.
 *
 * @category models
 * @since 0.1.0
 */
export type OAuthServices = Services | OAuthFlow

/**
 * Everything {@link layer} still needs from the application: the database
 * client and the mailer.
 *
 * @category models
 * @since 0.1.0
 */
export type Requirements = SqlClient.SqlClient | AuthEmails

/**
 * Everything {@link layerWithOAuth} still needs: {@link Requirements} plus a
 * transport, because talking to a provider is the one thing this library does
 * over the network.
 *
 * @category models
 * @since 0.1.0
 */
export type OAuthRequirements = Requirements | HttpClient.HttpClient

// -----------------------------------------------------------------------------
// Composition
// -----------------------------------------------------------------------------

/**
 * The two services this stack *exposes* that need randomness or the instance
 * secret, over the WebCrypto-backed `Crypto` default.
 *
 * **Details**
 *
 * `Crypto` is provided *into* this tier and never surfaces, so it stays a detail
 * of this stack rather than something an application has to satisfy — see
 * `Requirements`. A deployment that wants a platform implementation provides
 * `Crypto.Crypto` above these layers itself.
 *
 * `Hmac` is built from the configuration *value* rather than from `AuthConfig`,
 * because this tier sits below the one that publishes the service — and there is
 * nothing to wait for: the secret is already resolved by the time `compose`
 * runs.
 */
/**
 * The HKDF `info` the stack's own {@link AuthCipher} derives its key from.
 *
 * **Details**
 *
 * `AuthCipher` is keyed by secret *class*: two classes derive different keys
 * from the same deployment secret and fail each other's tag check. The stack
 * publishes one, under this class, so that a plugin with a single kind of
 * secret to encrypt needs no wiring at all. A plugin that wants a class of its
 * own provides `AuthCipher.layer("<its info>")` above the stack, which shadows
 * this one for everything built over it.
 *
 * It is part of the stored format: changing it makes every ciphertext written
 * under it unreadable.
 *
 * @category constructors
 * @since 0.2.0
 */
export const defaultCipherKeyInfo = "effect-auth/cipher/v1"

const secretTier = (config: AuthConfigService): Layer.Layer<Token | Hmac> =>
  Layer.mergeAll(
    tokenLayer.pipe(Layer.provide(layerWebCrypto)),
    hmacLayer.pipe(Layer.provide(Layer.succeed(AuthConfig)(config)))
  )

/**
 * The password hasher, which stays an implementation detail.
 *
 * **Details**
 *
 * Separate from {@link secretTier} for exactly one reason: `Token` is part of
 * this stack's surface (a plugin mints its own single-use values with it) and
 * the hasher is not. Replacing the hasher is a change to `Extras.passwordHasher`
 * rather than a layer a consumer can shadow, which is what keeps the cost
 * parameters a deployment's hashes were written at in one place.
 */
const hasherTier = (
  hasher: Layer.Layer<PasswordHasher, never, Crypto.Crypto> | undefined
): Layer.Layer<PasswordHasher> => (hasher ?? layerScrypt()).pipe(Layer.provide(layerWebCrypto))

/**
 * Everything below the domain services: the resolved settings, the stores, the
 * event hub and the rate limiter.
 *
 * **Details**
 *
 * `Extras.sessionStore`, when given, is laid *over* the SQL stores: it is
 * provided them, so it may delegate, and merged above them, so what it publishes
 * is the `SessionStore` every service in the stack resolves.
 */
const baseTier = <F extends UserFields>(
  config: AuthConfigService,
  options: Extras,
  model: UserModel<F>
): Layer.Layer<AuthConfig | AuthStores | AuthEvents | RateLimiter.RateLimiter, never, SqlClient.SqlClient> => {
  const sqlStores = SqlStores.layerFor(model).pipe(Layer.provide(Layer.succeed(AuthConfig)(config)))
  const stores =
    options.sessionStore === undefined ? sqlStores : options.sessionStore.pipe(Layer.provideMerge(sqlStores))
  return Layer.mergeAll(
    Layer.succeed(AuthConfig)(config),
    stores,
    // `capacity` is optional and `undefined`-able, so an absent
    // `eventCapacity` is simply an absent capacity — no ternary needed.
    eventsLayer({ capacity: options.eventCapacity }),
    RateLimits.layer
  )
}

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
const compose = <A, RIn, F extends UserFields>(
  config: AuthConfigService,
  options: Extras,
  model: UserModel<F>,
  top: Layer.Layer<A, never, RIn>
) =>
  Layer.mergeAll(middlewareLayerFor(model), usersLayerFor(model)).pipe(
    // `Users` sits beside the middleware rather than in `top`, because it reads
    // `Passwords` — which is what `top` provides — and because both of the two
    // entry points want it.
    Layer.provideMerge(top),
    // The seams every sign-in path and every factor plugin converges on.
    // `SignIn` is what `Passwords` and the OAuth flow in `top` mint through, so
    // it sits underneath them; `Challenges` and `AuthCipher` are what a plugin
    // above the stack reaches for. The two `Context.Reference` seams —
    // `AuthHooks`, `Authenticators` and `SignInPipeline` — are deliberately not
    // installed here: a reference resolves to its own default, and providing
    // one inside the stack would silently discard whatever a plugin appended
    // underneath it.
    Layer.provideMerge(Layer.mergeAll(signInLayerFor(model), challengesLayer, cipherLayer(defaultCipherKeyInfo))),
    Layer.provideMerge(
      Layer.mergeAll(sessionsLayerFor(model), accountsLayer, verificationsLayer, sessionCacheLayerFor(model))
    ),
    Layer.provideMerge(baseTier(config, options, model)),
    Layer.provideMerge(secretTier(config)),
    Layer.provide(hasherTier(options.passwordHasher)),
    // The model itself, for a plugin that provisions users and has no `F` of
    // its own to be generic over. A `Context.Reference` has a default, so this
    // layer provides `never` and merging it widens nothing.
    Layer.provideMerge(Layer.succeed(UserModelRef)(model)),
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
const oauthTop = <F extends UserFields>(
  model: UserModel<F>,
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
  | SignIn
  | Verifications
  | Token
  | PasswordHasher
  | HttpClient.HttpClient
> => Layer.mergeAll(passwordsLayerFor(model), flowLayer.pipe(Layer.provide(OAuthProviders.layer(providers))))

/**
 * The whole non-OAuth stack for one model.
 *
 * **Details**
 *
 * The ternaries in the four entry points below are here rather than inside the
 * tiers for one reason: `UserModel<F>` and `UserModel<{}>` are different types,
 * so "the model, or the base one" is a choice that has to be made *before*
 * anything is built with it. Everything downstream of that choice is generic in
 * the single `F` it settled on, and — because the field-sensitive services are
 * reached through typed views rather than through keys of their own — none of it
 * reaches the result type.
 */
const stack = <F extends UserFields>(
  config: AuthConfigService,
  options: Extras,
  model: UserModel<F>
): Layer.Layer<Services, never, Requirements> => compose(config, options, model, passwordsLayerFor(model))

/** {@link stack}, with the OAuth flow on top. */
const oauthStack = <F extends UserFields>(
  config: AuthConfigService,
  options: Extras,
  model: UserModel<F>,
  providers: ReadonlyArray<OAuthProviderConfig>
): Layer.Layer<OAuthServices, never, OAuthRequirements> => compose(config, options, model, oauthTop(model, providers))

/** The settings {@link ConfigOptions} reads from the environment. */
interface ScalarSettings {
  readonly baseUrl: string
  readonly secret: Redacted.Redacted
  readonly basePath: string | undefined
  readonly trustedOrigins: ReadonlyArray<string> | undefined
  readonly trustedProviders: ReadonlyArray<string> | undefined
}

const resolveConfig = <F extends UserFields>(
  options: ConfigOptions<F>
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
        assurance: options.assurance,
        emailPassword: options.emailPassword,
        cookie: options.cookie,
        tokens: options.tokens,
        rateLimit: options.rateLimit,
        emailPaths: options.emailPaths,
        cookieCache: options.cookieCache,
        user: options.user
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
 * @since 0.1.0
 */
export const layer = <F extends UserFields = {}>(options: Options<F>): Layer.Layer<Services, never, Requirements> =>
  options.user?.model === undefined
    ? stack(makeAuthConfig(options), options, baseUserModel)
    : stack(makeAuthConfig(options), options, options.user.model)

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
 * @since 0.1.0
 */
export const layerWithOAuth = <F extends UserFields = {}>(
  options: OAuthOptions<F>
): Layer.Layer<OAuthServices, never, OAuthRequirements> =>
  options.user?.model === undefined
    ? oauthStack(makeAuthConfig(options), options, baseUserModel, options.providers)
    : oauthStack(makeAuthConfig(options), options, options.user.model, options.providers)

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
 * @since 0.1.0
 */
export const layerConfig = <F extends UserFields = {}>(
  options: ConfigOptions<F>
): Layer.Layer<Services, Config.ConfigError, Requirements> =>
  Layer.unwrap(
    Effect.map(resolveConfig(options), (config) =>
      options.user?.model === undefined
        ? stack(config, options, baseUserModel)
        : stack(config, options, options.user.model)
    )
  )

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
 * @since 0.1.0
 */
export const layerConfigWithOAuth = <F extends UserFields = {}>(
  options: OAuthConfigOptions<F>
): Layer.Layer<OAuthServices, Config.ConfigError | DiscoveryError, OAuthRequirements> =>
  Layer.unwrap(
    Effect.map(Effect.all([resolveConfig(options), Effect.all(options.providers)]), ([config, providers]) =>
      options.user?.model === undefined
        ? oauthStack(config, options, baseUserModel, providers)
        : oauthStack(config, options, options.user.model, providers)
    )
  )

/**
 * Provides only {@link AuthConfig}, for a process that needs the resolved
 * settings without the services — a migration script, or a second server that
 * only reads cookies.
 *
 * @category layers
 * @since 0.1.0
 */
export const layerConfigOnly: (options: AuthConfigOptions) => Layer.Layer<AuthConfig> = authConfigLayer

// -----------------------------------------------------------------------------
// Definition
// -----------------------------------------------------------------------------

/**
 * Everything a deployment that declared its own user fields needs, gathered
 * around one model.
 *
 * **Details**
 *
 * Nothing here is a new capability: every member is what the corresponding
 * per-module function returns for the same model, and a deployment that prefers
 * to call those directly loses nothing. What it saves is the one mistake this
 * design cannot catch cheaply — handing *different* models to the API, the
 * handlers, the stack and the client. There is one model in a definition, so
 * there is one everywhere.
 *
 * @category models
 * @since 0.1.0
 */
export interface Definition<F extends UserFields> {
  /** The model every other member is derived from. */
  readonly model: UserModel<F>

  /** The stored user: `User` with this deployment's fields. */
  readonly User: UserModel<F>["select"]
  /** The client-facing projection of {@link Definition.User}. */
  readonly UserPublic: UserModel<F>["json"]
  /** The body every endpoint that reads or establishes a session answers with. */
  readonly SessionWithUser: SessionWithUserSchema<F>
  /** The body sign-up answers with. */
  readonly SignUpResponse: SignUpResponseSchema<F>
  /** The body an endpoint that answers with a user and nothing else uses. */
  readonly UserResponse: UserResponseSchema<F>

  /** `CurrentUser`, seen through this model — how a handler reads a custom field. */
  readonly CurrentUser: Context.Service<CurrentUser, UserOf<F>>
  /** `UserStore`, seen through this model. */
  readonly UserStore: Context.Service<UserStore, UserStoreService<F>>
  /** `Sessions`, seen through this model. */
  readonly Sessions: Context.Service<Sessions, SessionsService<F>>
  /** `Passwords`, seen through this model. */
  readonly Passwords: Context.Service<Passwords, PasswordsService<F>>
  /** `Users`, seen through this model. */
  readonly Users: Context.Service<Users, UsersService<F>>

  /** The `auth` group, declared with this model. */
  readonly ApiGroup: AuthApiGroupOf<F>
  /** The `auth` group as a standalone `HttpApi`, ready to be merged into an application's. */
  readonly Api: HttpApi.HttpApi<"effect-auth", AuthApiGroupOf<F>>
  /** Implements {@link Definition.ApiGroup} inside an API that contains it. */
  readonly handlers: <ApiId extends string, Groups extends HttpApiGroup.Constraint>(
    api: HttpApi.HttpApi<ApiId, Groups> & { readonly groups: { readonly auth: AuthApiGroupOf<F> } }
  ) => Layer.Layer<HttpApiGroup.Service<ApiId, "auth">, never, AuthHandlers.HandlerServices>

  /** {@link layer}, for this model. */
  readonly layer: (options: Settings) => Layer.Layer<Services, never, Requirements>
  /** {@link layerWithOAuth}, for this model. */
  readonly layerWithOAuth: (options: OAuthSettings) => Layer.Layer<OAuthServices, never, OAuthRequirements>
  /** {@link layerConfig}, for this model. */
  readonly layerConfig: (options: ConfigSettings) => Layer.Layer<Services, Config.ConfigError, Requirements>
  /** {@link layerConfigWithOAuth}, for this model. */
  readonly layerConfigWithOAuth: (
    options: OAuthConfigSettings
  ) => Layer.Layer<OAuthServices, Config.ConfigError | DiscoveryError, OAuthRequirements>
  /**
   * `Migrations.layer` plus the columns this model's custom fields need.
   *
   * **Gotchas**
   *
   * A quickstart convenience, as `Migrations.layer` is: it runs on every build
   * rather than being recorded, which is what keeps a field added after the
   * first deployment from being silently skipped. A deployment that owns its
   * migrator numbers `Migrations.forUserFields(model)` into its own record
   * instead.
   */
  readonly layerMigrations: Layer.Layer<never, Migrator.MigrationError | SqlError.SqlError, SqlClient.SqlClient>
}

/**
 * What {@link define} takes.
 *
 * @category models
 * @since 0.1.0
 */
export interface DefineOptions<F extends UserFields> {
  readonly user: {
    /**
     * The fields to add to `User`, each declared with a `UserField` constructor.
     *
     * **Gotchas**
     *
     * Every one of them must be constructible without a value — see
     * `makeUserModel`, which throws at start-up when one is not.
     */
    readonly fields: F
  }
}

/**
 * Declares a deployment's user fields once, and derives everything that depends
 * on them.
 *
 * **Example**
 *
 * ```ts
 * import { Layer, Redacted, Schema } from "effect"
 * import { HttpApi } from "effect/unstable/httpapi"
 * import { Auth, UserField } from "effect-auth"
 *
 * const auth = Auth.define({
 *   user: {
 *     fields: {
 *       plan: UserField.withDefault(Schema.Literals(["free", "pro"]), () => "free" as const)
 *     }
 *   }
 * })
 *
 * const MyApi = HttpApi.make("app").addHttpApi(auth.Api)
 *
 * const AuthLive = auth.layer({
 *   baseUrl: "http://localhost:3000",
 *   secret: Redacted.make("a-32-byte-or-longer-random-string"),
 *   emailPassword: { enabled: true }
 * })
 *
 * const HandlersLive = auth.handlers(MyApi).pipe(Layer.provide(AuthLive))
 * ```
 *
 * **Gotchas**
 *
 * Call it once, at module scope, and import the result. Two calls with the same
 * fields build two models — the same shape, and *different types*, which the
 * compiler will point out at the first call site that mixes them.
 *
 * The client is deliberately not part of the bundle: this module is not
 * browser-safe. Pass the model to `AuthClient.make({ api, model })` instead.
 *
 * @category constructors
 * @since 0.1.0
 */
export const define = <const F extends UserFields>(options: DefineOptions<F>): Definition<F> => {
  const model = makeUserModel(options.user.fields)
  const ApiGroup = makeAuthApiGroup(model)
  return {
    model,
    User: model.select,
    UserPublic: model.json,
    SessionWithUser: makeSessionWithUser(model),
    SignUpResponse: makeSignUpResponse(model),
    UserResponse: makeUserResponse(model),
    CurrentUser: currentUserOf(model),
    UserStore: userStoreOf(model),
    Sessions: sessionsOf(model),
    Passwords: passwordsOf(model),
    Users: usersOf(model),
    ApiGroup,
    Api: makeAuthApi(model),
    handlers: (api) => AuthHandlers.layer(api, model),
    layer: (settings) => stack(makeAuthConfig(settings), settings, model),
    layerWithOAuth: (settings) => oauthStack(makeAuthConfig(settings), settings, model, settings.providers),
    layerConfig: (settings) =>
      Layer.unwrap(Effect.map(resolveConfig(settings), (config) => stack(config, settings, model))),
    layerConfigWithOAuth: (settings) =>
      Layer.unwrap(
        Effect.map(Effect.all([resolveConfig(settings), Effect.all(settings.providers)]), ([config, providers]) =>
          oauthStack(config, settings, model, providers)
        )
      ),
    layerMigrations: Migrations.layerFor(model)
  }
}

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
 * @since 0.1.0
 */
export const cleanupExpired: Effect.Effect<
  { readonly sessions: number; readonly verifications: number },
  PersistenceError,
  SessionStore | VerificationStore
> = Effect.gen(function* () {
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
 * @since 0.1.0
 */
export const layerCleanup = (options?: {
  readonly interval?: Duration.Duration | undefined
}): Layer.Layer<never, never, SessionStore | VerificationStore> =>
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
 * import { Auth, AuthEvents } from "effect-auth"
 *
 * // `AuthEvent.matchOrElse` names the members this sink reports on and hands
 * // the rest to one fallback; `AuthEvent.match` is the exhaustive form.
 * const audit = Stream.runForEach(
 *   Auth.events,
 *   AuthEvents.AuthEvent.matchOrElse(
 *     { SignedIn: (event) => Effect.log("signed in", event.userId) },
 *     (event) => Effect.logDebug("auth event", event)
 *   )
 * )
 * ```
 *
 * **Gotchas**
 *
 * The hub drops rather than blocks, so a consumer that stops pulling costs
 * events, never a wedged sign-in. There is no replay: subscribe before the
 * traffic you want to observe.
 *
 * @category models
 * @since 0.1.0
 */
export const events: Stream.Stream<AuthEvent, never, AuthEvents> = Stream.unwrap(
  AuthEvents.use((hub) => Effect.succeed(hub.stream))
)
