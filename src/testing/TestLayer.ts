/**
 * A complete `effect-auth` deployment for a test suite: an in-memory PGlite
 * database with the migrations already applied, a fixed secret, a mailer that
 * captures what it was asked to deliver instead of sending it, and password
 * hashing at a cost a suite can afford.
 *
 * Everything runs under `it.effect` and `TestClock`, so session expiry, the
 * rolling refresh and token TTLs are all reachable by moving virtual time.
 *
 * **Details**
 *
 * {@link layerDatabase} and {@link layerStores} are module-level constants on
 * purpose. `@effect/vitest`'s `layer()` memoises a parent block's layers **by
 * object identity** when a nested `it.layer` forks the memo map, so a sub-block
 * that varies the configuration reuses the database the parent already booted —
 * one PGlite per file instead of one per test. Building them inside a function
 * would defeat that.
 *
 * A deployment with custom user fields needs a database with its columns, and
 * therefore one per model rather than one for the library. {@link layerDatabaseFor}
 * keeps the same guarantee by memoising on the model itself, so a fixture's model
 * is what ties a file's blocks to one PGlite.
 *
 * @since 1.0.0
 */
import { PgliteClient } from "@effect/sql-pglite"
import type { Crypto, Scope } from "effect"
import { Effect, FileSystem, Layer, Path, PubSub, Redacted } from "effect"
import { TestClock } from "effect/testing"
import type { HttpClient } from "effect/unstable/http"
import { Etag, FetchHttpClient, HttpPlatform } from "effect/unstable/http"
import type { HttpApiGroup } from "effect/unstable/httpapi"
import { HttpApi } from "effect/unstable/httpapi"
import type { SqlClient, SqlError } from "effect/unstable/sql"
import type { Migrator } from "effect/unstable/sql"
import type { OAuthServices, ProviderList, Services } from "../config/Auth.js"
import { layer as authLayer, layerWithOAuth as authOAuthLayer } from "../config/Auth.js"
import type {
  AuthConfigOptions,
  CookieCacheConfig,
  CookieConfig,
  EmailPasswordConfig,
  EmailPathConfig,
  PartialOptions,
  RateLimitConfig,
  SessionConfig,
  TokenConfig
} from "../config/AuthConfig.js"
import type { ScryptOptions } from "../crypto/PasswordHasher.js"
import { layerScrypt, makeScrypt, PasswordHasher } from "../crypto/PasswordHasher.js"
import type { AuthEvent } from "../domain/Events.js"
import { AuthEvents } from "../domain/Events.js"
import type { UserFields, UserModel } from "../domain/Schema.js"
import { baseUserModel } from "../domain/Schema.js"
import type { AuthStores, SessionStoreService } from "../domain/Stores.js"
import { SessionStore } from "../domain/Stores.js"
import type { AuthApiGroupOf } from "../http/AuthApi.js"
import { AuthApi } from "../http/AuthApi.js"
import * as AuthHandlers from "../http/Handlers.js"
import { webCrypto } from "../internal/crypto.js"
import * as Migrations from "../sql/Migrations.js"
import * as SqlStores from "../sql/SqlStores.js"
import type { EmailDelivery } from "./TestEmails.js"
import { layerEmails, TestEmails } from "./TestEmails.js"

export type { EmailDelivery, EmailKind, SentEmail, TestEmailsService } from "./TestEmails.js"
export { layerEmails, resetKind, TestEmails, verificationKind } from "./TestEmails.js"

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/**
 * The secret every test deployment is keyed with. Fixed on purpose: a signature
 * produced in one test is verifiable in the next, and nothing here is a
 * credential worth protecting.
 *
 * @category constructors
 * @since 1.0.0
 */
export const testSecret: Redacted.Redacted<string> = Redacted.make(
  "effect-auth-test-secret-do-not-use-in-production"
)

/**
 * The default base URL: plain HTTP, so the session cookie is written under its
 * un-prefixed name and a test can look for it without knowing whether TLS was
 * simulated.
 *
 * @category constructors
 * @since 1.0.0
 */
export const testBaseUrl = "http://localhost:3000"

/**
 * Scrypt parameters small enough for a suite. The stored format records the
 * cost it was written at, so a hash produced here still verifies under the
 * production layer.
 *
 * @category constructors
 * @since 1.0.0
 */
export const testScryptOptions: ScryptOptions = { N: 1024, r: 8, p: 1 }

// -----------------------------------------------------------------------------
// Options
// -----------------------------------------------------------------------------

/**
 * What a test may vary about the deployment under test, apart from the user
 * model. Everything is optional; the defaults are a working e-mail/password
 * deployment with the rate limits switched off.
 *
 * @category models
 * @since 1.0.0
 */
export interface Settings {
  readonly baseUrl?: string | undefined
  readonly secret?: Redacted.Redacted<string> | undefined
  readonly basePath?: string | undefined
  readonly trustedOrigins?: ReadonlyArray<string> | undefined
  readonly trustedProviders?: ReadonlyArray<string> | undefined
  readonly session?: PartialOptions<SessionConfig> | undefined
  readonly emailPassword?: PartialOptions<EmailPasswordConfig> | undefined
  readonly cookie?: PartialOptions<CookieConfig> | undefined
  readonly tokens?: PartialOptions<TokenConfig> | undefined
  readonly rateLimit?: PartialOptions<RateLimitConfig> | undefined
  readonly emailPaths?: PartialOptions<EmailPathConfig> | undefined
  /**
   * Cookie cache overrides. Off by default, exactly as in production.
   */
  readonly cookieCache?: PartialOptions<CookieCacheConfig> | undefined
  /**
   * A `SessionStore` laid over the SQL one — the seam
   * {@link countingSessionStore} plugs into.
   */
  readonly sessionStore?: Layer.Layer<SessionStore, never, SessionStore> | undefined
  /**
   * Scrypt cost overrides. Defaults to {@link testScryptOptions}, and is
   * ignored when {@link Settings.hasher} is given.
   */
  readonly scrypt?: ScryptOptions | undefined
  /**
   * A hashing layer to use instead of scrypt at test cost — the seam
   * {@link countingHasher} plugs into.
   */
  readonly hasher?: Layer.Layer<PasswordHasher, never, Crypto.Crypto> | undefined
  /**
   * Whether the capturing mailer accepts what it is handed, or records it and
   * then reports a delivery failure. Defaults to `"ok"`.
   */
  readonly emailDelivery?: EmailDelivery | undefined
}

/**
 * {@link Settings}, plus the user model the deployment is built for.
 *
 * **Details**
 *
 * Leaving `user` out is the same as passing `baseUserModel` — every existing
 * test in this library does. A block that varies the model passes the one its
 * fixture built, and gets a deployment whose stores, sign-up and middleware all
 * carry it.
 *
 * @category models
 * @since 1.0.0
 */
export interface Options<F extends UserFields = {}> extends Settings {
  readonly user?: { readonly model: UserModel<F> } | undefined
}

/**
 * Resolves {@link Options} into the options `Auth.layer` takes.
 *
 * **Details**
 *
 * The two departures from the library defaults are deliberate:
 * `emailPassword.enabled` is `true` (a test that had to switch it on before it
 * could sign anybody up would say nothing about the library), and
 * `rateLimit.enabled` is `false` (three requests is fewer than most flows make,
 * so the limits would fire in tests that are not about them — switch them back
 * on in the tests that are).
 *
 * @category constructors
 * @since 1.0.0
 */
export const testConfig = (options?: Settings): AuthConfigOptions => ({
  baseUrl: options?.baseUrl ?? testBaseUrl,
  secret: options?.secret ?? testSecret,
  basePath: options?.basePath,
  trustedOrigins: options?.trustedOrigins,
  trustedProviders: options?.trustedProviders,
  session: options?.session,
  emailPassword: { enabled: true, ...options?.emailPassword },
  cookie: options?.cookie,
  tokens: options?.tokens,
  rateLimit: { enabled: false, ...options?.rateLimit },
  emailPaths: options?.emailPaths,
  cookieCache: options?.cookieCache
})

const hasherOf = (options?: Settings): Layer.Layer<PasswordHasher, never, Crypto.Crypto> =>
  options?.hasher ?? layerScrypt(options?.scrypt ?? testScryptOptions)

/**
 * Everything above the database, built on a memo map of its own.
 *
 * `Layer.fresh` is what makes a nested `it.layer` variant mean anything.
 * `Auth.layer` composes module-level constants — `passwordsLayer`,
 * `sessionsLayer`, `SqlStores.layer` and the rest — and a nested block forks its
 * parent's memo map, so without this a sub-block that asked for, say,
 * `requireEmailVerification: true` would be handed the parent's `Passwords`,
 * built against the parent's configuration, and would silently test nothing.
 * The database stays *outside* this boundary, so it is still shared.
 */
const composed = <F extends UserFields>(options: Settings | undefined, model: UserModel<F>) =>
  Layer.fresh(
    authLayer({
      ...testConfig(options),
      passwordHasher: hasherOf(options),
      sessionStore: options?.sessionStore,
      user: { model }
    }).pipe(
      Layer.provideMerge(layerEmails(options?.emailDelivery))
    )
  )

// -----------------------------------------------------------------------------
// Layers
// -----------------------------------------------------------------------------

/**
 * One PGlite per model, keyed by the model itself.
 *
 * `layer()` memoises by object identity, so handing the same layer *value* to
 * every block in a file is what keeps them sharing one database. A model is the
 * natural key: a file that declares custom fields has exactly one, and asking
 * twice has to answer with the same layer or the second block boots a second,
 * empty database.
 */
const databases = new WeakMap<
  object,
  Layer.Layer<SqlClient.SqlClient | PgliteClient.PgliteClient, Migrator.MigrationError | SqlError.SqlError>
>()

/**
 * A fresh in-memory PGlite database with `effect-auth`'s migrations applied and
 * `model`'s own user columns added.
 *
 * **Gotchas**
 *
 * Memoised on the model, so calling it twice with the same model hands back the
 * same layer and therefore the same database — which is what a nested
 * `it.layer` needs in order to inherit its parent block's rows. Building an
 * equivalent layer yourself gets you a second, empty one.
 *
 * @category layers
 * @since 1.0.0
 */
export const layerDatabaseFor = <F extends UserFields>(
  model: UserModel<F>
): Layer.Layer<
  SqlClient.SqlClient | PgliteClient.PgliteClient,
  Migrator.MigrationError | SqlError.SqlError
> => {
  const existing = databases.get(model)
  if (existing !== undefined) return existing
  const created = Migrations.layerFor(model).pipe(Layer.provideMerge(PgliteClient.layer()))
  databases.set(model, created)
  return created
}

/**
 * The four stores of `model` over {@link layerDatabaseFor} — the whole
 * persistence tier, with nothing of the domain on top.
 *
 * @category layers
 * @since 1.0.0
 */
export const layerStoresFor = <F extends UserFields>(
  model: UserModel<F>
): Layer.Layer<
  AuthStores | SqlClient.SqlClient | PgliteClient.PgliteClient,
  Migrator.MigrationError | SqlError.SqlError
> => SqlStores.layerFor(model).pipe(Layer.provideMerge(layerDatabaseFor(model)))

/**
 * A fresh in-memory PGlite database with `effect-auth`'s migrations applied.
 *
 * **Gotchas**
 *
 * This is a module-level constant so that `layer()` blocks memoise it: every
 * layer in this module composes *this* value, so a nested `it.layer` reuses the
 * database its parent block already booted. Building an equivalent layer
 * yourself gets you a second, empty one.
 *
 * @category layers
 * @since 1.0.0
 */
export const layerDatabase: Layer.Layer<
  SqlClient.SqlClient | PgliteClient.PgliteClient,
  Migrator.MigrationError | SqlError.SqlError
> = layerDatabaseFor(baseUserModel)

/**
 * The four stores over {@link layerDatabase} — the whole persistence tier, with
 * nothing of the domain on top.
 *
 * **When to use**
 *
 * For the store tests themselves, and for anything that reads or writes rows
 * without going through `Sessions`, `Accounts` or `Passwords`.
 *
 * @category layers
 * @since 1.0.0
 */
export const layerStores: Layer.Layer<
  AuthStores | SqlClient.SqlClient | PgliteClient.PgliteClient,
  Migrator.MigrationError | SqlError.SqlError
> = layerStoresFor(baseUserModel)

/**
 * The whole test deployment: {@link layerDatabase}, the capturing mailer, and
 * `Auth.layer` at test cost.
 *
 * **Example**
 *
 * ```ts
 * import { assert, layer } from "@effect/vitest"
 * import { Effect, Redacted } from "effect"
 * import { Passwords } from "effect-auth"
 * import { AuthTest } from "effect-auth/testing"
 *
 * layer(AuthTest.layer())("passwords", (it) => {
 *   it.effect("signs a person up", () =>
 *     Effect.gen(function*() {
 *       const passwords = yield* Passwords.Passwords
 *       const { user } = yield* passwords.signUp({
 *         name: "Ada",
 *         email: "ada@example.com",
 *         password: Redacted.make("correct horse battery staple")
 *       })
 *       assert.strictEqual(user.email, "ada@example.com")
 *     }))
 * })
 * ```
 *
 * **Gotchas**
 *
 * This is `Auth.layer`, so `OAuthFlow` is absent and no `HttpClient` is needed;
 * {@link layerFlow} is the OAuth-shaped equivalent.
 *
 * Tests that share one of these share its database, so give every account a
 * distinct address and scope outbox assertions by recipient. A test that moves
 * the clock must wrap its body in {@link freshClock}: the block's `TestClock`
 * is shared too, and so is the event hub — see {@link recordingEvents}.
 *
 * A nested `it.layer(AuthTest.layer({ … }))` is a real configuration variant:
 * everything above the database is rebuilt for it, and only the database is
 * inherited from the enclosing block.
 *
 * `options.user.model` builds the deployment for a model with custom fields —
 * over that model's own database, which {@link layerDatabaseFor} memoises, so a
 * fixture's model is what ties a file's blocks to one PGlite.
 *
 * @category layers
 * @since 1.0.0
 */
export const layer = <F extends UserFields = {}>(
  options?: Options<F>
): Layer.Layer<
  Services | SqlClient.SqlClient | PgliteClient.PgliteClient | TestEmails,
  Migrator.MigrationError | SqlError.SqlError
> =>
  options?.user === undefined
    ? deployment(options, baseUserModel)
    : deployment(options, options.user.model)

/** {@link layer}, once the model has been settled on. See `Auth.stack`. */
const deployment = <F extends UserFields>(
  options: Settings | undefined,
  model: UserModel<F>
): Layer.Layer<
  Services | SqlClient.SqlClient | PgliteClient.PgliteClient | TestEmails,
  Migrator.MigrationError | SqlError.SqlError
> => composed(options, model).pipe(Layer.provideMerge(layerDatabaseFor(model)))

/**
 * A transport backed by a `fetch` a test controls — `MockProvider.mockServer`'s,
 * usually.
 *
 * @category layers
 * @since 1.0.0
 */
export const layerFetch = (fetch: typeof globalThis.fetch): Layer.Layer<HttpClient.HttpClient> =>
  FetchHttpClient.layer.pipe(Layer.provide(Layer.succeed(FetchHttpClient.Fetch)(fetch)))

/**
 * What {@link layerFlow} needs on top of {@link Settings}.
 *
 * @category models
 * @since 1.0.0
 */
export interface FlowSettings extends Settings {
  /**
   * The providers the deployment serves. Non-empty: a deployment with none uses
   * {@link layer}.
   */
  readonly providers: ProviderList
  /**
   * The transport every provider call goes over.
   */
  readonly fetch: typeof globalThis.fetch
}

/**
 * What {@link layerFlow} needs on top of {@link Options}.
 *
 * @category models
 * @since 1.0.0
 */
export interface FlowOptions<F extends UserFields = {}> extends Options<F>, FlowSettings {}

/**
 * {@link layer} with the OAuth flow in it, talking to a stubbed provider.
 *
 * @category layers
 * @since 1.0.0
 */
export const layerFlow = <F extends UserFields = {}>(
  options: FlowOptions<F>
): Layer.Layer<
  OAuthServices | SqlClient.SqlClient | PgliteClient.PgliteClient | TestEmails,
  Migrator.MigrationError | SqlError.SqlError
> =>
  options.user === undefined
    ? flowDeployment(options, baseUserModel)
    : flowDeployment(options, options.user.model)

/** {@link layerFlow}, once the model has been settled on. */
const flowDeployment = <F extends UserFields>(
  options: FlowSettings,
  model: UserModel<F>
): Layer.Layer<
  OAuthServices | SqlClient.SqlClient | PgliteClient.PgliteClient | TestEmails,
  Migrator.MigrationError | SqlError.SqlError
> =>
  Layer.fresh(
    authOAuthLayer({
      ...testConfig(options),
      passwordHasher: hasherOf(options),
      sessionStore: options.sessionStore,
      providers: options.providers,
      user: { model }
    }).pipe(
      Layer.provideMerge(layerEmails(options.emailDelivery)),
      Layer.provide(layerFetch(options.fetch))
    )
  ).pipe(Layer.provideMerge(layerDatabaseFor(model)))

/**
 * The platform services an `HttpApi` needs in order to encode a response.
 *
 * @category layers
 * @since 1.0.0
 */
export const layerPlatform: Layer.Layer<
  Path.Path | Etag.Generator | HttpPlatform.HttpPlatform | FileSystem.FileSystem
> = Layer.mergeAll(Path.layer, Etag.layerWeak, HttpPlatform.layer).pipe(
  Layer.provideMerge(FileSystem.layerNoop({}))
)

/**
 * An application API that embeds `effect-auth`'s group, exactly as a consumer
 * composes it — and therefore what `AuthHandlers.layer` has to infer against.
 *
 * @category constructors
 * @since 1.0.0
 */
export const TestApi = HttpApi.make("test-app").addHttpApi(AuthApi)

/**
 * Everything a request has to cross: {@link layer}, the handlers of `api`'s
 * `auth` group, whatever `extra` adds, and {@link layerPlatform}.
 *
 * **When to use**
 *
 * `extra` is the plugin seam. Hand it a plugin's handler layer — or its whole
 * stack — and it is provided the *same* `layer(options)` build the auth handlers
 * get, so the plugin reads the deployment's own `Sessions`, `UserStore` and rate
 * limiter rather than a second copy of them. Whatever it provides is part of the
 * result, which is what lets a test's `HttpApiBuilder.layer` see a plugin's group
 * implemented.
 *
 * **Example**
 *
 * ```ts skip-type-checking
 * const TestLayer = AuthTest.layerHttpApi(MagicLinkTest.TestApi, options, MagicLink.handlers(MagicLinkTest.TestApi))
 * ```
 *
 * **Gotchas**
 *
 * Two signatures rather than one optional parameter, because a `Layer`'s output
 * is contravariant: there is no value that "provides `Extra`" to fall back on
 * when no layer was given, and inventing one would need a cast. The two
 * signatures say the same thing the two call shapes mean.
 *
 * @category layers
 * @since 1.0.0
 */
export function layerHttpApi<
  ApiId extends string,
  Groups extends HttpApiGroup.Constraint,
  F extends UserFields = {}
>(
  api:
    & HttpApi.HttpApi<ApiId, Groups>
    & { readonly groups: { readonly auth: NoInfer<AuthApiGroupOf<F>> } },
  options?: Options<F>
): HttpApiLayer<ApiId>
export function layerHttpApi<
  ApiId extends string,
  Groups extends HttpApiGroup.Constraint,
  Extra,
  F extends UserFields = {}
>(
  api:
    & HttpApi.HttpApi<ApiId, Groups>
    & { readonly groups: { readonly auth: NoInfer<AuthApiGroupOf<F>> } },
  options: Options<F> | undefined,
  extra: Layer.Layer<Extra, never, DeploymentServices>
): HttpApiLayer<ApiId, Extra>
export function layerHttpApi<ApiId extends string, Groups extends HttpApiGroup.Constraint, F extends UserFields>(
  api:
    & HttpApi.HttpApi<ApiId, Groups>
    & { readonly groups: { readonly auth: NoInfer<AuthApiGroupOf<F>> } },
  options?: Options<F>,
  // `Layer<never, …>` accepts a layer providing anything at all — the output
  // channel is contravariant — so this is the widest parameter, not the
  // narrowest.
  extra?: Layer.Layer<never, never, DeploymentServices>
): HttpApiLayer<ApiId> {
  // One build, provided to both halves: a plugin's handlers and the auth
  // handlers then share the deployment's services rather than getting two
  // instances of them — which is the whole point of the seam, since a plugin
  // reads `Sessions`, `UserStore` and the rest of what the deployment published.
  const deployment = layer(options)
  // `options.user.model` reaches both halves: the handlers, so sign-up accepts
  // the deployment's own fields, and the deployment, so its stores write them.
  // `AuthHandlers.layer` is what rejects an API and a model that disagree.
  const handlers = AuthHandlers.layer(api, options?.user?.model)
  const groups = extra === undefined ? handlers : Layer.merge(handlers, extra)
  return Layer.merge(groups.pipe(Layer.provideMerge(deployment)), layerPlatform)
}

/**
 * Everything a test deployment publishes — what an `extra` layer handed to
 * {@link layerHttpApi} may ask for.
 *
 * @category models
 * @since 1.0.0
 */
export type DeploymentServices =
  | Services
  | SqlClient.SqlClient
  | PgliteClient.PgliteClient
  | TestEmails

/**
 * What {@link layerHttpApi} builds: the deployment, the handlers of the API's
 * `auth` group, whatever `extra` provided, and the platform services a response
 * is encoded with.
 *
 * @category models
 * @since 1.0.0
 */
export type HttpApiLayer<ApiId extends string, Extra = never> = Layer.Layer<
  | HttpApiGroup.Service<ApiId, "auth">
  | Extra
  | DeploymentServices
  | Path.Path
  | Etag.Generator
  | HttpPlatform.HttpPlatform
  | FileSystem.FileSystem,
  Migrator.MigrationError | SqlError.SqlError
>

/**
 * {@link layerHttpApi} over {@link TestApi} — the whole server stack a test of
 * this library's own endpoints runs on.
 *
 * @category layers
 * @since 1.0.0
 */
export function layerHttp(options?: Settings): HttpApiLayer<"test-app">
export function layerHttp<Extra>(
  options: Settings | undefined,
  extra: Layer.Layer<Extra, never, DeploymentServices>
): HttpApiLayer<"test-app", Extra>
export function layerHttp(
  options?: Settings,
  extra?: Layer.Layer<never, never, DeploymentServices>
): HttpApiLayer<"test-app"> {
  return extra === undefined ? layerHttpApi(TestApi, options) : layerHttpApi(TestApi, options, extra)
}

// -----------------------------------------------------------------------------
// Seams
// -----------------------------------------------------------------------------

/**
 * Runs `effect` on a `TestClock` of its own.
 *
 * **When to use**
 *
 * Inside a `layer()` block. The block builds its layers once, with one
 * `TestClock` shared by every test in it, so a test that calls
 * `TestClock.adjust` would move time for its siblings too. Providing an inner
 * clock shadows the shared one for the duration of this effect, which is what
 * makes a clock-moving test safe to run beside the others.
 *
 * **Gotchas**
 *
 * Every time this library reads the clock it reads it from the running fiber,
 * so the inner clock governs the whole body — including the services the block
 * layer built before it started.
 *
 * **Example**
 *
 * ```ts
 * import { Duration, Effect } from "effect"
 * import { TestClock } from "effect/testing"
 * import { AuthTest } from "effect-auth/testing"
 *
 * const expiry = AuthTest.freshClock(
 *   Effect.gen(function*() {
 *     yield* TestClock.adjust(Duration.days(8))
 *   })
 * )
 * ```
 *
 * @category combinators
 * @since 1.0.0
 */
export const freshClock = <A, E, R>(effect: Effect.Effect<A, E, R>): Effect.Effect<A, E, R> =>
  Effect.provide(effect, TestClock.layer())

/**
 * What {@link countingHasher} counts.
 *
 * @category models
 * @since 1.0.0
 */
export interface HasherCounts {
  hashes: number
  verifies: number
}

/**
 * A `PasswordHasher` that delegates to the real scrypt implementation and
 * counts what it was asked to do.
 *
 * **When to use**
 *
 * The timing defence in `Passwords.signIn` is invisible from the outside — an
 * unknown address and a wrong password produce the same error either way. What
 * distinguishes a correct implementation is that it *runs a verification* in
 * both cases, and that is what this counts.
 *
 * **Gotchas**
 *
 * The counter is shared by every test the layer is built for, so a block that
 * asserts on it must run sequentially.
 *
 * @category constructors
 * @since 1.0.0
 */
export const countingHasher = (
  options?: ScryptOptions
): { readonly layer: Layer.Layer<PasswordHasher>; readonly state: HasherCounts } => {
  const state: HasherCounts = { hashes: 0, verifies: 0 }
  const inner = makeScrypt(webCrypto, options ?? testScryptOptions)
  const layer = Layer.succeed(PasswordHasher)({
    hash: (password) =>
      Effect.suspend(() => {
        state.hashes++
        return inner.hash(password)
      }),
    verify: (password, hash) =>
      Effect.suspend(() => {
        state.verifies++
        return inner.verify(password, hash)
      })
  })
  return { layer, state }
}

/**
 * What {@link countingSessionStore} counts.
 *
 * @category models
 * @since 1.0.0
 */
export interface SessionStoreCounts {
  /** How many times a session was resolved from its token — a database read. */
  reads: number
  /** How many times the rolling refresh wrote a new expiry. */
  touches: number
}

/**
 * A `SessionStore` that delegates to the real one and counts the two operations
 * an authenticated request performs.
 *
 * **When to use**
 *
 * For the cookie cache, whose whole claim is *zero database reads on a hit*. It
 * is invisible from the outside — a cached request and an uncached one answer
 * identically — so what distinguishes the two is exactly this counter.
 *
 * **Example**
 *
 * ```ts
 * import { AuthTest } from "effect-auth/testing"
 *
 * const store = AuthTest.countingSessionStore()
 * const TestLayer = AuthTest.layerHttp({ cookieCache: { enabled: true }, sessionStore: store.layer })
 * ```
 *
 * **Gotchas**
 *
 * The counter is shared by every test the layer is built for, so a block that
 * asserts on it must run sequentially.
 *
 * @category constructors
 * @since 1.0.0
 */
export const countingSessionStore = (): {
  readonly layer: Layer.Layer<SessionStore, never, SessionStore>
  readonly state: SessionStoreCounts
} => {
  const state: SessionStoreCounts = { reads: 0, touches: 0 }
  const layer = Layer.effect(
    SessionStore,
    Effect.map(SessionStore, (inner): SessionStoreService => ({
      ...inner,
      findByTokenHash: (tokenHash) =>
        Effect.suspend(() => {
          state.reads++
          return inner.findByTokenHash(tokenHash)
        }),
      touch: (id, expiresAt) =>
        Effect.suspend(() => {
          state.touches++
          return inner.touch(id, expiresAt)
        })
    }))
  )
  return { layer, state }
}

/**
 * What {@link recordingEvents} hands back.
 *
 * @category models
 * @since 1.0.0
 */
export interface Recorded<A> {
  readonly result: A
  readonly events: ReadonlyArray<AuthEvent>
}

/**
 * Collects every `AuthEvent` the domain services publish while `body` runs, and
 * hands them back alongside its result.
 *
 * **Gotchas**
 *
 * The subscription is opened *before* `body` starts: the hub drops rather than
 * replays, so a subscriber attached afterwards would see nothing.
 *
 * The hub belongs to the deployment, not to the test. Inside a `layer()` block
 * whose tests run concurrently, this collects what the *siblings* published too.
 * Either run such a block sequentially, or assert on the events for one user
 * rather than on the whole sequence.
 *
 * @category combinators
 * @since 1.0.0
 */
export const recordingEvents = <A, E, R>(
  body: Effect.Effect<A, E, R>
): Effect.Effect<Recorded<A>, E, R | AuthEvents | Scope.Scope> =>
  Effect.gen(function*() {
    const hub = yield* AuthEvents
    const subscription = yield* hub.subscribe
    const result = yield* body
    const buffered = yield* PubSub.remaining(subscription)
    const events: ReadonlyArray<AuthEvent> = buffered === 0
      ? []
      : yield* PubSub.takeUpTo(subscription, buffered)
    return { result, events }
  })

/**
 * The tags of the events collected by {@link recordingEvents}, in order.
 *
 * @category combinators
 * @since 1.0.0
 */
export const tagsOf = (events: ReadonlyArray<AuthEvent>): ReadonlyArray<string> =>
  events.map((event) => event._tag)
