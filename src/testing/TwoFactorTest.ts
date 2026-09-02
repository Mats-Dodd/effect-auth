/**
 * The two-factor plugin, wired into a test deployment.
 *
 * **Details**
 *
 * The shape `EmailOtpTest` established — a mailer over the shared outbox, a
 * layer that adds the plugin to `AuthTest.layer`'s deployment, an API that
 * composes both groups, and the whole server stack for it — plus the two things
 * a plugin with tables and a pipeline decider adds:
 *
 * - {@link database} runs the plugin's own migrations over the *same* PGlite
 *   `AuthTest` memoises, so a file still boots one database;
 * - the decider and the authenticator contributor are built here as **values**
 *   and handed to `AuthTest.Settings.signInPipeline` / `.authenticators`, which
 *   is how a `Context.Reference` gets underneath a deployment that is composed
 *   in one call. It is the same arrangement `TwoFactor.layerSeams` builds for
 *   an application, expressed against the harness's own seam.
 *
 * **Example**
 *
 * ```ts skip-type-checking
 * import { layer } from "@effect/vitest"
 * import { TwoFactorTest } from "effect-auth/testing"
 *
 * layer(TwoFactorTest.layerHttp())("two-factor", (it) => {
 *   it.effect("asks a TOTP user for a code", () => …)
 * })
 * ```
 *
 * @since 0.2.0
 */
import { Effect, Layer, Redacted } from "effect"
import { TestClock } from "effect/testing"
import type { HttpApiGroup } from "effect/unstable/httpapi"
import { HttpApi } from "effect/unstable/httpapi"
import type { Migrator, SqlClient, SqlError } from "effect/unstable/sql"
import type { Services } from "../config/Auth.js"
import { layer as authConfigLayer } from "../config/AuthConfig.js"
import { baseUserModel } from "../domain/Schema.js"
import { AuthApi } from "../http/AuthApi.js"
import { TwoFactorApiGroup } from "../two-factor/Api.js"
import { handlers as twoFactorHandlers } from "../two-factor/Handlers.js"
import * as TwoFactorMigrations from "../two-factor/Migrations.js"
import type { Options as TwoFactorOptions, Requirements, TwoFactor } from "../two-factor/TwoFactor.js"
import { layer as twoFactorLayer, makeSeams, seamServices, TwoFactorEmails } from "../two-factor/TwoFactor.js"
import type * as Database from "./Database.js"
import { memoise } from "./internal/memo.js"
import { type EmailKind, TestEmails } from "./TestEmails.js"
import * as AuthTest from "./TestLayer.js"

/**
 * The kind the captured outbox records the "a recovery code was used" message
 * under.
 *
 * **Gotchas**
 *
 * `to` is the account's address, and the message carries no token — a
 * notification is not a credential. The outbox's `token` and `url` therefore
 * hold the *remaining code count*, as a string, which is the one number a test
 * wants to assert about it.
 *
 * @category constructors
 * @since 0.2.0
 */
export const recoveryCodeUsedKind: EmailKind = "two-factor-recovery-code-used"

/**
 * The plugin's mailer, implemented over the shared outbox.
 *
 * @category layers
 * @since 0.2.0
 */
export const layerEmails: Layer.Layer<TwoFactorEmails, never, TestEmails> = Layer.effect(
  TwoFactorEmails,
  Effect.map(TestEmails, (outbox) => ({
    sendRecoveryCodeUsed: (email) =>
      outbox.record({
        kind: recoveryCodeUsedKind,
        to: email.user.email,
        user: email.user,
        token: Redacted.make(String(email.remaining)),
        url: Redacted.make(String(email.remaining))
      })
  }))
)

/**
 * What a test may vary about a deployment serving two-factor authentication.
 *
 * @category models
 * @since 0.2.0
 */
export interface Options extends AuthTest.Settings {
  /** The plugin's own settings — the TOTP parameters, the TTLs, the budget. */
  readonly twoFactor?: TwoFactorOptions | undefined
}

/** One database per provider, memoised so that every block on it shares one. */
const databases = memoise((provider: Database.Provider) =>
  TwoFactorMigrations.layer.pipe(Layer.provideMerge(AuthTest.layerDatabaseFor(baseUserModel, provider)))
)

/**
 * The test database with this plugin's tables in it.
 *
 * **Gotchas**
 *
 * A module-level constant, and that is load-bearing twice over: `layer()`
 * memoises by object identity, so every block in a file shares one database,
 * and it is composed over `AuthTest.layerDatabaseFor` — the same memoised value
 * the deployment itself uses — so the plugin's tables and the library's are in
 * the same database rather than in two.
 *
 * This is the `Database.fromConfig` build. A deployment that overrides
 * `AuthTest.Settings.database` gets the same layer for *its* provider, and
 * {@link layer} composes that one.
 *
 * @category layers
 * @since 0.2.0
 */
export const database: Layer.Layer<
  SqlClient.SqlClient | Database.TestDatabase,
  Migrator.MigrationError | SqlError.SqlError
> = databases(AuthTest.providerOf())

/**
 * The four services the seams are built from, over the test configuration and
 * the test database.
 *
 * `provideMerge`, so `AuthConfig` reaches `makeSeams` itself as well as the
 * services beneath it. Everything here is provided *into* a `Layer.unwrap` and
 * never becomes part of what a block publishes.
 */
const seamTier = (options?: Options) =>
  seamServices.pipe(
    Layer.provideMerge(
      Layer.merge(authConfigLayer(AuthTest.testConfig(options)), databases(AuthTest.providerOf(options)))
    )
  )

/**
 * A whole test deployment with this plugin's two `Context.Reference` seams
 * installed underneath it.
 *
 * **When to use**
 *
 * For the sign-in tests: what is under test there is the *decider*, which lives
 * below the deployment and needs no endpoints in front of it. {@link layer} is
 * this plus the plugin's own service.
 *
 * @category layers
 * @since 0.2.0
 */
export const layerDeployment = (
  options?: Options
): Layer.Layer<
  Services | SqlClient.SqlClient | Database.TestDatabase | TestEmails,
  Migrator.MigrationError | SqlError.SqlError
> =>
  Layer.unwrap(
    Effect.map(makeSeams(options?.twoFactor), (seams) =>
      AuthTest.layer({ ...options, signInPipeline: seams.pipeline, authenticators: seams.authenticators })
    )
  ).pipe(Layer.provide(seamTier(options)))

/**
 * The plugin's service over a test deployment's own, with the outbox as its
 * mailer.
 *
 * **Gotchas**
 *
 * {@link layerEmails} goes in under `Layer.fresh`, and that is load-bearing:
 * `@effect/vitest` memoises layers by object identity across a block and its
 * nested `it.layer` variants, so without it a variant would reuse the parent's
 * build of this module-level constant — bound to the parent's outbox — while
 * `AuthTest.layer` hands the variant a new one. See `EmailOtpTest`.
 *
 * @category layers
 * @since 0.2.0
 */
export const layerTwoFactor = (
  options?: TwoFactorOptions
): Layer.Layer<TwoFactor, never, Exclude<Requirements, TwoFactorEmails> | TestEmails> =>
  twoFactorLayer(options).pipe(Layer.provide(Layer.fresh(layerEmails)))

/**
 * A whole test deployment with the two-factor plugin on top of it and its
 * seams underneath.
 *
 * @category layers
 * @since 0.2.0
 */
export const layer = (
  options?: Options
): Layer.Layer<
  TwoFactor | Services | SqlClient.SqlClient | Database.TestDatabase | TestEmails,
  Migrator.MigrationError | SqlError.SqlError
> => layerTwoFactor(options?.twoFactor).pipe(Layer.provideMerge(layerDeployment(options)))

/**
 * An application API that embeds this library's group *and* the plugin's,
 * exactly as a consumer composes them.
 *
 * @category constructors
 * @since 0.2.0
 */
export const TestApi = HttpApi.make("test-app").addHttpApi(AuthApi).add(TwoFactorApiGroup)

/**
 * Everything a request has to cross: the deployment with the seams under it,
 * both groups' handlers, and the platform services a response is encoded with.
 *
 * @category layers
 * @since 0.2.0
 */
export const layerHttp = (
  options?: Options
): AuthTest.HttpApiLayer<"test-app", HttpApiGroup.Service<"test-app", "twoFactor">> =>
  Layer.unwrap(
    Effect.map(makeSeams(options?.twoFactor), (seams) =>
      AuthTest.layerHttpApi(
        TestApi,
        { ...options, signInPipeline: seams.pipeline, authenticators: seams.authenticators },
        twoFactorHandlers(TestApi).pipe(Layer.provide(layerTwoFactor(options?.twoFactor)))
      )
    )
  ).pipe(Layer.provide(seamTier(options)))

/**
 * {@link layerHttp} on a `TestClock` of its own, which a test in the block may
 * move.
 *
 * **When to use**
 *
 * For anything that turns a TOTP step over, expires a pending authentication or
 * ages a trusted device. `AuthTest.freshClock` is the wrong tool over HTTP —
 * the handlers capture the clock the *layer* was built with — so the clock has
 * to be part of the deployment, as it is in `AuthTest.layerHttpMovingClock`.
 *
 * @category layers
 * @since 0.2.0
 */
export const layerHttpMovingClock = (
  options?: Options
): AuthTest.HttpApiLayer<"test-app", HttpApiGroup.Service<"test-app", "twoFactor"> | TestClock.TestClock> =>
  layerHttp(options).pipe(Layer.provideMerge(Layer.fresh(TestClock.layer())))
