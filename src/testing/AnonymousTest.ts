/**
 * The anonymous plugin, wired into a test deployment.
 *
 * **Details**
 *
 * The plugin composes in two places, so this harness does too:
 * {@link layerAnonymous} is the service, its store and its migrations *above*
 * the deployment, and {@link Options.anonymous}'s `onMerge` reaches the merge
 * hook *below* it, through {@link layer}. A test that wants merge-on-sign-in
 * states `onMerge` and gets both.
 *
 * **Example**
 *
 * ```ts skip-type-checking
 * import { layer } from "@effect/vitest"
 * import { AnonymousTest } from "effect-auth/testing"
 *
 * layer(AnonymousTest.layerHttp())("anonymous", (it) => {
 *   it.effect("signs in as nobody", () => ...)
 * })
 * ```
 *
 * @since 0.2.0
 */
import { Layer } from "effect"
import type { HttpApiGroup } from "effect/unstable/httpapi"
import { HttpApi } from "effect/unstable/httpapi"
import type { Migrator, SqlClient, SqlError } from "effect/unstable/sql"
import type { Anonymous, Options as AnonymousOptions, Requirements } from "../anonymous/Anonymous.js"
import { layer as anonymousLayer, layerHooks } from "../anonymous/Anonymous.js"
import { AnonymousApiGroup } from "../anonymous/Api.js"
import { handlers as anonymousHandlers } from "../anonymous/Handlers.js"
import * as AnonymousMigrations from "../anonymous/Migrations.js"
import type { AnonymousStore } from "../anonymous/Store.js"
import { layerAnonymousStore } from "../anonymous/Store.js"
import type { Services } from "../config/Auth.js"
import { baseUserModel } from "../domain/Schema.js"
import { AuthApi } from "../http/AuthApi.js"
import type * as Database from "./Database.js"
import type { TestEmails } from "./TestEmails.js"
import * as AuthTest from "./TestLayer.js"

/**
 * What a test may vary about a deployment serving anonymous accounts.
 *
 * @category models
 * @since 0.2.0
 */
export interface Options extends AuthTest.Settings {
  /** The plugin's own settings — the display name, the adopt list, the sweep, `onMerge`. */
  readonly anonymous?: AnonymousOptions | undefined
}

/**
 * The plugin's service, its store and its migrations over a test deployment's
 * own `SqlClient`.
 *
 * @category layers
 * @since 0.2.0
 */
export const layerAnonymous = (
  options?: AnonymousOptions
): Layer.Layer<Anonymous, never, Exclude<Requirements, AnonymousStore> | SqlClient.SqlClient> =>
  anonymousLayer(options).pipe(
    Layer.provide(layerAnonymousStore),
    Layer.provide(Layer.orDie(AnonymousMigrations.layer))
  )

/**
 * A whole test deployment with the anonymous plugin on top of it *and* its
 * merge hook underneath it.
 *
 * **Gotchas**
 *
 * The hook layer is provided under `AuthTest.layer`, which is the only place it
 * can go: `AuthHooks` is read when the services that consult it are built. It
 * is also `Layer.fresh`, so a nested `it.layer` variant with a different
 * `onMerge` gets its own build rather than the enclosing block's.
 *
 * @category layers
 * @since 0.2.0
 */
export const layer = (
  options?: Options
): Layer.Layer<
  Anonymous | Services | SqlClient.SqlClient | Database.TestDatabase | TestEmails,
  Migrator.MigrationError | SqlError.SqlError
> =>
  layerAnonymous(options?.anonymous).pipe(
    Layer.provideMerge(AuthTest.layer(options).pipe(Layer.provide(hooks(options))))
  )

/**
 * The merge hook over the block's own PGlite.
 *
 * **Gotchas**
 *
 * `AuthTest.layerDatabaseFor` on the base model and the deployment's own
 * provider rather than a database of its own, and that is load-bearing: the
 * pair is memoised, so the hook reads the *same* rows `AuthTest.layer` writes.
 * A second, equivalent database layer built here would be a second, empty
 * database.
 *
 * `Layer.fresh` covers the hook alone, so a nested `it.layer` variant with a
 * different `onMerge` gets its own build while the database stays shared.
 */
const hooks = (options?: Options): Layer.Layer<never> =>
  Layer.orDie(
    Layer.fresh(layerHooks(options?.anonymous)).pipe(
      Layer.provide(AuthTest.layerDatabaseFor(baseUserModel, AuthTest.providerOf(options)))
    )
  )

/**
 * An application API that embeds this library's group *and* the plugin's.
 *
 * @category constructors
 * @since 0.2.0
 */
export const TestApi = HttpApi.make("test-app").addHttpApi(AuthApi).add(AnonymousApiGroup)

/**
 * Everything a request has to cross: the deployment, both groups' handlers, and
 * the platform services a response is encoded with.
 *
 * **Gotchas**
 *
 * `AuthTest.layerHttpApi` builds the deployment itself, so the merge hook is
 * threaded in through its `options` — which it cannot be, since `Settings` has
 * no slot for a plugin's layer. The hook is therefore provided to the whole
 * result instead, which is equivalent here because nothing else in the stack
 * installs hooks.
 *
 * @category layers
 * @since 0.2.0
 */
export const layerHttp = (
  options?: Options
): AuthTest.HttpApiLayer<"test-app", HttpApiGroup.Service<"test-app", "anonymous"> | Anonymous> =>
  AuthTest.layerHttpApi(
    TestApi,
    options,
    // `provideMerge` rather than `provide`, so a test can drive the endpoints
    // *and* assert on the service behind them — the adoption seam is called
    // from a plugin's server code, not from a route, so there is no request a
    // test could make instead.
    anonymousHandlers(TestApi).pipe(Layer.provideMerge(layerAnonymous(options?.anonymous)))
  ).pipe(Layer.provide(hooks(options)))
