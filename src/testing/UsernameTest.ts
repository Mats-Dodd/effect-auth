/**
 * The username plugin, wired into a test deployment.
 *
 * **Details**
 *
 * What a plugin's test harness looks like when the plugin owns a table: the
 * plugin's service over its own store over its own migrations
 * ({@link layerUsername}), a whole deployment with it on top ({@link layer}),
 * an API composing the plugin's group beside this library's ({@link TestApi}),
 * and the server stack for it ({@link layerHttp}). Nothing here is specific to
 * testing except that the migrations are `orDie`d: the composition is exactly
 * what a consumer writes.
 *
 * **Example**
 *
 * ```ts skip-type-checking
 * import { layer } from "@effect/vitest"
 * import { UsernameTest } from "effect-auth/testing"
 *
 * layer(UsernameTest.layerHttp())("username", (it) => {
 *   it.effect("signs in", () => ...)
 * })
 * ```
 *
 * @since 0.2.0
 */
import type { PgliteClient } from "@effect/sql-pglite"
import { Layer } from "effect"
import type { HttpApiGroup } from "effect/unstable/httpapi"
import { HttpApi } from "effect/unstable/httpapi"
import type { Migrator, SqlClient, SqlError } from "effect/unstable/sql"
import type { Services } from "../config/Auth.js"
import { AuthApi } from "../http/AuthApi.js"
import { UsernameApiGroup } from "../username/Api.js"
import { handlers as usernameHandlers } from "../username/Handlers.js"
import * as UsernameMigrations from "../username/Migrations.js"
import type { UsernameStore } from "../username/Store.js"
import { layerUsernameStore } from "../username/Store.js"
import type { Options as UsernameOptions, Requirements, Username } from "../username/Username.js"
import { layer as usernameLayer } from "../username/Username.js"
import type { TestEmails } from "./TestEmails.js"
import * as AuthTest from "./TestLayer.js"

/**
 * What a test may vary about a deployment serving usernames.
 *
 * @category models
 * @since 0.2.0
 */
export interface Options extends AuthTest.Settings {
  /** The plugin's own settings — lengths, the character set, the reserved list, the oracle. */
  readonly username?: UsernameOptions | undefined
}

/**
 * The plugin's service, its store and its migrations over a test deployment's
 * own `SqlClient`.
 *
 * **Gotchas**
 *
 * The migration layer is `Layer.orDie`d, for two reasons: a migration that
 * cannot run in a test is a defect rather than a case to handle, and
 * `AuthTest.layerHttpApi`'s plugin seam takes a layer with no error channel.
 * A consumer keeps the error and lets their runtime report it.
 *
 * The migrations are provided *underneath* the store, so the table exists
 * before anything queries it — and underneath this library's own, which
 * `AuthTest.layer` has already applied by the time this builds, so the foreign
 * key onto `users` has something to point at.
 *
 * @category layers
 * @since 0.2.0
 */
export const layerUsername = (
  options?: UsernameOptions
): Layer.Layer<Username, never, Exclude<Requirements, UsernameStore> | SqlClient.SqlClient> =>
  usernameLayer(options).pipe(Layer.provide(layerUsernameStore), Layer.provide(Layer.orDie(UsernameMigrations.layer)))

/**
 * A whole test deployment with the username plugin on top of it.
 *
 * **When to use**
 *
 * For the domain-level tests. {@link layerHttp} is the same deployment with the
 * endpoints in front of it.
 *
 * @category layers
 * @since 0.2.0
 */
export const layer = (
  options?: Options
): Layer.Layer<
  Username | Services | SqlClient.SqlClient | PgliteClient.PgliteClient | TestEmails,
  Migrator.MigrationError | SqlError.SqlError
> => layerUsername(options?.username).pipe(Layer.provideMerge(AuthTest.layer(options)))

/**
 * An application API that embeds this library's group *and* the plugin's,
 * exactly as a consumer composes them.
 *
 * @category constructors
 * @since 0.2.0
 */
export const TestApi = HttpApi.make("test-app").addHttpApi(AuthApi).add(UsernameApiGroup)

/**
 * Everything a request has to cross: the deployment, both groups' handlers, and
 * the platform services a response is encoded with.
 *
 * @category layers
 * @since 0.2.0
 */
export const layerHttp = (
  options?: Options
): AuthTest.HttpApiLayer<"test-app", HttpApiGroup.Service<"test-app", "username"> | Username> =>
  AuthTest.layerHttpApi(
    TestApi,
    options,
    // `provideMerge` rather than `provide`, so a test can drive the endpoints
    // and still reach the service behind them.
    usernameHandlers(TestApi).pipe(Layer.provideMerge(layerUsername(options?.username)))
  )
