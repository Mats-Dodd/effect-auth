/**
 * The whole server, as one layer.
 *
 * This is the file the README's quickstart is copied from, and the file the
 * end-to-end test drives. Reading it top to bottom is the shortest description
 * of what wiring `effect-auth` into an application costs — including a
 * deployment's own user field, a plugin, and the two seams an application owns.
 */
import { PgliteClient } from "@effect/sql-pglite"
import { Config, Duration, FileSystem, Layer, Path, Redacted } from "effect"
import { Etag, FetchHttpClient, HttpPlatform } from "effect/unstable/http"
import { HttpApiBuilder } from "effect/unstable/httpapi"
import { Github, MagicLink } from "effect-auth"
import { AppApi } from "./Api.js"
import { auth } from "./Auth.js"
import * as Mailer from "./Mailer.js"
import * as Todos from "./Todos.js"

/**
 * Where the example serves from.
 *
 * **Details**
 *
 * A `Config`, not a string: {@link AuthLive} below is built with
 * `auth.layerConfig`, which takes the scalar settings as `Config` values and so
 * turns a missing or malformed one into a single `ConfigError` when the layer is
 * built. `main.ts` yields this same value for the port it binds, so the process
 * and the deployment cannot disagree about where it is served.
 *
 * **Gotchas**
 *
 * Plain HTTP by default, so the session cookie is written without the
 * `__Secure-` prefix; point `BASE_URL` at an `https:` origin and the cookie, the
 * `Secure` attribute and the prefix all change together.
 */
export const baseUrl: Config.Config<string> = Config.string("BASE_URL").pipe(
  Config.withDefault("http://localhost:3000")
)

/**
 * The key every token and cookie is signed with.
 *
 * `Config.redacted`, so it is a `Redacted<string>` from the moment it leaves the
 * environment: never a log line, and never the body of a `ConfigError`. The
 * default is here so the example runs with no environment at all — a deployment
 * drops it, and gets a `ConfigError` at boot instead of a shared secret every
 * reader of this file knows.
 */
const secret = Config.redacted("AUTH_SECRET").pipe(
  Config.withDefault(Redacted.make("example-secret-please-replace-in-production"))
)

/**
 * The one origin this example trusts: its own, derived from {@link baseUrl}
 * rather than stated a second time.
 */
const trustedOrigins = baseUrl.pipe(Config.map((url) => [url]))

/**
 * An in-memory PGlite database with the `effect-auth` tables created, plus the
 * `plan` column this deployment's model declared.
 *
 * **Gotchas**
 *
 * `auth.layerMigrations` is the quickstart convenience `Migrations.layer` is: it
 * runs the migrator when the layer is built. A real deployment either merges
 * `Migrations.migrations` and `Migrations.forUserFields(auth.model)` into its own
 * `Migrator` record or runs them as a deploy step, so that a process restart is
 * never a schema change.
 */
export const DatabaseLive = auth.layerMigrations.pipe(Layer.provideMerge(PgliteClient.layer()))

/**
 * `effect-auth`, configured.
 *
 * Its remaining requirements are exactly the two seams an application owns: the
 * database and the mailer. No OAuth provider is configured here, so this is
 * `auth.layer` — the entry point that neither provides an `OAuthFlow` nor asks
 * for an `HttpClient`.
 *
 * **Details**
 *
 * `user.changeEmail` and `user.deleteUser` are off by default, because letting
 * somebody move or destroy their own account is a product decision. This example
 * serves both, so the end-to-end test can drive them.
 *
 * `auth.layerConfig` rather than `auth.layer`: the same layer, with the scalar
 * settings read from the environment through `Config`. The structured sections
 * stay plain objects — `requireEmailVerification` is a decision this file makes,
 * not a knob a deployment turns.
 *
 * **When to use**
 *
 * To serve GitHub sign-in, swap this whole binding for the {@link AuthWithGithubLive}
 * below. That is the entire change: providers are values, and which entry point
 * you call is what decides whether the flow exists.
 */
export const AuthLive = auth
  .layerConfig({
    baseUrl,
    secret,
    emailPassword: { enabled: true, requireEmailVerification: false },
    user: { changeEmail: { enabled: true }, deleteUser: { enabled: true } },
    trustedOrigins
  })
  .pipe(Layer.provide(DatabaseLive), Layer.provide(Mailer.layer))

/**
 * The same deployment with GitHub sign-in switched on.
 *
 * **Details**
 *
 * The difference from {@link AuthLive} is the entry point and the `providers`
 * array — a provider is a value, so nothing about it is a layer. In exchange
 * this layer provides `OAuthFlow` (which is what makes the three social
 * endpoints answer) and requires an `HttpClient`, provided here.
 *
 * **Gotchas**
 *
 * The transport must not follow redirects. `FetchHttpClient.layer` does not.
 *
 * The credentials carry no default, unlike {@link secret}: `Github.makeConfig`
 * reads them from the environment, so a deployment that forgets one is a
 * `ConfigError` when this layer is built rather than a provider that answers
 * every sign-in attempt with an OAuth error nobody sees until production.
 */
export const AuthWithGithubLive = auth
  .layerConfigWithOAuth({
    baseUrl,
    secret,
    emailPassword: { enabled: true, requireEmailVerification: false },
    user: { changeEmail: { enabled: true }, deleteUser: { enabled: true } },
    trustedOrigins,
    providers: [
      Github.makeConfig({
        clientId: Config.string("GITHUB_CLIENT_ID"),
        clientSecret: Config.redacted("GITHUB_CLIENT_SECRET")
      })
    ]
  })
  .pipe(Layer.provide(DatabaseLive), Layer.provide(Mailer.layer), Layer.provide(FetchHttpClient.layer))

/**
 * The magic link plugin, over the configured library.
 *
 * **Details**
 *
 * The whole of what installing a plugin costs. `Layer.provideMerge(AuthLive)`
 * discharges everything it needs from the deployment — `Verifications`,
 * `Sessions`, the stores, the transaction runner — and republishes them, so what
 * comes out is the deployment *and* the plugin. The one thing it asks of the
 * application is a mailer of its own, and forgetting it is a compile error.
 *
 * The plugin owns no table: a link is a `Verifications` row, so
 * {@link DatabaseLive} needs nothing added to it.
 */
export const MagicLinkLive = MagicLink.layer({ ttl: Duration.minutes(10) }).pipe(
  Layer.provideMerge(AuthLive),
  Layer.provide(Mailer.magicLinkLayer)
)

/**
 * The platform services an `HttpApi` needs in order to encode a response.
 */
const PlatformLive = Layer.mergeAll(Path.layer, Etag.layerWeak, HttpPlatform.layer).pipe(
  Layer.provideMerge(FileSystem.layerNoop({}))
)

/**
 * All three groups of handlers, over one build of the deployment.
 *
 * `auth.handlers(AppApi)` is `AuthHandlers.layer(AppApi, auth.model)` with the
 * model already applied, and `MagicLink.handlers(AppApi)` is
 * `AuthHandlers.forGroup(MagicLinkApiGroup, …)` applied to the same API. Both
 * are provided the same `MagicLinkLive`, so the plugin and the core read one
 * `Sessions`, one `UserStore` and one rate limiter.
 */
export const HandlersLive = Layer.mergeAll(auth.handlers(AppApi), MagicLink.handlers(AppApi), Todos.layer).pipe(
  Layer.provide(MagicLinkLive)
)

/**
 * The router: `effect-auth`'s twenty-eight endpoints, the plugin's three, and
 * the application's two.
 */
export const AppLive = HttpApiBuilder.layer(AppApi).pipe(Layer.provide(HandlersLive), Layer.provideMerge(PlatformLive))
