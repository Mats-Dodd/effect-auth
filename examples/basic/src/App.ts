/**
 * The whole server, as one layer.
 *
 * This is the file the README's quickstart is copied from, and the file the
 * end-to-end test drives. Reading it top to bottom is the shortest description
 * of what wiring `effect-auth` into an application costs.
 */
import { PgliteClient } from "@effect/sql-pglite"
import { Layer, Redacted } from "effect"
import { FileSystem, Path } from "effect"
import { Etag, FetchHttpClient, HttpPlatform } from "effect/unstable/http"
import { HttpApiBuilder } from "effect/unstable/httpapi"
import { Auth, AuthHandlers, Github, Migrations } from "effect-auth"
import { AppApi } from "./Api.js"
import * as Mailer from "./Mailer.js"
import * as Todos from "./Todos.js"

/**
 * Where the example serves from. Plain HTTP, so the session cookie is written
 * without the `__Secure-` prefix; point `BASE_URL` at an `https:` origin and
 * the cookie, the `Secure` attribute and the prefix all change together.
 */
export const baseUrl = process.env["BASE_URL"] ?? "http://localhost:3000"

/**
 * An in-memory PGlite database with the `effect-auth` tables created.
 *
 * **Gotchas**
 *
 * `Migrations.layer` is the quickstart convenience: it runs the migrator when
 * the layer is built. A real deployment either merges `Migrations.migrations`
 * into its own `Migrator` record or runs them as a deploy step, so that a
 * process restart is never a schema change.
 */
export const DatabaseLive = Migrations.layer.pipe(
  Layer.provideMerge(PgliteClient.layer())
)

/**
 * `effect-auth`, configured.
 *
 * Its remaining requirements are exactly the two seams an application owns: the
 * database and the mailer. No OAuth provider is configured here, so this is
 * `Auth.layer` — the entry point that neither provides an `OAuthFlow` nor asks
 * for an `HttpClient`.
 *
 * **When to use**
 *
 * To serve GitHub sign-in, swap this whole binding for the {@link AuthWithGithubLive}
 * below. That is the entire change: providers are values, and which entry point
 * you call is what decides whether the flow exists.
 */
export const AuthLive = Auth.layer({
  baseUrl,
  secret: Redacted.make(process.env["AUTH_SECRET"] ?? "example-secret-please-replace-in-production"),
  emailPassword: { enabled: true, requireEmailVerification: false },
  trustedOrigins: [baseUrl]
}).pipe(
  Layer.provide(DatabaseLive),
  Layer.provide(Mailer.layer)
)

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
 */
export const AuthWithGithubLive = Auth.layerWithOAuth({
  baseUrl,
  secret: Redacted.make(process.env["AUTH_SECRET"] ?? "example-secret-please-replace-in-production"),
  emailPassword: { enabled: true, requireEmailVerification: false },
  trustedOrigins: [baseUrl],
  providers: [
    Github.make({
      clientId: process.env["GITHUB_CLIENT_ID"] ?? "example-github-client-id",
      clientSecret: Redacted.make(process.env["GITHUB_CLIENT_SECRET"] ?? "example-github-client-secret")
    })
  ]
}).pipe(
  Layer.provide(DatabaseLive),
  Layer.provide(Mailer.layer),
  Layer.provide(FetchHttpClient.layer)
)

/**
 * The platform services an `HttpApi` needs in order to encode a response.
 */
const PlatformLive = Layer.mergeAll(Path.layer, Etag.layerWeak, HttpPlatform.layer).pipe(
  Layer.provideMerge(FileSystem.layerNoop({}))
)

/**
 * Both groups of handlers, over the configured library.
 *
 * `AuthLive` discharges `AuthHandlers.layer`'s requirements completely — swap
 * in {@link AuthWithGithubLive} and it still does, because the OAuth flow is a
 * service the handlers look up optionally rather than one they require.
 */
export const HandlersLive = Layer.mergeAll(AuthHandlers.layer(AppApi), Todos.layer).pipe(
  Layer.provide(AuthLive)
)

/**
 * The router: `effect-auth`'s eighteen endpoints plus the application's two.
 */
export const AppLive = HttpApiBuilder.layer(AppApi).pipe(
  Layer.provide(HandlersLive),
  Layer.provideMerge(PlatformLive)
)
