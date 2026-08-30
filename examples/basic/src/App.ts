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
import { Auth, AuthHandlers, Migrations } from "effect-auth"
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
 * Its remaining requirements are exactly the two seams an application owns —
 * the database and the mailer — plus an `HttpClient`, which is only needed
 * because an OAuth provider could be configured here. Uncomment the
 * `providers` line and the GitHub endpoints start working; nothing else in
 * this file changes.
 */
export const AuthLive = Auth.layer({
  baseUrl,
  secret: Redacted.make(process.env["AUTH_SECRET"] ?? "example-secret-please-replace-in-production"),
  emailPassword: { enabled: true, requireEmailVerification: false },
  // providers: [Github.layer({ clientId, clientSecret })],
  trustedOrigins: [baseUrl]
}).pipe(
  Layer.provide(DatabaseLive),
  Layer.provide(Mailer.layer)
)

/**
 * The platform services an `HttpApi` needs in order to encode a response.
 */
const PlatformLive = Layer.mergeAll(Path.layer, Etag.layerWeak, HttpPlatform.layer).pipe(
  Layer.provideMerge(FileSystem.layerNoop({}))
)

/**
 * Both groups of handlers, over the configured library.
 */
export const HandlersLive = Layer.mergeAll(AuthHandlers.layer(AppApi), Todos.layer).pipe(
  Layer.provide(AuthLive),
  // Only OAuth needs it, and only when a provider is configured — but wiring it
  // in now means uncommenting the `providers` line above is the whole change.
  Layer.provide(FetchHttpClient.layer)
)

/**
 * The router: `effect-auth`'s eighteen endpoints plus the application's two.
 */
export const AppLive = HttpApiBuilder.layer(AppApi).pipe(
  Layer.provide(HandlersLive),
  Layer.provideMerge(PlatformLive)
)
