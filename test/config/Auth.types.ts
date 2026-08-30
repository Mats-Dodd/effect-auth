/**
 * A `tsc`-only test: the specification's target consumer snippet must compile,
 * and `Auth.layer` must ask for exactly the right things.
 *
 * There is nothing to run here — the assertions are the annotations. The file
 * is covered by `pnpm check`, which compiles `test/` alongside `src/`.
 */
import { Layer, Redacted } from "effect"
import type { HttpClient } from "effect/unstable/http"
import type { RateLimiter } from "effect/unstable/persistence"
import type { SqlClient } from "effect/unstable/sql"
import { Auth, AuthEmails } from "../../src/index.js"
import type { AuthConfig } from "../../src/config/AuthConfig.js"
import type { Accounts } from "../../src/domain/Accounts.js"
import type { AuthEvents } from "../../src/domain/Events.js"
import type { Passwords } from "../../src/domain/Passwords.js"
import type { Sessions } from "../../src/domain/Sessions.js"
import type { AuthStores } from "../../src/domain/Stores.js"
import type { Authenticated } from "../../src/http/Middleware.js"
import type { OAuthFlow } from "../../src/oauth/Flow.js"
import type { OAuthProviders } from "../../src/oauth/Provider.js"
import * as Github from "../../src/oauth/providers/Github.js"

declare const PgLive: Layer.Layer<SqlClient.SqlClient>
declare const MyMailer: Layer.Layer<AuthEmails.AuthEmails>

// ---------------------------------------------------------------------------
// The specification's snippet, verbatim in shape.
// ---------------------------------------------------------------------------

const AuthLive = Auth.layer({
  baseUrl: "http://localhost:3000",
  secret: Redacted.make("a-32-byte-or-longer-random-string"),
  emailPassword: { enabled: true },
  providers: [Github.layer({ clientId: "id", clientSecret: Redacted.make("secret") })]
}).pipe(Layer.provide(PgLive), Layer.provide(MyMailer))

// With a provider configured, the one thing left to supply is a transport.
const _withProviders: Layer.Layer<
  | AuthConfig
  | AuthEvents
  | AuthStores
  | Sessions
  | Accounts
  | Passwords
  | Authenticated
  | RateLimiter.RateLimiter
  | OAuthProviders
  | OAuthFlow,
  never,
  HttpClient.HttpClient
> = AuthLive

// ---------------------------------------------------------------------------
// Without providers there is no OAuth flow, and therefore no HttpClient.
// ---------------------------------------------------------------------------

const _withoutProviders: Layer.Layer<
  AuthConfig | Sessions | Passwords | Accounts | Authenticated | RateLimiter.RateLimiter,
  never,
  SqlClient.SqlClient | AuthEmails.AuthEmails
> = Auth.layer({
  baseUrl: "https://app.example.com",
  secret: Redacted.make("a-32-byte-or-longer-random-string")
})

// @ts-expect-error `OAuthFlow` is not provided when no provider is configured.
const _noFlow: Layer.Layer<OAuthFlow, never, SqlClient.SqlClient | AuthEmails.AuthEmails> = Auth.layer({
  baseUrl: "https://app.example.com",
  secret: Redacted.make("a-32-byte-or-longer-random-string")
})

// ---------------------------------------------------------------------------
// A provider layer that reads `Config` puts its error in the error channel.
// ---------------------------------------------------------------------------

declare const configuredGithub: Layer.Layer<OAuthProviders, import("effect").Config.ConfigError>

const _configuredProviders: Layer.Layer<
  OAuthFlow,
  import("effect").Config.ConfigError,
  SqlClient.SqlClient | AuthEmails.AuthEmails | HttpClient.HttpClient
> = Auth.layer({
  baseUrl: "https://app.example.com",
  secret: Redacted.make("a-32-byte-or-longer-random-string"),
  providers: [configuredGithub]
})

export type { _configuredProviders, _noFlow, _withoutProviders, _withProviders }
