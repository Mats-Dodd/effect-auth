/**
 * A `tsc`-only test: the specification's target consumer snippets must compile,
 * and the two entry points must ask for exactly the right things — and provide
 * exactly enough that `AuthHandlers.layer` discharges against them completely.
 *
 * There is nothing to run here — the assertions are the annotations. The file
 * is covered by `pnpm check`, which compiles `test/` alongside `src/`.
 */
import { Config, Layer, Redacted } from "effect"
import type { HttpClient } from "effect/unstable/http"
import type { HttpApiGroup } from "effect/unstable/httpapi"
import { HttpApi } from "effect/unstable/httpapi"
import type { RateLimiter } from "effect/unstable/persistence"
import type { SqlClient } from "effect/unstable/sql"
import { Auth, AuthApi, AuthEmails, AuthHandlers } from "../../src/index.js"
import type { AuthConfig } from "../../src/config/AuthConfig.js"
import type { DiscoveryError } from "../../src/domain/Errors.js"
import type { Hmac } from "../../src/crypto/Hmac.js"
import type { Token } from "../../src/crypto/Token.js"
import type { Accounts } from "../../src/domain/Accounts.js"
import type { AuthEvents } from "../../src/domain/Events.js"
import type { Passwords } from "../../src/domain/Passwords.js"
import type { Sessions } from "../../src/domain/Sessions.js"
import type { Users } from "../../src/domain/Users.js"
import type {
  AccountStore,
  SessionStore,
  UserStore,
  VerificationStore,
  WithAuthTransaction
} from "../../src/domain/Stores.js"
import type { Verifications } from "../../src/domain/Verifications.js"
import type { Authenticated } from "../../src/http/Middleware.js"
import type { SessionCache } from "../../src/http/SessionCache.js"
import type { OAuthFlow } from "../../src/oauth/Flow.js"
import * as Github from "../../src/oauth/providers/Github.js"

declare const PgLive: Layer.Layer<SqlClient.SqlClient>
declare const MyMailer: Layer.Layer<AuthEmails.AuthEmails>

/**
 * Every service the narrowed {@link Auth.Services} promises, spelled out rather
 * than imported, so that widening it silently is a compile error here.
 */
type Exposed =
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
  | SessionCache
  | Sessions
  | Accounts
  | Passwords
  | Users
  | Authenticated
  | RateLimiter.RateLimiter

// ---------------------------------------------------------------------------
// Without OAuth: the two seams, and nothing else.
// ---------------------------------------------------------------------------

const AuthLive = Auth.layer({
  baseUrl: "https://app.example.com",
  secret: Redacted.make("a-32-byte-or-longer-random-string"),
  emailPassword: { enabled: true }
})

const _plain: Layer.Layer<Exposed, never, SqlClient.SqlClient | AuthEmails.AuthEmails> = AuthLive

// @ts-expect-error `OAuthFlow` belongs to `layerWithOAuth`, not to `layer`.
const _noFlow: Layer.Layer<OAuthFlow, never, SqlClient.SqlClient | AuthEmails.AuthEmails> = AuthLive

// `Token` and `Hmac` *are* part of the surface: a plugin mints its own single-use
// values with one and signs its own cookies with the other.
const _token: Layer.Layer<Token | Hmac, never, SqlClient.SqlClient | AuthEmails.AuthEmails> = AuthLive

// @ts-expect-error the password hasher stays internal to the stack: replacing it
// is an option, not a layer a consumer can shadow.
const _noHasher: Layer.Layer<import("../../src/crypto/PasswordHasher.js").PasswordHasher> = AuthLive

// ---------------------------------------------------------------------------
// With OAuth: the specification's snippet, verbatim in shape.
// ---------------------------------------------------------------------------

const OAuthLive = Auth.layerWithOAuth({
  baseUrl: "http://localhost:3000",
  secret: Redacted.make("a-32-byte-or-longer-random-string"),
  emailPassword: { enabled: true },
  providers: [Github.make({ clientId: "id", clientSecret: Redacted.make("secret") })]
}).pipe(Layer.provide(PgLive), Layer.provide(MyMailer))

// With a provider configured, the one thing left to supply is a transport.
const _withProviders: Layer.Layer<Exposed | OAuthFlow, never, HttpClient.HttpClient> = OAuthLive

const _noEmptyProviders = Auth.layerWithOAuth({
  baseUrl: "https://app.example.com",
  secret: Redacted.make("a-32-byte-or-longer-random-string"),
  // @ts-expect-error `providers` must be non-empty — an empty deployment calls `Auth.layer`.
  providers: []
})

// ---------------------------------------------------------------------------
// Reading the providers from the environment puts `ConfigError` in the error
// channel and nothing else.
// ---------------------------------------------------------------------------

// Discovery joins `ConfigError` in the error channel: a provider list entry may
// be an `OidcDiscovery.make`, which reads a document over the network before the
// stack is built. A provider that only reads the environment simply never fails
// that way.
const _configured: Layer.Layer<
  Exposed | OAuthFlow,
  Config.ConfigError | DiscoveryError,
  SqlClient.SqlClient | AuthEmails.AuthEmails | HttpClient.HttpClient
> = Auth.layerConfigWithOAuth({
  baseUrl: Config.string("BASE_URL"),
  secret: Config.redacted("AUTH_SECRET"),
  providers: [
    Github.makeConfig({
      clientId: Config.string("GITHUB_CLIENT_ID"),
      clientSecret: Config.redacted("GITHUB_CLIENT_SECRET")
    })
  ]
})

const _configuredPlain: Layer.Layer<
  Exposed,
  Config.ConfigError,
  SqlClient.SqlClient | AuthEmails.AuthEmails
> = Auth.layerConfig({
  baseUrl: Config.string("BASE_URL"),
  secret: Config.redacted("AUTH_SECRET")
})

// ---------------------------------------------------------------------------
// The gate that matters: `AuthHandlers.layer` provided with either entry point
// must discharge completely — no service left over, no `Token` or `OAuthFlow`
// leaking into what the application has to supply.
// ---------------------------------------------------------------------------

const TypesApi = HttpApi.make("types-test").addHttpApi(AuthApi)

const _handlersOverPlain: Layer.Layer<
  HttpApiGroup.Service<"types-test", "auth">,
  never,
  SqlClient.SqlClient | AuthEmails.AuthEmails
> = AuthHandlers.layer(TypesApi).pipe(Layer.provide(AuthLive))

const _handlersOverOAuth: Layer.Layer<
  HttpApiGroup.Service<"types-test", "auth">,
  never,
  HttpClient.HttpClient
> = AuthHandlers.layer(TypesApi).pipe(Layer.provide(OAuthLive))

export type {
  _configured,
  _configuredPlain,
  _handlersOverOAuth,
  _handlersOverPlain,
  _noEmptyProviders,
  _noFlow,
  _noHasher,
  _plain,
  _token,
  _withProviders
}
