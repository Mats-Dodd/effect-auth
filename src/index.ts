/**
 * `effect-auth` — an Effect-native authentication library.
 *
 * **Details**
 *
 * Two kinds of export live here.
 *
 * The *contract* — the models, the tagged errors, the HTTP endpoint
 * declarations and the middleware keys — is re-exported flat, because those are
 * the names an application writes down: `User`, `InvalidCredentials`,
 * `AuthApi`, `CurrentUser`.
 *
 * Everything else is a module namespace, following the convention `effect`
 * itself uses for services (`SqlClient.SqlClient`, `HttpClient.HttpClient`):
 * `Auth.layer`, `Sessions.Sessions`, `PasswordHasher.layerScrypt`.
 *
 * The browser client lives at `effect-auth/client` and the test harness at
 * `effect-auth/testing`; neither is re-exported here, so a server bundle never
 * pulls in `FetchHttpClient` and a published build never pulls in PGlite.
 *
 * @since 1.0.0
 */

// -----------------------------------------------------------------------------
// The contract
// -----------------------------------------------------------------------------

export * from "./domain/Errors.js"
export * from "./domain/Schema.js"
export * from "./http/AuthApi.js"
export * from "./http/Middleware.js"
export { isUniqueViolation, PersistenceError, PersistenceFailureKind } from "./domain/Stores.js"
export type { AccountTokens, AuthStores, UserPatch } from "./domain/Stores.js"

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

export * as Auth from "./config/Auth.js"
export * as AuthConfig from "./config/AuthConfig.js"
export * as AuthEmails from "./config/AuthEmails.js"

// -----------------------------------------------------------------------------
// Crypto
// -----------------------------------------------------------------------------

export * as Hmac from "./crypto/Hmac.js"
export * as PasswordHasher from "./crypto/PasswordHasher.js"
export * as Token from "./crypto/Token.js"

// -----------------------------------------------------------------------------
// Domain
// -----------------------------------------------------------------------------

export * as Accounts from "./domain/Accounts.js"
export * as AuthEvents from "./domain/Events.js"
export * as Hooks from "./domain/Hooks.js"
export * as Ids from "./domain/Ids.js"
export * as Passwords from "./domain/Passwords.js"
export * as Sessions from "./domain/Sessions.js"
export * as Stores from "./domain/Stores.js"
export * as Users from "./domain/Users.js"
export * as Verifications from "./domain/Verifications.js"

// -----------------------------------------------------------------------------
// Persistence
// -----------------------------------------------------------------------------

export * as Migrations from "./sql/Migrations.js"
export * as SqlStores from "./sql/SqlStores.js"

// -----------------------------------------------------------------------------
// HTTP
// -----------------------------------------------------------------------------

export * as AuthCookies from "./http/Cookies.js"
export * as AuthHandlers from "./http/Handlers.js"
export * as MiddlewareLive from "./http/MiddlewareLive.js"
export * as OriginCheck from "./http/OriginCheck.js"
export * as RateLimits from "./http/RateLimits.js"
export * as SessionCache from "./http/SessionCache.js"

// -----------------------------------------------------------------------------
// OAuth
// -----------------------------------------------------------------------------

export * as IdToken from "./oauth/IdToken.js"
export * as OAuthFlow from "./oauth/Flow.js"
export * as OAuthProvider from "./oauth/Provider.js"
export * as OAuthState from "./oauth/State.js"
export * as OidcDiscovery from "./oauth/Discovery.js"
export * as Apple from "./oauth/providers/Apple.js"
export * as Discord from "./oauth/providers/Discord.js"
export * as Github from "./oauth/providers/Github.js"
export * as Gitlab from "./oauth/providers/Gitlab.js"
export * as Google from "./oauth/providers/Google.js"
export * as Microsoft from "./oauth/providers/Microsoft.js"

// -----------------------------------------------------------------------------
// Plugins
// -----------------------------------------------------------------------------

export * as MagicLink from "./magic-link/index.js"
