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
 * @since 0.1.0
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

export * as AuthCipher from "./crypto/Cipher.js"
export * as Hmac from "./crypto/Hmac.js"
export * as PasswordHasher from "./crypto/PasswordHasher.js"
export * as Token from "./crypto/Token.js"
export * as Totp from "./crypto/Totp.js"

// -----------------------------------------------------------------------------
// Domain
// -----------------------------------------------------------------------------

export * as Accounts from "./domain/Accounts.js"
export * as Assurance from "./domain/Assurance.js"
export * as Authenticators from "./domain/Authenticators.js"
export * as AuthEvents from "./domain/Events.js"
export * as Challenges from "./domain/Challenges.js"
export * as Hooks from "./domain/Hooks.js"
export * as Ids from "./domain/Ids.js"
export * as Passwords from "./domain/Passwords.js"
export * as Sessions from "./domain/Sessions.js"
export * as SignIn from "./domain/SignIn.js"
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
export * as Facebook from "./oauth/providers/Facebook.js"
export * as Github from "./oauth/providers/Github.js"
export * as Gitlab from "./oauth/providers/Gitlab.js"
export * as Google from "./oauth/providers/Google.js"
export * as Linear from "./oauth/providers/Linear.js"
export * as LinkedIn from "./oauth/providers/LinkedIn.js"
export * as Microsoft from "./oauth/providers/Microsoft.js"
export * as Notion from "./oauth/providers/Notion.js"
export * as Slack from "./oauth/providers/Slack.js"
export * as Spotify from "./oauth/providers/Spotify.js"
export * as Twitch from "./oauth/providers/Twitch.js"
export * as Twitter from "./oauth/providers/Twitter.js"

// -----------------------------------------------------------------------------
// Plugin authoring
// -----------------------------------------------------------------------------

export * as Plugin from "./Plugin.js"

// -----------------------------------------------------------------------------
// Plugins
// -----------------------------------------------------------------------------

/**
 * The plugins this package ships, each a module of its own that a deployment
 * composes for itself. A plugin owns its own tables, its own migrations from
 * `0001`, and its own `HttpApi` group; none of them is installed by
 * `Auth.layer`, and a deployment that does not serve one never builds it.
 *
 * `Passkeys` is the exception to the shape rather than to the rule: it lives on
 * the `effect-auth/passkeys` subpath because it is the only plugin with a peer
 * dependency (`@simplewebauthn/server`), and keeping it off this barrel is what
 * lets a deployment that does not serve WebAuthn install nothing.
 */

export * as Anonymous from "./anonymous/index.js"
export * as EmailOtp from "./email-otp/index.js"
export * as OneTap from "./one-tap/index.js"
export * as Phone from "./phone/index.js"
export * as TwoFactor from "./two-factor/index.js"
export * as Username from "./username/index.js"
