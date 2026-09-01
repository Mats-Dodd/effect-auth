/**
 * LinkedIn as an OIDC provider.
 *
 * **Details**
 *
 * LinkedIn's "Sign In with LinkedIn using OpenID Connect" product is a plain,
 * well-behaved OIDC provider: it issues an `id_token` signed by a published key
 * set, and the identity comes out of the verified token with no vendor
 * specifics at all. The one thing worth knowing is that the userinfo endpoint
 * lives on a different host to the issuer (`api.linkedin.com`, not
 * `www.linkedin.com`), and is consulted only when the token carries no address.
 *
 * @since 0.2.0
 */
import { Config, Effect, type Redacted } from "effect"
import { optionalConfig } from "../../internal/config.js"
import type { KeyResolver } from "../IdToken.js"
import type { OAuthProviderConfig, OAuthTokens } from "../Provider.js"
import { providerError } from "../Provider.js"
import { fetchIdentity, identityOf } from "../internal/userInfo.js"

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/**
 * The id LinkedIn is registered and addressed under.
 *
 * @category constructors
 * @since 0.2.0
 */
export const id = "linkedin"

/**
 * LinkedIn's OIDC issuer, and the issuer its accounts are stored under.
 *
 * @category constructors
 * @since 0.2.0
 */
export const issuer = "https://www.linkedin.com/oauth"

/**
 * LinkedIn's authorization endpoint.
 *
 * @category constructors
 * @since 0.2.0
 */
export const authorizationUrl = "https://www.linkedin.com/oauth/v2/authorization"

/**
 * LinkedIn's token endpoint.
 *
 * @category constructors
 * @since 0.2.0
 */
export const tokenUrl = "https://www.linkedin.com/oauth/v2/accessToken"

/**
 * Where LinkedIn publishes its `id_token` signing keys.
 *
 * @category constructors
 * @since 0.2.0
 */
export const jwksUrl = "https://www.linkedin.com/oauth/openid/jwks"

/**
 * LinkedIn's userinfo endpoint — a different host to the issuer.
 *
 * @category constructors
 * @since 0.2.0
 */
export const userInfoUrl = "https://api.linkedin.com/v2/userinfo"

/**
 * The scopes requested by default.
 *
 * @category constructors
 * @since 0.2.0
 */
export const defaultScopes: ReadonlyArray<string> = ["openid", "profile", "email"]

// -----------------------------------------------------------------------------
// Options
// -----------------------------------------------------------------------------

/**
 * What LinkedIn needs.
 *
 * @category models
 * @since 0.2.0
 */
export interface Options {
  readonly clientId: string
  readonly clientSecret: Redacted.Redacted
  /** Scopes on top of {@link defaultScopes}. */
  readonly scopes?: ReadonlyArray<string> | undefined
  /** Overrides `<baseUrl><basePath>/callback/linkedin`. */
  readonly redirectUri?: string | undefined
  /** A pinned key set instead of fetching {@link jwksUrl}. For tests. */
  readonly jwks?: KeyResolver | undefined
  /** Extra authorization parameters. */
  readonly authorizationParams?: Readonly<Record<string, string>> | undefined
}

// -----------------------------------------------------------------------------
// Constructors
// -----------------------------------------------------------------------------

/**
 * Builds the LinkedIn provider configuration.
 *
 * **Example**
 *
 * ```ts
 * import { Redacted } from "effect"
 * import { LinkedIn } from "effect-auth"
 *
 * const linkedin = LinkedIn.make({
 *   clientId: "linkedin-client-id",
 *   clientSecret: Redacted.make(process.env.LINKEDIN_CLIENT_SECRET!)
 * })
 * ```
 *
 * @category constructors
 * @since 0.2.0
 */
export const make = (options: Options): OAuthProviderConfig => {
  const userInfo = Effect.fnUntraced(function* (tokens: OAuthTokens) {
    const claims = tokens.idTokenClaims
    if (claims === null) return yield* providerError(id, "IdTokenInvalid")
    const identity = identityOf(claims)
    if (identity !== null) return identity
    return yield* fetchIdentity({ providerId: id, url: userInfoUrl, accessToken: tokens.accessToken, claims })
  })

  return {
    id,
    // The `email_verified` claim of a signed token.
    emailVerified: "derived",
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    authorizationUrl,
    tokenUrl,
    scopes: [...defaultScopes, ...(options.scopes ?? [])],
    oidc: {
      issuer,
      keys: options.jwks === undefined ? { jwksUrl } : { jwks: options.jwks }
    },
    ...(options.redirectUri === undefined ? {} : { redirectUri: options.redirectUri }),
    ...(options.authorizationParams === undefined ? {} : { authorizationParams: options.authorizationParams }),
    userInfo,
    accountId: (info) => info.id
  }
}

/**
 * What LinkedIn needs, per field, as `Config` values.
 *
 * @category models
 * @since 0.2.0
 */
export interface ConfigOptions {
  readonly clientId: Config.Config<string>
  readonly clientSecret: Config.Config<Redacted.Redacted>
  readonly scopes?: Config.Config<ReadonlyArray<string>> | undefined
  readonly redirectUri?: Config.Config<string> | undefined
  readonly authorizationParams?: Readonly<Record<string, string>> | undefined
}

/** The settings {@link ConfigOptions} reads from the environment. */
interface Settings {
  readonly clientId: string
  readonly clientSecret: Redacted.Redacted
  readonly scopes: ReadonlyArray<string> | undefined
  readonly redirectUri: string | undefined
}

/**
 * Builds the LinkedIn provider configuration, reading its credentials from
 * `Config`.
 *
 * @category constructors
 * @since 0.2.0
 */
export const makeConfig = (options: ConfigOptions): Effect.Effect<OAuthProviderConfig, Config.ConfigError> =>
  Effect.map(
    Config.unwrap<Settings>({
      clientId: options.clientId,
      clientSecret: options.clientSecret,
      scopes: optionalConfig(options.scopes),
      redirectUri: optionalConfig(options.redirectUri)
    }),
    (settings) => make({ ...settings, authorizationParams: options.authorizationParams })
  )
