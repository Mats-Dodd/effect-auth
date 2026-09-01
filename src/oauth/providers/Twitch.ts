/**
 * Twitch as an OIDC provider.
 *
 * **Details**
 *
 * Twitch is OIDC with one trap: it does not put `email`, `email_verified`,
 * `preferred_username` or `picture` in an `id_token` unless the authorization
 * request asked for them explicitly, through a `claims` parameter carrying a
 * JSON document. Ask for the `user:read:email` scope alone and the token comes
 * back with a `sub` and nothing else — an identity with no address, which this
 * library cannot link or provision. So {@link defaultClaims} is sent on every
 * authorization request, and it is the reason this provider exists as more than
 * four URLs.
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
 * The id Twitch is registered and addressed under.
 *
 * @category constructors
 * @since 0.2.0
 */
export const id = "twitch"

/**
 * Twitch's OIDC issuer, and the issuer its accounts are stored under.
 *
 * @category constructors
 * @since 0.2.0
 */
export const issuer = "https://id.twitch.tv/oauth2"

/**
 * Twitch's authorization endpoint.
 *
 * @category constructors
 * @since 0.2.0
 */
export const authorizationUrl = "https://id.twitch.tv/oauth2/authorize"

/**
 * Twitch's token endpoint.
 *
 * @category constructors
 * @since 0.2.0
 */
export const tokenUrl = "https://id.twitch.tv/oauth2/token"

/**
 * Where Twitch publishes its `id_token` signing keys.
 *
 * @category constructors
 * @since 0.2.0
 */
export const jwksUrl = "https://id.twitch.tv/oauth2/keys"

/**
 * Twitch's userinfo endpoint, consulted only when the token carries no address.
 *
 * @category constructors
 * @since 0.2.0
 */
export const userInfoUrl = "https://id.twitch.tv/oauth2/userinfo"

/**
 * The scopes requested by default.
 *
 * @category constructors
 * @since 0.2.0
 */
export const defaultScopes: ReadonlyArray<string> = ["openid", "user:read:email"]

/**
 * The `claims` authorization parameter, without which the `id_token` carries a
 * subject and nothing else.
 *
 * **Gotchas**
 *
 * A JSON document in a query parameter, with `null` meaning "voluntary" — that
 * is OpenID Connect Core §5.5's shape, not a Twitch invention, and the `null`s
 * are load-bearing rather than placeholders.
 *
 * @category constructors
 * @since 0.2.0
 */
export const defaultClaims: string = JSON.stringify({
  id_token: { email: null, email_verified: null, preferred_username: null, picture: null }
})

// -----------------------------------------------------------------------------
// Options
// -----------------------------------------------------------------------------

/**
 * What Twitch needs.
 *
 * @category models
 * @since 0.2.0
 */
export interface Options {
  readonly clientId: string
  readonly clientSecret: Redacted.Redacted
  /** Scopes on top of {@link defaultScopes}. */
  readonly scopes?: ReadonlyArray<string> | undefined
  /** Overrides `<baseUrl><basePath>/callback/twitch`. */
  readonly redirectUri?: string | undefined
  /**
   * Replaces {@link defaultClaims}.
   *
   * **Gotchas**
   *
   * A document that drops `email` produces tokens this library refuses, because
   * an identity with no address can be neither linked nor provisioned.
   */
  readonly claims?: string | undefined
  /** `force_verify`, which makes Twitch re-prompt for consent every time. */
  readonly forceVerify?: boolean | undefined
  /** A pinned key set instead of fetching {@link jwksUrl}. For tests. */
  readonly jwks?: KeyResolver | undefined
  /** Extra authorization parameters. */
  readonly authorizationParams?: Readonly<Record<string, string>> | undefined
}

// -----------------------------------------------------------------------------
// Constructors
// -----------------------------------------------------------------------------

/**
 * Builds the Twitch provider configuration.
 *
 * **Example**
 *
 * ```ts
 * import { Redacted } from "effect"
 * import { Twitch } from "effect-auth"
 *
 * const twitch = Twitch.make({
 *   clientId: "twitch-client-id",
 *   clientSecret: Redacted.make(process.env.TWITCH_CLIENT_SECRET!)
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
    // Reached when the `claims` parameter was replaced with one that does not
    // ask for the address: the userinfo endpoint still has it, and the subject
    // stays the one the signature covered.
    return yield* fetchIdentity({ providerId: id, url: userInfoUrl, accessToken: tokens.accessToken, claims })
  })

  return {
    id,
    // The `email_verified` claim of a signed token — which is present only
    // because `claims` asked for it.
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
    authorizationParams: {
      claims: options.claims ?? defaultClaims,
      ...(options.forceVerify === true ? { force_verify: "true" } : {}),
      ...options.authorizationParams
    },
    userInfo,
    accountId: (info) => info.id
  }
}

/**
 * What Twitch needs, per field, as `Config` values.
 *
 * @category models
 * @since 0.2.0
 */
export interface ConfigOptions {
  readonly clientId: Config.Config<string>
  readonly clientSecret: Config.Config<Redacted.Redacted>
  readonly scopes?: Config.Config<ReadonlyArray<string>> | undefined
  readonly redirectUri?: Config.Config<string> | undefined
  readonly forceVerify?: Config.Config<boolean> | undefined
  readonly authorizationParams?: Readonly<Record<string, string>> | undefined
}

/** The settings {@link ConfigOptions} reads from the environment. */
interface Settings {
  readonly clientId: string
  readonly clientSecret: Redacted.Redacted
  readonly scopes: ReadonlyArray<string> | undefined
  readonly redirectUri: string | undefined
  readonly forceVerify: boolean | undefined
}

/**
 * Builds the Twitch provider configuration, reading its credentials from
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
      redirectUri: optionalConfig(options.redirectUri),
      forceVerify: optionalConfig(options.forceVerify)
    }),
    (settings) => make({ ...settings, authorizationParams: options.authorizationParams })
  )
