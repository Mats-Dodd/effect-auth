/**
 * Google as an OIDC provider.
 *
 * Google publishes an issuer, so the flow takes the OIDC path: an `id_token` is
 * required, its signature is checked against Google's JWKS, and `iss`, `aud`,
 * `exp` and the `nonce` minted for this authorization request must all match
 * before a single claim in it is read. Accounts are stored under the real
 * issuer `https://accounts.google.com`, and the identity is the `sub` claim.
 *
 * **Details**
 *
 * `userInfo` normally makes no request at all: everything needed is in the
 * verified token. The one exception is a deployment that asks for `openid`
 * without `email`, where the token carries no address; the userinfo endpoint is
 * then consulted, through the flow's redirect-refusing client.
 *
 * @since 1.0.0
 */
import type { Redacted } from "effect"
import { Config, Effect, Option, Schema } from "effect"
import { optionalConfig } from "../../internal/config.js"
import type { KeyResolver } from "../IdToken.js"
import type { OAuthProviderConfig, OAuthTokens } from "../Provider.js"
import { providerError } from "../Provider.js"
import { lenient } from "../internal/claims.js"
import { fetchIdentity, identityOf } from "../internal/userInfo.js"

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/**
 * The id Google is registered and addressed under.
 *
 * @category constructors
 * @since 1.0.0
 */
export const id = "google"

/**
 * Google's OIDC issuer. This is also the `issuer` column of every account row
 * this provider writes.
 *
 * @category constructors
 * @since 1.0.0
 */
export const issuer = "https://accounts.google.com"

/**
 * Where Google publishes its signing keys.
 *
 * @category constructors
 * @since 1.0.0
 */
export const jwksUrl = "https://www.googleapis.com/oauth2/v3/certs"

/**
 * Google's authorization endpoint.
 *
 * @category constructors
 * @since 1.0.0
 */
export const authorizationUrl = "https://accounts.google.com/o/oauth2/v2/auth"

/**
 * Google's token endpoint.
 *
 * @category constructors
 * @since 1.0.0
 */
export const tokenUrl = "https://oauth2.googleapis.com/token"

/**
 * Google's OIDC userinfo endpoint, consulted only when the `id_token` carries
 * no address.
 *
 * @category constructors
 * @since 1.0.0
 */
export const userInfoUrl = "https://openidconnect.googleapis.com/v1/userinfo"

/**
 * The scopes requested by default.
 *
 * @category constructors
 * @since 1.0.0
 */
export const defaultScopes: ReadonlyArray<string> = ["openid", "email", "profile"]

// -----------------------------------------------------------------------------
// Options
// -----------------------------------------------------------------------------

/**
 * What Google needs.
 *
 * @category models
 * @since 1.0.0
 */
export interface Options {
  readonly clientId: string
  readonly clientSecret: Redacted.Redacted
  /** Scopes on top of {@link defaultScopes}. */
  readonly scopes?: ReadonlyArray<string> | undefined
  /** Overrides `<baseUrl><basePath>/callback/google`. */
  readonly redirectUri?: string | undefined
  /**
   * `access_type`. `"offline"` is what makes Google issue a refresh token, and
   * is the default.
   */
  readonly accessType?: "online" | "offline" | undefined
  /**
   * `prompt`. Google only re-issues a refresh token when the consent screen is
   * shown again, so `"consent"` is what a deployment that must keep refreshing
   * wants.
   */
  readonly prompt?: string | undefined
  /**
   * `hd` — restricts sign-in to one Google Workspace domain.
   *
   * **Details**
   *
   * Two halves, and both are needed. The value is sent as the `hd`
   * authorization parameter, which only pre-filters Google's account chooser,
   * *and* it is checked against the `hd` claim of the verified `id_token`. The
   * parameter alone is advisory: a caller holding the authorization URL can
   * strip it and sign in with any Google account, so a callback whose token
   * does not claim this exact domain is refused.
   */
  readonly hostedDomain?: string | undefined
  /**
   * A pre-resolved key set instead of fetching {@link jwksUrl}.
   *
   * **When to use**
   *
   * Tests, which hand in a `jose` `createLocalJWKSet` so verification runs with
   * no network at all, and deployments that pin Google's keys.
   *
   * **Gotchas**
   *
   * It replaces {@link jwksUrl} rather than joining it: the provider's key
   * source is one or the other, and pinning a key set is a statement that
   * nothing is to be fetched.
   */
  readonly jwks?: KeyResolver | undefined
}

// -----------------------------------------------------------------------------
// Constructors
// -----------------------------------------------------------------------------

// Every claim Google is read for is a string in its schema — unlike GitHub,
// whose user id is a JSON number — so nothing here coerces.

/**
 * The `hd` claim of a verified `id_token`, read out of the whole payload.
 */
const HostedDomainClaim = Schema.Struct({ hd: lenient(Schema.NonEmptyString) })

const readHostedDomain = Schema.decodeUnknownOption(HostedDomainClaim)

/**
 * Builds the Google provider configuration.
 *
 * **Example**
 *
 * ```ts
 * import { Redacted } from "effect"
 * import { Google } from "effect-auth"
 *
 * const google = Google.make({
 *   clientId: "0123.apps.googleusercontent.com",
 *   clientSecret: Redacted.make(process.env.GOOGLE_CLIENT_SECRET!)
 * })
 * ```
 *
 * @category constructors
 * @since 1.0.0
 */
export const make = (options: Options): OAuthProviderConfig => {
  const authorizationParams: Record<string, string> = {
    access_type: options.accessType ?? "offline"
  }
  if (options.prompt !== undefined) authorizationParams.prompt = options.prompt
  if (options.hostedDomain !== undefined) authorizationParams.hd = options.hostedDomain

  const userInfo = Effect.fnUntraced(function* (tokens: OAuthTokens) {
    const claims = tokens.idTokenClaims
    // The flow verifies the token before calling this, and refuses the callback
    // when there is none. A null here would mean the OIDC path was skipped.
    if (claims === null) return yield* providerError(id, "IdTokenInvalid")

    // The Workspace restriction, enforced. `authorizationParams.hd` only
    // pre-filters the account chooser and can be stripped from the URL; the
    // claim is part of what Google signed, and is checked after verification.
    if (options.hostedDomain !== undefined) {
      const hd = Option.match(readHostedDomain(claims.raw), {
        onNone: () => null,
        onSome: (fields) => fields.hd ?? null
      })
      if (hd !== options.hostedDomain) {
        return yield* providerError(id, "IdTokenInvalid")
      }
    }

    const identity = identityOf(claims)
    if (identity !== null) return identity

    return yield* fetchIdentity({ providerId: id, url: userInfoUrl, accessToken: tokens.accessToken, claims })
  })

  return {
    id,
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    authorizationUrl,
    tokenUrl,
    scopes: [...defaultScopes, ...(options.scopes ?? [])],
    // The OIDC block is what puts the flow on the OIDC path: an `id_token` is
    // then required and verified against these keys before anything in it is
    // read.
    oidc: {
      issuer,
      keys: options.jwks === undefined ? { jwksUrl } : { jwks: options.jwks }
    },
    ...(options.redirectUri === undefined ? {} : { redirectUri: options.redirectUri }),
    authorizationParams,
    userInfo,
    accountId: (info) => info.id
  }
}

/**
 * What Google needs, per field, as `Config` values.
 *
 * @category models
 * @since 1.0.0
 */
export interface ConfigOptions {
  readonly clientId: Config.Config<string>
  readonly clientSecret: Config.Config<Redacted.Redacted>
  readonly scopes?: Config.Config<ReadonlyArray<string>> | undefined
  readonly redirectUri?: Config.Config<string> | undefined
  readonly accessType?: Config.Config<"online" | "offline"> | undefined
  readonly prompt?: Config.Config<string> | undefined
  readonly hostedDomain?: Config.Config<string> | undefined
}

/** The settings {@link ConfigOptions} reads from the environment. */
interface Settings {
  readonly clientId: string
  readonly clientSecret: Redacted.Redacted
  readonly scopes: ReadonlyArray<string> | undefined
  readonly redirectUri: string | undefined
  readonly accessType: "online" | "offline" | undefined
  readonly prompt: string | undefined
  readonly hostedDomain: string | undefined
}

/**
 * Builds the Google provider configuration, reading its credentials from
 * `Config`.
 *
 * **Gotchas**
 *
 * The secret must come from `Config.redacted`, so that it is a
 * `Redacted<string>` from the moment it leaves the environment and never
 * appears in a log line or a `ConfigError`.
 *
 * @category constructors
 * @since 1.0.0
 */
export const makeConfig = (options: ConfigOptions): Effect.Effect<OAuthProviderConfig, Config.ConfigError> =>
  Effect.map(
    Config.unwrap<Settings>({
      clientId: options.clientId,
      clientSecret: options.clientSecret,
      scopes: optionalConfig(options.scopes),
      redirectUri: optionalConfig(options.redirectUri),
      accessType: optionalConfig(options.accessType),
      prompt: optionalConfig(options.prompt),
      hostedDomain: optionalConfig(options.hostedDomain)
    }),
    make
  )
