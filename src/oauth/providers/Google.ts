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
import type { Config, Redacted } from "effect"
import { Effect } from "effect"
import type { OAuthProviderConfig, OAuthTokens, OAuthUserInfo } from "../Provider.js"
import { fetchJson, providerError } from "../Provider.js"
import { asRecord } from "../internal/claims.js"

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
  readonly clientSecret: Redacted.Redacted<string>
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
   */
  readonly jwks?: OAuthProviderConfig["jwks"] | undefined
}

// -----------------------------------------------------------------------------
// Constructors
// -----------------------------------------------------------------------------

// Google's `readString` accepts only strings: every claim it reads is a string
// in Google's schema, and coercing here would be a semantic change. GitHub's
// local reader differs — its user id is a JSON number — so only `asRecord` is
// shared.
const readString = (record: Readonly<Record<string, unknown>>, key: string): string | null => {
  if (!Object.hasOwn(record, key)) return null
  const value = record[key]
  return typeof value === "string" && value.length > 0 ? value : null
}

const readVerified = (record: Readonly<Record<string, unknown>>): boolean => {
  if (!Object.hasOwn(record, "email_verified")) return false
  const value = record.email_verified
  return value === true || value === "true"
}

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

  const userInfo = Effect.fnUntraced(function*(tokens: OAuthTokens) {
    const claims = tokens.idTokenClaims
    // The flow verifies the token before calling this, and refuses the callback
    // when there is none. A null here would mean the OIDC path was skipped.
    if (claims === null) return yield* Effect.fail(providerError(id, "IdTokenInvalid"))

    // The Workspace restriction, enforced. `authorizationParams.hd` only
    // pre-filters the account chooser and can be stripped from the URL; the
    // claim is part of what Google signed, and is checked after verification.
    if (options.hostedDomain !== undefined) {
      const hd = readString(claims.raw, "hd")
      if (hd !== options.hostedDomain) {
        return yield* Effect.fail(providerError(id, "IdTokenInvalid"))
      }
    }

    if (claims.email !== null) {
      return {
        id: claims.subject,
        email: claims.email,
        emailVerified: claims.emailVerified,
        name: claims.name ?? claims.email,
        image: claims.picture
      } satisfies OAuthUserInfo
    }

    const response = yield* fetchJson({ providerId: id, url: userInfoUrl, accessToken: tokens.accessToken })
    const body = asRecord(response.body)
    const email = body === null ? null : readString(body, "email")
    if (body === null || email === null) return yield* Effect.fail(providerError(id, "UserInfoFailed"))
    // The subject still comes from the verified token, never from this body:
    // the response is only bearer-authenticated, the token is signed.
    return {
      id: claims.subject,
      email,
      emailVerified: readVerified(body),
      name: claims.name ?? readString(body, "name") ?? email,
      image: claims.picture ?? readString(body, "picture")
    } satisfies OAuthUserInfo
  })

  return {
    id,
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    authorizationUrl,
    tokenUrl,
    scopes: [...defaultScopes, ...(options.scopes ?? [])],
    issuer,
    jwksUrl,
    ...(options.jwks === undefined ? {} : { jwks: options.jwks }),
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
  readonly clientSecret: Config.Config<Redacted.Redacted<string>>
  readonly scopes?: Config.Config<ReadonlyArray<string>> | undefined
  readonly redirectUri?: Config.Config<string> | undefined
  readonly accessType?: Config.Config<"online" | "offline"> | undefined
  readonly prompt?: Config.Config<string> | undefined
  readonly hostedDomain?: Config.Config<string> | undefined
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
export const makeConfig: (
  options: ConfigOptions
) => Effect.Effect<OAuthProviderConfig, Config.ConfigError> = Effect.fnUntraced(
  function*(options: ConfigOptions) {
    return make({
      clientId: yield* options.clientId,
      clientSecret: yield* options.clientSecret,
      scopes: options.scopes === undefined ? undefined : yield* options.scopes,
      redirectUri: options.redirectUri === undefined ? undefined : yield* options.redirectUri,
      accessType: options.accessType === undefined ? undefined : yield* options.accessType,
      prompt: options.prompt === undefined ? undefined : yield* options.prompt,
      hostedDomain: options.hostedDomain === undefined ? undefined : yield* options.hostedDomain
    })
  }
)
