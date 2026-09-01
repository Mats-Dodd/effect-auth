/**
 * Spotify as an OAuth 2.0 provider.
 *
 * **Details**
 *
 * Spotify publishes no OIDC issuer, so accounts are stored under the synthetic
 * issuer `local:oauth:spotify` and the identity comes from one call to
 * `GET /v1/me`. That body carries an address and *no statement about it*: there
 * is no `verified` flag anywhere in the Web API, and Spotify's own
 * documentation says the address is unverified. This provider therefore
 * declares `emailVerified: "never"` and can never implicitly link onto a local
 * account holding the same address — which is the whole point of the
 * declaration, and the reason it is a required field.
 *
 * @since 0.2.0
 */
import { Config, Effect, Option, type Redacted, Schema } from "effect"
import { optionalConfig } from "../../internal/config.js"
import type { OAuthProviderConfig, OAuthTokens, OAuthUserInfo } from "../Provider.js"
import { fetchJson, providerError } from "../Provider.js"
import { lenient } from "../internal/claims.js"

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/**
 * The id Spotify is registered and addressed under.
 *
 * @category constructors
 * @since 0.2.0
 */
export const id = "spotify"

/**
 * Spotify's authorization endpoint.
 *
 * @category constructors
 * @since 0.2.0
 */
export const authorizationUrl = "https://accounts.spotify.com/authorize"

/**
 * Spotify's token endpoint.
 *
 * @category constructors
 * @since 0.2.0
 */
export const tokenUrl = "https://accounts.spotify.com/api/token"

/**
 * Spotify's current-user endpoint, where the identity comes from.
 *
 * @category constructors
 * @since 0.2.0
 */
export const userInfoUrl = "https://api.spotify.com/v1/me"

/**
 * The scopes requested by default: the address, and the profile it is attached
 * to.
 *
 * @category constructors
 * @since 0.2.0
 */
export const defaultScopes: ReadonlyArray<string> = ["user-read-email", "user-read-private"]

// -----------------------------------------------------------------------------
// Reading Spotify's JSON
// -----------------------------------------------------------------------------

/**
 * `GET /v1/me`, as far as it is believed. The Spotify user id is required; the
 * address is checked afterwards, because an identity without one cannot be used.
 */
const Profile = Schema.Struct({
  id: Schema.NonEmptyString,
  email: lenient(Schema.NonEmptyString),
  display_name: lenient(Schema.NonEmptyString),
  images: lenient(Schema.Array(Schema.Struct({ url: lenient(Schema.NonEmptyString) })))
})

const readProfile = Schema.decodeUnknownOption(Profile)

/**
 * The largest image Spotify listed, or `null`.
 *
 * **Gotchas**
 *
 * Spotify orders the array widest-first but does not promise to, and an entry
 * may carry no URL at all, so the first usable one is taken rather than
 * `images[0].url` asserted.
 *
 * @category combinators
 * @since 0.2.0
 */
export const avatarUrl = (images: ReadonlyArray<{ readonly url?: string | undefined }> | undefined): string | null => {
  for (const image of images ?? []) {
    if (image.url !== undefined) return image.url
  }
  return null
}

// -----------------------------------------------------------------------------
// Options
// -----------------------------------------------------------------------------

/**
 * What Spotify needs.
 *
 * @category models
 * @since 0.2.0
 */
export interface Options {
  readonly clientId: string
  readonly clientSecret: Redacted.Redacted
  /** Scopes on top of {@link defaultScopes}. */
  readonly scopes?: ReadonlyArray<string> | undefined
  /** Overrides `<baseUrl><basePath>/callback/spotify`. */
  readonly redirectUri?: string | undefined
  /**
   * `show_dialog`, which makes Spotify re-prompt for consent every time rather
   * than redirecting straight back for somebody who has already authorized.
   */
  readonly showDialog?: boolean | undefined
  /** Extra authorization parameters. */
  readonly authorizationParams?: Readonly<Record<string, string>> | undefined
}

// -----------------------------------------------------------------------------
// Constructors
// -----------------------------------------------------------------------------

/**
 * Builds the Spotify provider configuration.
 *
 * **Example**
 *
 * ```ts
 * import { Redacted } from "effect"
 * import { Spotify } from "effect-auth"
 *
 * const spotify = Spotify.make({
 *   clientId: "spotify-client-id",
 *   clientSecret: Redacted.make(process.env.SPOTIFY_CLIENT_SECRET!)
 * })
 * ```
 *
 * @category constructors
 * @since 0.2.0
 */
export const make = (options: Options): OAuthProviderConfig => {
  const userInfo = Effect.fnUntraced(function* (tokens: OAuthTokens) {
    const response = yield* fetchJson({ providerId: id, url: userInfoUrl, accessToken: tokens.accessToken })
    const decoded = readProfile(response.body)
    if (Option.isNone(decoded)) return yield* providerError(id, "UserInfoFailed")
    const profile = decoded.value

    // No address, no identity: the scope was refused, and a user can be neither
    // provisioned nor linked without one.
    const email = profile.email ?? null
    if (email === null) return yield* providerError(id, "UserInfoFailed")

    return {
      id: profile.id,
      email,
      // Spotify states nothing about the address; the provider's `"never"`
      // policy makes this stick whatever a future body claims.
      emailVerified: false,
      name: profile.display_name ?? email,
      image: avatarUrl(profile.images)
    } satisfies OAuthUserInfo
  })

  return {
    id,
    // The Web API carries no verification flag at all. See the module header.
    emailVerified: "never",
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    authorizationUrl,
    tokenUrl,
    scopes: [...defaultScopes, ...(options.scopes ?? [])],
    ...(options.redirectUri === undefined ? {} : { redirectUri: options.redirectUri }),
    authorizationParams: {
      ...(options.showDialog === true ? { show_dialog: "true" } : {}),
      ...options.authorizationParams
    },
    userInfo,
    accountId: (info) => info.id
  }
}

/**
 * What Spotify needs, per field, as `Config` values.
 *
 * @category models
 * @since 0.2.0
 */
export interface ConfigOptions {
  readonly clientId: Config.Config<string>
  readonly clientSecret: Config.Config<Redacted.Redacted>
  readonly scopes?: Config.Config<ReadonlyArray<string>> | undefined
  readonly redirectUri?: Config.Config<string> | undefined
  readonly showDialog?: Config.Config<boolean> | undefined
  readonly authorizationParams?: Readonly<Record<string, string>> | undefined
}

/** The settings {@link ConfigOptions} reads from the environment. */
interface Settings {
  readonly clientId: string
  readonly clientSecret: Redacted.Redacted
  readonly scopes: ReadonlyArray<string> | undefined
  readonly redirectUri: string | undefined
  readonly showDialog: boolean | undefined
}

/**
 * Builds the Spotify provider configuration, reading its credentials from
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
      showDialog: optionalConfig(options.showDialog)
    }),
    (settings) => make({ ...settings, authorizationParams: options.authorizationParams })
  )
