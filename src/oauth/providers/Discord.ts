/**
 * Discord as an OAuth 2.0 provider.
 *
 * Discord publishes no OIDC issuer, so accounts are stored under the synthetic
 * issuer `local:oauth:discord` and the identity comes from one bearer-authenticated
 * call to `GET /users/@me`.
 *
 * **Details**
 *
 * Two fields decide whether a sign-in is possible at all. `email` is absent
 * whenever the `email` scope was refused — Discord simply omits it — and an
 * identity with no address can be neither linked nor provisioned, so that is a
 * `UserInfoFailed` rather than a half-built user. `verified` is Discord's own
 * statement that it checked the address, and only a literal `true` counts: it is
 * what gates attaching this identity to a local account that already holds the
 * same address.
 *
 * @since 0.1.0
 */
import type { Redacted } from "effect"
import { Config, Effect, Option, Schema } from "effect"
import { optionalConfig } from "../../internal/config.js"
import type { OAuthProviderConfig, OAuthTokens, OAuthUserInfo } from "../Provider.js"
import { fetchJson, providerError } from "../Provider.js"
import { lenient, StringFromNumeric, Truthy } from "../internal/claims.js"

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/**
 * The id Discord is registered and addressed under.
 *
 * @category constructors
 * @since 0.1.0
 */
export const id = "discord"

/**
 * Discord's authorization endpoint.
 *
 * @category constructors
 * @since 0.1.0
 */
export const authorizationUrl = "https://discord.com/api/oauth2/authorize"

/**
 * Discord's token endpoint.
 *
 * @category constructors
 * @since 0.1.0
 */
export const tokenUrl = "https://discord.com/api/oauth2/token"

/**
 * Discord's user endpoint, where the identity comes from.
 *
 * @category constructors
 * @since 0.1.0
 */
export const userInfoUrl = "https://discord.com/api/users/@me"

/**
 * Where Discord serves avatars from.
 *
 * @category constructors
 * @since 0.1.0
 */
export const cdnUrl = "https://cdn.discordapp.com"

/**
 * The scopes requested by default: the profile, and the address without which
 * there is no identity.
 *
 * @category constructors
 * @since 0.1.0
 */
export const defaultScopes: ReadonlyArray<string> = ["identify", "email"]

// -----------------------------------------------------------------------------
// Avatars
// -----------------------------------------------------------------------------

/**
 * As much of a Discord profile as an avatar URL is built from.
 *
 * @category models
 * @since 0.1.0
 */
export interface AvatarSource {
  /** The account's snowflake. */
  readonly id: string
  /** The avatar hash, or `null` for an account that has never set one. */
  readonly avatar: string | null
  /**
   * The legacy four-digit discriminator, `"0"` for an account on the new
   * username system, `null` when Discord did not report one.
   */
  readonly discriminator: string | null
}

/** A snowflake, as far as `BigInt` is asked to read one. */
const snowflake = /^[0-9]+$/

/**
 * Which of Discord's six (new) or five (legacy) default avatars an account
 * without one is served.
 *
 * **Gotchas**
 *
 * The new scheme shifts the snowflake right by 22 bits, which overflows a
 * `number` — hence `BigInt`, and hence the shape check first: `BigInt("nonsense")`
 * throws, and a provider body is not something to be surprised by.
 */
const defaultAvatarIndex = (source: AvatarSource): number => {
  const discriminator = source.discriminator
  if (discriminator !== null && discriminator !== "0") {
    const legacy = Number.parseInt(discriminator, 10)
    return Number.isFinite(legacy) ? Math.abs(legacy) % 5 : 0
  }
  return snowflake.test(source.id) ? Number((BigInt(source.id) >> BigInt(22)) % BigInt(6)) : 0
}

/**
 * The avatar URL for a Discord profile.
 *
 * **Details**
 *
 * An account that has set an avatar gets the CDN URL for its hash, as a `gif`
 * when the hash carries Discord's `a_` animated prefix and a `png` otherwise.
 * An account that has not gets one of Discord's default avatars: six of them on
 * the new username system (chosen by the snowflake), five on the legacy one
 * (chosen by the discriminator).
 *
 * @category combinators
 * @since 0.1.0
 */
export const avatarUrl = (source: AvatarSource): string => {
  const avatar = source.avatar
  if (avatar !== null) {
    return `${cdnUrl}/avatars/${source.id}/${avatar}.${avatar.startsWith("a_") ? "gif" : "png"}`
  }
  return `${cdnUrl}/embed/avatars/${defaultAvatarIndex(source)}.png`
}

// -----------------------------------------------------------------------------
// Reading Discord's JSON
// -----------------------------------------------------------------------------

/**
 * `GET /users/@me`, as far as it is believed.
 *
 * Only the snowflake is required. Everything else is advisory or is checked
 * afterwards: an absent `email` is a refused scope, and `verified` counts only
 * as a literal `true`.
 */
const Profile = Schema.Struct({
  id: StringFromNumeric,
  username: lenient(Schema.NonEmptyString),
  global_name: lenient(Schema.NonEmptyString),
  discriminator: lenient(Schema.NonEmptyString),
  avatar: lenient(Schema.NonEmptyString),
  email: lenient(Schema.NonEmptyString),
  verified: lenient(Truthy)
})

const readProfile = Schema.decodeUnknownOption(Profile)

// -----------------------------------------------------------------------------
// Options
// -----------------------------------------------------------------------------

/**
 * What Discord needs.
 *
 * @category models
 * @since 0.1.0
 */
export interface Options {
  readonly clientId: string
  readonly clientSecret: Redacted.Redacted
  /** Scopes on top of {@link defaultScopes}. */
  readonly scopes?: ReadonlyArray<string> | undefined
  /** Overrides `<baseUrl><basePath>/callback/discord`. */
  readonly redirectUri?: string | undefined
  /**
   * `prompt`.
   *
   * **Details**
   *
   * `"none"` — the default — skips the consent screen for somebody who has
   * already authorized this application, which is what makes a repeat sign-in a
   * single redirect. `"consent"` shows it every time.
   */
  readonly prompt?: "none" | "consent" | undefined
  /** Extra authorization parameters, such as `permissions` for a bot install. */
  readonly authorizationParams?: Readonly<Record<string, string>> | undefined
}

// -----------------------------------------------------------------------------
// Constructors
// -----------------------------------------------------------------------------

/**
 * Builds the Discord provider configuration.
 *
 * **Example**
 *
 * ```ts
 * import { Redacted } from "effect"
 * import { Discord } from "effect-auth"
 *
 * const discord = Discord.make({
 *   clientId: "1234567890",
 *   clientSecret: Redacted.make(process.env.DISCORD_CLIENT_SECRET!)
 * })
 * ```
 *
 * @category constructors
 * @since 0.1.0
 */
export const make = (options: Options): OAuthProviderConfig => {
  const userInfo = Effect.fnUntraced(function* (tokens: OAuthTokens) {
    const response = yield* fetchJson({ providerId: id, url: userInfoUrl, accessToken: tokens.accessToken })
    const decoded = readProfile(response.body)
    if (Option.isNone(decoded)) return yield* providerError(id, "UserInfoFailed")
    const profile = decoded.value

    // No address, no identity: Discord omits `email` entirely when the scope was
    // refused, and a user cannot be provisioned or linked without one.
    const email = profile.email ?? null
    if (email === null) return yield* providerError(id, "UserInfoFailed")

    return {
      id: profile.id,
      email,
      // Discord's own statement, believed only as a literal `true`.
      emailVerified: profile.verified !== undefined,
      name: profile.global_name ?? profile.username ?? email,
      image: avatarUrl({
        id: profile.id,
        avatar: profile.avatar ?? null,
        discriminator: profile.discriminator ?? null
      })
    } satisfies OAuthUserInfo
  })

  return {
    id,
    // Every one of these reads a claim it can point at; see `EmailVerifiedPolicy`.
    emailVerified: "derived",
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    authorizationUrl,
    tokenUrl,
    scopes: [...defaultScopes, ...(options.scopes ?? [])],
    ...(options.redirectUri === undefined ? {} : { redirectUri: options.redirectUri }),
    authorizationParams: {
      prompt: options.prompt ?? "none",
      ...options.authorizationParams
    },
    userInfo,
    accountId: (info) => info.id
  }
}

/**
 * What Discord needs, per field, as `Config` values.
 *
 * @category models
 * @since 0.1.0
 */
export interface ConfigOptions {
  readonly clientId: Config.Config<string>
  readonly clientSecret: Config.Config<Redacted.Redacted>
  readonly scopes?: Config.Config<ReadonlyArray<string>> | undefined
  readonly redirectUri?: Config.Config<string> | undefined
  readonly prompt?: Config.Config<"none" | "consent"> | undefined
  readonly authorizationParams?: Readonly<Record<string, string>> | undefined
}

/** The settings {@link ConfigOptions} reads from the environment. */
interface Settings {
  readonly clientId: string
  readonly clientSecret: Redacted.Redacted
  readonly scopes: ReadonlyArray<string> | undefined
  readonly redirectUri: string | undefined
  readonly prompt: "none" | "consent" | undefined
}

/**
 * Builds the Discord provider configuration, reading its credentials from
 * `Config`.
 *
 * **Gotchas**
 *
 * The secret must come from `Config.redacted`, so that it is a
 * `Redacted<string>` from the moment it leaves the environment and never
 * appears in a log line or a `ConfigError`.
 *
 * @category constructors
 * @since 0.1.0
 */
export const makeConfig = (options: ConfigOptions): Effect.Effect<OAuthProviderConfig, Config.ConfigError> =>
  Effect.map(
    Config.unwrap<Settings>({
      clientId: options.clientId,
      clientSecret: options.clientSecret,
      scopes: optionalConfig(options.scopes),
      redirectUri: optionalConfig(options.redirectUri),
      prompt: optionalConfig(options.prompt)
    }),
    (settings) => make({ ...settings, authorizationParams: options.authorizationParams })
  )
