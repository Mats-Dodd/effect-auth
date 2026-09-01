/**
 * Notion as an OAuth 2.0 provider.
 *
 * **Details**
 *
 * Notion departs from the ordinary shape twice, and both departures are handled
 * here rather than pushed onto the deployment.
 *
 * *The token request is not a form post.* Notion requires HTTP Basic client
 * authentication and a **JSON** body, so this provider owns its exchange
 * ({@link OAuthProviderConfig.exchange}) instead of decorating the generic one.
 *
 * *Every API request is versioned.* Notion rejects a request that does not
 * carry a `Notion-Version` header, so {@link defaultVersion} is sent on the
 * user request. Pin it deliberately: the header is the whole of Notion's
 * compatibility contract.
 *
 * Notion issues no refresh tokens for internal or public integrations, so
 * `tokenRefresh` is disabled — a deployment that tried would spend a token that
 * does not exist and report a failure it cannot fix.
 *
 * **Gotchas**
 *
 * Notion reports an address on the bot's *owner* and says nothing about
 * verifying it, so this provider declares `emailVerified: "never"` and can
 * never implicitly link.
 *
 * @since 0.2.0
 */
import { Config, DateTime, Effect, Option, type Redacted, Schema } from "effect"
import { optionalConfig } from "../../internal/config.js"
import { decodeTokens } from "../Flow.js"
import type { OAuthProviderConfig, OAuthTokens, OAuthUserInfo } from "../Provider.js"
import { fetchJson, postJson, providerError } from "../Provider.js"
import { lenient } from "../internal/claims.js"

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/**
 * The id Notion is registered and addressed under.
 *
 * @category constructors
 * @since 0.2.0
 */
export const id = "notion"

/**
 * Notion's authorization endpoint.
 *
 * @category constructors
 * @since 0.2.0
 */
export const authorizationUrl = "https://api.notion.com/v1/oauth/authorize"

/**
 * Notion's token endpoint.
 *
 * @category constructors
 * @since 0.2.0
 */
export const tokenUrl = "https://api.notion.com/v1/oauth/token"

/**
 * Notion's current-bot endpoint, where the identity comes from.
 *
 * @category constructors
 * @since 0.2.0
 */
export const userInfoUrl = "https://api.notion.com/v1/users/me"

/**
 * The API version every request carries.
 *
 * @category constructors
 * @since 0.2.0
 */
export const defaultVersion = "2022-06-28"

/**
 * The header Notion versions its API with.
 *
 * @category constructors
 * @since 0.2.0
 */
export const versionHeader = "Notion-Version"

/**
 * The scopes requested by default: none. Notion's authorization request carries
 * no `scope` at all — the integration's capabilities are configured in Notion.
 *
 * @category constructors
 * @since 0.2.0
 */
export const defaultScopes: ReadonlyArray<string> = []

// -----------------------------------------------------------------------------
// Reading Notion's JSON
// -----------------------------------------------------------------------------

/**
 * `GET /v1/users/me`, as far as it is believed.
 *
 * The token belongs to a *bot*, whose `owner.user` is the person who authorized
 * it — that is the identity, and the bot's own id is not.
 */
const BotUser = Schema.Struct({
  bot: lenient(
    Schema.Struct({
      owner: lenient(
        Schema.Struct({
          user: lenient(
            Schema.Struct({
              id: Schema.NonEmptyString,
              name: lenient(Schema.NonEmptyString),
              avatar_url: lenient(Schema.NonEmptyString),
              person: lenient(Schema.Struct({ email: lenient(Schema.NonEmptyString) }))
            })
          )
        })
      )
    })
  )
})

const readBotUser = Schema.decodeUnknownOption(BotUser)

// -----------------------------------------------------------------------------
// Options
// -----------------------------------------------------------------------------

/**
 * What Notion needs.
 *
 * @category models
 * @since 0.2.0
 */
export interface Options {
  readonly clientId: string
  /** The integration secret. Notion has no public-client mode. */
  readonly clientSecret: Redacted.Redacted
  /** Overrides `<baseUrl><basePath>/callback/notion`. */
  readonly redirectUri?: string | undefined
  /** Overrides {@link defaultVersion}. */
  readonly version?: string | undefined
  /** Extra authorization parameters, such as `owner=user`. */
  readonly authorizationParams?: Readonly<Record<string, string>> | undefined
}

// -----------------------------------------------------------------------------
// Constructors
// -----------------------------------------------------------------------------

/**
 * Builds the Notion provider configuration.
 *
 * **Example**
 *
 * ```ts
 * import { Redacted } from "effect"
 * import { Notion } from "effect-auth"
 *
 * const notion = Notion.make({
 *   clientId: "notion-client-id",
 *   clientSecret: Redacted.make(process.env.NOTION_CLIENT_SECRET!)
 * })
 * ```
 *
 * @category constructors
 * @since 0.2.0
 */
export const make = (options: Options): OAuthProviderConfig => {
  const version = options.version ?? defaultVersion

  const exchange = Effect.fnUntraced(function* (input: { readonly code: string; readonly redirectUri: string }) {
    const response = yield* postJson({
      providerId: id,
      url: tokenUrl,
      body: { grant_type: "authorization_code", code: input.code, redirect_uri: input.redirectUri },
      headers: { [versionHeader]: version },
      basicAuth: { username: options.clientId, password: options.clientSecret }
    })
    if (response.status >= 400) return yield* providerError(id, "TokenExchangeFailed")
    const tokens = decodeTokens(response.body, yield* DateTime.now)
    if (tokens === null) return yield* providerError(id, "TokenExchangeFailed")
    return tokens
  })

  const userInfo = Effect.fnUntraced(function* (tokens: OAuthTokens) {
    const response = yield* fetchJson({
      providerId: id,
      url: userInfoUrl,
      accessToken: tokens.accessToken,
      headers: { [versionHeader]: version }
    })
    const decoded = readBotUser(response.body)
    if (Option.isNone(decoded)) return yield* providerError(id, "UserInfoFailed")

    // The person behind the bot, or nothing usable: a workspace-owned
    // integration has no `owner.user`, and there is no identity to report.
    const user = decoded.value.bot?.owner?.user
    const email = user?.person?.email ?? null
    if (user === undefined || email === null) return yield* providerError(id, "UserInfoFailed")

    return {
      id: user.id,
      email,
      // Notion states nothing; the provider's `"never"` policy makes it stick.
      emailVerified: false,
      name: user.name ?? email,
      image: user.avatar_url ?? null
    } satisfies OAuthUserInfo
  })

  return {
    id,
    // Notion reports the owner's address and never says it checked it.
    emailVerified: "never",
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    authorizationUrl,
    tokenUrl,
    scopes: defaultScopes,
    // No refresh tokens are issued, so nothing may try to spend one.
    tokenRefresh: { enabled: false },
    ...(options.redirectUri === undefined ? {} : { redirectUri: options.redirectUri }),
    authorizationParams: { owner: "user", ...options.authorizationParams },
    exchange,
    userInfo,
    accountId: (info) => info.id
  }
}

/**
 * What Notion needs, per field, as `Config` values.
 *
 * @category models
 * @since 0.2.0
 */
export interface ConfigOptions {
  readonly clientId: Config.Config<string>
  readonly clientSecret: Config.Config<Redacted.Redacted>
  readonly redirectUri?: Config.Config<string> | undefined
  readonly version?: Config.Config<string> | undefined
  readonly authorizationParams?: Readonly<Record<string, string>> | undefined
}

/** The settings {@link ConfigOptions} reads from the environment. */
interface Settings {
  readonly clientId: string
  readonly clientSecret: Redacted.Redacted
  readonly redirectUri: string | undefined
  readonly version: string | undefined
}

/**
 * Builds the Notion provider configuration, reading its credentials from
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
      redirectUri: optionalConfig(options.redirectUri),
      version: optionalConfig(options.version)
    }),
    (settings) => make({ ...settings, authorizationParams: options.authorizationParams })
  )
