/**
 * Linear as an OAuth 2.0 provider.
 *
 * **Details**
 *
 * Linear has no REST user endpoint and no OIDC issuer: the identity comes from
 * a GraphQL `POST` asking for `viewer`, which is what
 * {@link OAuthProviderConfig.userInfo} is a seam for. Accounts are stored under
 * the synthetic issuer `local:oauth:linear`.
 *
 * `actor=user` is sent on the authorization request so the token belongs to the
 * person rather than to the application — `actor=application` produces a token
 * whose `viewer` is the integration, which is not an identity anybody can sign
 * in as.
 *
 * **Gotchas**
 *
 * Linear's `viewer` carries an address and no statement about it, so this
 * provider declares `emailVerified: "never"` and can never implicitly link.
 *
 * @since 0.2.0
 */
import { Config, Effect, Option, type Redacted, Schema } from "effect"
import { optionalConfig } from "../../internal/config.js"
import type { OAuthProviderConfig, OAuthTokens, OAuthUserInfo } from "../Provider.js"
import { postJson, providerError } from "../Provider.js"
import { lenient } from "../internal/claims.js"

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/**
 * The id Linear is registered and addressed under.
 *
 * @category constructors
 * @since 0.2.0
 */
export const id = "linear"

/**
 * Linear's authorization endpoint.
 *
 * @category constructors
 * @since 0.2.0
 */
export const authorizationUrl = "https://linear.app/oauth/authorize"

/**
 * Linear's token endpoint.
 *
 * @category constructors
 * @since 0.2.0
 */
export const tokenUrl = "https://api.linear.app/oauth/token"

/**
 * Linear's GraphQL endpoint, where the identity comes from.
 *
 * @category constructors
 * @since 0.2.0
 */
export const graphqlUrl = "https://api.linear.app/graphql"

/**
 * The query the identity is read from. Four fields, and nothing that would
 * touch a workspace's data.
 *
 * @category constructors
 * @since 0.2.0
 */
export const viewerQuery = "query { viewer { id name email avatarUrl } }"

/**
 * The scopes requested by default.
 *
 * @category constructors
 * @since 0.2.0
 */
export const defaultScopes: ReadonlyArray<string> = ["read"]

// -----------------------------------------------------------------------------
// Reading Linear's JSON
// -----------------------------------------------------------------------------

/**
 * The GraphQL answer, as far as it is believed.
 *
 * **Gotchas**
 *
 * GraphQL answers `200` with an `errors` array rather than a status, so a body
 * that carries no `data.viewer.id` is the failure — the status alone is not.
 */
const Viewer = Schema.Struct({
  data: Schema.Struct({
    viewer: Schema.Struct({
      id: Schema.NonEmptyString,
      email: lenient(Schema.NonEmptyString),
      name: lenient(Schema.NonEmptyString),
      avatarUrl: lenient(Schema.NonEmptyString)
    })
  })
})

const readViewer = Schema.decodeUnknownOption(Viewer)

// -----------------------------------------------------------------------------
// Options
// -----------------------------------------------------------------------------

/**
 * What Linear needs.
 *
 * @category models
 * @since 0.2.0
 */
export interface Options {
  readonly clientId: string
  readonly clientSecret: Redacted.Redacted
  /** Scopes on top of {@link defaultScopes}. */
  readonly scopes?: ReadonlyArray<string> | undefined
  /** Overrides `<baseUrl><basePath>/callback/linear`. */
  readonly redirectUri?: string | undefined
  /** Extra authorization parameters. */
  readonly authorizationParams?: Readonly<Record<string, string>> | undefined
}

// -----------------------------------------------------------------------------
// Constructors
// -----------------------------------------------------------------------------

/**
 * Builds the Linear provider configuration.
 *
 * **Example**
 *
 * ```ts
 * import { Redacted } from "effect"
 * import { Linear } from "effect-auth"
 *
 * const linear = Linear.make({
 *   clientId: "linear-client-id",
 *   clientSecret: Redacted.make(process.env.LINEAR_CLIENT_SECRET!)
 * })
 * ```
 *
 * @category constructors
 * @since 0.2.0
 */
export const make = (options: Options): OAuthProviderConfig => {
  const userInfo = Effect.fnUntraced(function* (tokens: OAuthTokens) {
    const response = yield* postJson({
      providerId: id,
      url: graphqlUrl,
      body: { query: viewerQuery },
      accessToken: tokens.accessToken
    })
    const decoded = readViewer(response.body)
    if (Option.isNone(decoded)) return yield* providerError(id, "UserInfoFailed")
    const viewer = decoded.value.data.viewer

    const email = viewer.email ?? null
    if (email === null) return yield* providerError(id, "UserInfoFailed")

    return {
      id: viewer.id,
      email,
      // Linear states nothing; the provider's `"never"` policy makes it stick.
      emailVerified: false,
      name: viewer.name ?? email,
      image: viewer.avatarUrl ?? null
    } satisfies OAuthUserInfo
  })

  return {
    id,
    // The `viewer` query carries no verification flag. See the module header.
    emailVerified: "never",
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    authorizationUrl,
    tokenUrl,
    scopes: [...defaultScopes, ...(options.scopes ?? [])],
    ...(options.redirectUri === undefined ? {} : { redirectUri: options.redirectUri }),
    // A token that acts as the application has no person behind it, so the
    // actor is pinned rather than left to the deployment.
    authorizationParams: { actor: "user", ...options.authorizationParams },
    userInfo,
    accountId: (info) => info.id
  }
}

/**
 * What Linear needs, per field, as `Config` values.
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
 * Builds the Linear provider configuration, reading its credentials from
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
