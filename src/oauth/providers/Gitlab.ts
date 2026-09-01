/**
 * GitLab as an OAuth 2.0 provider, on gitlab.com or on a self-hosted instance.
 *
 * GitLab does publish an OIDC issuer, but this provider deliberately takes the
 * plain OAuth2 path: the `read_user` scope and `GET /api/v4/user` report the two
 * things an `id_token` does not — whether the account is `active` and whether it
 * is `locked` — and an identity is refused unless both say the account may sign
 * in. It therefore declares no `oidc` block at all, and accounts are stored
 * under the synthetic issuer `local:oauth:gitlab`.
 *
 * **Details**
 *
 * `baseUrl` is what makes this work against a self-hosted instance: every
 * endpoint is derived from it, so a deployment points at
 * `https://gitlab.acme.internal` and nothing else changes. Trailing slashes are
 * trimmed, so a configured `https://gitlab.acme.internal/` cannot produce a
 * double-slashed endpoint.
 *
 * @since 0.1.0
 */
import type { Redacted } from "effect"
import { Config, Effect, Option, Schema } from "effect"
import { optionalConfig } from "../../internal/config.js"
import { trimTrailingSlashes } from "../../internal/url.js"
import type { OAuthProviderConfig, OAuthTokens, OAuthUserInfo } from "../Provider.js"
import { fetchJson, providerError } from "../Provider.js"
import { lenient, StringFromNumeric, Truthy } from "../internal/claims.js"

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/**
 * The id GitLab is registered and addressed under.
 *
 * @category constructors
 * @since 0.1.0
 */
export const id = "gitlab"

/**
 * The host a deployment that says nothing else talks to.
 *
 * @category constructors
 * @since 0.1.0
 */
export const defaultBaseUrl = "https://gitlab.com"

/**
 * The scopes requested by default: enough to read the profile, and nothing else.
 *
 * @category constructors
 * @since 0.1.0
 */
export const defaultScopes: ReadonlyArray<string> = ["read_user"]

/**
 * The endpoints a GitLab instance serves, derived from its host.
 *
 * @category models
 * @since 0.1.0
 */
export interface Endpoints {
  readonly authorizationUrl: string
  readonly tokenUrl: string
  readonly userInfoUrl: string
}

/**
 * Where one GitLab instance's endpoints live.
 *
 * @category combinators
 * @since 0.1.0
 */
export const endpointsOf = (baseUrl?: string): Endpoints => {
  const host = trimTrailingSlashes(baseUrl ?? defaultBaseUrl)
  return {
    authorizationUrl: `${host}/oauth/authorize`,
    tokenUrl: `${host}/oauth/token`,
    userInfoUrl: `${host}/api/v4/user`
  }
}

// -----------------------------------------------------------------------------
// Reading GitLab's JSON
// -----------------------------------------------------------------------------

/**
 * `GET /api/v4/user`, as far as it is believed.
 *
 * **Gotchas**
 *
 * `id` arrives as a JSON *number* and is normalized to the string every other
 * subject in this library is. `state` is read leniently but checked strictly:
 * absent reads as "not active", which refuses the sign-in — a deactivated,
 * blocked or banned account must not be one this deployment lets in.
 */
const Profile = Schema.Struct({
  id: StringFromNumeric,
  email: Schema.NonEmptyString,
  username: lenient(Schema.NonEmptyString),
  name: lenient(Schema.NonEmptyString),
  state: lenient(Schema.NonEmptyString),
  locked: lenient(Truthy),
  avatar_url: lenient(Schema.NonEmptyString),
  email_verified: lenient(Truthy)
})

const readProfile = Schema.decodeUnknownOption(Profile)

/**
 * The one `state` a GitLab account may sign in from.
 *
 * @category constructors
 * @since 0.1.0
 */
export const activeState = "active"

// -----------------------------------------------------------------------------
// Options
// -----------------------------------------------------------------------------

/**
 * What GitLab needs.
 *
 * @category models
 * @since 0.1.0
 */
export interface Options {
  readonly clientId: string
  readonly clientSecret: Redacted.Redacted
  /** Scopes on top of {@link defaultScopes}. */
  readonly scopes?: ReadonlyArray<string> | undefined
  /** Overrides `<baseUrl><basePath>/callback/gitlab`. */
  readonly redirectUri?: string | undefined
  /**
   * The GitLab instance, for a self-hosted deployment.
   *
   * @default "https://gitlab.com"
   */
  readonly baseUrl?: string | undefined
  /** Extra authorization parameters. */
  readonly authorizationParams?: Readonly<Record<string, string>> | undefined
}

// -----------------------------------------------------------------------------
// Constructors
// -----------------------------------------------------------------------------

/**
 * Builds the GitLab provider configuration.
 *
 * **Example**
 *
 * ```ts
 * import { Redacted } from "effect"
 * import { Gitlab } from "effect-auth"
 *
 * const gitlab = Gitlab.make({
 *   clientId: "gitlab-application-id",
 *   clientSecret: Redacted.make(process.env.GITLAB_CLIENT_SECRET!),
 *   baseUrl: "https://gitlab.acme.internal"
 * })
 * ```
 *
 * @category constructors
 * @since 0.1.0
 */
export const make = (options: Options): OAuthProviderConfig => {
  const endpoints = endpointsOf(options.baseUrl)

  const userInfo = Effect.fnUntraced(function* (tokens: OAuthTokens) {
    const response = yield* fetchJson({
      providerId: id,
      url: endpoints.userInfoUrl,
      accessToken: tokens.accessToken
    })
    const decoded = readProfile(response.body)
    if (Option.isNone(decoded)) return yield* providerError(id, "UserInfoFailed")
    const profile = decoded.value

    // The two states that are not a sign-in. A blocked, deactivated or banned
    // account still holds a valid token; `locked` is the temporary form of the
    // same thing. Either one refuses the identity outright rather than letting
    // it through as an unverified address.
    if (profile.state !== activeState || profile.locked !== undefined) {
      return yield* providerError(id, "UserInfoFailed")
    }

    return {
      id: profile.id,
      email: profile.email,
      // GitLab may report `email_verified`, and does not have to. Absent means
      // no: this flag is what gates linking onto an existing local account.
      emailVerified: profile.email_verified !== undefined,
      name: profile.name ?? profile.username ?? profile.email,
      image: profile.avatar_url ?? null
    } satisfies OAuthUserInfo
  })

  return {
    id,
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    authorizationUrl: endpoints.authorizationUrl,
    tokenUrl: endpoints.tokenUrl,
    scopes: [...defaultScopes, ...(options.scopes ?? [])],
    ...(options.redirectUri === undefined ? {} : { redirectUri: options.redirectUri }),
    ...(options.authorizationParams === undefined ? {} : { authorizationParams: options.authorizationParams }),
    userInfo,
    accountId: (info) => info.id
  }
}

/**
 * What GitLab needs, per field, as `Config` values.
 *
 * @category models
 * @since 0.1.0
 */
export interface ConfigOptions {
  readonly clientId: Config.Config<string>
  readonly clientSecret: Config.Config<Redacted.Redacted>
  readonly scopes?: Config.Config<ReadonlyArray<string>> | undefined
  readonly redirectUri?: Config.Config<string> | undefined
  readonly baseUrl?: Config.Config<string> | undefined
  readonly authorizationParams?: Readonly<Record<string, string>> | undefined
}

/** The settings {@link ConfigOptions} reads from the environment. */
interface Settings {
  readonly clientId: string
  readonly clientSecret: Redacted.Redacted
  readonly scopes: ReadonlyArray<string> | undefined
  readonly redirectUri: string | undefined
  readonly baseUrl: string | undefined
}

/**
 * Builds the GitLab provider configuration, reading its credentials from
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
      baseUrl: optionalConfig(options.baseUrl)
    }),
    (settings) => make({ ...settings, authorizationParams: options.authorizationParams })
  )
