/**
 * GitHub as an OAuth 2.0 provider.
 *
 * GitHub is not an OIDC provider: there is no `id_token` and no issuer URL, so
 * accounts are stored under the synthetic issuer `local:oauth:github` and the
 * identity comes from two API calls rather than from a signed token.
 *
 * **Details**
 *
 * The interesting part is the address. `GET /user` returns a *public profile*
 * e-mail, which a person may have set to anything and which GitHub does not
 * claim to have verified — treating it as verified would let anybody who can
 * type an address into a profile form claim somebody else's local account by
 * e-mail matching. `GET /user/emails` is the authoritative list, and only the
 * `verified` flag on it is evidence. See {@link selectEmail}.
 *
 * @since 1.0.0
 */
import type { Config, Redacted } from "effect"
import { Effect, Layer } from "effect"
import type { OAuthProviderConfig, OAuthTokens, OAuthUserInfo } from "../Provider.js"
import { fetchJson, layer as registryLayer, makeRegistry, OAuthProviders, providerError } from "../Provider.js"

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/**
 * The id GitHub is registered and addressed under.
 *
 * @category constructors
 * @since 1.0.0
 */
export const id = "github"

/**
 * The scopes requested by default: enough to read the profile and the verified
 * address list, and nothing else.
 *
 * @category constructors
 * @since 1.0.0
 */
export const defaultScopes: ReadonlyArray<string> = ["read:user", "user:email"]

const defaultWebUrl = "https://github.com"
const defaultApiUrl = "https://api.github.com"

// -----------------------------------------------------------------------------
// E-mail selection
// -----------------------------------------------------------------------------

/**
 * One entry of `GET /user/emails`.
 *
 * @category models
 * @since 1.0.0
 */
export interface GithubEmail {
  readonly email: string
  readonly primary: boolean
  readonly verified: boolean
}

/**
 * The address to use, and whether GitHub says it verified it.
 *
 * @category models
 * @since 1.0.0
 */
export interface SelectedEmail {
  readonly email: string
  readonly emailVerified: boolean
}

/**
 * Picks the address an identity is reported under.
 *
 * **Details**
 *
 * In order:
 *
 * 1. the primary address, when it is verified — the ordinary case, and the only
 *    one that yields `emailVerified: true` for a primary;
 * 2. the primary address, unverified;
 * 3. the profile's public address, carrying the `verified` flag of its entry in
 *    the list, or `false` when it does not appear there at all;
 * 4. any verified address;
 * 5. the first address there is.
 *
 * `null` when GitHub reported no address — which happens when the `user:email`
 * scope was refused and the profile address is private. The flow answers
 * `UserInfoFailed`, because an identity with no address cannot be linked or
 * provisioned.
 *
 * **Gotchas**
 *
 * A profile address never counts as verified on its own. It is a free-text
 * field, and step 3 only trusts it as far as the *list* corroborates it.
 *
 * @category combinators
 * @since 1.0.0
 */
export const selectEmail = (
  profileEmail: string | null,
  emails: ReadonlyArray<GithubEmail>
): SelectedEmail | null => {
  const primary = emails.find((entry) => entry.primary)
  if (primary !== undefined && primary.verified) {
    return { email: primary.email, emailVerified: true }
  }
  if (primary !== undefined) {
    return { email: primary.email, emailVerified: false }
  }
  if (profileEmail !== null) {
    const listed = emails.find((entry) => entry.email.toLowerCase() === profileEmail.toLowerCase())
    return { email: profileEmail, emailVerified: listed?.verified ?? false }
  }
  const verified = emails.find((entry) => entry.verified)
  if (verified !== undefined) return { email: verified.email, emailVerified: true }
  const first = emails[0]
  return first === undefined ? null : { email: first.email, emailVerified: first.verified }
}

// -----------------------------------------------------------------------------
// Reading GitHub's JSON
// -----------------------------------------------------------------------------

const asRecord = (value: unknown): Readonly<Record<string, unknown>> | null =>
  typeof value === "object" && value !== null && !Array.isArray(value)
    ? value as Readonly<Record<string, unknown>>
    : null

const readString = (record: Readonly<Record<string, unknown>>, key: string): string | null => {
  if (!Object.hasOwn(record, key)) return null
  const value = record[key]
  if (typeof value === "string" && value.length > 0) return value
  // GitHub's user id is a JSON number; every other id we handle is a string.
  if (typeof value === "number" && Number.isFinite(value)) return String(value)
  return null
}

const readBoolean = (record: Readonly<Record<string, unknown>>, key: string): boolean => {
  if (!Object.hasOwn(record, key)) return false
  return record[key] === true
}

/**
 * Projects `GET /user/emails` into the entries {@link selectEmail} reads.
 *
 * Anything malformed is dropped rather than failing the sign-in: the list is
 * advisory, and one unparseable entry must not cost the person their session.
 *
 * @category combinators
 * @since 1.0.0
 */
export const decodeEmails = (body: unknown): ReadonlyArray<GithubEmail> => {
  if (!Array.isArray(body)) return []
  const entries: Array<GithubEmail> = []
  for (const item of body) {
    const record = asRecord(item)
    if (record === null) continue
    const email = readString(record, "email")
    if (email === null) continue
    entries.push({
      email,
      primary: readBoolean(record, "primary"),
      verified: readBoolean(record, "verified")
    })
  }
  return entries
}

// -----------------------------------------------------------------------------
// Options
// -----------------------------------------------------------------------------

/**
 * What GitHub needs.
 *
 * @category models
 * @since 1.0.0
 */
export interface Options {
  readonly clientId: string
  readonly clientSecret: Redacted.Redacted<string>
  /** Scopes on top of {@link defaultScopes}. */
  readonly scopes?: ReadonlyArray<string> | undefined
  /** Overrides `<baseUrl><basePath>/callback/github`. */
  readonly redirectUri?: string | undefined
  /** Extra authorization parameters, such as `login` or `allow_signup`. */
  readonly authorizationParams?: Readonly<Record<string, string>> | undefined
  /**
   * The GitHub web host, for GitHub Enterprise Server.
   *
   * @default "https://github.com"
   */
  readonly webUrl?: string | undefined
  /**
   * The GitHub API host, for GitHub Enterprise Server.
   *
   * @default "https://api.github.com"
   */
  readonly apiUrl?: string | undefined
}

// -----------------------------------------------------------------------------
// Constructors
// -----------------------------------------------------------------------------

/**
 * Builds the GitHub provider configuration.
 *
 * @category constructors
 * @since 1.0.0
 */
export const make = (options: Options): OAuthProviderConfig => {
  const webUrl = (options.webUrl ?? defaultWebUrl).replace(/\/+$/, "")
  const apiUrl = (options.apiUrl ?? defaultApiUrl).replace(/\/+$/, "")
  const scopes = [...defaultScopes, ...(options.scopes ?? [])]

  const userInfo = Effect.fnUntraced(function*(tokens: OAuthTokens) {
    const accessToken = tokens.accessToken
    const headers = { "user-agent": "effect-auth" }

    const profileResponse = yield* fetchJson({ providerId: id, url: `${apiUrl}/user`, accessToken, headers })
    const profile = asRecord(profileResponse.body)
    if (profile === null) return yield* Effect.fail(providerError(id, "UserInfoFailed"))
    const subject = readString(profile, "id")
    if (subject === null) return yield* Effect.fail(providerError(id, "UserInfoFailed"))

    // A refused `/user/emails` — the `user:email` scope was not granted — is not
    // fatal: the profile address may still be usable, just never as verified.
    const emailsResponse = yield* fetchJson({
      providerId: id,
      url: `${apiUrl}/user/emails`,
      accessToken,
      headers
    })
    const selected = selectEmail(readString(profile, "email"), decodeEmails(emailsResponse.body))
    if (selected === null) return yield* Effect.fail(providerError(id, "UserInfoFailed"))

    return {
      id: subject,
      email: selected.email,
      emailVerified: selected.emailVerified,
      name: readString(profile, "name") ?? readString(profile, "login") ?? selected.email,
      image: readString(profile, "avatar_url")
    } satisfies OAuthUserInfo
  })

  return {
    id,
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    authorizationUrl: `${webUrl}/login/oauth/authorize`,
    tokenUrl: `${webUrl}/login/oauth/access_token`,
    scopes,
    ...(options.redirectUri === undefined ? {} : { redirectUri: options.redirectUri }),
    ...(options.authorizationParams === undefined ? {} : { authorizationParams: options.authorizationParams }),
    userInfo,
    accountId: (info) => info.id
  }
}

/**
 * Registers GitHub.
 *
 * **Example**
 *
 * ```ts
 * import { Redacted } from "effect"
 * import { Github } from "effect-auth"
 *
 * const provider = Github.layer({
 *   clientId: "Iv1.0123456789abcdef",
 *   clientSecret: Redacted.make(process.env.GITHUB_CLIENT_SECRET!)
 * })
 * ```
 *
 * @category layers
 * @since 1.0.0
 */
export const layer = (options: Options): Layer.Layer<OAuthProviders> => registryLayer([make(options)])

/**
 * Registers GitHub, reading its credentials from `Config`.
 *
 * **Gotchas**
 *
 * The secret must come from `Config.redacted`, so that it is a
 * `Redacted<string>` from the moment it leaves the environment and never
 * appears in a log line or a `ConfigError`.
 *
 * @category layers
 * @since 1.0.0
 */
export const layerConfig = (options: {
  readonly clientId: Config.Config<string>
  readonly clientSecret: Config.Config<Redacted.Redacted<string>>
  readonly scopes?: Config.Config<ReadonlyArray<string>> | undefined
  readonly redirectUri?: Config.Config<string> | undefined
  readonly authorizationParams?: Readonly<Record<string, string>> | undefined
  readonly webUrl?: Config.Config<string> | undefined
  readonly apiUrl?: Config.Config<string> | undefined
}): Layer.Layer<OAuthProviders, Config.ConfigError> =>
  Layer.effect(
    OAuthProviders,
    Effect.gen(function*() {
      const provider = make({
        clientId: yield* options.clientId,
        clientSecret: yield* options.clientSecret,
        scopes: options.scopes === undefined ? undefined : yield* options.scopes,
        redirectUri: options.redirectUri === undefined ? undefined : yield* options.redirectUri,
        authorizationParams: options.authorizationParams,
        webUrl: options.webUrl === undefined ? undefined : yield* options.webUrl,
        apiUrl: options.apiUrl === undefined ? undefined : yield* options.apiUrl
      })
      return makeRegistry([provider])
    })
  )
