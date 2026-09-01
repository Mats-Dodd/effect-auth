/**
 * Slack as an OIDC provider ("Sign in with Slack").
 *
 * **Details**
 *
 * Slack is OIDC with one consequential deviation: its `sub` is scoped to the
 * *installation*, not to the person. The stable identity is carried in the
 * URI-namespaced claim `https://slack.com/user_id`, which is what
 * {@link subjectOf} reads and what {@link OAuthProviderConfig.accountId} then
 * projects. Anchoring on `sub` would key an account to one workspace
 * installation and re-provision the same person after a reinstall.
 *
 * **Gotchas**
 *
 * A token that does not carry the claim is refused rather than falling back to
 * `sub`: a fallback would mean two different account rows for one person
 * depending on which token happened to arrive, and the identity a provider is
 * anchored on is not something to guess at.
 *
 * The claim's counterpart `https://slack.com/team_id` is deliberately *not*
 * part of the identity. It would key an account to a workspace, which is a
 * multi-tenant modelling decision belonging to the application, not to the
 * sign-in.
 *
 * @since 0.2.0
 */
import { Config, Effect, Option, type Redacted, Schema } from "effect"
import { optionalConfig } from "../../internal/config.js"
import type { KeyResolver } from "../IdToken.js"
import type { OAuthProviderConfig, OAuthTokens, OAuthUserInfo } from "../Provider.js"
import { providerError } from "../Provider.js"
import { lenient } from "../internal/claims.js"
import { identityOf } from "../internal/userInfo.js"

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/**
 * The id Slack is registered and addressed under.
 *
 * @category constructors
 * @since 0.2.0
 */
export const id = "slack"

/**
 * Slack's OIDC issuer, and the issuer its accounts are stored under.
 *
 * @category constructors
 * @since 0.2.0
 */
export const issuer = "https://slack.com"

/**
 * Slack's authorization endpoint.
 *
 * @category constructors
 * @since 0.2.0
 */
export const authorizationUrl = "https://slack.com/openid/connect/authorize"

/**
 * Slack's token endpoint.
 *
 * @category constructors
 * @since 0.2.0
 */
export const tokenUrl = "https://slack.com/api/openid.connect.token"

/**
 * Where Slack publishes its `id_token` signing keys.
 *
 * @category constructors
 * @since 0.2.0
 */
export const jwksUrl = "https://slack.com/openid/connect/keys"

/**
 * The claim carrying the stable per-person subject.
 *
 * @category constructors
 * @since 0.2.0
 */
export const userIdClaim = "https://slack.com/user_id"

/**
 * The scopes requested by default.
 *
 * @category constructors
 * @since 0.2.0
 */
export const defaultScopes: ReadonlyArray<string> = ["openid", "profile", "email"]

// -----------------------------------------------------------------------------
// Claims
// -----------------------------------------------------------------------------

const Claims = Schema.Struct({
  [userIdClaim]: lenient(Schema.NonEmptyString)
})

const readClaims = Schema.decodeUnknownOption(Claims)

/**
 * The stable subject a Slack `id_token` states, or `null` when it states none.
 *
 * @category combinators
 * @since 0.2.0
 */
export const subjectOf = (claims: Readonly<Record<string, unknown>>): string | null =>
  Option.match(readClaims(claims), {
    onNone: () => null,
    onSome: (fields) => fields[userIdClaim] ?? null
  })

// -----------------------------------------------------------------------------
// Options
// -----------------------------------------------------------------------------

/**
 * What Slack needs.
 *
 * @category models
 * @since 0.2.0
 */
export interface Options {
  readonly clientId: string
  readonly clientSecret: Redacted.Redacted
  /** Scopes on top of {@link defaultScopes}. */
  readonly scopes?: ReadonlyArray<string> | undefined
  /** Overrides `<baseUrl><basePath>/callback/slack`. */
  readonly redirectUri?: string | undefined
  /**
   * Restricts the sign-in to one workspace, as Slack's `team` authorization
   * parameter.
   *
   * **Gotchas**
   *
   * It pre-filters the workspace chooser and is not a check: unlike Google's
   * hosted domain there is no signed claim this library can enforce it against,
   * because the team claim is not part of the identity here. Treat it as a
   * convenience and enforce membership in the application.
   */
  readonly team?: string | undefined
  /** A pinned key set instead of fetching {@link jwksUrl}. For tests. */
  readonly jwks?: KeyResolver | undefined
  /** Extra authorization parameters. */
  readonly authorizationParams?: Readonly<Record<string, string>> | undefined
}

// -----------------------------------------------------------------------------
// Constructors
// -----------------------------------------------------------------------------

/**
 * Builds the Slack provider configuration.
 *
 * **Example**
 *
 * ```ts
 * import { Redacted } from "effect"
 * import { Slack } from "effect-auth"
 *
 * const slack = Slack.make({
 *   clientId: "1234.5678",
 *   clientSecret: Redacted.make(process.env.SLACK_CLIENT_SECRET!)
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
    if (identity === null) return yield* providerError(id, "UserInfoFailed")

    // The one Slack-specific line: the subject is the URI-namespaced claim, and
    // a token without it is refused rather than anchored on the installation's
    // `sub`. Both come out of the signature, so neither is caller-chosen.
    const subject = subjectOf(claims.raw)
    if (subject === null) return yield* providerError(id, "UserInfoFailed")

    return { ...identity, id: subject } satisfies OAuthUserInfo
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
    authorizationParams: {
      ...(options.team === undefined ? {} : { team: options.team }),
      ...options.authorizationParams
    },
    userInfo,
    accountId: (info) => info.id
  }
}

/**
 * What Slack needs, per field, as `Config` values.
 *
 * @category models
 * @since 0.2.0
 */
export interface ConfigOptions {
  readonly clientId: Config.Config<string>
  readonly clientSecret: Config.Config<Redacted.Redacted>
  readonly scopes?: Config.Config<ReadonlyArray<string>> | undefined
  readonly redirectUri?: Config.Config<string> | undefined
  readonly team?: Config.Config<string> | undefined
  readonly authorizationParams?: Readonly<Record<string, string>> | undefined
}

/** The settings {@link ConfigOptions} reads from the environment. */
interface Settings {
  readonly clientId: string
  readonly clientSecret: Redacted.Redacted
  readonly scopes: ReadonlyArray<string> | undefined
  readonly redirectUri: string | undefined
  readonly team: string | undefined
}

/**
 * Builds the Slack provider configuration, reading its credentials from
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
      team: optionalConfig(options.team)
    }),
    (settings) => make({ ...settings, authorizationParams: options.authorizationParams })
  )
