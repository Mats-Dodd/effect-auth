/**
 * Facebook as an OAuth 2.0 provider, with the Limited Login variant beside it.
 *
 * **Details**
 *
 * Two shapes, one module. The ordinary web flow exchanges a code for a Graph
 * access token and reads `GET /me`; Limited Login — what Facebook's iOS and
 * Android SDKs return when tracking is restricted — hands back an OIDC
 * `id_token` and no Graph token at all, so the identity comes from the verified
 * token instead. {@link Options.limitedLogin} picks which one this value is.
 *
 * The web flow does something none of the other providers here needs: it calls
 * `debug_token` and refuses the sign-in unless the token it was handed was
 * minted **for this application** (`data.app_id`) and **for this person**
 * (`data.user_id` equals the profile's `id`). A Graph access token is a bearer
 * credential that any Facebook application can obtain; without that binding, a
 * token minted for somebody else's app and pasted into a client-side flow would
 * read as a valid identity here. Facebook's own documentation calls this the
 * confused-deputy check, and better-auth ships it for the same reason.
 *
 * **Gotchas**
 *
 * Neither path may claim a verified address, so this provider declares
 * `emailVerified: "never"` and can never *implicitly* link onto a local account
 * holding the same address. Graph's `/me` states no verification flag at all,
 * and Limited Login's `id_token` carries none either — Facebook confirms an
 * address at registration and then never tells the relying party so. Linking is
 * still available deliberately, from a session the person already holds.
 *
 * @since 0.2.0
 */
import { Config, Effect, Option, Redacted, Schema } from "effect"
import { optionalConfig } from "../../internal/config.js"
import type { OAuthProviderConfig, OAuthTokens, OAuthUserInfo } from "../Provider.js"
import { fetchJson, providerError } from "../Provider.js"
import { lenient, StringFromNumeric } from "../internal/claims.js"
import { identityOf } from "../internal/userInfo.js"

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/**
 * The id Facebook is registered and addressed under.
 *
 * @category constructors
 * @since 0.2.0
 */
export const id = "facebook"

/**
 * The Graph API version every URL here is pinned to.
 *
 * **Gotchas**
 *
 * Pinned rather than tracking `latest`: Facebook deprecates a version roughly
 * every two years, and a silent move is a sign-in that changes shape without a
 * release. Override it with {@link Options.graphVersion}.
 *
 * @category constructors
 * @since 0.2.0
 */
export const defaultGraphVersion = "v21.0"

/**
 * Facebook's OIDC issuer, as Limited Login `id_token`s declare it.
 *
 * @category constructors
 * @since 0.2.0
 */
export const issuer = "https://www.facebook.com"

/**
 * Where Limited Login's signing keys are published.
 *
 * @category constructors
 * @since 0.2.0
 */
export const jwksUrl = "https://www.facebook.com/.well-known/oauth/openid/jwks/"

/**
 * The scopes requested by default: the address, and enough of the profile to
 * name the account.
 *
 * @category constructors
 * @since 0.2.0
 */
export const defaultScopes: ReadonlyArray<string> = ["email", "public_profile"]

/** The profile fields asked for on the Graph user request. */
const profileFields = "id,name,email,picture"

// -----------------------------------------------------------------------------
// Endpoints
// -----------------------------------------------------------------------------

/**
 * The three endpoints of one Graph version.
 *
 * @category models
 * @since 0.2.0
 */
export interface Endpoints {
  readonly authorizationUrl: string
  readonly tokenUrl: string
  readonly userInfoUrl: string
  readonly debugTokenUrl: string
}

/**
 * The endpoints of a Graph version.
 *
 * @category combinators
 * @since 0.2.0
 */
export const endpointsFor = (version: string): Endpoints => ({
  authorizationUrl: `https://www.facebook.com/${version}/dialog/oauth`,
  tokenUrl: `https://graph.facebook.com/${version}/oauth/access_token`,
  userInfoUrl: `https://graph.facebook.com/${version}/me`,
  debugTokenUrl: `https://graph.facebook.com/${version}/debug_token`
})

// -----------------------------------------------------------------------------
// Reading Facebook's JSON
// -----------------------------------------------------------------------------

/**
 * `GET /me`, as far as it is believed. Only the id is required; an absent
 * `email` is a refused scope and is fatal, because an identity with no address
 * can be neither linked nor provisioned.
 */
const Profile = Schema.Struct({
  id: StringFromNumeric,
  name: lenient(Schema.NonEmptyString),
  email: lenient(Schema.NonEmptyString),
  picture: lenient(Schema.Struct({ data: lenient(Schema.Struct({ url: lenient(Schema.NonEmptyString) })) }))
})

const readProfile = Schema.decodeUnknownOption(Profile)

/**
 * `GET /debug_token`, as far as the binding needs it. Every field is required:
 * a body that does not state all three cannot support the check, and a check
 * that cannot be made is a refusal.
 */
const DebugToken = Schema.Struct({
  data: Schema.Struct({
    app_id: StringFromNumeric,
    user_id: StringFromNumeric,
    is_valid: Schema.Boolean
  })
})

const readDebugToken = Schema.decodeUnknownOption(DebugToken)

/**
 * Whether a `debug_token` answer binds this token to this application and this
 * person.
 *
 * **Details**
 *
 * Three conditions, all required: Facebook says the token is live, it was
 * minted for `clientId`, and it belongs to the account `GET /me` just reported.
 * A body that fails to decode fails the check — an unparseable answer is not
 * evidence.
 *
 * @category combinators
 * @since 0.2.0
 */
export const bindsToken = (body: unknown, options: { readonly clientId: string; readonly userId: string }): boolean =>
  Option.match(readDebugToken(body), {
    onNone: () => false,
    onSome: ({ data }) => data.is_valid && data.app_id === options.clientId && data.user_id === options.userId
  })

// -----------------------------------------------------------------------------
// Options
// -----------------------------------------------------------------------------

/**
 * What Facebook needs.
 *
 * @category models
 * @since 0.2.0
 */
export interface Options {
  readonly clientId: string
  /**
   * The application secret.
   *
   * **Gotchas**
   *
   * Required on both paths, and used for two different things: the token
   * exchange, and the app access token `debug_token` is called with. Facebook
   * has no public-client mode this library serves.
   */
  readonly clientSecret: Redacted.Redacted
  /**
   * Read the identity from a Limited Login `id_token` rather than from Graph.
   * Defaults to `false`.
   *
   * **When to use**
   *
   * For a deployment whose mobile clients sign in through Facebook's SDK with
   * tracking restricted: there is no Graph token to call `/me` with, and the
   * `id_token` is the whole of what comes back.
   */
  readonly limitedLogin?: boolean | undefined
  /** Scopes on top of {@link defaultScopes}. */
  readonly scopes?: ReadonlyArray<string> | undefined
  /** Overrides `<baseUrl><basePath>/callback/facebook`. */
  readonly redirectUri?: string | undefined
  /** Overrides {@link defaultGraphVersion}. */
  readonly graphVersion?: string | undefined
  /** Extra authorization parameters, such as `auth_type=rerequest`. */
  readonly authorizationParams?: Readonly<Record<string, string>> | undefined
}

// -----------------------------------------------------------------------------
// Constructors
// -----------------------------------------------------------------------------

/**
 * Builds the Facebook provider configuration.
 *
 * **Example**
 *
 * ```ts
 * import { Redacted } from "effect"
 * import { Facebook } from "effect-auth"
 *
 * const facebook = Facebook.make({
 *   clientId: "1234567890",
 *   clientSecret: Redacted.make(process.env.FACEBOOK_CLIENT_SECRET!)
 * })
 * ```
 *
 * @category constructors
 * @since 0.2.0
 */
export const make = (options: Options): OAuthProviderConfig => {
  const endpoints = endpointsFor(options.graphVersion ?? defaultGraphVersion)

  /** The Graph path: profile, then the binding check that makes it believable. */
  const graphUserInfo = Effect.fnUntraced(function* (tokens: OAuthTokens) {
    const accessToken = tokens.accessToken
    const response = yield* fetchJson({
      providerId: id,
      url: `${endpoints.userInfoUrl}?fields=${encodeURIComponent(profileFields)}`,
      accessToken
    })
    const decoded = readProfile(response.body)
    if (Option.isNone(decoded)) return yield* providerError(id, "UserInfoFailed")
    const profile = decoded.value

    const email = profile.email ?? null
    if (email === null) return yield* providerError(id, "UserInfoFailed")

    // The confused-deputy check. `input_token` is the token being inspected;
    // the credential on the request is the *app* access token, which is the one
    // thing an attacker holding somebody else's user token does not have.
    const debug = yield* fetchJson({
      providerId: id,
      url: `${endpoints.debugTokenUrl}?input_token=${encodeURIComponent(Redacted.value(accessToken))}`,
      accessToken: appAccessToken(options)
    })
    if (!bindsToken(debug.body, { clientId: options.clientId, userId: profile.id })) {
      return yield* providerError(id, "UserInfoFailed")
    }

    return {
      id: profile.id,
      email,
      // Overridden to `false` by the provider's own `"never"` policy; stated
      // here so the value this function produces is honest on its own.
      emailVerified: false,
      name: profile.name ?? email,
      image: profile.picture?.data?.url ?? null
    } satisfies OAuthUserInfo
  })

  /** The Limited Login path: the verified `id_token` is the whole identity. */
  const limitedUserInfo = Effect.fnUntraced(function* (tokens: OAuthTokens) {
    const claims = tokens.idTokenClaims
    if (claims === null) return yield* providerError(id, "IdTokenInvalid")
    const identity = identityOf(claims)
    if (identity === null) return yield* providerError(id, "UserInfoFailed")
    return identity
  })

  return {
    id,
    // Neither path carries a verification claim. See the module header.
    emailVerified: "never",
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    authorizationUrl: endpoints.authorizationUrl,
    tokenUrl: endpoints.tokenUrl,
    scopes: [...defaultScopes, ...(options.scopes ?? [])],
    ...(options.limitedLogin === true ? { oidc: { issuer, keys: { jwksUrl }, algorithms: ["RS256"] } } : {}),
    ...(options.redirectUri === undefined ? {} : { redirectUri: options.redirectUri }),
    ...(options.authorizationParams === undefined ? {} : { authorizationParams: options.authorizationParams }),
    userInfo: options.limitedLogin === true ? limitedUserInfo : graphUserInfo,
    accountId: (info) => info.id
  }
}

/**
 * The app access token `debug_token` is called with: `<app-id>|<app-secret>`,
 * which is what Facebook accepts in place of a fetched one.
 *
 * **Gotchas**
 *
 * It stays `Redacted` — it carries the application secret verbatim, so a log
 * line holding it is a leaked secret.
 */
const appAccessToken = (options: Options): Redacted.Redacted =>
  Redacted.make(`${options.clientId}|${Redacted.value(options.clientSecret)}`)

/**
 * What Facebook needs, per field, as `Config` values.
 *
 * @category models
 * @since 0.2.0
 */
export interface ConfigOptions {
  readonly clientId: Config.Config<string>
  readonly clientSecret: Config.Config<Redacted.Redacted>
  readonly limitedLogin?: Config.Config<boolean> | undefined
  readonly scopes?: Config.Config<ReadonlyArray<string>> | undefined
  readonly redirectUri?: Config.Config<string> | undefined
  readonly graphVersion?: Config.Config<string> | undefined
  readonly authorizationParams?: Readonly<Record<string, string>> | undefined
}

/** The settings {@link ConfigOptions} reads from the environment. */
interface Settings {
  readonly clientId: string
  readonly clientSecret: Redacted.Redacted
  readonly limitedLogin: boolean | undefined
  readonly scopes: ReadonlyArray<string> | undefined
  readonly redirectUri: string | undefined
  readonly graphVersion: string | undefined
}

/**
 * Builds the Facebook provider configuration, reading its credentials from
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
      limitedLogin: optionalConfig(options.limitedLogin),
      scopes: optionalConfig(options.scopes),
      redirectUri: optionalConfig(options.redirectUri),
      graphVersion: optionalConfig(options.graphVersion)
    }),
    (settings) => make({ ...settings, authorizationParams: options.authorizationParams })
  )
