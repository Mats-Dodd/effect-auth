/**
 * X (formerly Twitter) as an OAuth 2.0 provider.
 *
 * **Details**
 *
 * X is the awkward one, in three ways this module answers directly.
 *
 * *Client authentication.* A confidential X client must authenticate with HTTP
 * Basic on the token endpoint; `client_secret_post`, which the generic exchange
 * sends, is rejected. So this provider owns its exchange
 * ({@link OAuthProviderConfig.exchange}) and posts the code itself. PKCE is not
 * a special case — this library always sends a code challenge — but it *is* what
 * a public X client authenticates with instead, so a value built with no
 * `clientSecret` sends no `Authorization` header and works unchanged.
 *
 * *The address is a second request.* `GET /2/users/me` will not return
 * `confirmed_email` unless the `users.email` scope was granted, and asking for
 * the field without the scope fails the *whole* call. So the profile is fetched
 * first, without it, and the address is asked for separately: a refusal there
 * costs the address and not the sign-in.
 *
 * *There may be no address at all.* X accounts predate mandatory addresses and
 * the scope is routinely refused, so an identity with no `confirmed_email` is
 * reported under a placeholder — `<username>@twitter.invalid`, in the RFC 2606
 * reserved domain that can never be delivered to — and is never verified. It is
 * stable for the account (the username is not, so the *subject* is still the
 * numeric id) and it can never collide with a real address, so a person in that
 * state gets an account they can use and an address they can replace.
 *
 * @since 0.2.0
 */
import { Config, Effect, Option, type Redacted, Schema } from "effect"
import { optionalConfig } from "../../internal/config.js"
import type { OAuthProviderConfig, OAuthTokens, OAuthUserInfo } from "../Provider.js"
import { fetchJson, providerError } from "../Provider.js"
import { lenient, StringFromNumeric } from "../internal/claims.js"

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/**
 * The id X is registered and addressed under.
 *
 * **Gotchas**
 *
 * `"twitter"`, not `"x"`: it is the last segment of a callback path that is
 * registered with the provider and stored in every existing account row, so it
 * is a name and not a brand.
 *
 * @category constructors
 * @since 0.2.0
 */
export const id = "twitter"

/**
 * X's authorization endpoint.
 *
 * @category constructors
 * @since 0.2.0
 */
export const authorizationUrl = "https://x.com/i/oauth2/authorize"

/**
 * X's token endpoint.
 *
 * @category constructors
 * @since 0.2.0
 */
export const tokenUrl = "https://api.x.com/2/oauth2/token"

/**
 * X's user endpoint.
 *
 * @category constructors
 * @since 0.2.0
 */
export const userInfoUrl = "https://api.x.com/2/users/me"

/**
 * The domain a placeholder address is minted in. RFC 2606 reserves
 * `.invalid`, so nothing here is ever deliverable.
 *
 * @category constructors
 * @since 0.2.0
 */
export const placeholderDomain = "twitter.invalid"

/**
 * The scopes requested by default. `offline.access` is what makes a refresh
 * token exist at all, and `users.email` is what makes an address possible.
 *
 * @category constructors
 * @since 0.2.0
 */
export const defaultScopes: ReadonlyArray<string> = ["users.read", "tweet.read", "offline.access", "users.email"]

/** The profile fields asked for on the first call — none of them scope-gated. */
const profileFields = "profile_image_url,name,username"

// -----------------------------------------------------------------------------
// Reading X's JSON
// -----------------------------------------------------------------------------

/**
 * `GET /2/users/me`, as far as it is believed. X wraps everything in `data`.
 */
const Profile = Schema.Struct({
  data: Schema.Struct({
    id: StringFromNumeric,
    username: lenient(Schema.NonEmptyString),
    name: lenient(Schema.NonEmptyString),
    profile_image_url: lenient(Schema.NonEmptyString),
    confirmed_email: lenient(Schema.NonEmptyString)
  })
})

const readProfile = Schema.decodeUnknownOption(Profile)

/**
 * The address an X identity is reported under: the confirmed one, or a
 * placeholder that can never be delivered to and is never verified.
 *
 * @category combinators
 * @since 0.2.0
 */
export const selectEmail = (options: {
  readonly confirmedEmail: string | null
  readonly username: string | null
  readonly userId: string
}): { readonly email: string; readonly emailVerified: boolean } =>
  options.confirmedEmail === null
    ? // Keyed on the account id, never on the handle. X releases handles and
      // reassigns them, and `users.email` is unique: a placeholder minted from
      // `@ada` would collide with the earlier account of whoever held it
      // before, and the new person could then never sign in at all — the
      // address is unverified, so implicit linking refuses, and the refusal is
      // permanent. The id is the one thing about an X identity that does not
      // move.
      { email: `${options.userId}@${placeholderDomain}`, emailVerified: false }
    : // X calls the field `confirmed_email`, which is its statement that it
      // checked the address. Nothing else on the profile is evidence.
      { email: options.confirmedEmail, emailVerified: true }

// -----------------------------------------------------------------------------
// Options
// -----------------------------------------------------------------------------

/**
 * What X needs.
 *
 * @category models
 * @since 0.2.0
 */
export interface Options {
  readonly clientId: string
  /**
   * The client secret, or absent for a public client.
   *
   * **Details**
   *
   * A confidential client sends it as HTTP Basic on the token request — X
   * rejects `client_secret_post`. A public client omits it and is proved by
   * PKCE, which this library always sends.
   */
  readonly clientSecret?: Redacted.Redacted | undefined
  /** Scopes on top of {@link defaultScopes}. */
  readonly scopes?: ReadonlyArray<string> | undefined
  /** Overrides `<baseUrl><basePath>/callback/twitter`. */
  readonly redirectUri?: string | undefined
  /** Extra authorization parameters. */
  readonly authorizationParams?: Readonly<Record<string, string>> | undefined
}

// -----------------------------------------------------------------------------
// Constructors
// -----------------------------------------------------------------------------

/**
 * Builds the X provider configuration.
 *
 * **Example**
 *
 * ```ts
 * import { Redacted } from "effect"
 * import { Twitter } from "effect-auth"
 *
 * const twitter = Twitter.make({
 *   clientId: "some-client-id",
 *   clientSecret: Redacted.make(process.env.TWITTER_CLIENT_SECRET!)
 * })
 * ```
 *
 * @category constructors
 * @since 0.2.0
 */
export const make = (options: Options): OAuthProviderConfig => {
  const secret = options.clientSecret

  /**
   * The profile, then the address, as two calls.
   *
   * `GET /2/users/me` refuses the *whole* request if `confirmed_email` is asked
   * for without the `users.email` scope, and that scope is routinely not
   * granted. So the fields that are never scope-gated are fetched first, and
   * the address is asked for separately: a refusal there costs the address and
   * not the sign-in.
   */
  const userInfo = Effect.fnUntraced(function* (tokens: OAuthTokens) {
    const response = yield* fetchJson({
      providerId: id,
      url: `${userInfoUrl}?user.fields=${profileFields}`,
      accessToken: tokens.accessToken
    })
    const decoded = readProfile(response.body)
    if (Option.isNone(decoded)) return yield* providerError(id, "UserInfoFailed")
    const profile = decoded.value.data

    // Separately, and forgivingly: this is the only part of the identity a
    // provider's refusal is allowed to cost.
    const withEmail = yield* fetchJson({
      providerId: id,
      url: `${userInfoUrl}?user.fields=confirmed_email`,
      accessToken: tokens.accessToken
    })
    const address = readProfile(withEmail.body)
    const confirmedEmail = Option.isNone(address) ? null : address.value.data.confirmed_email

    const selected = selectEmail({
      confirmedEmail: confirmedEmail ?? null,
      username: profile.username ?? null,
      userId: profile.id
    })

    return {
      id: profile.id,
      email: selected.email,
      emailVerified: selected.emailVerified,
      name: profile.name ?? profile.username ?? selected.email,
      image: profile.profile_image_url ?? null
    } satisfies OAuthUserInfo
  })

  return {
    id,
    // `confirmed_email` is X's own statement that it checked the address; a
    // placeholder never carries it.
    emailVerified: "derived",
    clientId: options.clientId,
    ...(secret === undefined ? {} : { clientSecret: secret }),
    authorizationUrl,
    tokenUrl,
    // X refuses `client_secret_post` outright. Stated here rather than solved
    // with an `exchange` override, because an override covers the
    // authorization code and not the refresh: `offline.access` is in the
    // default scopes, so a deployment that signed somebody in would have failed
    // to refresh them two hours later, and nothing before then would have said
    // so.
    tokenAuth: "client_secret_basic",
    scopes: [...defaultScopes, ...(options.scopes ?? [])],
    ...(options.redirectUri === undefined ? {} : { redirectUri: options.redirectUri }),
    ...(options.authorizationParams === undefined ? {} : { authorizationParams: options.authorizationParams }),
    userInfo,
    accountId: (info) => info.id
  }
}

/**
 * What X needs, per field, as `Config` values.
 *
 * @category models
 * @since 0.2.0
 */
export interface ConfigOptions {
  readonly clientId: Config.Config<string>
  readonly clientSecret?: Config.Config<Redacted.Redacted> | undefined
  readonly scopes?: Config.Config<ReadonlyArray<string>> | undefined
  readonly redirectUri?: Config.Config<string> | undefined
  readonly authorizationParams?: Readonly<Record<string, string>> | undefined
}

/** The settings {@link ConfigOptions} reads from the environment. */
interface Settings {
  readonly clientId: string
  readonly clientSecret: Redacted.Redacted | undefined
  readonly scopes: ReadonlyArray<string> | undefined
  readonly redirectUri: string | undefined
}

/**
 * Builds the X provider configuration, reading its credentials from `Config`.
 *
 * @category constructors
 * @since 0.2.0
 */
export const makeConfig = (options: ConfigOptions): Effect.Effect<OAuthProviderConfig, Config.ConfigError> =>
  Effect.map(
    Config.unwrap<Settings>({
      clientId: options.clientId,
      clientSecret: optionalConfig(options.clientSecret),
      scopes: optionalConfig(options.scopes),
      redirectUri: optionalConfig(options.redirectUri)
    }),
    (settings) => make({ ...settings, authorizationParams: options.authorizationParams })
  )
