/**
 * Microsoft Entra ID as an OIDC provider — work, school and personal accounts.
 *
 * Entra is the multi-tenant case the rest of the OAuth module was built around.
 * One configured provider serves every tenant a deployment admits, and the
 * issuer a token must claim is not a constant: it names the tenant the token
 * came from. So the expected issuer is *derived* from the token's own `tid`
 * claim — the OIDC block's `issuerOf`, see {@link OAuthProviderConfig.oidc} —
 * and then compared with `iss`, and the identity is stored under that
 * per-tenant issuer rather than under one shared string.
 *
 * **Details**
 *
 * Three things here are load-bearing and none of them is obvious.
 *
 * The identity is `oid`, not `sub`. Entra's `sub` is *per application* — the
 * same person signing into two applications has two of them — while `oid` is
 * the account's immutable object id in its tenant. A token with no `oid` is
 * refused rather than anchored on something that will change.
 *
 * The `common`, `organizations` and `consumers` endpoints cannot pin an issuer,
 * so the tenant binding is enforced by hand: `iss` must name the token's own
 * `tid`, a personal-account token is refused under `organizations`, and a
 * work-account token is refused under `consumers`. Without that check the
 * `organizations` and `consumers` key sets overlap enough that either could sign
 * for the other.
 *
 * `email_verified` is an *optional* claim Entra does not emit unless the
 * application registration asks for it, so it defaults to `false` and the
 * `verified_primary_email` list is consulted as the only other evidence.
 *
 * @since 1.0.0
 */
import type { Redacted } from "effect"
import { Config, Effect, Option, Schema } from "effect"
import { dual } from "effect/Function"
import { optionalConfig } from "../../internal/config.js"
import { trimTrailingSlashes } from "../../internal/url.js"
import type { KeyResolver } from "../IdToken.js"
import type { OAuthProviderConfig, OAuthTokens, OAuthUserInfo } from "../Provider.js"
import { providerError } from "../Provider.js"
import { lenient, Truthy } from "../internal/claims.js"

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/**
 * The id Microsoft is registered and addressed under.
 *
 * @category constructors
 * @since 1.0.0
 */
export const id = "microsoft"

/**
 * The authority a deployment that says nothing else talks to.
 *
 * @category constructors
 * @since 1.0.0
 */
export const defaultAuthority = "https://login.microsoftonline.com"

/**
 * The tenant a deployment that says nothing else serves: every kind of account.
 *
 * @category constructors
 * @since 1.0.0
 */
export const defaultTenantId = "common"

/**
 * Microsoft's fixed tenant id for personal (consumer) accounts.
 *
 * **Details**
 *
 * Every personal-account token carries it as `tid`, which is what tells the
 * account *class* apart: `organizations` refuses it, `consumers` requires it.
 *
 * @category constructors
 * @since 1.0.0
 */
export const consumerTenantId = "9188040d-6c67-4c5b-b112-36a304b66dad"

/**
 * The three tenant names that are not a tenant, and therefore cannot pin an
 * issuer.
 *
 * @category constructors
 * @since 1.0.0
 */
export const multiTenantIds: ReadonlyArray<string> = ["common", "organizations", "consumers"]

/**
 * The scopes requested by default.
 *
 * `offline_access` is what makes Entra issue a refresh token, without which
 * `POST /auth/get-access-token` has nothing to refresh.
 *
 * @category constructors
 * @since 1.0.0
 */
export const defaultScopes: ReadonlyArray<string> = ["openid", "profile", "email", "User.Read", "offline_access"]

/**
 * The endpoints one authority-and-tenant pair serves.
 *
 * @category models
 * @since 1.0.0
 */
export interface Endpoints {
  readonly authority: string
  readonly tenantId: string
  readonly authorizationUrl: string
  readonly tokenUrl: string
  readonly jwksUrl: string
  /** The issuer of *this* tenant — `common`'s is nobody's, see {@link make}. */
  readonly issuer: string
}

/**
 * Where one Entra authority-and-tenant pair's endpoints live.
 *
 * **Gotchas**
 *
 * Trailing slashes are trimmed off the authority: left in, one would make the
 * expected issuer `https://host//<tid>/v2.0` and refuse every token.
 *
 * @category combinators
 * @since 1.0.0
 */
export const endpointsOf = (options?: {
  readonly authority?: string | undefined
  readonly tenantId?: string | undefined
}): Endpoints => {
  const authority = trimTrailingSlashes(options?.authority ?? defaultAuthority)
  const tenantId = options?.tenantId ?? defaultTenantId
  return {
    authority,
    tenantId,
    authorizationUrl: `${authority}/${tenantId}/oauth2/v2.0/authorize`,
    tokenUrl: `${authority}/${tenantId}/oauth2/v2.0/token`,
    jwksUrl: `${authority}/${tenantId}/discovery/v2.0/keys`,
    issuer: `${authority}/${tenantId}/v2.0`
  }
}

/**
 * The issuer a token from tenant `tid` must claim.
 *
 * @category combinators
 * @since 1.0.0
 */
export const issuerOfTenant: {
  (authority: string, tenantId: string): string
  (tenantId: string): (authority: string) => string
} = dual(2, (authority: string, tenantId: string): string => `${authority}/${tenantId}/v2.0`)

// -----------------------------------------------------------------------------
// Reading Entra's claims
// -----------------------------------------------------------------------------

/**
 * The claims of a verified Entra `id_token` this provider reads.
 *
 * `oid` is the identity and is checked for after decoding; everything else is
 * advisory. The two `verified_*` lists are Entra's only statement about an
 * address when the `email_verified` optional claim was not configured.
 */
const Claims = Schema.Struct({
  oid: lenient(Schema.NonEmptyString),
  tid: lenient(Schema.NonEmptyString),
  iss: lenient(Schema.NonEmptyString),
  email: lenient(Schema.NonEmptyString),
  preferred_username: lenient(Schema.NonEmptyString),
  name: lenient(Schema.NonEmptyString),
  picture: lenient(Schema.NonEmptyString),
  email_verified: lenient(Truthy),
  verified_primary_email: lenient(Schema.Array(Schema.String)),
  verified_secondary_email: lenient(Schema.Array(Schema.String))
})

const readClaims = Schema.decodeUnknownOption(Claims)

/** The `tid` claim, read out of a payload nothing has been believed of yet. */
const TenantClaim = Schema.Struct({ tid: lenient(Schema.NonEmptyString) })

const readTenant = Schema.decodeUnknownOption(TenantClaim)

/**
 * Whether Entra states it verified `email`.
 *
 * **Details**
 *
 * `email_verified` is an optional claim: an application registration that has
 * not asked for it gets nothing, which is not evidence of anything and reads as
 * `false`. The `verified_primary_email` / `verified_secondary_email` lists are
 * the fallback, and only when they contain the very address being reported.
 *
 * A token with no `email` claim at all is never verified, whatever else it
 * says: the address then came from `preferred_username`, and a flag about an
 * absent claim is not a statement about that.
 *
 * @category combinators
 * @since 1.0.0
 */
export const emailVerifiedOf = (claims: {
  readonly email?: string | undefined
  readonly email_verified?: true | "true" | undefined
  readonly verified_primary_email?: ReadonlyArray<string> | undefined
  readonly verified_secondary_email?: ReadonlyArray<string> | undefined
}): boolean => {
  const email = claims.email
  if (email === undefined) return false
  if (claims.email_verified !== undefined) return true
  return (
    (claims.verified_primary_email ?? []).includes(email) || (claims.verified_secondary_email ?? []).includes(email)
  )
}

// -----------------------------------------------------------------------------
// Options
// -----------------------------------------------------------------------------

/**
 * What Microsoft needs.
 *
 * @category models
 * @since 1.0.0
 */
export interface Options {
  readonly clientId: string
  /**
   * The client secret, for a confidential client.
   *
   * **Details**
   *
   * Optional, and genuinely so: Entra supports public clients — a native or
   * single-page application authorizing with PKCE — which have no secret to
   * keep. Omitting it sends no `client_secret` on the token request at all.
   */
  readonly clientSecret?: Redacted.Redacted | undefined
  /**
   * Which accounts may sign in: a tenant GUID or domain for one organization,
   * or `"common"` / `"organizations"` / `"consumers"`.
   *
   * @default "common"
   */
  readonly tenantId?: string | undefined
  /**
   * The authentication authority. `https://login.microsoftonline.com` for
   * standard Entra ID, `https://<tenant>.ciamlogin.com` for an External ID
   * (CIAM) deployment.
   *
   * @default "https://login.microsoftonline.com"
   */
  readonly authority?: string | undefined
  /** Scopes on top of {@link defaultScopes}. */
  readonly scopes?: ReadonlyArray<string> | undefined
  /** Overrides `<baseUrl><basePath>/callback/microsoft`. */
  readonly redirectUri?: string | undefined
  /** Extra authorization parameters, such as `prompt` or `login_hint`. */
  readonly authorizationParams?: Readonly<Record<string, string>> | undefined
  /** The JWS algorithms accepted on an `id_token`. */
  readonly algorithms?: ReadonlyArray<string> | undefined
  /**
   * A pre-resolved key set instead of fetching {@link Endpoints.jwksUrl}.
   *
   * **When to use**
   *
   * Tests, which hand in a `jose` `createLocalJWKSet` so verification runs with
   * no network at all.
   *
   * **Gotchas**
   *
   * It replaces {@link Endpoints.jwksUrl} rather than joining it: the
   * provider's key source is one or the other, and pinning a key set is a
   * statement that nothing is to be fetched.
   */
  readonly jwks?: KeyResolver | undefined
}

// -----------------------------------------------------------------------------
// Constructors
// -----------------------------------------------------------------------------

/**
 * Builds the Microsoft Entra ID provider configuration.
 *
 * **Details**
 *
 * The OIDC block is what puts the flow on the OIDC path — the `id_token` is
 * then required and verified fail-closed — and its `issuer` is this tenant's
 * own. For the three multi-tenant endpoints that string is nobody's issuer:
 * no token ever claims `.../common/v2.0`. It stays anyway, and it stays
 * *inert*: the block has to name an issuer, this is the honest name of where
 * the provider was pointed, and nothing believes it, because `issuerOf` derives
 * the real expectation from the token's `tid` and `userInfo` reports the issuer
 * the *verified* token named as the one the account is stored under.
 *
 * **Example**
 *
 * ```ts
 * import { Redacted } from "effect"
 * import { Microsoft } from "effect-auth"
 *
 * const microsoft = Microsoft.make({
 *   clientId: "00000000-0000-0000-0000-000000000000",
 *   clientSecret: Redacted.make(process.env.MICROSOFT_CLIENT_SECRET!),
 *   tenantId: "organizations"
 * })
 * ```
 *
 * @category constructors
 * @since 1.0.0
 */
export const make = (options: Options): OAuthProviderConfig => {
  const endpoints = endpointsOf(options)
  const scopes = [...defaultScopes, ...(options.scopes ?? [])]
  const multiTenant = multiTenantIds.includes(endpoints.tenantId)

  /**
   * The expected issuer for a token from *this* tenant, and the account-class
   * check the multi-tenant endpoints cannot get from a pinned issuer.
   *
   * It runs on a payload whose signature has been checked but whose issuer has
   * not, so it decides what to expect and never what to believe: whatever it
   * returns is compared with the token's own `iss`.
   */
  const issuerOf = (claims: Readonly<Record<string, unknown>>): string | null => {
    const tenant = Option.match(readTenant(claims), {
      onNone: () => null,
      onSome: (fields) => fields.tid ?? null
    })
    if (tenant === null) return null
    if (endpoints.tenantId === "organizations" && tenant === consumerTenantId) return null
    if (endpoints.tenantId === "consumers" && tenant !== consumerTenantId) return null
    return issuerOfTenant(endpoints.authority, tenant)
  }

  const userInfo = Effect.fnUntraced(function* (tokens: OAuthTokens) {
    const verified = tokens.idTokenClaims
    // The flow verifies the token before calling this and refuses the callback
    // when there is none. A null here would mean the OIDC path was skipped.
    if (verified === null) return yield* providerError(id, "IdTokenInvalid")
    const decoded = readClaims(verified.raw)
    if (Option.isNone(decoded)) return yield* providerError(id, "IdTokenInvalid")
    const claims = decoded.value

    // `oid`, not `sub`: Entra's `sub` is per application, `oid` is the account.
    // Without one there is no stable identity to anchor an account row on.
    const subject = claims.oid ?? null
    if (subject === null) return yield* providerError(id, "IdTokenInvalid")

    // Entra emits `email` only when the application registration asked for it,
    // so the UPN is the fallback address. It is never a *verified* one — see
    // `emailVerifiedOf` — which is what keeps it from linking onto an existing
    // local account by itself.
    const email = claims.email ?? claims.preferred_username ?? null
    if (email === null) return yield* providerError(id, "UserInfoFailed")

    return {
      id: subject,
      email,
      emailVerified: emailVerifiedOf(claims),
      name: claims.name ?? email,
      image: claims.picture ?? null,
      // Half of the account's identity, and it comes from the *verified* token:
      // the issuer `verify` compared `iss` against, per tenant.
      issuer: verified.issuer
    } satisfies OAuthUserInfo
  })

  return {
    id,
    clientId: options.clientId,
    ...(options.clientSecret === undefined ? {} : { clientSecret: options.clientSecret }),
    authorizationUrl: endpoints.authorizationUrl,
    tokenUrl: endpoints.tokenUrl,
    scopes,
    oidc: {
      issuer: endpoints.issuer,
      // Only where the configured "tenant" is not one: a pinned tenant's issuer
      // is already the right expectation, and deriving it again from the token's
      // own `tid` would let the token choose what it is checked against.
      ...(multiTenant ? { issuerOf } : {}),
      keys: options.jwks === undefined ? { jwksUrl: endpoints.jwksUrl } : { jwks: options.jwks },
      ...(options.algorithms === undefined ? {} : { algorithms: options.algorithms })
    },
    ...(options.redirectUri === undefined ? {} : { redirectUri: options.redirectUri }),
    ...(options.authorizationParams === undefined ? {} : { authorizationParams: options.authorizationParams }),
    // Entra wants the scopes repeated on a refresh; without them it answers with
    // a token for the default resource rather than the one that was granted.
    tokenRefresh: { params: { scope: scopes.join(" ") } },
    userInfo,
    accountId: (info) => info.id
  }
}

/**
 * What Microsoft needs, per field, as `Config` values.
 *
 * @category models
 * @since 1.0.0
 */
export interface ConfigOptions {
  readonly clientId: Config.Config<string>
  readonly clientSecret?: Config.Config<Redacted.Redacted> | undefined
  readonly tenantId?: Config.Config<string> | undefined
  readonly authority?: Config.Config<string> | undefined
  readonly scopes?: Config.Config<ReadonlyArray<string>> | undefined
  readonly redirectUri?: Config.Config<string> | undefined
  readonly authorizationParams?: Readonly<Record<string, string>> | undefined
  readonly algorithms?: ReadonlyArray<string> | undefined
}

/** The settings {@link ConfigOptions} reads from the environment. */
interface Settings {
  readonly clientId: string
  readonly clientSecret: Redacted.Redacted | undefined
  readonly tenantId: string | undefined
  readonly authority: string | undefined
  readonly scopes: ReadonlyArray<string> | undefined
  readonly redirectUri: string | undefined
}

/**
 * Builds the Microsoft provider configuration, reading its credentials from
 * `Config`.
 *
 * **Gotchas**
 *
 * The secret must come from `Config.redacted`, so that it is a
 * `Redacted<string>` from the moment it leaves the environment and never
 * appears in a log line or a `ConfigError`. Leaving it out is legitimate — a
 * public PKCE client has none — rather than a missing setting.
 *
 * @category constructors
 * @since 1.0.0
 */
export const makeConfig = (options: ConfigOptions): Effect.Effect<OAuthProviderConfig, Config.ConfigError> =>
  Effect.map(
    Config.unwrap<Settings>({
      clientId: options.clientId,
      clientSecret: optionalConfig(options.clientSecret),
      tenantId: optionalConfig(options.tenantId),
      authority: optionalConfig(options.authority),
      scopes: optionalConfig(options.scopes),
      redirectUri: optionalConfig(options.redirectUri)
    }),
    (settings) =>
      make({
        ...settings,
        authorizationParams: options.authorizationParams,
        algorithms: options.algorithms
      })
  )
