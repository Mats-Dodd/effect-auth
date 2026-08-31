/**
 * The OAuth provider seam.
 *
 * A provider is data, not code: an authorization endpoint, a token endpoint, a
 * client id and secret, the scopes to ask for, and two small functions that
 * turn what the provider hands back into an identity. Everything else — state,
 * PKCE, the code exchange, `id_token` verification, account linking, the
 * session — is the generic runner in `Flow.ts`, which is why adding a provider
 * is a value in an array and not a plugin.
 *
 * **Details**
 *
 * Two fields carry the security weight of the whole module:
 *
 * - {@link OAuthProviderConfig.accountId} names the provider's *stable
 *   subject*. It is never an e-mail address: addresses change hands, subjects
 *   do not, and `(issuer, accountId)` is the only identity an existing account
 *   is matched on.
 * - {@link OAuthUserInfo.emailVerified} decides whether an identity may be
 *   attached to a local account that already holds the same address. A provider
 *   that cannot prove it verified an address must report `false`.
 *
 * @since 1.0.0
 */
import type { Cause, DateTime } from "effect"
import { Context, Duration, Effect, Layer, Option, Redacted, Schedule } from "effect"
import type { HttpClientError } from "effect/unstable/http"
import { HttpClient, HttpClientRequest as Request } from "effect/unstable/http"
import type { OAuthProviderError } from "../domain/Errors.js"
import { OAuthProviderError as ProviderError } from "../domain/Errors.js"
import { oauthIssuer } from "../domain/Schema.js"
import type { IdTokenClaims, KeyResolver } from "./IdToken.js"

// -----------------------------------------------------------------------------
// Tokens
// -----------------------------------------------------------------------------

/**
 * What a token endpoint handed back, normalized.
 *
 * **Gotchas**
 *
 * Every credential is `Redacted`: these values are bearer tokens for somebody
 * else's account and must not reach a log line. They are unwrapped exactly
 * once, when the account row is written.
 *
 * @category models
 * @since 1.0.0
 */
export interface OAuthTokens {
  /** The access token, for a `userInfo` call and for storage on the account. */
  readonly accessToken: Redacted.Redacted<string>
  /** The `token_type` the provider reported, normally `"bearer"`. */
  readonly tokenType: string | null
  /** The refresh token, when the provider issued one. */
  readonly refreshToken: Redacted.Redacted<string> | null
  /** The raw OIDC `id_token`, when the provider issued one. */
  readonly idToken: Redacted.Redacted<string> | null
  /**
   * The claims of a **verified** `id_token`.
   *
   * **Details**
   *
   * Populated by the flow only after `IdToken.verify` has checked the
   * signature, issuer, audience, expiry and nonce. A provider reading this may
   * therefore trust it; a provider reading {@link OAuthTokens.idToken} may not.
   */
  readonly idTokenClaims: IdTokenClaims | null
  readonly accessTokenExpiresAt: DateTime.Utc | null
  readonly refreshTokenExpiresAt: DateTime.Utc | null
  /** The scopes the provider actually granted, space separated. */
  readonly scope: string | null
}

// -----------------------------------------------------------------------------
// User info
// -----------------------------------------------------------------------------

/**
 * The identity a provider reports for the person who just authorized.
 *
 * @category models
 * @since 1.0.0
 */
export interface OAuthUserInfo {
  /**
   * The provider's stable subject — the OIDC `sub`, or GitHub's numeric user
   * id. {@link OAuthProviderConfig.accountId} projects it out of this object.
   */
  readonly id: string
  /** The address the provider reports for this person. */
  readonly email: string
  /**
   * Whether the provider states it has verified that address. `false` unless
   * the provider genuinely says otherwise — this gates implicit linking of the
   * identity onto an existing local account.
   */
  readonly emailVerified: boolean
  /** A display name for a user this flow provisions. */
  readonly name?: string | undefined
  /** An avatar URL for a user this flow provisions. */
  readonly image?: string | null | undefined
}

// -----------------------------------------------------------------------------
// Provider configuration
// -----------------------------------------------------------------------------

/**
 * Everything the generic OAuth runner needs to talk to one provider.
 *
 * @category models
 * @since 1.0.0
 */
export interface OAuthProviderConfig {
  /**
   * The id this provider is registered and addressed under: the `providerId` of
   * `POST /auth/sign-in/social`, the last segment of the callback path, the
   * entry in `AuthConfig.trustedProviders`.
   */
  readonly id: string
  /** The OAuth client id. Public by construction — it travels in a query string. */
  readonly clientId: string
  /**
   * The OAuth client secret, sent with `client_secret_post` on the token
   * request and nowhere else.
   */
  readonly clientSecret: Redacted.Redacted<string>
  /** The provider's authorization endpoint, where the browser is sent. */
  readonly authorizationUrl: string
  /** The provider's token endpoint, where the code is exchanged server-side. */
  readonly tokenUrl: string
  /** The scopes always requested. A caller may add more, never remove these. */
  readonly scopes: ReadonlyArray<string>
  /**
   * The provider's OIDC issuer URL.
   *
   * **Details**
   *
   * Presence of this field is what makes the provider an OIDC one: the flow
   * then *requires* an `id_token`, verifies it fail-closed, and stores the
   * account under this issuer. A plain OAuth2 provider leaves it undefined and
   * is stored under the synthetic `local:oauth:<id>` issuer.
   */
  readonly issuer?: string | undefined
  /** Where the provider publishes its signing keys. Required with `issuer`. */
  readonly jwksUrl?: string | undefined
  /**
   * A pre-resolved key set, used instead of fetching {@link jwksUrl}.
   *
   * **When to use**
   *
   * Pinning keys that are shipped with the application, and tests, which hand
   * in a `jose` `createLocalJWKSet` resolver so that verification runs with no
   * network at all.
   */
  readonly jwks?: KeyResolver | undefined
  /**
   * The JWS algorithms accepted on an `id_token`. Defaults to whatever the
   * resolved key admits, which for a JWKS is always asymmetric.
   */
  readonly algorithms?: ReadonlyArray<string> | undefined
  /**
   * Overrides the redirect URI, which otherwise is
   * `<baseUrl><basePath>/callback/<id>`.
   *
   * **Gotchas**
   *
   * It must match what is registered with the provider *exactly*, and it is
   * sent again on the token request, where the provider re-checks it.
   */
  readonly redirectUri?: string | undefined
  /**
   * Extra authorization-request parameters, such as Google's `access_type`.
   *
   * **Gotchas**
   *
   * Parameters the flow owns — `state`, `code_challenge`, `redirect_uri`,
   * `client_id`, `response_type`, `scope`, `nonce` — cannot be overridden here;
   * see {@link reservedAuthorizationParams}.
   */
  readonly authorizationParams?: Readonly<Record<string, string>> | undefined
  /**
   * Resolves the tokens into an identity, calling the provider's user-info
   * endpoints where it needs to.
   *
   * **Details**
   *
   * The `HttpClient` this receives from the context is the flow's own: it
   * refuses HTTP redirects, so a provider implementation cannot be talked into
   * following one to an internal address.
   */
  readonly userInfo: (
    tokens: OAuthTokens
  ) => Effect.Effect<OAuthUserInfo, OAuthProviderError, HttpClient.HttpClient>
  /**
   * Projects the provider's stable subject out of the identity. Never the
   * e-mail address.
   */
  readonly accountId: (info: OAuthUserInfo) => string
}

/**
 * The authorization-request parameters the flow sets itself, which
 * {@link OAuthProviderConfig.authorizationParams} may not overwrite.
 *
 * @category constructors
 * @since 1.0.0
 */
export const reservedAuthorizationParams: ReadonlySet<string> = new Set([
  "response_type",
  "client_id",
  "redirect_uri",
  "scope",
  "state",
  "code_challenge",
  "code_challenge_method",
  "nonce"
])

/**
 * Whether the provider publishes an OIDC issuer, and therefore whether the flow
 * demands and verifies an `id_token`.
 *
 * @category guards
 * @since 1.0.0
 */
export const isOidc = (
  provider: OAuthProviderConfig
): provider is OAuthProviderConfig & { readonly issuer: string } => provider.issuer !== undefined

/**
 * The issuer an account of this provider is stored under: the OIDC issuer URL,
 * or the synthetic `local:oauth:<id>` for a plain OAuth2 provider.
 *
 * @category combinators
 * @since 1.0.0
 */
export const providerIssuer = (provider: OAuthProviderConfig): string => provider.issuer ?? oauthIssuer(provider.id)

// -----------------------------------------------------------------------------
// Registry
// -----------------------------------------------------------------------------

/**
 * The {@link OAuthProviders} service definition: the providers this instance
 * serves, addressed by id.
 *
 * @category models
 * @since 1.0.0
 */
export interface OAuthProvidersService {
  /**
   * Resolves a provider id that came from a request path or body.
   *
   * Fails with `OAuthProviderError({ reason: "UnknownProvider" })` rather than
   * returning `undefined`, so an unregistered id can never fall through into
   * the flow.
   */
  readonly get: (id: string) => Effect.Effect<OAuthProviderConfig, OAuthProviderError>
  /** The same lookup as an `Option`, for callers that have their own answer. */
  readonly find: (id: string) => Option.Option<OAuthProviderConfig>
  /** Every registered id, in registration order. */
  readonly ids: ReadonlyArray<string>
}

/**
 * The providers this instance serves, addressed by id.
 *
 * @category services
 * @since 1.0.0
 */
export class OAuthProviders extends Context.Service<OAuthProviders, OAuthProvidersService>()(
  "effect-auth/OAuthProviders"
) {
  /**
   * Provides the registry over a fixed list of providers.
   *
   * **When to use**
   *
   * This is the only way an `OAuthProviders` is built. A provider is inert data
   * — `Github.make({...})`, `Google.make({...})` — so a deployment collects the
   * ones it serves into one array and hands them over here; an empty array is a
   * legitimate registry whose every lookup answers `UnknownProvider`.
   *
   * @category layers
   * @since 1.0.0
   */
  static readonly layer = (
    providers: ReadonlyArray<OAuthProviderConfig>
  ): Layer.Layer<OAuthProviders> => Layer.succeed(OAuthProviders)(makeRegistry(providers))
}

/**
 * Builds a registry over a list of providers.
 *
 * **Gotchas**
 *
 * Ids arrive from request paths, so the backing dictionary is null-prototyped
 * and every read goes through `Object.hasOwn`: a request for the provider
 * `"__proto__"` must miss, not return a function.
 *
 * Two providers with the same id are a configuration mistake; the last one
 * registered wins.
 *
 * @category constructors
 * @since 1.0.0
 */
export const makeRegistry = (
  providers: Iterable<OAuthProviderConfig>
): OAuthProvidersService => {
  const byId = Object.create(null) as Record<string, OAuthProviderConfig>
  const ids: Array<string> = []
  for (const provider of providers) {
    if (!Object.hasOwn(byId, provider.id)) ids.push(provider.id)
    byId[provider.id] = provider
  }
  const find = (id: string): Option.Option<OAuthProviderConfig> =>
    Object.hasOwn(byId, id) ? Option.some(byId[id]!) : Option.none()
  return OAuthProviders.of({
    find,
    get: (id) =>
      Option.match(find(id), {
        onNone: () => Effect.fail(new ProviderError({ providerId: id, reason: "UnknownProvider" })),
        onSome: (provider) => Effect.succeed(provider)
      }),
    ids
  })
}

/**
 * Builds an {@link OAuthProviderError} without reaching into `domain/Errors.js`
 * — the constructor a provider module uses for its own failures.
 *
 * @category errors
 * @since 1.0.0
 */
export const providerError = (providerId: string, reason: OAuthProviderError["reason"]): OAuthProviderError =>
  new ProviderError({ providerId, reason })

/**
 * Unwraps a `Redacted` credential for the one call that has to send it.
 *
 * @category combinators
 * @since 1.0.0
 */
export const revealToken = (token: Redacted.Redacted<string> | null): string | null =>
  token === null ? null : Redacted.value(token)

// -----------------------------------------------------------------------------
// Outbound resilience
// -----------------------------------------------------------------------------

/**
 * How long any single request to a provider is given.
 *
 * @category constructors
 * @since 1.0.0
 */
export const providerRequestTimeout: Duration.Duration = Duration.seconds(10)

/**
 * How many times a transport-level failure is tried again.
 *
 * @category constructors
 * @since 1.0.0
 */
export const providerRetryCount = 2

/**
 * Gives an outbound provider request a deadline and a couple of retries.
 *
 * **Details**
 *
 * Two failure modes, treated differently. A request that hangs is bounded by
 * {@link providerRequestTimeout} — without it a provider that accepts a
 * connection and never answers holds a callback fiber open for as long as the
 * runtime allows. A `TransportError` — DNS, a refused connection, a dropped
 * socket — is worth repeating with an exponential back-off. Usually that means
 * the request never reached the provider, but not always: a socket can die
 * after the request was transmitted, so a retried one-time authorization code
 * may already be burnt. That retry cannot double-issue anything — the provider
 * answers `invalid_grant`, the sign-in fails either way — it only changes
 * which error the failure is reported as.
 *
 * **Gotchas**
 *
 * Only `TransportError` is retried. A `4xx`/`5xx` answer, and the
 * `StatusCodeError` a refused redirect becomes, are the provider's considered
 * reply: repeating them would turn one refused callback into three requests and
 * one blocked redirect into three attempts at the same SSRF hop. A timeout is
 * not retried either — three deadlines in a row is a minute of a browser
 * waiting on a redirect.
 *
 * The back-off sleeps on the Effect clock, so a test that drives a transport
 * failure under `TestClock` must advance it.
 *
 * @category combinators
 * @since 1.0.0
 */
export const resilient = <A, R>(
  request: Effect.Effect<A, HttpClientError.HttpClientError, R>
): Effect.Effect<A, HttpClientError.HttpClientError | Cause.TimeoutError, R> =>
  request.pipe(
    Effect.timeout(providerRequestTimeout),
    Effect.retry({
      schedule: Schedule.exponential(Duration.millis(100)),
      while: (error) => error._tag === "HttpClientError" && error.reason._tag === "TransportError",
      times: providerRetryCount
    })
  )

// -----------------------------------------------------------------------------
// Talking to a user-info endpoint
// -----------------------------------------------------------------------------

/**
 * What a provider's user-info endpoint answered.
 *
 * @category models
 * @since 1.0.0
 */
export interface JsonResponse {
  readonly status: number
  /**
   * The decoded body, or `null` when the endpoint answered `4xx`/`5xx` or sent
   * something that is not JSON.
   *
   * **Gotchas**
   *
   * Every key in here is chosen by the provider. Read it with a `Schema`
   * decoder and never enumerate it.
   */
  readonly body: unknown
}

/**
 * A bearer-authenticated `GET` that yields JSON, for a provider's user-info
 * endpoints.
 *
 * **Details**
 *
 * The `HttpClient` comes from the context, which for anything the flow calls is
 * the redirect-refusing client — so a user-info endpoint cannot bounce the
 * request to an internal address.
 *
 * A non-2xx answer is *not* a failure here: it is reported as a status with a
 * `null` body, because a provider refusing one of several endpoints (GitHub's
 * `/user/emails` without the `user:email` scope) is a case the provider module
 * has to decide about, not a transport error.
 *
 * @category combinators
 * @since 1.0.0
 */
export const fetchJson = (options: {
  readonly providerId: string
  readonly url: string
  readonly accessToken: Redacted.Redacted<string>
  readonly headers?: Readonly<Record<string, string>> | undefined
}): Effect.Effect<JsonResponse, OAuthProviderError, HttpClient.HttpClient> =>
  Effect.gen(function*() {
    const client = yield* HttpClient.HttpClient
    const request = Request.get(options.url, {
      acceptJson: true,
      ...(options.headers === undefined ? {} : { headers: { ...options.headers } })
    }).pipe(Request.bearerToken(options.accessToken))
    const response = yield* Effect.mapError(
      resilient(client.execute(request)),
      () => new ProviderError({ providerId: options.providerId, reason: "ProviderUnavailable" })
    )
    if (response.status >= 400) return { status: response.status, body: null }
    // The body gets its own deadline: a provider that answers with headers and
    // then trickles bytes forever would otherwise hold the callback open.
    const body = yield* Effect.result(Effect.timeout(response.json, providerRequestTimeout))
    return { status: response.status, body: body._tag === "Success" ? body.success : null }
  })
