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
import { jsonWithin } from "./internal/http.js"

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
  readonly accessToken: Redacted.Redacted
  /** The `token_type` the provider reported, normally `"bearer"`. */
  readonly tokenType: string | null
  /** The refresh token, when the provider issued one. */
  readonly refreshToken: Redacted.Redacted | null
  /** The raw OIDC `id_token`, when the provider issued one. */
  readonly idToken: Redacted.Redacted | null
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
  /**
   * The issuer this *particular* identity belongs under, when the provider is a
   * multi-tenant one and the tenant is only known from the token.
   *
   * **When to use**
   *
   * Microsoft Entra, where one configured provider serves every tenant and the
   * account's identity is `(issuer, sub)` with the issuer derived from the
   * token's `tid`. A single-tenant provider leaves it undefined and its accounts
   * are stored under {@link providerIssuer}.
   *
   * **Gotchas**
   *
   * It becomes half of an account's primary identity, so it must come from a
   * **verified** `id_token` claim and never from a user-info body: an
   * attacker-chosen issuer would be an attacker-chosen account.
   */
  readonly issuer?: string | undefined
}

/**
 * What a provider's {@link OAuthProviderConfig.userInfo} is told about the
 * request that produced the tokens.
 *
 * @category models
 * @since 1.0.0
 */
export interface UserInfoOptions {
  /**
   * The extra parameters the provider sent back with the authorization code.
   *
   * **When to use**
   *
   * Apple, which posts a `user` field carrying the person's name — once, on the
   * very first authorization, and never again. A provider that needs nothing
   * from the callback ignores this.
   *
   * **Gotchas**
   *
   * Every value here is attacker-controllable: it arrived in a query string or a
   * form body, and no signature covers it. Read it with a `Schema` decoder, and
   * use it only for display fields a person can change anyway — never for an
   * identity, an address, or a verification flag.
   */
  readonly params?: Readonly<Record<string, string>> | undefined
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
   *
   * **Details**
   *
   * Three shapes, because three kinds of client exist. A confidential client
   * holds a fixed secret and passes the `Redacted` string. A client whose secret
   * is *minted* per request — Apple, whose secret is a short-lived ES256
   * assertion — passes an `Effect` that produces one, and it is run once per
   * token request. A **public** client omits it altogether: PKCE is what proves
   * the exchange, and a secret shipped inside a native or single-page
   * application would not be one.
   *
   * **Gotchas**
   *
   * Resolve it with {@link resolveClientSecret} rather than reading this field:
   * the three shapes are one `Option` there, and the effectful case has an error
   * channel a caller must not drop.
   */
  readonly clientSecret?: Redacted.Redacted | Effect.Effect<Redacted.Redacted, OAuthProviderError> | undefined
  /** The provider's authorization endpoint, where the browser is sent. */
  readonly authorizationUrl: string
  /** The provider's token endpoint, where the code is exchanged server-side. */
  readonly tokenUrl: string
  /** The scopes always requested. A caller may add more, never remove these. */
  readonly scopes: ReadonlyArray<string>
  /**
   * Everything that makes this provider an OIDC one, or nothing at all.
   *
   * **Details**
   *
   * Presence of this block is what makes the provider an OIDC one: the flow
   * then *requires* an `id_token`, verifies it fail-closed, and stores the
   * account under {@link OAuthProviderConfig.oidc}'s `issuer`. A plain OAuth2
   * provider leaves the whole block undefined and is stored under the synthetic
   * `local:oauth:<id>` issuer.
   *
   * The fields travel together because they are only meaningful together, and
   * `keys` is a union rather than two optional fields so that "an OIDC provider
   * with no key source" cannot be written down at all — where the prose once
   * said a JWKS URL was *required with* an issuer, the type now says it.
   *
   * **Gotchas**
   *
   * There is no partial OIDC: adding this block turns the `id_token` from
   * something the flow tolerates into something it demands.
   */
  readonly oidc?:
    | {
        /** The provider's OIDC issuer URL, and the issuer its accounts are stored under. */
        readonly issuer: string
        /**
         * The issuer an `id_token` must claim, derived from the token's own claims.
         *
         * **When to use**
         *
         * Multi-tenant providers, where the expected `iss` is not one string but a
         * function of the tenant the token names — Microsoft Entra derives it from
         * `tid`. Returning `null` rejects the token.
         *
         * **Gotchas**
         *
         * It runs on the token's payload **before** the signature has been checked
         * against that issuer, so it decides what to *expect*, never what to
         * believe. A provider that accepts any tenant must still constrain the
         * shape of the issuer it derives, or the check is not one; when it is
         * absent, the block's `issuer` is the expected value, as it is for every
         * single-tenant provider.
         */
        readonly issuerOf?: ((claims: Readonly<Record<string, unknown>>) => string | null) | undefined
        /**
         * Where the signing keys come from: a JWKS URL to fetch, or a key set
         * already resolved.
         *
         * **When to use**
         *
         * `jwksUrl` for every real provider. `jwks` for keys pinned into the
         * application, and for tests, which hand in a `jose` `createLocalJWKSet`
         * resolver so that verification runs with no network at all.
         */
        readonly keys: { readonly jwksUrl: string } | { readonly jwks: KeyResolver }
        /**
         * The audience an `id_token` must carry, when it is not simply
         * {@link OAuthProviderConfig.clientId}.
         *
         * **When to use**
         *
         * Where one deployment accepts tokens minted for more than one client —
         * Apple, whose native applications receive tokens addressed to the app's
         * bundle identifier rather than to the web Services ID.
         *
         * **Gotchas**
         *
         * A list is a list of *permitted* audiences, not a requirement that all be
         * present. Keep it as short as the deployment genuinely needs: every entry
         * is another client whose tokens are accepted here.
         */
        readonly audience?: string | ReadonlyArray<string> | undefined
        /**
         * The JWS algorithms accepted on an `id_token`. Defaults to whatever the
         * resolved key admits, which for a JWKS is always asymmetric.
         */
        readonly algorithms?: ReadonlyArray<string> | undefined
      }
    | undefined
  /**
   * Whether, and how, this provider's stored tokens may be refreshed.
   *
   * **Details**
   *
   * Absent means refreshing is allowed with no extra parameters, which is what
   * the specification describes. Set `enabled: false` for a provider whose
   * refresh tokens this deployment must not spend, and `params` for one that
   * requires more than `grant_type` and `refresh_token` on the request —
   * Microsoft wants the `scope` repeated.
   *
   * **Gotchas**
   *
   * Parameters the flow owns cannot be overridden here; see
   * {@link reservedTokenParams}.
   */
  readonly tokenRefresh?:
    | {
        readonly enabled?: boolean | undefined
        readonly params?: Readonly<Record<string, string>> | undefined
      }
    | undefined
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
   * Takes over the authorization-code exchange, for the provider the generic
   * token request cannot describe.
   *
   * **Details**
   *
   * Absent — the ordinary case — means the generic runner performs the exchange
   * itself. Present means this function owns it: nothing else posts the code.
   *
   * It is handed the generic request as `fallback`, already built for these
   * exact inputs, because most overrides only *decorate* the default. A
   * provider that needs one extra header, or that has to post-process the
   * tokens it gets back, wraps `fallback` rather than reimplementing the
   * exchange — and so keeps secret resolution
   * ({@link resolveClientSecret}, including the per-request minting an Apple
   * client needs) and {@link reservedTokenParams} filtering, both of which stay
   * private to the flow.
   *
   * **Gotchas**
   *
   * An implementation that ignores `fallback` and builds its own request owns
   * everything the flow was doing for it, secret handling included. Reach for
   * that only when the provider's exchange genuinely is not an OAuth2 token
   * request.
   */
  readonly exchange?:
    | ((options: {
        readonly code: string
        readonly codeVerifier: string
        readonly redirectUri: string
        /** The generic token request for these inputs, for overrides that only decorate it. */
        readonly fallback: Effect.Effect<OAuthTokens, OAuthProviderError>
      }) => Effect.Effect<OAuthTokens, OAuthProviderError, HttpClient.HttpClient>)
    | undefined
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
    tokens: OAuthTokens,
    options?: UserInfoOptions
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
 * The token-request parameters the flow sets itself, which
 * {@link OAuthProviderConfig.tokenRefresh}'s `params` may not overwrite.
 *
 * @category constructors
 * @since 1.0.0
 */
export const reservedTokenParams: ReadonlySet<string> = new Set([
  "grant_type",
  "code",
  "code_verifier",
  "refresh_token",
  "redirect_uri",
  "client_id",
  "client_secret"
])

/**
 * Resolves a provider's client secret: absent for a public PKCE client, a fixed
 * value for a confidential one, freshly minted for a provider that signs its
 * own.
 *
 * **Gotchas**
 *
 * Run this once per token request, not once per layer. The effectful case exists
 * because the secret *expires* — Apple's is a JWT with an `exp` — so caching it
 * across a deployment's lifetime is exactly what it must not do.
 *
 * @category combinators
 * @since 1.0.0
 */
export const resolveClientSecret = (
  provider: OAuthProviderConfig
): Effect.Effect<Option.Option<Redacted.Redacted>, OAuthProviderError> => {
  const secret = provider.clientSecret
  if (secret === undefined) return Effect.succeedNone
  return Redacted.isRedacted(secret) ? Effect.succeedSome(secret) : Effect.map(secret, Option.some)
}

/**
 * Whether the provider carries an OIDC block, and therefore whether the flow
 * demands and verifies an `id_token`.
 *
 * **Details**
 *
 * The narrowed type has `oidc` as a **required** field, so a caller past this
 * guard reads the issuer and the key source without a second check — which is
 * the whole reason the OIDC settings live in one block.
 *
 * @category guards
 * @since 1.0.0
 */
export const isOidc = (
  provider: OAuthProviderConfig
): provider is OAuthProviderConfig & { readonly oidc: NonNullable<OAuthProviderConfig["oidc"]> } =>
  provider.oidc !== undefined

/**
 * The issuer an account of this provider is stored under: the OIDC issuer URL,
 * or the synthetic `local:oauth:<id>` for a plain OAuth2 provider.
 *
 * @category combinators
 * @since 1.0.0
 */
export const providerIssuer = (provider: OAuthProviderConfig): string =>
  provider.oidc?.issuer ?? oauthIssuer(provider.id)

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
  "effect-auth/oauth/Provider/OAuthProviders"
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
  static readonly layer = (providers: ReadonlyArray<OAuthProviderConfig>): Layer.Layer<OAuthProviders> =>
    Layer.succeed(OAuthProviders)(makeRegistry(providers))
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
 * Two providers with the same id throw. A duplicate id is a deployment that
 * cannot be served coherently — one of the two would silently never receive a
 * callback — so it is a construction-time defect, not a last-one-wins merge.
 * Building {@link OAuthProviders.layer} over such a list therefore fails loudly
 * at start-up, rather than starting a deployment in which one provider quietly
 * stopped working.
 *
 * @category constructors
 * @since 1.0.0
 */
export const makeRegistry = (providers: Iterable<OAuthProviderConfig>): OAuthProvidersService => {
  const byId: Record<string, OAuthProviderConfig> = Object.create(null)
  const ids: Array<string> = []
  for (const provider of providers) {
    if (Object.hasOwn(byId, provider.id)) {
      throw new Error(`effect-auth: duplicate OAuth provider id ${JSON.stringify(provider.id)}`)
    }
    ids.push(provider.id)
    byId[provider.id] = provider
  }
  const find = (id: string): Option.Option<OAuthProviderConfig> =>
    Object.hasOwn(byId, id) ? Option.some(byId[id]!) : Option.none()
  return OAuthProviders.of({
    find,
    get: (id) =>
      Option.match(find(id), {
        onNone: () => Effect.fail(ProviderError.make({ providerId: id, reason: "UnknownProvider" })),
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
  ProviderError.make({ providerId, reason })

/**
 * Unwraps a `Redacted` credential for the one call that has to send it.
 *
 * @category combinators
 * @since 1.0.0
 */
export const revealToken = (token: Redacted.Redacted | null): string | null =>
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
 * How long one whole {@link OAuthProviderConfig.userInfo} invocation is given,
 * however many requests it makes inside.
 *
 * **Details**
 *
 * The split is deliberate: the flow owns *policy*, the helpers own *mechanics*.
 * {@link fetchJson} bounds a single request with
 * {@link providerRequestTimeout} and retries transport failures, because that is
 * what one request needs; this deadline sits above the provider's entire
 * `userInfo` and answers a different question — how long a callback fiber may be
 * held at all. GitHub asking two endpoints in sequence, each near its own
 * timeout, is still bounded by this one.
 *
 * **Gotchas**
 *
 * It is enforced by the flow rather than by the helper on purpose. A provider
 * implementation is free to bypass {@link fetchJson} and use the `HttpClient`
 * directly, and one that does must still not be able to hang a callback — so
 * the bound lives where it cannot be opted out of.
 *
 * @category constructors
 * @since 1.0.0
 */
export const userInfoDeadline: Duration.Duration = Duration.seconds(30)

/**
 * How long one whole code exchange is given, an
 * {@link OAuthProviderConfig.exchange} override included.
 *
 * **Details**
 *
 * The same rule as {@link userInfoDeadline}, one step earlier in the callback.
 * The generic exchange is a single {@link resilient} request and is bounded
 * already; this deadline is for an override that ignores the `fallback` it is
 * handed and drives the `HttpClient` itself, which nothing else bounds. A
 * provider that accepts a connection and never answers must not be able to hold
 * a callback fiber whichever side of the seam it does it from.
 *
 * **Gotchas**
 *
 * Enforced by the flow around the override and the default alike, for the
 * reason {@link userInfoDeadline} is: a bound an implementation can opt out of
 * is not a bound. A default exchange pushed to its full retry budget — three
 * attempts and their back-off — can reach this deadline just before the
 * provider's own answer; both report `ProviderUnavailable`, so which one wins
 * that race is not observable.
 *
 * @category constructors
 * @since 1.0.0
 */
export const exchangeDeadline: Duration.Duration = Duration.seconds(30)

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
  readonly accessToken: Redacted.Redacted
  readonly headers?: Readonly<Record<string, string>> | undefined
}): Effect.Effect<JsonResponse, OAuthProviderError, HttpClient.HttpClient> =>
  Effect.gen(function* () {
    const client = yield* HttpClient.HttpClient
    const request = Request.get(options.url, {
      acceptJson: true,
      ...(options.headers === undefined ? {} : { headers: { ...options.headers } })
    }).pipe(Request.bearerToken(options.accessToken))
    const response = yield* Effect.mapError(resilient(client.execute(request)), () =>
      ProviderError.make({ providerId: options.providerId, reason: "ProviderUnavailable" })
    )
    if (response.status >= 400) return { status: response.status, body: null }
    const body = yield* Effect.result(jsonWithin(response, providerRequestTimeout))
    return { status: response.status, body: body._tag === "Success" ? body.success : null }
  })
