/**
 * The generic OAuth 2.0 / OIDC runner.
 *
 * Every provider goes through exactly this code. `start` mints the single-use
 * state and the PKCE challenge and builds the authorization URL; `callback`
 * claims that state atomically, exchanges the authorization code, verifies an
 * `id_token` when the provider is an OIDC one, resolves the identity through
 * `Accounts` and establishes a session. A provider module contributes
 * endpoints, scopes and a `userInfo` function, and nothing else.
 *
 * **Details**
 *
 * The security decisions all live here rather than in the providers, which is
 * the point of the split:
 *
 * - PKCE is always `S256`. There is no `plain` fallback and no way to turn it
 *   off.
 * - State is a random token stored hashed, consumed by a single
 *   `DELETE ... RETURNING`, and bound to the provider it was minted for.
 * - The token and user-info requests **refuse HTTP redirects**. A provider
 *   endpoint that answers `302` is an SSRF primitive — it can point a
 *   server-side request carrying the client secret at an internal address — so
 *   the redirect is never followed and the exchange fails instead.
 * - Every outbound request carries a deadline, and only a connection that was
 *   never made is retried — see `Provider.resilient`. A provider that accepts a
 *   connection and never answers must not hold a callback fiber open.
 * - An OIDC provider *must* return an `id_token`, and it is verified
 *   fail-closed before any claim in it is read. Its signing keys are fetched
 *   over the same redirect-refusing client and cached by `IdToken.Jwks`.
 * - Every redirect target the flow will send a browser to is validated against
 *   `trustedOrigins` when the flow *starts*, not when it finishes.
 *
 * **Gotchas**
 *
 * The session a successful callback mints is created *after* the transaction
 * that wrote the user and the account, not inside it — the password sign-up
 * path is built the same way. A storage failure in that window leaves a user
 * with a linked identity and no session, which the next attempt resolves as an
 * ordinary sign-in (branch 1 of the linking algorithm), so the window is
 * recoverable rather than corrupting. Closing it would mean threading a session
 * factory through `Accounts`, coupling identity resolution to session
 * lifetime. See the amendment note in `SPEC.md`.
 *
 * @since 1.0.0
 */
import { Array, Context, DateTime, Duration, Effect, Layer, Option, Redacted, Schema } from "effect"
import { FetchHttpClient, HttpBody, HttpClient, HttpClientError, HttpClientRequest } from "effect/unstable/http"
import type { AuthConfigService } from "../config/AuthConfig.js"
import { AuthConfig } from "../config/AuthConfig.js"
import { Token } from "../crypto/Token.js"
import type { OAuthIdentity } from "../domain/Accounts.js"
import { Accounts } from "../domain/Accounts.js"
import type { AccountAlreadyLinked, OAuthProviderError, UserNotFound } from "../domain/Errors.js"
import { NotFound, OAuthStateMismatch, TokenRefreshFailed } from "../domain/Errors.js"
import { AuthEvents, oauthMethod, publishSafely } from "../domain/Events.js"
import type { PolicyRefused, ProvisionSource } from "../domain/Hooks.js"
import { AuthHooks } from "../domain/Hooks.js"
import type { Account, AccountId, Session, User, UserId } from "../domain/Schema.js"
import { scopesOf } from "../domain/Schema.js"
import { Sessions } from "../domain/Sessions.js"
import type { AccountTokens, PersistenceError } from "../domain/Stores.js"
import { AccountStore, VerificationStore } from "../domain/Stores.js"
import { policyRefusedTarget, resolveUrl, withErrorCode } from "../http/OriginCheck.js"
import type { IdTokenClaims, KeyResolver } from "./IdToken.js"
import { isRedirectResponse, Jwks, layerJwks, verify as verifyIdToken } from "./IdToken.js"
import type { OAuthProviderConfig, OAuthTokens } from "./Provider.js"
import {
  isOidc,
  OAuthProviders,
  providerError,
  providerIssuer,
  providerRequestTimeout,
  reservedAuthorizationParams,
  reservedTokenParams,
  resilient,
  resolveClientSecret,
  revealToken
} from "./Provider.js"
import type { IssueOptions, StatePayload } from "./State.js"
import { codeChallengeMethod, consume as consumeState, issue as issueState } from "./State.js"
import { lenient, Seconds } from "./internal/claims.js"

// -----------------------------------------------------------------------------
// Refusing redirects
// -----------------------------------------------------------------------------

const manualRedirect: globalThis.RequestInit = { redirect: "manual" }

/**
 * Wraps an `HttpClient` so that it never follows an HTTP redirect.
 *
 * **Details**
 *
 * Two locks, because one is not portable. The request is made with
 * `redirect: "manual"` — which stops the platform `fetch` from following the
 * hop at all — and the resolved response is then checked with
 * {@link isRedirectResponse}, which catches both the real `3xx` a Node runtime
 * reports and the opaque `status: 0` filtered response a spec-compliant runtime
 * hands back. A redirect fails the request as an `HttpClientError`.
 *
 * **Gotchas**
 *
 * The error stays an `HttpClientError` on purpose: the result is still an
 * ordinary `HttpClient`, so it can be provided to a provider's `userInfo`,
 * which is written against the plain service. The flow maps it to
 * `OAuthProviderError` at its own boundary.
 *
 * `redirect: "manual"` is delivered through `FetchHttpClient.RequestInit`, so a
 * client that is not fetch-backed only gets the second lock — it will not
 * *return* a redirect, but it may have followed one internally. Configure such
 * a client not to follow redirects, or use the fetch client.
 *
 * @category combinators
 * @since 1.0.0
 */
export const refuseRedirects = (client: HttpClient.HttpClient): HttpClient.HttpClient =>
  HttpClient.transformResponse(client, (effect) =>
    effect.pipe(
      Effect.provideService(FetchHttpClient.RequestInit, manualRedirect),
      Effect.flatMap((response) =>
        isRedirectResponse(response)
          ? Effect.fail(
            new HttpClientError.HttpClientError({
              reason: new HttpClientError.StatusCodeError({
                request: response.request,
                response,
                description: "effect-auth refuses HTTP redirects on OAuth requests"
              })
            })
          )
          : Effect.succeed(response)
      )
    ))

/**
 * {@link refuseRedirects} as a layer over the ambient `HttpClient`.
 *
 * **When to use**
 *
 * Providing anything that talks to a provider — the flow itself, and the
 * {@link Jwks} key sets it verifies `id_token`s against. It is what makes a
 * `jwks_uri` that answers `302` a failure rather than an SSRF primitive.
 *
 * @category layers
 * @since 1.0.0
 */
export const layerSafeClient: Layer.Layer<HttpClient.HttpClient, never, HttpClient.HttpClient> = Layer.effect(
  HttpClient.HttpClient,
  Effect.gen(function*() {
    return refuseRedirects(yield* HttpClient.HttpClient)
  })
)

// -----------------------------------------------------------------------------
// URLs
// -----------------------------------------------------------------------------

const joinUrl = (baseUrl: string, path: string): string => `${baseUrl.replace(/\/+$/, "")}${path}`

/**
 * The redirect URI this deployment serves for a provider:
 * `<baseUrl><basePath>/callback/<id>`, unless the provider overrides it.
 *
 * **Gotchas**
 *
 * It is sent twice — on the authorization request and again on the token
 * request — and the provider compares both against what is registered with it.
 * A mismatch is the single most common cause of a `TokenExchangeFailed`.
 *
 * @category combinators
 * @since 1.0.0
 */
export const callbackUri = (config: AuthConfigService, provider: OAuthProviderConfig): string =>
  provider.redirectUri ?? joinUrl(config.baseUrl, `${config.basePath}/callback/${encodeURIComponent(provider.id)}`)

/**
 * The scopes actually requested: the provider's own, plus whatever the caller
 * asked for, in order and without repeats.
 *
 * @category combinators
 * @since 1.0.0
 */
export const mergeScopes = (
  provider: OAuthProviderConfig,
  extra: ReadonlyArray<string> | undefined
): ReadonlyArray<string> =>
  Array.dedupe([...provider.scopes, ...(extra ?? [])].filter((scope) => scope.length > 0))

/**
 * Builds the authorization URL the browser is sent to.
 *
 * **Gotchas**
 *
 * A provider's `authorizationParams` are written first and the flow's own
 * parameters second, so a configuration that tries to set `state`,
 * `redirect_uri` or `code_challenge` cannot win — and
 * {@link reservedAuthorizationParams} drops those keys before they are even
 * written.
 *
 * @category combinators
 * @since 1.0.0
 */
export const authorizationUrl = (options: {
  readonly provider: OAuthProviderConfig
  readonly redirectUri: string
  readonly state: string
  readonly codeChallenge: string
  readonly nonce: string | null
  readonly scopes: ReadonlyArray<string>
}): string => {
  const url = new URL(options.provider.authorizationUrl)
  const extra = options.provider.authorizationParams
  if (extra !== undefined) {
    for (const [key, value] of Object.entries(extra)) {
      if (reservedAuthorizationParams.has(key)) continue
      url.searchParams.set(key, value)
    }
  }
  url.searchParams.set("response_type", "code")
  url.searchParams.set("client_id", options.provider.clientId)
  url.searchParams.set("redirect_uri", options.redirectUri)
  url.searchParams.set("scope", options.scopes.join(" "))
  url.searchParams.set("state", options.state)
  url.searchParams.set("code_challenge", options.codeChallenge)
  url.searchParams.set("code_challenge_method", codeChallengeMethod)
  if (options.nonce !== null) url.searchParams.set("nonce", options.nonce)
  return url.toString()
}

// -----------------------------------------------------------------------------
// Reading a provider's JSON
// -----------------------------------------------------------------------------

/**
 * What a token endpoint is believed to have said.
 *
 * **Gotchas**
 *
 * `access_token` is the only required field, and its absence is also how an
 * OAuth error body (`{"error":"invalid_grant"}`) is detected. The provider's own
 * message is deliberately not modelled: it routinely echoes the authorization
 * code and, on some providers, the client secret.
 *
 * Every other field is advisory, so a provider that spells one badly loses that
 * field rather than the sign-in. The keys are the provider's, and `Schema.Struct`
 * reads own properties only: a body carrying `__proto__` or `constructor` reads
 * as absent, not as a function.
 */
const TokenResponse = Schema.Struct({
  access_token: Schema.NonEmptyString,
  token_type: lenient(Schema.NonEmptyString),
  refresh_token: lenient(Schema.NonEmptyString),
  id_token: lenient(Schema.NonEmptyString),
  expires_in: lenient(Seconds),
  refresh_token_expires_in: lenient(Seconds),
  scope: lenient(Schema.NonEmptyString)
})

const readTokenResponse = Schema.decodeUnknownOption(TokenResponse)

/**
 * Normalizes a token endpoint's JSON body.
 *
 * **Details**
 *
 * Answers `null` when the body is not an object or carries no `access_token`.
 *
 * @category combinators
 * @since 1.0.0
 */
export const decodeTokens = (body: unknown, now: DateTime.Utc): OAuthTokens | null =>
  Option.match(readTokenResponse(body), {
    onNone: () => null,
    onSome: (fields) => ({
      accessToken: Redacted.make(fields.access_token),
      tokenType: fields.token_type ?? null,
      refreshToken: fields.refresh_token === undefined ? null : Redacted.make(fields.refresh_token),
      idToken: fields.id_token === undefined ? null : Redacted.make(fields.id_token),
      idTokenClaims: null,
      accessTokenExpiresAt: fields.expires_in === undefined ? null : addSeconds(now, fields.expires_in),
      refreshTokenExpiresAt: fields.refresh_token_expires_in === undefined
        ? null
        : addSeconds(now, fields.refresh_token_expires_in),
      scope: fields.scope ?? null
    })
  })

const addSeconds = (now: DateTime.Utc, seconds: number): DateTime.Utc =>
  DateTime.addDuration(now, Duration.seconds(Math.max(0, Math.trunc(seconds))))

/**
 * How one caller of the token endpoint reports its three failure modes.
 *
 * **Details**
 *
 * The code exchange and the refresh are the same HTTP request and fail in the
 * same three ways — the client secret could not be produced, the provider could
 * not be reached, the provider answered and refused — but they are different
 * errors to the caller. The mapping travels with the request.
 */
interface TokenFailures<E> {
  /** The provider's client secret could not be resolved. */
  readonly secret: (error: OAuthProviderError) => E
  /** The request never got an answer: transport, timeout, or a refused redirect. */
  readonly unavailable: () => E
  /** The provider answered with an error status, or with no usable token. */
  readonly rejected: () => E
}

// -----------------------------------------------------------------------------
// Models
// -----------------------------------------------------------------------------

/**
 * What starting a flow needs.
 *
 * @category models
 * @since 1.0.0
 */
export interface StartOptions {
  readonly providerId: string
  /** Where to land after a successful callback. Validated here, not later. */
  readonly callbackURL?: string | null | undefined
  /** Where to land when the callback fails. Validated here too. */
  readonly errorCallbackURL?: string | null | undefined
  /** Scopes to request on top of the provider's configured set. */
  readonly scopes?: ReadonlyArray<string> | undefined
  readonly rememberMe?: boolean | undefined
  /**
   * Set for `POST /auth/link-social`: the already signed-in user this identity
   * will be attached to. The callback then links instead of signing anybody in,
   * and creates no session.
   */
  readonly linkUserId?: User["id"] | null | undefined
}

/**
 * A started flow.
 *
 * @category models
 * @since 1.0.0
 */
export interface StartResult {
  readonly providerId: string
  /** The authorization URL, carrying `state` and the S256 `code_challenge`. */
  readonly url: string
  /** The raw state value. Only its digest was stored. */
  readonly state: Redacted.Redacted<string>
  /** When the pending request stops being redeemable. */
  readonly expiresAt: DateTime.Utc
}

/**
 * What came back from the provider.
 *
 * @category models
 * @since 1.0.0
 */
export interface CallbackOptions {
  readonly providerId: string
  readonly code?: string | undefined
  readonly state?: string | undefined
  /** The provider's `error` query parameter, when it refused. */
  readonly error?: string | undefined
  /**
   * Whatever else the provider sent back with the code, forwarded to the
   * provider's `userInfo`.
   *
   * **Gotchas**
   *
   * Unsigned, attacker-controllable input — see `UserInfoOptions.params`. It is
   * carried, not trusted.
   */
  readonly params?: Readonly<Record<string, string>> | undefined
  readonly ipAddress?: string | null | undefined
  readonly userAgent?: string | null | undefined
}

/**
 * Which of a user's linked accounts a token operation addresses.
 *
 * **Gotchas**
 *
 * `userId` comes from the session, `accountId` from the request, and the store
 * matches on both in one statement — so naming somebody else's account is a
 * `NotFound`, indistinguishable from naming one that does not exist.
 *
 * @category models
 * @since 1.0.0
 */
export interface TokenSelector {
  readonly userId: UserId
  readonly accountId: AccountId
}

/**
 * A usable access token for one linked account.
 *
 * **Gotchas**
 *
 * `accessToken` and `idToken` are `Redacted`: they are bearer credentials for
 * somebody's account *at the provider*, so they must reach a response body and
 * nothing else — never a log line, never a span attribute.
 *
 * @category models
 * @since 1.0.0
 */
export interface AccessTokenResult {
  readonly accessToken: Redacted.Redacted<string>
  readonly accessTokenExpiresAt: DateTime.Utc | null
  readonly idToken: Redacted.Redacted<string> | null
  /** The granted scopes, split out of the stored `scope` column. */
  readonly scopes: ReadonlyArray<string>
  readonly providerId: string
  readonly accountId: AccountId
}

/**
 * {@link AccessTokenResult} together with the refresh token that produced it.
 *
 * **Details**
 *
 * A provider that rotates refresh tokens returns a new one and the old one stops
 * working; a provider that does not returns none, and the stored one is kept. In
 * both cases this carries the refresh token the account now holds.
 *
 * @category models
 * @since 1.0.0
 */
export interface RefreshedTokens extends AccessTokenResult {
  readonly refreshToken: Redacted.Redacted<string>
  readonly refreshTokenExpiresAt: DateTime.Utc | null
}

/**
 * A completed callback.
 *
 * **Gotchas**
 *
 * `session` and `token` are `null` for a link flow (`linkUserId` was set when
 * the flow started): the person was already signed in, and minting a second
 * session for them would be a silent session upgrade. The HTTP layer sets a
 * cookie exactly when `token` is not `null`.
 *
 * @category models
 * @since 1.0.0
 */
export interface CallbackResult {
  readonly providerId: string
  readonly user: User
  readonly account: Account
  readonly session: Session | null
  readonly token: Redacted.Redacted<string> | null
  /** The validated URL the browser is to be sent to. */
  readonly redirectTo: string
  readonly userCreated: boolean
  readonly accountCreated: boolean
  /** `true` when this callback attached an identity to a signed-in user. */
  readonly linked: boolean
  /**
   * What the caller asked for when the flow *started*, carried through the
   * state row.
   *
   * **Details**
   *
   * It shortens the session's own lifetime (`Sessions.create`), and it decides
   * whether the cookie the HTTP layer writes carries a `Max-Age` at all —
   * `false` means a browser-session cookie, exactly as on the password path.
   * Always `true` for a link flow, which mints no session.
   */
  readonly rememberMe: boolean
}

/**
 * Everything {@link OAuthFlow.callback} can fail with, apart from persistence.
 *
 * @category models
 * @since 1.0.0
 */
export type CallbackError =
  | OAuthStateMismatch
  | OAuthProviderError
  | AccountAlreadyLinked
  | PolicyRefused
  | UserNotFound

/**
 * The outcome of a callback that always resolves to somewhere to send the
 * browser.
 *
 * @category models
 * @since 1.0.0
 */
export type CallbackOutcome =
  | ({ readonly _tag: "Success" } & CallbackResult)
  | {
    readonly _tag: "Failure"
    readonly error: CallbackError
    /**
     * The validated error URL, carrying `?error=<code>` — and, when a
     * deployment's own hook was what refused, `&code=<the hook's code>` beside
     * it.
     */
    readonly redirectTo: string
    /** The safe, closed-set error code that was appended. */
    readonly code: string
  }

/**
 * The safe error code a failed callback reports in the redirect's query string.
 *
 * **Details**
 *
 * A closed set. A provider's own error text is never echoed: it routinely
 * contains the authorization code, and describing precisely which check failed
 * only helps somebody probing the callback.
 *
 * @category combinators
 * @since 1.0.0
 */
export const errorCode = (error: CallbackError): string => {
  switch (error._tag) {
    case "OAuthStateMismatch":
      return "state_mismatch"
    case "AccountAlreadyLinked":
      return "account_already_linked"
    // A deployment's own hook declining the provisioning, the link or the
    // session. The hook's own `code` names which rule it was; this is only the
    // classification, and it is this library's, exactly as the others are.
    case "PolicyRefused":
      return "policy_refused"
    case "UserNotFound":
      return "user_not_found"
    case "OAuthProviderError":
      return snakeCase(error.reason)
  }
}

const snakeCase = (value: string): string => value.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase()

// -----------------------------------------------------------------------------
// Service
// -----------------------------------------------------------------------------

/**
 * The {@link OAuthFlow} service definition.
 *
 * @category models
 * @since 1.0.0
 */
export interface OAuthFlowService {
  /**
   * Mints state and PKCE and answers with the provider's authorization URL.
   *
   * Fails `OAuthProviderError({ reason: "UnknownProvider" })` for an id this
   * instance does not serve.
   */
  readonly start: (
    options: StartOptions
  ) => Effect.Effect<StartResult, OAuthProviderError | PersistenceError>

  /**
   * Completes a callback: consumes the state, exchanges the code, verifies an
   * `id_token` where there is one, links the identity and creates the session.
   *
   * A deployment's hooks are consulted along the way — on the user this
   * provisions, on the identity it attaches to an existing account, and on the
   * session it is about to mint — so `PolicyRefused` is one of the failures,
   * carrying the code whichever rule refused named itself with.
   */
  readonly callback: (
    options: CallbackOptions
  ) => Effect.Effect<CallbackResult, CallbackError | PersistenceError>

  /**
   * `callback`, but resolving a failure into a redirect rather than an error.
   *
   * **When to use**
   *
   * This is what the HTTP callback endpoint calls. The browser arrived by a
   * top-level navigation from the provider and must leave by one whatever
   * happened, so a failure becomes a `302` to the validated `errorCallbackURL`
   * with a safe `?error=` code rather than an error page.
   */
  readonly complete: (
    options: CallbackOptions
  ) => Effect.Effect<CallbackOutcome, PersistenceError>

  /**
   * A usable access token for one of the caller's linked accounts, refreshing it
   * first only if it has to.
   *
   * **Details**
   *
   * "Has to" means: the stored access token is within
   * {@link accessTokenSkew} of expiring (or already past it), the account has a
   * refresh token, and the provider permits refreshing. Otherwise the stored
   * token is handed back untouched — this endpoint is on an application's hot
   * path, and spending a refresh token per call would both cost a round trip and,
   * on a provider that rotates them, race with itself.
   *
   * **Gotchas**
   *
   * An account with no access token and no way to get one is
   * `TokenRefreshFailed({ reason: "AccessTokenMissing" })`, not a `null` success:
   * the caller asked for a credential and there is none.
   */
  readonly accessToken: (
    selector: TokenSelector
  ) => Effect.Effect<AccessTokenResult, NotFound | TokenRefreshFailed | PersistenceError>

  /**
   * Spends an account's refresh token, unconditionally, and stores what comes
   * back.
   *
   * **When to use**
   *
   * Where the caller knows the stored access token is no good — a provider
   * answered `401` with it — and {@link OAuthFlowService.accessToken}'s expiry
   * arithmetic therefore says the wrong thing. Ordinary callers want
   * `accessToken`.
   *
   * **Gotchas**
   *
   * The granted `scope` is never overwritten by a refresh: providers routinely
   * omit it from a refresh response, and taking that as "no scopes" would erase
   * what the person actually consented to.
   *
   * Emits `TokensRefreshed`.
   */
  readonly refreshTokens: (
    selector: TokenSelector
  ) => Effect.Effect<RefreshedTokens, NotFound | TokenRefreshFailed | PersistenceError>
}

/**
 * How close to expiry a stored access token has to be before
 * {@link OAuthFlowService.accessToken} refreshes it.
 *
 * **Details**
 *
 * Small on purpose. It is not a safety margin for the caller's own request — a
 * token handed over with four seconds left is a token that will fail — but the
 * width of the window in which *this* process might race its own clock against
 * the provider's. A generous margin would refresh far more often than necessary,
 * and on a provider that rotates refresh tokens every refresh is a write.
 *
 * @category constructors
 * @since 1.0.0
 */
export const accessTokenSkew: Duration.Duration = Duration.seconds(5)

/**
 * The OAuth runner.
 *
 * @category services
 * @since 1.0.0
 */
export class OAuthFlow extends Context.Service<OAuthFlow, OAuthFlowService>()("effect-auth/OAuthFlow") {}

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

/**
 * Builds the {@link OAuthFlow} implementation.
 *
 * @category constructors
 * @since 1.0.0
 */
export const make: () => Effect.Effect<
  OAuthFlowService,
  never,
  | AuthConfig
  | OAuthProviders
  | Token
  | VerificationStore
  | Accounts
  | AccountStore
  | Sessions
  | AuthEvents
  | Jwks
  | HttpClient.HttpClient
> = Effect.fnUntraced(function*() {
  const config = yield* AuthConfig
  const registry = yield* OAuthProviders
  const accounts = yield* Accounts
  const accountStore = yield* AccountStore
  const sessions = yield* Sessions
  const events = yield* AuthEvents
  const keySets = yield* Jwks
  const client = refuseRedirects(yield* HttpClient.HttpClient)
  // A `Context.Reference` with a no-op default, so a deployment that installs
  // nothing provides nothing — and, being read here, the set is fixed when the
  // layer is built rather than looked up on every callback.
  const hooks = yield* AuthHooks

  // `State` reads its services from the context. Capturing them once, when the
  // layer is built, keeps them out of every method's requirements.
  const stateServices = yield* Effect.context<AuthConfig | Token | VerificationStore>()
  const issue = (options: IssueOptions) =>
    Effect.provideContext(issueState(options), stateServices)
  const consume = (providerId: string, state: Redacted.Redacted<string>) =>
    Effect.provideContext(consumeState(providerId, state), stateServices)

  const start = Effect.fnUntraced(function*(options: StartOptions) {
    const provider = yield* registry.get(options.providerId)
    const issued = yield* issue({
      providerId: provider.id,
      callbackURL: resolveUrl(config, options.callbackURL),
      errorURL: resolveUrl(config, options.errorCallbackURL),
      linkUserId: options.linkUserId ?? null,
      rememberMe: options.rememberMe ?? true,
      withNonce: isOidc(provider)
    })
    return {
      providerId: provider.id,
      url: authorizationUrl({
        provider,
        redirectUri: callbackUri(config, provider),
        state: Redacted.value(issued.state),
        codeChallenge: issued.codeChallenge,
        nonce: issued.nonce,
        scopes: mergeScopes(provider, options.scopes)
      }),
      state: issued.state,
      expiresAt: issued.expiresAt
    } satisfies StartResult
  }, (effect, options) => Effect.withSpan(effect, "OAuthFlow.start", { attributes: { providerId: options.providerId } }))

  /**
   * One request to the provider's token endpoint: the code exchange and the
   * refresh are the same request with a different `grant_type`.
   *
   * **Gotchas**
   *
   * The two callers report the same three failures as different errors — a
   * failed sign-in is an `OAuthProviderError`, a failed refresh is a
   * `TokenRefreshFailed` naming the account — so the mapping is a parameter
   * rather than a `catchTag` at the boundary.
   */
  const tokenRequest = Effect.fnUntraced(function*<E>(options: {
    readonly provider: OAuthProviderConfig
    /** The flow's own parameters. They always win over `extraParams`. */
    readonly params: Readonly<Record<string, string>>
    /** A provider's configured extras, filtered by {@link reservedTokenParams}. */
    readonly extraParams?: Readonly<Record<string, string>> | undefined
    readonly failures: TokenFailures<E>
  }) {
    const { extraParams, failures, params, provider } = options
    // Resolved per request, not per layer: a provider whose secret is minted
    // rather than configured mints one that expires. A public PKCE client has
    // none, and sends none — PKCE is what proves the exchange there.
    const secret = yield* Effect.mapError(resolveClientSecret(provider), failures.secret)

    // A map rather than an object: the keys are configuration-supplied, and a
    // duplicate must overwrite rather than be appended a second time.
    const form = new Map<string, string>()
    for (const [key, value] of Object.entries(extraParams ?? {})) {
      if (reservedTokenParams.has(key)) continue
      form.set(key, value)
    }
    for (const [key, value] of Object.entries(params)) form.set(key, value)
    form.set("client_id", provider.clientId)
    // The one place the secret is unwrapped. `client_secret_post`: it goes in
    // the body of this single request and nowhere else.
    if (Option.isSome(secret)) form.set("client_secret", Redacted.value(secret.value))

    const request = HttpClientRequest.post(provider.tokenUrl, {
      acceptJson: true,
      body: HttpBody.urlParams([...form])
    })

    // This is the one request that carries the client secret, and the one a
    // provider outage can hang forever: it gets a deadline, and a couple of
    // retries for a connection that never got made.
    const response = yield* Effect.mapError(resilient(client.execute(request)), failures.unavailable)
    if (response.status >= 400) return yield* Effect.fail(failures.rejected())
    const body = yield* Effect.mapError(Effect.timeout(response.json, providerRequestTimeout), failures.rejected)
    const tokens = decodeTokens(body, yield* DateTime.now)
    if (tokens === null) return yield* Effect.fail(failures.rejected())
    return tokens
  })

  const exchange = (
    provider: OAuthProviderConfig,
    code: string,
    codeVerifier: string
  ): Effect.Effect<OAuthTokens, OAuthProviderError> =>
    tokenRequest({
      provider,
      params: {
        grant_type: "authorization_code",
        code,
        redirect_uri: callbackUri(config, provider),
        code_verifier: codeVerifier
      },
      failures: {
        secret: (error) => error,
        unavailable: () => providerError(provider.id, "ProviderUnavailable"),
        rejected: () => providerError(provider.id, "TokenExchangeFailed")
      }
    })

  const withIdToken = Effect.fnUntraced(function*(
    provider: OAuthProviderConfig,
    tokens: OAuthTokens,
    nonce: string | null
  ) {
    if (!isOidc(provider)) return tokens
    const invalid = providerError(provider.id, "IdTokenInvalid")
    if (tokens.idToken === null) return yield* Effect.fail(invalid)
    // Fail closed, twice over: no key source at all is not "skip verification",
    // and a `jwks_uri` that could not be read is not either.
    const { jwks: pinned, jwksUrl } = provider
    const keys: KeyResolver = pinned !== undefined
      ? pinned
      : jwksUrl === undefined
      ? yield* Effect.fail(invalid)
      : yield* Effect.mapError(keySets.keys(jwksUrl), () => invalid)
    const claims: IdTokenClaims = yield* verifyIdToken({
      providerId: provider.id,
      token: tokens.idToken,
      // A multi-tenant provider derives the expected issuer from the token's own
      // claims; everyone else states one. See `VerifyOptions.issuer`.
      issuer: provider.issuerOf ?? provider.issuer,
      audience: provider.idTokenAudience ?? provider.clientId,
      keys,
      nonce,
      // Key rotation: a fetched key set that does not hold the token's `kid`
      // is refetched once (rate-limited by Jwks). Pinned keys are pinned.
      ...(pinned === undefined && jwksUrl !== undefined
        ? { freshKeys: Effect.mapError(keySets.refresh(jwksUrl), () => invalid) }
        : {}),
      ...(provider.algorithms === undefined ? {} : { algorithms: provider.algorithms })
    })
    return { ...tokens, idTokenClaims: claims } satisfies OAuthTokens
  })

  const accountTokens = (tokens: OAuthTokens): AccountTokens => ({
    accessToken: Redacted.value(tokens.accessToken),
    refreshToken: revealToken(tokens.refreshToken),
    idToken: revealToken(tokens.idToken),
    accessTokenExpiresAt: tokens.accessTokenExpiresAt,
    refreshTokenExpiresAt: tokens.refreshTokenExpiresAt,
    scope: tokens.scope
  })

  const begin = Effect.fnUntraced(function*(options: CallbackOptions) {
    const provider = yield* registry.get(options.providerId)
    if (options.state === undefined || options.state.length === 0) {
      return yield* Effect.fail(new OAuthStateMismatch())
    }
    const payload = yield* consume(provider.id, Redacted.make(options.state))
    return { provider, payload }
  })

  const finish = Effect.fnUntraced(function*(
    provider: OAuthProviderConfig,
    payload: StatePayload,
    options: CallbackOptions
  ) {
    if (options.error !== undefined && options.error.length > 0) {
      return yield* Effect.fail(
        providerError(provider.id, options.error === "access_denied" ? "AccessDenied" : "TokenExchangeFailed")
      )
    }
    if (options.code === undefined || options.code.length === 0) {
      return yield* Effect.fail(providerError(provider.id, "TokenExchangeFailed"))
    }

    const exchanged = yield* exchange(provider, options.code, payload.codeVerifier)
    const tokens = yield* withIdToken(provider, exchanged, payload.nonce)

    const info = yield* Effect.provideService(
      // Whatever else the provider posted back travels with the tokens — Apple
      // sends the person's name there, once, and never again. It is unsigned, so
      // a provider that reads it is expected to treat it as such.
      provider.userInfo(tokens, { params: options.params ?? {} }),
      HttpClient.HttpClient,
      client
    )
    const subject = provider.accountId(info)
    if (subject.length === 0 || info.email.length === 0) {
      return yield* Effect.fail(providerError(provider.id, "UserInfoFailed"))
    }

    const identity: OAuthIdentity = {
      providerId: provider.id,
      // A multi-tenant provider names the issuer this identity belongs under,
      // derived from a *verified* `id_token` claim; everyone else is stored under
      // the provider's own.
      issuer: info.issuer ?? providerIssuer(provider),
      accountId: subject,
      email: info.email,
      emailVerified: info.emailVerified,
      name: info.name ?? info.email,
      image: info.image ?? null,
      tokens: accountTokens(tokens)
    }

    const linkUserId = payload.linkUserId
    const link = yield* (linkUserId === null
      ? accounts.linkOAuth(identity)
      : accounts.linkToUser(linkUserId, identity))

    if (linkUserId !== null) {
      return {
        providerId: provider.id,
        user: link.user,
        account: link.account,
        session: null,
        token: null,
        redirectTo: resolveUrl(config, payload.callbackURL),
        userCreated: link.userCreated,
        accountCreated: link.accountCreated,
        linked: true,
        rememberMe: true
      } satisfies CallbackResult
    }

    // After the identity has been resolved, deliberately. Only a browser that
    // came back holding a state this deployment minted, with a code its own
    // client credentials could exchange, ever reaches this line — so a refusal
    // here tells whoever provoked it nothing the exchange had not established
    // already. It travels out as the callback's redirect outcome, exactly as a
    // failed exchange does, rather than as a page the browser cannot leave.
    const beforeSession = hooks.beforeSessionCreate
    if (beforeSession !== undefined) {
      const source: ProvisionSource = { _tag: "OAuth", providerId: provider.id, info }
      yield* beforeSession({ user: link.user, source })
    }

    const created = yield* sessions.create({
      userId: link.user.id,
      ipAddress: options.ipAddress ?? null,
      userAgent: options.userAgent ?? null,
      rememberMe: payload.rememberMe
    })
    yield* publishSafely(events, {
      _tag: "SignedIn",
      userId: link.user.id,
      sessionId: created.session.id,
      method: oauthMethod(provider.id)
    })

    return {
      providerId: provider.id,
      user: link.user,
      account: link.account,
      session: created.session,
      token: created.token,
      redirectTo: resolveUrl(config, payload.callbackURL),
      userCreated: link.userCreated,
      accountCreated: link.accountCreated,
      linked: false,
      rememberMe: payload.rememberMe
    } satisfies CallbackResult
  })

  const callback = Effect.fnUntraced(
    function*(options: CallbackOptions) {
      const { payload, provider } = yield* begin(options)
      return yield* finish(provider, payload, options)
    },
    (effect, options) =>
      Effect.withSpan(effect, "OAuthFlow.callback", { attributes: { providerId: options.providerId } })
  )

  const failure = (error: CallbackError, errorURL: string | null): CallbackOutcome => {
    const code = errorCode(error)
    return {
      _tag: "Failure",
      error,
      // A refusal carries the deployment's own classification beside this
      // library's, in the one shape every redirect-shaped completion answers
      // with. `?error=` is unchanged by that: `errorCode` above already answers
      // `policy_refused` for this case, and it stays the closed set it was.
      redirectTo: error._tag === "PolicyRefused"
        ? policyRefusedTarget(config, errorURL, error.code)
        : withErrorCode(resolveUrl(config, errorURL), code),
      code
    }
  }

  const complete = Effect.fnUntraced(function*(options: CallbackOptions) {
    const begun = yield* Effect.result(begin(options))
    if (begun._tag === "Failure") {
      if (begun.failure._tag === "PersistenceError") return yield* Effect.fail(begun.failure)
      return failure(begun.failure, null)
    }
    const { payload, provider } = begun.success
    const finished = yield* Effect.result(finish(provider, payload, options))
    if (finished._tag === "Failure") {
      if (finished.failure._tag === "PersistenceError") return yield* Effect.fail(finished.failure)
      return failure(finished.failure, payload.errorURL)
    }
    return { _tag: "Success", ...finished.success } satisfies CallbackOutcome
  }, (effect, options) =>
    Effect.withSpan(effect, "OAuthFlow.complete", { attributes: { providerId: options.providerId } }))

  // ---------------------------------------------------------------------------
  // Provider tokens, after the flow
  // ---------------------------------------------------------------------------

  const refreshFailure = (accountId: AccountId, reason: TokenRefreshFailed["reason"]): TokenRefreshFailed =>
    new TokenRefreshFailed({ accountId, reason })

  /**
   * The caller's own account, or `NotFound` — which is also the answer for
   * somebody else's account, and deliberately the same one.
   */
  const findAccount = Effect.fnUntraced(function*(selector: TokenSelector) {
    const found = yield* accountStore.findByIdAndUserId(selector.accountId, selector.userId)
    return yield* Effect.fromOption(found, () => new NotFound())
  })

  /** Whether a refresh could even be attempted, before anything is spent. */
  const refreshable = (account: Account): boolean => {
    if (account.refreshToken === null) return false
    const provider = registry.find(account.providerId)
    return Option.isSome(provider) && provider.value.tokenRefresh?.enabled !== false
  }

  /** Whether the stored access token is inside {@link accessTokenSkew} of expiry. */
  const expiring = (account: Account, now: DateTime.Utc): boolean => {
    if (account.accessToken === null) return true
    // An expiry the provider never stated is not an expiry that has arrived.
    if (account.accessTokenExpiresAt === null) return false
    const remaining = DateTime.toEpochMillis(account.accessTokenExpiresAt) - DateTime.toEpochMillis(now)
    return remaining < Duration.toMillis(accessTokenSkew)
  }

  /** What the account currently holds, as the endpoint answers it. */
  const storedTokens = (account: Account): Effect.Effect<AccessTokenResult, TokenRefreshFailed> =>
    account.accessToken === null
      ? Effect.fail(refreshFailure(account.id, "AccessTokenMissing"))
      : Effect.succeed({
        accessToken: Redacted.make(account.accessToken),
        accessTokenExpiresAt: account.accessTokenExpiresAt,
        idToken: account.idToken === null ? null : Redacted.make(account.idToken),
        scopes: scopesOf(account.scope),
        providerId: account.providerId,
        accountId: account.id
      })

  const refreshFor = Effect.fnUntraced(function*(account: Account) {
    const provider = yield* Effect.mapError(
      registry.get(account.providerId),
      () => refreshFailure(account.id, "ProviderNotSupported")
    )
    if (provider.tokenRefresh?.enabled === false) {
      return yield* Effect.fail(refreshFailure(account.id, "RefreshNotSupported"))
    }
    const refreshToken = account.refreshToken
    if (refreshToken === null) {
      return yield* Effect.fail(refreshFailure(account.id, "RefreshTokenMissing"))
    }

    const tokens = yield* tokenRequest({
      provider,
      params: { grant_type: "refresh_token", refresh_token: refreshToken },
      extraParams: provider.tokenRefresh?.params,
      failures: {
        // A secret that cannot be minted is, to the caller, a provider this
        // deployment cannot talk to right now.
        secret: () => refreshFailure(account.id, "ProviderUnavailable"),
        unavailable: () => refreshFailure(account.id, "ProviderUnavailable"),
        rejected: () => refreshFailure(account.id, "RefreshRejected")
      }
    })

    // `scope` is absent on purpose: providers routinely omit it from a refresh
    // response, and writing that omission down as "no scopes" would erase what
    // the person actually consented to. A refresh token the provider did not
    // rotate is kept for the same reason — the stored one still works.
    const patch: AccountTokens = {
      accessToken: Redacted.value(tokens.accessToken),
      accessTokenExpiresAt: tokens.accessTokenExpiresAt,
      ...(tokens.refreshToken === null ? {} : {
        refreshToken: Redacted.value(tokens.refreshToken),
        refreshTokenExpiresAt: tokens.refreshTokenExpiresAt
      }),
      ...(tokens.idToken === null ? {} : { idToken: Redacted.value(tokens.idToken) })
    }
    // The account was unlinked between the read and the write: there is nothing
    // to answer with, and what was just minted belongs to nobody.
    const row = yield* Effect.fromOption(
      yield* accountStore.updateTokens(account.id, patch),
      () => new NotFound()
    )

    yield* publishSafely(events, {
      _tag: "TokensRefreshed",
      userId: row.userId,
      accountId: row.id,
      providerId: row.providerId
    })

    const stored = yield* storedTokens(row)
    // Unreachable: the row either kept its refresh token or was given a new one.
    if (row.refreshToken === null) {
      return yield* Effect.fail(refreshFailure(row.id, "RefreshTokenMissing"))
    }
    return {
      ...stored,
      refreshToken: Redacted.make(row.refreshToken),
      refreshTokenExpiresAt: row.refreshTokenExpiresAt
    } satisfies RefreshedTokens
  })

  const accessToken = Effect.fnUntraced(function*(selector: TokenSelector) {
    const account = yield* findAccount(selector)
    // The hot path: a token with life left in it, or one that could not be
    // renewed anyway, is handed straight back.
    if (!expiring(account, yield* DateTime.now) || !refreshable(account)) {
      return yield* storedTokens(account)
    }
    return yield* refreshFor(account)
  }, (effect, selector) =>
    Effect.withSpan(effect, "OAuthFlow.accessToken", { attributes: { accountId: selector.accountId } }))

  const refreshTokens = Effect.fnUntraced(
    function*(selector: TokenSelector) {
      return yield* refreshFor(yield* findAccount(selector))
    },
    (effect, selector) =>
      Effect.withSpan(effect, "OAuthFlow.refreshTokens", { attributes: { accountId: selector.accountId } })
  )

  return OAuthFlow.of({
    start,
    callback,
    complete,
    accessToken,
    refreshTokens
  })
})

/**
 * Provides {@link OAuthFlow}.
 *
 * **Details**
 *
 * The JWKS cache is the flow's own: {@link Jwks} is provided here, over the
 * redirect-refusing client, rather than asked of the application. One cache per
 * deployment, built and discarded with this layer — nothing survives in a
 * module-level variable between two `Auth` stacks in one process.
 *
 * @category layers
 * @since 1.0.0
 */
export const layer: Layer.Layer<
  OAuthFlow,
  never,
  | AuthConfig
  | OAuthProviders
  | Token
  | VerificationStore
  | Accounts
  | AccountStore
  | Sessions
  | AuthEvents
  | HttpClient.HttpClient
> = Layer.effect(OAuthFlow, make()).pipe(
  Layer.provide(layerJwks.pipe(Layer.provide(layerSafeClient)))
)
