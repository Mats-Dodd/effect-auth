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
import { OAuthStateMismatch } from "../domain/Errors.js"
import { AuthEvents, oauthMethod, publishSafely } from "../domain/Events.js"
import type { Account, Session, User } from "../domain/Schema.js"
import { Sessions } from "../domain/Sessions.js"
import type { AccountTokens, PersistenceError } from "../domain/Stores.js"
import { VerificationStore } from "../domain/Stores.js"
import { resolveUrl } from "../http/OriginCheck.js"
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
  resilient,
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
  readonly ipAddress?: string | null | undefined
  readonly userAgent?: string | null | undefined
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
export type CallbackError = OAuthStateMismatch | OAuthProviderError | AccountAlreadyLinked | UserNotFound

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
    /** The validated error URL, carrying `?error=<code>`. */
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
    case "UserNotFound":
      return "user_not_found"
    case "OAuthProviderError":
      return snakeCase(error.reason)
  }
}

const snakeCase = (value: string): string => value.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase()

/**
 * Appends the safe error code to a validated error URL.
 *
 * @category combinators
 * @since 1.0.0
 */
export const withErrorCode = (url: string, code: string): string => {
  const parsed = new URL(url)
  parsed.searchParams.set("error", code)
  return parsed.toString()
}

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
}

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
  | Sessions
  | AuthEvents
  | Jwks
  | HttpClient.HttpClient
> = Effect.fnUntraced(function*() {
  const config = yield* AuthConfig
  const registry = yield* OAuthProviders
  const accounts = yield* Accounts
  const sessions = yield* Sessions
  const events = yield* AuthEvents
  const keySets = yield* Jwks
  const client = refuseRedirects(yield* HttpClient.HttpClient)

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

  const exchange = Effect.fnUntraced(function*(
    provider: OAuthProviderConfig,
    code: string,
    codeVerifier: string
  ) {
    const failed = providerError(provider.id, "TokenExchangeFailed")
    const request = HttpClientRequest.post(provider.tokenUrl, {
      acceptJson: true,
      body: HttpBody.urlParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: callbackUri(config, provider),
        code_verifier: codeVerifier,
        client_id: provider.clientId,
        // The one place the secret is unwrapped. `client_secret_post`: it goes
        // in the body of this single request and nowhere else.
        client_secret: Redacted.value(provider.clientSecret)
      })
    })

    // The exchange is the one request that carries the client secret, and the
    // one a provider outage can hang forever: it gets a deadline, and a couple
    // of retries for a connection that never got made.
    const response = yield* Effect.mapError(
      resilient(client.execute(request)),
      () => providerError(provider.id, "ProviderUnavailable")
    )
    if (response.status >= 400) return yield* Effect.fail(failed)
    const body = yield* Effect.mapError(Effect.timeout(response.json, providerRequestTimeout), () => failed)
    const tokens = decodeTokens(body, yield* DateTime.now)
    if (tokens === null) return yield* Effect.fail(failed)
    return tokens
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
      issuer: provider.issuer,
      audience: provider.clientId,
      keys,
      nonce,
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
      provider.userInfo(tokens),
      HttpClient.HttpClient,
      client
    )
    const subject = provider.accountId(info)
    if (subject.length === 0 || info.email.length === 0) {
      return yield* Effect.fail(providerError(provider.id, "UserInfoFailed"))
    }

    const identity: OAuthIdentity = {
      providerId: provider.id,
      issuer: providerIssuer(provider),
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
      redirectTo: withErrorCode(resolveUrl(config, errorURL), code),
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

  return OAuthFlow.of({ start, callback, complete })
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
  | Sessions
  | AuthEvents
  | HttpClient.HttpClient
> = Layer.effect(OAuthFlow, make()).pipe(
  Layer.provide(layerJwks.pipe(Layer.provide(layerSafeClient)))
)
