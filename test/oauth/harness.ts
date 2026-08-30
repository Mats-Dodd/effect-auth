import { PgliteClient } from "@effect/sql-pglite"
import type { Duration } from "effect"
import { Effect, Layer, Redacted } from "effect"
import { FetchHttpClient, HttpClient } from "effect/unstable/http"
import type { JWTPayload } from "jose"
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } from "jose"
import type { AuthConfigOptions } from "../../src/config/AuthConfig.js"
import { layer as authConfigLayer } from "../../src/config/AuthConfig.js"
import { layer as accountsLayer } from "../../src/domain/Accounts.js"
import { layer as authEventsLayer } from "../../src/domain/Events.js"
import { layer as sessionsLayer } from "../../src/domain/Sessions.js"
import { layer as tokenLayer } from "../../src/crypto/Token.js"
import * as Flow from "../../src/oauth/Flow.js"
import type { OAuthProviderConfig, OAuthTokens, OAuthUserInfo } from "../../src/oauth/Provider.js"
import { fetchJson, OAuthProviders, providerError } from "../../src/oauth/Provider.js"
import * as Migrations from "../../src/sql/Migrations.js"
import * as SqlStores from "../../src/sql/SqlStores.js"

/**
 * Per-test timeout. Every test builds its own PGlite database and runs the
 * migrations so that it also owns its own `TestClock`; five seconds is not
 * always enough for the first of them on a cold machine.
 */
export const testTimeout = 30_000

// -----------------------------------------------------------------------------
// A provider, stubbed at the transport
// -----------------------------------------------------------------------------

/**
 * One request the stubbed provider saw, decoded far enough to assert on.
 */
export interface RecordedRequest {
  readonly url: string
  readonly method: string
  readonly headers: Readonly<Record<string, string>>
  readonly body: string
  /** The `redirect` mode the client asked for — `"manual"` for every OAuth call. */
  readonly redirect: string | undefined
}

/**
 * Reads a form-encoded request body as a lookup.
 */
export const formOf = (request: RecordedRequest): URLSearchParams => new URLSearchParams(request.body)

const decodeBody = (body: unknown): string => {
  if (typeof body === "string") return body
  if (body instanceof Uint8Array) return new TextDecoder().decode(body)
  if (body instanceof ArrayBuffer) return new TextDecoder().decode(new Uint8Array(body))
  return ""
}

const headersOf = (input: unknown): Readonly<Record<string, string>> => {
  const out: Record<string, string> = Object.create(null)
  if (input instanceof Headers) {
    input.forEach((value, key) => {
      out[key.toLowerCase()] = value
    })
    return { ...out }
  }
  if (typeof input === "object" && input !== null) {
    for (const [key, value] of Object.entries(input as Record<string, unknown>)) {
      if (typeof value === "string") out[key.toLowerCase()] = value
    }
  }
  return { ...out }
}

/**
 * A handler for one endpoint of the stubbed provider.
 */
export type RouteHandler = (request: RecordedRequest) => Response | Promise<Response>

/**
 * The provider's HTTP surface, stubbed.
 *
 * **Details**
 *
 * Routes are looked up at call time from a null-prototyped dictionary, so a
 * test can replace one after the flow has already started — which is what the
 * OIDC tests do, because the `id_token` they mint has to echo the nonce that
 * `start` generated.
 */
export const mockServer = () => {
  const routes = Object.create(null) as Record<string, RouteHandler>
  const requests: Array<RecordedRequest> = []

  const fetch: typeof globalThis.fetch = async (input, init) => {
    const url = typeof input === "string"
      ? input
      : input instanceof URL
      ? input.toString()
      : (input as Request).url
    const record: RecordedRequest = {
      url,
      method: init?.method ?? "GET",
      headers: headersOf(init?.headers),
      body: decodeBody(init?.body),
      redirect: init?.redirect
    }
    requests.push(record)
    const parsed = new URL(url)
    const key = `${parsed.origin}${parsed.pathname}`
    if (!Object.hasOwn(routes, key)) return new Response("no such route", { status: 404 })
    return routes[key]!(record)
  }

  return {
    fetch,
    requests,
    /** Registers (or replaces) the handler for one endpoint. */
    on: (url: string, handler: RouteHandler): void => {
      routes[url] = handler
    },
    /** Every request sent to one endpoint. */
    to: (url: string): ReadonlyArray<RecordedRequest> => requests.filter((request) => request.url.startsWith(url))
  }
}

/**
 * A JSON response, as a provider would send one.
 */
export const json = (body: unknown, status = 200): Response =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } })

/**
 * A redirect, which every OAuth fetch in this library must refuse to follow.
 */
export const redirect = (location: string, status = 302): Response =>
  new Response(null, { status, headers: { location } })

// -----------------------------------------------------------------------------
// The provider under test
// -----------------------------------------------------------------------------

export const providerOrigin = "https://provider.test"
export const tokenUrl = `${providerOrigin}/token`
export const userInfoUrl = `${providerOrigin}/userinfo`
export const authorizeUrl = `${providerOrigin}/authorize`

const readString = (record: Readonly<Record<string, unknown>>, key: string): string | null => {
  if (!Object.hasOwn(record, key)) return null
  const value = record[key]
  return typeof value === "string" && value.length > 0 ? value : null
}

/**
 * A plain OAuth2 provider whose identity comes from a user-info endpoint.
 */
export const mockProvider = (overrides?: Partial<OAuthProviderConfig>): OAuthProviderConfig => ({
  id: "mock",
  clientId: "mock-client-id",
  clientSecret: Redacted.make("mock-client-secret"),
  authorizationUrl: authorizeUrl,
  tokenUrl,
  scopes: ["profile", "email"],
  userInfo: Effect.fnUntraced(function*(tokens: OAuthTokens) {
    const response = yield* fetchJson({
      providerId: "mock",
      url: userInfoUrl,
      accessToken: tokens.accessToken
    })
    const body = response.body
    if (typeof body !== "object" || body === null || Array.isArray(body)) {
      return yield* Effect.fail(providerError("mock", "UserInfoFailed"))
    }
    const record = body as Readonly<Record<string, unknown>>
    const id = readString(record, "sub")
    const email = readString(record, "email")
    if (id === null || email === null) return yield* Effect.fail(providerError("mock", "UserInfoFailed"))
    return {
      id,
      email,
      emailVerified: Object.hasOwn(record, "email_verified") && record.email_verified === true,
      name: readString(record, "name") ?? email,
      image: readString(record, "picture")
    } satisfies OAuthUserInfo
  }),
  accountId: (info) => info.id,
  ...overrides
})

/**
 * An OIDC provider: the identity comes from the verified `id_token` alone, so
 * no user-info request is made at all.
 */
export const oidcProvider = (
  keys: OAuthProviderConfig["jwks"],
  overrides?: Partial<OAuthProviderConfig>
): OAuthProviderConfig => ({
  ...mockProvider(),
  id: "oidc",
  issuer: providerOrigin,
  jwks: keys,
  algorithms: ["RS256"],
  userInfo: Effect.fnUntraced(function*(tokens: OAuthTokens) {
    const claims = tokens.idTokenClaims
    if (claims === null || claims.email === null) {
      return yield* Effect.fail(providerError("oidc", "UserInfoFailed"))
    }
    return {
      id: claims.subject,
      email: claims.email,
      emailVerified: claims.emailVerified,
      name: claims.name ?? claims.email,
      image: claims.picture
    } satisfies OAuthUserInfo
  }),
  ...overrides
})

// -----------------------------------------------------------------------------
// Signing id_tokens
// -----------------------------------------------------------------------------

/**
 * A key pair and the local JWKS that admits it, so that `id_token`
 * verification runs with no network.
 */
export const idTokenSigner = Effect.promise(async () => {
  const pair = await generateKeyPair("RS256", { extractable: true })
  const jwk = await exportJWK(pair.publicKey)
  const jwks = createLocalJWKSet({ keys: [{ ...jwk, kid: "k1", alg: "RS256" }] })
  const sign = (payload: JWTPayload, options?: {
    readonly issuer?: string | undefined
    readonly audience?: string | undefined
    readonly expiresAt?: number | undefined
  }) =>
    new SignJWT(payload)
      .setProtectedHeader({ alg: "RS256", kid: "k1" })
      .setIssuer(options?.issuer ?? providerOrigin)
      .setAudience(options?.audience ?? "mock-client-id")
      .setExpirationTime(options?.expiresAt ?? 3600)
      .sign(pair.privateKey)
  return { jwks, sign }
})

// -----------------------------------------------------------------------------
// Layers
// -----------------------------------------------------------------------------

/**
 * The stubbed transport, as an `HttpClient`.
 */
export const httpLayer = (fetch: typeof globalThis.fetch) =>
  FetchHttpClient.layer.pipe(Layer.provide(Layer.succeed(FetchHttpClient.Fetch)(fetch)))

/**
 * The stubbed transport wrapped exactly as the flow wraps it, for exercising a
 * provider's `userInfo` on its own: a provider always runs under the
 * redirect-refusing client, and a test of one should too.
 */
export const safeHttpLayer = (fetch: typeof globalThis.fetch) =>
  Layer.effect(
    HttpClient.HttpClient,
    Effect.gen(function*() {
      return Flow.refuseRedirects(yield* HttpClient.HttpClient)
    })
  ).pipe(Layer.provide(httpLayer(fetch)))

/**
 * A complete OAuth stack on a fresh PGlite database, talking to a stubbed
 * provider.
 */
export const flowLayer = (options: {
  readonly providers: ReadonlyArray<OAuthProviderConfig>
  readonly fetch: typeof globalThis.fetch
  readonly trustedOrigins?: ReadonlyArray<string> | undefined
  readonly trustedProviders?: ReadonlyArray<string> | undefined
  readonly oauthStateTtl?: Duration.Duration | undefined
}) => {
  const config: AuthConfigOptions = {
    baseUrl: "https://app.example.com",
    secret: Redacted.make("test-secret-not-for-production"),
    trustedOrigins: options.trustedOrigins ?? [],
    trustedProviders: options.trustedProviders ?? [],
    tokens: options.oauthStateTtl === undefined ? undefined : { oauthStateTtl: options.oauthStateTtl }
  }
  const database = PgliteClient.layer()
  const storage = SqlStores.layer.pipe(
    Layer.provide(Migrations.layer.pipe(Layer.provideMerge(database)))
  )
  const infrastructure = Layer.mergeAll(
    storage,
    authConfigLayer(config),
    tokenLayer,
    authEventsLayer(),
    OAuthProviders.layer(options.providers),
    httpLayer(options.fetch)
  )
  const domain = Layer.mergeAll(sessionsLayer, accountsLayer).pipe(
    Layer.provideMerge(infrastructure)
  )
  return Flow.layer.pipe(Layer.provideMerge(domain))
}

/**
 * The query parameters of an authorization URL.
 */
export const paramsOf = (url: string): URLSearchParams => new URL(url).searchParams

/**
 * A token set, for exercising a provider's `userInfo` on its own.
 */
export const tokensOf = (
  accessToken: string,
  overrides?: Partial<OAuthTokens>
): OAuthTokens => ({
  accessToken: Redacted.make(accessToken),
  tokenType: "bearer",
  refreshToken: null,
  idToken: null,
  idTokenClaims: null,
  accessTokenExpiresAt: null,
  refreshTokenExpiresAt: null,
  scope: null,
  ...overrides
})
