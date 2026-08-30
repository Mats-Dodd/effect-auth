/**
 * An OAuth provider, stubbed at the transport.
 *
 * **Details**
 *
 * Nothing here talks to a network. {@link mockServer} hands out a `fetch` that
 * answers from a route table a test controls, {@link mockProvider} and
 * {@link oidcProvider} are the two provider shapes this library has to serve —
 * one whose identity comes from a user-info request, one whose identity comes
 * from a signed `id_token` — and {@link IdTokenSigner} mints those tokens
 * against a key pair generated once per layer rather than once per test.
 *
 * @since 1.0.0
 */
import { Context, Effect, Layer, Redacted } from "effect"
import { HttpClient } from "effect/unstable/http"
import type { JWTPayload } from "jose"
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } from "jose"
import { refuseRedirects } from "../oauth/Flow.js"
import type { KeyResolver } from "../oauth/IdToken.js"
import type { OAuthProviderConfig, OAuthTokens, OAuthUserInfo } from "../oauth/Provider.js"
import { fetchJson, providerError } from "../oauth/Provider.js"
import { layerFetch } from "./TestLayer.js"

// -----------------------------------------------------------------------------
// The stubbed transport
// -----------------------------------------------------------------------------

/**
 * One request the stubbed provider saw, decoded far enough to assert on.
 *
 * @category models
 * @since 1.0.0
 */
export interface RecordedRequest {
  readonly url: string
  readonly method: string
  readonly headers: Readonly<Record<string, string>>
  readonly body: string
  /**
   * The `redirect` mode the client asked for — `"manual"` for every OAuth call.
   */
  readonly redirect: string | undefined
}

/**
 * Reads a form-encoded request body as a lookup.
 *
 * @category combinators
 * @since 1.0.0
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
 *
 * @category models
 * @since 1.0.0
 */
export type RouteHandler = (request: RecordedRequest) => Response | Promise<Response>

/**
 * The provider's HTTP surface, stubbed.
 *
 * @category models
 * @since 1.0.0
 */
export interface MockServer {
  /**
   * The transport, in the shape `FetchHttpClient.Fetch` wants.
   */
  readonly fetch: typeof globalThis.fetch
  /**
   * Every request the server saw, in order.
   */
  readonly requests: Array<RecordedRequest>
  /**
   * Registers (or replaces) the handler for one endpoint.
   */
  readonly on: (url: string, handler: RouteHandler) => void
  /**
   * Every request sent to one endpoint.
   */
  readonly to: (url: string) => ReadonlyArray<RecordedRequest>
  /**
   * Forgets every request recorded so far; the routes are left alone.
   *
   * **When to use**
   *
   * At the top of each test in a sequential `layer()` block that shares one
   * server, so that `requests` and {@link MockServer.to} describe *this* test
   * rather than everything the block has done.
   */
  readonly clear: () => void
}

/**
 * The provider's HTTP surface, stubbed.
 *
 * **Details**
 *
 * Routes are looked up at call time from a null-prototyped dictionary, so a
 * test can replace one after the flow has already started — which is what the
 * OIDC tests do, because the `id_token` they mint has to echo the nonce that
 * `start` generated.
 *
 * **Gotchas**
 *
 * The route table and the request log are shared mutable state. A `layer()`
 * block that mutates routes per test must run sequentially.
 *
 * @category constructors
 * @since 1.0.0
 */
export const mockServer = (): MockServer => {
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
    on: (url, handler) => {
      routes[url] = handler
    },
    to: (url) => requests.filter((request) => request.url.startsWith(url)),
    clear: () => {
      requests.length = 0
    }
  }
}

/**
 * A JSON response, as a provider would send one.
 *
 * @category constructors
 * @since 1.0.0
 */
export const json = (body: unknown, status = 200): Response =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } })

/**
 * A redirect, which every OAuth fetch in this library must refuse to follow.
 *
 * @category constructors
 * @since 1.0.0
 */
export const redirect = (location: string, status = 302): Response =>
  new Response(null, { status, headers: { location } })

// -----------------------------------------------------------------------------
// The provider under test
// -----------------------------------------------------------------------------

/**
 * The origin the stubbed provider serves from.
 *
 * @category constructors
 * @since 1.0.0
 */
export const providerOrigin = "https://provider.test"

/**
 * The stubbed provider's token endpoint.
 *
 * @category constructors
 * @since 1.0.0
 */
export const tokenUrl = `${providerOrigin}/token`

/**
 * The stubbed provider's user-info endpoint.
 *
 * @category constructors
 * @since 1.0.0
 */
export const userInfoUrl = `${providerOrigin}/userinfo`

/**
 * The stubbed provider's authorization endpoint.
 *
 * @category constructors
 * @since 1.0.0
 */
export const authorizeUrl = `${providerOrigin}/authorize`

const readString = (record: Readonly<Record<string, unknown>>, key: string): string | null => {
  if (!Object.hasOwn(record, key)) return null
  const value = record[key]
  return typeof value === "string" && value.length > 0 ? value : null
}

/**
 * A plain OAuth2 provider whose identity comes from a user-info endpoint.
 *
 * @category constructors
 * @since 1.0.0
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
 *
 * @category constructors
 * @since 1.0.0
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

/**
 * A token set, for exercising a provider's `userInfo` on its own.
 *
 * @category constructors
 * @since 1.0.0
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

/**
 * The query parameters of an authorization URL.
 *
 * @category combinators
 * @since 1.0.0
 */
export const paramsOf = (url: string): URLSearchParams => new URL(url).searchParams

// -----------------------------------------------------------------------------
// Signing id_tokens
// -----------------------------------------------------------------------------

/**
 * How an `id_token` may depart from the defaults.
 *
 * @category models
 * @since 1.0.0
 */
export interface SignOptions {
  readonly issuer?: string | undefined
  readonly audience?: string | undefined
  /**
   * The `exp` claim, in seconds since the (test) epoch. `null` mints a token
   * with no expiry at all — which a provider must never be believed about, and
   * which is therefore worth a test.
   */
  readonly expiresAt?: number | null | undefined
}

/**
 * A key pair and the local JWKS that admits it, so that `id_token`
 * verification runs with no network. See {@link IdTokenSigner}.
 *
 * @category models
 * @since 1.0.0
 */
export interface IdTokenSignerService {
  /**
   * The key set to hand a provider as its `jwks`.
   */
  readonly jwks: KeyResolver
  /**
   * Mints a signed `id_token` for `payload`.
   */
  readonly sign: (payload: JWTPayload, options?: SignOptions) => Promise<string>
}

/**
 * The `id_token` signer. See {@link IdTokenSignerService}.
 *
 * **Gotchas**
 *
 * RSA key generation costs tens of milliseconds. Build this once per `layer()`
 * block — that is the whole reason it is a service rather than a helper.
 *
 * @category services
 * @since 1.0.0
 */
export class IdTokenSigner extends Context.Service<IdTokenSigner, IdTokenSignerService>()(
  "effect-auth/testing/IdTokenSigner"
) {
  /**
   * A freshly generated key pair, behind the {@link IdTokenSigner} key.
   *
   * @category layers
   * @since 1.0.0
   */
  static readonly layer: Layer.Layer<IdTokenSigner> = Layer.effect(IdTokenSigner, makeIdTokenSigner())
}

/**
 * Generates a key pair and the local JWKS that admits it.
 *
 * @category constructors
 * @since 1.0.0
 */
export function makeIdTokenSigner(): Effect.Effect<IdTokenSignerService> {
  return Effect.promise(async () => {
    const pair = await generateKeyPair("RS256", { extractable: true })
    const jwk = await exportJWK(pair.publicKey)
    const jwks = createLocalJWKSet({ keys: [{ ...jwk, kid: "k1", alg: "RS256" }] })
    const sign = (payload: JWTPayload, options?: SignOptions) => {
      const unsigned = new SignJWT(payload)
        .setProtectedHeader({ alg: "RS256", kid: "k1" })
        .setIssuer(options?.issuer ?? providerOrigin)
        .setAudience(options?.audience ?? "mock-client-id")
      return (options?.expiresAt === null ? unsigned : unsigned.setExpirationTime(options?.expiresAt ?? 3600))
        .sign(pair.privateKey)
    }
    return { jwks, sign }
  })
}

// -----------------------------------------------------------------------------
// Layers
// -----------------------------------------------------------------------------

/**
 * The stubbed transport, as an `HttpClient`.
 *
 * @category layers
 * @since 1.0.0
 */
export const httpLayer = (fetch: typeof globalThis.fetch): Layer.Layer<HttpClient.HttpClient> => layerFetch(fetch)

/**
 * The stubbed transport wrapped exactly as the flow wraps it, for exercising a
 * provider's `userInfo` on its own: a provider always runs under the
 * redirect-refusing client, and a test of one should too.
 *
 * @category layers
 * @since 1.0.0
 */
export const safeHttpLayer = (fetch: typeof globalThis.fetch): Layer.Layer<HttpClient.HttpClient> =>
  Layer.effect(
    HttpClient.HttpClient,
    Effect.gen(function*() {
      return refuseRedirects(yield* HttpClient.HttpClient)
    })
  ).pipe(Layer.provide(httpLayer(fetch)))
