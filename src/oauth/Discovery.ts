/**
 * OIDC discovery: a provider built from its own `.well-known` document.
 *
 * Every OIDC provider publishes where its endpoints and its keys are. This turns
 * that document into an {@link OAuthProviderConfig}, so a deployment that talks
 * to Auth0, Okta, Keycloak, Zitadel or its own identity server writes an issuer
 * and a client id rather than five URLs it has to keep in step with the
 * provider.
 *
 * **Details**
 *
 * Discovery runs *once*, while the stack is being built, and everything it can
 * refuse it refuses there: a deployment whose provider cannot be discovered
 * fails to boot rather than failing every sign-in at three in the morning. That
 * is why the error is `DiscoveryError` with a reason and not one opaque failure
 * — the reasons are for whoever is reading the boot log.
 *
 * Three rules keep a discovery document from being a trust hole:
 *
 * - the fetch refuses redirects, like every other outbound request in this
 *   module, so a `.well-known` that answers `302` cannot bounce a server-side
 *   request at an internal address;
 * - `issuer` must equal the configured one byte for byte — a document is only
 *   evidence about the issuer it is served for, and a mismatch is precisely what
 *   a hijacked discovery endpoint looks like;
 * - no `jwks_uri` and no pinned key set is `KeysMissing`, never "skip the
 *   `id_token` check". The provider type now says as much structurally — the
 *   OIDC block's `keys` is a union with no empty case — but discovery is where
 *   the shortfall is a *document's*, and so where it is worth a reason somebody
 *   reading a boot log can act on rather than a type error nobody sees.
 *
 * Anything a caller states explicitly wins over what the document says.
 *
 * @since 1.0.0
 */
import { Effect, Option, Schema } from "effect"
import { HttpClient, HttpClientRequest } from "effect/unstable/http"
import { DiscoveryError } from "../domain/Errors.js"
import { trimTrailingSlashes } from "../internal/url.js"
import { refuseRedirects } from "./Flow.js"
import type { KeyResolver } from "./IdToken.js"
import { isRedirectResponse } from "./IdToken.js"
import type { OAuthProviderConfig, OAuthTokens } from "./Provider.js"
import { providerError, providerRequestTimeout, resilient } from "./Provider.js"
import { lenient } from "./internal/claims.js"
import { jsonWithin } from "./internal/http.js"
import { fetchIdentity, identityOf } from "./internal/userInfo.js"

// -----------------------------------------------------------------------------
// The document
// -----------------------------------------------------------------------------

/**
 * The path an issuer's discovery document is served at.
 *
 * @category constructors
 * @since 1.0.0
 */
export const wellKnownPath = "/.well-known/openid-configuration"

/**
 * The discovery document, as far as it is read.
 *
 * **Details**
 *
 * Only the fields this library builds a provider from. `issuer` is lenient like
 * the rest so that a document without one can be reported as `IssuerMissing`
 * rather than as `Malformed` — the distinction is the whole value of the error's
 * reason.
 *
 * @category models
 * @since 1.0.0
 */
export const DiscoveryDocument = Schema.Struct({
  issuer: lenient(Schema.NonEmptyString),
  authorization_endpoint: lenient(Schema.NonEmptyString),
  token_endpoint: lenient(Schema.NonEmptyString),
  userinfo_endpoint: lenient(Schema.NonEmptyString),
  jwks_uri: lenient(Schema.NonEmptyString),
  scopes_supported: lenient(Schema.Array(Schema.String)),
  id_token_signing_alg_values_supported: lenient(Schema.Array(Schema.String))
})

/**
 * The type of a {@link DiscoveryDocument}.
 *
 * @category models
 * @since 1.0.0
 */
export type DiscoveryDocument = typeof DiscoveryDocument.Type

const readDocument = Schema.decodeUnknownOption(DiscoveryDocument)

/**
 * The discovery URL for an issuer.
 *
 * **Gotchas**
 *
 * The path is appended to the issuer, it does not replace the issuer's own path:
 * an issuer of `https://host/realms/acme` publishes at
 * `https://host/realms/acme/.well-known/openid-configuration`, which is what
 * Keycloak and Zitadel do.
 *
 * @category combinators
 * @since 1.0.0
 */
export const discoveryUrlOf = (issuer: string): string => `${trimTrailingSlashes(issuer)}${wellKnownPath}`

/**
 * The signature algorithms a discovered provider will accept an `id_token`
 * under.
 *
 * **Details**
 *
 * The document's own list, narrowed to the asymmetric families. A provider that
 * advertises `HS256` is advertising an algorithm whose "public" key is the
 * client secret, and admitting it from a *discovered* list would be admitting it
 * on the provider's say-so. Nothing is returned when the narrowed list is empty,
 * which leaves the decision to whatever the resolved JWKS key admits.
 *
 * @category combinators
 * @since 1.0.0
 */
export const asymmetricAlgorithms = (
  algorithms: ReadonlyArray<string> | undefined
): ReadonlyArray<string> | undefined => {
  if (algorithms === undefined) return undefined
  const admitted = algorithms.filter(
    (algorithm) =>
      algorithm.startsWith("RS") || algorithm.startsWith("PS") || algorithm.startsWith("ES") || algorithm === "EdDSA"
  )
  return admitted.length === 0 ? undefined : admitted
}

// -----------------------------------------------------------------------------
// Options
// -----------------------------------------------------------------------------

/** The OIDC block a discovered provider is assembled into. */
type Oidc = NonNullable<OAuthProviderConfig["oidc"]>

/**
 * What discovering a provider needs.
 *
 * **Details**
 *
 * Everything the document can supply may also be stated here, and stating it
 * wins: a deployment behind a gateway that rewrites one endpoint does not lose
 * discovery for the other four.
 *
 * The options stay flat where the built provider's OIDC settings are one block:
 * a caller is answering "what did the document get wrong", one field at a time,
 * and half of what it states — the endpoints, the scopes — is not OIDC at all.
 * {@link make} is what folds the OIDC half into the block.
 *
 * @category models
 * @since 1.0.0
 */
export interface Options {
  /**
   * The id this provider is registered and addressed under — the `providerId`
   * of `POST /auth/sign-in/social` and the last segment of the callback path.
   */
  readonly id: string
  /**
   * The issuer, which is both where the document is fetched from and the value
   * it must declare.
   */
  readonly issuer: string
  /**
   * The discovery document's URL, when it is not
   * `<issuer>/.well-known/openid-configuration`.
   */
  readonly discoveryUrl?: string | undefined
  readonly clientId: string
  /**
   * The client secret: fixed, minted per request, or absent for a public PKCE
   * client. See `OAuthProviderConfig.clientSecret`.
   */
  readonly clientSecret?: OAuthProviderConfig["clientSecret"]
  /**
   * The scopes to request.
   *
   * @default ["openid", "email", "profile"]
   */
  readonly scopes?: ReadonlyArray<string> | undefined
  /** Overrides the document's `authorization_endpoint`. */
  readonly authorizationUrl?: string | undefined
  /** Overrides the document's `token_endpoint`. */
  readonly tokenUrl?: string | undefined
  /** Overrides the document's `jwks_uri`. */
  readonly jwksUrl?: string | undefined
  /** Overrides the document's `userinfo_endpoint`. */
  readonly userInfoUrl?: string | undefined
  /**
   * A pre-resolved key set, instead of fetching a `jwks_uri` at all.
   *
   * **Gotchas**
   *
   * It wins outright: the built provider's `keys` is one or the other, and a
   * pinned key set is a deliberate statement that no JWKS is to be fetched for
   * this provider — including the one the document advertises.
   */
  readonly jwks?: KeyResolver | undefined
  /** Overrides the algorithms narrowed out of the document. */
  readonly algorithms?: ReadonlyArray<string> | undefined
  /** Overrides `<baseUrl><basePath>/callback/<id>`. */
  readonly redirectUri?: string | undefined
  /** Extra authorization-request parameters. */
  readonly authorizationParams?: Readonly<Record<string, string>> | undefined
  /** The audience an `id_token` must carry, when it is not `clientId`. */
  readonly audience?: Oidc["audience"]
  /** The expected issuer derived from a token's own claims, for a multi-tenant provider. */
  readonly issuerOf?: Oidc["issuerOf"]
  /** Whether, and how, this provider's stored tokens may be refreshed. */
  readonly tokenRefresh?: OAuthProviderConfig["tokenRefresh"]
  /**
   * Resolves the tokens into an identity, replacing the default.
   *
   * **When to use**
   *
   * A provider whose claims need mapping — a group claim that decides the
   * display name, an address under a vendor-specific key. The default reads the
   * verified `id_token` and, only when that carries no address, the discovered
   * userinfo endpoint.
   */
  readonly userInfo?: OAuthProviderConfig["userInfo"]
  /** Projects the stable subject out of the identity. Defaults to the `sub`. */
  readonly accountId?: OAuthProviderConfig["accountId"]
}

/**
 * The scopes a discovered provider asks for unless told otherwise.
 *
 * @category constructors
 * @since 1.0.0
 */
export const defaultScopes: ReadonlyArray<string> = ["openid", "email", "profile"]

// -----------------------------------------------------------------------------
// Discovery
// -----------------------------------------------------------------------------

const failure = (id: string, reason: DiscoveryError["reason"]) => DiscoveryError.make({ id, reason })

/**
 * Fetches a provider's discovery document and builds its configuration.
 *
 * **When to use**
 *
 * As an entry of `Auth.layerConfigWithOAuth`'s provider list, whose error
 * channel already admits `DiscoveryError` and whose `HttpClient` this borrows.
 * `Auth.layerWithOAuth` takes provider *values*, so a discovered provider is
 * resolved before the stack is described — `Effect.map` it into whatever builds
 * the layer.
 *
 * **Example**
 *
 * ```ts skip-type-checking
 * Auth.layerConfigWithOAuth({
 *   baseUrl: Config.string("BASE_URL"),
 *   secret: Config.redacted("AUTH_SECRET"),
 *   providers: [
 *     Effect.flatMap(
 *       Config.all([Config.string("OIDC_CLIENT_ID"), Config.redacted("OIDC_CLIENT_SECRET")]),
 *       ([clientId, clientSecret]) =>
 *         OidcDiscovery.make({ id: "acme", issuer: "https://id.acme.test", clientId, clientSecret })
 *     )
 *   ]
 * })
 * ```
 *
 * @category constructors
 * @since 1.0.0
 */
export const make: (options: Options) => Effect.Effect<OAuthProviderConfig, DiscoveryError, HttpClient.HttpClient> =
  Effect.fnUntraced(function* (options: Options) {
    // The same redirect-refusing client the flow itself runs on: a `.well-known`
    // that answers `302` must not become a server-side hop to an internal
    // address.
    const client = refuseRedirects(yield* HttpClient.HttpClient)
    const url = options.discoveryUrl ?? discoveryUrlOf(options.issuer)

    const response = yield* Effect.mapError(
      resilient(client.execute(HttpClientRequest.get(url, { acceptJson: true }))),
      () => failure(options.id, "Unreachable")
    )
    // Belt and braces: the client refuses redirects, and a redirect that reached
    // this far is still not a discovery document.
    if (isRedirectResponse(response) || response.status >= 400) {
      return yield* failure(options.id, "Unreachable")
    }

    const body = yield* Effect.mapError(jsonWithin(response, providerRequestTimeout), () =>
      failure(options.id, "Malformed")
    )
    const decoded = readDocument(body)
    if (Option.isNone(decoded)) return yield* failure(options.id, "Malformed")
    const document = decoded.value

    if (document.issuer === undefined) return yield* failure(options.id, "IssuerMissing")
    // Byte for byte, per OpenID Connect Discovery §4.3. A document is evidence
    // about the issuer it names and no other.
    if (document.issuer !== options.issuer) {
      return yield* failure(options.id, "IssuerMismatch")
    }

    const authorizationUrl = options.authorizationUrl ?? document.authorization_endpoint
    const tokenUrl = options.tokenUrl ?? document.token_endpoint
    if (authorizationUrl === undefined || tokenUrl === undefined) {
      return yield* failure(options.id, "EndpointsMissing")
    }

    const jwksUrl = options.jwksUrl ?? document.jwks_uri
    // Fail closed: "no keys" is not "skip the signature check". A pinned key set
    // is the one way to have no `jwks_uri` and still be verifiable — and it is
    // what the block's `keys` union is asking for, one of the two and never
    // neither.
    const keys: Oidc["keys"] | undefined =
      options.jwks !== undefined ? { jwks: options.jwks } : jwksUrl !== undefined ? { jwksUrl } : undefined
    if (keys === undefined) {
      return yield* failure(options.id, "KeysMissing")
    }

    const userInfoUrl = options.userInfoUrl ?? document.userinfo_endpoint
    const algorithms = options.algorithms ?? asymmetricAlgorithms(document.id_token_signing_alg_values_supported)

    const userInfo = Effect.fnUntraced(function* (tokens: OAuthTokens) {
      const claims = tokens.idTokenClaims
      // The provider carries an OIDC block, so the flow verified an `id_token`
      // before calling this. A null here would mean the OIDC path was skipped.
      if (claims === null) return yield* providerError(options.id, "IdTokenInvalid")

      const identity = identityOf(claims)
      if (identity !== null) return identity

      // No address in the token, and nowhere to ask for one.
      if (userInfoUrl === undefined) {
        return yield* providerError(options.id, "UserInfoFailed")
      }
      return yield* fetchIdentity({
        providerId: options.id,
        url: userInfoUrl,
        accessToken: tokens.accessToken,
        claims
      })
    })

    return {
      id: options.id,
      clientId: options.clientId,
      ...(options.clientSecret === undefined ? {} : { clientSecret: options.clientSecret }),
      authorizationUrl,
      tokenUrl,
      scopes: options.scopes ?? defaultScopes,
      // Discovery only ever builds an OIDC provider: the document it read is an
      // `openid-configuration`, and the issuer it declared has just been matched
      // byte for byte against the configured one.
      oidc: {
        issuer: document.issuer,
        ...(options.issuerOf === undefined ? {} : { issuerOf: options.issuerOf }),
        keys,
        ...(options.audience === undefined ? {} : { audience: options.audience }),
        ...(algorithms === undefined ? {} : { algorithms })
      },
      ...(options.redirectUri === undefined ? {} : { redirectUri: options.redirectUri }),
      ...(options.authorizationParams === undefined ? {} : { authorizationParams: options.authorizationParams }),
      ...(options.tokenRefresh === undefined ? {} : { tokenRefresh: options.tokenRefresh }),
      userInfo: options.userInfo ?? userInfo,
      accountId: options.accountId ?? ((info) => info.id)
    } satisfies OAuthProviderConfig
  })
