/**
 * OIDC `id_token` verification, fail-closed.
 *
 * An `id_token` is the only part of an OAuth callback that asserts *who* the
 * person is without a further round trip, which is exactly why it is the part
 * an attacker would like to forge. This module is the single place a token is
 * turned into claims, and it accepts one only when every one of the following
 * holds:
 *
 * - the signature verifies against a key from the provider's JWKS;
 * - `iss` equals the provider's configured issuer;
 * - `aud` contains our client id;
 * - `exp` is in the future by the Effect clock (so `TestClock` drives it);
 * - `sub` is present and non-empty;
 * - `nonce` equals the nonce minted for this authorization request, whenever
 *   one was minted.
 *
 * Anything else — a malformed token, an unreachable JWKS, a missing claim, an
 * unexpected algorithm — is `OAuthProviderError({ reason: "IdTokenInvalid" })`.
 * There is deliberately no path that reports "could not check" as success.
 *
 * @since 1.0.0
 */
import { Cache, Context, DateTime, Duration, Effect, Exit, Layer, Redacted, Schema } from "effect"
import { HttpClient, HttpClientRequest } from "effect/unstable/http"
import type { JWTPayload, JWTVerifyGetKey } from "jose"
import { createLocalJWKSet, jwtVerify } from "jose"
import { OAuthProviderError as ProviderError } from "../domain/Errors.js"
import { lenient, Truthy } from "./internal/claims.js"

// -----------------------------------------------------------------------------
// Models
// -----------------------------------------------------------------------------

/**
 * Resolves the signing key for a token — `jose`'s `createRemoteJWKSet` or
 * `createLocalJWKSet` result.
 *
 * @category models
 * @since 1.0.0
 */
export type KeyResolver = JWTVerifyGetKey

/**
 * The claims of an `id_token` that has passed every check.
 *
 * @category models
 * @since 1.0.0
 */
export interface IdTokenClaims {
  /** `sub` — the provider's stable subject, and the account's identity half. */
  readonly subject: string
  /** `iss`, as verified against the provider's configured issuer. */
  readonly issuer: string
  /** `aud`, normalized to a list. */
  readonly audience: ReadonlyArray<string>
  /** `email`, when the provider put one in the token. */
  readonly email: string | null
  /** `email_verified`. `false` unless the claim says otherwise. */
  readonly emailVerified: boolean
  /** `name`, when present. */
  readonly name: string | null
  /** `picture`, when present. */
  readonly picture: string | null
  /** `nonce`, when present. Already compared against the expected value. */
  readonly nonce: string | null
  /** `exp`, as an instant. */
  readonly expiresAt: DateTime.Utc
  /**
   * The whole verified payload.
   *
   * **Gotchas**
   *
   * Provider-controlled keys. Read it with a `Schema` decoder, never by walking
   * the object, and never enumerate it with `for...in`.
   */
  readonly raw: JWTPayload
}

/**
 * What {@link verify} needs.
 *
 * @category models
 * @since 1.0.0
 */
export interface VerifyOptions {
  /** Named only so a failure can say which provider it came from. */
  readonly providerId: string
  /** The compact JWS handed back by the token endpoint. */
  readonly token: Redacted.Redacted<string>
  /** The issuer the token must claim. */
  readonly issuer: string
  /** The audience the token must carry — our OAuth client id. */
  readonly audience: string
  /** Where the verification key comes from. */
  readonly keys: KeyResolver
  /**
   * The nonce minted when this authorization request started, or `null` when
   * none was.
   *
   * **Gotchas**
   *
   * When this is a string the token *must* carry an equal `nonce` claim. A
   * token that omits it is rejected: an omitted nonce is precisely what a
   * replayed token from another session looks like.
   */
  readonly nonce: string | null
  /** Accepted JWS algorithms. Defaults to whatever the resolved key admits. */
  readonly algorithms?: ReadonlyArray<string> | undefined
  /** Clock skew allowance for `exp` and `nbf`, in seconds. Default 0. */
  readonly clockToleranceSeconds?: number | undefined
}

// -----------------------------------------------------------------------------
// Refusing a redirected JWKS
// -----------------------------------------------------------------------------

const redirectStatuses: ReadonlySet<number> = new Set([301, 302, 303, 307, 308])

/**
 * Whether a response fetched with `redirect: "manual"` is in fact a redirect.
 *
 * **Details**
 *
 * Node and undici expose the real 3xx status. Spec-compliant runtimes (Deno,
 * Cloudflare Workers, browsers) hand back an opaque filtered response with
 * status `0` and type `"opaqueredirect"` instead, so the status alone does not
 * settle it.
 *
 * @category guards
 * @since 1.0.0
 */
export const isRedirectResponse = (response: {
  readonly status: number
  readonly type?: string
}): boolean => response.type === "opaqueredirect" || response.status === 0 || redirectStatuses.has(response.status)

// -----------------------------------------------------------------------------
// Remote key sets
// -----------------------------------------------------------------------------

/**
 * A provider's `jwks_uri` could not be turned into a usable key set.
 *
 * **Gotchas**
 *
 * This never reaches a caller of the flow: `OAuthFlow` maps it straight to
 * `OAuthProviderError({ reason: "IdTokenInvalid" })`, because "we could not
 * check the signature" and "the signature is wrong" must be the same answer.
 *
 * @category errors
 * @since 1.0.0
 */
export class JwksUnavailable
  extends Schema.TaggedError<JwksUnavailable>("effect-auth/JwksUnavailable")("JwksUnavailable", {
    jwksUrl: Schema.String
  }, {
    description: "A provider's JWKS endpoint could not be read"
  })
{}

/**
 * One key of a JSON Web Key Set, as a provider publishes it.
 *
 * **Gotchas**
 *
 * Only the public parameters are read. A key set that carries private material
 * — `d`, `p`, `q` — has it dropped here rather than handed to `jose`.
 */
const JsonWebKey = Schema.Struct({
  kty: Schema.optionalKey(Schema.String),
  alg: Schema.optionalKey(Schema.String),
  use: Schema.optionalKey(Schema.String),
  kid: Schema.optionalKey(Schema.String),
  crv: Schema.optionalKey(Schema.String),
  e: Schema.optionalKey(Schema.String),
  n: Schema.optionalKey(Schema.String),
  x: Schema.optionalKey(Schema.String),
  y: Schema.optionalKey(Schema.String),
  pub: Schema.optionalKey(Schema.String),
  x5c: Schema.optionalKey(Schema.mutable(Schema.Array(Schema.String))),
  x5t: Schema.optionalKey(Schema.String),
  "x5t#S256": Schema.optionalKey(Schema.String),
  x5u: Schema.optionalKey(Schema.String),
  key_ops: Schema.optionalKey(Schema.mutable(Schema.Array(Schema.String))),
  ext: Schema.optionalKey(Schema.Boolean)
})

const JsonWebKeySet = Schema.Struct({
  keys: Schema.mutable(Schema.Array(JsonWebKey))
})

const decodeKeySet = Schema.decodeUnknownEffect(JsonWebKeySet)

/**
 * How long a fetched key set is reused, and how many providers' key sets are
 * kept at once.
 *
 * @category models
 * @since 1.0.0
 */
export interface JwksOptions {
  /**
   * How long a successfully fetched key set is served from memory.
   *
   * **Gotchas**
   *
   * A provider that rotates its signing keys publishes the new one well before
   * it signs with it, so a stale window of minutes is safe; a window of hours
   * is not. Failures are never cached, so an unreachable endpoint is retried on
   * the next callback rather than after this duration.
   *
   * @default "10 minutes"
   */
  readonly timeToLive?: Duration.Input | undefined
  /**
   * How many distinct `jwks_uri`s are kept. One per OIDC provider.
   *
   * @default 16
   */
  readonly capacity?: number | undefined
}

/**
 * The {@link Jwks} service definition: a provider's published signing keys,
 * fetched over the ambient `HttpClient` and cached per URL.
 *
 * @category models
 * @since 1.0.0
 */
export interface JwksService {
  /**
   * The key resolver for a `jwks_uri`.
   *
   * **Details**
   *
   * Concurrent callbacks for the same provider share one fetch, and the
   * resulting key set is reused for {@link JwksOptions.timeToLive}. A failed
   * fetch is not cached.
   */
  readonly keys: (jwksUrl: string) => Effect.Effect<KeyResolver, JwksUnavailable>
}

/**
 * A provider's published signing keys.
 *
 * **Details**
 *
 * The fetch goes over the `HttpClient` this service was built with — the flow
 * hands it the same redirect-refusing client the token exchange runs on, so a
 * `jwks_uri` that answers `302` cannot bounce a server-side request at an
 * internal address and serve keys from the target.
 *
 * @category services
 * @since 1.0.0
 */
export class Jwks extends Context.Service<Jwks, JwksService>()("effect-auth/Jwks") {}

/**
 * How long a JWKS fetch is given before it is treated as unreachable.
 *
 * @category constructors
 * @since 1.0.0
 */
export const jwksRequestTimeout: Duration.Duration = Duration.seconds(10)

/**
 * Builds the {@link Jwks} implementation.
 *
 * @category constructors
 * @since 1.0.0
 */
export const makeJwks: (
  options?: JwksOptions
) => Effect.Effect<JwksService, never, HttpClient.HttpClient> = Effect.fnUntraced(
  function*(options?: JwksOptions) {
    const client = yield* HttpClient.HttpClient
    const timeToLive = options?.timeToLive ?? Duration.minutes(10)

    const fetchKeys = Effect.fnUntraced(function*(jwksUrl: string) {
      const unavailable = new JwksUnavailable({ jwksUrl })
      const response = yield* Effect.mapError(
        Effect.timeout(client.execute(HttpClientRequest.get(jwksUrl, { acceptJson: true })), jwksRequestTimeout),
        () => unavailable
      )
      // Belt and braces: the client refuses redirects, and a redirect that
      // reached this far is still not a key set.
      if (isRedirectResponse(response) || response.status >= 400) return yield* Effect.fail(unavailable)
      const body = yield* Effect.mapError(Effect.timeout(response.json, jwksRequestTimeout), () => unavailable)
      const keySet = yield* Effect.mapError(decodeKeySet(body), () => unavailable)
      return yield* Effect.try({ try: () => createLocalJWKSet(keySet), catch: () => unavailable })
    })

    const cache = yield* Cache.makeWith(fetchKeys, {
      capacity: options?.capacity ?? 16,
      // Only a key set earns the cache. A provider that was unreachable once is
      // asked again on the next callback rather than refused for ten minutes.
      timeToLive: (exit: Exit.Exit<KeyResolver, JwksUnavailable>) => Exit.isSuccess(exit) ? timeToLive : Duration.zero
    })

    return Jwks.of({ keys: (jwksUrl) => Cache.get(cache, jwksUrl) })
  }
)

/**
 * Provides {@link Jwks} over the ambient `HttpClient`.
 *
 * @category layers
 * @since 1.0.0
 */
export const layerJwks: Layer.Layer<Jwks, never, HttpClient.HttpClient> = Layer.effect(Jwks, makeJwks())

/**
 * {@link layerJwks}, with the cache tuned.
 *
 * @category layers
 * @since 1.0.0
 */
export const layerJwksWith = (
  options: JwksOptions
): Layer.Layer<Jwks, never, HttpClient.HttpClient> => Layer.effect(Jwks, makeJwks(options))

// -----------------------------------------------------------------------------
// Verification
// -----------------------------------------------------------------------------

/**
 * The claims this module projects, and the only shapes they are believed in.
 *
 * `sub` and `exp` are load-bearing and required; everything else is advisory
 * and reads as absent when the provider spells it in some other way.
 */
const Claims = Schema.Struct({
  sub: Schema.NonEmptyString,
  exp: Schema.Finite,
  aud: lenient(Schema.Union([Schema.NonEmptyString, Schema.Array(Schema.String)])),
  email: lenient(Schema.NonEmptyString),
  email_verified: lenient(Truthy),
  name: lenient(Schema.NonEmptyString),
  picture: lenient(Schema.NonEmptyString),
  nonce: lenient(Schema.NonEmptyString)
})

const decodeClaims = Schema.decodeUnknownEffect(Claims)

const audienceOf = (aud: string | ReadonlyArray<string> | undefined): ReadonlyArray<string> =>
  aud === undefined ? [] : typeof aud === "string" ? [aud] : aud

/**
 * Verifies an `id_token` and projects its claims.
 *
 * **Details**
 *
 * `jose` performs the signature, `iss`, `aud`, `exp` and `nbf` checks; the
 * current time comes from the Effect clock, so a test can move a token past its
 * expiry with `TestClock`. The `sub` and `nonce` checks are done here, after
 * the signature, because an unverified claim is not evidence of anything.
 *
 * Every failure — a forged signature, an unreachable JWKS, a missing claim —
 * collapses to one opaque `IdTokenInvalid`: the caller is a browser coming back
 * from a provider, and telling it *which* check failed only helps somebody
 * probing the verifier.
 *
 * @category combinators
 * @since 1.0.0
 */
export const verify = Effect.fnUntraced(function*(options: VerifyOptions) {
  const invalid = new ProviderError({ providerId: options.providerId, reason: "IdTokenInvalid" })
  const now = yield* DateTime.now

  const verified = yield* Effect.tryPromise({
    try: () =>
      jwtVerify(Redacted.value(options.token), options.keys, {
        issuer: options.issuer,
        audience: options.audience,
        currentDate: DateTime.toDate(now),
        clockTolerance: options.clockToleranceSeconds ?? 0,
        ...(options.algorithms === undefined ? {} : { algorithms: [...options.algorithms] })
      }),
    catch: () => invalid
  })

  const payload = verified.payload
  const claims = yield* Effect.mapError(decodeClaims(payload), () => invalid)

  const nonce = claims.nonce ?? null
  if (options.nonce !== null && nonce !== options.nonce) {
    return yield* Effect.fail(invalid)
  }

  return {
    subject: claims.sub,
    issuer: options.issuer,
    audience: audienceOf(claims.aud),
    email: claims.email ?? null,
    emailVerified: claims.email_verified !== undefined,
    name: claims.name ?? null,
    picture: claims.picture ?? null,
    nonce,
    expiresAt: DateTime.fromEpochSeconds(claims.exp),
    raw: payload
  } satisfies IdTokenClaims
})
