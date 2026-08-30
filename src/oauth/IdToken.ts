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
import { DateTime, Effect, Redacted } from "effect"
import type { JWTPayload, JWTVerifyGetKey } from "jose"
import { createRemoteJWKSet, customFetch, jwtVerify } from "jose"
import type { OAuthProviderError } from "../domain/Errors.js"
import { OAuthProviderError as ProviderError } from "../domain/Errors.js"

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
   * Provider-controlled keys. Read it with `Object.hasOwn`, never with `in`,
   * and never enumerate it with `for...in`.
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
// Remote key sets
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

const jwksCache = new Map<string, KeyResolver>()

/**
 * A JWKS resolver for a provider's `jwks_uri`, cached per URL.
 *
 * **Details**
 *
 * `jose` keeps its own key cache and cooldown behind the returned function, so
 * reusing one resolver per URL is what stops every callback from fetching the
 * key set again. The fetch refuses HTTP redirects for the same reason the token
 * exchange does: a `jwks_uri` that can bounce the server elsewhere is an SSRF
 * primitive, and a JWKS served from the redirect target would sign whatever the
 * attacker wants.
 *
 * **Gotchas**
 *
 * This one call goes through the platform `fetch` rather than the ambient
 * `HttpClient`: `jose` owns the request. Pass `fetchImpl` to intercept it.
 *
 * @category constructors
 * @since 1.0.0
 */
export const remoteKeys = (
  jwksUrl: string,
  fetchImpl?: typeof globalThis.fetch
): KeyResolver => {
  const cached = jwksCache.get(jwksUrl)
  if (fetchImpl === undefined && cached !== undefined) return cached
  const perform = fetchImpl ?? globalThis.fetch
  const resolver = createRemoteJWKSet(new URL(jwksUrl), {
    [customFetch]: async (url, options) => {
      const response = await perform(url, { ...options, redirect: "manual" })
      if (isRedirectResponse(response)) {
        throw new Error("effect-auth: the JWKS endpoint answered with a redirect, which is refused")
      }
      return response
    }
  })
  if (fetchImpl === undefined) jwksCache.set(jwksUrl, resolver)
  return resolver
}

// -----------------------------------------------------------------------------
// Verification
// -----------------------------------------------------------------------------

const stringClaim = (payload: JWTPayload, key: string): string | null => {
  if (!Object.hasOwn(payload, key)) return null
  const value = payload[key]
  return typeof value === "string" && value.length > 0 ? value : null
}

const booleanClaim = (payload: JWTPayload, key: string): boolean => {
  if (!Object.hasOwn(payload, key)) return false
  const value = payload[key]
  // Several providers encode the flag as the string "true".
  return value === true || value === "true"
}

const audienceOf = (payload: JWTPayload): ReadonlyArray<string> => {
  const value = payload.aud
  if (typeof value === "string") return [value]
  if (Array.isArray(value)) return value.filter((entry): entry is string => typeof entry === "string")
  return []
}

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
  const subject = stringClaim(payload, "sub")
  if (subject === null) return yield* Effect.fail(invalid)

  const nonce = stringClaim(payload, "nonce")
  if (options.nonce !== null && nonce !== options.nonce) {
    return yield* Effect.fail(invalid)
  }

  const expiresAt = typeof payload.exp === "number" ? DateTime.fromEpochSeconds(payload.exp) : null
  if (expiresAt === null) return yield* Effect.fail(invalid)

  const claims: IdTokenClaims = {
    subject,
    issuer: options.issuer,
    audience: audienceOf(payload),
    email: stringClaim(payload, "email"),
    emailVerified: booleanClaim(payload, "email_verified"),
    name: stringClaim(payload, "name"),
    picture: stringClaim(payload, "picture"),
    nonce,
    expiresAt,
    raw: payload
  }
  return claims
})

/**
 * The type {@link verify} answers with.
 *
 * @category models
 * @since 1.0.0
 */
export type Verified = Effect.Effect<IdTokenClaims, OAuthProviderError>
