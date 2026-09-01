/**
 * The identity an OIDC provider reports, as the default `userInfo` reads one.
 *
 * Every OIDC provider in this package resolves an identity the same way: the
 * verified `id_token` is the source, and the userinfo endpoint is consulted
 * only when the token carries no address. The two halves live here so that the
 * rule they share is stated once, and so a provider module is left with the one
 * thing that is actually its own — Google's hosted-domain check, Apple's name
 * from the first authorization.
 *
 * @internal
 */
import type { Redacted } from "effect"
import { Effect, Option, Schema } from "effect"
import type { HttpClient } from "effect/unstable/http"
import type { OAuthProviderError } from "../../domain/Errors.js"
import type { IdTokenClaims } from "../IdToken.js"
import type { OAuthUserInfo } from "../Provider.js"
import { fetchJson, providerError } from "../Provider.js"
import { lenient, Truthy } from "./claims.js"

/**
 * A userinfo body, as far as a default `userInfo` believes one. The address is
 * required — without one there is no identity — and everything else is
 * advisory.
 *
 * @internal
 */
export const UserInfoBody = Schema.Struct({
  email: Schema.NonEmptyString,
  email_verified: lenient(Truthy),
  name: lenient(Schema.NonEmptyString),
  picture: lenient(Schema.NonEmptyString)
})

const readUserInfo = Schema.decodeUnknownOption(UserInfoBody)

/**
 * The identity a verified `id_token` states on its own, or `null` when it
 * carries no address.
 *
 * **Details**
 *
 * `name` is the caller's own display name for this sign-in, for the one
 * provider that has one — Apple sends a name with the very first authorization
 * and never again. Everything else comes from the token: absent, the name falls
 * back to the token's `name` claim and then to the address.
 *
 * @internal
 */
export const identityOf = (claims: IdTokenClaims, name?: string | null): OAuthUserInfo | null =>
  claims.email === null
    ? null
    : {
        id: claims.subject,
        email: claims.email,
        emailVerified: claims.emailVerified,
        name: name ?? claims.name ?? claims.email,
        image: claims.picture
      }

/**
 * The identity a provider's userinfo endpoint reports, for a token that carried
 * no address.
 *
 * **Gotchas**
 *
 * The subject stays the one the signature covered. A userinfo body is only
 * bearer-authenticated — an access token is enough to obtain it — while the
 * `id_token` is signed, so the body may state the address and the advisory
 * fields and never the identity: a `sub` read out of it would be an identity
 * chosen by whoever holds the token. The claims win over the body for `name`
 * and `image` for the same reason.
 *
 * @internal
 */
export const fetchIdentity = (options: {
  readonly providerId: string
  readonly url: string
  readonly accessToken: Redacted.Redacted
  readonly claims: IdTokenClaims
}): Effect.Effect<OAuthUserInfo, OAuthProviderError, HttpClient.HttpClient> =>
  Effect.gen(function* () {
    const response = yield* fetchJson({
      providerId: options.providerId,
      url: options.url,
      accessToken: options.accessToken
    })
    const decoded = readUserInfo(response.body)
    if (Option.isNone(decoded)) return yield* providerError(options.providerId, "UserInfoFailed")
    const body = decoded.value
    const claims = options.claims
    return {
      id: claims.subject,
      email: body.email,
      emailVerified: body.email_verified !== undefined,
      name: claims.name ?? body.name ?? body.email,
      image: claims.picture ?? body.picture ?? null
    } satisfies OAuthUserInfo
  })
