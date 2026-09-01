/**
 * The HTTP contract of the Google One Tap plugin.
 *
 * Two endpoints under `/auth/one-tap`: mint a nonce, and hand back the
 * credential Google's script produced with it.
 *
 * **Details**
 *
 * **One Tap is not a new authentication method.** The credential is an OIDC
 * `id_token`, and this plugin's whole job is to check who it was minted for and
 * then hand it to the two things that already exist — `IdToken.verify` and
 * `Accounts.linkOAuth`. There is no signature code, no JWKS fetch and no claim
 * mapping of its own anywhere in this module or its siblings; if there ever is,
 * a mistake has been made. The same path serves Sign in with Apple JS.
 *
 * This module is import-safe from a browser, exactly as `email-otp/Api.ts` is.
 *
 * @since 0.2.0
 */
import { Schema } from "effect"
import { HttpApi, HttpApiEndpoint, HttpApiGroup, OpenApi } from "effect/unstable/httpapi"
import { AccountAlreadyLinked, OAuthProviderError, RateLimited, UserNotFound } from "../domain/Errors.js"
import { PolicyRefused } from "../domain/Hooks.js"
import { SessionWithUser } from "../domain/Schema.js"
import { MfaRequired } from "../http/AuthApi.js"
import { OriginNotAllowed } from "../http/OriginCheck.js"

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/**
 * The credential was not the one this browser asked for.
 *
 * **Details**
 *
 * One opaque answer for every way the *binding* can be wrong: no nonce cookie,
 * a nonce that does not match the one this browser was given, a redirect-mode
 * post whose `g_csrf_token` body field does not match its cookie, or a
 * deployment whose configured provider is not an OIDC one at all. What the
 * token itself is wrong about — a forged signature, an audience minted for
 * somebody else's Google application, an expired `exp`, a hosted domain the
 * provider config does not admit — stays `OAuthProviderError`, which is the
 * same answer the redirect flow gives for the same token.
 *
 * Telling the two apart is deliberate and safe: the first is about this
 * deployment's own cookie, the second about a credential the caller supplied.
 * Telling apart the *reasons within* either is not, and neither does.
 *
 * @category errors
 * @since 0.2.0
 */
export class OneTapRejected extends Schema.TaggedError<OneTapRejected>("effect-auth/one-tap/OneTapRejected")(
  "OneTapRejected",
  {},
  {
    description: "The credential was not the one this browser asked for",
    httpApiStatus: 401
  }
) {}

// -----------------------------------------------------------------------------
// Payloads
// -----------------------------------------------------------------------------

/** A compact JWS is a few hundred bytes; this is a bound, not a size. */
const bounded = (maxLength: number) =>
  Schema.String.pipe(Schema.check(Schema.isMinLength(1), Schema.isMaxLength(maxLength)))

/**
 * The credential Google's script hands the page.
 *
 * @category models
 * @since 0.2.0
 */
export const InputCredential = Schema.Redacted(bounded(8192))

/**
 * The body of `POST /auth/one-tap/callback`.
 *
 * @category models
 * @since 0.2.0
 */
export const OneTapCallbackPayload = Schema.Struct({
  /** The `credential` field of Google's `CredentialResponse`. */
  credential: InputCredential,
  /**
   * The nonce the page passed to `google.accounts.id.initialize`.
   *
   * **Gotchas**
   *
   * Optional, and never the authority: what the token's `nonce` claim is
   * checked against is the value in this browser's `__Host-` cookie, which a
   * page cannot read and an attacker on another origin cannot set. Sending it
   * is a courtesy that turns "the page used the wrong nonce" into a clear
   * refusal instead of a signature-shaped one.
   */
  nonce: Schema.optional(bounded(256)),
  /**
   * Google's `g_csrf_token` form field, for a deployment running
   * `ux_mode: "redirect"`.
   *
   * **Gotchas**
   *
   * Google posts that mode's response as `application/x-www-form-urlencoded`
   * with `credential` and `g_csrf_token` fields, which is not this endpoint's
   * media type: the deployment's own landing route receives the form post and
   * forwards both values here. When `Options.uxMode` is `"redirect"` this field
   * and the `g_csrf_token` cookie must both be present and equal.
   */
  csrfToken: Schema.optional(bounded(256)),
  /**
   * How long the session this mints should outlive the browser. Defaults to
   * `true`, as every other sign-in door in this library does.
   *
   * **Gotchas**
   *
   * One Tap is a sign-in, and a sign-in is where that choice is made; the two
   * `verify` endpoints of other plugins that raise an *existing* session take
   * no such field, because the session already made it.
   */
  rememberMe: Schema.optional(Schema.Boolean)
})

/**
 * The type of a {@link OneTapCallbackPayload}.
 *
 * @category models
 * @since 0.2.0
 */
export type OneTapCallbackPayload = typeof OneTapCallbackPayload.Type

/**
 * What `GET /auth/one-tap/nonce` answers.
 *
 * **Gotchas**
 *
 * The nonce is in the body *and* in a `__Host-` cookie, and the two halves do
 * different jobs: the body copy is what the page passes to
 * `google.accounts.id.initialize` so that Google signs it into the token, and
 * the cookie copy is what the server compares against and a page cannot read.
 * It is not a secret — it is a binding — which is why it may be in a body at
 * all.
 *
 * @category models
 * @since 0.2.0
 */
export const OneTapNonce = Schema.Struct({
  nonce: Schema.String,
  expiresAt: Schema.DateTimeUtcFromString
})

/**
 * The type of a {@link OneTapNonce}.
 *
 * @category models
 * @since 0.2.0
 */
export type OneTapNonce = typeof OneTapNonce.Type

// -----------------------------------------------------------------------------
// Group
// -----------------------------------------------------------------------------

/**
 * The path every endpoint of this plugin is served under.
 *
 * @category constructors
 * @since 0.2.0
 */
export const oneTapPrefix = "/auth/one-tap"

/**
 * The two endpoints the One Tap plugin serves.
 *
 * **Details**
 *
 * Neither carries the `Authenticated` middleware: a One Tap credential *is* the
 * credential, and the endpoint that mints a nonce has to be reachable by
 * somebody who cannot sign in at all.
 *
 * @category models
 * @since 0.2.0
 */
export class OneTapApiGroup extends HttpApiGroup.make("oneTap")
  .add(
    HttpApiEndpoint.get("nonce", "/nonce", {
      success: OneTapNonce,
      error: RateLimited
    }).annotateMerge(
      OpenApi.annotations({
        summary: "Mint a nonce for a One Tap ceremony",
        description:
          "Answers a fresh nonce and sets the same value in a __Host- cookie. The page passes the body copy to google.accounts.id.initialize; the callback compares the token's nonce claim against the cookie, which is what stops a credential minted for one browser from being replayed from another. Without this, a One Tap credential is replayable for its whole lifetime."
      })
    ),
    HttpApiEndpoint.post("callback", "/callback", {
      payload: OneTapCallbackPayload,
      success: [SessionWithUser, MfaRequired],
      error: [
        OneTapRejected,
        OAuthProviderError,
        AccountAlreadyLinked,
        UserNotFound,
        PolicyRefused,
        OriginNotAllowed,
        RateLimited
      ]
    }).annotateMerge(
      OpenApi.annotations({
        summary: "Sign in with a One Tap credential",
        description:
          "Checks the nonce against this browser's cookie, then hands the credential to the same id_token verifier and the same account-linking rules the redirect flow uses — including the provider's hosted-domain restriction. Success is the two-status union: 200 with the session and its user, or 202 with MfaRequired when a factor plugin owes a second factor, in which case the pending-authentication token is set and no session cookie is written."
      })
    )
  )
  .prefix(oneTapPrefix)
  .annotateMerge(
    OpenApi.annotations({
      title: "Google One Tap",
      description: "Sign in with a Google-issued ID token, verified by the OAuth module that already verifies them."
    })
  ) {}

/**
 * The One Tap endpoints as a standalone `HttpApi`.
 *
 * @category models
 * @since 0.2.0
 */
export const OneTapApi = HttpApi.make("effect-auth-one-tap").add(OneTapApiGroup)
