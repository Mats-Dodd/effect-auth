/**
 * The HTTP contract of the magic link plugin.
 *
 * Three endpoints under `/auth/magic-link`: ask for a link, follow one from a
 * browser, and exchange one for a session from a client that would rather have
 * JSON than a redirect.
 *
 * This module is import-safe from a browser, exactly as `http/AuthApi.ts` is: it
 * pulls in schemas and the group declaration, never a store, a mailer or a node
 * builtin. It is what `MagicLinkClient` and the server implementation share.
 *
 * @since 0.1.0
 */
import { Schema } from "effect"
import { HttpApi, HttpApiEndpoint, HttpApiGroup, OpenApi } from "effect/unstable/httpapi"
import { InvalidToken, RateLimited } from "../domain/Errors.js"
import { PolicyRefused } from "../domain/Hooks.js"
import { Email, SessionWithUser } from "../domain/Schema.js"
import { InputName, InputToken, InputUrl, Ok, Redirect, Secret } from "../http/AuthApi.js"

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/**
 * The deployment does not create accounts from magic links, and the address the
 * link names has none.
 *
 * **Gotchas**
 *
 * Reachable only from `exchange`, the JSON twin. The browser endpoint answers
 * every failure with a redirect carrying `?error=sign_up_disabled`, because a
 * person who followed a link out of their mailbox has to land on a page.
 *
 * Asking for a link to an unknown address under `disableSignUp` still answers
 * `200` and sends nothing: the refusal happens where the token is spent, never
 * where it is requested, so the request endpoint stays free of an enumeration
 * oracle.
 *
 * @category errors
 * @since 0.1.0
 */
export class SignUpDisabled extends Schema.TaggedError<SignUpDisabled>("effect-auth/magic-link/SignUpDisabled")(
  "SignUpDisabled",
  {},
  {
    description: "This deployment does not create accounts from magic links",
    httpApiStatus: 403
  }
) {}

// -----------------------------------------------------------------------------
// Payloads
// -----------------------------------------------------------------------------

/**
 * The body of `POST /auth/magic-link/sign-in`.
 *
 * **Details**
 *
 * Every URL here is validated against `trustedOrigins` before it is stored in
 * the token's payload, and one that does not survive that is dropped rather than
 * refused — the link is worth sending without it. None of them is ever echoed
 * back to the caller.
 *
 * @category models
 * @since 0.1.0
 */
export const MagicLinkSignInPayload = Schema.Struct({
  email: Email,
  /**
   * The display name to give the account, if this link ends up creating one.
   * Ignored for an address that already has one.
   */
  name: Schema.optional(InputName),
  /** Where to land after the link is followed. */
  callbackURL: Schema.optional(InputUrl),
  /** Where to land instead when the link created the account. */
  newUserCallbackURL: Schema.optional(InputUrl),
  /** Where to land when following the link fails. */
  errorCallbackURL: Schema.optional(InputUrl),
  /** When `false` the session the link establishes expires in a day. */
  rememberMe: Schema.optional(Schema.Boolean)
})

/**
 * The type of a {@link MagicLinkSignInPayload}.
 *
 * @category models
 * @since 0.1.0
 */
export type MagicLinkSignInPayload = typeof MagicLinkSignInPayload.Type

/**
 * The query string of `GET /auth/magic-link/verify`.
 *
 * **Gotchas**
 *
 * A plain `string` rather than a {@link Secret}: query strings do not go through
 * the JSON codec, so there is no transformation to hang the redaction on. The
 * handler wraps it with `Redacted.make` as its first act.
 *
 * @category models
 * @since 0.1.0
 */
export const MagicLinkVerifyQuery = Schema.Struct({
  token: InputToken
})

/**
 * The type of a {@link MagicLinkVerifyQuery}.
 *
 * @category models
 * @since 0.1.0
 */
export type MagicLinkVerifyQuery = typeof MagicLinkVerifyQuery.Type

/**
 * The body of `POST /auth/magic-link/exchange`.
 *
 * @category models
 * @since 0.1.0
 */
export const MagicLinkExchangePayload = Schema.Struct({
  token: Secret
})

/**
 * The type of a {@link MagicLinkExchangePayload}.
 *
 * @category models
 * @since 0.1.0
 */
export type MagicLinkExchangePayload = typeof MagicLinkExchangePayload.Type

// -----------------------------------------------------------------------------
// Group
// -----------------------------------------------------------------------------

/**
 * The path every endpoint of this plugin is served under.
 *
 * **Gotchas**
 *
 * Baked into the group, and not changeable with `HttpApi.prefix` — that rewrites
 * the endpoint paths in the type, so the result no longer satisfies the
 * `groups.magicLink` constraint `MagicLink.handlers` and `MagicLinkClient.make`
 * check against. See `AuthApi`'s own note: mounting the server elsewhere is a
 * deployment concern, and `AuthConfig.basePath` is how the library is told.
 *
 * @category constructors
 * @since 0.1.0
 */
export const magicLinkPrefix = "/auth/magic-link"

/**
 * The three endpoints the magic link plugin serves.
 *
 * **Details**
 *
 * A class, for the same two reasons `AuthApiGroup` is one: it is the shape a
 * consumer's `groups.magicLink` constraint names, and it keeps the inferred group
 * type behind a single named declaration in the emitted types.
 *
 * None of the three carries the `Authenticated` middleware. A magic link *is* the
 * credential: requiring a session to spend one would defeat the flow, and the
 * request endpoint has to be reachable by somebody who cannot sign in at all.
 *
 * @category models
 * @since 0.1.0
 */
export class MagicLinkApiGroup extends HttpApiGroup.make("magicLink")
  .add(
    HttpApiEndpoint.post("signIn", "/sign-in", {
      payload: MagicLinkSignInPayload,
      success: Ok,
      error: RateLimited
    }).annotateMerge(
      OpenApi.annotations({
        summary: "Send a sign-in link to an e-mail address",
        description:
          "Always answers 200 for a well-formed address, whether or not it has an account and whether or not the message could be delivered: a distinguishable answer would tell an unauthenticated caller who is registered here. With disableSignUp on, an address with no account is answered identically and sent nothing."
      })
    ),
    HttpApiEndpoint.get("verify", "/verify", {
      query: MagicLinkVerifyQuery,
      success: Redirect,
      error: RateLimited
    }).annotateMerge(
      OpenApi.annotations({
        summary: "Follow a sign-in link",
        description:
          "Claims the single-use token, establishes the session, sets the cookie and redirects. Every failure is a redirect too — to the errorCallbackURL the link was minted with, carrying ?error=invalid_token or ?error=sign_up_disabled — because the person arrived here by a top-level browser navigation and has to land on a page. A deployment hook that refuses the account or the session redirects to that same errorCallbackURL carrying ?error=policy_refused&code=..., with the code that hook chose; the link is spent either way."
      })
    ),
    HttpApiEndpoint.post("exchange", "/exchange", {
      payload: MagicLinkExchangePayload,
      success: SessionWithUser,
      error: [InvalidToken, SignUpDisabled, PolicyRefused, RateLimited]
    }).annotateMerge(
      OpenApi.annotations({
        summary: "Exchange a sign-in link's token for a session",
        description:
          "The JSON twin of verify, for a single-page application or a mobile client that would rather read a body than follow a redirect. It sets the session cookie as well, so a browser using it is signed in either way. PolicyRefused is a deployment's own hook declining the account this link would have created or the session it would have started, and carries the code that hook chose; it is raised only after the token has been claimed, so the link is spent whichever way it went."
      })
    )
  )
  .prefix(magicLinkPrefix)
  .annotateMerge(
    OpenApi.annotations({
      title: "Magic link",
      description: "Passwordless sign-in by a single-use link sent to an e-mail address."
    })
  ) {}

/**
 * The magic link endpoints as a standalone `HttpApi`.
 *
 * **When to use**
 *
 * As the client's declaration — `MagicLinkClient.make` builds against this — and
 * as a compact way to serve the plugin on its own. An application that composes
 * its own API adds the *group* to it instead:
 *
 * **Example**
 *
 * ```ts
 * import { HttpApi } from "effect/unstable/httpapi"
 * import { AuthApi } from "effect-auth"
 * import { MagicLink } from "effect-auth"
 *
 * const AppApi = HttpApi.make("app").addHttpApi(AuthApi).add(MagicLink.MagicLinkApiGroup)
 * ```
 *
 * @category models
 * @since 0.1.0
 */
export const MagicLinkApi = HttpApi.make("effect-auth-magic-link").add(MagicLinkApiGroup)
