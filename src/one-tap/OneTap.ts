/**
 * Google One Tap, as a thin binding check in front of the verifier this library
 * already has.
 *
 * **Details**
 *
 * The credential a One Tap ceremony produces is an OIDC `id_token` signed by
 * Google — the same artefact the authorization-code flow receives on its
 * callback, arriving by a different road. So this module verifies nothing
 * itself. It checks the two things that are about *this browser* — the nonce
 * and, in redirect mode, the CSRF token — and then calls
 * `IdToken.verify` with the configured provider's own issuer, audience and key
 * source, hands the verified claims to that provider's own `userInfo` (which is
 * where a hosted-domain restriction is enforced), and finishes at
 * `Accounts.linkOAuth` and `SignIn.complete`. There is no second copy of any of
 * those rules, which is the entire design: a One Tap endpoint with a
 * verification path of its own is how a deployment ends up accepting tokens
 * minted for somebody else's Google application.
 *
 * **Gotchas — the two bindings**
 *
 * *The nonce is not optional.* A Google credential is a bearer token valid for
 * about an hour, and a page that hands one to an endpoint which does not check
 * a nonce has built a replay oracle: anybody who captures it — a shared device,
 * a proxy, a log — can present it again from anywhere until it expires. The
 * server mints the nonce, keeps it in a `__Host-` cookie the page cannot read,
 * and requires the token's `nonce` claim to equal it. `IdToken.verify` does
 * that comparison, and rejects a token that carries no `nonce` at all, which is
 * exactly what a replayed credential from another session looks like.
 *
 * *No tokens are stored.* A One Tap credential is not an OAuth grant: there is
 * no access token and no refresh token behind it. The identity handed to
 * `Accounts.linkOAuth` therefore states no `tokens` at all, so signing in this
 * way never overwrites the real credentials an authorization-code flow stored
 * for the same account.
 *
 * @since 0.2.0
 */
import { Context, DateTime, Duration, Effect, Layer, Option, Redacted } from "effect"
import { HttpClient } from "effect/unstable/http"
import { Token } from "../crypto/Token.js"
import type { OAuthIdentity } from "../domain/Accounts.js"
import { Accounts } from "../domain/Accounts.js"
import type { AccountAlreadyLinked, OAuthProviderError, UserNotFound } from "../domain/Errors.js"
import { oauthMethod } from "../domain/Events.js"
import type { PolicyRefused, ProvisionSource } from "../domain/Hooks.js"
import type { Evidence } from "../domain/Sessions.js"
import type { SignInResult } from "../domain/SignIn.js"
import { SignIn } from "../domain/SignIn.js"
import type { PersistenceError, SessionWithUser } from "../domain/Stores.js"
import type { KeyResolver } from "../oauth/IdToken.js"
import { Jwks, layerJwks, verify as verifyIdToken } from "../oauth/IdToken.js"
import { layerSafeClient, refuseRedirects } from "../oauth/Flow.js"
import type { OAuthProviderConfig, OAuthTokens, OAuthUserInfo } from "../oauth/Provider.js"
import { OAuthProviders, providerError, providerIssuer } from "../oauth/Provider.js"
import { withDefaults } from "../internal/records.js"
import { OneTapRejected } from "./Api.js"

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/**
 * The provider this plugin serves unless a deployment names another.
 *
 * @category constructors
 * @since 0.2.0
 */
export const defaultProviderId = "google"

/**
 * The cookie the nonce rides in, before any prefix.
 *
 * `__Host-effect_auth.onetap_nonce` on a TLS deployment. Host-only, because a
 * sibling subdomain that can set a cookie of this name onto the host that reads
 * it can choose the nonce, and a chosen nonce is no binding at all.
 *
 * @category constructors
 * @since 0.2.0
 */
export const nonceCookieBaseName = "effect_auth.onetap_nonce"

/**
 * The cookie Google's redirect mode writes its CSRF token into. Its name is
 * Google's, not ours.
 *
 * @category constructors
 * @since 0.2.0
 */
export const csrfCookieName = "g_csrf_token"

/**
 * The two spellings of Google's issuer.
 *
 * **Details**
 *
 * Google has minted `id_token`s claiming both `accounts.google.com` and
 * `https://accounts.google.com`, so a check that admits one of them refuses
 * legitimate credentials. Both are admitted here and **only** here: a provider
 * whose configured issuer is neither of these is checked against that one
 * string exactly, as the redirect flow checks it. Loosening this is not a
 * loosening of anything else — the signature is still Google's key, the
 * audience is still this deployment's client id.
 *
 * @category constructors
 * @since 0.2.0
 */
export const googleIssuers: ReadonlySet<string> = new Set(["accounts.google.com", "https://accounts.google.com"])

/**
 * What a One Tap ceremony proves.
 *
 * Possession of an account at the provider, and nothing more — the same
 * evidence the redirect flow records, because it is the same proof by a
 * different road. `oauth:<providerId>` has no registered `amr` value, which is
 * why the evidence is stored rather than translated.
 *
 * @category combinators
 * @since 0.2.0
 */
export const providerEvidence = (providerId: string): Evidence => ({
  method: oauthMethod(providerId),
  factor: "possession",
  phishingResistant: false,
  restricted: false
})

/** How long the provider's own `userInfo` may take, if it makes a request at all. */
const userInfoDeadline = Duration.seconds(10)

// -----------------------------------------------------------------------------
// Options
// -----------------------------------------------------------------------------

/**
 * What a deployment may vary about One Tap.
 *
 * @category models
 * @since 0.2.0
 */
export interface Config {
  /**
   * The registered OAuth provider whose credentials this endpoint accepts.
   * Defaults to `"google"`.
   *
   * **Gotchas**
   *
   * It must be an *OIDC* provider — one whose configuration carries an `oidc`
   * block — because that block is where the issuer, the audience and the key
   * source come from. A provider without one is `OneTapRejected`, not a
   * fallback to some other check.
   */
  readonly providerId: string
  /** How long a minted nonce may be used for. Defaults to ten minutes. */
  readonly nonceTtl: Duration.Duration
  /**
   * Require a nonce. Defaults to **`true`**, and turning it off is a real
   * decision.
   *
   * **Gotchas**
   *
   * Without it a captured credential replays for its whole lifetime from any
   * browser — which is what a One Tap endpoint that plumbs a nonce through and
   * never compares it amounts to. Off is for a deployment whose page genuinely
   * cannot round-trip one, and it should not exist for long.
   */
  readonly requireNonce: boolean
  /**
   * Which `ux_mode` the page runs. Defaults to `"popup"`.
   *
   * `"redirect"` additionally requires the `g_csrf_token` cookie and body field
   * to be present and equal, which is Google's own defence for a mode whose
   * response arrives as a cross-site form post.
   */
  readonly uxMode: "popup" | "redirect"
}

/**
 * {@link Config}, with every field optional.
 *
 * @category models
 * @since 0.2.0
 */
export interface Options {
  readonly providerId?: string | undefined
  readonly nonceTtl?: Duration.Duration | undefined
  readonly requireNonce?: boolean | undefined
  readonly uxMode?: "popup" | "redirect" | undefined
}

/**
 * The defaults every unstated {@link Options} field resolves to.
 *
 * @category constructors
 * @since 0.2.0
 */
export const defaults: Config = {
  providerId: defaultProviderId,
  nonceTtl: Duration.minutes(10),
  requireNonce: true,
  uxMode: "popup"
}

/**
 * Resolves {@link Options} against {@link defaults}.
 *
 * @category constructors
 * @since 0.2.0
 */
export const makeConfig = (options?: Options): Config => withDefaults(defaults, options)

// -----------------------------------------------------------------------------
// Models
// -----------------------------------------------------------------------------

/**
 * A minted nonce and when it stops being accepted.
 *
 * @category models
 * @since 0.2.0
 */
export interface IssuedNonce {
  readonly nonce: string
  readonly expiresAt: DateTime.Utc
}

/**
 * What {@link OneTapService.callback} takes.
 *
 * **Gotchas**
 *
 * The two `…Cookie` fields are read off the request by the handler and passed
 * in, rather than read here: the comparisons are the policy and belong in the
 * service, while reading a cookie is transport and belongs in the handler. It
 * is also what makes every one of these rules testable without an HTTP server.
 *
 * @category models
 * @since 0.2.0
 */
export interface CallbackOptions {
  /** The `credential` field of Google's `CredentialResponse`. */
  readonly credential: Redacted.Redacted
  /** The nonce the page says it used, if it sent one. */
  readonly nonce?: string | undefined
  /** The nonce out of this browser's `__Host-` cookie — the authority. */
  readonly expectedNonce?: string | undefined
  /** Google's `g_csrf_token` body field, in redirect mode. */
  readonly csrfToken?: string | undefined
  /** Google's `g_csrf_token` cookie, in redirect mode. */
  readonly csrfCookie?: string | undefined
  readonly rememberMe?: boolean | undefined
  readonly ipAddress?: string | null | undefined
  readonly userAgent?: string | null | undefined
  /**
   * The session the request already carried, for the anonymous-merge seam.
   * `undefined` on every ordinary sign-in.
   */
  readonly current?: SessionWithUser | undefined
}

/**
 * Everything a callback can fail with that is not persistence.
 *
 * @category models
 * @since 0.2.0
 */
export type CallbackError = OneTapRejected | OAuthProviderError | AccountAlreadyLinked | UserNotFound | PolicyRefused

// -----------------------------------------------------------------------------
// Service
// -----------------------------------------------------------------------------

/**
 * The {@link OneTap} service definition.
 *
 * @category models
 * @since 0.2.0
 */
export interface OneTapService {
  /** The resolved configuration this instance was built with. */
  readonly config: Config

  /**
   * Mints a nonce for one ceremony.
   *
   * **Gotchas**
   *
   * Full token entropy from `Token`, which is the one seam randomness enters
   * this library — never `Math.random` and never `Random`, which is seedable.
   */
  readonly mintNonce: Effect.Effect<IssuedNonce>

  /**
   * Checks the browser bindings, verifies the credential through the OAuth
   * module, links the identity and completes the sign-in.
   *
   * **Details**
   *
   * In that order, deliberately. The bindings are about this deployment's own
   * cookies and cost nothing; the verification is where a credential is
   * believed; the link is where a *new account* may be created, and it runs
   * only once the token has been proved to be Google's and to have been minted
   * for this deployment.
   */
  readonly callback: (options: CallbackOptions) => Effect.Effect<SignInResult, CallbackError | PersistenceError>
}

/**
 * Google One Tap. See {@link OneTapService}.
 *
 * @category services
 * @since 0.2.0
 */
export class OneTap extends Context.Service<OneTap, OneTapService>()("effect-auth/one-tap/OneTap") {}

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

/**
 * What {@link make} needs. {@link layer} provides {@link Jwks} itself, exactly
 * as `OAuthFlow.layer` does, so a consumer supplies an `HttpClient` and the
 * provider registry.
 *
 * @category models
 * @since 0.2.0
 */
export type Requirements = OAuthProviders | Accounts | SignIn | Token | Jwks | HttpClient.HttpClient

/**
 * What every user this plugin signs in came from.
 *
 * `OAuth` with the provider's own id, and not a tag of its own: a hook
 * branching on the source must not have to know which road a Google identity
 * arrived by, and `Accounts.linkOAuth` is the same call either way.
 */
const sourceOf = (provider: OAuthProviderConfig, info: OAuthUserInfo): ProvisionSource => ({
  _tag: "OAuth",
  providerId: provider.id,
  info
})

/**
 * Builds the {@link OneTap} implementation.
 *
 * @category constructors
 * @since 0.2.0
 */
export const make: (options?: Options) => Effect.Effect<OneTapService, never, Requirements> = Effect.fnUntraced(
  function* (options?: Options) {
    const settings = makeConfig(options)
    const registry = yield* OAuthProviders
    const accounts = yield* Accounts
    const { complete: completeSignIn } = yield* SignIn
    const tokens = yield* Token
    const keySets = yield* Jwks
    const client = refuseRedirects(yield* HttpClient.HttpClient)

    const mintNonce = Effect.gen(function* () {
      const nonce = yield* tokens.generateToken
      const now = yield* DateTime.now
      return {
        // Not a stored secret: it is a value this server minted, echoed back
        // through Google, and compared against a cookie of this browser's. The
        // page has to be able to read it, which is why it is a plain string.
        nonce: Redacted.value(nonce),
        expiresAt: DateTime.addDuration(now, settings.nonceTtl)
      } satisfies IssuedNonce
    })

    /**
     * The issuer this token must claim.
     *
     * A function rather than a string so that Google's two spellings are both
     * admitted — see {@link googleIssuers}. Every other provider is compared
     * against its configured issuer exactly, which is what the redirect flow
     * does. A provider that names its own `issuerOf` keeps it.
     */
    const issuerFor = (oidc: NonNullable<OAuthProviderConfig["oidc"]>) => {
      if (oidc.issuerOf !== undefined) return oidc.issuerOf
      if (!googleIssuers.has(oidc.issuer)) return oidc.issuer
      return (claims: Readonly<Record<string, unknown>>): string | null =>
        typeof claims.iss === "string" && googleIssuers.has(claims.iss) ? claims.iss : null
    }

    const claimsOf = Effect.fnUntraced(function* (provider: OAuthProviderConfig, options: CallbackOptions) {
      const oidc = provider.oidc
      // Not an OIDC provider: there is no issuer, no audience and no key source
      // to check this credential against, and inventing one is exactly the
      // mistake this module exists not to make.
      if (oidc === undefined) return yield* OneTapRejected.make()
      const invalid = providerError(provider.id, "IdTokenInvalid")
      const source = oidc.keys
      const resolved: { readonly keys: KeyResolver; readonly jwksUrl: string | null } =
        "jwksUrl" in source
          ? { keys: yield* Effect.mapError(keySets.keys(source.jwksUrl), () => invalid), jwksUrl: source.jwksUrl }
          : { keys: source.jwks, jwksUrl: null }
      return yield* verifyIdToken({
        providerId: provider.id,
        token: options.credential,
        issuer: issuerFor(oidc),
        audience: oidc.audience ?? provider.clientId,
        keys: resolved.keys,
        // The binding. `verify` refuses a token whose `nonce` claim is absent or
        // different, which is what a credential minted for another browser is.
        nonce: options.expectedNonce ?? null,
        ...(resolved.jwksUrl === null
          ? {}
          : { freshKeys: Effect.mapError(keySets.refresh(resolved.jwksUrl), () => invalid) }),
        ...(oidc.algorithms === undefined ? {} : { algorithms: oidc.algorithms })
      })
    })

    /** The two checks that are about this browser rather than about the token. */
    const checkBindings = Effect.fnUntraced(function* (options: CallbackOptions) {
      if (settings.requireNonce && (options.expectedNonce === undefined || options.expectedNonce.length === 0)) {
        return yield* OneTapRejected.make()
      }
      // A page that sent its own copy has to agree with the cookie. It is not
      // the authoritative comparison — that one is inside `IdToken.verify`,
      // against what Google signed — but disagreeing here means the ceremony
      // and this browser are not the same ceremony.
      if (options.nonce !== undefined && options.nonce !== options.expectedNonce) {
        return yield* OneTapRejected.make()
      }
      if (settings.uxMode === "redirect" || options.csrfToken !== undefined || options.csrfCookie !== undefined) {
        const token = options.csrfToken
        const cookie = options.csrfCookie
        if (token === undefined || cookie === undefined || token.length === 0 || token !== cookie) {
          return yield* OneTapRejected.make()
        }
      }
    })

    const callback = Effect.fnUntraced(
      function* (options: CallbackOptions) {
        yield* checkBindings(options)
        const provider = yield* registry.get(settings.providerId)
        const claims = yield* claimsOf(provider, options)

        // The provider's *own* projection of a verified token: for Google that
        // is where the `hd` hosted-domain restriction is enforced and where the
        // subject and address are read. One Tap reads no claim itself.
        const tokensForInfo: OAuthTokens = {
          // There is no access token in a One Tap ceremony. A provider that
          // needed one to answer would fail its own userinfo request, which is
          // the honest outcome — the alternative is inventing a credential.
          accessToken: Redacted.make(""),
          tokenType: null,
          refreshToken: null,
          idToken: options.credential,
          idTokenClaims: claims,
          accessTokenExpiresAt: null,
          refreshTokenExpiresAt: null,
          scope: null
        }
        const info = yield* Effect.provideService(
          provider.userInfo(tokensForInfo, { params: {} }),
          HttpClient.HttpClient,
          client
        ).pipe(
          Effect.timeout(userInfoDeadline),
          Effect.catchTag("TimeoutError", () => Effect.fail(providerError(provider.id, "ProviderUnavailable")))
        )
        const subject = provider.accountId(info)
        if (subject.length === 0 || info.email.length === 0) {
          return yield* providerError(provider.id, "UserInfoFailed")
        }

        const identity: OAuthIdentity = {
          providerId: provider.id,
          issuer: info.issuer ?? providerIssuer(provider),
          accountId: subject,
          email: info.email,
          emailVerified: info.emailVerified,
          name: info.name ?? info.email,
          image: info.image ?? null
          // No `tokens`: a One Tap credential is not an OAuth grant, and stating
          // an empty set here would wipe the access and refresh tokens a real
          // authorization-code flow stored for this same account.
        }
        const link = yield* accounts.linkOAuth(identity)

        return yield* completeSignIn({
          user: link.user,
          source: sourceOf(provider, info),
          evidence: [providerEvidence(provider.id)],
          current: Option.fromNullishOr(options.current),
          request: {
            ipAddress: options.ipAddress ?? null,
            userAgent: options.userAgent ?? null,
            rememberMe: options.rememberMe
          }
        })
      },
      (effect) => Effect.withSpan(effect, "OneTap.callback")
    )

    return OneTap.of({ config: settings, mintNonce, callback })
  }
)

/**
 * Provides {@link OneTap}.
 *
 * **Details**
 *
 * The JWKS cache is the plugin's own, provided here over the same
 * redirect-refusing client `OAuthFlow.layer` uses — so a deployment serving
 * both has two caches of one key set rather than a shared service it has to
 * wire. That is the arrangement `OAuthFlow` already chose, and matching it
 * keeps One Tap composable over a deployment that configured no OAuth flow at
 * all.
 *
 * @category layers
 * @since 0.2.0
 */
export const layer = (
  options?: Options
): Layer.Layer<OneTap, never, OAuthProviders | Accounts | SignIn | Token | HttpClient.HttpClient> =>
  Layer.effect(OneTap, make(options)).pipe(Layer.provide(layerJwks.pipe(Layer.provide(layerSafeClient))))
