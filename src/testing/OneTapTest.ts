/**
 * The Google One Tap plugin, wired into a test deployment.
 *
 * **Details**
 *
 * The one thing a One Tap harness has to arrange that a mail plugin's does not
 * is a *signing key*: the credential under test is a real compact JWS that the
 * real verifier has to accept or reject on its merits. `MockProvider`'s
 * `IdTokenSigner` already mints those against a key pair generated once per
 * layer, and {@link layerProviders} registers a Google provider whose
 * `oidc.keys` is that signer's local key set — so verification runs with no
 * network at all and a forged token really does fail the signature check.
 *
 * **Example**
 *
 * ```ts skip-type-checking
 * import { layer } from "@effect/vitest"
 * import { MockProvider, OneTapTest } from "effect-auth/testing"
 *
 * layer(OneTapTest.layerHttp())("one-tap", (it) => {
 *   it.effect("signs a Google account in", () =>
 *     Effect.gen(function*() {
 *       const credential = yield* OneTapTest.credential({ sub: "1", email: "ada@example.com", nonce })
 *     }))
 * })
 * ```
 *
 * **Gotchas**
 *
 * The client id the signer's tokens are addressed to is {@link testClientId},
 * and it is also the client id the registered provider carries. A test that
 * mints a token for anything else is testing the audience check, which is the
 * point of being able to.
 *
 * @since 0.2.0
 */
import type { PgliteClient } from "@effect/sql-pglite"
import { Effect, Layer, Redacted } from "effect"
import type { HttpApiGroup } from "effect/unstable/httpapi"
import { HttpApi } from "effect/unstable/httpapi"
import type { HttpClient } from "effect/unstable/http"
import type { Migrator, SqlClient, SqlError } from "effect/unstable/sql"
import type { JWTPayload } from "jose"
import type { Services } from "../config/Auth.js"
import { AuthApi } from "../http/AuthApi.js"
import { OneTapApiGroup } from "../one-tap/Api.js"
import { handlers as oneTapHandlers } from "../one-tap/Handlers.js"
import type { OneTap, Options as OneTapOptions } from "../one-tap/OneTap.js"
import { layer as oneTapLayer } from "../one-tap/OneTap.js"
import * as Google from "../oauth/providers/Google.js"
import { OAuthProviders } from "../oauth/Provider.js"
import { IdTokenSigner } from "./MockProvider.js"
import type { TestEmails } from "./TestEmails.js"
import * as AuthTest from "./TestLayer.js"

/**
 * The client id every token this harness mints is addressed to, and the one the
 * registered provider carries.
 *
 * @category constructors
 * @since 0.2.0
 */
export const testClientId = "effect-auth-test.apps.googleusercontent.com"

/**
 * Google's issuer, as its `id_token`s claim it.
 *
 * @category constructors
 * @since 0.2.0
 */
export const testIssuer = "https://accounts.google.com"

/**
 * What the registered Google provider may vary.
 *
 * @category models
 * @since 0.2.0
 */
export interface ProviderOptions {
  /** Defaults to {@link testClientId}. */
  readonly clientId?: string | undefined
  /** The Workspace domain the provider restricts sign-in to. */
  readonly hostedDomain?: string | undefined
}

/**
 * A transport that refuses every request.
 *
 * **Gotchas**
 *
 * One Tap makes no HTTP request at all: the keys are pinned into the provider
 * and a Google credential carries the address, so the provider's `userInfo`
 * answers from the token. A harness that handed it a working `fetch` would hide
 * the day that stopped being true, so this one fails loudly instead.
 */
const refusingFetch: typeof globalThis.fetch = () =>
  Promise.reject(new Error("effect-auth: One Tap made an HTTP request, which it is not supposed to need"))

/**
 * A Google provider whose keys are the block's own signer, registered as the
 * only provider.
 *
 * @category layers
 * @since 0.2.0
 */
export const layerProviders = (options?: ProviderOptions): Layer.Layer<OAuthProviders | IdTokenSigner> =>
  Layer.unwrap(
    Effect.map(IdTokenSigner, (signer) =>
      OAuthProviders.layer([
        Google.make({
          clientId: options?.clientId ?? testClientId,
          clientSecret: Redacted.make("test-google-client-secret"),
          jwks: signer.jwks,
          ...(options?.hostedDomain === undefined ? {} : { hostedDomain: options.hostedDomain })
        })
      ])
    )
  ).pipe(Layer.provideMerge(IdTokenSigner.layer))

/**
 * What a test may vary about a deployment serving One Tap.
 *
 * @category models
 * @since 0.2.0
 */
export interface Options extends AuthTest.Settings {
  /** The plugin's own settings — the provider id, the nonce policy, the ux mode. */
  readonly oneTap?: OneTapOptions | undefined
  /** The registered Google provider's own settings. */
  readonly provider?: ProviderOptions | undefined
}

/**
 * The plugin's service over a test deployment's own, with a pinned key set and
 * a transport that refuses to be used.
 *
 * @category layers
 * @since 0.2.0
 */
export const layerOneTap = (
  options?: Options
): Layer.Layer<OneTap | OAuthProviders | IdTokenSigner, never, Services | HttpClient.HttpClient> =>
  oneTapLayer(options?.oneTap).pipe(Layer.provideMerge(layerProviders(options?.provider)))

/**
 * A whole test deployment with One Tap on top of it.
 *
 * @category layers
 * @since 0.2.0
 */
export const layer = (
  options?: Options
): Layer.Layer<
  OneTap | OAuthProviders | IdTokenSigner | Services | SqlClient.SqlClient | PgliteClient.PgliteClient | TestEmails,
  Migrator.MigrationError | SqlError.SqlError
> =>
  layerOneTap(options).pipe(
    Layer.provide(AuthTest.layerFetch(refusingFetch)),
    Layer.provideMerge(AuthTest.layer(options))
  )

/**
 * An application API that embeds this library's group *and* the plugin's.
 *
 * @category constructors
 * @since 0.2.0
 */
export const TestApi = HttpApi.make("test-app").addHttpApi(AuthApi).add(OneTapApiGroup)

/**
 * Everything a request has to cross.
 *
 * @category layers
 * @since 0.2.0
 */
export const layerHttp = (
  options?: Options
): AuthTest.HttpApiLayer<
  "test-app",
  OneTap | OAuthProviders | IdTokenSigner | HttpApiGroup.Service<"test-app", "oneTap">
> => {
  const stack = layerOneTap(options).pipe(Layer.provide(AuthTest.layerFetch(refusingFetch)))
  return AuthTest.layerHttpApi(TestApi, options, Layer.merge(oneTapHandlers(TestApi).pipe(Layer.provide(stack)), stack))
}

// -----------------------------------------------------------------------------
// Minting credentials
// -----------------------------------------------------------------------------

/**
 * What {@link credential} puts in a token.
 *
 * @category models
 * @since 0.2.0
 */
export interface CredentialOptions {
  /** The `sub` claim — Google's stable subject. */
  readonly subject: string
  /** The `email` claim. */
  readonly email: string
  /** The `email_verified` claim. Defaults to `true`. */
  readonly emailVerified?: boolean | undefined
  /** The `nonce` claim. Omit it to mint a token that carries none. */
  readonly nonce?: string | undefined
  /** The `hd` claim — the Workspace domain the account belongs to. */
  readonly hostedDomain?: string | undefined
  /** The `name` claim. */
  readonly name?: string | undefined
  /** Overrides the issuer, for the test that a wrong one is refused. */
  readonly issuer?: string | undefined
  /** Overrides the audience, for the test that somebody else's client id is refused. */
  readonly audience?: string | undefined
  /** Seconds from now until `exp`, or `null` for a token with no expiry at all. */
  readonly expiresIn?: number | null | undefined
}

/**
 * A Google-shaped `id_token`, signed by the block's own key.
 *
 * @category constructors
 * @since 0.2.0
 */
export const credential = (options: CredentialOptions): Effect.Effect<Redacted.Redacted, never, IdTokenSigner> =>
  Effect.flatMap(IdTokenSigner, (signer) => {
    const payload: JWTPayload = {
      sub: options.subject,
      email: options.email,
      email_verified: options.emailVerified ?? true,
      ...(options.nonce === undefined ? {} : { nonce: options.nonce }),
      ...(options.hostedDomain === undefined ? {} : { hd: options.hostedDomain }),
      ...(options.name === undefined ? {} : { name: options.name })
    }
    return Effect.map(
      Effect.promise(() =>
        signer.sign(payload, {
          issuer: options.issuer ?? testIssuer,
          audience: options.audience ?? testClientId,
          expiresAt: options.expiresIn === undefined ? 3600 : options.expiresIn
        })
      ),
      Redacted.make
    )
  })
