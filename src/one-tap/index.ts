/**
 * The Google One Tap plugin.
 *
 * **Details**
 *
 * The smallest plugin in this library, and deliberately so: it owns no table,
 * no migrations, no crypto and no claim mapping. A One Tap credential is an
 * OIDC `id_token`, so the module checks the two bindings that are about the
 * browser in front of it — the nonce, and in redirect mode the CSRF token —
 * and then hands the credential to `IdToken.verify` with the configured
 * provider's own issuer, audience and keys, to that provider's own `userInfo`
 * (where a hosted-domain restriction lives), and to `Accounts.linkOAuth` and
 * `SignIn.complete`.
 *
 * **Example**
 *
 * ```ts skip-type-checking
 * import { Layer } from "effect"
 * import { HttpApi } from "effect/unstable/httpapi"
 * import { Auth, AuthApi, AuthHandlers, Google, OAuthProviders, OneTap } from "effect-auth"
 *
 * const providers = OAuthProviders.layer([Google.make({ clientId, clientSecret })])
 *
 * const OneTapLive = OneTap.layer().pipe(
 *   Layer.provideMerge(AuthLive),
 *   Layer.provide(providers),
 *   Layer.provide(FetchHttpClient.layer)
 * )
 *
 * const AppApi = HttpApi.make("app").addHttpApi(AuthApi).add(OneTap.OneTapApiGroup)
 * const HandlersLive = Layer.mergeAll(AuthHandlers.layer(AppApi), OneTap.handlers(AppApi)).pipe(
 *   Layer.provide(OneTapLive)
 * )
 * ```
 *
 * **Gotchas**
 *
 * The provider it serves must be a registered *OIDC* provider — the same
 * `Google.make({...})` value the redirect flow uses, in the same
 * `OAuthProviders` registry. A deployment that serves both gets one client id,
 * one hosted-domain rule and one set of accounts out of one configuration,
 * which is the point.
 *
 * @since 0.2.0
 */
export * from "./Api.js"
export * from "./Handlers.js"
export * from "./OneTap.js"
