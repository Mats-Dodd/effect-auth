/**
 * `effect-auth/passkeys` — WebAuthn credentials as a way into an account.
 *
 * **Details**
 *
 * A subpath of its own, and that is the whole reason this module exists as one:
 * verifying a WebAuthn assertion is delegated to `@simplewebauthn/server`, an
 * **optional peer dependency**, so a deployment that does not serve passkeys
 * never installs it and `effect-auth` keeps its single runtime dependency.
 * Nothing reachable from `effect-auth`, `effect-auth/client` or
 * `effect-auth/testing` names the package; the only module that does is
 * `WebAuthn.layerSimple`, and it names it inside a dynamic `import`.
 *
 * The plugin owns two tables — `effect_auth_passkeys` and
 * `effect_auth_passkey_users` — under its own migration bookkeeping, and no
 * column on any core table.
 *
 * **Example**
 *
 * ```ts skip-type-checking
 * import { Layer } from "effect"
 * import { HttpApi } from "effect/unstable/httpapi"
 * import { Auth, AuthApi, AuthHandlers, Migrations } from "effect-auth"
 * import {
 *   PasskeyHandlers,
 *   PasskeyMigrations,
 *   Passkeys,
 *   PasskeysApiGroup,
 *   PasskeyStore,
 *   WebAuthn
 * } from "effect-auth/passkeys"
 *
 * const StoreLive = PasskeyStore.layer
 *
 * // Underneath the deployment: this is what makes `Accounts.unlink` count a
 * // passkey as a way in, and what makes the takeover defence revoke one.
 * const AuthLive = Auth.layer(options).pipe(
 *   Layer.provide(Passkeys.layerAuthenticators.pipe(Layer.provide(StoreLive))),
 *   Layer.provide(PgLive)
 * )
 *
 * const PasskeysLive = Passkeys.layer({
 *   rpId: "example.com",
 *   origin: "https://example.com"
 * }).pipe(
 *   Layer.provideMerge(AuthLive),
 *   Layer.provide(WebAuthn.layerSimple),
 *   Layer.provide(StoreLive)
 * )
 *
 * const AppApi = HttpApi.make("app").addHttpApi(AuthApi).add(PasskeysApiGroup)
 *
 * const HandlersLive = Layer.mergeAll(
 *   AuthHandlers.layer(AppApi),
 *   PasskeyHandlers.handlers(AppApi)
 * ).pipe(Layer.provide(PasskeysLive))
 *
 * // Sequenced after the core set: both tables reference `users`.
 * const MigrationsLive = PasskeyMigrations.layer.pipe(Layer.provide(Migrations.layer))
 * ```
 *
 * **Gotchas**
 *
 * `rpId` and `origin` are required. A relying party that derives either from the
 * request's own headers has an attacker-controlled origin, and origin binding is
 * the whole of what makes WebAuthn phishing-resistant.
 *
 * The client lives in `effect-auth/client` (`PasskeysClient`), not here: a
 * browser bundle must not reach a store, a verifier or a migration.
 *
 * @since 0.2.0
 */
export * from "./Api.js"
export * from "./Errors.js"
export * as PasskeyHandlers from "./Handlers.js"
export * as PasskeyMigrations from "./Migrations.js"
export * as Passkeys from "./Passkeys.js"
export * from "./Schema.js"
export * as PasskeyStore from "./Store.js"
export * as WebAuthn from "./WebAuthn.js"
export * from "./Wire.js"
