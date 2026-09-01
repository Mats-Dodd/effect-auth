/**
 * Sign in with Apple.
 *
 * Apple is an OIDC provider with two peculiarities the rest of this module has
 * to accommodate, and both of them are the reason the provider seam looks the
 * way it does.
 *
 * The client secret is not a secret a deployment holds: it is a short-lived
 * ES256 assertion minted from a `.p8` signing key, with a maximum lifetime of
 * six months and a `sub` naming the Services ID. {@link clientSecret} mints a
 * fresh one per token request, which is why `OAuthProviderConfig.clientSecret`
 * accepts an `Effect` at all.
 *
 * The person's *name* is not in the token. Apple sends it exactly once — on the
 * very first authorization, as a JSON `user` field posted back with the code —
 * and never again. It is unsigned, attacker-controllable input, so it is read
 * with a decoder and used for the display name and for nothing else.
 *
 * **Details**
 *
 * `response_mode=form_post` follows from asking for the `name` scope: Apple then
 * `POST`s the callback cross-site rather than redirecting to it, which is what
 * `POST /auth/callback/:providerId` exists for — it turns the cross-site post
 * into the top-level `GET` navigation the flow is built around. The
 * `response_type` stays `code`: this library exchanges the code server-side and
 * has no use for the hybrid flow's front-channel token.
 *
 * @since 1.0.0
 */
import type { Redacted as RedactedType } from "effect"
import { Config, DateTime, Duration, Effect, Option, Redacted, Schema } from "effect"
import { importPKCS8, SignJWT } from "jose"
import { optionalConfig } from "../../internal/config.js"
import type { OAuthProviderError } from "../../domain/Errors.js"
import type { KeyResolver } from "../IdToken.js"
import type { OAuthProviderConfig, OAuthTokens, UserInfoOptions } from "../Provider.js"
import { providerError } from "../Provider.js"
import { lenient } from "../internal/claims.js"
import { identityOf } from "../internal/userInfo.js"

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/**
 * The id Apple is registered and addressed under.
 *
 * @category constructors
 * @since 1.0.0
 */
export const id = "apple"

/**
 * Apple's OIDC issuer. This is also the `issuer` column of every account row
 * this provider writes.
 *
 * @category constructors
 * @since 1.0.0
 */
export const issuer = "https://appleid.apple.com"

/**
 * Apple's authorization endpoint.
 *
 * @category constructors
 * @since 1.0.0
 */
export const authorizationUrl = `${issuer}/auth/authorize`

/**
 * Apple's token endpoint.
 *
 * @category constructors
 * @since 1.0.0
 */
export const tokenUrl = `${issuer}/auth/token`

/**
 * Where Apple publishes its signing keys.
 *
 * @category constructors
 * @since 1.0.0
 */
export const jwksUrl = `${issuer}/auth/keys`

/**
 * The scopes requested by default. `name` is what makes Apple post the `user`
 * field back on the first authorization — and what makes it use `form_post`.
 *
 * @category constructors
 * @since 1.0.0
 */
export const defaultScopes: ReadonlyArray<string> = ["email", "name"]

/**
 * How long a minted client secret lives by default.
 *
 * @category constructors
 * @since 1.0.0
 */
export const defaultSecretTtl: Duration.Duration = Duration.hours(1)

/**
 * The longest client-secret lifetime Apple accepts: six months, past which the
 * token endpoint refuses the assertion outright.
 *
 * @category constructors
 * @since 1.0.0
 */
export const maximumSecretTtl: Duration.Duration = Duration.days(180)

// -----------------------------------------------------------------------------
// The client secret
// -----------------------------------------------------------------------------

/**
 * What minting a client secret needs.
 *
 * @category models
 * @since 1.0.0
 */
export interface SecretOptions {
  /** The Services ID — the `sub` of the assertion, and the OAuth client id. */
  readonly clientId: string
  /** The ten-character Apple Developer team id, which is the assertion's `iss`. */
  readonly teamId: string
  /** The id of the `.p8` signing key, which becomes the assertion's `kid`. */
  readonly keyId: string
  /**
   * The `.p8` signing key itself, in PKCS#8 PEM form.
   *
   * **Gotchas**
   *
   * `Redacted` end to end: this is the one credential from which every future
   * client secret can be minted, so it must never reach a log line. It is
   * unwrapped exactly once, inside {@link clientSecret}, to be imported as a key.
   */
  readonly privateKey: RedactedType.Redacted<string>
  /**
   * How long the assertion lives. Clamped to {@link maximumSecretTtl}.
   *
   * @default "1 hour"
   */
  readonly secretTtl?: Duration.Duration | undefined
}

/**
 * Mints a client secret: a fresh ES256 assertion for one token request.
 *
 * **Details**
 *
 * `iss` is the team, `sub` the Services ID, `aud` Apple itself, and `kid` names
 * the `.p8` key. The clock is the Effect one, so a test can move a minted secret
 * past its own expiry.
 *
 * **Gotchas**
 *
 * Run per token request, never cached in a layer: the whole point of the
 * assertion is that it expires. Anything that goes wrong — a key that is not a
 * PKCS#8 PEM, one that is not a P-256 key — is
 * `OAuthProviderError({ reason: "ClientSecretUnavailable" })`, which the flow
 * reports without ever quoting the key.
 *
 * @category constructors
 * @since 1.0.0
 */
export const clientSecret: (
  options: SecretOptions
) => Effect.Effect<RedactedType.Redacted<string>, OAuthProviderError> = Effect.fnUntraced(function* (
  options: SecretOptions
) {
  const now = yield* DateTime.now
  const ttl = Duration.min(options.secretTtl ?? defaultSecretTtl, maximumSecretTtl)
  const issuedAt = Math.floor(DateTime.toEpochMillis(now) / 1000)
  const expiresAt = issuedAt + Math.floor(Duration.toMillis(ttl) / 1000)
  const signed = yield* Effect.tryPromise({
    try: async () => {
      const key = await importPKCS8(Redacted.value(options.privateKey), "ES256")
      return await new SignJWT({})
        .setProtectedHeader({ alg: "ES256", kid: options.keyId })
        .setIssuer(options.teamId)
        .setSubject(options.clientId)
        .setAudience(issuer)
        .setIssuedAt(issuedAt)
        .setExpirationTime(expiresAt)
        .sign(key)
    },
    catch: () => providerError(id, "ClientSecretUnavailable")
  })
  return Redacted.make(signed)
})

// -----------------------------------------------------------------------------
// The `user` field
// -----------------------------------------------------------------------------

/**
 * Apple's `user` callback field: the person's name, posted back once and never
 * again.
 *
 * **Gotchas**
 *
 * Nothing signs it. Every field here is attacker-controllable, which is why it
 * feeds the display name and nothing else — never the identity, the address or
 * the verification flag.
 */
const UserParam = Schema.Struct({
  name: lenient(
    Schema.Struct({
      firstName: lenient(Schema.NonEmptyString),
      lastName: lenient(Schema.NonEmptyString)
    })
  )
})

const readUserParam = Schema.decodeUnknownOption(Schema.fromJsonString(UserParam))

/**
 * The display name Apple's `user` field carries, or `null` when it carried none.
 *
 * **When to use**
 *
 * Nowhere but this module and its tests: it is exported because the rule — a
 * name is only ever built from the two parts, trimmed, and an empty result is no
 * name at all — is worth pinning.
 *
 * @category combinators
 * @since 1.0.0
 */
export const nameOf = (user: string | undefined): string | null => {
  if (user === undefined) return null
  return Option.match(readUserParam(user), {
    onNone: () => null,
    onSome: (fields) => {
      const name = fields.name
      if (name === undefined) return null
      const full = `${name.firstName ?? ""} ${name.lastName ?? ""}`.trim()
      return full.length === 0 ? null : full
    }
  })
}

// -----------------------------------------------------------------------------
// Options
// -----------------------------------------------------------------------------

/**
 * What Apple needs.
 *
 * @category models
 * @since 1.0.0
 */
export interface Options extends SecretOptions {
  /** Scopes on top of {@link defaultScopes}. */
  readonly scopes?: ReadonlyArray<string> | undefined
  /** Overrides `<baseUrl><basePath>/callback/apple`. */
  readonly redirectUri?: string | undefined
  /**
   * The bundle identifier of the native application, when one signs in too.
   *
   * **Details**
   *
   * A token minted for an iOS or macOS application carries the bundle
   * identifier as its `aud`, not the web Services ID — so a deployment that
   * accepts tokens from the app states it here and they become the expected
   * audience.
   *
   * **Gotchas**
   *
   * It *replaces* the Services ID rather than joining it. A deployment serving
   * both the web flow and the native one passes both through
   * {@link Options.audience}.
   */
  readonly appBundleIdentifier?: string | undefined
  /**
   * The full set of audiences this deployment accepts `id_token`s for,
   * overriding {@link Options.appBundleIdentifier} and the Services ID.
   *
   * **Gotchas**
   *
   * Every entry is another client whose tokens are admitted here. Keep it as
   * short as the deployment genuinely needs.
   */
  readonly audience?: string | ReadonlyArray<string> | undefined
  /** Extra authorization parameters. `response_mode` is set already. */
  readonly authorizationParams?: Readonly<Record<string, string>> | undefined
  /** The JWS algorithms accepted on an `id_token`. */
  readonly algorithms?: ReadonlyArray<string> | undefined
  /**
   * A pre-resolved key set instead of fetching {@link jwksUrl}.
   *
   * **When to use**
   *
   * Tests, which hand in a `jose` `createLocalJWKSet` so verification runs with
   * no network at all, and deployments that pin Apple's keys.
   *
   * **Gotchas**
   *
   * It replaces {@link jwksUrl} rather than joining it: the provider's key
   * source is one or the other, and pinning a key set is a statement that
   * nothing is to be fetched.
   */
  readonly jwks?: KeyResolver | undefined
}

// -----------------------------------------------------------------------------
// Constructors
// -----------------------------------------------------------------------------

/**
 * Builds the Apple provider configuration.
 *
 * **Details**
 *
 * Pure: no key is imported and nothing is signed here. `clientSecret` is left as
 * an `Effect` the flow runs once per token request, so a deployment whose `.p8`
 * is wrong boots happily and fails at the first callback — which is why
 * {@link makeConfig} mints one at build time instead.
 *
 * **Example**
 *
 * ```ts
 * import { Redacted } from "effect"
 * import { Apple } from "effect-auth"
 *
 * const apple = Apple.make({
 *   clientId: "com.example.web",
 *   teamId: "ABCDE12345",
 *   keyId: "FGHIJ67890",
 *   privateKey: Redacted.make(process.env.APPLE_PRIVATE_KEY!)
 * })
 * ```
 *
 * @category constructors
 * @since 1.0.0
 */
export const make = (options: Options): OAuthProviderConfig => {
  const userInfo = Effect.fnUntraced(function* (tokens: OAuthTokens, info?: UserInfoOptions | undefined) {
    const claims = tokens.idTokenClaims
    // The whole identity is in the token: Apple has no user-info endpoint.
    if (claims === null) return yield* Effect.fail(providerError(id, "IdTokenInvalid"))

    // The first authorization is the only one that carries a name. Every later
    // sign-in has none, and falls back to what the token says. `emailVerified`
    // is Apple's `true` or `"true"`, which `verify` has already normalized.
    const identity = identityOf(claims, nameOf(info?.params?.user))
    if (identity === null) return yield* Effect.fail(providerError(id, "UserInfoFailed"))
    return identity
  })

  const audience = options.audience ?? options.appBundleIdentifier ?? options.clientId

  return {
    id,
    clientId: options.clientId,
    // Minted per token request, from the `.p8` key. See `clientSecret`.
    clientSecret: clientSecret(options),
    authorizationUrl,
    tokenUrl,
    scopes: [...defaultScopes, ...(options.scopes ?? [])],
    oidc: {
      issuer,
      keys: options.jwks === undefined ? { jwksUrl } : { jwks: options.jwks },
      // Always stated, because Apple's is not always the client id: a token
      // minted for the native application names the bundle identifier instead.
      audience,
      ...(options.algorithms === undefined ? {} : { algorithms: options.algorithms })
    },
    ...(options.redirectUri === undefined ? {} : { redirectUri: options.redirectUri }),
    authorizationParams: {
      // Asking for `name` makes Apple post the callback cross-site instead of
      // redirecting to it; `POST /auth/callback/apple` turns that back into the
      // top-level GET the rest of the flow expects.
      response_mode: "form_post",
      ...options.authorizationParams
    },
    userInfo,
    accountId: (info) => info.id
  }
}

/**
 * What Apple needs, per field, as `Config` values.
 *
 * @category models
 * @since 1.0.0
 */
export interface ConfigOptions {
  readonly clientId: Config.Config<string>
  readonly teamId: Config.Config<string>
  readonly keyId: Config.Config<string>
  readonly privateKey: Config.Config<RedactedType.Redacted<string>>
  readonly scopes?: Config.Config<ReadonlyArray<string>> | undefined
  readonly redirectUri?: Config.Config<string> | undefined
  readonly appBundleIdentifier?: Config.Config<string> | undefined
  readonly audience?: Config.Config<ReadonlyArray<string>> | undefined
  readonly secretTtl?: Config.Config<Duration.Duration> | undefined
  readonly authorizationParams?: Readonly<Record<string, string>> | undefined
  readonly algorithms?: ReadonlyArray<string> | undefined
}

/** The settings {@link ConfigOptions} reads from the environment. */
interface Settings {
  readonly clientId: string
  readonly teamId: string
  readonly keyId: string
  readonly privateKey: RedactedType.Redacted<string>
  readonly scopes: ReadonlyArray<string> | undefined
  readonly redirectUri: string | undefined
  readonly appBundleIdentifier: string | undefined
  readonly audience: ReadonlyArray<string> | undefined
  readonly secretTtl: Duration.Duration | undefined
}

/**
 * Builds the Apple provider configuration, reading its credentials from
 * `Config`, and proves the signing key works.
 *
 * **Details**
 *
 * One trial assertion is minted here and thrown away. A `.p8` that is not a
 * PKCS#8 PEM, or is not a P-256 key, is a deployment that can never complete a
 * sign-in, so it is a *defect* at boot rather than a `ClientSecretUnavailable`
 * on somebody's first callback.
 *
 * **Gotchas**
 *
 * The key must come from `Config.redacted`, so that it is a `Redacted<string>`
 * from the moment it leaves the environment and never appears in a log line or
 * a `ConfigError`.
 *
 * @category constructors
 * @since 1.0.0
 */
export const makeConfig: (options: ConfigOptions) => Effect.Effect<OAuthProviderConfig, Config.ConfigError> =
  Effect.fnUntraced(function* (options: ConfigOptions) {
    const settings = yield* Config.unwrap<Settings>({
      clientId: options.clientId,
      teamId: options.teamId,
      keyId: options.keyId,
      privateKey: options.privateKey,
      scopes: optionalConfig(options.scopes),
      redirectUri: optionalConfig(options.redirectUri),
      appBundleIdentifier: optionalConfig(options.appBundleIdentifier),
      audience: optionalConfig(options.audience),
      secretTtl: optionalConfig(options.secretTtl)
    })
    // The trial mint: a broken key fails the build, not the first sign-in.
    yield* Effect.orDie(clientSecret(settings))
    return make({
      ...settings,
      authorizationParams: options.authorizationParams,
      algorithms: options.algorithms
    })
  })
