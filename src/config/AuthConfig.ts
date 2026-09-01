/**
 * The configuration of an `effect-auth` instance.
 *
 * `AuthConfig` is the single service every other module reads its knobs from:
 * session lifetimes, the password policy, cookie shape, trusted origins, the
 * signing secret. {@link make} applies the defaults, so a consumer only states
 * what differs from them.
 *
 * @since 1.0.0
 */
import { Context, Duration, Layer, Redacted } from "effect"
import type { Session, User } from "../domain/Schema.js"
import { trustedOriginSet } from "../internal/origins.js"
import { withDefaults } from "../internal/records.js"

/**
 * Makes every property of `T` optional and explicitly `undefined`-able, so a
 * caller may pass `{ basePath: undefined }` under `exactOptionalPropertyTypes`.
 *
 * @category models
 * @since 1.0.0
 */
export type PartialOptions<T> = { readonly [K in keyof T]?: T[K] | undefined }

// -----------------------------------------------------------------------------
// Sections
// -----------------------------------------------------------------------------

/**
 * Session lifetime knobs.
 *
 * @category models
 * @since 1.0.0
 */
export interface SessionConfig {
  /**
   * How long a new session is valid for. Default 7 days.
   */
  readonly expiresIn: Duration.Duration
  /**
   * How much of `expiresIn` must have elapsed before a verified session has its
   * expiry rolled forward. Default 1 day: a session seen at least a day after
   * it was last refreshed is extended, and the cookie re-set.
   */
  readonly updateAge: Duration.Duration
  /**
   * How recently a session must have been created to count as "fresh" for
   * sensitive operations such as changing a password. Default 1 day.
   */
  readonly freshAge: Duration.Duration
  /**
   * The expiry given to sessions created with `rememberMe: false`.
   * Default 1 day.
   */
  readonly rememberMeDisabledExpiresIn: Duration.Duration
}

/**
 * E-mail and password sign-in knobs.
 *
 * @category models
 * @since 1.0.0
 */
export interface EmailPasswordConfig {
  /**
   * Whether the e-mail/password endpoints are served at all. Default `false`.
   */
  readonly enabled: boolean
  /**
   * When `true`, signing in with an unverified address fails
   * `EmailNotVerified` and sign-up sends a verification mail. Default `false`.
   */
  readonly requireEmailVerification: boolean
  /**
   * Minimum accepted password length. Default 8.
   */
  readonly minPasswordLength: number
  /**
   * Maximum accepted password length. Default 128 — a bound on the work an
   * unauthenticated caller can ask the password hasher to do.
   */
  readonly maxPasswordLength: number
  /**
   * Whether a successful sign-up also establishes a session. Default `true`.
   */
  readonly autoSignIn: boolean
}

/**
 * Session cookie shape.
 *
 * @category models
 * @since 1.0.0
 */
export interface CookieConfig {
  /**
   * Cookie path. Default `"/"`.
   */
  readonly path: string
  /**
   * `SameSite` attribute. Default `"lax"`: it survives top-level navigations
   * back from an OAuth provider while blocking cross-site form posts.
   */
  readonly sameSite: "lax" | "strict" | "none"
  /**
   * `Secure` attribute. Defaults to whether `baseUrl` is `https:`.
   */
  readonly secure: boolean
  /**
   * Optional `Domain` attribute. Omitted by default, which scopes the cookie to
   * the exact host that set it.
   */
  readonly domain: string | undefined
}

/**
 * Lifetimes of the single-use values stored in the verification table.
 *
 * @category models
 * @since 1.0.0
 */
export interface TokenConfig {
  /**
   * Lifetime of an e-mail verification link. Default 1 day.
   */
  readonly emailVerificationTtl: Duration.Duration
  /**
   * Lifetime of a password reset link. Default 1 hour.
   */
  readonly passwordResetTtl: Duration.Duration
  /**
   * Lifetime of a pending OAuth authorization request. Default 10 minutes.
   */
  readonly oauthStateTtl: Duration.Duration
  /**
   * Lifetime of each hop of an e-mail change. Default 1 hour.
   *
   * **Details**
   *
   * The same figure bounds both the confirmation sent to the current address
   * and the verification sent to the new one, and it is short for the reason a
   * password reset is: a link that changes where the account's mail goes is a
   * link that takes the account over.
   */
  readonly changeEmailTtl: Duration.Duration
  /**
   * Lifetime of an account-deletion confirmation link. Default 1 day.
   *
   * **Gotchas**
   *
   * Longer than the others on purpose: the outcome is irreversible, so the
   * person is meant to have time to think, and a link that has expired costs
   * them nothing but another click.
   */
  readonly deleteAccountTtl: Duration.Duration
}

/**
 * Whether a signed-in person may change the address on their account.
 *
 * @category models
 * @since 1.0.0
 */
export interface ChangeEmailConfig {
  /**
   * Whether the three change-email endpoints are served. Default `false`.
   *
   * **Details**
   *
   * Opt-in, because the flow needs a working mailer and because a deployment
   * that treats the address as an external identifier — provisioned by an
   * identity provider, say — must not let it be edited from inside the
   * application.
   */
  readonly enabled: boolean
}

/**
 * Whether a signed-in person may delete their own account, and how.
 *
 * @category models
 * @since 1.0.0
 */
export interface DeleteUserConfig {
  /**
   * Whether the two delete-account endpoints are served. Default `false`.
   */
  readonly enabled: boolean
  /**
   * When `true`, `POST /auth/delete-user` mails a confirmation link instead of
   * deleting, and the deletion happens when that link is followed. Default
   * `false`.
   *
   * **When to use**
   *
   * Wherever losing the account is worse than being unable to leave it: the mail
   * step means a stolen session alone cannot destroy somebody's data, because
   * the attacker also has to reach the mailbox.
   */
  readonly confirmByEmail: boolean
}

/**
 * What a signed-in person may do to their own user record.
 *
 * @category models
 * @since 1.0.0
 */
export interface UserConfig {
  readonly changeEmail: ChangeEmailConfig
  readonly deleteUser: DeleteUserConfig
}

/**
 * What a consumer may state about {@link UserConfig}.
 *
 * **Gotchas**
 *
 * Its own type rather than a `PartialOptions<UserConfig>`, because the two
 * members are themselves sections: a caller stating one field of `deleteUser`
 * must not lose the default of the other.
 *
 * @category models
 * @since 1.0.0
 */
export interface UserConfigOptions {
  readonly changeEmail?: PartialOptions<ChangeEmailConfig> | undefined
  readonly deleteUser?: PartialOptions<DeleteUserConfig> | undefined
}

/**
 * Rate limiting knobs.
 *
 * @category models
 * @since 1.0.0
 */
export interface RateLimitConfig {
  /**
   * Whether the built-in limits are applied. Default `true`.
   */
  readonly enabled: boolean
  /**
   * The request headers consulted, in order, to derive a client IP. Only the
   * first hop of the first header that is present is used.
   *
   * **Gotchas**
   *
   * These headers are trivially forged unless a proxy you control overwrites
   * them. Behind no proxy, leave this empty: requests then share one
   * fail-closed bucket rather than one attacker-chosen bucket each.
   */
  readonly ipHeaders: ReadonlyArray<string>
  /**
   * What to do when the rate limiter's *store* fails — as opposed to the limit
   * being reached. Default `false`: the failure is logged and the request is
   * allowed, so a broken counter cannot take sign-in down with it.
   *
   * **When to use**
   *
   * Set `true` where the limits are load-bearing rather than advisory: with a
   * shared (Redis, SQL) `RateLimiterStore`, somebody who can degrade that store
   * can otherwise remove all throttling from sign-in, sign-up and the mail
   * endpoints, and the only trace is a log line. Failing closed answers
   * `RateLimited` instead, which costs availability of those endpoints while
   * the store is down.
   */
  readonly failClosed: boolean
}

/**
 * The session cookie cache: the zero-database-read fast path for
 * `GET /session` and for every endpoint behind the `Authenticated` middleware.
 *
 * **Details**
 *
 * When it is on, a signed snapshot of the session and its user rides in a second
 * cookie, and a request that presents a valid one is served without touching the
 * session store. See `src/http/SessionCache.ts` for the format, the threat model
 * and — importantly — the limitations, which are what {@link CookieCacheConfig.maxAge}
 * trades against.
 *
 * @category models
 * @since 1.0.0
 */
export interface CookieCacheConfig {
  /**
   * Whether the cache is written and read at all. Default `false`: a deployment
   * opts into the revocation lag below, it is never opted in for them.
   */
  readonly enabled: boolean
  /**
   * How long a snapshot may be trusted. Default 5 minutes.
   *
   * **Gotchas**
   *
   * This is exactly the window in which a session revoked in *another* browser
   * still answers requests in this one: nothing consults the database while a
   * snapshot is valid. Five minutes is the same trade `better-auth` makes;
   * shorten it where a sign-out has to bite sooner, and switch the cache off
   * where it has to bite immediately.
   */
  readonly maxAge: Duration.Duration
  /**
   * A value that invalidates every outstanding snapshot when it changes.
   *
   * **When to use**
   *
   * Bump the string after a deployment whose user shape changed, or pass a
   * function to make the cache sensitive to something about the principal — a
   * tenant, a role, a `passwordChangedAt` — so that changing it invalidates that
   * person's snapshots and nobody else's. Default `""`.
   *
   * **Gotchas**
   *
   * The function runs on the snapshot's own contents, so it can only read what
   * the cache carries. It must be pure and cheap: it is on the hot path of every
   * cached request. Key it on a public field or a session field. Models with
   * hidden fields disable the cookie cache entirely because those values cannot
   * safely be placed in a browser cookie.
   */
  readonly version: string | ((session: Session, user: User) => string)
}

/**
 * The paths, relative to `baseUrl`, that the e-mails link to.
 *
 * @category models
 * @since 1.0.0
 */
export interface EmailPathConfig {
  /**
   * Where a verification link points. The token is appended as `?token=`.
   * Default `"/auth/verify-email"`.
   */
  readonly verifyEmail: string
  /**
   * Where a password reset link points. The token is appended as `?token=`.
   * Default `"/auth/reset-password"`.
   */
  readonly resetPassword: string
  /**
   * Where the *first* hop of an e-mail change points — the link sent to the
   * address the account currently has. Default
   * `"/auth/change-email/confirm"`.
   */
  readonly changeEmailConfirm: string
  /**
   * Where the *second* hop points — the link sent to the new address, which is
   * what actually changes it. Default `"/auth/change-email/verify"`.
   */
  readonly changeEmailVerify: string
  /**
   * Where an account-deletion confirmation link points. Default
   * `"/auth/delete-user/callback"`.
   */
  readonly deleteAccount: string
}

// -----------------------------------------------------------------------------
// Service
// -----------------------------------------------------------------------------

/**
 * The {@link AuthConfig} service definition: the fully resolved configuration,
 * every default applied, nothing optional.
 *
 * @category models
 * @since 1.0.0
 */
export interface AuthConfigService {
  /**
   * The public origin of the application, for example
   * `"https://app.example.com"`. Used to build e-mail links, to decide whether
   * cookies are `Secure`, and as an always-trusted origin.
   */
  readonly baseUrl: string
  /**
   * The prefix the auth endpoints are mounted under. Default `"/auth"`.
   */
  readonly basePath: string
  /**
   * The signing secret. Kept `Redacted` end to end and unwrapped only inside
   * the HMAC service.
   */
  readonly secret: Redacted.Redacted<string>
  /**
   * Origins, in addition to `baseUrl`'s, that may originate cookie
   * authenticated mutations and be redirected to. Compared by origin, never by
   * prefix.
   */
  readonly trustedOrigins: ReadonlyArray<string>
  /**
   * `baseUrl` and `trustedOrigins`, parsed: every origin this deployment
   * trusts, as origins rather than as URLs.
   *
   * **Details**
   *
   * Computed once by {@link make}, because it is on the hot path of every
   * state-changing request and of every redirect target. An entry that has no
   * origin — anything that is not an absolute `http(s)` URL — is absent from
   * it, so a misconfigured `data:` entry grants no trust. `OriginCheck` reads
   * this field rather than re-parsing; see `OriginCheck.trustedOrigins`.
   */
  readonly trustedOriginSet: ReadonlySet<string>
  /**
   * Provider ids whose verified e-mail claim is trusted enough to link a new
   * OAuth identity onto an existing local account automatically.
   */
  readonly trustedProviders: ReadonlyArray<string>
  readonly session: SessionConfig
  readonly emailPassword: EmailPasswordConfig
  readonly cookie: CookieConfig
  readonly tokens: TokenConfig
  readonly rateLimit: RateLimitConfig
  readonly emailPaths: EmailPathConfig
  readonly cookieCache: CookieCacheConfig
  readonly user: UserConfig
}

/**
 * The configuration service. See {@link AuthConfigService}.
 *
 * @category services
 * @since 1.0.0
 */
export class AuthConfig extends Context.Service<AuthConfig, AuthConfigService>()("effect-auth/AuthConfig") {}

// -----------------------------------------------------------------------------
// Options
// -----------------------------------------------------------------------------

/**
 * What a consumer passes to {@link make} — or to `Auth.layer`. Only `baseUrl`
 * and `secret` are required.
 *
 * @category models
 * @since 1.0.0
 */
export interface AuthConfigOptions {
  readonly baseUrl: string
  readonly secret: Redacted.Redacted<string>
  readonly basePath?: string | undefined
  readonly trustedOrigins?: ReadonlyArray<string> | undefined
  readonly trustedProviders?: ReadonlyArray<string> | undefined
  readonly session?: PartialOptions<SessionConfig> | undefined
  readonly emailPassword?: PartialOptions<EmailPasswordConfig> | undefined
  readonly cookie?: PartialOptions<CookieConfig> | undefined
  readonly tokens?: PartialOptions<TokenConfig> | undefined
  readonly rateLimit?: PartialOptions<RateLimitConfig> | undefined
  readonly emailPaths?: PartialOptions<EmailPathConfig> | undefined
  readonly cookieCache?: PartialOptions<CookieCacheConfig> | undefined
  readonly user?: UserConfigOptions | undefined
}

// -----------------------------------------------------------------------------
// Defaults
// -----------------------------------------------------------------------------

/**
 * The default session lifetimes.
 *
 * @category constructors
 * @since 1.0.0
 */
export const defaultSession: SessionConfig = {
  expiresIn: Duration.days(7),
  updateAge: Duration.days(1),
  freshAge: Duration.days(1),
  rememberMeDisabledExpiresIn: Duration.days(1)
}

/**
 * The default e-mail/password policy: disabled, no verification requirement,
 * passwords of 8 to 128 characters.
 *
 * @category constructors
 * @since 1.0.0
 */
export const defaultEmailPassword: EmailPasswordConfig = {
  enabled: false,
  requireEmailVerification: false,
  minPasswordLength: 8,
  maxPasswordLength: 128,
  autoSignIn: true
}

/**
 * The default single-use token lifetimes.
 *
 * @category constructors
 * @since 1.0.0
 */
export const defaultTokens: TokenConfig = {
  emailVerificationTtl: Duration.days(1),
  passwordResetTtl: Duration.hours(1),
  oauthStateTtl: Duration.minutes(10),
  changeEmailTtl: Duration.hours(1),
  deleteAccountTtl: Duration.days(1)
}

/**
 * The default rate limiting configuration.
 *
 * @category constructors
 * @since 1.0.0
 */
export const defaultRateLimit: RateLimitConfig = {
  enabled: true,
  // Forwarding headers are attacker-controlled unless a trusted proxy
  // overwrites them. Deployments behind such a proxy opt in explicitly.
  ipHeaders: [],
  failClosed: false
}

/**
 * The default e-mail link paths.
 *
 * @category constructors
 * @since 1.0.0
 */
export const defaultEmailPaths: EmailPathConfig = {
  verifyEmail: "/auth/verify-email",
  resetPassword: "/auth/reset-password",
  changeEmailConfirm: "/auth/change-email/confirm",
  changeEmailVerify: "/auth/change-email/verify",
  deleteAccount: "/auth/delete-user/callback"
}

/**
 * The default change-email policy: not served.
 *
 * @category constructors
 * @since 1.0.0
 */
export const defaultChangeEmail: ChangeEmailConfig = { enabled: false }

/**
 * The default delete-account policy: not served, and — were it served — direct
 * rather than confirmed by mail.
 *
 * @category constructors
 * @since 1.0.0
 */
export const defaultDeleteUser: DeleteUserConfig = { enabled: false, confirmByEmail: false }

/**
 * The default cookie cache configuration: off, five minutes, no version.
 *
 * @category constructors
 * @since 1.0.0
 */
export const defaultCookieCache: CookieCacheConfig = {
  enabled: false,
  maxAge: Duration.minutes(5),
  version: ""
}

/**
 * The name of the session cookie, before any `__Secure-` prefix.
 *
 * **Gotchas**
 *
 * This is a constant, not a knob. A security scheme's key is fixed when the
 * `Authenticated` middleware class is declared, so the name a request is *read*
 * under cannot depend on runtime configuration; a configurable name would let a
 * deployment write its cookie under one name and look for it under another, and
 * every cookie-authenticated request would then answer `Unauthorized`.
 *
 * @category constructors
 * @since 1.0.0
 */
export const defaultCookieName = "effect_auth.session"

/**
 * Whether an origin is served over TLS, which decides the `Secure` attribute
 * and the `__Secure-` cookie prefix.
 *
 * @category guards
 * @since 1.0.0
 */
export const isSecureUrl = (url: string): boolean => {
  try {
    return new URL(url).protocol === "https:"
  } catch {
    return false
  }
}

/**
 * The name a session cookie is actually set under.
 *
 * **Details**
 *
 * A `Secure` cookie is given the `__Secure-` prefix, which browsers only accept
 * over TLS and only from a secure origin — so a network attacker on a plain
 * HTTP sibling origin cannot overwrite the session cookie.
 *
 * @category combinators
 * @since 1.0.0
 */
export const cookieName = (config: AuthConfigService): string =>
  config.cookie.secure ? `__Secure-${defaultCookieName}` : defaultCookieName

/**
 * The name of the session cache cookie, before any `__Secure-` prefix.
 *
 * **Details**
 *
 * A second cookie rather than a bigger session cookie: the session token is the
 * credential and must stay small, `HttpOnly` and independent of whatever the
 * cache happens to hold, and a snapshot that outgrows its budget has to be
 * droppable without touching the session.
 *
 * @category constructors
 * @since 1.0.0
 */
export const defaultCacheCookieName = "effect_auth.session_data"

/**
 * The name the session cache cookie is actually set under — the same
 * `__Secure-` rule as {@link cookieName}.
 *
 * @category combinators
 * @since 1.0.0
 */
export const cacheCookieName = (config: AuthConfigService): string =>
  config.cookie.secure ? `__Secure-${defaultCacheCookieName}` : defaultCacheCookieName

// -----------------------------------------------------------------------------
// Constructors
// -----------------------------------------------------------------------------

const configurationError = (message: string): never => {
  throw new TypeError(`effect-auth: ${message}`)
}

const positiveDuration = (name: string, value: Duration.Duration): void => {
  const millis = Duration.toMillis(value)
  if (!Number.isFinite(millis) || millis <= 0) configurationError(`${name} must be positive`)
}

const absoluteWebUrl = (name: string, value: string): URL => {
  let parsed: URL
  try {
    parsed = new URL(value)
  } catch {
    return configurationError(`${name} must be an absolute http(s) URL`)
  }
  if ((parsed.protocol !== "http:" && parsed.protocol !== "https:") || parsed.username !== "" || parsed.password !== "") {
    return configurationError(`${name} must be an absolute http(s) URL without credentials`)
  }
  return parsed
}

/** Fails immediately when security-sensitive settings contradict each other. */
const validate = (config: AuthConfigService): AuthConfigService => {
  const base = absoluteWebUrl("baseUrl", config.baseUrl)
  if (base.pathname !== "/" || base.search !== "" || base.hash !== "") {
    configurationError("baseUrl must be an origin without a path, query, or fragment")
  }
  if (new TextEncoder().encode(Redacted.value(config.secret)).byteLength < 32) {
    configurationError("secret must contain at least 32 UTF-8 bytes")
  }
  if (!config.basePath.startsWith("/") || config.basePath.startsWith("//") || config.basePath.includes("\\")) {
    configurationError("basePath must be a path beginning with one forward slash")
  }
  if (base.protocol === "https:" && !config.cookie.secure) {
    configurationError("cookie.secure cannot be false for an HTTPS baseUrl")
  }
  if (config.cookie.sameSite === "none" && !config.cookie.secure) {
    configurationError('cookie.sameSite "none" requires cookie.secure')
  }
  if (!config.cookie.path.startsWith("/")) configurationError("cookie.path must begin with a forward slash")
  if (!Number.isSafeInteger(config.emailPassword.minPasswordLength) || config.emailPassword.minPasswordLength < 8) {
    configurationError("emailPassword.minPasswordLength must be an integer of at least 8")
  }
  if (!Number.isSafeInteger(config.emailPassword.maxPasswordLength) ||
    config.emailPassword.maxPasswordLength < config.emailPassword.minPasswordLength) {
    configurationError("emailPassword.maxPasswordLength must be an integer not smaller than minPasswordLength")
  }

  positiveDuration("session.expiresIn", config.session.expiresIn)
  positiveDuration("session.updateAge", config.session.updateAge)
  positiveDuration("session.freshAge", config.session.freshAge)
  positiveDuration("session.rememberMeDisabledExpiresIn", config.session.rememberMeDisabledExpiresIn)
  // Both bounds say the same thing: the refresh window has to fit inside the
  // *shortest* session this deployment mints, or that session would expire
  // without the rolling refresh ever applying to it. `rememberMeDisabledExpiresIn`
  // is that shortest lifetime, so `updateAge` is bounded by it as well as by
  // `expiresIn`.
  //
  // This is deliberately not a promotion guard. A `rememberMe: false` session
  // becoming refresh-due before it expires — which is exactly what these bounds
  // guarantee — used to promote its browser-session cookie to a persistent one,
  // because the row recorded no remember-me choice. That is closed on the row
  // instead: `session.rememberMe` is persisted, and the rolling refresh re-sends
  // the cookie with the persistence the person actually chose (see
  // `MiddlewareLive.setSessionCookie`). Inverting these bounds to forbid the
  // relationship would defend against nothing the column does not already close,
  // while forbidding sub-day refresh granularity and making a short session
  // unrefreshable — which is behaviour `grantedLifetime` exists to support.
  if (Duration.toMillis(config.session.updateAge) >= Duration.toMillis(config.session.expiresIn) ||
    Duration.toMillis(config.session.updateAge) > Duration.toMillis(config.session.rememberMeDisabledExpiresIn)) {
    configurationError("session.updateAge must be shorter than expiresIn and no longer than rememberMeDisabledExpiresIn")
  }
  for (const [name, value] of Object.entries(config.tokens)) positiveDuration(`tokens.${name}`, value)
  positiveDuration("cookieCache.maxAge", config.cookieCache.maxAge)

  for (const [index, origin] of config.trustedOrigins.entries()) absoluteWebUrl(`trustedOrigins[${index}]`, origin)
  for (const [name, path] of Object.entries(config.emailPaths)) {
    if (!path.startsWith("/") || path.startsWith("//") || path.includes("\\")) {
      configurationError(`emailPaths.${name} must be a path beginning with one forward slash`)
    }
  }
  return config
}

/**
 * Resolves user options against the defaults.
 *
 * **Example**
 *
 * ```ts
 * import { Redacted } from "effect"
 * import { AuthConfig } from "effect-auth"
 *
 * const config = AuthConfig.make({
 *   baseUrl: "https://app.example.com",
 *   secret: Redacted.make(process.env.AUTH_SECRET!),
 *   emailPassword: { enabled: true, requireEmailVerification: true }
 * })
 * ```
 *
 * @category constructors
 * @since 1.0.0
 */
export const make = (options: AuthConfigOptions): AuthConfigService => {
  const origins = options.trustedOrigins ?? []
  return validate({
    baseUrl: options.baseUrl,
    basePath: options.basePath ?? "/auth",
    secret: options.secret,
    trustedOrigins: origins,
    // The origin set is on the hot path of every state-changing request and of
    // every redirect target, and it is a pure function of the two fields above
    // — so it is parsed here, once, rather than on the first request to ask.
    trustedOriginSet: trustedOriginSet({ baseUrl: options.baseUrl, trustedOrigins: origins }),
    trustedProviders: options.trustedProviders ?? [],
    session: withDefaults(defaultSession, options.session),
    emailPassword: withDefaults(defaultEmailPassword, options.emailPassword),
    cookie: withDefaults(defaultCookie(options.baseUrl), options.cookie),
    tokens: withDefaults(defaultTokens, options.tokens),
    rateLimit: withDefaults(defaultRateLimit, options.rateLimit),
    emailPaths: withDefaults(defaultEmailPaths, options.emailPaths),
    cookieCache: withDefaults(defaultCookieCache, options.cookieCache),
    // Field by field rather than through one `withDefaults`, because `user` is a
    // section of sections: resolving it wholesale would let a caller stating
    // `deleteUser.enabled` lose the default of `confirmByEmail`. It also means
    // anything else a caller's `user` object happens to carry — `Auth.Options`
    // puts the deployment's `model` there — cannot reach the resolved
    // configuration.
    user: {
      changeEmail: withDefaults(defaultChangeEmail, options.user?.changeEmail),
      deleteUser: withDefaults(defaultDeleteUser, options.user?.deleteUser)
    }
  })
}

/**
 * Provides {@link AuthConfig} from plain options.
 *
 * @category layers
 * @since 1.0.0
 */
export const layer = (options: AuthConfigOptions): Layer.Layer<AuthConfig> => Layer.succeed(AuthConfig)(make(options))

/**
 * The default cookie shape for a deployment served from `baseUrl`.
 *
 * `secure` is the only default that depends on anything, and `domain` is
 * deliberately present-and-`undefined`: omitting the attribute scopes the
 * cookie to the exact host that set it.
 */
const defaultCookie = (baseUrl: string): CookieConfig => ({
  path: "/",
  sameSite: "lax",
  secure: isSecureUrl(baseUrl),
  domain: undefined
})
