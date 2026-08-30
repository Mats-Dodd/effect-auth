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
import type { Redacted } from "effect"
import { Context, Duration, Layer } from "effect"

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
  oauthStateTtl: Duration.minutes(10)
}

/**
 * The default rate limiting configuration.
 *
 * @category constructors
 * @since 1.0.0
 */
export const defaultRateLimit: RateLimitConfig = {
  enabled: true,
  ipHeaders: ["x-forwarded-for"],
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
  resetPassword: "/auth/reset-password"
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
export const isSecureUrl = (url: string): boolean => url.startsWith("https:")

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

// -----------------------------------------------------------------------------
// Constructors
// -----------------------------------------------------------------------------

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
  const secure = options.cookie?.secure ?? isSecureUrl(options.baseUrl)
  return {
    baseUrl: options.baseUrl,
    basePath: options.basePath ?? "/auth",
    secret: options.secret,
    trustedOrigins: options.trustedOrigins ?? [],
    trustedProviders: options.trustedProviders ?? [],
    session: { ...defaultSession, ...stripUndefined(options.session) },
    emailPassword: { ...defaultEmailPassword, ...stripUndefined(options.emailPassword) },
    cookie: {
      path: options.cookie?.path ?? "/",
      sameSite: options.cookie?.sameSite ?? "lax",
      secure,
      domain: options.cookie?.domain
    },
    tokens: { ...defaultTokens, ...stripUndefined(options.tokens) },
    rateLimit: { ...defaultRateLimit, ...stripUndefined(options.rateLimit) },
    emailPaths: { ...defaultEmailPaths, ...stripUndefined(options.emailPaths) }
  }
}

/**
 * Provides {@link AuthConfig} from plain options.
 *
 * @category layers
 * @since 1.0.0
 */
export const layer = (options: AuthConfigOptions): Layer.Layer<AuthConfig> => Layer.succeed(AuthConfig)(make(options))

// A section's keys are declared by us, but a caller may pass an explicit
// `undefined` for any of them; those must not overwrite a default when spread.
const stripUndefined = <T extends object>(section: PartialOptions<T> | undefined): Partial<T> => {
  const out: Record<string, unknown> = Object.create(null)
  if (section === undefined) return out as Partial<T>
  for (const key of Object.keys(section)) {
    const value = (section as Record<string, unknown>)[key]
    if (value !== undefined) out[key] = value
  }
  return { ...out } as Partial<T>
}
