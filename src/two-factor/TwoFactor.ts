/**
 * Two-factor authentication: an authenticator app, the recovery codes that
 * stand behind it, and the browsers a person has told this deployment to
 * remember.
 *
 * One module for the three of them, because they are one feature: "never leave
 * somebody with a second factor and no way back in" is an invariant rather than
 * a roadmap item, and a remembered browser is meaningless without a factor for
 * it to skip.
 *
 * **Details — where this interposes**
 *
 * Exactly one place: {@link SignInPipeline}. A person with a confirmed
 * enrolment is asked for a second factor by *every* sign-in path this library
 * serves — password, OAuth, magic link, and any plugin's — because the decider
 * runs inside `SignIn.complete` and there is no list of routes to forget one
 * from. That is the whole of the difference between this and the prior art it
 * is modelled on, whose 2FA gate was a literal three-path list and whose TOTP
 * users could sign in by magic link with no second factor at all.
 *
 * A challenge mints nothing. The pending state is a `Verifications` row under
 * {@link pendingAuthPurpose}, carrying the evidence the first factor produced,
 * and its token travels only in the `__Host-effect_auth.pending` cookie. The
 * second half — {@link TwoFactorService.verify} — claims that row, checks the
 * code, and hands the accumulated evidence to `SignIn.complete`, which is the
 * one place a session is ever minted.
 *
 * **Details — what is stored**
 *
 * The TOTP secret is the only long-lived secret in this library that has to be
 * readable, so it is encrypted with {@link AuthCipher} under a key class of
 * this plugin's own and bound to the row by its AAD. A recovery code and a
 * device token are never readable: only a keyed digest (`Hmac`) is stored, and
 * both are spent by a single guarded statement.
 *
 * @since 0.2.0
 */
import {
  Context,
  Crypto,
  Data,
  DateTime,
  Duration,
  Effect,
  Encoding,
  Layer,
  Option,
  Redacted,
  Result,
  Schema,
  Stream
} from "effect"
import type { Scope } from "effect"
import { HttpServerRequest } from "effect/unstable/http"
import { HttpApiBuilder } from "effect/unstable/httpapi"
import { RateLimiter } from "effect/unstable/persistence"
import type { SqlClient } from "effect/unstable/sql"
import type { AuthConfigService } from "../config/AuthConfig.js"
import { AuthConfig } from "../config/AuthConfig.js"
import type { AuthCipherService } from "../crypto/Cipher.js"
import { AuthCipher, layer as cipherLayer } from "../crypto/Cipher.js"
import type { HmacService } from "../crypto/Hmac.js"
import { Hmac, layer as hmacLayer } from "../crypto/Hmac.js"
import type { TokenService } from "../crypto/Token.js"
import { layer as tokenLayer, Token } from "../crypto/Token.js"
import * as Totp from "../crypto/Totp.js"
import { AuthenticationMethods, deriveAal } from "../domain/Assurance.js"
import type { AuthenticatorsService, AuthenticatorSummary } from "../domain/Authenticators.js"
import { Authenticators, combine as combineAuthenticators } from "../domain/Authenticators.js"
import type { EmailDeliveryError, RateLimited } from "../domain/Errors.js"
import { InvalidCode, InvalidToken } from "../domain/Errors.js"
import { AuthEvent, AuthEvents, PluginEvent, publishSafely } from "../domain/Events.js"
import { PolicyRefused, ProvisionSource } from "../domain/Hooks.js"
import type { Session, User } from "../domain/Schema.js"
import { UserId } from "../domain/Schema.js"
import type { Evidence } from "../domain/Sessions.js"
import { recoveryCodeMethod, Sessions, stampEvidence } from "../domain/Sessions.js"
import type { CompleteOptions, SignInPipelineService } from "../domain/SignIn.js"
import {
  combine as combinePipelines,
  methodOf,
  proceed,
  SignIn,
  SignInDecision,
  SignInPipeline,
  SignInResult
} from "../domain/SignIn.js"
import type { PersistenceError } from "../domain/Stores.js"
import { UserStore } from "../domain/Stores.js"
import type { TokenPurpose } from "../domain/Verifications.js"
import { decodeSubjectToken, layer as verificationsLayer, purpose, Verifications } from "../domain/Verifications.js"
import type { PluginCookie } from "../http/Cookies.js"
import { pluginCookieFor } from "../http/Cookies.js"
import { originOf } from "../http/OriginCheck.js"
import type { Bucket } from "../http/RateLimits.js"
import { consumeKeyed } from "../http/RateLimits.js"
import { encode as encodeBase32 } from "../internal/base32.js"
import { encodeUtf8, layerWebCrypto } from "../internal/crypto.js"
import { deliverEmail, insertRow } from "../internal/effects.js"
import { withDefaults } from "../internal/records.js"
import * as SqlStores from "../sql/SqlStores.js"
import { TotpAlreadyEnrolled, TotpNotEnrolled } from "./Api.js"
import * as RecoveryCodes from "./RecoveryCodes.js"
import type { TrustedDeviceId } from "./Schema.js"
import { RecoveryCode, TotpEnrolment, totpMethod, TrustedDevice } from "./Schema.js"
import type { TwoFactorStoreService } from "./Store.js"
import { layer as storeLayer, TwoFactorStore } from "./Store.js"

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/**
 * The name this plugin publishes `PluginEvent`s under.
 *
 * @category constructors
 * @since 0.2.0
 */
export const twoFactorPlugin = "two-factor"

/**
 * The `method` a trusted-device skip is recorded under.
 *
 * @category constructors
 * @since 0.2.0
 */
export const trustedDeviceMethod = "trustedDevice"

/**
 * What an authenticator-app code proves: possession of the enrolled device,
 * over a channel a phishing page can relay.
 *
 * @category constructors
 * @since 0.2.0
 */
export const totpEvidence: Evidence = {
  method: totpMethod,
  factor: "possession",
  phishingResistant: false,
  restricted: false
}

/**
 * What a recovery code proves.
 *
 * **Details**
 *
 * The same kind of thing a TOTP code proves — something the person has — and
 * it is recorded under its own name rather than dressed up as one, so
 * `AssurancePolicy.allowRecovery: false` can refuse it on the endpoints where
 * a printed code is not good enough. Refusing it *silently* is what locks
 * somebody out of the page where they would repair their second factor, which
 * is why the recovery path answers a real session and lets policy decide.
 *
 * @category constructors
 * @since 0.2.0
 */
export const recoveryCodeEvidence: Evidence = {
  method: recoveryCodeMethod,
  factor: "possession",
  phishingResistant: false,
  restricted: false
}

/**
 * What a trusted-device skip records: that it happened, and that it proves
 * nothing.
 *
 * **Gotchas**
 *
 * `factor: "none"`, so `Assurance.deriveAal` gives it no weight. NIST does not
 * recognise device trust as a factor and RFC 8176 has no value for it;
 * recording the skipped factor's value would corrupt every derivation
 * downstream of the session.
 *
 * @category constructors
 * @since 0.2.0
 */
export const trustedDeviceEvidence: Evidence = {
  method: trustedDeviceMethod,
  factor: "none",
  phishingResistant: false,
  restricted: false
}

/**
 * Whether one of this plugin's own factors is already on a sign-in's evidence.
 *
 * **Details**
 *
 * The decider's idempotence test. A `factor: "none"` entry is not an answer —
 * a trusted-device skip records that the question was waived, not that it was
 * answered — so it is excluded, which is the same rule `Assurance.deriveAal`
 * applies to it.
 */
const answeredHere = (evidence: ReadonlyArray<Evidence>): boolean =>
  evidence.some(
    (entry) => entry.factor !== "none" && (entry.method === totpMethod || entry.method === recoveryCodeMethod)
  )

/**
 * The `kind` the challenge this plugin issues carries.
 *
 * @category constructors
 * @since 0.2.0
 */
export const challengeKind = "two-factor"

/**
 * The `PolicyRefused.code` a sign-in this plugin cannot finish leaves by — a
 * redirect-shaped flow that has nowhere to prompt, or a second plugin
 * challenging a ceremony this one has just completed.
 *
 * @category constructors
 * @since 0.2.0
 */
export const mfaRequiredCode = "mfa_required"

/**
 * The `Authenticators` type an enrolment contributes.
 *
 * @category constructors
 * @since 0.2.0
 */
export const totpAuthenticatorType = "totp"

/**
 * The `Authenticators` type a live recovery-code set contributes.
 *
 * @category constructors
 * @since 0.2.0
 */
export const recoveryCodesAuthenticatorType = "recoveryCodes"

/**
 * The `AuthCipher` key class the TOTP secret is encrypted under.
 *
 * **Gotchas**
 *
 * Part of the stored format: change it and every enrolment becomes
 * unreadable. It is deliberately *not* the stack's own class — two classes
 * derive different keys from the same deployment secret and fail each other's
 * tag check, so a TOTP secret cannot be read by anything that reads an OAuth
 * refresh token.
 *
 * @category constructors
 * @since 0.2.0
 */
export const cipherKeyInfo = "effect-auth/totp-secret/v1"

/**
 * How many random bytes a TOTP secret has: twenty, RFC 4226 §4 R6's
 * recommendation and what every authenticator app expects.
 *
 * @category constructors
 * @since 0.2.0
 */
export const secretBytes = 20

/**
 * The cookie a remembered browser is known by, before the deployment's prefix.
 *
 * @category constructors
 * @since 0.2.0
 */
export const trustedDeviceCookieBaseName = "effect_auth.tdev"

/**
 * The domain separation of a trusted-device cookie's signature.
 *
 * **Gotchas**
 *
 * Part of the format. `Hmac` is a published service — a plugin may sign values
 * of its own with the same key — so a tag is only ever a tag *for* something,
 * and a value signed under any other context is refused here.
 *
 * @category constructors
 * @since 0.2.0
 */
export const trustedDeviceContext = "effect-auth/two-factor/trusted-device/v1\n"

/**
 * The domain separation of a trusted-device token's stored digest.
 *
 * @category constructors
 * @since 0.2.0
 */
export const trustedDeviceHashContext = "effect-auth/two-factor/trusted-device-token/v1\n"

/**
 * The domain separation of a recovery code's stored digest.
 *
 * **Gotchas**
 *
 * Part of the stored format: changing it invalidates every outstanding
 * recovery code.
 *
 * @category constructors
 * @since 0.2.0
 */
export const recoveryCodeHashContext = "effect-auth/two-factor/recovery-code/v1\n"

/**
 * What separates the two halves of a trusted-device cookie's payload: the user
 * it belongs to, and the token itself.
 */
const deviceBindingSeparator = "\n"

// -----------------------------------------------------------------------------
// Pending authentication
// -----------------------------------------------------------------------------

/**
 * What a pending authentication remembers about the sign-in it interrupted.
 *
 * **Details**
 *
 * The evidence the first factor produced, stamped with the moment it actually
 * happened, so the completed session's log says "the password was proved at
 * 09:01 and the code at 09:02" rather than back-dating both. `method` is the
 * entry point the sign-in came in through, carried so the `SignedIn` event a
 * challenged sign-in publishes names the same thing an unchallenged one would.
 *
 * **Gotchas**
 *
 * A payload, not a claim: it lives in the `verifications` row and the token is
 * a handle to it. It is also what makes the row un-redeemable as anything
 * else — a purpose that declares a payload refuses a row that does not carry
 * one, and vice versa.
 *
 * @category models
 * @since 0.2.0
 */
export const PendingAuthPayload = Schema.Struct({
  userId: UserId,
  /** What the first factor proved, already stamped. */
  evidence: AuthenticationMethods,
  /** Whether the interrupted sign-in asked to be remembered. */
  rememberMe: Schema.Boolean,
  /** `SignIn.methodOf` of the source that was interrupted. */
  method: Schema.String
})

/**
 * The type of a {@link PendingAuthPayload}.
 *
 * @category models
 * @since 0.2.0
 */
export type PendingAuthPayload = typeof PendingAuthPayload.Type

/**
 * The purpose a pending authentication's row is written under.
 *
 * **Gotchas**
 *
 * The name is fixed by the library's contract — a second-factor plugin issues
 * `"pending-auth"` and the HTTP layer carries its token in
 * `__Host-effect_auth.pending`. The subject is the user id, so two sign-ins for
 * one person share a namespace and the newer one retires the older.
 *
 * @category constructors
 * @since 0.2.0
 */
export const pendingAuthPurpose: TokenPurpose<PendingAuthPayload> = purpose("pending-auth", PendingAuthPayload)

// -----------------------------------------------------------------------------
// Options
// -----------------------------------------------------------------------------

/**
 * The per-account attempt budget, shared by every code this plugin checks.
 *
 * **Details**
 *
 * Ten in fifteen minutes, keyed on the user id rather than on a client address:
 * a per-challenge cap is defeated by starting a fresh sign-in, and an
 * address-keyed one by a second address. It covers TOTP codes, recovery codes
 * and enrolment confirmations together, so an attacker cannot spend a fresh
 * budget by switching to the other endpoint.
 *
 * @category constructors
 * @since 0.2.0
 */
export const lockoutBucket: Bucket = {
  name: "two-factor",
  limit: 10,
  window: Duration.minutes(15)
}

/**
 * What a deployment may vary about this plugin.
 *
 * @category models
 * @since 0.2.0
 */
export interface Config {
  /**
   * What an authenticator app lists the enrolment under. `null` derives it from
   * `AuthConfig.baseUrl`'s host, which is what a person will recognise.
   */
  readonly issuer: string | null
  /** How many digits a code has. Defaults to six — see `Totp`'s header. */
  readonly digits: number
  /** How many seconds a step lasts. Defaults to thirty. */
  readonly period: number
  /** Which hash is keyed. Defaults to SHA-1, which is what the apps implement. */
  readonly algorithm: Totp.TotpAlgorithm
  /** How many steps either side of the current one are accepted. Defaults to one. */
  readonly window: number
  /**
   * How long an unconfirmed enrolment may be confirmed for. Defaults to
   * fifteen minutes; starting again abandons it and mints a new secret.
   */
  readonly enrolmentTtl: Duration.Duration
  /**
   * How long a pending authentication may be answered for. Defaults to ten
   * minutes.
   */
  readonly pendingAuthTtl: Duration.Duration
  /** How many recovery codes a set has. Defaults to ten. */
  readonly recoveryCodeCount: number
  /**
   * At or below how many unspent codes `RecoveryCodesLow` is published.
   * Defaults to three.
   */
  readonly lowRecoveryCodes: number
  /** The per-account attempt budget. Defaults to {@link lockoutBucket}. */
  readonly lockout: Bucket
  /**
   * How long a remembered browser is trusted for. Defaults to thirty days, and
   * it is **absolute**: using a device rotates its token and never moves its
   * expiry, because a rolling window is a permanent bypass for whoever holds
   * the cookie.
   */
  readonly trustedDeviceTtl: Duration.Duration
  /**
   * What a trusted-device skip is worth. Defaults to `"none"`, which is the
   * conformant answer: the skip is recorded, it proves nothing, and a session
   * established this way is `aal1`. Routine browsing works; anything guarded by
   * `requireAssurance({ aal: "aal2" })` still costs a real factor.
   *
   * **Gotchas**
   *
   * `"aal2"` is documented as **non-conformant** — NIST does not recognise
   * device trust as a factor — and, with the seams core ships today, it cannot
   * be honoured either: a `SignInPipeline` decider says *whether* a session may
   * be minted, not what evidence it records, so nothing this plugin can do at
   * that point raises the level. Setting it logs a warning when the layer is
   * built and behaves as `"none"`, which fails closed. See the module's
   * `leftForFixer` note: one optional `evidence` member on `SignInDecision`'s
   * `Proceed` closes it.
   */
  readonly trustedDeviceSatisfies: "none" | "aal2"
  /**
   * A further test for {@link TwoFactorService.sweepOn}, beyond the fixed rules
   * below.
   *
   * **Details**
   *
   * The built-in matrix names only events this library's *core* publishes, so
   * it cannot know that a deployment also runs a factor plugin whose enrolments
   * ought to forget a remembered browser too. Naming another plugin's event
   * strings here would make this plugin a registry of the others, which is the
   * one thing a plugin is not. A deployment that runs both states the rule
   * instead — for example, forgetting every device when a passkey is registered
   * or removed:
   *
   * ```ts skip-type-checking
   * import { AuthEvents } from "effect-auth"
   * import * as Passkeys from "effect-auth/passkeys"
   *
   * alsoSweepOn: AuthEvents.AuthEvent.matchOrElse(
   *   {
   *     PluginEvent: (event) =>
   *       event.plugin === Passkeys.passkeysPlugin &&
   *       (event.event === Passkeys.registeredEvent || event.event === Passkeys.removedEvent)
   *   },
   *   () => false
   * )
   * ```
   *
   * Defaults to a predicate that is never true.
   */
  readonly alsoSweepOn: (event: AuthEvent) => boolean
}

/**
 * {@link Config}, with every field optional.
 *
 * @category models
 * @since 0.2.0
 */
export interface Options {
  readonly issuer?: string | null | undefined
  readonly digits?: number | undefined
  readonly period?: number | undefined
  readonly algorithm?: Totp.TotpAlgorithm | undefined
  readonly window?: number | undefined
  readonly enrolmentTtl?: Duration.Duration | undefined
  readonly pendingAuthTtl?: Duration.Duration | undefined
  readonly recoveryCodeCount?: number | undefined
  readonly lowRecoveryCodes?: number | undefined
  readonly lockout?: Bucket | undefined
  readonly trustedDeviceTtl?: Duration.Duration | undefined
  readonly trustedDeviceSatisfies?: "none" | "aal2" | undefined
  readonly alsoSweepOn?: ((event: AuthEvent) => boolean) | undefined
}

/**
 * The defaults every unstated {@link Options} field resolves to.
 *
 * @category constructors
 * @since 0.2.0
 */
export const defaults: Config = {
  issuer: null,
  digits: Totp.defaultDigits,
  period: Totp.defaultPeriod,
  algorithm: Totp.defaultAlgorithm,
  window: Totp.defaultWindow,
  enrolmentTtl: Duration.minutes(15),
  pendingAuthTtl: Duration.minutes(10),
  recoveryCodeCount: 10,
  lowRecoveryCodes: 3,
  lockout: lockoutBucket,
  trustedDeviceTtl: Duration.days(30),
  trustedDeviceSatisfies: "none",
  alsoSweepOn: () => false
}

/**
 * Resolves {@link Options} against {@link defaults}.
 *
 * @category constructors
 * @since 0.2.0
 */
export const makeConfig = (options?: Options): Config => withDefaults(defaults, options)

// -----------------------------------------------------------------------------
// Mail
// -----------------------------------------------------------------------------

/**
 * What the "a recovery code was used" message says.
 *
 * @category models
 * @since 0.2.0
 */
export interface RecoveryCodeUsedEmail {
  /** Whose account it was. */
  readonly user: User
  /** How many unspent codes are left. */
  readonly remaining: number
}

/**
 * The {@link TwoFactorEmails} service definition — what an application
 * implements to tell somebody their recovery code was spent.
 *
 * **Gotchas**
 *
 * A service of the plugin's own rather than a method on `AuthEmails`: a plugin
 * cannot widen a library interface every other deployment implements. A
 * deployment that forgets it gets a compile error from {@link layer}, which is
 * the point — spending a recovery code is the strongest signal this library has
 * that an account is being taken over, and it must reach its owner.
 *
 * @category models
 * @since 0.2.0
 */
export interface TwoFactorEmailsService {
  readonly sendRecoveryCodeUsed: (email: RecoveryCodeUsedEmail) => Effect.Effect<void, EmailDeliveryError>
}

/**
 * Delivers this plugin's notifications. See {@link TwoFactorEmailsService}.
 *
 * @category services
 * @since 0.2.0
 */
export class TwoFactorEmails extends Context.Service<TwoFactorEmails, TwoFactorEmailsService>()(
  "effect-auth/two-factor/TwoFactor/TwoFactorEmails"
) {}

// -----------------------------------------------------------------------------
// Cookies
// -----------------------------------------------------------------------------

/**
 * The trusted-device cookie for this deployment.
 *
 * **Details**
 *
 * `__Host-effect_auth.tdev` on a TLS deployment, the bare name on plain HTTP.
 * Host-only, because it is a credential: a sibling subdomain can set a
 * `Domain`-scoped cookie of any name onto the host that reads it, and
 * `__Host-` is what forbids that.
 *
 * @category combinators
 * @since 0.2.0
 */
export const trustedDeviceCookie = (config: AuthConfigService, maxAge: Duration.Duration): PluginCookie =>
  pluginCookieFor(config, { baseName: trustedDeviceCookieBaseName, hostOnly: true, maxAge })

/**
 * Attaches the trusted-device cookie to the response being built.
 *
 * @category combinators
 * @since 0.2.0
 */
export const setTrustedDeviceCookie = (
  config: AuthConfigService,
  value: Redacted.Redacted,
  maxAge: Duration.Duration
): Effect.Effect<void, never, HttpServerRequest.HttpServerRequest> => {
  const cookie = trustedDeviceCookie(config, maxAge)
  return HttpApiBuilder.securitySetCookie(cookie.security, value, cookie.options)
}

/**
 * Expires the trusted-device cookie on the response being built.
 *
 * @category combinators
 * @since 0.2.0
 */
export const clearTrustedDeviceCookie = (
  config: AuthConfigService
): Effect.Effect<void, never, HttpServerRequest.HttpServerRequest> => {
  const cookie = trustedDeviceCookie(config, Duration.zero)
  return HttpApiBuilder.securitySetCookie(cookie.security, Redacted.make(""), cookie.expiredOptions)
}

/**
 * The trusted-device cookie this request presented, if it presented one.
 *
 * @category combinators
 * @since 0.2.0
 */
export const readTrustedDeviceCookie = (
  config: AuthConfigService,
  request: HttpServerRequest.HttpServerRequest
): Option.Option<string> => {
  const value = request.cookies[trustedDeviceCookie(config, Duration.zero).name]
  return value === undefined || value.length === 0 ? Option.none() : Option.some(value)
}

// -----------------------------------------------------------------------------
// Service
// -----------------------------------------------------------------------------

/**
 * A started enrolment, as its owner is shown it.
 *
 * @category models
 * @since 0.2.0
 */
export interface StartedEnrolment {
  /** The shared secret, RFC 4648 base32. */
  readonly secret: Redacted.Redacted
  /** The `otpauth://totp/…` URI a QR code encodes. */
  readonly otpauthUri: Redacted.Redacted
  /** When it stops being confirmable. */
  readonly expiresAt: DateTime.Utc
}

/**
 * Which factor is being answered.
 *
 * @category models
 * @since 0.2.0
 */
export type Factor = Data.TaggedEnum<{
  /** A code from the enrolled authenticator app. */
  Totp: { readonly code: Redacted.Redacted }
  /** One of the codes handed out when the enrolment was confirmed. */
  RecoveryCode: { readonly code: Redacted.Redacted }
}>

/**
 * Constructors and matchers for {@link Factor}.
 *
 * **Details**
 *
 * `Factor.Totp({ code })` is what an HTTP handler builds from its payload, and
 * `Factor.$is("RecoveryCode")` is how the service tells the two apart.
 *
 * **Gotchas**
 *
 * `$is` checks the tag and nothing else, so point it only at a factor a caller
 * of this library constructed — never at something decoded from a request.
 *
 * @category constructors
 * @since 0.2.0
 */
export const Factor = Data.taggedEnum<Factor>()

/**
 * Who is answering it: a sign-in that was interrupted, or a live session being
 * raised.
 *
 * **Details**
 *
 * The discriminator the library's contract calls `ChallengeSubject`. A pending
 * authentication has no session by construction — that is what a second factor
 * *means* — so the two arms cannot be collapsed into one authenticated
 * endpoint.
 *
 * @category models
 * @since 0.2.0
 */
export type ChallengeSubject = Data.TaggedEnum<{
  /** A sign-in that stopped at this plugin, named by its pending token. */
  PendingAuth: { readonly token: Redacted.Redacted }
  /** A live session being raised, with the person holding it. */
  Session: { readonly session: Session; readonly user: User }
}>

/**
 * Constructors and matchers for {@link ChallengeSubject}.
 *
 * **Details**
 *
 * `ChallengeSubject.PendingAuth({ token })` and
 * `ChallengeSubject.Session({ session, user })` are what an HTTP handler
 * resolves a request into; `$is` is how the service and the handler branch.
 *
 * **Gotchas**
 *
 * `$is` checks the tag and nothing else, so point it only at a subject this
 * library resolved — never at something decoded from a request.
 *
 * @category constructors
 * @since 0.2.0
 */
export const ChallengeSubject = Data.taggedEnum<ChallengeSubject>()

/**
 * What {@link TwoFactorService.verify} takes.
 *
 * @category models
 * @since 0.2.0
 */
export interface VerifyOptions {
  readonly factor: Factor
  readonly subject: ChallengeSubject
  /** Recorded on a session this mints, and on a device it remembers. */
  readonly ipAddress: string | null
  /** Recorded for the same reason. */
  readonly userAgent: string | null
}

/**
 * What answering a second factor came to.
 *
 * **Gotchas**
 *
 * One shape for both arms, because both end in a session and a token the
 * caller has to write back: the pending arm's token is a *new* session's, the
 * session arm's is the rotated one the elevation issued.
 *
 * @category models
 * @since 0.2.0
 */
export interface VerifyResult {
  readonly session: Session
  readonly user: User
  readonly token: Redacted.Redacted
  /** Whether the session cookie should outlive the browser session. */
  readonly rememberMe: boolean
}

/**
 * One remembered browser, as its owner sees it.
 *
 * @category models
 * @since 0.2.0
 */
export interface DeviceSummary {
  readonly id: TrustedDeviceId
  readonly label: string | null
  readonly userAgent: string | null
  readonly ipAddress: string | null
  readonly createdAt: DateTime.Utc
  readonly lastUsedAt: DateTime.Utc
  readonly expiresAt: DateTime.Utc
  /** Whether this is the browser that asked. */
  readonly current: boolean
}

/**
 * A newly remembered browser and the cookie value that names it.
 *
 * @category models
 * @since 0.2.0
 */
export interface TrustedDeviceIssued {
  readonly device: TrustedDevice
  /** The signed cookie value. The only copy that will ever exist. */
  readonly value: Redacted.Redacted
  readonly maxAge: Duration.Duration
}

/**
 * The {@link TwoFactor} service definition.
 *
 * @category models
 * @since 0.2.0
 */
export interface TwoFactorService {
  /**
   * Mints a pending enrolment and hands back the secret, once.
   *
   * Starting again while one is pending abandons it. Starting again over a
   * *confirmed* enrolment fails {@link TotpAlreadyEnrolled}.
   */
  readonly startEnrolment: (user: User) => Effect.Effect<StartedEnrolment, TotpAlreadyEnrolled | PersistenceError>

  /**
   * Proves a pending enrolment with a code, and answers the recovery codes —
   * generated at this moment, and shown once.
   *
   * The step the code belongs to is recorded, so the confirming code cannot
   * then be replayed as a sign-in.
   */
  readonly confirmEnrolment: (
    user: User,
    code: Redacted.Redacted
  ) => Effect.Effect<
    ReadonlyArray<Redacted.Redacted>,
    InvalidCode | TotpAlreadyEnrolled | TotpNotEnrolled | RateLimited | PersistenceError
  >

  /**
   * Answers a second factor, for either subject. See {@link VerifyOptions}.
   *
   * **Gotchas**
   *
   * In the pending arm the row is claimed *first* — atomically, so two
   * requests cannot both complete one sign-in — and re-issued under the same
   * handle when the code turns out to be wrong, so a typo costs an attempt
   * rather than the whole sign-in. The re-issue keeps the original expiry, so
   * guessing cannot extend the window.
   */
  readonly verify: (
    options: VerifyOptions
  ) => Effect.Effect<VerifyResult, InvalidCode | InvalidToken | PolicyRefused | RateLimited | PersistenceError>

  /**
   * Removes the enrolment, every recovery code and every remembered browser.
   */
  readonly disable: (user: User) => Effect.Effect<void, TotpNotEnrolled | PersistenceError>

  /**
   * Replaces the recovery-code set and forgets every remembered browser.
   */
  readonly regenerateRecoveryCodes: (
    user: User
  ) => Effect.Effect<ReadonlyArray<Redacted.Redacted>, TotpNotEnrolled | PersistenceError>

  /** Remembers a browser, and answers the cookie value that names it. */
  readonly trustDevice: (options: {
    readonly userId: UserId
    readonly ipAddress: string | null
    readonly userAgent: string | null
    readonly label?: string | undefined
  }) => Effect.Effect<TrustedDeviceIssued, PersistenceError>

  /**
   * The person's live devices, newest first, with the one that asked marked.
   */
  readonly listDevices: (
    userId: UserId,
    presented: Option.Option<string>
  ) => Effect.Effect<ReadonlyArray<DeviceSummary>, PersistenceError>

  /** Forgets one device of `userId`, and answers whether it was theirs. */
  readonly revokeDevice: (id: string, userId: UserId) => Effect.Effect<boolean, PersistenceError>

  /** Forgets every device of `userId`, and answers how many went. */
  readonly revokeDevices: (userId: UserId) => Effect.Effect<number, PersistenceError>

  /**
   * What this plugin does about one core event — the revoke-on matrix, as a
   * function, so that it is testable without a running subscription.
   *
   * **Details**
   *
   * Every remembered browser is forgotten when the password changes (whether
   * by the current one or by a reset), when the address changes, and when every
   * session is revoked. Each of those is somebody saying "I have lost control
   * of this account"; a device that could still skip the second factor
   * afterwards would be the one thing they did not manage to revoke. Every
   * other event is ignored.
   *
   * The enrolment-side revocations — enrol, confirm, disable, recovery use,
   * regenerate — are not here: this plugin performs them itself, inside the
   * operation, rather than by listening to its own events.
   */
  readonly sweepOn: (event: AuthEvent) => Effect.Effect<void, PersistenceError>
}

/**
 * Two-factor authentication. See {@link TwoFactorService}.
 *
 * @category services
 * @since 0.2.0
 */
export class TwoFactor extends Context.Service<TwoFactor, TwoFactorService>()("effect-auth/two-factor/TwoFactor") {}

// -----------------------------------------------------------------------------
// Shared primitives
// -----------------------------------------------------------------------------

/** The keyed digest a stored value is matched by. */
const digestOf = (hmac: HmacService, context: string, value: string): Effect.Effect<string> =>
  Effect.map(hmac.sign(encodeUtf8(`${context}${value}`)), Encoding.encodeBase64Url)

/** Everything but the digits somebody may have typed between them. */
const digitsOf = (code: string): string => code.replace(/[\s-]/g, "")

/**
 * The kinds of second factor a person can answer a challenge with.
 *
 * `recoveryCode` only when there is one left to spend, so a client is not
 * offered a prompt that cannot succeed.
 */
const factorsFor = (
  store: TwoFactorStoreService,
  userId: UserId
): Effect.Effect<ReadonlyArray<string>, PersistenceError> =>
  Effect.map(store.countRecoveryCodes(userId), (remaining) =>
    remaining > 0 ? [totpMethod, recoveryCodeMethod] : [totpMethod]
  )

/**
 * The authenticators this plugin contributes for one person.
 *
 * **Gotchas**
 *
 * A *pending* enrolment contributes nothing: it is not a way into the account,
 * and counting it would let `Accounts.unlink` remove the last real credential
 * on the strength of a factor nobody has proved.
 */
const summariesFor = (
  store: TwoFactorStoreService,
  userId: UserId
): Effect.Effect<ReadonlyArray<AuthenticatorSummary>, PersistenceError> =>
  Effect.gen(function* () {
    const enrolment = yield* store.findTotp(userId)
    if (Option.isNone(enrolment) || enrolment.value.verifiedAt === null) return []
    const remaining = yield* store.countRecoveryCodes(userId)
    const totp: AuthenticatorSummary = {
      type: totpAuthenticatorType,
      // One enrolment per person, so the person is its identity.
      id: userId,
      name: null,
      verifiedAt: enrolment.value.verifiedAt,
      lastUsedAt: null,
      // A second factor is not a way *in* by itself: a deployment must never
      // conclude from this that the account can be signed into.
      signIn: false,
      secondFactor: true,
      restricted: false
    }
    if (remaining === 0) return [totp]
    return [
      totp,
      {
        type: recoveryCodesAuthenticatorType,
        id: userId,
        name: null,
        verifiedAt: enrolment.value.verifiedAt,
        lastUsedAt: null,
        signIn: false,
        secondFactor: true,
        restricted: false
      }
    ]
  })

/**
 * Spends the trusted-device cookie this request presented, rotating its token,
 * and answers whether the browser may skip the prompt.
 *
 * **Details**
 *
 * The envelope binds the token to a user id, so a cookie cannot be tried
 * against another account, and the row is checked against the same id — belt
 * and braces, because the row is the authority. The rotation is one guarded
 * `UPDATE` that also enforces the absolute expiry, and the new cookie is
 * attached to whatever response the request ends up producing.
 */
const spendTrustedDevice = (
  config: AuthConfigService,
  hmac: HmacService,
  tokens: TokenService,
  store: TwoFactorStoreService,
  userId: UserId
): Effect.Effect<boolean, PersistenceError> =>
  Effect.gen(function* () {
    // The decider runs inside whichever flow is signing in, and only some of
    // those flows have a request behind them: a direct domain call has none,
    // and a browser is exactly what a device cookie describes. So the request
    // is read optionally rather than required, which is also what keeps the
    // pipeline's own signature free of an HTTP requirement.
    const maybeRequest = yield* Effect.serviceOption(HttpServerRequest.HttpServerRequest)
    if (Option.isNone(maybeRequest)) return false
    const request = maybeRequest.value
    const presented = readTrustedDeviceCookie(config, request)
    if (Option.isNone(presented)) return false

    const opened = yield* openDevice(hmac, presented.value)
    if (Option.isNone(opened) || opened.value.userId !== userId) return false

    const tokenHash = yield* digestOf(hmac, trustedDeviceHashContext, opened.value.token)
    const next = yield* tokens.generateToken
    const nextHash = yield* digestOf(hmac, trustedDeviceHashContext, Redacted.value(next))
    const now = yield* DateTime.now
    const rotated = yield* store.useDevice(tokenHash, nextHash, now)
    if (Option.isNone(rotated) || rotated.value.userId !== userId) return false

    // The absolute expiry is the row's and is never moved; the cookie repeats
    // whatever is left of it, so a browser stops presenting a device the
    // database would refuse anyway.
    const remaining = DateTime.distance(now, rotated.value.expiresAt)
    const sealed = yield* sealDevice(hmac, userId, Redacted.value(next))
    yield* setTrustedDeviceCookie(config, Redacted.make(sealed), Duration.max(Duration.zero, remaining)).pipe(
      Effect.provideService(HttpServerRequest.HttpServerRequest, request)
    )
    return true
  })

/**
 * The cookie a remembered browser carries: the user it belongs to and the
 * token, under this deployment's signature.
 *
 * **Details**
 *
 * The binding is the point. A device cookie names a row, and the row names its
 * owner — but signing the two together means a cookie cannot even be *tried*
 * against another account, and a value this deployment did not write is not a
 * cookie at all. The tag covers {@link trustedDeviceContext}, so a value signed
 * by some other part of this library under the same key is refused here.
 */
const sealDevice = (hmac: HmacService, userId: string, token: string): Effect.Effect<string> =>
  hmac.signedValue(trustedDeviceContext, encodeUtf8(`${userId}${deviceBindingSeparator}${token}`))

/**
 * The user and the token inside a cookie this deployment signed, or `None` for
 * every way of not being one.
 */
const openDevice = (
  hmac: HmacService,
  value: string
): Effect.Effect<Option.Option<{ readonly userId: string; readonly token: string }>> =>
  Effect.map(hmac.verifySignedValue(trustedDeviceContext, value), (opened) => {
    if (Option.isNone(opened)) return Option.none()
    const payload = new TextDecoder().decode(opened.value)
    const at = payload.indexOf(deviceBindingSeparator)
    if (at <= 0 || at === payload.length - 1) return Option.none()
    return Option.some({ userId: payload.slice(0, at), token: payload.slice(at + 1) })
  })

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

/**
 * What {@link make} needs.
 *
 * **Gotchas**
 *
 * Everything but {@link TwoFactorEmails} is published by `Auth.layer`, so a
 * consumer composes this plugin over their deployment and supplies one mailer.
 * `AuthCipher` is *not* here: this plugin provides its own, under its own key
 * class, so a TOTP secret is not readable by anything that reads another class
 * of secret.
 *
 * @category models
 * @since 0.2.0
 */
export type Requirements =
  | TwoFactorEmails
  | AuthConfig
  | AuthEvents
  | Hmac
  | Token
  | Verifications
  | SignIn
  | Sessions
  | UserStore
  | SqlClient.SqlClient
  | RateLimiter.RateLimiter

/**
 * Builds the {@link TwoFactor} implementation.
 *
 * **Gotchas**
 *
 * Every service is resolved here, when the layer is built, so that no method
 * carries a request-time requirement — the shape every service in this library
 * has.
 *
 * @category constructors
 * @since 0.2.0
 */
export const make: (
  options?: Options
) => Effect.Effect<TwoFactorService, never, Requirements | TwoFactorStore | AuthCipher | Crypto.Crypto> =
  Effect.fnUntraced(function* (options?: Options) {
    const settings = makeConfig(options)
    const config = yield* AuthConfig
    const events = yield* AuthEvents
    const emails = yield* TwoFactorEmails
    const hmac = yield* Hmac
    const tokens = yield* Token
    const cipher: AuthCipherService = yield* AuthCipher
    const verifications = yield* Verifications
    const { complete: completeSignIn } = yield* SignIn
    const sessions = yield* Sessions
    const users = yield* UserStore
    const store = yield* TwoFactorStore
    const limiter = yield* RateLimiter.RateLimiter
    const crypto = yield* Crypto.Crypto

    if (settings.trustedDeviceSatisfies === "aal2") {
      yield* Effect.logWarning(
        "two-factor: trustedDeviceSatisfies 'aal2' is not conformant and cannot be honoured — a SignInPipeline decider states whether a session may be minted, not what evidence it records. Behaving as 'none'."
      )
    }

    const issuer = settings.issuer ?? issuerOf(config)

    /**
     * The per-account budget, spent before any comparison runs. `always`: this is
     * a brute-force bound on a six-digit code, not a throttle, so it is spent
     * whether or not the deployment's IP throttles (`rateLimit.enabled`) are on.
     */
    const spendAttempt = (userId: UserId): Effect.Effect<void, RateLimited> =>
      consumeKeyed({ config, limiter, bucket: settings.lockout, key: userId, always: true })

    const publish = (event: string, userId: UserId, data: Record<string, unknown>) =>
      publishSafely(events, PluginEvent.make({ plugin: twoFactorPlugin, event, userId, data }))

    const secretOf = (enrolment: TotpEnrolment): Effect.Effect<Uint8Array> =>
      // A ciphertext this deployment cannot read is an operational fault — a
      // rotated secret, a restored dump — not something the person typing a
      // code can act on.
      Effect.map(Effect.orDie(cipher.decrypt(enrolment.secretCiphertext, enrolment.userId)), Redacted.value)

    const hashRecoveryCode = (code: string) => digestOf(hmac, recoveryCodeHashContext, code)

    const newRecoveryCodes = (userId: UserId) =>
      Effect.gen(function* () {
        const codes = yield* RecoveryCodes.generate(settings.recoveryCodeCount).pipe(
          Effect.provideService(Crypto.Crypto, crypto)
        )
        const rows = yield* Effect.forEach(codes, (code) =>
          Effect.flatMap(hashRecoveryCode(Redacted.value(code)), (codeHash) =>
            insertRow(RecoveryCode.insert, { userId, codeHash, usedAt: null })
          )
        )
        yield* store.replaceRecoveryCodes(userId, rows)
        // Shown in the format they are printed in; the stored form is the
        // normalised one, which is what a person's transcription is compared
        // against.
        return codes.map((code) => Redacted.make(RecoveryCodes.format(Redacted.value(code))))
      })

    const startEnrolment = Effect.fnUntraced(function* (user: User) {
      const bytes = yield* Effect.orDie(crypto.randomBytes(secretBytes))
      const secretCiphertext = yield* cipher.encrypt(Redacted.make(bytes), user.id)
      const row = yield* insertRow(TotpEnrolment.insert, {
        userId: user.id,
        secretCiphertext,
        verifiedAt: null,
        lastUsedStep: null
      })
      const stored = yield* store.upsertPendingTotp(row)
      if (Option.isNone(stored)) return yield* TotpAlreadyEnrolled.make()
      return {
        secret: Redacted.make(encodeBase32(bytes)),
        otpauthUri: Redacted.make(
          Totp.otpauthUri({
            issuer,
            account: user.email,
            secret: bytes,
            algorithm: settings.algorithm,
            digits: settings.digits,
            period: settings.period
          })
        ),
        expiresAt: DateTime.addDuration(stored.value.createdAt, settings.enrolmentTtl)
      } satisfies StartedEnrolment
    })

    const confirmEnrolment = Effect.fnUntraced(function* (user: User, code: Redacted.Redacted) {
      const enrolment = yield* store.findTotp(user.id)
      if (Option.isNone(enrolment)) return yield* TotpNotEnrolled.make()
      if (enrolment.value.verifiedAt !== null) return yield* TotpAlreadyEnrolled.make()

      const now = yield* DateTime.now
      const expiresAt = DateTime.addDuration(enrolment.value.createdAt, settings.enrolmentTtl)
      // A pending enrolment nobody finished is not a factor; it is refused
      // rather than confirmed, and starting again mints a new secret.
      if (DateTime.isLessThanOrEqualTo(expiresAt, now)) return yield* TotpNotEnrolled.make()

      yield* spendAttempt(user.id)
      const secret = yield* secretOf(enrolment.value)
      const matched = yield* Totp.verify({
        secret,
        code: digitsOf(Redacted.value(code)),
        now,
        window: settings.window,
        lastUsedStep: enrolment.value.lastUsedStep,
        period: settings.period,
        digits: settings.digits,
        algorithm: settings.algorithm
      })
      if (Option.isNone(matched)) return yield* InvalidCode.make()

      // The step is recorded by the same statement that makes the enrolment
      // active, so the code that proved it cannot then sign anybody in.
      const confirmed = yield* store.confirmTotp(user.id, now, matched.value)
      if (Option.isNone(confirmed)) return yield* TotpAlreadyEnrolled.make()

      const codes = yield* newRecoveryCodes(user.id)
      // Enrolling a factor is one of the moments every remembered browser is
      // forgotten: whoever set this up is at the keyboard now, and a device
      // trusted before it cannot have been trusted *for* it.
      const forgotten = yield* store.deleteDevices(user.id)
      yield* publish("FactorEnrolled", user.id, {
        factor: totpAuthenticatorType,
        recoveryCodes: codes.length,
        trustedDevicesRevoked: forgotten
      })
      return codes
    })

    const disable = Effect.fnUntraced(function* (user: User) {
      const removed = yield* store.deleteTotp(user.id)
      if (!removed) return yield* TotpNotEnrolled.make()
      const codes = yield* store.deleteRecoveryCodes(user.id)
      const devices = yield* store.deleteDevices(user.id)
      yield* publish("FactorRemoved", user.id, {
        factor: totpAuthenticatorType,
        recoveryCodes: codes,
        trustedDevicesRevoked: devices
      })
    })

    const regenerateRecoveryCodes = Effect.fnUntraced(function* (user: User) {
      const enrolment = yield* store.findTotp(user.id)
      if (Option.isNone(enrolment) || enrolment.value.verifiedAt === null) return yield* TotpNotEnrolled.make()
      const codes = yield* newRecoveryCodes(user.id)
      const devices = yield* store.deleteDevices(user.id)
      yield* publish("RecoveryCodesRegenerated", user.id, {
        count: codes.length,
        trustedDevicesRevoked: devices
      })
      return codes
    })

    /**
     * Checks one factor and answers what it proved, spending whatever the
     * check consumes. Every way of being wrong is one `InvalidCode`: a code for
     * a step already used, a code for an enrolment that was never confirmed, a
     * recovery code that was spent or never existed.
     */
    const checkFactor = Effect.fnUntraced(function* (userId: UserId, factor: Factor) {
      if (Factor.$is("RecoveryCode")(factor)) {
        const normalised = RecoveryCodes.normalise(Redacted.value(factor.code))
        const codeHash = yield* hashRecoveryCode(normalised)
        const now = yield* DateTime.now
        const spent = yield* store.consumeRecoveryCode(userId, codeHash, now)
        if (!spent) return yield* InvalidCode.make()
        return recoveryCodeEvidence
      }

      const enrolment = yield* store.findTotp(userId)
      // A pending enrolment is never accepted for authentication.
      if (Option.isNone(enrolment) || enrolment.value.verifiedAt === null) return yield* InvalidCode.make()
      const secret = yield* secretOf(enrolment.value)
      const now = yield* DateTime.now
      const matched = yield* Totp.verify({
        secret,
        code: digitsOf(Redacted.value(factor.code)),
        now,
        window: settings.window,
        lastUsedStep: enrolment.value.lastUsedStep,
        period: settings.period,
        digits: settings.digits,
        algorithm: settings.algorithm
      })
      if (Option.isNone(matched)) return yield* InvalidCode.make()
      // The replay rule is the statement, not the comparison: two requests
      // carrying the same code produce exactly one success.
      const consumed = yield* store.consumeTotpStep(userId, matched.value)
      if (!consumed) return yield* InvalidCode.make()
      return totpEvidence
    })

    /** What spending a recovery code costs everything else. */
    const afterRecovery = Effect.fnUntraced(function* (user: User) {
      const devices = yield* store.deleteDevices(user.id)
      const remaining = yield* store.countRecoveryCodes(user.id)
      yield* publish("RecoveryCodeUsed", user.id, { remaining, trustedDevicesRevoked: devices })
      if (remaining <= settings.lowRecoveryCodes) {
        yield* publish("RecoveryCodesLow", user.id, { remaining })
      }
      // The one message this plugin sends, and the strongest signal it has
      // that an account is being taken over. A delivery failure is logged and
      // dropped: it must not change what the caller observes.
      yield* deliverEmail(
        emails.sendRecoveryCodeUsed({ user, remaining }),
        "two-factor: the recovery-code notification could not be delivered"
      )
    })

    /**
     * Puts a claimed pending row back under the handle its owner is holding,
     * with whatever is left of its original lifetime.
     *
     * The same discipline `Challenges` runs for a short code: an attempt is
     * spent by a comparison that ran, and the *state* the attempt was made
     * against survives it. The expiry is recomputed rather than extended, so a
     * caller cannot keep a pending authentication alive by guessing at it.
     */
    const reissuePending = (
      expiresAt: DateTime.Utc,
      secret: Redacted.Redacted,
      payload: PendingAuthPayload
    ): Effect.Effect<void, PersistenceError> =>
      Effect.gen(function* () {
        const now = yield* DateTime.now
        const remaining = DateTime.distance(now, expiresAt)
        if (!Duration.isPositive(remaining)) return
        yield* Effect.asVoid(
          verifications.issue({ purpose: pendingAuthPurpose, subject: payload.userId, ttl: remaining, payload, secret })
        )
      })

    const verify = Effect.fnUntraced(function* (options: VerifyOptions) {
      if (ChallengeSubject.$is("Session")(options.subject)) {
        const { session, user } = options.subject
        yield* spendAttempt(user.id)
        const evidence = yield* checkFactor(user.id, options.factor)
        const elevated = yield* sessions.elevate(session, evidence)
        if (Factor.$is("RecoveryCode")(options.factor)) yield* afterRecovery(user)
        return {
          session: elevated.session,
          user,
          token: elevated.token,
          rememberMe: elevated.session.rememberMe
        } satisfies VerifyResult
      }

      // The half of the token that addresses the row, read before the claim
      // consumes it: it is what puts the row back under the same handle when
      // the code turns out to be wrong. `claim` parses the token the same way,
      // so this cannot accept anything the claim would not.
      const parts = decodeSubjectToken(options.subject.token)
      if (Option.isNone(parts)) return yield* InvalidToken.make()

      // The pending row is claimed first, and atomically: two requests racing
      // to finish one sign-in cannot both mint a session.
      const claimed = yield* verifications.claim(pendingAuthPurpose, options.subject.token)
      const payload = claimed.payload
      const userId = payload.userId

      const attempt = yield* Effect.result(
        Effect.gen(function* () {
          yield* spendAttempt(userId)
          return yield* checkFactor(userId, options.factor)
        })
      )
      if (Result.isFailure(attempt)) {
        // A wrong code costs an attempt, not the sign-in: the row goes back
        // under the *same* handle, so the cookie the browser is holding still
        // names it, and with the *original* expiry, so guessing cannot extend
        // the window.
        yield* reissuePending(claimed.verification.expiresAt, parts.value.secret, payload)
        return yield* attempt.failure
      }

      const found = yield* users.findById(userId)
      // The account went away between the two halves of the sign-in. The
      // pending row is already spent, so there is nothing to put back.
      if (Option.isNone(found)) return yield* InvalidToken.make()
      const user = found.value

      const result = yield* completeSignIn({
        user,
        // The sign-in was interrupted after `beforeSessionCreate` had already
        // seen its real source and allowed it; this half names the plugin that
        // finished it, carrying the original method so the `SignedIn` event
        // reads the same as an uninterrupted one.
        source: ProvisionSource.Plugin({ plugin: payload.method }),
        evidence: [...payload.evidence, attempt.success],
        current: Option.none(),
        request: {
          rememberMe: payload.rememberMe,
          ipAddress: options.ipAddress,
          userAgent: options.userAgent
        }
      })
      if (SignInResult.$is("Challenge")(result)) {
        // Another factor plugin owes something as well. This endpoint has no
        // way to answer a second challenge, so it fails closed rather than
        // leaving a half-authenticated caller holding two pending rows.
        return yield* PolicyRefused.make({ code: mfaRequiredCode })
      }

      if (Factor.$is("RecoveryCode")(options.factor)) yield* afterRecovery(user)
      return {
        session: result.session,
        user,
        token: result.token,
        rememberMe: payload.rememberMe
      } satisfies VerifyResult
    })

    const trustDevice = Effect.fnUntraced(function* (options: {
      readonly userId: UserId
      readonly ipAddress: string | null
      readonly userAgent: string | null
      readonly label?: string | undefined
    }) {
      const token = yield* tokens.generateToken
      const tokenHash = yield* digestOf(hmac, trustedDeviceHashContext, Redacted.value(token))
      const now = yield* DateTime.now
      const row = yield* insertRow(TrustedDevice.insert, {
        userId: options.userId,
        tokenHash,
        expiresAt: DateTime.addDuration(now, settings.trustedDeviceTtl),
        userAgent: options.userAgent,
        ipAddress: options.ipAddress,
        label: options.label ?? null
      })
      const device = yield* store.createDevice(row)
      yield* publish("TrustedDeviceAdded", options.userId, { deviceId: device.id })
      return {
        device,
        value: Redacted.make(yield* sealDevice(hmac, options.userId, Redacted.value(token))),
        maxAge: settings.trustedDeviceTtl
      } satisfies TrustedDeviceIssued
    })

    const listDevices = Effect.fnUntraced(function* (userId: UserId, presented: Option.Option<string>) {
      const now = yield* DateTime.now
      const rows = yield* store.listDevices(userId, now)
      const currentHash = yield* Option.match(presented, {
        onNone: () => Effect.succeed<string | null>(null),
        onSome: (value) =>
          Effect.gen(function* () {
            const opened = yield* openDevice(hmac, value)
            if (Option.isNone(opened) || opened.value.userId !== userId) return null
            return yield* digestOf(hmac, trustedDeviceHashContext, opened.value.token)
          })
      })
      return rows.map((row): DeviceSummary => ({
        id: row.id,
        label: row.label,
        userAgent: row.userAgent,
        ipAddress: row.ipAddress,
        createdAt: row.createdAt,
        lastUsedAt: row.lastUsedAt,
        expiresAt: row.expiresAt,
        current: currentHash !== null && row.tokenHash === currentHash
      }))
    })

    const revokeDevice = Effect.fnUntraced(function* (id: string, userId: UserId) {
      const removed = yield* store.deleteDevice(id, userId)
      if (removed) yield* publish("TrustedDeviceRevoked", userId, { scope: "single", count: 1 })
      return removed
    })

    const revokeDevices = Effect.fnUntraced(function* (userId: UserId) {
      const count = yield* store.deleteDevices(userId)
      if (count > 0) yield* publish("TrustedDeviceRevoked", userId, { scope: "all", count })
      return count
    })

    const sweepOn = (event: AuthEvent): Effect.Effect<void, PersistenceError> => {
      const shouldSweep =
        AuthEvent.isAnyOf(["PasswordChanged", "EmailChanged"])(event) ||
        (AuthEvent.isAnyOf(["SessionRevoked"])(event) && event.scope === "all") ||
        settings.alsoSweepOn(event)
      // An event that names nobody sweeps nobody: a `PluginEvent` may carry a
      // null `userId`, and this is not a rule that gets to guess whose
      // browsers it meant.
      if (!shouldSweep || event.userId === null) return Effect.void
      return Effect.asVoid(revokeDevices(event.userId))
    }

    return TwoFactor.of({
      startEnrolment,
      confirmEnrolment,
      verify,
      disable,
      regenerateRecoveryCodes,
      trustDevice,
      listDevices,
      revokeDevice,
      revokeDevices,
      sweepOn
    })
  })

/**
 * The host an authenticator app lists an enrolment under, when the deployment
 * states no issuer: `baseUrl`'s host, which is what a person recognises.
 */
const issuerOf = (config: AuthConfigService): string =>
  Option.match(originOf(config.baseUrl), {
    onNone: () => config.baseUrl,
    onSome: (origin) => origin.replace(/^https?:\/\//, "")
  })

/**
 * Provides {@link TwoFactor} over a deployment.
 *
 * **Details**
 *
 * The plugin's own `AuthCipher` — under {@link cipherKeyInfo} — and the
 * WebCrypto `Crypto` default are provided *into* this layer, so neither
 * appears in {@link Requirements} and neither shadows the deployment's.
 *
 * **Example**
 *
 * ```ts skip-type-checking
 * import { Layer } from "effect"
 * import { TwoFactor } from "effect-auth"
 *
 * const TwoFactorLive = TwoFactor.layer({ trustedDeviceTtl: Duration.days(14) }).pipe(
 *   Layer.provideMerge(AuthLive),
 *   Layer.provide(MyTwoFactorMailer)
 * )
 * ```
 *
 * @category layers
 * @since 0.2.0
 */
export const layer = (options?: Options): Layer.Layer<TwoFactor, never, Requirements> => {
  const service = Layer.effect(TwoFactor, make(options))
  // One `service`, referenced twice: layer memoisation is by reference, so the
  // subscription runs against the same instance the deployment gets.
  return Layer.merge(service, Layer.effectDiscard(sweepSubscription).pipe(Layer.provide(service))).pipe(
    Layer.provide(cipherLayer(cipherKeyInfo)),
    Layer.provide(layerWebCrypto),
    // The plugin's own three tables, over whatever `SqlClient` the deployment
    // was given. Stateless, so a second instance beside the one `layerSeams`
    // builds is the same store, not a second opinion.
    Layer.provide(storeLayer)
  )
}

/**
 * Runs {@link TwoFactorService.sweepOn} over every event the deployment
 * publishes, for as long as the plugin's layer is alive.
 *
 * **Details**
 *
 * The revoke-on matrix is worthless as documentation. A remembered browser that
 * survives a password reset is the exact "permanent bypass" the absolute expiry
 * was written to bound: somebody who phished one code and ticked *remember this
 * browser* keeps their way in for thirty days after the victim has changed the
 * password and signed out everywhere. Leaving the subscription as five lines in
 * a README makes that the default for every deployment that does not read it,
 * so `layer` installs it and it lives and dies with the plugin.
 *
 * A sweep that fails is logged and dropped: it is a background reaction to
 * something that has already committed, and there is nothing to return it to.
 */
const sweepSubscription: Effect.Effect<void, never, TwoFactor | AuthEvents | Scope.Scope> = Effect.gen(function* () {
  const events = yield* AuthEvents
  const twoFactor = yield* TwoFactor
  yield* Effect.forkScoped(
    Stream.runForEach(events.stream, (event) =>
      Effect.catchCause(twoFactor.sweepOn(event), (cause) =>
        Effect.logWarning("effect-auth/two-factor: a trusted-device sweep failed", cause)
      )
    )
  )
})

// -----------------------------------------------------------------------------
// Seams
// -----------------------------------------------------------------------------

/**
 * The two `Context.Reference` seams this plugin installs.
 *
 * @category models
 * @since 0.2.0
 */
export interface Seams {
  /** The decider that turns a first factor into a challenge. */
  readonly pipeline: SignInPipelineService
  /** What this plugin contributes to `Authenticators`. */
  readonly authenticators: AuthenticatorsService
}

/**
 * Builds {@link Seams}.
 *
 * **Gotchas**
 *
 * These are *references*, read when the services that consult them are built,
 * so they must be provided **underneath** `Auth.layer` — which is why they are
 * built from the four services below rather than from {@link TwoFactor}, which
 * is built above it. All four are either derivable from the deployment's own
 * configuration and database or are stateless, so the private instances this
 * builds agree byte for byte with the deployment's: `Hmac` is keyed from the
 * same secret, `Verifications` writes the same rows, and the store is the same
 * three tables.
 *
 * @category constructors
 * @since 0.2.0
 */
export const makeSeams: (
  options?: Options
) => Effect.Effect<Seams, never, AuthConfig | Hmac | Token | Verifications | TwoFactorStore> = Effect.fnUntraced(
  function* (options?: Options) {
    const settings = makeConfig(options)
    const config = yield* AuthConfig
    const hmac = yield* Hmac
    const tokens = yield* Token
    const verifications = yield* Verifications
    const store = yield* TwoFactorStore

    const decide = (options: CompleteOptions): Effect.Effect<SignInDecision, PolicyRefused | PersistenceError> =>
      Effect.gen(function* () {
        const now = yield* DateTime.now
        const evidence = options.evidence.map((entry) => stampEvidence(entry, now))
        // A ceremony this plugin has already answered is never asked again.
        //
        // The test is "is one of my own factors on the log", NOT "does the log
        // derive to aal2". Two possession entries are one factor kind under
        // `deriveAal`, so a possession-only first factor — OAuth, email-otp,
        // SMS, One Tap, a UV=0 passkey — completed with a TOTP or recovery
        // code still reads `aal1`, and a level test would re-enter here,
        // issue a second pending row, and leave `verify` failing
        // `PolicyRefused("mfa_required")` with the code already spent. That is
        // a lockout of every non-password sign-in path, and it is the reason
        // this branch is keyed on the method and not on the level.
        if (answeredHere(evidence)) return proceed
        // A ceremony that reached two factors in one step — a user-verified
        // passkey — is not asked for another one either.
        if (deriveAal(evidence) === "aal2") return proceed

        const enrolment = yield* store.findTotp(options.user.id)
        // Nothing enrolled, or an enrolment nobody ever proved: this plugin
        // has nothing to ask for.
        if (Option.isNone(enrolment) || enrolment.value.verifiedAt === null) return proceed

        const trusted = yield* spendTrustedDevice(config, hmac, tokens, store, options.user.id)
        if (trusted) return proceed

        const available = yield* factorsFor(store, options.user.id)
        const issued = yield* verifications.issue({
          purpose: pendingAuthPurpose,
          subject: options.user.id,
          ttl: settings.pendingAuthTtl,
          payload: {
            userId: options.user.id,
            evidence,
            rememberMe: options.request.rememberMe !== false,
            method: methodOf(options.source)
          }
        })
        return SignInDecision.Challenge({
          kind: challengeKind,
          available,
          token: issued.token,
          expiresAt: issued.expiresAt
        })
      })

    return {
      pipeline: { decide },
      authenticators: {
        list: (userId) => summariesFor(store, userId),
        // A sweep counts the authenticators it removed. The remembered
        // browsers go too — an account being swept is one whose every way in
        // is being taken away — but a device is not an authenticator and is
        // not counted as one.
        revokeAll: (userId) =>
          Effect.gen(function* () {
            const enrolment = yield* store.deleteTotp(userId)
            const codes = yield* store.deleteRecoveryCodes(userId)
            yield* store.deleteDevices(userId)
            return (enrolment ? 1 : 0) + (codes > 0 ? 1 : 0)
          })
      }
    } satisfies Seams
  }
)

/**
 * The services {@link makeSeams} is built from, over a configuration and a
 * database.
 *
 * **Details**
 *
 * Private instances of four services the deployment also has, built here
 * because the seams have to exist *before* the deployment does. All four agree
 * with the deployment's by construction: `Hmac` is keyed from the same secret,
 * `Token` is stateless, `Verifications` writes the same rows through the same
 * digest, and the store is the same three tables. `layerSeams` provides this
 * into itself rather than merging it out, so nothing here becomes part of what
 * the plugin publishes.
 *
 * **When to use**
 *
 * Only to build {@link makeSeams} somewhere other than {@link layerSeams} — a
 * test harness that has to hand the two references to a deployment builder as
 * *values*. Applications use {@link layerSeams}.
 *
 * @category layers
 * @since 0.2.0
 */
export const seamServices: Layer.Layer<
  Hmac | Token | Verifications | TwoFactorStore,
  never,
  AuthConfig | SqlClient.SqlClient
> = Layer.mergeAll(
  hmacLayer,
  tokenLayer.pipe(Layer.provide(layerWebCrypto)),
  verificationsLayer.pipe(
    Layer.provide(tokenLayer.pipe(Layer.provide(layerWebCrypto))),
    Layer.provide(SqlStores.layer)
  ),
  storeLayer
)

/**
 * Installs this plugin's two `Context.Reference` seams: the sign-in decider and
 * the authenticator contributor.
 *
 * **When to use**
 *
 * Underneath `Auth.layer`, always — a reference is read when the services that
 * consult it are built, so one provided above the deployment is never seen.
 * `AuthConfig` is a requirement rather than something this builds, so the
 * deployment and the plugin cannot end up disagreeing about the secret or the
 * cookie names; discharge it with `Auth.layerConfigOnly` over the *same*
 * options object.
 *
 * **Example**
 *
 * ```ts skip-type-checking
 * import { Layer } from "effect"
 * import { Auth, TwoFactor } from "effect-auth"
 *
 * const options = { baseUrl, secret, emailPassword: { enabled: true } }
 * const Seams = TwoFactor.layerSeams().pipe(
 *   Layer.provide(Layer.merge(Auth.layerConfigOnly(options), PgLive))
 * )
 *
 * const AuthLive = Auth.layer(options).pipe(
 *   Layer.provide(Seams),
 *   Layer.provide(PgLive),
 *   Layer.provide(MyMailer)
 * )
 * ```
 *
 * @category layers
 * @since 0.2.0
 */
export const layerSeams = (options?: Options): Layer.Layer<never, never, AuthConfig | SqlClient.SqlClient> =>
  Layer.unwrap(
    Effect.map(makeSeams(options), (seams) =>
      Layer.mergeAll(
        // Both are appended rather than installed: a plugin cannot know what
        // else the deployment put here, and replacing it would silently
        // discard another factor's decider or another credential's summaries.
        Layer.effect(
          SignInPipeline,
          Effect.map(SignInPipeline, (installed) => combinePipelines(installed, seams.pipeline))
        ),
        Layer.effect(
          Authenticators,
          Effect.map(Authenticators, (installed) => combineAuthenticators(installed, seams.authenticators))
        )
      )
    )
  ).pipe(Layer.provide(seamServices))
