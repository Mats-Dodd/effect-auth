/**
 * A verified phone number: a contact detail, a way to sign in, and a way to
 * raise a live session's assurance.
 *
 * **Details**
 *
 * Three capabilities, declared separately, because they are three different
 * decisions. Attaching a number to an account is a contact detail and is on by
 * default; *signing in* with one is a passwordless credential and is off by
 * default; raising an existing session with one is a second factor. A
 * deployment that wanted the first must not get the second for free — that is
 * how a contact field becomes an unconditional passwordless sign-in nobody
 * asked for.
 *
 * The code itself is `Challenges` over `Verifications`: six digits, ten
 * minutes, five attempts, the digest peppered with the deployment secret and
 * the attempt budget bound to a *handle* the browser holds in a `__Host-`
 * cookie. The number is never the identifier of a challenge on its own —
 * `phone:verify`, `phone:signIn` and `phone:stepUp` are three purposes, so a
 * code answered under one can never be spent under another.
 *
 * **Gotchas — the two rules that shape this module**
 *
 * *Every number is E.164 or it is nothing.* `E164.normalize` runs at each
 * boundary and the canonical form is the only thing stored, keyed, rate-limited
 * or compared. A validator that is a predicate rather than a transform, called
 * on some paths and not others, is how `+1 555-0100` and `+15550100` become two
 * accounts.
 *
 * *An SMS costs money, so the defaults refuse to send one.*
 * {@link Config.allowedCountries} is empty by default and an empty list denies
 * everything: a deployment states where its messages may go before the first
 * one leaves. Four rate limits ship on and are counted against the destination
 * number, the destination prefix, the calling client and the authenticated
 * subject, because toll fraud is bought by the range and not by the number.
 *
 * @since 0.2.0
 */
import { Context, DateTime, Duration, Effect, Layer, Option, Redacted, Schema } from "effect"
import { RateLimiter } from "effect/unstable/persistence"
import { AuthConfig } from "../config/AuthConfig.js"
import type { AuthenticatorsService, AuthenticatorSummary } from "../domain/Authenticators.js"
import { append as appendAuthenticators, Authenticators, list as listAuthenticators } from "../domain/Authenticators.js"
import { Challenges } from "../domain/Challenges.js"
import type { RateLimited } from "../domain/Errors.js"
import { InvalidCode } from "../domain/Errors.js"
import { AuthEvents, PluginEvent, publishSafely } from "../domain/Events.js"
import type { PolicyRefused } from "../domain/Hooks.js"
import { ProvisionSource } from "../domain/Hooks.js"
import type { Session, User, UserId } from "../domain/Schema.js"
import type { ElevatedSession, Evidence } from "../domain/Sessions.js"
import { Sessions } from "../domain/Sessions.js"
import type { SignInResult } from "../domain/SignIn.js"
import { SignIn } from "../domain/SignIn.js"
import type { PersistenceError, SessionWithUser } from "../domain/Stores.js"
import { isUniqueViolation, UserStore } from "../domain/Stores.js"
import type { TokenPurpose } from "../domain/Verifications.js"
import { decodeSubjectToken, purpose } from "../domain/Verifications.js"
import type { Bucket } from "../http/RateLimits.js"
import { consumeKeyed } from "../http/RateLimits.js"
import { annotateAuthLogs } from "../internal/effects.js"
import { withDefaults } from "../internal/records.js"
import {
  InvalidPhoneNumber,
  PhoneAlreadyInUse,
  PhoneCountryNotAllowed,
  PhoneNotVerified,
  RestrictedFactorNotAllowed
} from "./Api.js"
import * as E164 from "./E164.js"
import type { PhoneNumber, PhoneStoreService } from "./Store.js"
import { isVerified, PhoneStore } from "./Store.js"

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/**
 * The name this plugin publishes `PluginEvent`s under.
 *
 * **Details**
 *
 * Two events, both for watching the thing a deployment paying per message
 * cares about: `"PhoneOtpIssued"` when a code is minted and `"PhoneOtpVerified"`
 * when one is answered. The ratio between them is the send/verify conversion,
 * and a collapse in it is what toll fraud looks like from the outside. Neither
 * carries a code, a handle or a whole number.
 *
 * @category constructors
 * @since 0.2.0
 */
export const phonePlugin = "phone"

/**
 * The `PluginEvent.event` a minted code is published under.
 *
 * @category constructors
 * @since 0.2.0
 */
export const otpIssuedEvent = "PhoneOtpIssued"

/**
 * The `PluginEvent.event` an answered code is published under.
 *
 * @category constructors
 * @since 0.2.0
 */
export const otpVerifiedEvent = "PhoneOtpVerified"

/**
 * The `method` an SMS code records on a session.
 *
 * @category constructors
 * @since 0.2.0
 */
export const smsMethod = "sms"

/**
 * The `type` this plugin's `Authenticators` summaries carry.
 *
 * @category constructors
 * @since 0.2.0
 */
export const phoneAuthenticatorType = "phone"

/**
 * What answering a code sent by SMS proves.
 *
 * **Details**
 *
 * Possession of the handset — a possession factor, over a channel NIST 800-63B
 * §3.2.9 *restricts*: the PSTN is subject to SIM swap and to interception this
 * library cannot see, so the entry is marked `restricted` and is never
 * phishing-resistant. It still counts: beside a password it is a second factor
 * and the session reaches `aal2`. What `restricted` buys is that a deployment
 * can refuse it where it matters, and that
 * {@link Config.requireAlternateSecondFactor} can insist on a fallback.
 *
 * @category constructors
 * @since 0.2.0
 */
export const smsEvidence: Evidence = {
  method: smsMethod,
  factor: "possession",
  phishingResistant: false,
  restricted: true
}

/**
 * What every user this plugin signs in came from.
 *
 * `Plugin` rather than a member of its own: `ProvisionSource` names the plugins
 * this library shipped in 0.1.0 and nothing else, and a new tag there is a
 * breaking change to every deployment's hooks for no gain.
 */
const phoneSource: ProvisionSource = ProvisionSource.Plugin({ plugin: phonePlugin })

// -----------------------------------------------------------------------------
// Cookies
// -----------------------------------------------------------------------------

/**
 * The cookie the phone-verification handle rides in, before any prefix.
 *
 * @category constructors
 * @since 0.2.0
 */
export const verifyCookieBaseName = "effect_auth.phone_verify"

/**
 * The cookie the sign-in handle rides in, before any prefix.
 *
 * @category constructors
 * @since 0.2.0
 */
export const signInCookieBaseName = "effect_auth.phone_sign_in"

/**
 * The cookie the step-up handle rides in, before any prefix.
 *
 * **Gotchas**
 *
 * Three names rather than one, so that a person attaching a number in one tab
 * and raising their session in another does not have the second flow silently
 * eat the first flow's handle.
 *
 * @category constructors
 * @since 0.2.0
 */
export const stepUpCookieBaseName = "effect_auth.phone_step_up"

// -----------------------------------------------------------------------------
// Purposes
// -----------------------------------------------------------------------------

/**
 * What travels with a phone challenge: the number it was sent to.
 *
 * **Details**
 *
 * Carried even where the subject already is the number, for two reasons. It
 * lets the step-up path check that the number on the record is still the one
 * the code went to, and — because a purpose that declares a payload decodes one
 * — it means a challenge handle cannot be redeemed as if it were a link token
 * under the same purpose name.
 *
 * @category models
 * @since 0.2.0
 */
export const PhoneChallengePayload = Schema.Struct({
  phoneE164: Schema.String
})

/**
 * The type of a {@link PhoneChallengePayload}.
 *
 * @category models
 * @since 0.2.0
 */
export type PhoneChallengePayload = typeof PhoneChallengePayload.Type

/**
 * The purpose a code attaching a number to an account is minted under. Its
 * subject is the caller's user id.
 *
 * @category constructors
 * @since 0.2.0
 */
export const verifyPurpose: TokenPurpose<PhoneChallengePayload> = purpose("phone:verify", PhoneChallengePayload)

/**
 * The purpose a sign-in code is minted under. Its subject is the canonical
 * number.
 *
 * **Gotchas**
 *
 * A different purpose from {@link stepUpPurpose} even though the two look
 * identical, so a code obtained under "confirm your number" can never raise a
 * session — which is exactly the confusion a shared identifier produced in the
 * prior art this plugin is modelled against.
 *
 * @category constructors
 * @since 0.2.0
 */
export const signInPurpose: TokenPurpose<PhoneChallengePayload> = purpose("phone:signIn", PhoneChallengePayload)

/**
 * The purpose a step-up code is minted under. Its subject is the caller's user
 * id.
 *
 * @category constructors
 * @since 0.2.0
 */
export const stepUpPurpose: TokenPurpose<PhoneChallengePayload> = purpose("phone:stepUp", PhoneChallengePayload)

// -----------------------------------------------------------------------------
// The sender seam
// -----------------------------------------------------------------------------

/**
 * The application's SMS gateway could not take the message.
 *
 * **Gotchas**
 *
 * Never reaches a caller. Every send in this plugin is forked off the request
 * path and its failure is logged and dropped, exactly as `deliverEmail` does
 * for mail: whether a message went out must not be observable, or the endpoints
 * that answer identically for a known and an unknown number stop doing so.
 *
 * @category errors
 * @since 0.2.0
 */
export class SmsDeliveryError extends Schema.TaggedError<SmsDeliveryError>("effect-auth/phone/SmsDeliveryError")(
  "SmsDeliveryError",
  {
    reason: Schema.String,
    cause: Schema.optional(Schema.Defect())
  },
  {
    description: "The message could not be delivered",
    httpApiStatus: 500
  }
) {}

/**
 * One message, as the application is asked to deliver it.
 *
 * @category models
 * @since 0.2.0
 */
export interface SmsMessage {
  /** The canonical E.164 number it goes to. */
  readonly to: string
  /** The text to send, composed by {@link Config.message}. */
  readonly body: Redacted.Redacted
  /**
   * The code on its own, for a gateway that fills a provider-side template
   * rather than taking a body.
   *
   * **Gotchas**
   *
   * The same secret as {@link SmsMessage.body}, offered twice so that a
   * deployment does not have to parse it back out of the text. Do not log it.
   */
  readonly code: Redacted.Redacted
  /**
   * The account it is about, or `null` when the flow does not know one — a
   * sign-in code for a number nobody holds.
   */
  readonly user: User | null
}

/**
 * The {@link SmsSender} service definition — what an application implements to
 * deliver a message.
 *
 * **Gotchas**
 *
 * A service of the plugin's own, never a method on `AuthEmails`: a plugin
 * cannot widen a library interface every other deployment implements, and this
 * is a different transport with a different failure. A deployment that forgets
 * it gets a compile error from {@link layer}'s requirements, which is the
 * point.
 *
 * @category models
 * @since 0.2.0
 */
export interface SmsSenderService {
  readonly send: (message: SmsMessage) => Effect.Effect<void, SmsDeliveryError>
}

/**
 * Delivers this plugin's messages. See {@link SmsSenderService}.
 *
 * @category services
 * @since 0.2.0
 */
export class SmsSender extends Context.Service<SmsSender, SmsSenderService>()("effect-auth/phone/Phone/SmsSender") {}

// -----------------------------------------------------------------------------
// Rate limits
// -----------------------------------------------------------------------------

/**
 * Messages to one number: three an hour.
 *
 * @category constructors
 * @since 0.2.0
 */
export const destinationBucket: Bucket = {
  name: "phone-send-destination",
  limit: 3,
  window: Duration.hours(1)
}

/**
 * Messages to one destination *prefix* — the country code and three digits:
 * thirty an hour.
 *
 * **Details**
 *
 * The bucket toll fraud actually hits. A stolen card buys traffic to a range of
 * premium numbers, not to one number, so a per-number limit alone never sees
 * the attack: a thousand numbers in one range is a thousand fresh allowances.
 *
 * @category constructors
 * @since 0.2.0
 */
export const prefixBucket: Bucket = {
  name: "phone-send-prefix",
  limit: 30,
  window: Duration.hours(1)
}

/**
 * Messages asked for by one client address: five in ten minutes.
 *
 * **Gotchas**
 *
 * The only one of the four counted the way this library's own buckets are —
 * against the caller and the path. An unresolvable address falls into the
 * shared bucket, which is fail-closed and is what `RateLimits.clientAddress`
 * already does.
 *
 * @category constructors
 * @since 0.2.0
 */
export const clientBucket: Bucket = {
  name: "phone-send-client",
  limit: 5,
  window: Duration.minutes(10)
}

/**
 * Messages asked for by one signed-in account: five an hour.
 *
 * @category constructors
 * @since 0.2.0
 */
export const subjectBucket: Bucket = {
  name: "phone-send-subject",
  limit: 5,
  window: Duration.hours(1)
}

/**
 * Codes answered against one subject: ten in fifteen minutes.
 *
 * **Details**
 *
 * The second layer under the per-challenge attempt budget. A budget bound to a
 * handle is defeated by asking for a new code, so the guessing is also counted
 * across challenges, against the number or the account rather than against the
 * caller's address.
 *
 * @category constructors
 * @since 0.2.0
 */
export const verifyBucket: Bucket = {
  name: "phone-verify-subject",
  limit: 10,
  window: Duration.minutes(15)
}

/**
 * The five buckets, as a deployment may vary them.
 *
 * @category models
 * @since 0.2.0
 */
export interface Limits {
  readonly destination: Bucket
  readonly prefix: Bucket
  readonly client: Bucket
  readonly subject: Bucket
  readonly verify: Bucket
}

/**
 * The shipped limits.
 *
 * @category constructors
 * @since 0.2.0
 */
export const defaultLimits: Limits = {
  destination: destinationBucket,
  prefix: prefixBucket,
  client: clientBucket,
  subject: subjectBucket,
  verify: verifyBucket
}

// -----------------------------------------------------------------------------
// Options
// -----------------------------------------------------------------------------

/**
 * What a deployment may vary about the phone plugin.
 *
 * @category models
 * @since 0.2.0
 */
export interface Config {
  /**
   * Serve the two endpoints that attach a number to a signed-in account.
   * Defaults to `true` — this is the capability the plugin exists for.
   */
  readonly contact: boolean
  /**
   * Serve the two endpoints that sign somebody in with a number. Defaults to
   * **`false`**.
   *
   * **Gotchas**
   *
   * A verified phone number is a contact detail; a phone number you can sign in
   * with is a credential, and it is the weakest one this library offers — a SIM
   * swap is somebody else's sign-in. Turning it on is a deliberate act, and it
   * is also what makes the plugin's `Authenticators` summary report
   * `signIn: true`, which is what `Accounts.unlink` counts.
   *
   * This plugin never *creates* an account. A code sent to a number nobody
   * holds is answered `InvalidCode`, exactly as a wrong code is.
   */
  readonly signIn: boolean
  /**
   * Serve the two endpoints that raise a live session with a code. Defaults to
   * `false`.
   *
   * **Details**
   *
   * Off by default for the same reason {@link Config.signIn} is: turning it on
   * is what makes a phone number a *factor*, and the PSTN is the one channel
   * NIST 800-63B §3.2.9 restricts. The shipped configuration keeps a number as
   * a contact detail — `summaryOf` reports `secondFactor: false` and nothing
   * about the account's assurance changes when one is attached.
   *
   * **Gotchas**
   *
   * Independent of {@link Config.signIn}: a deployment may want the number as a
   * second factor without accepting it as a first one. Turning it on also turns
   * {@link Config.requireAlternateSecondFactor} on unless that is stated.
   */
  readonly stepUp: boolean
  /**
   * How many digits a code has. Defaults to six — what fits on a lock screen
   * notification and what a person types off one.
   */
  readonly digits: number
  /**
   * How long a code may be answered for. Defaults to ten minutes, NIST
   * 800-63B §5.1.3's ceiling for an out-of-band authenticator.
   */
  readonly ttl: Duration.Duration
  /**
   * How many wrong guesses one code survives. Defaults to five.
   */
  readonly attempts: number
  /**
   * The country calling codes this deployment will send to — `["1", "44"]`.
   *
   * **Gotchas**
   *
   * **Defaults to the empty list, which refuses every number.** That is not an
   * oversight: an SMS is the one thing this library does that costs real money
   * per request, and international premium-rate fraud is the most expensive way
   * to find that out. A deployment says where its messages may go, and the
   * plugin refuses everything else with `PhoneCountryNotAllowed` before a
   * message, a row or a rate-limit token is spent.
   *
   * Values are E.164 country *calling* codes without the `+`, one to three
   * digits, and they match by prefix — so `"1"` admits the whole North American
   * plan, and adding `"1876"` beside it gives Jamaica a prefix bucket of its
   * own.
   */
  readonly allowedCountries: ReadonlyArray<string>
  /**
   * The text of a message. Defaults to `"<code> is your verification code."`.
   */
  readonly message: (code: string) => string
  /**
   * Refuse to attach a number to an account that holds no *unrestricted* second
   * factor. Defaults to `false`.
   *
   * **Details**
   *
   * NIST 800-63B §3.2.9 restricts SMS, and a subscriber whose only second
   * factor is a restricted one has no way back when the restriction bites.
   * Turned on, {@link PhoneService.sendVerification} and
   * {@link PhoneService.verify} both consult the `Authenticators` seam and
   * refuse with `RestrictedFactorNotAllowed` unless some other plugin already
   * holds an unrestricted `secondFactor` authenticator for that person.
   *
   * **Gotchas**
   *
   * Unstated, it follows {@link Config.stepUp} — which is what decides whether
   * the number is a second factor at all. In the shipped configuration step-up
   * is off, the number is a contact detail, and the rule has nothing to say, so
   * verifying one asks for no other authenticator. A deployment that turns
   * step-up on gets the rule with it, because that is the moment a restricted
   * channel starts standing between somebody and their account; one that
   * genuinely wants SMS to stand alone states `false` and means it.
   */
  readonly requireAlternateSecondFactor: boolean
  /** The five rate limits. Defaults to {@link defaultLimits}. */
  readonly limits: Limits
}

/**
 * {@link Config}, with every field optional.
 *
 * @category models
 * @since 0.2.0
 */
export interface Options {
  readonly contact?: boolean | undefined
  readonly signIn?: boolean | undefined
  readonly stepUp?: boolean | undefined
  readonly digits?: number | undefined
  readonly ttl?: Duration.Duration | undefined
  readonly attempts?: number | undefined
  readonly allowedCountries?: ReadonlyArray<string> | undefined
  readonly message?: ((code: string) => string) | undefined
  readonly requireAlternateSecondFactor?: boolean | undefined
  readonly limits?: Partial<Limits> | undefined
}

/**
 * The defaults every unstated {@link Options} field resolves to.
 *
 * @category constructors
 * @since 0.2.0
 */
export const defaults: Config = {
  contact: true,
  signIn: false,
  stepUp: false,
  digits: 6,
  ttl: Duration.minutes(10),
  attempts: 5,
  allowedCountries: [],
  message: (code) => `${code} is your verification code.`,
  requireAlternateSecondFactor: false,
  limits: defaultLimits
}

/**
 * Resolves {@link Options} against {@link defaults}.
 *
 * @category constructors
 * @since 0.2.0
 */
export const makeConfig = (options?: Options): Config => {
  const resolved = withDefaults(defaults, { ...options, limits: undefined })
  return {
    ...resolved,
    // The restricted-factor rule follows the capability that makes the number
    // a factor at all. Unstated, it is whatever `stepUp` resolved to: off in
    // the shipped configuration, where the number is a contact detail and the
    // rule has nothing to say, and on the moment a deployment turns step-up on
    // and the number becomes somebody's second factor. A deployment that
    // genuinely wants SMS to stand alone says so.
    requireAlternateSecondFactor: options?.requireAlternateSecondFactor ?? resolved.stepUp,
    limits: withDefaults(defaultLimits, options?.limits)
  }
}

// -----------------------------------------------------------------------------
// Models
// -----------------------------------------------------------------------------

/**
 * A code that has been sent, as far as the caller of this service is concerned.
 *
 * **Gotchas**
 *
 * The handle, and never the code. Put the handle in the matching `__Host-`
 * cookie with `expiresAt` as its lifetime and drop it; the code is on its way
 * to a handset and this process will not see it again.
 *
 * @category models
 * @since 0.2.0
 */
export interface IssuedChallenge {
  readonly handle: Redacted.Redacted
  readonly expiresAt: DateTime.Utc
}

/**
 * What {@link PhoneService.verify} answers.
 *
 * @category models
 * @since 0.2.0
 */
export interface AttachedPhone {
  /** The canonical number, in full — it is the caller's own. */
  readonly phoneE164: string
  /** When possession was proved. */
  readonly verifiedAt: DateTime.Utc
}

/**
 * What every method that answers a code takes.
 *
 * @category models
 * @since 0.2.0
 */
export interface AnswerOptions {
  /** The handle out of this plugin's cookie. */
  readonly handle: Redacted.Redacted
  /** Exactly what the person typed. */
  readonly code: Redacted.Redacted
}

/**
 * What {@link PhoneService.completeSignIn} takes.
 *
 * @category models
 * @since 0.2.0
 */
export interface CompleteSignInOptions extends AnswerOptions {
  readonly rememberMe?: boolean | undefined
  readonly ipAddress?: string | null | undefined
  readonly userAgent?: string | null | undefined
  /**
   * The session the request already carried, for the anonymous-merge seam.
   * `undefined` on every ordinary sign-in.
   */
  readonly current?: SessionWithUser | undefined
}

// -----------------------------------------------------------------------------
// Service
// -----------------------------------------------------------------------------

/**
 * The {@link Phone} service definition.
 *
 * @category models
 * @since 0.2.0
 */
export interface PhoneService {
  /** The resolved configuration this instance was built with. */
  readonly config: Config

  /**
   * Mints a code for a number the signed-in caller wants to attach, and sends
   * it.
   *
   * **Details**
   *
   * The number is normalised, its country checked against the allowlist, and
   * three keyed limits spent — destination, prefix, subject — before anything
   * is written. The challenge's subject is the *caller*, not the number, so a
   * second ask replaces the first rather than running two live codes for one
   * person.
   */
  readonly sendVerification: (options: {
    readonly user: User
    readonly phoneNumber: string
  }) => Effect.Effect<
    IssuedChallenge,
    InvalidPhoneNumber | PhoneCountryNotAllowed | RestrictedFactorNotAllowed | RateLimited | PersistenceError
  >

  /**
   * Answers a code and attaches the number.
   *
   * **Gotchas**
   *
   * The handle's subject must be the caller: a handle collected from somebody
   * else's browser is `InvalidCode` here, not a way to attach their number to
   * this account.
   */
  readonly verify: (
    options: AnswerOptions & { readonly user: User }
  ) => Effect.Effect<
    AttachedPhone,
    InvalidCode | PhoneAlreadyInUse | RestrictedFactorNotAllowed | RateLimited | PersistenceError
  >

  /**
   * Mints a sign-in code for a number and sends it — if anybody holds it.
   *
   * **Gotchas**
   *
   * The challenge is issued either way and the answer is identical either way.
   * The message is only sent for a number that names an account, because an SMS
   * to a stranger is an invoice rather than an anti-enumeration measure, and it
   * is sent off the request path so that both branches take the same time.
   */
  readonly sendSignIn: (options: {
    readonly phoneNumber: string
  }) => Effect.Effect<IssuedChallenge, InvalidPhoneNumber | PhoneCountryNotAllowed | RateLimited | PersistenceError>

  /**
   * Answers a sign-in code, through the one choke point every credential in
   * this library goes through.
   */
  readonly completeSignIn: (
    options: CompleteSignInOptions
  ) => Effect.Effect<SignInResult, InvalidCode | PolicyRefused | RateLimited | PersistenceError>

  /**
   * Mints a step-up code and sends it to the number already on the caller's
   * record.
   */
  readonly sendStepUp: (options: {
    readonly user: User
  }) => Effect.Effect<IssuedChallenge, PhoneNotVerified | RateLimited | PersistenceError>

  /**
   * Answers a step-up code, raising the caller's session and rotating its
   * token.
   */
  readonly completeStepUp: (
    options: AnswerOptions & { readonly user: User; readonly session: Session }
  ) => Effect.Effect<ElevatedSession, InvalidCode | RateLimited | PersistenceError>

  /** Detaches the caller's number, answering how many rows went. */
  readonly remove: (options: { readonly user: User }) => Effect.Effect<number, PersistenceError>

  /**
   * The `Authenticators` contribution for one user — what {@link authenticators}
   * answers, exposed so a deployment can build an aggregate view without
   * installing the seam twice.
   */
  readonly summaries: (userId: UserId) => Effect.Effect<ReadonlyArray<AuthenticatorSummary>, PersistenceError>
}

/**
 * Phone numbers, codes and the three things they are good for. See
 * {@link PhoneService}.
 *
 * @category services
 * @since 0.2.0
 */
export class Phone extends Context.Service<Phone, PhoneService>()("effect-auth/phone/Phone") {}

// -----------------------------------------------------------------------------
// The restricted-factor rule
// -----------------------------------------------------------------------------

/**
 * Whether a person holds a second factor that is not a restricted one.
 *
 * **When to use**
 *
 * It is the rule behind {@link Config.requireAlternateSecondFactor}, exported
 * because it is a statement about a set of summaries rather than about this
 * plugin: a deployment enforcing NIST 800-63B §3.2.9 somewhere else asks the
 * same question of the same seam.
 *
 * @category guards
 * @since 0.2.0
 */
export const hasUnrestrictedSecondFactor = (summaries: ReadonlyArray<AuthenticatorSummary>): boolean =>
  summaries.some((summary) => summary.secondFactor && !summary.restricted)

/**
 * One stored number, as the `Authenticators` seam describes it.
 *
 * **Details**
 *
 * The flags are the honest ones and they are read off the configuration rather
 * than assumed: `signIn` is only true where the deployment turned the sign-in
 * capability on, `secondFactor` only where it turned step-up on, and
 * `restricted` is always true because the channel is restricted whatever else
 * is configured — NIST 800-63B §3.2.9. The name is masked, because a summary
 * ends up in lists and in logs while the account's owner can always read the
 * whole number off their own record.
 *
 * @category combinators
 * @since 0.2.0
 */
export const summaryOf = (row: PhoneNumber, config: Config): AuthenticatorSummary => ({
  type: phoneAuthenticatorType,
  id: row.phoneE164,
  name: E164.mask(row.phoneE164),
  verifiedAt: row.verifiedAt,
  lastUsedAt: null,
  signIn: config.signIn,
  secondFactor: config.stepUp,
  restricted: true
})

/**
 * The seam's `list`, over one store and one configuration. Written once because
 * the service exposes it and the contributor installs it, and two copies of a
 * flag table is how the two answers drift apart.
 */
const listFor =
  (store: PhoneStoreService, config: Config) =>
  (userId: UserId): Effect.Effect<ReadonlyArray<AuthenticatorSummary>, PersistenceError> =>
    Effect.map(store.findByUserId(userId), (found) =>
      Option.match(Option.filter(found, isVerified), {
        onNone: () => [],
        onSome: (row) => [summaryOf(row, config)]
      })
    )

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

/**
 * What {@link make} needs.
 *
 * **Gotchas**
 *
 * Everything but {@link SmsSender} and {@link PhoneStore} is published by
 * `Auth.layer`, so a consumer composes the plugin over their deployment and
 * supplies a gateway and the plugin's own table:
 *
 * ```ts skip-type-checking
 * const PhoneStoreLive = Phone.Store.layer.pipe(Layer.provide(PgLive))
 * const PhoneLive = Phone.layer({ allowedCountries: ["1"] }).pipe(
 *   Layer.provideMerge(AuthLive),
 *   Layer.provide(PhoneStoreLive),
 *   Layer.provide(MySmsGateway)
 * )
 * ```
 *
 * @category models
 * @since 0.2.0
 */
export type Requirements =
  | SmsSender
  | PhoneStore
  | AuthConfig
  | AuthEvents
  | Challenges
  | SignIn
  | Sessions
  | UserStore
  | RateLimiter.RateLimiter

/**
 * Builds the {@link Phone} implementation.
 *
 * @category constructors
 * @since 0.2.0
 */
export const make: (options?: Options) => Effect.Effect<PhoneService, never, Requirements> = Effect.fnUntraced(
  function* (options?: Options) {
    const settings = makeConfig(options)
    const config = yield* AuthConfig
    const sender = yield* SmsSender
    const store = yield* PhoneStore
    const events = yield* AuthEvents
    const challenges = yield* Challenges
    const { complete: completeSignInWith } = yield* SignIn
    const sessions = yield* Sessions
    const users = yield* UserStore
    const limiter = yield* RateLimiter.RateLimiter
    // A `Context.Reference` with a no-op default, read here so the contributor
    // set is fixed when the layer is built rather than looked up per request.
    const authenticators: AuthenticatorsService = yield* Authenticators

    const spend = (bucket: Bucket, key: string) => consumeKeyed({ config, limiter, bucket, key })

    /**
     * The canonical number, or the refusal. Every entry point starts here and
     * nothing downstream ever sees the caller's spelling.
     */
    const canonical = (input: string): Effect.Effect<string, InvalidPhoneNumber> =>
      Effect.fromOption(E164.normalize(input), () => InvalidPhoneNumber.make())

    /**
     * The number's country, or the refusal. An empty allowlist refuses
     * everything, which is the default.
     */
    const country = (e164: string): Effect.Effect<string, PhoneCountryNotAllowed> =>
      Effect.fromOption(E164.countryCodeOf(settings.allowedCountries, e164), () => PhoneCountryNotAllowed.make())

    /**
     * The three toll-fraud limits a destination costs, in the order that spends
     * the least on a request that is going to be refused anyway.
     */
    const spendDestination = Effect.fnUntraced(function* (e164: string, subject: string | null) {
      const code = yield* country(e164)
      yield* spend(settings.limits.destination, e164)
      yield* spend(settings.limits.prefix, E164.prefixOf(code, e164))
      if (subject !== null) yield* spend(settings.limits.subject, subject)
      return code
    })

    /**
     * Hands a message to the gateway and forgets whatever it says.
     *
     * **Gotchas**
     *
     * Forked, and that is the point: a send awaited only on the branch where
     * the number is known would make the two branches distinguishable by a
     * stopwatch, which is the whole of what the identical answers were for. It
     * starts immediately so that a gateway doing synchronous work has done it
     * before the response is built, and is detached so that the request does
     * not wait for the network.
     */
    const deliver = (message: SmsMessage): Effect.Effect<void> =>
      Effect.asVoid(
        Effect.forkDetach(
          annotateAuthLogs(Effect.ignore(sender.send(message), { log: "Warn", message: "an SMS was not delivered" })),
          { startImmediately: true }
        )
      )

    const issue = Effect.fnUntraced(function* (options: {
      readonly tokenPurpose: TokenPurpose<PhoneChallengePayload>
      readonly subject: string
      readonly phoneE164: string
      readonly userId: UserId | null
      readonly send: boolean
      readonly user: User | null
    }) {
      const issued = yield* challenges.issueCode({
        purpose: options.tokenPurpose,
        subject: options.subject,
        digits: settings.digits,
        ttl: settings.ttl,
        attempts: settings.attempts,
        payload: { phoneE164: options.phoneE164 }
      })
      if (options.send) {
        yield* deliver({
          to: options.phoneE164,
          body: Redacted.make(settings.message(Redacted.value(issued.code))),
          code: issued.code,
          user: options.user
        })
      }
      yield* publishSafely(
        events,
        PluginEvent.make({
          plugin: phonePlugin,
          event: otpIssuedEvent,
          userId: options.userId,
          // No number, no code, no handle: a subscriber watching the send/verify
          // conversion needs the purpose and the country and nothing else.
          data: { purpose: options.tokenPurpose.name, delivered: options.send }
        })
      )
      return { handle: issued.handle, expiresAt: issued.expiresAt } satisfies IssuedChallenge
    })

    const answered = Effect.fnUntraced(function* (options: {
      readonly tokenPurpose: TokenPurpose<PhoneChallengePayload>
      readonly subject: string
      readonly handle: Redacted.Redacted
      readonly code: Redacted.Redacted
      readonly userId: UserId | null
      /**
       * What the cross-challenge budget is counted against, or `null` for a
       * path where the caller would be choosing it.
       *
       * Never a value read out of the request. A key the caller picks is a key
       * the caller can exhaust on somebody else's behalf: the sign-in handle
       * carries its own subject, so ten forged handles naming a stranger's
       * number would lock that number out of answering its own code — a denial
       * of service anyone could run from anywhere, renewed every window.
       */
      readonly limitKey: string | null
    }) {
      // Counted across challenges as well as within one: a per-challenge budget
      // bound to a handle is defeated by asking for another code.
      if (options.limitKey !== null) yield* spend(settings.limits.verify, options.limitKey)
      const claimed = yield* challenges.verifyCode({
        purpose: options.tokenPurpose,
        handle: options.handle,
        code: options.code
      })
      yield* publishSafely(
        events,
        PluginEvent.make({
          plugin: phonePlugin,
          event: otpVerifiedEvent,
          userId: options.userId,
          data: { purpose: options.tokenPurpose.name }
        })
      )
      return claimed
    })

    const requireAlternate = Effect.fnUntraced(function* (userId: UserId) {
      if (!settings.requireAlternateSecondFactor) return
      const summaries = yield* listAuthenticators(authenticators, userId)
      if (hasUnrestrictedSecondFactor(summaries)) return
      return yield* RestrictedFactorNotAllowed.make()
    })

    /**
     * The account that proved it holds a number, if any does. An unverified row
     * is not one: a claim nobody answered a code for is not a credential.
     */
    const holderOf = (e164: string): Effect.Effect<Option.Option<User>, PersistenceError> =>
      Effect.flatMap(store.findByPhone(e164), (found) =>
        Option.match(Option.filter(found, isVerified), {
          onNone: () => Effect.succeedNone,
          onSome: (row) => users.findById(row.userId)
        })
      )

    const sendVerification = Effect.fnUntraced(
      function* (options: { readonly user: User; readonly phoneNumber: string }) {
        const e164 = yield* canonical(options.phoneNumber)
        // Before the message, not only before the row: a refusal that arrives
        // after the SMS has gone out has already cost what it was meant to save.
        yield* requireAlternate(options.user.id)
        yield* spendDestination(e164, options.user.id)
        // Whether anybody else holds this number is not decided here. Answering
        // differently would turn this endpoint into "is this number
        // registered?", which is a question about somebody else's account.
        return yield* issue({
          tokenPurpose: verifyPurpose,
          subject: options.user.id,
          phoneE164: e164,
          userId: options.user.id,
          send: true,
          user: options.user
        })
      },
      (effect) => Effect.withSpan(effect, "Phone.sendVerification")
    )

    const verify = Effect.fnUntraced(
      function* (options: AnswerOptions & { readonly user: User }) {
        const claimed = yield* answered({
          tokenPurpose: verifyPurpose,
          subject: options.user.id,
          handle: options.handle,
          code: options.code,
          userId: options.user.id,
          // The authenticated caller's own id — not something they stated.
          limitKey: options.user.id
        })
        // A handle is a bearer value; the subject on the row is what says whose
        // it was. A cookie lifted from another browser answers nothing here.
        if (claimed.subject !== options.user.id) return yield* InvalidCode.make()
        yield* requireAlternate(options.user.id)
        const row = yield* Effect.catchIf(
          store.claim({ phoneE164: claimed.payload.phoneE164, userId: options.user.id }),
          isUniqueViolation,
          () => PhoneAlreadyInUse.make()
        )
        return {
          phoneE164: row.phoneE164,
          verifiedAt: row.verifiedAt ?? (yield* DateTime.now)
        } satisfies AttachedPhone
      },
      (effect) => Effect.withSpan(effect, "Phone.verify")
    )

    const sendSignIn = Effect.fnUntraced(
      function* (options: { readonly phoneNumber: string }) {
        const e164 = yield* canonical(options.phoneNumber)
        yield* spendDestination(e164, null)
        // The lookup runs on both branches, so the answer and the work are the
        // same for a number nobody holds; only the send differs, and the send
        // is off the request path.
        const user = yield* holderOf(e164)
        return yield* issue({
          tokenPurpose: signInPurpose,
          subject: e164,
          phoneE164: e164,
          userId: Option.isNone(user) ? null : user.value.id,
          send: Option.isSome(user),
          user: Option.getOrNull(user)
        })
      },
      (effect) => Effect.withSpan(effect, "Phone.sendSignIn")
    )

    const completeSignIn = Effect.fnUntraced(
      function* (options: CompleteSignInOptions) {
        // A handle that is not one at all never reaches the store. The number
        // it names is *not* used as a rate-limit key — see `limitKey` below.
        const subject = yield* Effect.fromOption(decodeSubjectToken(options.handle), () => InvalidCode.make())
        const claimed = yield* answered({
          tokenPurpose: signInPurpose,
          subject: subject.subject,
          handle: options.handle,
          code: options.code,
          userId: null,
          // Nothing here: the only identifier this path has is the one the
          // caller wrote into their own cookie. Guessing is bounded without
          // it — a challenge allows five attempts and `limits.destination`
          // allows three codes an hour to a number, so fifteen guesses an hour
          // against a six-digit space — and the handler spends a per-client
          // bucket besides.
          limitKey: null
        })
        // A number nobody holds — and one whose account went while the code was
        // in flight — is the same answer as a wrong code: there is nobody to
        // sign in either way, and saying so would make this endpoint a register
        // of who has an account here.
        const user = yield* holderOf(claimed.payload.phoneE164)
        if (Option.isNone(user)) return yield* InvalidCode.make()
        return yield* completeSignInWith({
          user: user.value,
          source: phoneSource,
          evidence: [smsEvidence],
          current: Option.fromNullishOr(options.current),
          request: {
            ipAddress: options.ipAddress ?? null,
            userAgent: options.userAgent ?? null,
            rememberMe: options.rememberMe
          }
        })
      },
      (effect) => Effect.withSpan(effect, "Phone.completeSignIn")
    )

    const sendStepUp = Effect.fnUntraced(
      function* (options: { readonly user: User }) {
        const found = yield* store.findByUserId(options.user.id)
        const row = yield* Effect.fromOption(Option.filter(found, isVerified), () => PhoneNotVerified.make())
        // No allowlist *check*: this number is already on the account, which
        // means it passed the allowlist when it was attached, and a deployment
        // that has since narrowed the list must not strand the people whose
        // second factor it is. All three destination limits still apply — a
        // stolen session must not be a way to buy traffic, and the range bucket
        // is the one that sees premium-rate fraud, which pays for traffic to a
        // block and not to a single handset. A number the current allowlist no
        // longer names is bucketed by its own calling code rather than being
        // let through uncounted.
        yield* spend(settings.limits.destination, row.phoneE164)
        yield* spend(
          settings.limits.prefix,
          E164.prefixOf(
            Option.getOrElse(E164.countryCodeOf(settings.allowedCountries, row.phoneE164), () => ""),
            row.phoneE164
          )
        )
        yield* spend(settings.limits.subject, options.user.id)
        return yield* issue({
          tokenPurpose: stepUpPurpose,
          subject: options.user.id,
          phoneE164: row.phoneE164,
          userId: options.user.id,
          send: true,
          user: options.user
        })
      },
      (effect) => Effect.withSpan(effect, "Phone.sendStepUp")
    )

    const completeStepUp = Effect.fnUntraced(
      function* (options: AnswerOptions & { readonly user: User; readonly session: Session }) {
        const claimed = yield* answered({
          tokenPurpose: stepUpPurpose,
          subject: options.user.id,
          handle: options.handle,
          code: options.code,
          userId: options.user.id,
          limitKey: options.user.id
        })
        if (claimed.subject !== options.user.id) return yield* InvalidCode.make()
        // The number the code went to must still be the number on the record: a
        // code in flight while the account's number changed proves possession of
        // a handset this account no longer claims.
        const found = yield* store.findByUserId(options.user.id)
        const row = Option.filter(found, isVerified)
        if (Option.isNone(row) || row.value.phoneE164 !== claimed.payload.phoneE164) return yield* InvalidCode.make()
        return yield* sessions.elevate(options.session, smsEvidence)
      },
      (effect) => Effect.withSpan(effect, "Phone.completeStepUp")
    )

    const summaries = listFor(store, settings)

    return Phone.of({
      config: settings,
      sendVerification,
      verify,
      sendSignIn,
      completeSignIn,
      sendStepUp,
      completeStepUp,
      remove: (options) => store.deleteForUser(options.user.id),
      summaries
    })
  }
)

/**
 * Provides {@link Phone}.
 *
 * @category layers
 * @since 0.2.0
 */
export const layer = (options?: Options): Layer.Layer<Phone, never, Requirements> => Layer.effect(Phone, make(options))

/**
 * The plugin's contribution to the `Authenticators` seam.
 *
 * **When to use**
 *
 * Provide it **underneath** the deployment, not beside it — the reference is
 * read when the services that consult it are built, so a contributor installed
 * above `Auth.layer` is one `Accounts.unlink` never sees:
 *
 * ```ts skip-type-checking
 * const AuthLive = Auth.layer(options).pipe(
 *   Layer.provide(Phone.authenticators({ signIn: true }).pipe(Layer.provide(PhoneStoreLive)))
 * )
 * ```
 *
 * **Details**
 *
 * `append`, never `layer`: a plugin cannot know what else the deployment
 * installed, and a deployment serving phone *and* passkeys must get both in one
 * answer. The flags are the honest ones — `signIn` follows
 * {@link Config.signIn}, `secondFactor` follows {@link Config.stepUp}, and
 * `restricted` is always `true` — so whoever enforces NIST's restriction reads
 * it off the seam rather than guessing from the type name.
 *
 * `revokeAll` runs inside its caller's transaction, under the row lock that
 * caller already holds, and does one statement: it is what stops the
 * unproven-account takeover defence from leaving a pre-registrant's SMS factor
 * behind.
 *
 * @category layers
 * @since 0.2.0
 */
export const authenticators = (options?: Options): Layer.Layer<never, never, PhoneStore> =>
  Layer.unwrap(
    Effect.map(PhoneStore, (store) =>
      appendAuthenticators({
        list: listFor(store, makeConfig(options)),
        revokeAll: (userId) => store.deleteForUser(userId)
      })
    )
  )
