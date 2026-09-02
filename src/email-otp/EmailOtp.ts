/**
 * Sign-in, address verification, password reset, step-up and change-of-address
 * by a short code mailed to an e-mail address — with a single-use link beside
 * it, backed by the same row.
 *
 * **Details**
 *
 * The plugin owns no table. A challenge is an ordinary `Verifications` row under
 * one of the five purposes below, minted through `Challenges`: the row's secret
 * is a full-entropy **handle** the browser keeps in a cookie, and the row's
 * payload carries a peppered digest of the code and an attempt budget. The code
 * itself only ever exists in the message.
 *
 * *The hybrid.* Under the sign-in purpose one issuance mints two rows at the
 * same identifier: the challenge, answered with a code, and a plain
 * `Verifications` token, answered by following a link. Consuming either retires
 * the other, because both are retired by identifier. That is what folds magic
 * link into this module: the link is the same credential as the code, and a
 * mail scanner that prefetches the link burns a credential the person can still
 * answer with the code — or the other way round.
 *
 * **Gotchas — the three rules that shape this module**
 *
 * *No user enumeration.* {@link EmailOtpService.send} answers the same for an
 * address with an account and one without, and does the same work: the lookup
 * runs either way, the challenge and the link are always minted, the handle
 * cookie is always set, and delivery is **forked off the request path** so a
 * slow mailer cannot be timed. Where a code could never do anything — an
 * unknown address under `disableSignUp`, a reset for an address with no account
 * — the rows are minted and then discarded, so the writes match too. The
 * refusal happens where the code is spent, as `InvalidCode` or
 * `SignUpDisabled`, never where it is requested.
 *
 * *A purpose is a namespace.* `signIn` and `stepUp` are different rows; a code
 * mailed under "confirm your address" can never elevate a session, because the
 * identifier a claim is looked up by carries the purpose name. The handle cookie
 * states its purpose so the wrong pairing is refused before a query runs.
 *
 * *An unproven account is not a credential.* Somebody can register an address
 * they do not own, wait, and hope its real owner later proves control of it;
 * they would then share the account. So when a code or a link proves control of
 * an address whose account is *unverified*, that account's sign-in methods, its
 * authenticators, its sessions and every outstanding link it is the subject of
 * are destroyed in one transaction and the address is marked verified — see
 * {@link Config.revokeUnprovenAccounts}, which is on by default.
 *
 * @since 0.2.0
 */
import { Context, type DateTime, Duration, Effect, Layer, Option, Redacted, Result, Schema, type Scope } from "effect"
import { AuthConfig } from "../config/AuthConfig.js"
import { tokenUrl } from "../config/AuthEmails.js"
import { Authenticators, revokeAll as revokeAllAuthenticators } from "../domain/Authenticators.js"
import type { EmailDeliveryError } from "../domain/Errors.js"
import { EmailUnchanged, InvalidCode, UserAlreadyExists } from "../domain/Errors.js"
import { AuthEvents, publishSafely } from "../domain/Events.js"
import type { PolicyRefused, ProvisionSource } from "../domain/Hooks.js"
import type { Session, User } from "../domain/Schema.js"
import { normalizeEmail, User as UserModel } from "../domain/Schema.js"
import { Challenges } from "../domain/Challenges.js"
import type { ElevatedSession, Evidence } from "../domain/Sessions.js"
import { Sessions } from "../domain/Sessions.js"
import type { SignInChallenge } from "../domain/SignIn.js"
import { SignIn } from "../domain/SignIn.js"
import type { PersistenceError, SessionWithUser } from "../domain/Stores.js"
import { AccountStore, isUniqueViolation, SessionStore, UserStore, WithAuthTransaction } from "../domain/Stores.js"
import { Users } from "../domain/Users.js"
import type { TokenPurpose } from "../domain/Verifications.js"
import { passwordResetPurpose, purpose, retireUserSubjectTokens, Verifications } from "../domain/Verifications.js"
import type { RedirectFailure } from "../http/OriginCheck.js"
import { redirectFailure, resolveUrl, validateUrl } from "../http/OriginCheck.js"
import { deliverEmail, insertRow } from "../internal/effects.js"
import { withDefaults } from "../internal/records.js"
import { emailOtpLinkPath, type SendPurpose, SignUpDisabled } from "./Api.js"

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/**
 * The `method` every event this plugin publishes carries, and the name its
 * evidence goes into the session's method log under.
 *
 * @category constructors
 * @since 0.2.0
 */
export const emailOtpMethod = "emailOtp"

/**
 * The name this plugin publishes `PluginEvent`s under, and what
 * `ProvisionSource.Plugin` names it.
 *
 * @category constructors
 * @since 0.2.0
 */
export const emailOtpPlugin = "email-otp"

/**
 * What answering a mailed code — or following the link beside it — proves:
 * control of the mailbox, and nothing else.
 *
 * A possession factor delivered over a channel that is not the one being
 * authenticated, and not phishing-resistant: a code can be read out over the
 * telephone and a link can be forwarded. Beside a password it reaches `aal2`;
 * on its own it is `aal1`.
 *
 * @category constructors
 * @since 0.2.0
 */
export const emailOtpEvidence: Evidence = {
  method: emailOtpMethod,
  factor: "possession",
  phishingResistant: false,
  restricted: false
}

/**
 * What every user this plugin provisions, and every session it mints, came
 * from. One value rather than a literal per call site: a hook branching on the
 * source must see the same tag from the provisioning as from the sign-in.
 *
 * @category constructors
 * @since 0.2.0
 */
export const emailOtpSource: ProvisionSource = { _tag: "Plugin", plugin: emailOtpPlugin }

// -----------------------------------------------------------------------------
// Purposes
// -----------------------------------------------------------------------------

/**
 * What travels with a challenge, in the row rather than in the message.
 *
 * **Details**
 *
 * Server-side state in the `verifications` table, never a claim in a URL or in
 * a code. The link carries the token and nothing else, so a recipient cannot
 * edit their own landing page — or their own display name — into it.
 *
 * One shape for all five purposes, so the codec is written once. Members a
 * purpose has no use for are `null`.
 *
 * @category models
 * @since 0.2.0
 */
export const EmailOtpPayload = Schema.Struct({
  /** The display name to give the account this code may create. */
  name: Schema.NullOr(Schema.String),
  /** Where to land after the link is followed. Already validated when it was stored. */
  callbackURL: Schema.NullOr(Schema.String),
  /** Where to land instead when the link created the account. */
  newUserCallbackURL: Schema.NullOr(Schema.String),
  /** Where to land when following the link fails. */
  errorCallbackURL: Schema.NullOr(Schema.String),
  /** Whether the session this code establishes is a remembered one. */
  rememberMe: Schema.Boolean,
  /** The address an account is being moved to, for the `changeEmail` purpose. */
  newEmail: Schema.NullOr(Schema.String)
})

/**
 * The type of an {@link EmailOtpPayload}.
 *
 * @category models
 * @since 0.2.0
 */
export type EmailOtpPayload = typeof EmailOtpPayload.Type

/** The payload of a challenge that asks for none of it. */
const emptyPayload: EmailOtpPayload = {
  name: null,
  callbackURL: null,
  newUserCallbackURL: null,
  errorCallbackURL: null,
  rememberMe: true,
  newEmail: null
}

/**
 * Every purpose this plugin mints challenges under.
 *
 * **Details**
 *
 * `signIn`, `verifyEmail` and `resetPassword` are subject-to-address purposes an
 * unauthenticated caller asks for. `stepUp` and `changeEmail` are subject-to-user-id
 * purposes only an authenticated endpoint mints. The two sets are separate rows
 * and separate endpoints, which is what stops a code phished under one from
 * being answered as the other.
 *
 * @category models
 * @since 0.2.0
 */
export type EmailOtpPurpose = SendPurpose | "stepUp" | "changeEmail"

/**
 * The purpose of a sign-in code, and of the link minted beside it. Its subject
 * is the normalized e-mail address.
 *
 * @category constructors
 * @since 0.2.0
 */
export const signInPurpose: TokenPurpose<EmailOtpPayload> = purpose("email-otp:sign-in", EmailOtpPayload)

/**
 * The purpose of an address-verification code. Its subject is the normalized
 * e-mail address.
 *
 * @category constructors
 * @since 0.2.0
 */
export const verifyEmailPurpose: TokenPurpose<EmailOtpPayload> = purpose("email-otp:verify-email", EmailOtpPayload)

/**
 * The purpose of a password-reset code. Its subject is the normalized e-mail
 * address; answering one hands back a continuation minted under the library's
 * own `password-reset` purpose.
 *
 * @category constructors
 * @since 0.2.0
 */
export const resetPasswordPurpose: TokenPurpose<EmailOtpPayload> = purpose("email-otp:reset-password", EmailOtpPayload)

/**
 * The purpose of a step-up code. Its subject is the **user id**, never the
 * address, so a code cannot be redirected at another account.
 *
 * @category constructors
 * @since 0.2.0
 */
export const stepUpPurpose: TokenPurpose<EmailOtpPayload> = purpose("email-otp:step-up", EmailOtpPayload)

/**
 * The purpose of a change-of-address code. Its subject is the user id and its
 * payload carries the address being moved to; the code goes to that address.
 *
 * @category constructors
 * @since 0.2.0
 */
export const changeEmailPurpose: TokenPurpose<EmailOtpPayload> = purpose("email-otp:change-email", EmailOtpPayload)

/**
 * The purposes by name.
 *
 * @category constructors
 * @since 0.2.0
 */
export const purposes: { readonly [K in EmailOtpPurpose]: TokenPurpose<EmailOtpPayload> } = {
  signIn: signInPurpose,
  verifyEmail: verifyEmailPurpose,
  resetPassword: resetPasswordPurpose,
  stepUp: stepUpPurpose,
  changeEmail: changeEmailPurpose
}

/**
 * Which purpose names are real, for {@link decodeHandleCookie}'s parse.
 *
 * A predicate over {@link purposes}' own keys rather than a cast: the record is
 * total over {@link EmailOtpPurpose}, so a name it holds *is* one, and stating
 * that as a guard is what keeps the parse free of an assertion.
 */
const isEmailOtpPurpose = (name: string): name is EmailOtpPurpose => Object.hasOwn(purposes, name)

// -----------------------------------------------------------------------------
// The handle cookie
// -----------------------------------------------------------------------------

/**
 * The name, before any prefix, of the cookie a challenge handle rides in.
 *
 * **Details**
 *
 * `__Host-effect_auth.email_otp_handle` on a TLS deployment, the bare name on
 * plain HTTP — `AuthCookies.pluginCookie` makes that decision. The handle is a
 * credential the *requester* holds, which is what binds a code's attempt budget
 * to the browser that asked for it rather than to the address it names: without
 * it, anybody who knows a victim's address could burn the victim's five guesses
 * from anywhere.
 *
 * @category constructors
 * @since 0.2.0
 */
export const handleCookieBaseName = "effect_auth.email_otp_handle"

/**
 * What separates the purpose from the handle inside the cookie.
 *
 * @category constructors
 * @since 0.2.0
 */
export const handleCookieSeparator = "."

/**
 * The cookie's value: `<purpose>.<handle>`.
 *
 * **Details**
 *
 * The purpose is a routing hint, not a credential. `POST /verify` serves three
 * purposes and the caller does not name which — the send endpoint decided — so
 * the cookie has to say. It is not a security boundary: a handle presented
 * under the wrong purpose names an identifier no row was ever written under, so
 * it matches nothing and consumes nothing. The prefix only lets that be refused
 * without a query.
 *
 * @category combinators
 * @since 0.2.0
 */
export const encodeHandleCookie = (purpose: EmailOtpPurpose, handle: Redacted.Redacted): Redacted.Redacted =>
  Redacted.make(`${purpose}${handleCookieSeparator}${Redacted.value(handle)}`)

/**
 * Reads a handle cookie back. `None` when it is not one, or names no purpose
 * this plugin mints.
 *
 * @category combinators
 * @since 0.2.0
 */
export const decodeHandleCookie = (
  value: Redacted.Redacted
): Option.Option<{ readonly purpose: EmailOtpPurpose; readonly handle: Redacted.Redacted }> => {
  const raw = Redacted.value(value)
  const at = raw.indexOf(handleCookieSeparator)
  if (at <= 0) return Option.none()
  const name = raw.slice(0, at)
  if (!isEmailOtpPurpose(name)) return Option.none()
  const handle = raw.slice(at + handleCookieSeparator.length)
  if (handle.length === 0) return Option.none()
  return Option.some({ purpose: name, handle: Redacted.make(handle) })
}

// -----------------------------------------------------------------------------
// The mailer seam
// -----------------------------------------------------------------------------

/**
 * One code, as the application is asked to deliver it.
 *
 * **Gotchas**
 *
 * `user` is `null` when the address has no account — a plugin's mail is not
 * always about somebody the library knows. Both messages must go out, and should
 * look alike enough that a recipient cannot use them to decide whether an address
 * is registered.
 *
 * `link` is present only for the `signIn` purpose, where a code and a link are
 * two ways to spend one row. A message that carries both should say so: the
 * person may be reading it on a handset and typing the code into a laptop.
 *
 * @category models
 * @since 0.2.0
 */
export interface EmailOtpEmail {
  /** The account it belongs to, or `null` when the address has none. */
  readonly user: User | null
  /** The address the message goes to, normalized. */
  readonly email: string
  /** The code itself. The only copy that will ever exist. */
  readonly code: Redacted.Redacted
  /** The link that spends the same row, or `null` for a purpose that has none. */
  readonly link: Redacted.Redacted | null
  /** What the code is for, so one template can serve all five. */
  readonly purpose: EmailOtpPurpose
}

/**
 * The {@link EmailOtpEmails} service definition — what an application implements
 * to deliver codes.
 *
 * **Gotchas**
 *
 * A service of the plugin's own rather than a method on `AuthEmails`: a plugin
 * cannot widen a library interface every other deployment implements, and this
 * message's shape genuinely differs (there may be no user). A deployment that
 * forgets it gets a compile error from {@link layer}'s requirements, which is
 * the point.
 *
 * @category models
 * @since 0.2.0
 */
export interface EmailOtpEmailsService {
  readonly sendCode: (email: EmailOtpEmail) => Effect.Effect<void, EmailDeliveryError>
}

/**
 * Delivers one-time codes. See {@link EmailOtpEmailsService}.
 *
 * @category services
 * @since 0.2.0
 */
export class EmailOtpEmails extends Context.Service<EmailOtpEmails, EmailOtpEmailsService>()(
  "effect-auth/email-otp/EmailOtp/EmailOtpEmails"
) {}

// -----------------------------------------------------------------------------
// Options
// -----------------------------------------------------------------------------

/**
 * What a deployment may vary about the e-mail one-time-code flow.
 *
 * @category models
 * @since 0.2.0
 */
export interface Config {
  /**
   * How many digits a code has. Defaults to **eight**.
   *
   * **Gotchas**
   *
   * Six is the norm for something typed off a handset. An e-mailed code is
   * copied and pasted, so two more digits are two orders of magnitude of guess
   * resistance for no ergonomic cost.
   */
  readonly digits: number
  /**
   * How long a code and its link may be answered for. Defaults to ten minutes,
   * which is NIST 800-63B's ceiling for a mailed authenticator.
   */
  readonly ttl: Duration.Duration
  /** How many wrong guesses one issuance survives. Defaults to five. */
  readonly attempts: number
  /**
   * The shortest interval between two codes for the same subject. Defaults to
   * sixty seconds, counted against the address (or the user id) rather than the
   * caller's own network address, so it cannot be escaped by rotating an IP.
   */
  readonly resendCooldown: Duration.Duration
  /**
   * Refuse to create an account for an address that has none. Defaults to
   * `false` — a mailed code is the classic sign-up-and-sign-in-in-one.
   *
   * **Gotchas**
   *
   * Switching it on changes nothing an unauthenticated caller can observe about
   * {@link EmailOtpService.send}: the rows are still written and the cookie is
   * still set. The refusal arrives at `verify`, as `SignUpDisabled`.
   */
  readonly disableSignUp: boolean
  /**
   * The path the e-mailed link points at, resolved against `baseUrl`. Defaults
   * to `/auth/email-otp/link`, which is where `EmailOtpApiGroup` serves it.
   *
   * **Gotchas**
   *
   * Change it only to point at a page of your own that forwards the `token` to
   * the endpoint — a deployment serving the API somewhere else changes
   * `AuthConfig.basePath` and this together.
   */
  readonly linkPath: string
  /**
   * Whether a sign-in code also mints a link. Defaults to `true`: the hybrid is
   * the reason this module absorbed magic link.
   */
  readonly link: boolean
  /**
   * How long the continuation a `resetPassword` code hands back may be spent
   * for. Defaults to fifteen minutes.
   */
  readonly resetTtl: Duration.Duration
  /**
   * Destroy the sign-in methods, authenticators and sessions of an *unverified*
   * account when a code proves control of its address. Defaults to `true`.
   *
   * **Gotchas**
   *
   * This is the pre-registration takeover defence, and switching it off is a
   * real decision: an address whose account was created by somebody who never
   * proved they owned it keeps whatever they set up — a password they know, an
   * OAuth identity they control, a passkey they registered — and they keep it
   * *alongside* the real owner, who has just signed in.
   */
  readonly revokeUnprovenAccounts: boolean
}

/**
 * {@link Config}, with every field optional.
 *
 * @category models
 * @since 0.2.0
 */
export interface Options {
  readonly digits?: number | undefined
  readonly ttl?: Duration.Duration | undefined
  readonly attempts?: number | undefined
  readonly resendCooldown?: Duration.Duration | undefined
  readonly disableSignUp?: boolean | undefined
  readonly linkPath?: string | undefined
  readonly link?: boolean | undefined
  readonly resetTtl?: Duration.Duration | undefined
  readonly revokeUnprovenAccounts?: boolean | undefined
}

/**
 * The defaults every unstated {@link Options} field resolves to.
 *
 * @category constructors
 * @since 0.2.0
 */
export const defaults: Config = {
  digits: 8,
  ttl: Duration.minutes(10),
  attempts: 5,
  resendCooldown: Duration.seconds(60),
  disableSignUp: false,
  linkPath: emailOtpLinkPath,
  link: true,
  resetTtl: Duration.minutes(15),
  revokeUnprovenAccounts: true
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
 * What {@link EmailOtpService.send} takes.
 *
 * @category models
 * @since 0.2.0
 */
export interface SendOptions {
  /** The address to send the code to. Normalized here, not by the caller. */
  readonly email: string
  /** What the code is for. */
  readonly purpose: SendPurpose
  /** The display name to give an account this code ends up creating. */
  readonly name?: string | undefined
  /** Where to land after the link is followed. Validated here as well as by the caller. */
  readonly callbackURL?: string | undefined
  /** Where to land instead when the link created the account. */
  readonly newUserCallbackURL?: string | undefined
  /** Where to land when following the link fails. */
  readonly errorCallbackURL?: string | undefined
  /** When explicitly `false`, the session the code establishes expires in a day. */
  readonly rememberMe?: boolean | undefined
}

/**
 * An issued challenge, as the endpoint that asked for it sees it.
 *
 * **Gotchas**
 *
 * There is always one, even when nothing was delivered and the rows were
 * discarded: a caller that got no cookie would know something about the address
 * it named. A handle naming a row that is not there answers `InvalidCode`, which
 * is the same answer a wrong code gets.
 *
 * @category models
 * @since 0.2.0
 */
export interface Issued {
  /** The cookie's value — `<purpose>.<handle>`. See {@link encodeHandleCookie}. */
  readonly handle: Redacted.Redacted
  /** When the challenge stops being answerable, and how long the cookie should live. */
  readonly expiresAt: DateTime.Utc
}

/**
 * What {@link EmailOtpService.verify} takes.
 *
 * @category models
 * @since 0.2.0
 */
export interface VerifyOptions {
  /** The cookie's value, exactly as the browser sent it. */
  readonly handle: Redacted.Redacted
  /** Exactly what the person typed. */
  readonly code: Redacted.Redacted
  /** Recorded on the session row, so a person can recognise their own devices. */
  readonly ipAddress?: string | null | undefined
  readonly userAgent?: string | null | undefined
  /**
   * The session the browser already carried, if it carried one.
   *
   * The upgrade seam: somebody who was browsing as an anonymous visitor and now
   * answers a code for the account they had all along. It reaches
   * `AuthHooks.beforeSessionMint`, which is where a deployment merges the two.
   * `None` on every ordinary sign-in.
   */
  readonly current?: SessionWithUser | undefined
}

/**
 * A session this plugin established.
 *
 * @category models
 * @since 0.2.0
 */
export interface SignedIn {
  readonly _tag: "SignedIn"
  readonly user: User
  readonly session: Session
  /**
   * The session's raw token — the only copy that will ever exist. Put it in a
   * `Set-Cookie` and drop it.
   */
  readonly token: Redacted.Redacted
  /** What the request asked for, carried through the challenge's payload. */
  readonly rememberMe: boolean
  /** `true` when spending this credential is what created the account. */
  readonly userCreated: boolean
  /** The validated URL a browser is to be sent to. */
  readonly redirectTo: string
}

/**
 * A credential that was accepted, where a factor plugin owes a second factor
 * before a session exists.
 *
 * @category models
 * @since 0.2.0
 */
export interface Challenged {
  readonly _tag: "Challenge"
  readonly challenge: SignInChallenge
  /** The validated URL a browser is to be sent to, once it has answered. */
  readonly redirectTo: string
}

/**
 * A code that proved control of an address and established nothing.
 *
 * @category models
 * @since 0.2.0
 */
export interface Verified {
  readonly _tag: "Verified"
  readonly user: User
}

/**
 * A reset code's continuation.
 *
 * @category models
 * @since 0.2.0
 */
export interface PasswordReset {
  readonly _tag: "PasswordReset"
  /** Spend it at `Passwords.resetPassword` — `POST /auth/reset-password`. */
  readonly token: Redacted.Redacted
  readonly expiresAt: DateTime.Utc
}

/**
 * What answering a code can mean.
 *
 * @category models
 * @since 0.2.0
 */
export type VerifyResult = SignedIn | Challenged | Verified | PasswordReset

/**
 * Everything spending a code or a link can fail with that this plugin
 * classifies itself, apart from persistence.
 *
 * @category models
 * @since 0.2.0
 */
export type VerifyError = InvalidCode | SignUpDisabled | PolicyRefused

/**
 * The outcome of {@link EmailOtpService.follow}: always somewhere to send the
 * browser.
 *
 * @category models
 * @since 0.2.0
 */
export type LinkOutcome = Result.Result<SignedIn | Challenged, RedirectFailure<VerifyError>>

/**
 * The codes themselves, keyed by tag. The mapped type is what keeps the set
 * closed: a new member of {@link VerifyError} is a compile error here rather
 * than a silent fall-through to somebody else's code.
 */
const errorCodes: { readonly [Tag in VerifyError["_tag"]]: string } = {
  SignUpDisabled: "sign_up_disabled",
  PolicyRefused: "policy_refused",
  InvalidCode: "invalid_token"
}

/**
 * The safe error code a failed link reports in the redirect's query string.
 *
 * **Details**
 *
 * A closed set of three, chosen by this library. Nothing a caller supplied is
 * ever echoed, and none of the codes says whether the address has an account:
 * `invalid_token` covers a link that was never minted, one already spent and one
 * that expired alike — and it is spelled the way magic link spelled it, because
 * a landing page that already handles it should go on working.
 *
 * @category combinators
 * @since 0.2.0
 */
export const errorCode = (error: VerifyError): string => errorCodes[error._tag]

// -----------------------------------------------------------------------------
// Service
// -----------------------------------------------------------------------------

/**
 * The {@link EmailOtp} service definition.
 *
 * @category models
 * @since 0.2.0
 */
export interface EmailOtpService {
  /** The resolved configuration this instance was built with. */
  readonly config: Config

  /**
   * Mints a code — and, for the sign-in purpose, a link against the same row —
   * and hands them to the {@link EmailOtpEmails} seam.
   *
   * **Gotchas**
   *
   * Succeeds whether or not the address belongs to a user, and answers a handle
   * either way. Delivery is forked, so nothing about the mailer is on the
   * caller's clock.
   */
  readonly send: (options: SendOptions) => Effect.Effect<Issued, PersistenceError>

  /**
   * Answers a code: claims the challenge atomically, compares in the storage
   * domain, and does whatever the purpose the handle names means.
   *
   * **Details**
   *
   * `InvalidCode` is every way of being wrong — an unknown or malformed handle,
   * a wrong code, an expired one, one already answered, one issued under
   * another purpose, and a budget that has run out. `SignUpDisabled` is the
   * deployment refusing to create an account; `PolicyRefused` is a deployment's
   * own hook declining the account or the session, raised only after the code
   * has been spent.
   */
  readonly verify: (options: VerifyOptions) => Effect.Effect<VerifyResult, VerifyError | PersistenceError>

  /**
   * Spends the link minted beside a sign-in code, resolved into somewhere to
   * send a browser.
   *
   * **When to use**
   *
   * From the `GET` endpoint. The person arrived by a top-level navigation out of
   * their mailbox and has to land on a page, so a failure becomes a redirect to
   * the link's own `errorCallbackURL` carrying `?error=<code>` rather than an
   * error body.
   */
  readonly follow: (options: {
    readonly token: Redacted.Redacted
    readonly ipAddress?: string | null | undefined
    readonly userAgent?: string | null | undefined
    /** The session the browser already carried. See {@link VerifyOptions.current}. */
    readonly current?: SessionWithUser | undefined
  }) => Effect.Effect<LinkOutcome, PersistenceError>

  /**
   * Mints a step-up code for a signed-in person and mails it to the address
   * their own account carries.
   */
  readonly requestStepUp: (user: User) => Effect.Effect<Issued, PersistenceError>

  /**
   * Answers a step-up code, raising the session's assurance.
   *
   * **Gotchas**
   *
   * The challenge's subject is checked against the session's user here, in the
   * service, rather than being trusted from the route: a handle is a bearer
   * value and the row it names says whose it is.
   */
  readonly verifyStepUp: (options: {
    readonly session: Session
    readonly handle: Redacted.Redacted
    readonly code: Redacted.Redacted
  }) => Effect.Effect<ElevatedSession, InvalidCode | PersistenceError>

  /**
   * Mints a change-of-address code and mails it to the address the account is
   * to be moved to.
   *
   * **Gotchas**
   *
   * Nothing is delivered when that address already belongs to somebody — the
   * rows are minted and discarded instead, so the caller cannot use this
   * endpoint to enumerate registrations from their own mailbox, and a stranger
   * is never told that somebody tried to take their address.
   */
  readonly requestEmailChange: (options: {
    readonly user: User
    readonly newEmail: string
  }) => Effect.Effect<Issued, EmailUnchanged | PersistenceError>

  /**
   * Answers a change-of-address code and moves the account.
   */
  readonly verifyEmailChange: (options: {
    readonly user: User
    readonly handle: Redacted.Redacted
    readonly code: Redacted.Redacted
  }) => Effect.Effect<User, InvalidCode | UserAlreadyExists | PersistenceError>
}

/**
 * E-mail one-time codes, and the link beside them. See {@link EmailOtpService}.
 *
 * @category services
 * @since 0.2.0
 */
export class EmailOtp extends Context.Service<EmailOtp, EmailOtpService>()("effect-auth/email-otp/EmailOtp") {}

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

/**
 * What {@link make} needs.
 *
 * **Gotchas**
 *
 * Every one of these but {@link EmailOtpEmails} is published by `Auth.layer`, so
 * a consumer composes this plugin over their deployment and supplies one mailer:
 *
 * ```ts skip-type-checking
 * const EmailOtpLive = EmailOtp.layer({ ttl }).pipe(
 *   Layer.provideMerge(AuthLive),
 *   Layer.provide(MyOtpMailer)
 * )
 * ```
 *
 * @category models
 * @since 0.2.0
 */
export type Requirements =
  | EmailOtpEmails
  | AuthConfig
  | AuthEvents
  | Challenges
  | Verifications
  | SignIn
  | Sessions
  | Users
  | UserStore
  | AccountStore
  | SessionStore
  | WithAuthTransaction

/**
 * Builds the {@link EmailOtp} implementation.
 *
 * **Gotchas**
 *
 * Every service is resolved here, when the layer is built, so that no method
 * carries a request-time requirement — the same shape `Passwords.make` has.
 *
 * The `Scope` is the layer's own, and it is what deliveries are forked into:
 * a mail must outlive the request that asked for it (or the send endpoint is a
 * timing oracle) and must not outlive the deployment.
 *
 * @category constructors
 * @since 0.2.0
 */
export const make: (options?: Options) => Effect.Effect<EmailOtpService, never, Requirements | Scope.Scope> =
  Effect.fnUntraced(function* (options?: Options) {
    const settings = makeConfig(options)
    const config = yield* AuthConfig
    const emails = yield* EmailOtpEmails
    const events = yield* AuthEvents
    const challenges = yield* Challenges
    const verifications = yield* Verifications
    // The one choke point every sign-in in this library goes through.
    const { complete: completeSignIn } = yield* SignIn
    const sessions = yield* Sessions
    const domain = yield* Users
    const users = yield* UserStore
    const accounts = yield* AccountStore
    const sessionStore = yield* SessionStore
    const transaction = yield* WithAuthTransaction
    // A `Context.Reference` with a no-op default, read here so the set of
    // contributors is fixed when the layer is built rather than looked up on
    // every request. It has to be provided *under* this layer as well as under
    // `Auth.layer`, which one `Layer.provide` over the composed plugin does.
    const authenticators = yield* Authenticators
    // Deliveries are forked into the layer's scope: off the request's clock,
    // and interrupted when the deployment goes down rather than leaking.
    const scope = yield* Effect.scope

    /**
     * A caller-supplied redirect target, or `null` when it did not survive
     * `trustedOrigins`.
     *
     * Dropped rather than refused, and validated *here* as well as at the HTTP
     * layer: what goes in ends up in a link sent to somebody's mailbox, and an
     * open redirect there is a phishing page with this deployment's name on it.
     */
    const target = (candidate: string | undefined): string | null => Option.getOrNull(validateUrl(config, candidate))

    /**
     * Hands one message to the mailer, off the request path.
     *
     * A mail that is awaited only on the branch where the address is known is a
     * timing oracle whatever else the endpoint equalises, and a mailer is the
     * one thing in this flow whose latency the library does not control.
     */
    const deliver = (email: EmailOtpEmail): Effect.Effect<void> =>
      Effect.asVoid(
        Effect.forkIn(deliverEmail(emails.sendCode(email), "email one-time code delivery failed", email.email), scope)
      )

    /** Mints the challenge, and — for the sign-in purpose — the link beside it. */
    const issue = Effect.fnUntraced(function* (
      purposeName: EmailOtpPurpose,
      subject: string,
      payload: EmailOtpPayload
    ) {
      const rowPurpose = purposes[purposeName]
      // Retires whatever was outstanding for this subject, code and link alike:
      // two live codes for one person is two chances to guess, and the one they
      // are looking at is the one that just arrived.
      const issued = yield* challenges.issueCode({
        purpose: rowPurpose,
        subject,
        digits: settings.digits,
        ttl: settings.ttl,
        attempts: settings.attempts,
        payload
      })
      // Deliberately after the challenge: `issueCode` retires both namespaces
      // first, so a link minted before it would be swept away by its own
      // issuance. The two rows live at two identifiers — a challenge row is not
      // redeemable as a link, which is the point of `Challenges.codeNamespace`
      // — so "consuming one consumes the other" is carried by each door
      // retiring the other's namespace, in `claimCode` and in `follow`.
      const link =
        purposeName === "signIn" && settings.link
          ? yield* verifications.issue({ purpose: rowPurpose, subject, ttl: settings.ttl, payload })
          : null
      return { issued, link }
    })

    const send = Effect.fnUntraced(
      function* (options: SendOptions) {
        const email = normalizeEmail(options.email)
        // The lookup runs on every path. Its result decides what the mailer is
        // told, never what the caller observes.
        const found = yield* users.findByEmail(email)
        const known = Option.isSome(found)

        const { issued, link } = yield* issue(options.purpose, email, {
          name: options.name ?? null,
          callbackURL: target(options.callbackURL),
          newUserCallbackURL: target(options.newUserCallbackURL),
          errorCallbackURL: target(options.errorCallbackURL),
          rememberMe: options.rememberMe !== false,
          newEmail: null
        })

        // Could this code ever do anything? An unknown address under
        // `disableSignUp` has nothing to sign in to, and an unknown address has
        // nothing to verify and no password to reset. Only the *delivery*
        // branches on that, and the delivery is forked: every path runs exactly
        // the same statements against the database, in the same order, so the
        // two answers are not separable by a stopwatch.
        //
        // The rows on an undeliverable path are left where they are rather than
        // deleted, because deleting them is one more round trip that the
        // deliverable path does not make — which is the whole timing signal
        // this endpoint exists to not have. They are inert: the code was never
        // mailed, and every spend refuses on its own account whatever the row
        // says (`resolve` answers `SignUpDisabled`, `markVerified` and
        // `resetContinuation` answer `InvalidCode`, all before the row's
        // payload is used for anything). They expire with the ttl.
        const deliverable = options.purpose === "signIn" ? known || !settings.disableSignUp : known
        if (deliverable) {
          yield* deliver({
            user: Option.getOrNull(found),
            email,
            code: issued.code,
            link: link === null ? null : tokenUrl(config, settings.linkPath, link.token),
            purpose: options.purpose
          })
        }

        return {
          handle: encodeHandleCookie(options.purpose, issued.handle),
          expiresAt: issued.expiresAt
        } satisfies Issued
      },
      (effect) => Effect.withSpan(effect, "EmailOtp.send")
    )

    /**
     * Provisions the account a sign-in credential is about.
     *
     * The row is built from the base user fields alone and handed to the
     * base-typed `Users.provision`, which is where `beforeUserCreate` and
     * `afterUserCreate` are consulted. A deployment's own columns are filled in
     * there from the model's declared defaults, so this plugin never has to know
     * what they are and a policy typed by the model still sees them.
     */
    const create = Effect.fnUntraced(function* (email: string, name: string | null) {
      const candidate = yield* insertRow(UserModel.insert, {
        name: name ?? email,
        email,
        // The code was delivered to this address and came back: that is the
        // whole of what verification ever proves.
        emailVerified: true,
        image: null
      })
      const user = yield* transaction.run(domain.provision({ candidate, source: emailOtpSource }))
      yield* publishSafely(events, {
        _tag: "UserCreated",
        userId: user.id,
        email: user.email,
        emailVerified: user.emailVerified,
        method: emailOtpMethod
      })
      return user
    })

    /**
     * Destroys an unverified account's sign-in methods, authenticators and
     * sessions, and marks the address verified. See the module header for why.
     */
    const reclaim = Effect.fnUntraced(function* (user: User) {
      const outcome = yield* transaction.run(
        Effect.gen(function* () {
          // Serialize on the USER row for the length of the transaction. The set
          // of a user's sign-in methods is being destroyed, and a concurrent
          // credential must not be added between the read and the delete. A
          // `FOR UPDATE` on the account rows alone cannot see a row a racing
          // link is about to *insert* — under READ COMMITTED that is a phantom,
          // unblocked — so both sides contend on the user row instead.
          yield* users.lockUserRow(user.id)
          const linked = yield* accounts.listByUserIdForUpdate(user.id)
          yield* accounts.deleteByUserId(user.id)
          // Inside the same transaction and under the same lock as the account
          // rows, because a factor is a way into this account exactly as an
          // `accounts` row is. A sweep bolted on after the commit would leave a
          // window in which the pre-registrant's passkey still worked — and the
          // defence claims the opposite. Contributors that installed nothing
          // answer zero.
          const factors = yield* revokeAllAuthenticators(authenticators, user.id)
          const revoked = yield* sessionStore.deleteByUserId(user.id)
          // An outstanding link is a way in as much as a password is, and it
          // outlives the session that asked for it. The one that matters most is
          // `change-email-verify`: on an unverified account the change-email flow
          // has no first hop, so whoever registered this address could already
          // have a live link that moves the account to a mailbox of their own.
          yield* retireUserSubjectTokens(verifications, user.id)
          const updated = yield* users.update(user.id, { emailVerified: true })
          return { linked, revoked, factors, updated }
        })
      )

      for (const account of outcome.linked) {
        yield* publishSafely(events, {
          _tag: "AccountUnlinked",
          userId: user.id,
          accountId: account.id,
          providerId: account.providerId,
          issuer: account.issuer
        })
      }
      yield* publishSafely(events, {
        _tag: "SessionRevoked",
        userId: user.id,
        sessionId: null,
        scope: "all",
        count: outcome.revoked
      })
      yield* publishSafely(events, {
        _tag: "PluginEvent",
        plugin: emailOtpPlugin,
        event: "UnprovenAccountRevoked",
        userId: user.id,
        data: { accounts: outcome.linked.length, authenticators: outcome.factors, sessions: outcome.revoked }
      })
      return outcome.updated
    })

    /**
     * The account a credential proved control of, as it stands once that proof
     * has been applied — `None` when the row went between the claim and the
     * write.
     */
    const settle = Effect.fnUntraced(function* (user: User) {
      if (user.emailVerified) return Option.some(user)
      const updated = settings.revokeUnprovenAccounts
        ? yield* reclaim(user)
        : yield* users.update(user.id, { emailVerified: true })
      if (Option.isNone(updated)) return Option.none<User>()
      yield* publishSafely(events, {
        _tag: "EmailVerified",
        userId: updated.value.id,
        email: updated.value.email
      })
      return Option.some(updated.value)
    })

    const resolve = Effect.fnUntraced(function* (email: string, payload: EmailOtpPayload) {
      const found = yield* users.findByEmail(email)
      if (Option.isNone(found)) {
        if (settings.disableSignUp) {
          return yield* SignUpDisabled.make()
        }
        return { user: yield* create(email, payload.name), userCreated: true }
      }
      const settled = yield* settle(found.value)
      if (Option.isNone(settled)) {
        // The row went between the two reads — a concurrent deletion. The
        // credential is spent and there is nobody to sign in.
        return yield* InvalidCode.make()
      }
      return { user: settled.value, userCreated: false }
    })

    const finish = Effect.fnUntraced(function* (
      email: string,
      payload: EmailOtpPayload,
      meta: {
        readonly ipAddress?: string | null | undefined
        readonly userAgent?: string | null | undefined
        readonly current?: SessionWithUser | undefined
      }
    ) {
      const { user, userCreated } = yield* resolve(email, payload)

      // After the claim, deliberately: only somebody holding a credential this
      // deployment minted and mailed to the address reaches this line, so a
      // refusal tells them nothing they had not already proved — and the code is
      // spent whichever way it goes, rather than left replayable until the
      // policy happens to allow it.
      const completed = yield* completeSignIn({
        user,
        source: emailOtpSource,
        evidence: [emailOtpEvidence],
        current: meta.current === undefined ? Option.none() : Option.some(meta.current),
        request: {
          ipAddress: meta.ipAddress ?? null,
          userAgent: meta.userAgent ?? null,
          rememberMe: payload.rememberMe
        }
      })

      const redirectTo = resolveUrl(
        config,
        userCreated ? (payload.newUserCallbackURL ?? payload.callbackURL) : payload.callbackURL
      )

      if (completed._tag === "Challenge") {
        // No session, no session cookie: the caller is handed the challenge and
        // the endpoint decides how to say so — a 202 for the JSON path, a
        // `?mfa=required` redirect for the browser one.
        return { _tag: "Challenge", challenge: completed, redirectTo } satisfies Challenged
      }

      return {
        _tag: "SignedIn",
        user,
        session: completed.session,
        token: completed.token,
        rememberMe: payload.rememberMe,
        userCreated,
        redirectTo
      } satisfies SignedIn
    })

    /** One retry, in one place: every entry point must resolve the race identically. */
    const spend = (
      email: string,
      payload: EmailOtpPayload,
      meta: {
        readonly ipAddress?: string | null | undefined
        readonly userAgent?: string | null | undefined
        readonly current?: SessionWithUser | undefined
      }
    ) =>
      Effect.retry(finish(email, payload, meta), {
        while: (error) => error._tag === "PersistenceError" && isUniqueViolation(error),
        times: 1
      })

    /**
     * Marks an address verified, and takes nothing away.
     *
     * **Details**
     *
     * Deliberately *not* `settle`: this door hands out no session, so nobody
     * gains a way into the account by walking through it, and the unproven
     * account rule exists to make sure the person who proves an address does
     * not have to share the account with whoever registered it unproved. The
     * two doors that do hand out access — the sign-in code and the reset
     * continuation — still apply it.
     *
     * Running it here instead destroys the ordinary case: somebody signs up
     * with a password, is asked to confirm their address, confirms it, and is
     * logged out everywhere with the password they chose two minutes ago
     * deleted. That is what the core `POST /auth/verify-email` does not do to
     * them, and this endpoint answers the same proof.
     *
     * **Gotchas**
     *
     * A person who arrives here to reclaim an address a squatter registered
     * marks it verified and disarms the sign-in door's defence, because that
     * door only fires on an unverified account. They cannot sign in — they do
     * not know the squatter's password — so the path they must actually take is
     * the reset code, which does still evict. Recorded rather than closed: the
     * alternative is the ordinary case above.
     */
    const markVerified = Effect.fnUntraced(function* (email: string) {
      const found = yield* users.findByEmail(email)
      if (Option.isNone(found)) return yield* InvalidCode.make()
      if (found.value.emailVerified) return { _tag: "Verified", user: found.value } satisfies Verified
      const updated = yield* users.update(found.value.id, { emailVerified: true })
      if (Option.isNone(updated)) return yield* InvalidCode.make()
      yield* publishSafely(events, {
        _tag: "EmailVerified",
        userId: updated.value.id,
        email: updated.value.email
      })
      return { _tag: "Verified", user: updated.value } satisfies Verified
    })

    /** Hands back a continuation the caller spends at `Passwords.resetPassword`. */
    const resetContinuation = Effect.fnUntraced(function* (email: string) {
      const found = yield* users.findByEmail(email)
      if (Option.isNone(found)) return yield* InvalidCode.make()
      // Proving control of the address is what the takeover defence turns on,
      // and it turns on it here too: whoever registered this address without
      // owning it does not get to keep their way in just because the real owner
      // arrived by the reset door rather than the sign-in one.
      const settled = yield* settle(found.value)
      if (Option.isNone(settled)) return yield* InvalidCode.make()
      const issued = yield* verifications.issue({
        purpose: passwordResetPurpose,
        subject: settled.value.id,
        ttl: settings.resetTtl,
        payload: null
      })
      yield* publishSafely(events, { _tag: "PasswordResetRequested", userId: settled.value.id })
      return { _tag: "PasswordReset", token: issued.token, expiresAt: issued.expiresAt } satisfies PasswordReset
    })

    /**
     * Claims a challenge and retires the link that was minted against the same
     * row — the other half of "consuming either retires both".
     */
    const claimCode = Effect.fnUntraced(function* (
      purposeName: EmailOtpPurpose,
      handle: Redacted.Redacted,
      code: Redacted.Redacted
    ) {
      const rowPurpose = purposes[purposeName]
      const claimed = yield* challenges.verifyCode({ purpose: rowPurpose, handle, code })
      // The code row is already consumed by the claim; this is the link beside
      // it, which the answered code retires.
      yield* verifications.retire(rowPurpose, claimed.subject)
      return claimed
    })

    const verify = Effect.fnUntraced(
      function* (options: VerifyOptions) {
        const cookie = yield* Effect.fromOption(decodeHandleCookie(options.handle), () => InvalidCode.make())
        // The two authenticated purposes have endpoints of their own and are not
        // reachable from here whatever the cookie says.
        if (cookie.purpose === "stepUp" || cookie.purpose === "changeEmail") {
          return yield* InvalidCode.make()
        }
        const claimed = yield* claimCode(cookie.purpose, cookie.handle, options.code)
        const email = normalizeEmail(claimed.subject)
        switch (cookie.purpose) {
          case "signIn":
            return yield* spend(email, claimed.payload, options)
          case "verifyEmail":
            return yield* markVerified(email)
          case "resetPassword":
            return yield* resetContinuation(email)
        }
      },
      (effect) => Effect.withSpan(effect, "EmailOtp.verify")
    )

    const failure = redirectFailure(config, errorCode)

    const follow = Effect.fnUntraced(
      function* (options: {
        readonly token: Redacted.Redacted
        readonly ipAddress?: string | null | undefined
        readonly userAgent?: string | null | undefined
        readonly current?: SessionWithUser | undefined
      }) {
        const claimed = yield* Effect.result(
          Effect.flatMap(verifications.claim(signInPurpose, options.token), (claimed) =>
            // The link row is already consumed by the claim; the code minted
            // beside it dies with it, in its own namespace.
            Effect.as(challenges.retire(signInPurpose, claimed.subject), claimed)
          )
        )
        if (claimed._tag === "Failure") {
          if (claimed.failure._tag === "PersistenceError") return yield* claimed.failure
          // No payload was ever read, so there is no error URL to honour: the
          // token is not one this deployment minted.
          return failure(InvalidCode.make(), null)
        }
        const finished = yield* Effect.result(
          spend(normalizeEmail(claimed.success.subject), claimed.success.payload, options)
        )
        if (finished._tag === "Failure") {
          // A fault is the one failure this endpoint cannot answer with a
          // redirect: it is a `500`, not a place to send somebody.
          if (finished.failure._tag === "PersistenceError") {
            return yield* finished.failure
          }
          return failure(finished.failure, claimed.success.payload.errorCallbackURL)
        }
        return Result.succeed(finished.success) satisfies LinkOutcome
      },
      (effect) => Effect.withSpan(effect, "EmailOtp.follow")
    )

    const requestStepUp = Effect.fnUntraced(
      function* (user: User) {
        const { issued } = yield* issue("stepUp", user.id, emptyPayload)
        yield* deliver({ user, email: normalizeEmail(user.email), code: issued.code, link: null, purpose: "stepUp" })
        return { handle: encodeHandleCookie("stepUp", issued.handle), expiresAt: issued.expiresAt } satisfies Issued
      },
      (effect) => Effect.withSpan(effect, "EmailOtp.requestStepUp")
    )

    const verifyStepUp = Effect.fnUntraced(
      function* (options: {
        readonly session: Session
        readonly handle: Redacted.Redacted
        readonly code: Redacted.Redacted
      }) {
        const cookie = yield* Effect.fromOption(decodeHandleCookie(options.handle), () => InvalidCode.make())
        if (cookie.purpose !== "stepUp") return yield* InvalidCode.make()
        const claimed = yield* claimCode("stepUp", cookie.handle, options.code)
        // Ownership in the service, never per route: the row says whose the
        // challenge is, and a handle is a bearer value.
        if (claimed.subject !== options.session.userId) return yield* InvalidCode.make()
        return yield* sessions.elevate(options.session, emailOtpEvidence)
      },
      (effect) => Effect.withSpan(effect, "EmailOtp.verifyStepUp")
    )

    const requestEmailChange = Effect.fnUntraced(
      function* (options: { readonly user: User; readonly newEmail: string }) {
        const newEmail = normalizeEmail(options.newEmail)
        if (newEmail === normalizeEmail(options.user.email)) {
          return yield* EmailUnchanged.make()
        }
        const taken = Option.isSome(yield* users.findByEmail(newEmail))
        const { issued } = yield* issue("changeEmail", options.user.id, { ...emptyPayload, newEmail })
        if (!taken) {
          yield* deliver({
            user: options.user,
            email: newEmail,
            code: issued.code,
            link: null,
            purpose: "changeEmail"
          })
        }
        // An address that belongs to somebody else is mailed nothing, and the
        // row minted for it is left in place rather than deleted: the two
        // branches must run the same statements, or an authenticated caller
        // could read a registration off the clock. The code was never sent and
        // `verifyEmailChange` refuses on the unique index regardless.
        return {
          handle: encodeHandleCookie("changeEmail", issued.handle),
          expiresAt: issued.expiresAt
        } satisfies Issued
      },
      (effect) => Effect.withSpan(effect, "EmailOtp.requestEmailChange")
    )

    const verifyEmailChange = Effect.fnUntraced(
      function* (options: {
        readonly user: User
        readonly handle: Redacted.Redacted
        readonly code: Redacted.Redacted
      }) {
        const cookie = yield* Effect.fromOption(decodeHandleCookie(options.handle), () => InvalidCode.make())
        if (cookie.purpose !== "changeEmail") return yield* InvalidCode.make()
        const claimed = yield* claimCode("changeEmail", cookie.handle, options.code)
        if (claimed.subject !== options.user.id) return yield* InvalidCode.make()
        const newEmail = claimed.payload.newEmail
        if (newEmail === null) return yield* InvalidCode.make()

        const previousEmail = options.user.email
        // The unique index is the arbiter: an address taken between the request
        // and the answer surfaces here and nowhere else.
        const updated = yield* Effect.catchIf(
          users.update(options.user.id, { email: newEmail, emailVerified: true }),
          isUniqueViolation,
          () => UserAlreadyExists.make()
        )
        if (Option.isNone(updated)) return yield* InvalidCode.make()

        yield* publishSafely(events, {
          _tag: "EmailChanged",
          userId: updated.value.id,
          previousEmail,
          email: updated.value.email
        })
        yield* publishSafely(events, {
          _tag: "EmailVerified",
          userId: updated.value.id,
          email: updated.value.email
        })
        return updated.value
      },
      (effect) => Effect.withSpan(effect, "EmailOtp.verifyEmailChange")
    )

    return EmailOtp.of({
      config: settings,
      send,
      verify,
      follow,
      requestStepUp,
      verifyStepUp,
      requestEmailChange,
      verifyEmailChange
    })
  })

/**
 * Provides {@link EmailOtp}.
 *
 * **Example**
 *
 * ```ts skip-type-checking
 * import { Layer } from "effect"
 * import { EmailOtp } from "effect-auth"
 *
 * const EmailOtpLive = EmailOtp.layer({ disableSignUp: true }).pipe(
 *   Layer.provideMerge(AuthLive),
 *   Layer.provide(MyOtpMailer)
 * )
 * ```
 *
 * @category layers
 * @since 0.2.0
 */
export const layer = (options?: Options): Layer.Layer<EmailOtp, never, Requirements> =>
  Layer.effect(EmailOtp, make(options))
