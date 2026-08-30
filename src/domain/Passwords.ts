/**
 * E-mail and password authentication.
 *
 * `Passwords` owns the local credential: signing up, signing in, the two
 * single-use e-mail flows (verification and reset), and changing a password
 * while signed in. The password hash lives on an {@link Account} row with the
 * synthetic issuer `local:credential`, so a user's password is just one more
 * sign-in method alongside their linked OAuth providers and can be added or
 * removed without touching the `users` table.
 *
 * **Details**
 *
 * Two rules shape almost every decision in this module.
 *
 * *No user enumeration.* An unauthenticated caller must not be able to learn
 * whether an address has an account. `signIn` therefore always performs exactly
 * one password verification — against {@link dummyPassword}'s hash when there
 * is no user or no credential — so a missing account costs the same wall-clock
 * time as a wrong password, and both answer `InvalidCredentials`.
 * `requestReset` and `sendVerificationEmail` succeed whether or not the address
 * is known.
 *
 * *Tokens are single-use and stored hashed.* The reset and verification links
 * carry a token whose SHA-256 digest is all the database holds, and claiming
 * one is a single atomic `DELETE ... RETURNING`.
 *
 * @since 1.0.0
 */
import { Context, DateTime, Effect, Encoding, Layer, Option, Redacted, Result } from "effect"
import { AuthConfig } from "../config/AuthConfig.js"
import type { AuthConfigService } from "../config/AuthConfig.js"
import { AuthEmails, resetPasswordUrl, verifyEmailUrl } from "../config/AuthEmails.js"
import { PasswordHasher } from "../crypto/PasswordHasher.js"
import { Token } from "../crypto/Token.js"
import { validateUrl } from "../http/OriginCheck.js"
import type { PasswordHashError } from "./Errors.js"
import {
  EmailNotVerified,
  InvalidCredentials,
  InvalidToken,
  PasswordPolicyViolation,
  UserAlreadyExists
} from "./Errors.js"
import { AuthEvents, passwordMethod, publishSafely } from "./Events.js"
import type { Session, SessionId, User, UserId } from "./Schema.js"
import {
  Account,
  CredentialIssuer,
  emailVerifyIdentifier,
  normalizeEmail,
  passwordResetIdentifier,
  User as UserModel,
  Verification
} from "./Schema.js"
import type { CreatedSession } from "./Sessions.js"
import { Sessions } from "./Sessions.js"
import type { PersistenceError } from "./Stores.js"
import {
  AccountStore,
  isUniqueViolation,
  SessionStore,
  UserStore,
  VerificationStore,
  WithAuthTransaction
} from "./Stores.js"

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/**
 * The `providerId` written on the `local:credential` account that carries a
 * user's password hash.
 *
 * **Gotchas**
 *
 * The row's identity is `(issuer, accountId)` = `("local:credential", userId)`.
 * `providerId` is only a label for `listAccounts` responses, so a client can
 * show "Password" next to "GitHub".
 *
 * @category constructors
 * @since 1.0.0
 */
export const credentialProviderId = "credential"

/**
 * The constant hashed once at layer construction and verified against whenever
 * sign-in has no real hash to check.
 *
 * **Gotchas**
 *
 * The value is irrelevant; what matters is that its stored form was produced by
 * the *same* hasher with the *same* cost parameters as a real password, so the
 * verification takes the same time. A hand-written literal with different
 * parameters would verify at a different cost and re-open the enumeration
 * channel this is here to close.
 *
 * @category constructors
 * @since 1.0.0
 */
export const dummyPassword = "effect-auth::timing-defence::not-a-real-password"

/**
 * The user id `signIn` looks a credential up under when the address is unknown.
 *
 * **Details**
 *
 * The nil UUID. Ids are UUIDv7, whose version nibble is `7`, so no row this
 * library writes can ever carry it — the lookup is a guaranteed miss with the
 * same shape and cost as a real one, which is what keeps the two sign-in paths
 * indistinguishable in round trips as well as in hashing work.
 *
 * @category constructors
 * @since 1.0.0
 */
export const absentUserId = "00000000-0000-0000-0000-000000000000" as UserId

// -----------------------------------------------------------------------------
// Subject tokens
// -----------------------------------------------------------------------------

/**
 * The separator between a subject-token's subject and its secret. Neither half
 * can contain it: the subject is base64url encoded and the secret is a
 * base64url token.
 *
 * @category constructors
 * @since 1.0.0
 */
export const subjectTokenSeparator = "."

/**
 * Pairs the subject a single-use token belongs to with the secret itself.
 *
 * @category models
 * @since 1.0.0
 */
export interface SubjectToken {
  /** The user id (password reset) or normalized e-mail address (verification). */
  readonly subject: string
  /** The 43-character random half, the only part that is hashed and stored. */
  readonly secret: Redacted.Redacted<string>
}

/**
 * Builds the token that goes into an e-mail link:
 * `<base64url(subject)>.<secret>`.
 *
 * **Details**
 *
 * `Verification.identifier` is namespaced by subject (`password-reset:<userId>`,
 * `email-verify:<email>`), and `VerificationStore.consume` — the atomic
 * single-use claim — needs both the identifier and the value hash. A recipient
 * presenting only a bare secret could not name the row, so the subject travels
 * with it. The subject is not a secret; the 256 bits of randomness beside it
 * are, and only their digest is stored.
 *
 * @category constructors
 * @since 1.0.0
 */
export const encodeSubjectToken = (subject: string, secret: Redacted.Redacted<string>): Redacted.Redacted<string> =>
  Redacted.make(`${Encoding.encodeBase64Url(subject)}${subjectTokenSeparator}${Redacted.value(secret)}`)

/**
 * Splits a subject token back into its subject and its secret, or `None` when
 * it is not a subject token at all.
 *
 * @category combinators
 * @since 1.0.0
 */
export const decodeSubjectToken = (token: Redacted.Redacted<string>): Option.Option<SubjectToken> => {
  const raw = Redacted.value(token)
  const at = raw.indexOf(subjectTokenSeparator)
  if (at <= 0 || at === raw.length - 1) return Option.none()
  const subject = Encoding.decodeBase64UrlString(raw.slice(0, at))
  if (Result.isFailure(subject)) return Option.none()
  return Option.some({ subject: subject.success, secret: Redacted.make(raw.slice(at + 1)) })
}

// -----------------------------------------------------------------------------
// Policy
// -----------------------------------------------------------------------------

/**
 * Checks a password against the configured policy, failing
 * `PasswordPolicyViolation` when it is too short or too long.
 *
 * **Gotchas**
 *
 * The maximum is a denial-of-service bound, not a security requirement: without
 * it an unauthenticated caller could hand the key-derivation function an
 * arbitrarily large input.
 *
 * @category combinators
 * @since 1.0.0
 */
export const checkPolicy = (
  password: Redacted.Redacted<string>,
  config: AuthConfigService
): Effect.Effect<void, PasswordPolicyViolation> => {
  const { maxPasswordLength, minPasswordLength } = config.emailPassword
  const length = Redacted.value(password).length
  if (length < minPasswordLength) {
    return Effect.fail(
      new PasswordPolicyViolation({ reason: "TooShort", minLength: minPasswordLength, maxLength: maxPasswordLength })
    )
  }
  if (length > maxPasswordLength) {
    return Effect.fail(
      new PasswordPolicyViolation({ reason: "TooLong", minLength: minPasswordLength, maxLength: maxPasswordLength })
    )
  }
  return Effect.void
}

// -----------------------------------------------------------------------------
// Models
// -----------------------------------------------------------------------------

/**
 * What {@link Passwords} needs to register a user.
 *
 * @category models
 * @since 1.0.0
 */
export interface SignUpOptions {
  readonly name: string
  readonly email: string
  readonly password: Redacted.Redacted<string>
  readonly image?: string | null | undefined
  readonly ipAddress?: string | null | undefined
  readonly userAgent?: string | null | undefined
  readonly rememberMe?: boolean | undefined
  /**
   * Where the verification link should send the user afterwards. Validated
   * against `trustedOrigins` here as well as by the caller, and dropped from
   * the link when it does not survive that.
   */
  readonly callbackURL?: string | undefined
}

/**
 * The outcome of a sign-up.
 *
 * **Details**
 *
 * `session` is `None` when `emailPassword.autoSignIn` is off, and also when
 * `emailPassword.requireEmailVerification` is on — a user who still has to
 * prove they own the address does not get a session for having claimed it.
 *
 * @category models
 * @since 1.0.0
 */
export interface SignUpResult {
  readonly user: User
  readonly session: Option.Option<CreatedSession>
}

/**
 * What {@link Passwords} needs to sign a user in.
 *
 * @category models
 * @since 1.0.0
 */
export interface SignInOptions {
  readonly email: string
  readonly password: Redacted.Redacted<string>
  readonly ipAddress?: string | null | undefined
  readonly userAgent?: string | null | undefined
  readonly rememberMe?: boolean | undefined
}

/**
 * A completed sign-in: the user, the session, and the session's raw token.
 *
 * @category models
 * @since 1.0.0
 */
export interface SignInResult {
  readonly user: User
  readonly session: Session
  readonly token: Redacted.Redacted<string>
}

/**
 * What {@link Passwords} needs to change a password from inside a session.
 *
 * @category models
 * @since 1.0.0
 */
export interface ChangePasswordOptions {
  readonly userId: UserId
  readonly currentPassword: Redacted.Redacted<string>
  readonly newPassword: Redacted.Redacted<string>
  /**
   * Sign every other device out. Defaults to `true`: a password change is
   * usually a response to a suspected compromise.
   */
  readonly revokeOtherSessions?: boolean | undefined
  /**
   * The session making the request, kept alive when other sessions are
   * revoked. Without it, revoking "others" revokes everything including the
   * caller's own session.
   */
  readonly currentSessionId?: SessionId | undefined
}

// -----------------------------------------------------------------------------
// Service
// -----------------------------------------------------------------------------

/**
 * The {@link Passwords} service definition.
 *
 * @category models
 * @since 1.0.0
 */
export interface PasswordsService {
  /**
   * Registers a user and their `local:credential` account in one transaction,
   * then — outside it — emits `UserCreated`, sends the verification mail if the
   * configuration asks for one, and establishes a session if it allows one.
   */
  readonly signUp: (
    options: SignUpOptions
  ) => Effect.Effect<SignUpResult, UserAlreadyExists | PasswordPolicyViolation | PasswordHashError | PersistenceError>

  /**
   * Verifies a password and establishes a session.
   *
   * **Details**
   *
   * Exactly one hash verification runs on every call, whether or not the
   * address exists, so response time reveals nothing. An unknown address, a
   * user with no password credential, and a wrong password are one and the same
   * answer: `InvalidCredentials`.
   *
   * **Gotchas**
   *
   * The password policy is deliberately *not* applied here. A branch taken
   * before the verification would be a timing signal, and rejecting an
   * over-long password early would refuse a credential that was valid under an
   * earlier policy. The key-derivation cost does not depend on the input's
   * length; bounding the request body is the HTTP layer's job.
   */
  readonly signIn: (
    options: SignInOptions
  ) => Effect.Effect<SignInResult, InvalidCredentials | EmailNotVerified | PasswordHashError | PersistenceError>

  /**
   * Mints a password reset token and hands it to the `AuthEmails` seam.
   *
   * **Gotchas**
   *
   * Succeeds whether or not the address belongs to a user, and swallows
   * delivery failures after logging them, so the status code and the body are
   * identical either way.
   *
   * What is *not* identical is the latency: a known address additionally mints
   * a token, writes a row and awaits the mailer. Closing that channel properly
   * means handing delivery to a queue — an `AuthEmails` implementation that
   * enqueues and returns is all this needs, and is what a deployment that
   * cares about the residual signal should provide. Delivering from inside the
   * request fibre is kept as the default because it is what makes a broken
   * mailer visible in the request's own logs.
   */
  readonly requestReset: (
    options: { readonly email: string; readonly redirectTo?: string | undefined }
  ) => Effect.Effect<void, PersistenceError>

  /**
   * Claims a reset token, replaces the password hash, and revokes every session
   * the user has.
   *
   * **Details**
   *
   * Whoever held the old password — or the mailbox — should not keep a live
   * session, so revocation is unconditional and runs in the same transaction as
   * the hash update. Any *other* reset token outstanding for the same user is
   * deleted in that transaction too: a second, still-unexpired link would
   * otherwise let the account be taken straight back.
   */
  readonly resetPassword: (
    options: { readonly token: Redacted.Redacted<string>; readonly newPassword: Redacted.Redacted<string> }
  ) => Effect.Effect<void, InvalidToken | PasswordPolicyViolation | PasswordHashError | PersistenceError>

  /**
   * Replaces a password after checking the current one.
   *
   * **Gotchas**
   *
   * Session freshness is *not* checked here — the HTTP layer's `requireFresh`
   * guard owns that, because only it can see the caller's session.
   */
  readonly changePassword: (
    options: ChangePasswordOptions
  ) => Effect.Effect<void, InvalidCredentials | PasswordPolicyViolation | PasswordHashError | PersistenceError>

  /**
   * Mints an e-mail verification token and hands it to the `AuthEmails` seam.
   * Silently succeeds for an unknown or already-verified address.
   */
  readonly sendVerificationEmail: (
    options: { readonly email: string; readonly callbackURL?: string | undefined }
  ) => Effect.Effect<void, PersistenceError>

  /**
   * Claims a verification token and marks the address verified.
   *
   * **Gotchas**
   *
   * An expired token is indistinguishable from an unknown one: consumption is a
   * single conditional delete, so there is no row left to inspect. Both report
   * `InvalidToken`.
   */
  readonly verifyEmail: (
    token: Redacted.Redacted<string>
  ) => Effect.Effect<User, InvalidToken | PersistenceError>
}

/**
 * E-mail and password authentication.
 *
 * @category services
 * @since 1.0.0
 */
export class Passwords extends Context.Service<Passwords, PasswordsService>()("effect-auth/Passwords") {}

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

/**
 * Builds the {@link Passwords} implementation.
 *
 * **Gotchas**
 *
 * Hashing {@link dummyPassword} happens once, here, when the layer is built. A
 * hasher that cannot hash a constant string is a broken deployment, so the
 * failure is promoted to a defect rather than added to the layer's error
 * channel.
 *
 * @category constructors
 * @since 1.0.0
 */
export const make: () => Effect.Effect<
  PasswordsService,
  never,
  | AuthConfig
  | AuthEmails
  | AuthEvents
  | PasswordHasher
  | Token
  | Sessions
  | UserStore
  | SessionStore
  | AccountStore
  | VerificationStore
  | WithAuthTransaction
> = Effect.fnUntraced(function*() {
  const config = yield* AuthConfig
  const hasher = yield* PasswordHasher
  const tokens = yield* Token
  const users = yield* UserStore
  const accounts = yield* AccountStore
  const sessionStore = yield* SessionStore
  const verifications = yield* VerificationStore
  const transaction = yield* WithAuthTransaction
  const emails = yield* AuthEmails
  const sessions = yield* Sessions
  const events = yield* AuthEvents

  const dummyHash = yield* Effect.orDie(hasher.hash(Redacted.make(dummyPassword)))

  /**
   * Appends the caller's landing page to an e-mailed link — after validating
   * it, again.
   *
   * **Gotchas**
   *
   * The HTTP layer is expected to have validated this already, and this second
   * pass is deliberate: what goes in here ends up in a link sent to somebody's
   * mailbox, and an open redirect there is a phishing page with the
   * deployment's own name on it. A candidate that does not survive
   * `validateUrl` is dropped rather than refused — the reset mail is worth
   * sending without it.
   */
  const withCallback = (
    url: Redacted.Redacted<string>,
    callbackURL: string | undefined
  ): Redacted.Redacted<string> => {
    const validated = validateUrl(config, callbackURL)
    if (Option.isNone(validated)) return url
    const parsed = new URL(Redacted.value(url))
    parsed.searchParams.set("callbackURL", validated.value)
    return Redacted.make(parsed.toString())
  }

  /** Mints a single-use value, stores its digest, and returns the subject token. */
  const issue = Effect.fnUntraced(function*(identifier: string, subject: string, expiresAt: DateTime.Utc) {
    const secret = yield* tokens.generateToken
    const valueHash = yield* tokens.hashToken(secret)
    const row = yield* Effect.orDie(Verification.insert.makeEffect({
      identifier,
      valueHash,
      payload: null,
      expiresAt
    }))
    yield* verifications.create(row)
    return encodeSubjectToken(subject, secret)
  })

  /** Claims a single-use value named by a subject token. */
  const claim = Effect.fnUntraced(function*(
    token: Redacted.Redacted<string>,
    identifierOf: (subject: string) => string
  ) {
    const parts = decodeSubjectToken(token)
    if (Option.isNone(parts)) {
      return yield* Effect.fail(new InvalidToken())
    }
    const valueHash = yield* tokens.hashToken(parts.value.secret)
    const consumed = yield* verifications.consume(identifierOf(parts.value.subject), valueHash)
    if (Option.isNone(consumed)) {
      return yield* Effect.fail(new InvalidToken())
    }
    return parts.value.subject
  })

  const sendVerificationTo = Effect.fnUntraced(function*(
    user: User,
    callbackURL: string | undefined
  ) {
    const now = yield* DateTime.now
    const token = yield* issue(
      emailVerifyIdentifier(user.email),
      user.email,
      DateTime.addDuration(now, config.tokens.emailVerificationTtl)
    )
    const url = withCallback(verifyEmailUrl(config, token), callbackURL)
    // Delivery is the application's responsibility and its failure must not
    // change what the caller observes; it is logged and dropped.
    yield* Effect.ignore(
      emails.sendVerification({ user, token, url }),
      { log: "Warn", message: "effect-auth: verification e-mail delivery failed" }
    )
  })

  const credentialAccountFor = (userId: UserId) => accounts.findByIssuerAccountId(CredentialIssuer, userId)

  const createCredentialAccount = Effect.fnUntraced(function*(userId: UserId, passwordHash: string) {
    const row = yield* Effect.orDie(Account.insert.makeEffect({
      issuer: CredentialIssuer,
      accountId: userId,
      providerId: credentialProviderId,
      userId,
      accessToken: null,
      refreshToken: null,
      idToken: null,
      accessTokenExpiresAt: null,
      refreshTokenExpiresAt: null,
      scope: null,
      passwordHash
    }))
    return yield* accounts.create(row)
  })

  // ---------------------------------------------------------------------------

  const signUp = Effect.fnUntraced(function*(options: SignUpOptions) {
    yield* checkPolicy(options.password, config)
    const email = normalizeEmail(options.email)

    const existing = yield* users.findByEmail(email)
    if (Option.isSome(existing)) {
      return yield* Effect.fail(new UserAlreadyExists())
    }

    const passwordHash = yield* hasher.hash(options.password)

    const user = yield* transaction.run(Effect.gen(function*() {
      const row = yield* Effect.orDie(UserModel.insert.makeEffect({
        name: options.name,
        email,
        emailVerified: false,
        image: options.image ?? null
      }))
      const created = yield* users.create(row)
      yield* createCredentialAccount(created.id, passwordHash)
      return created
    })).pipe(
      // The pre-check above closes the ordinary case; this closes the race in
      // which two sign-ups for one address interleave.
      Effect.catchTag(
        "PersistenceError",
        (error): Effect.Effect<never, UserAlreadyExists | PersistenceError> =>
          isUniqueViolation(error) ? Effect.fail(new UserAlreadyExists()) : Effect.fail(error)
      )
    )

    yield* publishSafely(events, {
      _tag: "UserCreated",
      userId: user.id,
      email: user.email,
      emailVerified: user.emailVerified,
      method: passwordMethod
    })

    if (config.emailPassword.requireEmailVerification) {
      yield* sendVerificationTo(user, options.callbackURL)
      return { user, session: Option.none() } satisfies SignUpResult
    }

    if (!config.emailPassword.autoSignIn) {
      return { user, session: Option.none() } satisfies SignUpResult
    }

    const created = yield* sessions.create({
      userId: user.id,
      ipAddress: options.ipAddress ?? null,
      userAgent: options.userAgent ?? null,
      rememberMe: options.rememberMe
    })
    yield* publishSafely(events, {
      _tag: "SignedIn",
      userId: user.id,
      sessionId: created.session.id,
      method: passwordMethod
    })
    return { user, session: Option.some(created) } satisfies SignUpResult
  })

  const signIn = Effect.fnUntraced(function*(options: SignInOptions) {
    const email = normalizeEmail(options.email)
    const found = yield* users.findByEmail(email)

    // The account lookup runs on both paths, against a userId that cannot
    // exist when the address is unknown. A branch here would make a known
    // address cost one more round trip than an unknown one — a smaller signal
    // than an unbalanced hash verify, but the same enumeration channel, and it
    // costs one indexed miss to close.
    const account = yield* credentialAccountFor(
      Option.isSome(found) ? found.value.id : absentUserId
    )
    const storedHash = Option.isSome(account) ? account.value.passwordHash : null

    // One verification runs on every path. When there is nothing real to check
    // it runs against the dummy hash, which was produced by this same hasher at
    // the same cost, so the two paths take the same time.
    const matches = yield* hasher.verify(options.password, storedHash ?? dummyHash)

    if (Option.isNone(found) || storedHash === null || !matches) {
      return yield* Effect.fail(new InvalidCredentials())
    }
    const user = found.value

    if (config.emailPassword.requireEmailVerification && !user.emailVerified) {
      return yield* Effect.fail(new EmailNotVerified())
    }

    const created = yield* sessions.create({
      userId: user.id,
      ipAddress: options.ipAddress ?? null,
      userAgent: options.userAgent ?? null,
      rememberMe: options.rememberMe
    })
    yield* publishSafely(events, {
      _tag: "SignedIn",
      userId: user.id,
      sessionId: created.session.id,
      method: passwordMethod
    })
    return { user, session: created.session, token: created.token } satisfies SignInResult
  })

  const requestReset = Effect.fnUntraced(function*(
    options: { readonly email: string; readonly redirectTo?: string | undefined }
  ) {
    const found = yield* users.findByEmail(normalizeEmail(options.email))
    if (Option.isNone(found)) {
      // No row, no mail, no event — and no observable difference.
      return
    }
    const user = found.value
    const now = yield* DateTime.now
    const token = yield* issue(
      passwordResetIdentifier(user.id),
      user.id,
      DateTime.addDuration(now, config.tokens.passwordResetTtl)
    )
    const url = withCallback(resetPasswordUrl(config, token), options.redirectTo)
    yield* Effect.ignore(
      emails.sendPasswordReset({ user, token, url }),
      { log: "Warn", message: "effect-auth: password reset e-mail delivery failed" }
    )
    yield* publishSafely(events, { _tag: "PasswordResetRequested", userId: user.id })
  })

  const resetPassword = Effect.fnUntraced(function*(
    options: { readonly token: Redacted.Redacted<string>; readonly newPassword: Redacted.Redacted<string> }
  ) {
    yield* checkPolicy(options.newPassword, config)
    const subject = yield* claim(options.token, (userId) => passwordResetIdentifier(userId as UserId))
    const userId = subject as UserId

    const found = yield* users.findById(userId)
    if (Option.isNone(found)) {
      return yield* Effect.fail(new InvalidToken())
    }

    const passwordHash = yield* hasher.hash(options.newPassword)

    // The hash update and the revocation commit together: a reset must never
    // leave a new password in place while an old session survives.
    const revoked = yield* transaction.run(Effect.gen(function*() {
      const updated = yield* accounts.updatePasswordHash(userId, passwordHash)
      if (Option.isNone(updated)) {
        // An OAuth-only user completing a reset gains a password credential.
        yield* createCredentialAccount(userId, passwordHash)
      }
      // Every *other* outstanding reset link for this user dies with the one
      // just used. Two "forgot password" clicks mint two independent tokens,
      // and somebody with a few minutes of mailbox access must not keep a
      // working key to an account whose owner has just re-secured it.
      yield* verifications.deleteByIdentifier(passwordResetIdentifier(userId))
      return yield* sessionStore.deleteByUserId(userId)
    }))

    yield* publishSafely(events, {
      _tag: "SessionRevoked",
      userId,
      sessionId: null,
      scope: "all",
      count: revoked
    })
    yield* publishSafely(events, { _tag: "PasswordChanged", userId, viaReset: true })
  })

  const changePassword = Effect.fnUntraced(function*(options: ChangePasswordOptions) {
    yield* checkPolicy(options.newPassword, config)

    const account = yield* credentialAccountFor(options.userId)
    const storedHash = Option.isSome(account) ? account.value.passwordHash : null
    const matches = yield* hasher.verify(options.currentPassword, storedHash ?? dummyHash)
    if (storedHash === null || !matches) {
      return yield* Effect.fail(new InvalidCredentials())
    }

    const passwordHash = yield* hasher.hash(options.newPassword)
    const updated = yield* accounts.updatePasswordHash(options.userId, passwordHash)
    if (Option.isNone(updated)) {
      // The credential account was removed between the verification above and
      // this write — a racing unlink or reset. Nothing changed, so nothing is
      // revoked and no `PasswordChanged` is published: the caller must present
      // the current password again, against whatever credential now exists.
      return yield* Effect.fail(new InvalidCredentials())
    }

    // Same reasoning as in `resetPassword`: a password that has just been
    // changed from inside a session must not still be resettable by a link
    // somebody asked for beforehand.
    yield* verifications.deleteByIdentifier(passwordResetIdentifier(options.userId))

    if (options.revokeOtherSessions !== false) {
      yield* options.currentSessionId === undefined
        ? sessions.revokeAll(options.userId)
        : sessions.revokeOthers(options.userId, options.currentSessionId)
    }

    yield* publishSafely(events, { _tag: "PasswordChanged", userId: options.userId, viaReset: false })
  })

  const sendVerificationEmail = Effect.fnUntraced(function*(
    options: { readonly email: string; readonly callbackURL?: string | undefined }
  ) {
    const found = yield* users.findByEmail(normalizeEmail(options.email))
    if (Option.isNone(found) || found.value.emailVerified) {
      return
    }
    yield* sendVerificationTo(found.value, options.callbackURL)
  })

  const verifyEmail = Effect.fnUntraced(function*(token: Redacted.Redacted<string>) {
    const email = yield* claim(token, emailVerifyIdentifier)

    const found = yield* users.findByEmail(normalizeEmail(email))
    if (Option.isNone(found)) {
      return yield* Effect.fail(new InvalidToken())
    }

    const updated = yield* users.update(found.value.id, { emailVerified: true })
    if (Option.isNone(updated)) {
      return yield* Effect.fail(new InvalidToken())
    }

    yield* publishSafely(events, {
      _tag: "EmailVerified",
      userId: updated.value.id,
      email: updated.value.email
    })
    return updated.value
  })

  return Passwords.of({
    signUp,
    signIn,
    requestReset,
    resetPassword,
    changePassword,
    sendVerificationEmail,
    verifyEmail
  })
})

/**
 * Provides {@link Passwords}.
 *
 * @category layers
 * @since 1.0.0
 */
export const layer: Layer.Layer<
  Passwords,
  never,
  | AuthConfig
  | AuthEmails
  | AuthEvents
  | PasswordHasher
  | Token
  | Sessions
  | UserStore
  | SessionStore
  | AccountStore
  | VerificationStore
  | WithAuthTransaction
> = Layer.effect(Passwords, make())
