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
import { Context, Effect, Layer, Option, Redacted } from "effect"
import { AuthConfig } from "../config/AuthConfig.js"
import type { AuthConfigService } from "../config/AuthConfig.js"
import { AuthEmails, resetPasswordUrl, verifyEmailUrl, withCallbackUrl } from "../config/AuthEmails.js"
import { PasswordHasher } from "../crypto/PasswordHasher.js"
import { annotateAuthLogs, insertRow } from "../internal/effects.js"
import { pickKeys } from "../internal/records.js"
import type { PasswordHashError } from "./Errors.js"
import {
  EmailNotVerified,
  InvalidCredentials,
  InvalidToken,
  PasswordAlreadySet,
  PasswordPolicyViolation,
  UserAlreadyExists
} from "./Errors.js"
import { AuthEvents, passwordMethod, publishSafely } from "./Events.js"
import type {
  Session,
  SessionId,
  UserExtras,
  UserFields,
  UserId,
  UserModel,
  UserOf
} from "./Schema.js"
import { Account, baseUserModel, CredentialIssuer, normalizeEmail } from "./Schema.js"
import type { CreatedSession } from "./Sessions.js"
import { Sessions } from "./Sessions.js"
import type { PersistenceError } from "./Stores.js"
import {
  AccountStore,
  isUniqueViolation,
  SessionStore,
  UserStore,
  userStoreOf,
  WithAuthTransaction
} from "./Stores.js"
// The list of user-subject purposes is declared beside the flows that mint most
// of them; nothing is read from it before a request runs.
import { emailVerifyPurpose, passwordResetPurpose, userSubjectPurposes, Verifications } from "./Verifications.js"

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
 * What {@link Passwords} needs to register a user, before a deployment's own
 * fields are added to it.
 *
 * @category models
 * @since 1.0.0
 */
export interface BaseSignUpOptions {
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
 * What {@link Passwords} needs to register a user.
 *
 * **Details**
 *
 * The custom half comes straight off the model's `jsonCreate` variant, so a
 * field declared with `UserField.withDefault` is optional here, and one declared
 * `readOnly` or `hidden` cannot be passed at all.
 *
 * @category models
 * @since 1.0.0
 */
export type SignUpOptions<F extends UserFields = {}> = BaseSignUpOptions & UserExtras<F, "jsonCreate">

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
export interface SignUpResult<F extends UserFields = {}> {
  readonly user: UserOf<F>
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
export interface SignInResult<F extends UserFields = {}> {
  readonly user: UserOf<F>
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

/**
 * What {@link PasswordsService.setPassword} needs to give a user their first
 * password.
 *
 * @category models
 * @since 1.0.0
 */
export interface SetPasswordOptions {
  readonly userId: UserId
  readonly newPassword: Redacted.Redacted<string>
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
export interface PasswordsService<F extends UserFields = {}> {
  /**
   * Registers a user and their `local:credential` account in one transaction,
   * then — outside it — emits `UserCreated`, sends the verification mail if the
   * configuration asks for one, and establishes a session if it allows one.
   */
  readonly signUp: (
    options: SignUpOptions<F>
  ) => Effect.Effect<
    SignUpResult<F>,
    UserAlreadyExists | PasswordPolicyViolation | PasswordHashError | PersistenceError
  >

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
  ) => Effect.Effect<SignInResult<F>, InvalidCredentials | EmailNotVerified | PasswordHashError | PersistenceError>

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
   * the hash update. Every link outstanding for the same user is deleted in
   * that transaction too — not merely the other reset tokens, but the
   * change-email and delete-account ones as well: any of them would otherwise
   * let the account be taken straight back out of the hands of somebody who has
   * just re-secured it.
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
   * Whether a password matches the user's stored credential.
   *
   * **Details**
   *
   * Exactly one hash verification runs, whether or not the user has a credential
   * — against {@link dummyPassword}'s hash when they do not — so "no password
   * set" and "wrong password" take the same time and are the same answer,
   * `false`.
   *
   * **When to use**
   *
   * As a re-authentication check inside an already-authenticated flow: deleting
   * an account, for instance. It answers a boolean rather than failing, because
   * the caller decides what a mismatch means for its own operation.
   */
  readonly verifyPassword: (
    userId: UserId,
    password: Redacted.Redacted<string>
  ) => Effect.Effect<boolean, PasswordHashError | PersistenceError>

  /**
   * Gives a user their **first** password.
   *
   * **Details**
   *
   * A user provisioned through OAuth alone has no `local:credential` account;
   * this creates one, so they can sign in with an address and password as well.
   * A user whose credential row exists but carries no hash — nothing this
   * library writes, but a migration might — has it filled in.
   *
   * **Gotchas**
   *
   * It can never *replace* a password: a user who already has one gets
   * `PasswordAlreadySet`, and so does the loser of a race between two concurrent
   * calls, which the unique index settles. Changing a known password is
   * `changePassword` and replacing a forgotten one is the reset flow — both of
   * them prove something this endpoint cannot.
   *
   * Nothing is revoked: no existing credential was invalidated, so no session
   * was.
   *
   * Emits `AccountLinked` for the credential account.
   */
  readonly setPassword: (
    options: SetPasswordOptions
  ) => Effect.Effect<
    void,
    PasswordAlreadySet | PasswordPolicyViolation | PasswordHashError | PersistenceError
  >

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
  ) => Effect.Effect<UserOf<F>, InvalidToken | PersistenceError>
}

/**
 * E-mail and password authentication.
 *
 * @category services
 * @since 1.0.0
 */
export class Passwords extends Context.Service<Passwords, PasswordsService>()("effect-auth/Passwords") {}

/**
 * {@link Passwords}, seen through a model's custom fields.
 *
 * The same key with a narrower shape: the three methods that answer with a user
 * answer with the deployment's own. See `userStoreOf` in `domain/Stores.ts` for
 * what a typed view is and why it is sound.
 *
 * @category services
 * @since 1.0.0
 */
export const passwordsOf = <F extends UserFields>(
  _model: UserModel<F>
): Context.Service<Passwords, PasswordsService<F>> =>
  Context.Service<Passwords, PasswordsService<F>>("effect-auth/Passwords")

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
 * `model` is what makes a deployment's own user columns part of sign-up: the
 * custom half of `SignUpOptions` comes off its `jsonCreate` variant, and the row
 * is built through the model so anything the caller left out is defaulted.
 *
 * @category constructors
 * @since 1.0.0
 */
export const make: <F extends UserFields>(model: UserModel<F>) => Effect.Effect<
  PasswordsService<F>,
  never,
  | AuthConfig
  | AuthEmails
  | AuthEvents
  | PasswordHasher
  | Verifications
  | Sessions
  | UserStore
  | SessionStore
  | AccountStore
  | WithAuthTransaction
> = Effect.fnUntraced(function*<F extends UserFields>(model: UserModel<F>) {
  const config = yield* AuthConfig
  const hasher = yield* PasswordHasher
  const users = yield* userStoreOf(model)
  const accounts = yield* AccountStore
  const sessionStore = yield* SessionStore
  const verifications = yield* Verifications
  const transaction = yield* WithAuthTransaction
  const emails = yield* AuthEmails
  const sessions = yield* Sessions
  const events = yield* AuthEvents

  const dummyHash = yield* Effect.orDie(hasher.hash(Redacted.make(dummyPassword)))

  const sendVerificationTo = Effect.fnUntraced(function*(
    user: UserOf<F>,
    callbackURL: string | undefined
  ) {
    const issued = yield* verifications.issue({
      purpose: emailVerifyPurpose,
      subject: normalizeEmail(user.email),
      ttl: config.tokens.emailVerificationTtl,
      payload: null
    })
    const url = withCallbackUrl(config, verifyEmailUrl(config, issued.token), callbackURL)
    // Delivery is the application's responsibility and its failure must not
    // change what the caller observes; it is logged and dropped.
    yield* annotateAuthLogs(Effect.ignore(
      emails.sendVerification({ user, token: issued.token, url }),
      { log: "Warn", message: "verification e-mail delivery failed" }
    ))
  })

  const credentialAccountFor = (userId: UserId) => accounts.findByIssuerAccountId(CredentialIssuer, userId)

  const createCredentialAccount = Effect.fnUntraced(function*(userId: UserId, passwordHash: string) {
    const row = yield* insertRow(Account.insert, {
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
    })
    return yield* accounts.create(row)
  })

  // ---------------------------------------------------------------------------

  const signUp = Effect.fnUntraced(function*(options: SignUpOptions<F>) {
    yield* checkPolicy(options.password, config)
    const email = normalizeEmail(options.email)

    const existing = yield* users.findByEmail(email)
    if (Option.isSome(existing)) {
      return yield* Effect.fail(new UserAlreadyExists())
    }

    const passwordHash = yield* hasher.hash(options.password)

    const user = yield* transaction.run(Effect.gen(function*() {
      // Whatever the model declares beyond the base fields comes off the
      // payload by name; anything the caller did not state is defaulted by the
      // model itself.
      const row = yield* model.makeInsert({
        name: options.name,
        email,
        emailVerified: false,
        image: options.image ?? null,
        ...pickKeys(options, model.extraKeys)
      })
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
      return { user, session: Option.none() } satisfies SignUpResult<F>
    }

    if (!config.emailPassword.autoSignIn) {
      return { user, session: Option.none() } satisfies SignUpResult<F>
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
    return { user, session: Option.some(created) } satisfies SignUpResult<F>
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
    return { user, session: created.session, token: created.token } satisfies SignInResult<F>
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
    const issued = yield* verifications.issue({
      purpose: passwordResetPurpose,
      subject: user.id,
      ttl: config.tokens.passwordResetTtl,
      payload: null
    })
    const url = withCallbackUrl(config, resetPasswordUrl(config, issued.token), options.redirectTo)
    yield* annotateAuthLogs(Effect.ignore(
      emails.sendPasswordReset({ user, token: issued.token, url }),
      { log: "Warn", message: "password reset e-mail delivery failed" }
    ))
    yield* publishSafely(events, { _tag: "PasswordResetRequested", userId: user.id })
  })

  const resetPassword = Effect.fnUntraced(function*(
    options: { readonly token: Redacted.Redacted<string>; readonly newPassword: Redacted.Redacted<string> }
  ) {
    yield* checkPolicy(options.newPassword, config)
    const claimed = yield* verifications.claim(passwordResetPurpose, options.token)
    const userId = claimed.subject as UserId

    yield* Effect.fromOption(yield* users.findById(userId), () => new InvalidToken())

    const passwordHash = yield* hasher.hash(options.newPassword)

    // The hash update and the revocation commit together: a reset must never
    // leave a new password in place while an old session survives.
    const revoked = yield* transaction.run(Effect.gen(function*() {
      const updated = yield* accounts.updatePasswordHash(userId, passwordHash)
      if (Option.isNone(updated)) {
        // An OAuth-only user completing a reset gains a password credential.
        yield* createCredentialAccount(userId, passwordHash)
      }
      // Every *other* outstanding link this user is the subject of dies with
      // the one just used, not merely the other reset links. Two "forgot
      // password" clicks mint two independent tokens, and somebody with a few
      // minutes of mailbox access must not keep a working key to an account
      // whose owner has just re-secured it — and a `change-email-verify` token
      // is the strongest such key there is, because following it moves the
      // account to the address that asked for it. On an account whose address
      // was never verified, one of those may well be outstanding: the flow
      // skips its first hop there, so whoever registered the address could
      // have aimed the account at a mailbox of their own.
      for (const kind of userSubjectPurposes) {
        yield* verifications.retire(kind, userId)
      }
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

  const verifyPassword = Effect.fnUntraced(function*(
    userId: UserId,
    password: Redacted.Redacted<string>
  ) {
    const account = yield* credentialAccountFor(userId)
    const storedHash = Option.isSome(account) ? account.value.passwordHash : null
    // One verification, always. A user with no credential is checked against the
    // dummy hash — produced by this hasher at this cost — so "no password set"
    // and "wrong password" take the same time as well as answering the same.
    const matches = yield* hasher.verify(password, storedHash ?? dummyHash)
    return storedHash !== null && matches
  })

  const setPassword = Effect.fnUntraced(function*(options: SetPasswordOptions) {
    yield* checkPolicy(options.newPassword, config)

    const existing = yield* credentialAccountFor(options.userId)
    if (Option.isSome(existing) && existing.value.passwordHash !== null) {
      return yield* Effect.fail(new PasswordAlreadySet())
    }

    const passwordHash = yield* hasher.hash(options.newPassword)

    // Two fibres can both pass the check above. Only one insert survives the
    // unique index on `(issuer, account_id)`, and the loser is told the same
    // thing the check would have told it.
    const created = createCredentialAccount(options.userId, passwordHash).pipe(
      Effect.catchTag(
        "PersistenceError",
        (error): Effect.Effect<Account, PasswordAlreadySet | PersistenceError> =>
          isUniqueViolation(error) ? Effect.fail(new PasswordAlreadySet()) : Effect.fail(error)
      )
    )

    const account = Option.isNone(existing)
      ? yield* created
      // A credential row with no hash — nothing this library writes, but a
      // migration from another system might. `None` means it was removed
      // between the read and the write, which leaves the create as the answer.
      : yield* Effect.flatMap(
        accounts.updatePasswordHash(options.userId, passwordHash),
        Option.match({ onNone: () => created, onSome: Effect.succeed })
      )

    yield* publishSafely(events, {
      _tag: "AccountLinked",
      userId: options.userId,
      accountId: account.id,
      providerId: account.providerId,
      issuer: account.issuer
    })
  })

  const changePassword = Effect.fnUntraced(function*(options: ChangePasswordOptions) {
    yield* checkPolicy(options.newPassword, config)

    if (!(yield* verifyPassword(options.userId, options.currentPassword))) {
      return yield* Effect.fail(new InvalidCredentials())
    }

    const passwordHash = yield* hasher.hash(options.newPassword)
    // A `None` here means the credential account was removed between the
    // verification above and this write — a racing unlink or reset. Nothing
    // changed, so nothing is revoked and no `PasswordChanged` is published: the
    // caller must present the current password again, against whatever
    // credential now exists.
    const updated = yield* accounts.updatePasswordHash(options.userId, passwordHash)
    yield* Effect.fromOption(updated, () => new InvalidCredentials())

    // Same reasoning as in `resetPassword`: a password that has just been
    // changed from inside a session is a re-securing of the account, so every
    // outstanding link whose subject is this user goes with it — a reset link
    // somebody asked for beforehand, and just as much a `change-email-verify`
    // link that would move the account to an address they chose.
    for (const kind of userSubjectPurposes) {
      yield* verifications.retire(kind, options.userId)
    }

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
    const claimed = yield* verifications.claim(emailVerifyPurpose, token)

    const found = yield* users.findByEmail(normalizeEmail(claimed.subject))
    const user = yield* Effect.fromOption(found, () => new InvalidToken())

    const updated = yield* users.update(user.id, model.basePatch({ emailVerified: true }))
    // The user was deleted between the two reads: the token is spent and there
    // is nothing to verify.
    const verified = yield* Effect.fromOption(updated, () => new InvalidToken())

    yield* publishSafely(events, {
      _tag: "EmailVerified",
      userId: verified.id,
      email: verified.email
    })
    return verified
  })

  return passwordsOf(model).of({
    signUp,
    signIn,
    requestReset,
    resetPassword,
    changePassword,
    verifyPassword,
    setPassword,
    sendVerificationEmail,
    verifyEmail
  })
})

/**
 * Provides {@link Passwords} for the user model given: sign-up takes that
 * model's custom fields and every method that answers with a user answers with
 * its own, while the layer's type stays the base one.
 *
 * @category layers
 * @since 1.0.0
 */
export const layerFor = <F extends UserFields>(
  model: UserModel<F>
): Layer.Layer<
  Passwords,
  never,
  | AuthConfig
  | AuthEmails
  | AuthEvents
  | PasswordHasher
  | Verifications
  | Sessions
  | UserStore
  | SessionStore
  | AccountStore
  | WithAuthTransaction
> => Layer.effect(passwordsOf(model), make(model))

/**
 * {@link layerFor}, for a deployment that added no user fields of its own.
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
  | Verifications
  | Sessions
  | UserStore
  | SessionStore
  | AccountStore
  | WithAuthTransaction
> = layerFor(baseUserModel)
