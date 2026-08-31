/**
 * What a signed-in person may do to their own user record: edit the profile,
 * move the account to another e-mail address, and delete it.
 *
 * **Details**
 *
 * Three flows, and two of them are deliberately not one-shot.
 *
 * *Changing an address is two hops.* A session alone must not be enough to walk
 * off with somebody's account, and an address is the account's recovery path —
 * whoever receives its mail can reset its password. So the first hop tells the
 * address the account has **now** that a move has been requested, and only when
 * that link is followed is a second one sent to the **new** address; following
 * *that* is what changes the column. The proposed address never appears in a
 * URL: it travels in the token's server-side payload, so a link cannot be edited
 * into a link that moves the account somewhere else. An account whose current
 * address is unverified has no first hop — an unverified address is no evidence
 * that anybody reads it — and starts at the second.
 *
 * *Deleting is either fresh or confirmed.* With `user.deleteUser.confirmByEmail`
 * off, the caller's session has to be fresh and the row goes immediately; with it
 * on, a link is mailed and the deletion happens when that link is followed. Both
 * shapes exist because the right one depends on what losing the account costs.
 *
 * **Gotchas — enumeration**
 *
 * `requestEmailChange` answers the same whether or not the new address already
 * belongs to somebody: the lookup runs on every path, `"Ignored"` is reported to
 * the endpoint above exactly as the other two outcomes are, and that endpoint
 * answers `200` regardless. A distinguishable answer would turn a signed-in
 * session into an oracle for "is this person registered here". The collision is
 * caught at the *second* hop instead, by the unique index, and reported as
 * `UserAlreadyExists` to somebody who has by then proven they control the
 * address.
 *
 * The response is not the only thing a caller can watch, though: the caller owns
 * the mailbox hop one is sent to. So a verified current address is mailed the
 * confirmation **whether or not the new address is free** — an attacker who
 * asks to move to somebody else's address sees exactly what they see when they
 * ask to move to a free one — and the address is re-checked when that link is
 * followed, where a taken one silently sends no second hop. Nothing is ever
 * mailed to the *new* address until its own hop, so a third party's mailbox
 * tells the attacker nothing either.
 *
 * What is *not* identical is the latency, on the one branch where the two paths
 * still differ: an account whose current address is unverified has no first hop,
 * so a free address mints a token, writes a row and awaits the mailer where a
 * taken one returns after the lookup. Nothing arrives anywhere the caller can
 * see in either case, which leaves timing — the same residual channel
 * `Passwords.requestReset` documents, and it closes the same way, with an
 * `AuthEmails` implementation that enqueues and returns.
 *
 * @since 1.0.0
 */
import { Context, Effect, Layer, Option, Redacted } from "effect"
import { AuthConfig } from "../config/AuthConfig.js"
import {
  AuthEmails,
  changeEmailConfirmUrl,
  changeEmailVerifyUrl,
  deleteAccountUrl,
  withCallbackUrl
} from "../config/AuthEmails.js"
import { resolveUrl, validateUrl } from "../http/OriginCheck.js"
import { annotateAuthLogs } from "../internal/effects.js"
import { omitUndefined, pickKeys } from "../internal/records.js"
import type { SessionNotFresh } from "./Errors.js"
import { EmailUnchanged, InvalidCredentials, InvalidToken, UserAlreadyExists, UserNotFound } from "./Errors.js"
import type { UpdatedUserField } from "./Events.js"
import { AuthEvents, publishSafely } from "./Events.js"
import { Passwords } from "./Passwords.js"
import type { Session, UserExtras, UserFields, UserId, UserModel, UserOf } from "./Schema.js"
import { baseUserModel, normalizeEmail } from "./Schema.js"
import { Sessions } from "./Sessions.js"
import type { PersistenceError } from "./Stores.js"
import { isUniqueViolation, UserStore, userStoreOf, VerificationStore, WithAuthTransaction } from "./Stores.js"
import {
  changeEmailConfirmPurpose,
  changeEmailVerifyPurpose,
  deleteAccountPurpose,
  emailVerifyPurpose,
  userSubjectPurposes,
  Verifications
} from "./Verifications.js"

// The change-email and delete-account purposes are defined beside the other
// token purposes in `Verifications.ts` (so `Passwords` can retire them without
// importing this module) and re-exported here, where their flows live.
export {
  ChangeEmailPayload,
  changeEmailConfirmPurpose,
  changeEmailVerifyPurpose,
  DeleteAccountPayload,
  deleteAccountPurpose,
  userSubjectPurposes
} from "./Verifications.js"

// -----------------------------------------------------------------------------
// Models
// -----------------------------------------------------------------------------

/**
 * The base half of {@link UpdateOptions}: who is being updated, and the two
 * mutable fields every user has.
 *
 * **Gotchas**
 *
 * An absent key is a column the update does not touch; `image: null` clears it.
 * The distinction is why these are `| undefined` rather than merely optional.
 *
 * @category models
 * @since 1.0.0
 */
export interface BaseUpdateOptions {
  readonly userId: UserId
  readonly name?: string | undefined
  readonly image?: string | null | undefined
}

/**
 * What {@link UsersService.update} takes: the base fields, plus whichever of the
 * deployment's own the caller stated.
 *
 * **Details**
 *
 * The custom half comes straight off the model's `jsonUpdate` variant, so a
 * field declared `readOnly` or `hidden` cannot be passed at all — the same rule
 * `SignUpOptions` follows for creation.
 *
 * @category models
 * @since 1.0.0
 */
export type UpdateOptions<F extends UserFields = {}> = BaseUpdateOptions & UserExtras<F, "jsonUpdate">

/**
 * What {@link UsersService.requestEmailChange} takes.
 *
 * @category models
 * @since 1.0.0
 */
export interface RequestEmailChangeOptions<F extends UserFields = {}> {
  /** The signed-in user, as the middleware resolved them. */
  readonly user: UserOf<F>
  /** The address they have asked to move to. Normalized here, not by the caller. */
  readonly newEmail: string
  /**
   * Where the link should land once the change completes. Validated against
   * `trustedOrigins` again here, and dropped rather than refused if it does not
   * survive that.
   */
  readonly callbackURL?: string | undefined
}

/**
 * What asking for an e-mail change did.
 *
 * **Gotchas**
 *
 * Every member is reported to the caller as the same `200`. The distinction is
 * for logs and for a domain-level caller — not for an HTTP response, which would
 * make it an enumeration oracle. See the module header.
 *
 * @category models
 * @since 1.0.0
 */
export type EmailChangeOutcome =
  /** The current address is verified, so hop one was mailed to it. */
  | "ConfirmationSent"
  /** The current address is unverified, so the flow started at hop two. */
  | "VerificationSent"
  /**
   * The new address already belongs to somebody, so the change will go no
   * further.
   *
   * **Gotchas**
   *
   * Hop one was still mailed where there was one to mail — a verified current
   * address gets the same message it gets for a free address, because the
   * caller's own mailbox must not tell them which it was. Nothing was sent to
   * the new address, and following that first hop does nothing.
   */
  | "Ignored"

/**
 * What {@link UsersService.requestDeletion} takes.
 *
 * @category models
 * @since 1.0.0
 */
export interface RequestDeletionOptions<F extends UserFields = {}> {
  readonly user: UserOf<F>
  /** The session making the request — the freshness guard's subject. */
  readonly session: Session
  /**
   * The caller's current password, where they have one.
   *
   * **Details**
   *
   * Verified in constant work when present: exactly one hash comparison runs,
   * against a dummy hash for a user with no credential, so "you have no
   * password" and "that is the wrong password" cost the same and answer the
   * same.
   */
  readonly password?: Redacted.Redacted<string> | undefined
  /** Where to send the browser after the deletion completes. */
  readonly callbackURL?: string | undefined
}

/**
 * What asking to delete an account did.
 *
 * @category models
 * @since 1.0.0
 */
export type DeletionOutcome =
  /** The row is gone, and every session with it. */
  | "Deleted"
  /** A confirmation link was mailed; nothing has been deleted yet. */
  | "ConfirmationSent"

/**
 * What {@link UsersService.confirmDeletion} takes.
 *
 * @category models
 * @since 1.0.0
 */
export interface ConfirmDeletionOptions {
  /** The token from the link. */
  readonly token: Redacted.Redacted<string>
  /**
   * The user the *session* presenting the link belongs to.
   *
   * **Gotchas**
   *
   * The token is claimed before this is compared, so a link presented by the
   * wrong person is burnt as well as refused. Leaving it claimable would let
   * somebody who has read another person's mailbox park the link until they
   * could get a session.
   */
  readonly userId: UserId
}

/**
 * Where a completed deletion sends the browser.
 *
 * @category models
 * @since 1.0.0
 */
export interface DeletionResult {
  /** The validated URL, already resolved against `trustedOrigins`. */
  readonly redirectTo: string
}

// -----------------------------------------------------------------------------
// Service
// -----------------------------------------------------------------------------

/**
 * The {@link Users} service definition, for a model parameterized by `F`.
 *
 * @category models
 * @since 1.0.0
 */
export interface UsersService<F extends UserFields = {}> {
  /**
   * Applies a profile update and answers the stored row.
   *
   * **Details**
   *
   * `UserNotFound` means the row vanished between the middleware resolving the
   * session and this write — a concurrent deletion, not a caller mistake.
   *
   * Emits `UserUpdated` naming the base fields that actually changed.
   */
  readonly update: (
    options: UpdateOptions<F>
  ) => Effect.Effect<UserOf<F>, UserNotFound | PersistenceError>

  /**
   * Starts an e-mail change. See the module header for the two hops.
   *
   * **Gotchas**
   *
   * Fails `EmailUnchanged` when the address is the one the account already has,
   * which is the only refusal this step makes out loud — the caller already
   * knows their own address, so saying so leaks nothing.
   */
  readonly requestEmailChange: (
    options: RequestEmailChangeOptions<F>
  ) => Effect.Effect<EmailChangeOutcome, EmailUnchanged | PersistenceError>

  /**
   * Claims a first-hop token and mails the second hop to the new address.
   *
   * Nothing about the account has changed when this succeeds.
   */
  readonly confirmEmailChange: (
    token: Redacted.Redacted<string>
  ) => Effect.Effect<void, InvalidToken | PersistenceError>

  /**
   * Claims a second-hop token and moves the account to the new address, which
   * ends up **verified** — the token that got here was delivered to it.
   *
   * **Details**
   *
   * The write and the retirement of every sibling token commit together. A
   * collision on the unique index is `UserAlreadyExists`: somebody else claimed
   * the address between hop one and hop two.
   *
   * Emits `EmailChanged`.
   */
  readonly verifyEmailChange: (
    token: Redacted.Redacted<string>
  ) => Effect.Effect<UserOf<F>, InvalidToken | UserAlreadyExists | PersistenceError>

  /**
   * Deletes the account, or mails a link that will.
   *
   * **Details**
   *
   * With `confirmByEmail` off this requires a fresh session and deletes
   * immediately; with it on it mints a `delete-account` token and mails it, and
   * the session's age does not matter because the mailbox is the second factor.
   */
  readonly requestDeletion: (
    options: RequestDeletionOptions<F>
  ) => Effect.Effect<DeletionOutcome, InvalidCredentials | SessionNotFresh | PersistenceError>

  /**
   * Claims a deletion token presented by a signed-in caller and deletes the
   * account.
   */
  readonly confirmDeletion: (
    options: ConfirmDeletionOptions
  ) => Effect.Effect<DeletionResult, InvalidToken | PersistenceError>

  /**
   * Deletes a user outright — no token, no freshness check.
   *
   * **When to use**
   *
   * From an application's own administrative code. Sessions and accounts cascade
   * with the row, and this user's outstanding verification tokens are retired
   * with it. Emits `UserDeleted` after the row has gone.
   */
  readonly delete: (user: UserOf<F>) => Effect.Effect<void, PersistenceError>
}

/**
 * What a signed-in person may do to their own user record. See
 * {@link UsersService}.
 *
 * @category services
 * @since 1.0.0
 */
export class Users extends Context.Service<Users, UsersService>()("effect-auth/Users") {}

/**
 * {@link Users}, seen through a model's custom fields.
 *
 * The same key with a narrower shape: the methods that take or answer with a
 * user carry the deployment's own. See `userStoreOf` in `domain/Stores.ts` for
 * what a typed view is and why it is sound.
 *
 * @category services
 * @since 1.0.0
 */
export const usersOf = <F extends UserFields>(
  _model: UserModel<F>
): Context.Service<Users, UsersService<F>> => Context.Service<Users, UsersService<F>>("effect-auth/Users")

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

/**
 * What {@link make} needs.
 *
 * @category models
 * @since 1.0.0
 */
export type Requirements =
  | AuthConfig
  | AuthEmails
  | AuthEvents
  | Verifications
  | UserStore
  | VerificationStore
  | WithAuthTransaction
  | Sessions
  | Passwords

/**
 * Builds the {@link Users} implementation for a user model.
 *
 * **Gotchas**
 *
 * Every service is resolved here, when the layer is built, so that no method
 * carries a request-time requirement — the same shape `Passwords.make` has, and
 * for the same reason.
 *
 * `VerificationStore` is in {@link Requirements} without being resolved here:
 * every row this module writes or retires goes through `Verifications`, which is
 * the service that owns the store. It stays in the requirement so that the
 * declared shape of the layer does not depend on which side of that seam a given
 * method happens to sit on.
 *
 * @category constructors
 * @since 1.0.0
 */
export const make: <F extends UserFields>(
  model: UserModel<F>
) => Effect.Effect<UsersService<F>, never, Requirements> = Effect.fnUntraced(function*<F extends UserFields>(
  model: UserModel<F>
) {
  const config = yield* AuthConfig
  const emails = yield* AuthEmails
  const events = yield* AuthEvents
  const verifications = yield* Verifications
  const users = yield* userStoreOf(model)
  const transaction = yield* WithAuthTransaction
  const sessions = yield* Sessions
  const passwords = yield* Passwords

  /**
   * Hands a message to the seam and forgets whatever it says.
   *
   * Delivery is the application's responsibility and its failure must not change
   * what the caller observes — least of all on the change-email path, where a
   * distinguishable answer would be the enumeration oracle the whole flow is
   * shaped to avoid.
   */
  const deliver = <E>(email: Effect.Effect<void, E>, message: string): Effect.Effect<void> =>
    annotateAuthLogs(Effect.ignore(email, { log: "Warn", message }))

  /**
   * The second hop: a token minted for the new address and mailed to it.
   *
   * Any hop-two token already outstanding for this user is retired first, so a
   * person who asks twice has exactly one live link — the latest one. Two of
   * them would be two addresses the account could still be moved to.
   */
  const sendVerificationHop = Effect.fnUntraced(function*(
    user: UserOf<F>,
    newEmail: string,
    callbackURL: string | undefined
  ) {
    yield* verifications.retire(changeEmailVerifyPurpose, user.id)
    const issued = yield* verifications.issue({
      purpose: changeEmailVerifyPurpose,
      subject: user.id,
      ttl: config.tokens.changeEmailTtl,
      payload: { newEmail }
    })
    yield* deliver(
      emails.sendChangeEmailVerification({
        user,
        newEmail,
        token: issued.token,
        url: withCallbackUrl(config, changeEmailVerifyUrl(config, issued.token), callbackURL)
      }),
      "change-email verification e-mail delivery failed"
    )
  })

  /**
   * Deletes the row and everything that outlives it. The retirements share the
   * delete's transaction: a token that survived a rolled-back deletion would be
   * a live link to an account whose owner believes it is gone.
   */
  const deleteUser = Effect.fnUntraced(function*(user: UserOf<F>) {
    yield* transaction.run(Effect.gen(function*() {
      yield* users.delete(user.id)
      for (const kind of userSubjectPurposes) {
        yield* verifications.retire(kind, user.id)
      }
      // The one purpose keyed by the address rather than by the id.
      yield* verifications.retire(emailVerifyPurpose, normalizeEmail(user.email))
    }))
    yield* publishSafely(events, { _tag: "UserDeleted", userId: user.id, email: user.email })
  })

  // ---------------------------------------------------------------------------

  const update = Effect.fnUntraced(function*(options: UpdateOptions<F>) {
    const found = yield* users.findById(options.userId)
    const current = yield* Effect.fromOption(found, () => new UserNotFound())

    // An absent key is a column the statement does not touch, so the two
    // `undefined`s are dropped before anything else looks at them.
    const base = omitUndefined({ name: options.name, image: options.image })
    const fields: Array<UpdatedUserField> = []
    if (base.name !== undefined && base.name !== current.name) fields.push("name")
    if (Object.hasOwn(base, "image") && base.image !== current.image) fields.push("image")

    // The custom half arrives in the model's `jsonUpdate` shape and the store
    // takes its `update` shape. Only the model knows the two are the same
    // columns, so the mapping is here rather than at the caller: `basePatch`
    // states the base half's type and the extras are laid over it by name.
    const patch = Object.assign(model.basePatch(base), pickKeys(options, model.extraKeys))

    const written = yield* users.update(options.userId, patch)
    // The row went between the read above and this write — a concurrent
    // deletion, not a caller mistake.
    const updated = yield* Effect.fromOption(written, () => new UserNotFound())

    yield* publishSafely(events, { _tag: "UserUpdated", userId: updated.id, fields })
    return updated
  })

  const requestEmailChange = Effect.fnUntraced(function*(options: RequestEmailChangeOptions<F>) {
    const user = options.user
    const newEmail = normalizeEmail(options.newEmail)
    if (newEmail === normalizeEmail(user.email)) {
      // The one refusal this step makes out loud: the caller already knows
      // their own address, so saying so tells them nothing they did not have.
      return yield* Effect.fail(new EmailUnchanged())
    }

    const taken = Option.isSome(yield* users.findByEmail(newEmail))
    if (taken) {
      // The address is deliberately absent from the log line: it is somebody
      // else's, and this line is not the place to record that it is registered
      // here.
      yield* annotateAuthLogs(
        Effect.logInfo("an e-mail change will go no further: the requested address is already in use")
      )
    }

    if (!user.emailVerified) {
      // An unverified address is no evidence that anybody reads it, so there is
      // nobody to warn: the flow starts at the second hop — which is also the
      // only mailbox anything would arrive in, and it is not the caller's. A
      // taken address therefore stops here without an observable difference.
      if (taken) return "Ignored" as const
      yield* sendVerificationHop(user, newEmail, options.callbackURL)
      return "VerificationSent" as const
    }

    // Hop one goes out whether or not the address is free. The caller owns this
    // mailbox, so a message that arrived only for a free address would tell
    // them exactly what the 200 refuses to: whether somebody is registered
    // here. Following it is where the collision is noticed instead.
    //
    // As with the second hop, asking twice replaces the request rather than
    // adding to it.
    yield* verifications.retire(changeEmailConfirmPurpose, user.id)
    const issued = yield* verifications.issue({
      purpose: changeEmailConfirmPurpose,
      subject: user.id,
      ttl: config.tokens.changeEmailTtl,
      payload: { newEmail }
    })
    yield* deliver(
      emails.sendChangeEmailConfirmation({
        user,
        newEmail,
        token: issued.token,
        url: withCallbackUrl(config, changeEmailConfirmUrl(config, issued.token), options.callbackURL)
      }),
      "change-email confirmation e-mail delivery failed"
    )
    return taken ? "Ignored" as const : "ConfirmationSent" as const
  })

  const confirmEmailChange = Effect.fnUntraced(function*(token: Redacted.Redacted<string>) {
    const claimed = yield* verifications.claim(changeEmailConfirmPurpose, token)
    const userId = claimed.subject as UserId

    const found = yield* users.findById(userId)
    // The account went while the link sat in a mailbox. The token is spent and
    // there is nothing to confirm.
    const user = yield* Effect.fromOption(found, () => new InvalidToken())

    const newEmail = normalizeEmail(claimed.payload.newEmail)
    if (Option.isSome(yield* users.findByEmail(newEmail))) {
      // Hop one is mailed for a taken address too — see the module header — and
      // this is where that stops: no second hop is sent, so nothing ever
      // reaches a mailbox that is not the caller's, and the answer is the same
      // `Ok` a free address gets. Somebody who took the address between the two
      // hops lands here as well, and the unique index at hop two is the
      // backstop for the race the read cannot close.
      yield* annotateAuthLogs(
        Effect.logInfo("an e-mail change stopped at the first hop: the requested address is already in use")
      )
      return
    }

    // The landing page the first hop was asked for does not survive into the
    // second: the payload carries the address and nothing else, and widening it
    // would put a caller-supplied URL into a row that is read back on an
    // unauthenticated path.
    yield* sendVerificationHop(user, newEmail, undefined)
  })

  const verifyEmailChange = Effect.fnUntraced(function*(token: Redacted.Redacted<string>) {
    const claimed = yield* verifications.claim(changeEmailVerifyPurpose, token)
    const userId = claimed.subject as UserId
    const newEmail = normalizeEmail(claimed.payload.newEmail)

    const found = yield* users.findById(userId)
    const user = yield* Effect.fromOption(found, () => new InvalidToken())
    const previousEmail = user.email

    const updated = yield* transaction.run(Effect.gen(function*() {
      // The address ends up verified: the link that got here was delivered to
      // it, which is the whole of what verification means.
      const written = yield* users.update(userId, model.basePatch({ email: newEmail, emailVerified: true }))
      const stored = yield* Effect.fromOption(written, () => new InvalidToken())
      // Every other link that could move this account dies with the one just
      // used — including a first hop somebody asked for in the meantime.
      for (const kind of [changeEmailConfirmPurpose, changeEmailVerifyPurpose]) {
        yield* verifications.retire(kind, userId)
      }
      return stored
    })).pipe(
      // Somebody claimed the address between the two hops. The unique index is
      // what settles it, so there is no check-then-act window to lose.
      Effect.catchTag(
        "PersistenceError",
        (error): Effect.Effect<never, UserAlreadyExists | PersistenceError> =>
          isUniqueViolation(error) ? Effect.fail(new UserAlreadyExists()) : Effect.fail(error)
      )
    )

    yield* publishSafely(events, {
      _tag: "EmailChanged",
      userId: updated.id,
      previousEmail,
      email: updated.email
    })
    return updated
  })

  const requestDeletion = Effect.fnUntraced(function*(options: RequestDeletionOptions<F>) {
    if (options.password !== undefined) {
      const matches = yield* passwords.verifyPassword(options.user.id, options.password).pipe(
        // A hasher that cannot verify is a broken deployment rather than a
        // refusable request, and this method's callers are written against a
        // channel that does not mention it.
        Effect.catchTag("PasswordHashError", (error) => Effect.die(error))
      )
      if (!matches) {
        return yield* Effect.fail(new InvalidCredentials())
      }
    }

    if (config.user.deleteUser.confirmByEmail) {
      // The mailbox is the second factor here, so the session's age does not
      // decide anything and is not consulted.
      yield* verifications.retire(deleteAccountPurpose, options.user.id)
      const issued = yield* verifications.issue({
        purpose: deleteAccountPurpose,
        subject: options.user.id,
        ttl: config.tokens.deleteAccountTtl,
        payload: { callbackURL: Option.getOrNull(validateUrl(config, options.callbackURL)) }
      })
      yield* deliver(
        emails.sendDeleteAccountConfirmation({
          user: options.user,
          token: issued.token,
          url: deleteAccountUrl(config, issued.token)
        }),
        "delete-account confirmation e-mail delivery failed"
      )
      return "ConfirmationSent" as const
    }

    // Nothing was mailed, so the session itself is the only evidence there is:
    // a stale cookie must not be enough to destroy an account.
    yield* sessions.requireFresh(options.session)
    yield* deleteUser(options.user)
    return "Deleted" as const
  })

  const confirmDeletion = Effect.fnUntraced(function*(options: ConfirmDeletionOptions) {
    // Claimed before the owner is checked, so a link presented by the wrong
    // person is burnt as well as refused. Leaving it claimable would let
    // somebody who has read another person's mail park it until they had a
    // session of their own.
    const claimed = yield* verifications.claim(deleteAccountPurpose, options.token)
    if (claimed.subject !== options.userId) {
      return yield* Effect.fail(new InvalidToken())
    }

    const found = yield* users.findById(options.userId)
    const user = yield* Effect.fromOption(found, () => new InvalidToken())
    yield* deleteUser(user)

    // Validated once when the token was minted and again here: the row is
    // server-side state, but it is state built out of what a caller supplied.
    return { redirectTo: resolveUrl(config, claimed.payload.callbackURL) } satisfies DeletionResult
  })

  return usersOf(model).of({
    update,
    requestEmailChange,
    confirmEmailChange,
    verifyEmailChange,
    requestDeletion,
    confirmDeletion,
    delete: deleteUser
  })
})

/**
 * Provides {@link Users} for the user model given: the methods that carry a user
 * carry that model's, while the layer's own type stays the base one.
 *
 * @category layers
 * @since 1.0.0
 */
export const layerFor = <F extends UserFields>(
  model: UserModel<F>
): Layer.Layer<Users, never, Requirements> => Layer.effect(usersOf(model), make(model))

/**
 * {@link layerFor}, for a deployment that added no user fields of its own.
 *
 * @category layers
 * @since 1.0.0
 */
export const layer: Layer.Layer<Users, never, Requirements> = layerFor(baseUserModel)
