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
 * @since 0.1.0
 */
import { Brand, Context, Effect, Layer, Option, type Redacted } from "effect"
import { AuthConfig } from "../config/AuthConfig.js"
import {
  AuthEmails,
  changeEmailConfirmUrl,
  changeEmailVerifyUrl,
  deleteAccountUrl,
  withCallbackUrl
} from "../config/AuthEmails.js"
import { resolveUrl, validateUrl } from "../http/OriginCheck.js"
import { annotateAuthLogs, deliverEmail, revalidateRewrite } from "../internal/effects.js"
import { omitUndefined, pickKeys } from "../internal/records.js"
import type { SessionNotFresh } from "./Errors.js"
import { EmailUnchanged, InvalidCredentials, InvalidToken, UserAlreadyExists, UserNotFound } from "./Errors.js"
import type { UpdatedUserField } from "./Events.js"
import { AuthEvents, publishSafely } from "./Events.js"
import type { PolicyRefused, ProvisionSource } from "./Hooks.js"
import { AuthHooks } from "./Hooks.js"
import { Passwords } from "./Passwords.js"
import type { Session, UserExtras, UserFields, UserId, UserInsertOf, UserModel, UserOf } from "./Schema.js"
import { baseUserModel, normalizeEmail } from "./Schema.js"
import { Sessions } from "./Sessions.js"
import {
  isUniqueViolation,
  type PersistenceError,
  type UserStore,
  userStoreOf,
  type VerificationStore,
  WithAuthTransaction
} from "./Stores.js"
import {
  changeEmailConfirmPurpose,
  changeEmailVerifyPurpose,
  deleteAccountPurpose,
  emailVerifyPurpose,
  retireUserSubjectTokens,
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
 * @since 0.1.0
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
 * @since 0.1.0
 */
export type UpdateOptions<F extends UserFields = {}> = BaseUpdateOptions & UserExtras<F, "jsonUpdate">

/**
 * What {@link UsersService.provision} takes.
 *
 * @category models
 * @since 0.1.0
 */
export interface ProvisionOptions<F extends UserFields = {}> {
  /**
   * The row the calling flow built, id and timestamps included.
   *
   * **Details**
   *
   * It is already an insert row rather than a bag of fields: the id is
   * application-generated, so the flow that is about to write related rows knows
   * it before this is called.
   */
  readonly candidate: UserInsertOf<F>
  /** What created this person, for whatever the hooks decide with it. */
  readonly source: ProvisionSource
}

/**
 * What {@link UsersService.requestEmailChange} takes.
 *
 * @category models
 * @since 0.1.0
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
 * @since 0.1.0
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
 * @since 0.1.0
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
  readonly password?: Redacted.Redacted | undefined
  /** Where to send the browser after the deletion completes. */
  readonly callbackURL?: string | undefined
}

/**
 * What asking to delete an account did.
 *
 * @category models
 * @since 0.1.0
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
 * @since 0.1.0
 */
export interface ConfirmDeletionOptions {
  /** The token from the link. */
  readonly token: Redacted.Redacted
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
 * @since 0.1.0
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
 * @since 0.1.0
 */
export interface UsersService<F extends UserFields = {}> {
  /**
   * Writes a new user row — the one place in this library that does.
   *
   * **When to use**
   *
   * From any flow that creates a person: the password sign-up, the OAuth
   * resolution, a plugin. Going through here rather than through
   * `UserStore.create` is what makes `beforeUserCreate` and `afterUserCreate` a
   * choke point rather than three of them.
   *
   * **Details**
   *
   * `beforeUserCreate` may rewrite the candidate or refuse it; a rewrite is
   * re-validated through the model's own `insert` variant, so a hook cannot
   * store a row the schema would have rejected. `afterUserCreate` then runs with
   * the stored row, which is where a related row with a foreign key onto it
   * belongs.
   *
   * **Gotchas**
   *
   * It opens no transaction and publishes no event. Both are the caller's: the
   * hooks run inside whatever transaction the sign-up already holds, so a
   * refusal aborts the whole of it, and `UserCreated` stays where it is —
   * published after the commit, as `Events.ts` requires.
   */
  readonly provision: (options: ProvisionOptions<F>) => Effect.Effect<UserOf<F>, PolicyRefused | PersistenceError>

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
  readonly update: (options: UpdateOptions<F>) => Effect.Effect<UserOf<F>, UserNotFound | PersistenceError>

  /**
   * Starts an e-mail change. See the module header for the two hops.
   *
   * **Gotchas**
   *
   * Fails `EmailUnchanged` when the address is the one the account already has,
   * which is the only refusal this step makes out loud — the caller already
   * knows their own address, so saying so leaks nothing.
   *
   * `beforeEmailChange` is consulted before the address is even looked up, so a
   * deployment's policy cannot become an oracle for who else is registered.
   */
  readonly requestEmailChange: (
    options: RequestEmailChangeOptions<F>
  ) => Effect.Effect<EmailChangeOutcome, EmailUnchanged | PolicyRefused | PersistenceError>

  /**
   * Claims a first-hop token and mails the second hop to the new address.
   *
   * Nothing about the account has changed when this succeeds.
   */
  readonly confirmEmailChange: (token: Redacted.Redacted) => Effect.Effect<void, InvalidToken | PersistenceError>

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
    token: Redacted.Redacted
  ) => Effect.Effect<UserOf<F>, InvalidToken | UserAlreadyExists | PersistenceError>

  /**
   * Deletes the account, or mails a link that will.
   *
   * **Details**
   *
   * With `confirmByEmail` off this requires a fresh session and deletes
   * immediately; with it on it mints a `delete-account` token and mails it, and
   * the session's age does not matter because the mailbox is the second factor.
   *
   * `beforeUserDelete` is consulted once the caller has proved who they are, so
   * a deployment's policy never stands in for the credential checks.
   */
  readonly requestDeletion: (
    options: RequestDeletionOptions<F>
  ) => Effect.Effect<DeletionOutcome, InvalidCredentials | SessionNotFresh | PolicyRefused | PersistenceError>

  /**
   * Claims a deletion token presented by a signed-in caller and deletes the
   * account.
   *
   * **Gotchas**
   *
   * `beforeUserDelete` is consulted *after* the token has been claimed, so a
   * link a policy refuses is spent rather than left replayable.
   */
  readonly confirmDeletion: (
    options: ConfirmDeletionOptions
  ) => Effect.Effect<DeletionResult, InvalidToken | PolicyRefused | PersistenceError>

  /**
   * Deletes a user outright — no token, no freshness check.
   *
   * **When to use**
   *
   * From an application's own administrative code. Sessions and accounts cascade
   * with the row, and this user's outstanding verification tokens are retired
   * with it. Emits `UserDeleted` after the row has gone.
   *
   * **Gotchas**
   *
   * Only a call that actually removed the row publishes. Handing the same user
   * back a second time retires the tokens again — which changes nothing — and
   * announces nothing, because there was no second deletion to act on.
   */
  readonly delete: (user: UserOf<F>) => Effect.Effect<void, PersistenceError>
}

/**
 * What a signed-in person may do to their own user record. See
 * {@link UsersService}.
 *
 * @category services
 * @since 0.1.0
 */
export class Users extends Context.Service<Users, UsersService>()("effect-auth/domain/Users") {}

/**
 * {@link Users}, seen through a model's custom fields.
 *
 * The same key with a narrower shape: the methods that take or answer with a
 * user carry the deployment's own. See `userStoreOf` in `domain/Stores.ts` for
 * what a typed view is and why it is sound.
 *
 * @category services
 * @since 0.1.0
 */
export const usersOf = <F extends UserFields>(_model: UserModel<F>): Context.Service<Users, UsersService<F>> =>
  Context.Service<Users, UsersService<F>>("effect-auth/domain/Users")

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

/**
 * Names a claimed token's subject as the {@link UserId} it was minted under.
 *
 * `Verifications.claim` only answers for a row whose identifier is
 * `<purpose>:<subject>` *and* whose secret matched, and every purpose reached
 * from here writes `subject: user.id`. So the string it hands back is the very
 * `UserId` that was stored at issue time; `UserId` is a nominal brand, so this
 * restates that type without adding a runtime check.
 *
 * @internal
 */
const asUserId = Brand.nominal<UserId>()

/**
 * What {@link make} needs.
 *
 * @category models
 * @since 0.1.0
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
 * @since 0.1.0
 */
export const make: <F extends UserFields>(model: UserModel<F>) => Effect.Effect<UsersService<F>, never, Requirements> =
  Effect.fnUntraced(function* <F extends UserFields>(model: UserModel<F>) {
    const config = yield* AuthConfig
    const emails = yield* AuthEmails
    const events = yield* AuthEvents
    // A `Context.Reference` with a no-op default, so a deployment that installs
    // nothing provides nothing — and, being read here, the set is fixed when the
    // layer is built rather than looked up on every request.
    const hooks = yield* AuthHooks
    const verifications = yield* Verifications
    const users = yield* userStoreOf(model)
    const transaction = yield* WithAuthTransaction
    const sessions = yield* Sessions
    const passwords = yield* Passwords

    /**
     * The second hop: a token minted for the new address and mailed to it.
     *
     * Any hop-two token already outstanding for this user is retired first, so a
     * person who asks twice has exactly one live link — the latest one. Two of
     * them would be two addresses the account could still be moved to.
     */
    const sendVerificationHop = Effect.fnUntraced(function* (
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
      yield* deliverEmail(
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
    const deleteUser = Effect.fnUntraced(function* (user: UserOf<F>) {
      const removed = yield* transaction.run(
        Effect.gen(function* () {
          const deleted = yield* users.delete(user.id)
          yield* retireUserSubjectTokens(verifications, user.id)
          // The one purpose keyed by the address rather than by the id.
          yield* verifications.retire(emailVerifyPurpose, normalizeEmail(user.email))
          return deleted
        })
      )
      // The row had already gone — the same user handed here twice, a deletion
      // that raced this one. The retirements above are idempotent and stand, but
      // the event says a user was deleted and this call deleted nobody: a second
      // `UserDeleted` would have a subscriber act twice on one deletion.
      if (!removed) return
      yield* publishSafely(events, { _tag: "UserDeleted", userId: user.id, email: user.email })
    })

    // ---------------------------------------------------------------------------

    /**
     * Puts what a `beforeUserCreate` answered with back through the schema, and
     * re-normalizes the address it answered with. See `revalidateRewrite` for why
     * the address matters — normalizing costs a rewrite nothing and is the one
     * invariant a rewrite could otherwise break silently.
     */
    const rewritten = (answer: UserInsertOf<{}>) => revalidateRewrite(model.makeInsert, answer, normalizeEmail)

    const provision = Effect.fnUntraced(function* (options: ProvisionOptions<F>) {
      // The deployment's own columns are filled in *before* the hook is asked, not
      // after it. A base-typed caller — the magic-link plugin, a plugin of
      // somebody's own — builds its candidate out of the base fields alone, and a
      // policy installed through `hooksOf` is promised a row that really does
      // carry the extra columns: without this it would read `undefined` for every
      // one of them and derive whatever it derives from that. A candidate that
      // already carries them is handed straight back.
      const completed = yield* model.completeInsert(options.candidate)

      const before = hooks.beforeUserCreate
      // A rewrite goes back through the model's own `insert` variant: what a hook
      // hands back is an ordinary object, and nothing else would stop it storing
      // a row the schema rejects. The unrewritten path is already validated — the
      // caller built it with `insertRow` — so it is not paid for twice.
      const candidate =
        before === undefined
          ? completed
          : yield* rewritten(yield* before({ candidate: completed, source: options.source }))

      const user = yield* users.create(candidate)

      // Same transaction as the caller's, so a related row that cannot be written
      // takes the user down with it rather than leaving a half-provisioned
      // account behind.
      const after = hooks.afterUserCreate
      if (after !== undefined) {
        yield* after({ user, source: options.source })
      }
      return user
    })

    const update = Effect.fnUntraced(function* (options: UpdateOptions<F>) {
      const found = yield* users.findById(options.userId)
      const current = yield* Effect.fromOption(found, () => UserNotFound.make())

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
      // Picked by the `jsonUpdate` variant's keys, not the full `extraKeys`: the
      // latter includes fields a deployment declared `readOnly` or `hidden`, and
      // the type on `UpdateOptions` is the only thing that keeps a client from
      // setting one. A deployment that feeds loosely-typed data straight to the
      // domain layer has no such type, so the runtime whitelist must match the
      // declared one — otherwise a `readOnly` `role: "admin"` would be writable.
      const patch = Object.assign(model.basePatch(base), pickKeys(options, model.jsonUpdateExtraKeys))

      const written = yield* users.update(options.userId, patch)
      // The row went between the read above and this write — a concurrent
      // deletion, not a caller mistake.
      const updated = yield* Effect.fromOption(written, () => UserNotFound.make())

      yield* publishSafely(events, { _tag: "UserUpdated", userId: updated.id, fields })
      return updated
    })

    const requestEmailChange = Effect.fnUntraced(function* (options: RequestEmailChangeOptions<F>) {
      const user = options.user
      const newEmail = normalizeEmail(options.newEmail)
      if (newEmail === normalizeEmail(user.email)) {
        // The one refusal this step makes out loud: the caller already knows
        // their own address, so saying so tells them nothing they did not have.
        return yield* EmailUnchanged.make()
      }

      // Before the lookup, and therefore before the taken/free fork: a policy that
      // ran after it would have to answer differently for the two branches, or
      // else pay for a lookup it does not use — and the whole shape of this flow
      // is that neither the caller nor the clock can tell those branches apart.
      // Nothing has been minted or mailed yet either, so a refusal leaves no state.
      const beforeChange = hooks.beforeEmailChange
      if (beforeChange !== undefined) {
        yield* beforeChange({ user, newEmail })
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
      yield* deliverEmail(
        emails.sendChangeEmailConfirmation({
          user,
          newEmail,
          token: issued.token,
          url: withCallbackUrl(config, changeEmailConfirmUrl(config, issued.token), options.callbackURL)
        }),
        "change-email confirmation e-mail delivery failed"
      )
      return taken ? ("Ignored" as const) : ("ConfirmationSent" as const)
    })

    const confirmEmailChange = Effect.fnUntraced(function* (token: Redacted.Redacted) {
      const claimed = yield* verifications.claim(changeEmailConfirmPurpose, token)
      const userId = asUserId(claimed.subject)

      const found = yield* users.findById(userId)
      // The account went while the link sat in a mailbox. The token is spent and
      // there is nothing to confirm.
      const user = yield* Effect.fromOption(found, () => InvalidToken.make())

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

    const verifyEmailChange = Effect.fnUntraced(function* (token: Redacted.Redacted) {
      const claimed = yield* verifications.claim(changeEmailVerifyPurpose, token)
      const userId = asUserId(claimed.subject)
      const newEmail = normalizeEmail(claimed.payload.newEmail)

      const found = yield* users.findById(userId)
      const user = yield* Effect.fromOption(found, () => InvalidToken.make())
      const previousEmail = user.email

      const updated = yield* transaction
        .run(
          Effect.gen(function* () {
            // The address ends up verified: the link that got here was delivered to
            // it, which is the whole of what verification means.
            const written = yield* users.update(userId, model.basePatch({ email: newEmail, emailVerified: true }))
            const stored = yield* Effect.fromOption(written, () => InvalidToken.make())
            // Every link that could move or take over this account dies with the one
            // just used. That is more than the two change-email hops — a first hop
            // somebody asked for in the meantime among them: a `password-reset` or
            // `delete-account` token mailed to the address the account is *leaving*
            // has to go too. Completing a two-hop change is exactly the moment an
            // owner remediates a compromised old mailbox, and a reset link that mailbox
            // still holds (up to an hour's TTL) would otherwise take the account
            // straight back. This is the same re-securing `resetPassword` and
            // `changePassword` already do for this class of token.
            yield* retireUserSubjectTokens(verifications, userId)
            // The one purpose keyed by the address rather than the id: the OLD
            // address's own `email-verify` token, so a stale verify link cannot later
            // flip a stranger who re-registers the address this account just freed.
            yield* verifications.retire(emailVerifyPurpose, normalizeEmail(previousEmail))
            return stored
          })
        )
        .pipe(
          // Somebody claimed the address between the two hops. The unique index is
          // what settles it, so there is no check-then-act window to lose.
          Effect.catchTag("PersistenceError", (error): Effect.Effect<never, UserAlreadyExists | PersistenceError> =>
            isUniqueViolation(error) ? Effect.fail(UserAlreadyExists.make()) : Effect.fail(error)
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

    const requestDeletion = Effect.fnUntraced(function* (options: RequestDeletionOptions<F>) {
      // Freshness is checked before anything answers differently for a right and
      // a wrong password. Without a mailed confirmation the session is the only
      // evidence there is, so a stale cookie must not be enough to destroy an
      // account; and whenever a password is offered at all, a stale cookie must
      // not be enough to *test* one — `InvalidCredentials` versus anything else
      // would make this endpoint a password oracle for whoever stole the cookie.
      if (options.password !== undefined || !config.user.deleteUser.confirmByEmail) {
        yield* sessions.requireFresh(options.session)
      }

      if (options.password !== undefined) {
        const matches = yield* passwords.verifyPassword(options.user.id, options.password).pipe(
          // A hasher that cannot verify is a broken deployment rather than a
          // refusable request, and this method's callers are written against a
          // channel that does not mention it.
          Effect.catchTag("PasswordHashError", (error) => Effect.die(error))
        )
        if (!matches) {
          return yield* InvalidCredentials.make()
        }
      }

      // After the freshness guard *and* after the password check, so a policy
      // never stands in for either: the one verification the branch above runs is
      // what makes "you have no password" and "that is the wrong password" cost
      // the same, and a hook that short-circuited it would skip that defence. It
      // is still before anything is minted or mailed.
      const beforeDelete = hooks.beforeUserDelete
      if (beforeDelete !== undefined) {
        yield* beforeDelete({ user: options.user })
      }

      if (config.user.deleteUser.confirmByEmail) {
        // The mailbox is the second factor here, so — unless a password was
        // offered, above — the session's age does not decide anything.
        yield* verifications.retire(deleteAccountPurpose, options.user.id)
        const issued = yield* verifications.issue({
          purpose: deleteAccountPurpose,
          subject: options.user.id,
          ttl: config.tokens.deleteAccountTtl,
          payload: { callbackURL: Option.getOrNull(validateUrl(config, options.callbackURL)) }
        })
        yield* deliverEmail(
          emails.sendDeleteAccountConfirmation({
            user: options.user,
            token: issued.token,
            url: deleteAccountUrl(config, issued.token)
          }),
          "delete-account confirmation e-mail delivery failed"
        )
        return "ConfirmationSent" as const
      }

      // Nothing was mailed; freshness was already required above.
      yield* deleteUser(options.user)
      return "Deleted" as const
    })

    const confirmDeletion = Effect.fnUntraced(function* (options: ConfirmDeletionOptions) {
      // Claimed before the owner is checked, so a link presented by the wrong
      // person is burnt as well as refused. Leaving it claimable would let
      // somebody who has read another person's mail park it until they had a
      // session of their own.
      const claimed = yield* verifications.claim(deleteAccountPurpose, options.token)
      if (claimed.subject !== options.userId) {
        return yield* InvalidToken.make()
      }

      const found = yield* users.findById(options.userId)
      const user = yield* Effect.fromOption(found, () => InvalidToken.make())

      // After the claim, deliberately: the token is spent whichever way the
      // policy answers, so a link a hook refuses cannot be parked and replayed
      // against a policy that has since changed its mind.
      const beforeDelete = hooks.beforeUserDelete
      if (beforeDelete !== undefined) {
        yield* beforeDelete({ user })
      }

      yield* deleteUser(user)

      // Validated once when the token was minted and again here: the row is
      // server-side state, but it is state built out of what a caller supplied.
      return { redirectTo: resolveUrl(config, claimed.payload.callbackURL) } satisfies DeletionResult
    })

    return usersOf(model).of({
      provision,
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
 * @since 0.1.0
 */
export const layerFor = <F extends UserFields>(model: UserModel<F>): Layer.Layer<Users, never, Requirements> =>
  Layer.effect(usersOf(model), make(model))

/**
 * {@link layerFor}, for a deployment that added no user fields of its own.
 *
 * @category layers
 * @since 0.1.0
 */
export const layer: Layer.Layer<Users, never, Requirements> = layerFor(baseUserModel)
